//! Analyst-scoped facts for recovering a virtualized region. A profile is an
//! assertion about one binary, not evidence that devirtualization succeeded.

use hydir_core::{Address, Location, ProgramSpec};
use hydir_loader::import_elf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

mod explore;
pub use explore::{VmEdge, VmEdgeKind, VmExploreNode, VmExploreReport, VmNodeKey, explore_profile};

pub const VM_PROFILE_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    AnalystAssertion,
    StaticInference,
    TraceObservation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmEvidence {
    pub kind: EvidenceKind,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<Location>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmFact<T> {
    pub value: T,
    pub evidence: Vec<VmEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmRange {
    pub start: Location,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VmStorage {
    Register { name: String },
    ContextOffset { offset: u64, width_bits: u16 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmVpc {
    pub storage: VmStorage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<Location>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmContext {
    pub entry_register: String,
    pub base_register: String,
    pub size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VmGuestEffect {
    Register {
        name: String,
    },
    ContextRange {
        offset: u64,
        size: u64,
    },
    /// An analyst assertion that external writes cannot change interpreter
    /// code, bytecode, or VM-private state during this analysis.
    Memory {
        disjoint_from_vm: bool,
    },
    Call,
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmProfile {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: VmFact<Location>,
    pub exits: Vec<VmFact<Location>>,
    pub vpc: VmFact<VmVpc>,
    pub bytecode_ranges: Vec<VmFact<VmRange>>,
    pub context: VmFact<VmContext>,
    pub guest_effects: Vec<VmFact<VmGuestEffect>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VmProfileReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: Location,
    pub bytecode_ranges: usize,
    pub static_bytecode_ranges: usize,
    pub evidence_items: usize,
    /// This only means the profile is internally consistent with the ELF.
    pub profile_validated: bool,
    pub guest_cfg_recovered: bool,
    pub rewrite_ready: bool,
}

fn in_range(point: Location, range: VmRange) -> bool {
    point.address_space == range.start.address_space
        && point.value.0 >= range.start.value.0
        && range
            .start
            .value
            .0
            .checked_add(range.size)
            .is_some_and(|end| point.value.0 < end)
}

fn mapped_segment<'a>(
    spec: &'a ProgramSpec,
    range: VmRange,
) -> Option<&'a hydir_core::MappedSegmentSpec> {
    let end = range.start.value.0.checked_add(range.size)?;
    spec.mapped_segments.iter().find(|segment| {
        segment.address_space == range.start.address_space
            && range.start.value.0 >= segment.virtual_address.0
            && segment
                .virtual_address
                .0
                .checked_add(segment.memory_size)
                .is_some_and(|mapped_end| end <= mapped_end)
    })
}

fn check_fact<T>(fact: &VmFact<T>, name: &str) -> Result<usize, String> {
    if fact.evidence.is_empty() {
        return Err(format!("{name} needs at least one evidence item"));
    }
    for item in &fact.evidence {
        if item.detail.trim().is_empty() {
            return Err(format!("{name} has empty evidence detail"));
        }
    }
    Ok(fact.evidence.len())
}

fn valid_register(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "rax"
            | "rbx"
            | "rcx"
            | "rdx"
            | "rsi"
            | "rdi"
            | "rbp"
            | "rsp"
            | "r8"
            | "r9"
            | "r10"
            | "r11"
            | "r12"
            | "r13"
            | "r14"
            | "r15"
    )
}

/// Validate analyst facts against the supplied ELF without promoting them to
/// a recovered CFG or a verified guest transfer function.
pub fn validate_profile(bytes: &[u8], profile: &VmProfile) -> Result<VmProfileReport, String> {
    if profile.schema_version != VM_PROFILE_VERSION {
        return Err(format!(
            "VM profile version {} is unsupported; expected {VM_PROFILE_VERSION}",
            profile.schema_version
        ));
    }
    let actual_digest = format!("{:x}", Sha256::digest(bytes));
    if profile.binary_sha256 != actual_digest {
        return Err("VM profile binary digest does not match the ELF".to_owned());
    }
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    if spec.file_kind == "Relocatable" {
        return Err("VM profiles currently require a linked ELF address space".to_owned());
    }
    let mut evidence_items = check_fact(&profile.entry, "entry")?;
    let entry_range = VmRange {
        start: profile.entry.value,
        size: 1,
    };
    if !mapped_segment(&spec, entry_range).is_some_and(|segment| segment.executable) {
        return Err("VM entry is not in an executable mapped segment".to_owned());
    }
    if profile.exits.is_empty() {
        return Err("VM profile must name at least one exit".to_owned());
    }
    let mut exits = BTreeSet::new();
    for exit in &profile.exits {
        evidence_items += check_fact(exit, "exit")?;
        if !exits.insert(exit.value) {
            return Err("VM profile contains duplicate exits".to_owned());
        }
        if !mapped_segment(
            &spec,
            VmRange {
                start: exit.value,
                size: 1,
            },
        )
        .is_some_and(|segment| segment.executable)
        {
            return Err("VM exit is not in an executable mapped segment".to_owned());
        }
    }
    evidence_items += check_fact(&profile.vpc, "VPC")?;
    evidence_items += check_fact(&profile.context, "context")?;
    if !valid_register(&profile.context.value.entry_register)
        || !valid_register(&profile.context.value.base_register)
        || profile.context.value.size == 0
    {
        return Err("VM context needs valid entry/base GPRs and nonzero size".to_owned());
    }
    match &profile.vpc.value.storage {
        VmStorage::Register { name } if !valid_register(name) => {
            return Err("VPC storage register is not an x86-64 GPR".to_owned());
        }
        VmStorage::ContextOffset { offset, width_bits } => {
            if !matches!(width_bits, 8 | 16 | 32 | 64)
                || offset
                    .checked_add(u64::from(*width_bits) / 8)
                    .is_none_or(|end| end > profile.context.value.size)
            {
                return Err("VPC context offset is outside the VM context".to_owned());
            }
        }
        _ => {}
    }
    if profile.bytecode_ranges.is_empty() {
        return Err("VM profile needs a bytecode range".to_owned());
    }
    let mut static_bytecode_ranges = 0;
    let mut ranges = Vec::new();
    for fact in &profile.bytecode_ranges {
        evidence_items += check_fact(fact, "bytecode range")?;
        let range = fact.value;
        if range.size == 0 {
            return Err("bytecode range cannot be empty".to_owned());
        }
        let segment = mapped_segment(&spec, range)
            .ok_or_else(|| "bytecode range is outside mapped ELF memory".to_owned())?;
        if !segment.readable {
            return Err("bytecode range is not readable".to_owned());
        }
        let file_end = segment.virtual_address.0.saturating_add(segment.file_size);
        if !segment.writable && range.start.value.0.saturating_add(range.size) <= file_end {
            static_bytecode_ranges += 1;
        }
        ranges.push(range);
    }
    ranges.sort_by_key(|range| (range.start.address_space, range.start.value.0));
    for pair in ranges.windows(2) {
        let left = pair[0];
        let right = pair[1];
        if left.start.address_space == right.start.address_space
            && left.start.value.0 + left.size > right.start.value.0
        {
            return Err("bytecode ranges overlap".to_owned());
        }
    }
    if let Some(vpc) = profile.vpc.value.initial_value {
        if !ranges.iter().any(|range| in_range(vpc, *range)) {
            return Err("initial VPC is outside the annotated bytecode".to_owned());
        }
    }
    if profile.guest_effects.is_empty() {
        return Err("VM profile needs at least one guest-visible effect".to_owned());
    }
    for effect in &profile.guest_effects {
        evidence_items += check_fact(effect, "guest effect")?;
        match &effect.value {
            VmGuestEffect::Register { name } if !valid_register(name) => {
                return Err("guest effect register is not an x86-64 GPR".to_owned());
            }
            VmGuestEffect::ContextRange { offset, size }
                if *size == 0
                    || offset
                        .checked_add(*size)
                        .is_none_or(|end| end > profile.context.value.size) =>
            {
                return Err("guest effect range is outside the VM context".to_owned());
            }
            _ => {}
        }
    }
    Ok(VmProfileReport {
        schema_version: VM_PROFILE_VERSION,
        binary_sha256: actual_digest,
        entry: profile.entry.value,
        bytecode_ranges: ranges.len(),
        static_bytecode_ranges,
        evidence_items,
        profile_validated: true,
        guest_cfg_recovered: false,
        rewrite_ready: false,
    })
}

pub fn linked_location(value: u64) -> Location {
    Location {
        address_space: 0,
        value: Address(value),
    }
}
