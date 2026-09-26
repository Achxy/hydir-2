//! Bounded CFG-aware LLVM execution for a selected Ghidra raw P-code function.
//! Each operation keeps its source address. Stops are explicit and fidelity is
//! Unknown: this is a concrete path engine, not an equivalence proof.

use crate::pcode_llvm::{emit_pcode_exact_operation_llvm, pcode_offset, pcode_space_id};
use crate::pcode_standalone::{MAX_STATE_BYTES, PcodeStateByte, helper_definitions, node_bytes};
use hydir_ir::pcode::{
    GhidraAddressSpace, GhidraFlowKind, GhidraSnapshot, PcodeAddress, PcodeEffect, PcodeOperation,
    PcodeVarnode,
};
use hydir_ir::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PCODE_CFG_LLVM_VERSION: u32 = 2;
pub const PCODE_CFG_GUEST_RAM_MAX_BYTES: u64 = 1_048_576;
const MAX_CFG_INSTRUCTIONS: usize = 4096;
const MAX_CFG_OPERATIONS: usize = 4096;
const MAX_RUNTIME_STEPS: u32 = 262_144;
const MAX_LLVM_BYTES: usize = 4 * 1024 * 1024;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeCfgLlvmStatus {
    Return = 1,
    Call = 2,
    OpaqueEffect = 3,
    UnsupportedMemory = 4,
    IndirectFlow = 5,
    UnresolvedFlow = 6,
    AmbiguousFlow = 7,
    OutOfFunction = 8,
    MalformedTarget = 9,
    UnknownInput = 10,
    StepBudget = 11,
    InvalidArguments = 12,
    VisitBudget = 13,
    InvalidOperation = 14,
    MemoryUnknownAlias = 15,
    MemoryUnknownBytes = 16,
    MemoryOutOfBounds = 17,
    MemoryAddressOverflow = 18,
    MemorySpaceMismatch = 19,
    MemoryUnsupportedLayout = 20,
    MemoryNonRamSpace = 21,
    MemoryUnknownSpace = 22,
}

impl PcodeCfgLlvmStatus {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCfgLlvmSourceOperation {
    /// Ghidra P-code operation source address, which may differ from its
    /// containing instruction for delay-slot or override cases.
    pub address: PcodeAddress,
    pub instruction_address: PcodeAddress,
    pub instruction_index: usize,
    pub operation_index: usize,
    pub mnemonic: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCfgLlvmStopSite {
    pub address: PcodeAddress,
    pub operation_index: Option<usize>,
    pub status: PcodeCfgLlvmStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCfgLlvmArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub start: PcodeAddress,
    pub source_operations: Vec<PcodeCfgLlvmSourceOperation>,
    pub stop_sites: Vec<PcodeCfgLlvmStopSite>,
    pub state_bytes: usize,
    pub guest_ram_limit_bytes: u64,
    pub byte_map: Vec<PcodeStateByte>,
    pub state_abi: String,
    pub llvm_ir: String,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

fn offset(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.strip_prefix("0x").ok_or("missing 0x offset")?, 16)
        .map_err(|_| "invalid hexadecimal offset".to_owned())
}

fn relative_target(node: &PcodeVarnode, current: usize, count: usize) -> Result<usize, String> {
    if node.space != "const" || !(1..=8).contains(&node.size) {
        return Err("relative branch requires a 1..=8 byte constant".into());
    }
    let raw = offset(&node.offset)?;
    let shift = 64 - node.size * 8;
    if raw > (u64::MAX >> shift) {
        return Err("relative branch offset exceeds declared width".into());
    }
    let delta = ((raw << shift) as i64) >> shift;
    let target = (current as i64)
        .checked_add(delta)
        .ok_or("relative branch operation index overflows")?;
    if target < 0 || target as usize >= count {
        return Err("relative branch leaves its instruction".into());
    }
    Ok(target as usize)
}

fn target_label(
    target: &PcodeVarnode,
    instruction: usize,
    operation: usize,
    operation_count: usize,
    index: &BTreeMap<(String, u64), usize>,
) -> Result<String, (PcodeCfgLlvmStatus, String)> {
    if target.space == "const" {
        return relative_target(target, operation, operation_count)
            .map(|next| format!("op_{instruction}_{next}"))
            .map_err(|reason| (PcodeCfgLlvmStatus::MalformedTarget, reason));
    }
    let address =
        offset(&target.offset).map_err(|reason| (PcodeCfgLlvmStatus::MalformedTarget, reason))?;
    index
        .get(&(target.space.clone(), address))
        .map(|next| format!("ins_{next}"))
        .ok_or((
            PcodeCfgLlvmStatus::OutOfFunction,
            "direct branch target is outside selected instructions".into(),
        ))
}

fn stop_site(
    sites: &mut Vec<PcodeCfgLlvmStopSite>,
    address: &PcodeAddress,
    operation_index: Option<usize>,
    status: PcodeCfgLlvmStatus,
    reason: impl Into<String>,
) {
    sites.push(PcodeCfgLlvmStopSite {
        address: address.clone(),
        operation_index,
        status,
        reason: reason.into(),
    });
}

fn log_event(id: usize, count: &str, suffix: &str, destination: &str) -> String {
    format!(
        "  %slot_{id}_{suffix} = getelementptr i32, ptr %events, i32 {count}\n\
           store i32 {id}, ptr %slot_{id}_{suffix}\n\
           %next_{id}_{suffix} = add i32 {count}, 1\n\
           store i32 %next_{id}_{suffix}, ptr %event_count\n\
           br label %{destination}\n"
    )
}

fn stop_label(status: PcodeCfgLlvmStatus) -> &'static str {
    match status {
        PcodeCfgLlvmStatus::Return => "stop_return",
        PcodeCfgLlvmStatus::Call => "stop_call",
        PcodeCfgLlvmStatus::OpaqueEffect => "stop_opaque",
        PcodeCfgLlvmStatus::UnsupportedMemory => "stop_memory",
        PcodeCfgLlvmStatus::IndirectFlow => "stop_indirect",
        PcodeCfgLlvmStatus::UnresolvedFlow => "stop_unresolved",
        PcodeCfgLlvmStatus::AmbiguousFlow => "stop_ambiguous",
        PcodeCfgLlvmStatus::OutOfFunction => "stop_outside",
        PcodeCfgLlvmStatus::MalformedTarget => "stop_malformed",
        PcodeCfgLlvmStatus::UnknownInput => "stop_unknown",
        PcodeCfgLlvmStatus::StepBudget => "stop_budget",
        PcodeCfgLlvmStatus::InvalidArguments => "stop_invalid_args",
        PcodeCfgLlvmStatus::VisitBudget => "stop_visit_budget",
        PcodeCfgLlvmStatus::InvalidOperation => "stop_invalid_op",
        PcodeCfgLlvmStatus::MemoryUnknownAlias => "stop_memory_alias",
        PcodeCfgLlvmStatus::MemoryUnknownBytes => "stop_memory_bytes",
        PcodeCfgLlvmStatus::MemoryOutOfBounds => "stop_memory_bounds",
        PcodeCfgLlvmStatus::MemoryAddressOverflow => "stop_memory_overflow",
        PcodeCfgLlvmStatus::MemorySpaceMismatch => "stop_memory_space",
        PcodeCfgLlvmStatus::MemoryUnsupportedLayout => "stop_memory_layout",
        PcodeCfgLlvmStatus::MemoryNonRamSpace => "stop_memory_nonram",
        PcodeCfgLlvmStatus::MemoryUnknownSpace => "stop_memory_unknown_space",
    }
}

fn branch_to_stop(status: PcodeCfgLlvmStatus) -> String {
    format!("  br label %{}\n", stop_label(status))
}

fn known_check(
    node: &PcodeVarnode,
    stem: &str,
    body: &mut String,
) -> Result<Option<String>, String> {
    if node.space == "const" {
        return Ok(None);
    }
    let id = pcode_space_id(&node.space)?;
    let byte_offset = pcode_offset(node)?;
    let mask = if node.size == 8 {
        u64::MAX
    } else {
        (1u64 << (node.size * 8)) - 1
    };
    body.push_str(&format!(
        "  %{stem}_mask = call i64 @hydir_read_varnode(ptr %known, i32 {id}, i64 {byte_offset}, i32 {})\n\
           %{stem}_ok = icmp eq i64 %{stem}_mask, {mask}\n",
        node.size
    ));
    Ok(Some(format!("%{stem}_ok")))
}

fn emit_known_guard(
    checks: &[String],
    stem: &str,
    body: &mut String,
    next: &str,
    missing_status: PcodeCfgLlvmStatus,
) {
    if checks.is_empty() {
        body.push_str(&format!("  br label %{next}\n"));
        return;
    }
    let mut combined = checks[0].clone();
    for (index, check) in checks.iter().enumerate().skip(1) {
        let name = format!("%{stem}_all_{index}");
        body.push_str(&format!("  {name} = and i1 {combined}, {check}\n"));
        combined = name;
    }
    body.push_str(&format!(
        "  br i1 {combined}, label %{next}, label %{}\n",
        stop_label(missing_status)
    ));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryKind {
    Load,
    Store,
}

struct MemoryLayout<'a> {
    kind: MemoryKind,
    space: &'a GhidraAddressSpace,
    pointer: &'a PcodeVarnode,
    value: &'a PcodeVarnode,
    width: u32,
}

fn memory_layout<'a>(
    source: &'a PcodeOperation,
    spaces: &'a [GhidraAddressSpace],
) -> Result<MemoryLayout<'a>, (PcodeCfgLlvmStatus, String)> {
    let invalid = |reason: &str| {
        (
            PcodeCfgLlvmStatus::MemoryUnsupportedLayout,
            reason.to_owned(),
        )
    };
    let kind = match (source.opcode, source.mnemonic.as_str()) {
        (2, "LOAD") if source.inputs.len() == 2 && source.output.is_some() => MemoryKind::Load,
        (3, "STORE") if source.inputs.len() == 3 && source.output.is_none() => MemoryKind::Store,
        _ => {
            return Err(invalid(
                "LOAD/STORE opcode, mnemonic, arity or output is invalid",
            ));
        }
    };
    let id_node = &source.inputs[0];
    if id_node.space != "const" || !(1..=8).contains(&id_node.size) {
        return Err(invalid("memory space ID must be a 1..=8 byte constant"));
    }
    let id = offset(&id_node.offset).map_err(|reason| invalid(&reason))?;
    let mask = if id_node.size == 8 {
        u64::MAX
    } else {
        (1u64 << (id_node.size * 8)) - 1
    };
    if id > mask {
        return Err(invalid("memory space ID exceeds its varnode width"));
    }
    let space = spaces
        .iter()
        .find(|space| u64::try_from(space.id).ok() == Some(id))
        .ok_or((
            PcodeCfgLlvmStatus::MemoryUnknownSpace,
            format!("no Ghidra address space has ID {id}"),
        ))?;
    if space.space_type != 1 || matches!(space.name.as_str(), "const" | "register" | "unique") {
        return Err((
            PcodeCfgLlvmStatus::MemoryNonRamSpace,
            format!("{} is not a Ghidra RAM space", space.name),
        ));
    }
    let pointer = &source.inputs[1];
    if !(1..=8).contains(&space.pointer_size)
        || pointer.size != space.pointer_size
        || !matches!(pointer.space.as_str(), "register" | "unique" | "const")
    {
        return Err(invalid(
            "pointer varnode differs from RAM space pointer width",
        ));
    }
    let value = match kind {
        MemoryKind::Load => source.output.as_ref().expect("LOAD output checked above"),
        MemoryKind::Store => &source.inputs[2],
    };
    if !matches!(value.space.as_str(), "register" | "unique" | "const")
        || kind == MemoryKind::Load && value.space == "const"
        || !(1..=8).contains(&value.size)
        || space.addressable_unit_size == 0
    {
        return Err(invalid("memory value width or state space is unsupported"));
    }
    Ok(MemoryLayout {
        kind,
        space,
        pointer,
        value,
        width: value.size,
    })
}

fn emit_memory_operation(
    layout: &MemoryLayout<'_>,
    id: usize,
    body: &mut String,
    next_label: &str,
) -> Result<(), String> {
    let space_id = layout.space.id;
    body.push_str(&format!(
        "  %space_match_{id} = icmp eq i32 %guest_space_id, {space_id}\n  br i1 %space_match_{id}, label %memory_pointer_{id}, label %stop_memory_space\nmemory_pointer_{id}:\n"
    ));
    if let Some(check) = known_check(layout.pointer, &format!("pointer_{id}"), body)? {
        body.push_str(&format!(
            "  br i1 {check}, label %memory_address_{id}, label %stop_memory_alias\n"
        ));
    } else {
        body.push_str(&format!("  br label %memory_address_{id}\n"));
    }
    body.push_str(&format!("memory_address_{id}:\n"));
    let pointer = if layout.pointer.space == "const" {
        let bits = layout.pointer.size * 8;
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        format!("{}", offset(&layout.pointer.offset)? & mask)
    } else {
        let name = format!("%pointer_value_{id}");
        body.push_str(&format!(
            "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
            pcode_space_id(&layout.pointer.space)?,
            pcode_offset(layout.pointer)?,
            layout.pointer.size
        ));
        name
    };
    let unit = layout.space.addressable_unit_size;
    let last = layout.width - 1;
    body.push_str(&format!(
        "  %scaled_{id} = call {{ i64, i1 }} @llvm.umul.with.overflow.i64(i64 {pointer}, i64 {unit})\n  %byte_address_{id} = extractvalue {{ i64, i1 }} %scaled_{id}, 0\n  %scale_overflow_{id} = extractvalue {{ i64, i1 }} %scaled_{id}, 1\n  %last_{id} = call {{ i64, i1 }} @llvm.uadd.with.overflow.i64(i64 %byte_address_{id}, i64 {last})\n  %end_overflow_{id} = extractvalue {{ i64, i1 }} %last_{id}, 1\n  %address_overflow_{id} = or i1 %scale_overflow_{id}, %end_overflow_{id}\n  br i1 %address_overflow_{id}, label %stop_memory_overflow, label %memory_bounds_{id}\nmemory_bounds_{id}:\n  %below_base_{id} = icmp ult i64 %byte_address_{id}, %guest_base\n  %relative_{id} = sub i64 %byte_address_{id}, %guest_base\n  %enough_{id} = icmp uge i64 %guest_len, {}\n  %last_start_{id} = sub i64 %guest_len, {}\n  %inside_{id} = icmp ule i64 %relative_{id}, %last_start_{id}\n  %room_{id} = and i1 %enough_{id}, %inside_{id}\n  %not_below_{id} = xor i1 %below_base_{id}, true\n  %in_bounds_{id} = and i1 %room_{id}, %not_below_{id}\n  br i1 %in_bounds_{id}, label %memory_value_{id}, label %stop_memory_bounds\nmemory_value_{id}:\n",
        layout.width, layout.width
    ));
    match layout.kind {
        MemoryKind::Load => {
            let mut known_checks = Vec::new();
            for byte in 0..layout.width {
                body.push_str(&format!(
                    "  %relative_{id}_{byte} = add i64 %relative_{id}, {byte}\n  %guest_known_ptr_{id}_{byte} = getelementptr i8, ptr %guest_known, i64 %relative_{id}_{byte}\n  %guest_known_byte_{id}_{byte} = load i8, ptr %guest_known_ptr_{id}_{byte}\n  %guest_byte_ok_{id}_{byte} = icmp eq i8 %guest_known_byte_{id}_{byte}, -1\n"
                ));
                known_checks.push(format!("%guest_byte_ok_{id}_{byte}"));
            }
            emit_known_guard(
                &known_checks,
                &format!("guest_{id}"),
                body,
                &format!("memory_load_{id}"),
                PcodeCfgLlvmStatus::MemoryUnknownBytes,
            );
            body.push_str(&format!("memory_load_{id}:\n"));
            let mut previous = None::<String>;
            for byte in 0..layout.width {
                body.push_str(&format!(
                    "  %guest_ptr_{id}_{byte} = getelementptr i8, ptr %guest_ram, i64 %relative_{id}_{byte}\n  %guest_byte_{id}_{byte} = load i8, ptr %guest_ptr_{id}_{byte}\n  %guest_wide_{id}_{byte} = zext i8 %guest_byte_{id}_{byte} to i64\n  %guest_part_{id}_{byte} = shl i64 %guest_wide_{id}_{byte}, {}\n",
                    byte * 8
                ));
                let part = format!("%guest_part_{id}_{byte}");
                if let Some(previous_value) = previous {
                    let name = format!("%guest_acc_{id}_{byte}");
                    body.push_str(&format!("  {name} = or i64 {previous_value}, {part}\n"));
                    previous = Some(name);
                } else {
                    previous = Some(part);
                }
            }
            let result = previous.expect("memory width checked nonzero");
            let output_space = pcode_space_id(&layout.value.space)?;
            let output_offset = pcode_offset(layout.value)?;
            body.push_str(&format!(
                "  call void @hydir_write_varnode(ptr %state, i32 {output_space}, i64 {output_offset}, i32 {}, i64 {result})\n  call void @hydir_write_varnode(ptr %known, i32 {output_space}, i64 {output_offset}, i32 {}, i64 -1)\n",
                layout.width, layout.width
            ));
        }
        MemoryKind::Store => {
            let data = layout.value;
            if let Some(check) = known_check(data, &format!("store_data_{id}"), body)? {
                body.push_str(&format!(
                    "  br i1 {check}, label %memory_store_{id}, label %stop_unknown\n"
                ));
            } else {
                body.push_str(&format!("  br label %memory_store_{id}\n"));
            }
            body.push_str(&format!("memory_store_{id}:\n"));
            let value =
                if data.space == "const" {
                    let bits = data.size * 8;
                    let mask = if bits == 64 {
                        u64::MAX
                    } else {
                        (1u64 << bits) - 1
                    };
                    format!("{}", offset(&data.offset)? & mask)
                } else {
                    let name = format!("%store_value_{id}");
                    body.push_str(&format!(
                    "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
                    pcode_space_id(&data.space)?, pcode_offset(data)?, data.size
                ));
                    name
                };
            for byte in 0..layout.width {
                body.push_str(&format!(
                    "  %store_shifted_{id}_{byte} = lshr i64 {value}, {}\n  %store_byte_{id}_{byte} = trunc i64 %store_shifted_{id}_{byte} to i8\n  %store_relative_{id}_{byte} = add i64 %relative_{id}, {byte}\n  %store_guest_ptr_{id}_{byte} = getelementptr i8, ptr %guest_ram, i64 %store_relative_{id}_{byte}\n  store i8 %store_byte_{id}_{byte}, ptr %store_guest_ptr_{id}_{byte}\n  %store_known_ptr_{id}_{byte} = getelementptr i8, ptr %guest_known, i64 %store_relative_{id}_{byte}\n  store i8 -1, ptr %store_known_ptr_{id}_{byte}\n",
                    byte * 8
                ));
            }
        }
    }
    body.push_str(&log_event(
        id,
        &format!("%count_{id}"),
        "memory",
        next_label,
    ));
    Ok(())
}

/// Emit a self-contained LLVM module for one bounded concrete CFG path.
/// `state` and `known` are equally sized byte arrays indexed by `byte_map`.
/// A known byte is 0xff, an unknown byte is 0x00. `events` has at least
/// `event_capacity` i32 slots. The function writes successful operation IDs
/// and their count, then returns a `PcodeCfgLlvmStatus` code. Both execution
/// and instruction visits are bounded, including zero-operation loops.
pub fn emit_pcode_cfg_llvm(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
) -> Result<PcodeCfgLlvmArtifact, String> {
    snapshot.pcode_cfg_ir()?;
    if !snapshot.program.language_id.starts_with("x86:LE:64:") {
        return Err("P-code CFG LLVM currently requires x86-64 little endian".into());
    }
    let semantic = snapshot.pcode_function_ir()?.lower_semantics();
    if semantic.instructions.len() > MAX_CFG_INSTRUCTIONS {
        return Err("P-code CFG LLVM instruction limit exceeded".into());
    }
    let operation_count = semantic
        .instructions
        .iter()
        .map(|instruction| instruction.operations.len())
        .sum::<usize>();
    if operation_count > MAX_CFG_OPERATIONS {
        return Err("P-code CFG LLVM operation limit exceeded".into());
    }
    let mut index = BTreeMap::new();
    for (number, instruction) in semantic.instructions.iter().enumerate() {
        index.insert(
            (
                instruction.address.space.clone(),
                offset(&instruction.address.offset)?,
            ),
            number,
        );
    }
    let start = start.unwrap_or(&snapshot.selected_function.entry).clone();
    let start_index = index
        .get(&(start.space.clone(), offset(&start.offset)?))
        .ok_or("P-code CFG LLVM start is not a selected instruction")?;
    let mut fallthroughs = vec![Vec::<Option<PcodeAddress>>::new(); semantic.instructions.len()];
    for edge in &snapshot.selected_function.flow_edges {
        if edge.kind == GhidraFlowKind::Fallthrough {
            let source = index[&(edge.source.space.clone(), offset(&edge.source.offset)?)];
            fallthroughs[source].push(edge.target.clone());
        }
    }
    let mut byte_keys = BTreeSet::new();
    for instruction in &semantic.instructions {
        for operation in &instruction.operations {
            if matches!(operation.effect, PcodeEffect::Assign { .. })
                && emit_pcode_exact_operation_llvm(operation).is_ok()
            {
                for input in &operation.source.inputs {
                    node_bytes(input, &mut byte_keys)?;
                }
                if let Some(output) = &operation.source.output {
                    node_bytes(output, &mut byte_keys)?;
                }
            } else if operation.source.opcode == 5
                && operation.source.inputs.len() == 2
                && operation.source.inputs[1].size == 1
                && matches!(
                    operation.source.inputs[1].space.as_str(),
                    "register" | "unique" | "const"
                )
            {
                node_bytes(&operation.source.inputs[1], &mut byte_keys)?;
            } else if matches!(operation.source.opcode, 2 | 3)
                && let Ok(layout) = memory_layout(&operation.source, &semantic.address_spaces)
            {
                node_bytes(layout.pointer, &mut byte_keys)?;
                node_bytes(layout.value, &mut byte_keys)?;
            }
        }
    }
    if byte_keys.len() > MAX_STATE_BYTES {
        return Err("P-code CFG LLVM state byte limit exceeded".into());
    }
    let byte_map = byte_keys
        .into_iter()
        .enumerate()
        .map(|(index, (space, offset))| PcodeStateByte {
            space,
            offset: format!("0x{offset:x}"),
            index: index as u32,
        })
        .collect::<Vec<_>>();

    let mut sources = Vec::new();
    let mut sites = Vec::new();
    let mut helper_ir = String::new();
    // Reserve every mapped state byte against the Rust executor's combined
    // one-MiB known-state limit, even if the caller marks all of them known.
    let guest_ram_limit = PCODE_CFG_GUEST_RAM_MAX_BYTES - byte_map.len() as u64;
    let mut body = format!(
        "define i32 @hydir_pcode_cfg(ptr %state, ptr %known, i32 %guest_space_id, ptr %guest_ram, ptr %guest_known, i64 %guest_base, i64 %guest_len, ptr %events, ptr %event_count, i32 %event_capacity, i32 %max_steps) {{\n\
         entry:\n  %bad_state = icmp eq ptr %state, null\n  %bad_known = icmp eq ptr %known, null\n\
           %bad_guest_ram = icmp eq ptr %guest_ram, null\n  %bad_guest_known = icmp eq ptr %guest_known, null\n\
           %bad_events = icmp eq ptr %events, null\n  %bad_count = icmp eq ptr %event_count, null\n\
           %bad_a = or i1 %bad_state, %bad_known\n  %bad_b = or i1 %bad_events, %bad_count\n\
           %bad_c = or i1 %bad_guest_ram, %bad_guest_known\n  %bad_d = or i1 %bad_a, %bad_b\n\
           %bad_ptr = or i1 %bad_c, %bad_d\n  %too_many = icmp ugt i32 %max_steps, 262144\n\
           %small_log = icmp ult i32 %event_capacity, %max_steps\n\
           %negative_capacity = icmp slt i32 %event_capacity, 0\n\
           %bad_capacity = or i1 %small_log, %negative_capacity\n\
           %bad_steps = or i1 %too_many, %bad_capacity\n\
           %guest_too_large = icmp ugt i64 %guest_len, {guest_ram_limit}\n\
           %guest_empty = icmp eq i64 %guest_len, 0\n  %guest_tail_raw = sub i64 %guest_len, 1\n\
           %guest_tail = select i1 %guest_empty, i64 0, i64 %guest_tail_raw\n\
           %max_guest_base = sub i64 -1, %guest_tail\n\
           %guest_base_overflow = icmp ugt i64 %guest_base, %max_guest_base\n\
           %bad_guest_range = or i1 %guest_too_large, %guest_base_overflow\n\
           %bad_bounds = or i1 %bad_steps, %bad_guest_range\n\
           %bad_args = or i1 %bad_ptr, %bad_bounds\n\
           br i1 %bad_args, label %stop_invalid_args, label %initialize\n\
         initialize:\n  store i32 0, ptr %event_count\n  %visit_counter = alloca i32\n\
           store i32 0, ptr %visit_counter\n",
    );
    body.push_str(&format!("  br label %ins_{start_index}\n"));
    for (instruction_index, instruction) in semantic.instructions.iter().enumerate() {
        body.push_str(&format!(
            "ins_{instruction_index}:\n  %visits_{instruction_index} = load i32, ptr %visit_counter\n\
               %visit_exhausted_{instruction_index} = icmp uge i32 %visits_{instruction_index}, {MAX_RUNTIME_STEPS}\n\
               br i1 %visit_exhausted_{instruction_index}, label %stop_visit_budget, label %enter_{instruction_index}\n\
             enter_{instruction_index}:\n  %visit_next_{instruction_index} = add i32 %visits_{instruction_index}, 1\n\
               store i32 %visit_next_{instruction_index}, ptr %visit_counter\n\
               call void @hydir_clear_unique(ptr %state)\n  call void @hydir_clear_unique(ptr %known)\n"
        ));
        let first_label = if instruction.operations.is_empty() {
            format!("end_{instruction_index}")
        } else {
            format!("op_{instruction_index}_0")
        };
        body.push_str(&format!("  br label %{first_label}\n"));

        for (operation_index, operation) in instruction.operations.iter().enumerate() {
            let id = sources.len();
            let source = &operation.source;
            sources.push(PcodeCfgLlvmSourceOperation {
                address: source.source_address.clone(),
                instruction_address: instruction.address.clone(),
                instruction_index,
                operation_index,
                mnemonic: source.mnemonic.clone(),
            });
            let next_label = if operation_index + 1 == instruction.operations.len() {
                format!("end_{instruction_index}")
            } else {
                format!("op_{instruction_index}_{}", operation_index + 1)
            };
            body.push_str(&format!(
                "op_{instruction_index}_{operation_index}:\n  %count_{id} = load i32, ptr %event_count\n\
                   %budget_{id} = icmp uge i32 %count_{id}, %max_steps\n\
                   br i1 %budget_{id}, label %stop_budget, label %run_{id}\nrun_{id}:\n"
            ));
            match source.opcode {
                4 | 5 => {
                    let conditional = source.opcode == 5;
                    let expected = if conditional { "CBRANCH" } else { "BRANCH" };
                    if source.mnemonic != expected
                        || source.output.is_some()
                        || source.inputs.len() != if conditional { 2 } else { 1 }
                        || conditional && source.inputs[1].size != 1
                    {
                        stop_site(
                            &mut sites,
                            &source.source_address,
                            Some(operation_index),
                            PcodeCfgLlvmStatus::MalformedTarget,
                            "invalid direct branch shape",
                        );
                        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
                        continue;
                    }
                    let target = target_label(
                        &source.inputs[0],
                        instruction_index,
                        operation_index,
                        instruction.operations.len(),
                        &index,
                    );
                    if conditional {
                        let condition = &source.inputs[1];
                        let mut checks = Vec::new();
                        match known_check(condition, &format!("cond_{id}"), &mut body) {
                            Ok(Some(check)) => checks.push(check),
                            Ok(None) => (),
                            Err(reason) => {
                                stop_site(
                                    &mut sites,
                                    &source.source_address,
                                    Some(operation_index),
                                    PcodeCfgLlvmStatus::MalformedTarget,
                                    reason,
                                );
                                body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
                                continue;
                            }
                        }
                        emit_known_guard(
                            &checks,
                            &format!("cond_{id}"),
                            &mut body,
                            &format!("condition_{id}"),
                            PcodeCfgLlvmStatus::UnknownInput,
                        );
                        body.push_str(&format!("condition_{id}:\n"));
                        let value = if condition.space == "const" {
                            format!("{}", offset(&condition.offset)? & 0xff)
                        } else {
                            let name = format!("%condition_value_{id}");
                            body.push_str(&format!(
                                "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 1)\n",
                                pcode_space_id(&condition.space)?, pcode_offset(condition)?
                            ));
                            name
                        };
                        body.push_str(&format!(
                            "  %take_{id} = icmp ne i64 {value}, 0\n  br i1 %take_{id}, label %taken_{id}, label %false_{id}\n"
                        ));
                        body.push_str(&format!("false_{id}:\n"));
                        body.push_str(&log_event(
                            id,
                            &format!("%count_{id}"),
                            "false",
                            &next_label,
                        ));
                        body.push_str(&format!("taken_{id}:\n"));
                    }
                    match target {
                        Ok(target) => {
                            body.push_str(&log_event(id, &format!("%count_{id}"), "taken", &target))
                        }
                        Err((status, reason)) => {
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                status,
                                reason,
                            );
                            body.push_str(&branch_to_stop(status));
                        }
                    }
                }
                6 => {
                    stop_site(
                        &mut sites,
                        &source.source_address,
                        Some(operation_index),
                        PcodeCfgLlvmStatus::IndirectFlow,
                        "BRANCHIND requires dynamic target resolution",
                    );
                    body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::IndirectFlow));
                }
                7 | 8 | 10 => {
                    let status = if source.opcode == 10 {
                        PcodeCfgLlvmStatus::Return
                    } else {
                        PcodeCfgLlvmStatus::Call
                    };
                    stop_site(
                        &mut sites,
                        &source.source_address,
                        Some(operation_index),
                        status,
                        format!("{} ends the emitted path", source.mnemonic),
                    );
                    body.push_str(&branch_to_stop(status));
                }
                2 | 3 => match memory_layout(source, &semantic.address_spaces) {
                    Ok(layout) => {
                        for (status, reason) in [
                            (
                                PcodeCfgLlvmStatus::MemorySpaceMismatch,
                                "guest RAM binding does not match P-code space ID",
                            ),
                            (
                                PcodeCfgLlvmStatus::MemoryUnknownAlias,
                                "pointer varnode bytes are unknown",
                            ),
                            (
                                PcodeCfgLlvmStatus::MemoryAddressOverflow,
                                "scaled memory address overflows u64",
                            ),
                            (
                                PcodeCfgLlvmStatus::MemoryOutOfBounds,
                                "memory access is outside guest RAM window",
                            ),
                        ] {
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                status,
                                reason,
                            );
                        }
                        if layout.kind == MemoryKind::Load {
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                PcodeCfgLlvmStatus::MemoryUnknownBytes,
                                "loaded guest RAM bytes are unknown",
                            );
                        } else {
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                PcodeCfgLlvmStatus::UnknownInput,
                                "STORE data varnode bytes are unknown",
                            );
                        }
                        emit_memory_operation(&layout, id, &mut body, &next_label)?;
                    }
                    Err((status, reason)) => {
                        stop_site(
                            &mut sites,
                            &source.source_address,
                            Some(operation_index),
                            status,
                            reason,
                        );
                        body.push_str(&branch_to_stop(status));
                    }
                },
                _ => {
                    let helper = if matches!(operation.effect, PcodeEffect::Assign { .. }) {
                        emit_pcode_exact_operation_llvm(operation)
                    } else {
                        Err("opaque P-code effect".into())
                    };
                    match helper {
                        Ok(helper) => {
                            let helper_name = format!("hydir_cfg_exact_{id}");
                            helper_ir.push_str(&helper.replacen(
                                "@hydir_pcode_exact(",
                                &format!("@{helper_name}("),
                                1,
                            ));
                            helper_ir.push('\n');
                            let mut checks = Vec::new();
                            for (input_index, input) in source.inputs.iter().enumerate() {
                                if let Some(check) = known_check(
                                    input,
                                    &format!("input_{id}_{input_index}"),
                                    &mut body,
                                )? {
                                    checks.push(check);
                                }
                            }
                            emit_known_guard(
                                &checks,
                                &format!("input_{id}"),
                                &mut body,
                                &format!("value_{id}"),
                                PcodeCfgLlvmStatus::UnknownInput,
                            );
                            body.push_str(&format!("value_{id}:\n"));
                            let mut arguments = Vec::new();
                            for (input_index, input) in source.inputs.iter().enumerate() {
                                if input.space == "const" {
                                    continue;
                                }
                                let bits = input.size * 8;
                                let raw = format!("%raw_{id}_{input_index}");
                                body.push_str(&format!(
                                    "  {raw} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
                                    pcode_space_id(&input.space)?, pcode_offset(input)?, input.size
                                ));
                                let value = if bits == 64 {
                                    raw
                                } else {
                                    let typed = format!("%typed_{id}_{input_index}");
                                    body.push_str(&format!(
                                        "  {typed} = trunc i64 {raw} to i{bits}\n"
                                    ));
                                    typed
                                };
                                arguments.push(format!("i{bits} {value}"));
                            }
                            let output = source
                                .output
                                .as_ref()
                                .ok_or("exact operation lacks output")?;
                            let bits = output.size * 8;
                            body.push_str(&format!(
                                "  %result_{id} = call i{bits} @{helper_name}({})\n",
                                arguments.join(", ")
                            ));
                            let raw = if bits == 64 {
                                format!("%result_{id}")
                            } else {
                                body.push_str(&format!(
                                    "  %result_raw_{id} = zext i{bits} %result_{id} to i64\n"
                                ));
                                format!("%result_raw_{id}")
                            };
                            let space_id = pcode_space_id(&output.space)?;
                            let output_offset = pcode_offset(output)?;
                            body.push_str(&format!(
                                "  call void @hydir_write_varnode(ptr %state, i32 {space_id}, i64 {output_offset}, i32 {}, i64 {raw})\n\
                                   call void @hydir_write_varnode(ptr %known, i32 {space_id}, i64 {output_offset}, i32 {}, i64 -1)\n",
                                output.size, output.size
                            ));
                            body.push_str(&log_event(
                                id,
                                &format!("%count_{id}"),
                                "effect",
                                &next_label,
                            ));
                        }
                        Err(reason) => {
                            let status = if matches!(operation.effect, PcodeEffect::Assign { .. }) {
                                PcodeCfgLlvmStatus::InvalidOperation
                            } else {
                                PcodeCfgLlvmStatus::OpaqueEffect
                            };
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                status,
                                reason,
                            );
                            body.push_str(&branch_to_stop(status));
                        }
                    }
                }
            }
        }
        body.push_str(&format!("end_{instruction_index}:\n"));
        match fallthroughs[instruction_index].as_slice() {
            [Some(target)] => {
                let target_key = (target.space.clone(), offset(&target.offset)?);
                if let Some(next) = index.get(&target_key) {
                    body.push_str(&format!("  br label %ins_{next}\n"));
                } else {
                    stop_site(
                        &mut sites,
                        &instruction.address,
                        None,
                        PcodeCfgLlvmStatus::OutOfFunction,
                        "fallthrough target is outside selected instructions",
                    );
                    body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::OutOfFunction));
                }
            }
            [] | [None] => {
                stop_site(
                    &mut sites,
                    &instruction.address,
                    None,
                    PcodeCfgLlvmStatus::UnresolvedFlow,
                    "no proven fallthrough target",
                );
                body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::UnresolvedFlow));
            }
            _ => {
                stop_site(
                    &mut sites,
                    &instruction.address,
                    None,
                    PcodeCfgLlvmStatus::AmbiguousFlow,
                    "multiple fallthrough candidates",
                );
                body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::AmbiguousFlow));
            }
        }
    }
    for status in [
        PcodeCfgLlvmStatus::Return,
        PcodeCfgLlvmStatus::Call,
        PcodeCfgLlvmStatus::OpaqueEffect,
        PcodeCfgLlvmStatus::UnsupportedMemory,
        PcodeCfgLlvmStatus::IndirectFlow,
        PcodeCfgLlvmStatus::UnresolvedFlow,
        PcodeCfgLlvmStatus::AmbiguousFlow,
        PcodeCfgLlvmStatus::OutOfFunction,
        PcodeCfgLlvmStatus::MalformedTarget,
        PcodeCfgLlvmStatus::UnknownInput,
        PcodeCfgLlvmStatus::StepBudget,
        PcodeCfgLlvmStatus::InvalidArguments,
        PcodeCfgLlvmStatus::VisitBudget,
        PcodeCfgLlvmStatus::InvalidOperation,
        PcodeCfgLlvmStatus::MemoryUnknownAlias,
        PcodeCfgLlvmStatus::MemoryUnknownBytes,
        PcodeCfgLlvmStatus::MemoryOutOfBounds,
        PcodeCfgLlvmStatus::MemoryAddressOverflow,
        PcodeCfgLlvmStatus::MemorySpaceMismatch,
        PcodeCfgLlvmStatus::MemoryUnsupportedLayout,
        PcodeCfgLlvmStatus::MemoryNonRamSpace,
        PcodeCfgLlvmStatus::MemoryUnknownSpace,
    ] {
        body.push_str(&format!(
            "{}:\n  ret i32 {}\n",
            stop_label(status),
            status.code()
        ));
    }
    body.push_str("}\n");
    let mut llvm_ir =
        String::from("; Hydir raw P-code concrete CFG path; equivalence unverified.\n\n");
    llvm_ir.push_str("declare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64)\n");
    llvm_ir.push_str("declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64)\n\n");
    llvm_ir.push_str(&helper_definitions(&byte_map));
    llvm_ir.push('\n');
    llvm_ir.push_str(&helper_ir);
    llvm_ir.push_str(&body);
    if llvm_ir.len() > MAX_LLVM_BYTES {
        return Err("P-code CFG LLVM module exceeds byte limit".into());
    }
    Ok(PcodeCfgLlvmArtifact {
        schema_version: PCODE_CFG_LLVM_VERSION,
        binary_sha256: snapshot.binary_sha256.clone(),
        start,
        source_operations: sources,
        stop_sites: sites,
        state_bytes: byte_map.len(),
        guest_ram_limit_bytes: guest_ram_limit,
        byte_map,
        state_abi: format!(
            "hydir-pcode-cfg-state-v2: @hydir_pcode_cfg(ptr state, ptr known, i32 guest_space_id, ptr guest_ram, ptr guest_known, i64 guest_base, i64 guest_len, ptr events, ptr event_count, i32 event_capacity, i32 max_steps) -> i32 status; state/known use byte_map; guest arrays hold guest_len bytes in guest_space_id from guest_base byte offset; known byte 0xff, unknown 0x00; event_count initialized by callee after argument validation; event_capacity>=max_steps; guest_len<={guest_ram_limit}; max_steps<=262144; arrays must be separate and allocated to their declared lengths"
        ),
        llvm_ir,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_ir::pcode::{
        PcodeConcreteState, PcodePathEvent, PcodePathStop, parse_ghidra_snapshot,
    };
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap()
    }

    fn calls_fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap()
    }

    fn register(offset: &str, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: "register".into(),
            offset: offset.into(),
            size,
        }
    }

    fn source_event_ids(
        artifact: &PcodeCfgLlvmArtifact,
        trace: &hydir_ir::pcode::PcodePathTrace,
    ) -> Vec<usize> {
        trace
            .events
            .iter()
            .filter_map(|event| match event {
                PcodePathEvent::Effect { operation } => Some(&operation.source),
                PcodePathEvent::Branch { source, .. } => Some(source),
                PcodePathEvent::Fallthrough { .. } => None,
            })
            .map(|source| {
                artifact
                    .source_operations
                    .iter()
                    .position(|candidate| {
                        candidate.address == source.source_address
                            && candidate.operation_index == source.sequence_index as usize
                    })
                    .unwrap()
            })
            .collect()
    }

    fn verify(llvm: &str) {
        if Command::new("opt").arg("--version").output().is_err() {
            return;
        }
        let mut child = Command::new("opt")
            .args(["-passes=verify", "-disable-output", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(llvm.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{llvm}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct GuestTestMemory {
        space_id: i32,
        base: u64,
        bytes: Vec<Option<u8>>,
        expected: Vec<(usize, u8, bool)>,
        expected_state: Vec<(String, String, u8, bool)>,
    }

    fn run_lli(
        artifact: &PcodeCfgLlvmArtifact,
        seed: &PcodeConcreteState,
        max_steps: u32,
        expected_status: PcodeCfgLlvmStatus,
        expected_events: &[usize],
        expected_rax_low: Option<u8>,
    ) {
        run_lli_with_guest(
            artifact,
            seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0,
                bytes: Vec::new(),
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            max_steps,
            expected_status,
            expected_events,
            expected_rax_low,
        );
    }

    fn run_lli_with_guest(
        artifact: &PcodeCfgLlvmArtifact,
        seed: &PcodeConcreteState,
        guest: &GuestTestMemory,
        max_steps: u32,
        expected_status: PcodeCfgLlvmStatus,
        expected_events: &[usize],
        expected_rax_low: Option<u8>,
    ) {
        if Command::new("lli").arg("--version").output().is_err() {
            return;
        }
        let state_size = artifact.state_bytes.max(1);
        let guest_size = guest.bytes.len().max(1);
        let event_capacity = max_steps.max(1);
        let mut main = format!(
            "define i32 @main() {{\nentry:\n  %state_array = alloca [{state_size} x i8]\n\
               %state = getelementptr [{state_size} x i8], ptr %state_array, i64 0, i64 0\n\
               %known_array = alloca [{state_size} x i8]\n\
               %known = getelementptr [{state_size} x i8], ptr %known_array, i64 0, i64 0\n\
               %guest_array = alloca [{guest_size} x i8]\n\
               %guest = getelementptr [{guest_size} x i8], ptr %guest_array, i64 0, i64 0\n\
               %guest_known_array = alloca [{guest_size} x i8]\n\
               %guest_mask = getelementptr [{guest_size} x i8], ptr %guest_known_array, i64 0, i64 0\n\
               %events_array = alloca [{event_capacity} x i32]\n\
               %events = getelementptr [{event_capacity} x i32], ptr %events_array, i64 0, i64 0\n\
               %event_count = alloca i32\n"
        );
        for byte in &artifact.byte_map {
            let known = seed
                .read_varnode(&PcodeVarnode {
                    space: byte.space.clone(),
                    offset: byte.offset.clone(),
                    size: 1,
                })
                .unwrap();
            main.push_str(&format!(
                "  %s{} = getelementptr i8, ptr %state, i64 {}\n  store i8 {}, ptr %s{}\n\
                   %k{} = getelementptr i8, ptr %known, i64 {}\n  store i8 {}, ptr %k{}\n",
                byte.index,
                byte.index,
                known.unwrap_or(0),
                byte.index,
                byte.index,
                byte.index,
                if known.is_some() { 255 } else { 0 },
                byte.index
            ));
        }
        for index in 0..guest_size {
            let known = guest.bytes.get(index).copied().flatten();
            main.push_str(&format!(
                "  %guest_s_{index} = getelementptr i8, ptr %guest, i64 {index}\n  store i8 {}, ptr %guest_s_{index}\n  %guest_k_{index} = getelementptr i8, ptr %guest_mask, i64 {index}\n  store i8 {}, ptr %guest_k_{index}\n",
                known.unwrap_or(0),
                if known.is_some() { 255 } else { 0 }
            ));
        }
        main.push_str(&format!(
            "  %status = call i32 @hydir_pcode_cfg(ptr %state, ptr %known, i32 {}, ptr %guest, ptr %guest_mask, i64 {}, i64 {}, ptr %events, ptr %event_count, i32 {event_capacity}, i32 {max_steps})\n\
               %count = load i32, ptr %event_count\n\
               %status_ok = icmp eq i32 %status, {}\n\
               %count_ok = icmp eq i32 %count, {}\n\
               %ok_initial = and i1 %status_ok, %count_ok\n",
            guest.space_id,
            guest.base,
            guest.bytes.len(),
            expected_status.code(),
            expected_events.len()
        ));
        let mut previous = "%ok_initial".to_owned();
        for (index, event) in expected_events.iter().enumerate() {
            main.push_str(&format!(
                "  %event_ptr_{index} = getelementptr i32, ptr %events, i32 {index}\n\
                   %event_{index} = load i32, ptr %event_ptr_{index}\n\
                   %event_ok_{index} = icmp eq i32 %event_{index}, {event}\n\
                   %ok_{index} = and i1 {previous}, %event_ok_{index}\n"
            ));
            previous = format!("%ok_{index}");
        }
        if let Some(expected) = expected_rax_low {
            let rax_index = artifact
                .byte_map
                .iter()
                .find(|byte| byte.space == "register" && byte.offset == "0x0")
                .unwrap()
                .index;
            main.push_str(&format!(
                "  %rax_ptr = getelementptr i8, ptr %state, i64 {rax_index}\n\
                   %rax = load i8, ptr %rax_ptr\n  %rax_ok = icmp eq i8 %rax, {expected}\n\
                   %ok_rax = and i1 {previous}, %rax_ok\n"
            ));
            previous = "%ok_rax".to_owned();
        }
        for (check, (index, value, known)) in guest.expected.iter().enumerate() {
            main.push_str(&format!(
                "  %guest_result_ptr_{check} = getelementptr i8, ptr %guest, i64 {index}\n  %guest_result_{check} = load i8, ptr %guest_result_ptr_{check}\n  %guest_value_ok_{check} = icmp eq i8 %guest_result_{check}, {value}\n  %guest_known_ptr_{check} = getelementptr i8, ptr %guest_mask, i64 {index}\n  %guest_known_result_{check} = load i8, ptr %guest_known_ptr_{check}\n  %guest_known_ok_{check} = icmp eq i8 %guest_known_result_{check}, {}\n  %guest_ok_{check} = and i1 %guest_value_ok_{check}, %guest_known_ok_{check}\n  %ok_guest_{check} = and i1 {previous}, %guest_ok_{check}\n",
                if *known { 255 } else { 0 }
            ));
            previous = format!("%ok_guest_{check}");
        }
        for (check, (space, offset, value, known)) in guest.expected_state.iter().enumerate() {
            let index = artifact
                .byte_map
                .iter()
                .find(|byte| &byte.space == space && &byte.offset == offset)
                .unwrap()
                .index;
            main.push_str(&format!(
                "  %state_result_ptr_{check} = getelementptr i8, ptr %state, i64 {index}\n  %state_result_{check} = load i8, ptr %state_result_ptr_{check}\n  %state_value_ok_{check} = icmp eq i8 %state_result_{check}, {value}\n  %state_known_ptr_{check} = getelementptr i8, ptr %known, i64 {index}\n  %state_known_result_{check} = load i8, ptr %state_known_ptr_{check}\n  %state_known_ok_{check} = icmp eq i8 %state_known_result_{check}, {}\n  %state_ok_{check} = and i1 %state_value_ok_{check}, %state_known_ok_{check}\n  %ok_state_{check} = and i1 {previous}, %state_ok_{check}\n",
                if *known { 255 } else { 0 }
            ));
            previous = format!("%ok_state_{check}");
        }
        main.push_str(&format!(
            "  %failed = xor i1 {previous}, true\n  %result = zext i1 %failed to i32\n  ret i32 %result\n}}\n"
        ));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), format!("{}\n{main}", artifact.llvm_ir)).unwrap();
        let output = Command::new("lli").arg(file.path()).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}\n{main}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn real_prism_branch_paths_verify_and_match_rust_event_prefixes() {
        let snapshot = fixture();
        let start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013d9".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&start)).unwrap();
        assert_eq!(artifact.schema_version, PCODE_CFG_LLVM_VERSION);
        assert_eq!(artifact.semantic_fidelity, SemanticFidelity::Unknown);
        assert!(
            artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MemoryUnknownAlias)
        );
        verify(&artifact.llvm_ir);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::UnknownInput,
            &[],
            None,
        );
        for (condition, expected_rax) in [(1, 0), (0, 1)] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(
                &PcodeVarnode {
                    space: "register".into(),
                    offset: "0x206".into(),
                    size: 1,
                },
                condition,
            )
            .unwrap();
            seed.write_varnode(
                &PcodeVarnode {
                    space: "register".into(),
                    offset: "0x0".into(),
                    size: 8,
                },
                0,
            )
            .unwrap();
            let rust = snapshot
                .execute_concrete_path(&seed, Some(&start), 8, 8)
                .unwrap();
            assert!(matches!(rust.stop, PcodePathStop::EffectBoundary { .. }));
            let events = rust
                .events
                .iter()
                .filter_map(|event| match event {
                    PcodePathEvent::Effect { operation } => Some(&operation.source),
                    PcodePathEvent::Branch { source, .. } => Some(source),
                    PcodePathEvent::Fallthrough { .. } => None,
                })
                .map(|source| {
                    artifact
                        .source_operations
                        .iter()
                        .position(|candidate| {
                            candidate.address == source.source_address
                                && candidate.operation_index == source.sequence_index as usize
                        })
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(events.len(), if condition == 0 { 2 } else { 1 });
            assert_eq!(
                rust.final_state
                    .read_varnode(&PcodeVarnode {
                        space: "register".into(),
                        offset: "0x0".into(),
                        size: 1,
                    })
                    .unwrap(),
                Some(expected_rax)
            );
            run_lli(
                &artifact,
                &seed,
                8,
                PcodeCfgLlvmStatus::MemoryUnknownAlias,
                &events,
                Some(expected_rax as u8),
            );
        }
    }

    #[test]
    fn synthetic_branch_loop_hits_runtime_operation_budget() {
        let mut snapshot = fixture();
        snapshot.selected_function.instructions.truncate(1);
        snapshot.selected_function.flow_edges.clear();
        let instruction = &mut snapshot.selected_function.instructions[0];
        let mut branch = instruction.pcode[0].clone();
        branch.mnemonic = "BRANCH".into();
        branch.opcode = 4;
        branch.output = None;
        branch.inputs = vec![PcodeVarnode {
            space: "ram".into(),
            offset: instruction.address.offset.clone(),
            size: 8,
        }];
        instruction.pcode = vec![branch];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        let rust = snapshot
            .execute_concrete_path(&PcodeConcreteState::default(), None, 3, 8)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::OperationBudget { .. }));
        assert_eq!(rust.events.len(), 3);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            3,
            PcodeCfgLlvmStatus::StepBudget,
            &[0, 0, 0],
            None,
        );
    }

    #[test]
    fn narrow_backward_relative_branch_and_unresolved_flow_are_explicit() {
        let mut snapshot = fixture();
        snapshot.selected_function.instructions.truncate(1);
        snapshot.selected_function.flow_edges.clear();
        let instruction = &mut snapshot.selected_function.instructions[0];
        let mut jump_forward = instruction.pcode[0].clone();
        jump_forward.mnemonic = "BRANCH".into();
        jump_forward.opcode = 4;
        jump_forward.output = None;
        jump_forward.inputs = vec![PcodeVarnode {
            space: "const".into(),
            offset: "0x2".into(),
            size: 1,
        }];
        let mut ret = jump_forward.clone();
        ret.mnemonic = "RETURN".into();
        ret.opcode = 10;
        ret.sequence_index = 1;
        ret.sequence_time = 1;
        ret.inputs = vec![PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 8,
        }];
        let mut jump_back = jump_forward.clone();
        jump_back.sequence_index = 2;
        jump_back.sequence_time = 2;
        jump_back.inputs[0].offset = "0xff".into();
        instruction.pcode = vec![jump_forward, ret, jump_back];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        let rust = snapshot
            .execute_concrete_path(&PcodeConcreteState::default(), None, 8, 8)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(rust.events.len(), 2);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::Return,
            &[0, 2],
            None,
        );

        snapshot.selected_function.instructions[0].pcode.truncate(1);
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        assert!(
            artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MalformedTarget)
        );
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::MalformedTarget,
            &[],
            None,
        );

        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode[0].mnemonic = "COPY".into();
        instruction.pcode[0].opcode = 1;
        instruction.pcode[0].output = Some(PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 8,
        });
        instruction.pcode[0].inputs = vec![PcodeVarnode {
            space: "const".into(),
            offset: "0x1".into(),
            size: 8,
        }];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::UnresolvedFlow,
            &[0],
            Some(1),
        );
    }

    #[test]
    fn real_ghidra_store_and_load_match_rust_concrete_paths() {
        let snapshot = calls_fixture();
        let store_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013ad".into(),
        };
        let store_artifact = emit_pcode_cfg_llvm(&snapshot, Some(&store_start)).unwrap();
        assert_eq!(
            store_artifact.guest_ram_limit_bytes,
            PCODE_CFG_GUEST_RAM_MAX_BYTES - store_artifact.state_bytes as u64
        );
        assert!(store_artifact.llvm_ir.contains(&format!(
            "%guest_len, {}",
            store_artifact.guest_ram_limit_bytes
        )));
        verify(&store_artifact.llvm_ir);
        let mut store_seed = PcodeConcreteState::default();
        store_seed
            .write_varnode(&register("0x20", 8), 0x1008)
            .unwrap();
        let store_rust = snapshot
            .execute_concrete_path(&store_seed, Some(&store_start), 8, 4)
            .unwrap();
        assert!(matches!(store_rust.stop, PcodePathStop::Call { .. }));
        assert_eq!(
            store_rust
                .final_state
                .read_memory("ram", 0x1000, 8)
                .unwrap(),
            Some(0x2013b2)
        );
        let store_events = source_event_ids(&store_artifact, &store_rust);
        assert_eq!(store_events.len(), 2);
        let written = 0x2013b2u64.to_le_bytes();
        run_lli_with_guest(
            &store_artifact,
            &store_seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: vec![None; 8],
                expected: written
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| (i, *byte, true))
                    .collect(),
                expected_state: vec![("register".into(), "0x20".into(), 0x00, true)],
            },
            8,
            PcodeCfgLlvmStatus::Call,
            &store_events,
            None,
        );

        let load_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013b6".into(),
        };
        let load_artifact = emit_pcode_cfg_llvm(&snapshot, Some(&load_start)).unwrap();
        verify(&load_artifact.llvm_ir);
        let mut load_seed = PcodeConcreteState::default();
        load_seed
            .write_varnode(&register("0x20", 8), 0x1000)
            .unwrap();
        let value = 0x1122_3344_5566_7788u64;
        load_seed.write_memory("ram", 0x1000, 8, value).unwrap();
        let load_rust = snapshot
            .execute_concrete_path(&load_seed, Some(&load_start), 8, 4)
            .unwrap();
        assert!(matches!(load_rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(
            load_rust
                .final_state
                .read_varnode(&register("0x288", 8))
                .unwrap(),
            Some(value)
        );
        let load_events = source_event_ids(&load_artifact, &load_rust);
        assert_eq!(load_events.len(), 2);
        run_lli_with_guest(
            &load_artifact,
            &load_seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: value.to_le_bytes().into_iter().map(Some).collect(),
                expected: Vec::new(),
                expected_state: value
                    .to_le_bytes()
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| ("register".into(), format!("0x{:x}", 0x288 + i), *byte, true))
                    .collect(),
            },
            8,
            PcodeCfgLlvmStatus::Return,
            &load_events,
            None,
        );
    }

    #[test]
    fn guest_ram_boundaries_stop_before_memory_effects() {
        let snapshot = calls_fixture();
        let start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013b6".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&start)).unwrap();
        verify(&artifact.llvm_ir);
        let known_ram = GuestTestMemory {
            space_id: 433,
            base: 0x1000,
            bytes: vec![Some(0x42); 8],
            expected: Vec::new(),
            expected_state: Vec::new(),
        };
        run_lli_with_guest(
            &artifact,
            &PcodeConcreteState::default(),
            &known_ram,
            8,
            PcodeCfgLlvmStatus::MemoryUnknownAlias,
            &[],
            None,
        );

        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x20", 8), 0x1000).unwrap();
        let mut partial_ram = vec![Some(0x42); 8];
        partial_ram[3] = None;
        let unknown_ram = GuestTestMemory {
            bytes: partial_ram,
            ..known_ram
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &unknown_ram,
            8,
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
            &[],
            None,
        );
        let short_ram = GuestTestMemory {
            bytes: vec![Some(0x42); 4],
            ..unknown_ram
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &short_ram,
            8,
            PcodeCfgLlvmStatus::MemoryOutOfBounds,
            &[],
            None,
        );
        let wrong_space = GuestTestMemory {
            space_id: 42,
            bytes: vec![Some(0x42); 8],
            ..short_ram
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &wrong_space,
            8,
            PcodeCfgLlvmStatus::MemorySpaceMismatch,
            &[],
            None,
        );
        seed.write_varnode(&register("0x20", 8), u64::MAX).unwrap();
        let right_space = GuestTestMemory {
            space_id: 433,
            ..wrong_space
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &right_space,
            8,
            PcodeCfgLlvmStatus::MemoryAddressOverflow,
            &[],
            None,
        );

        let mut non_ram = snapshot.clone();
        non_ram.selected_function.instructions[3].pcode[0].inputs[0].offset = "0x35".into();
        let non_ram_artifact = emit_pcode_cfg_llvm(&non_ram, Some(&start)).unwrap();
        verify(&non_ram_artifact.llvm_ir);
        assert!(
            non_ram_artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MemoryNonRamSpace)
        );
        run_lli_with_guest(
            &non_ram_artifact,
            &seed,
            &right_space,
            8,
            PcodeCfgLlvmStatus::MemoryNonRamSpace,
            &[],
            None,
        );
    }

    #[test]
    fn addressable_unit_scaling_and_unknown_store_data_match_rust() {
        let mut snapshot = calls_fixture();
        snapshot
            .address_spaces
            .iter_mut()
            .find(|space| space.name == "ram")
            .unwrap()
            .addressable_unit_size = 2;
        let load_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013b6".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&load_start)).unwrap();
        verify(&artifact.llvm_ir);
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x20", 8), 0x800).unwrap();
        let value = 0x0102_0304_0506_0708u64;
        seed.write_memory("ram", 0x1000, 8, value).unwrap();
        let rust = snapshot
            .execute_concrete_path(&seed, Some(&load_start), 8, 4)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(
            rust.final_state
                .read_varnode(&register("0x288", 8))
                .unwrap(),
            Some(value)
        );
        let events = source_event_ids(&artifact, &rust);
        run_lli_with_guest(
            &artifact,
            &seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: value.to_le_bytes().into_iter().map(Some).collect(),
                expected: Vec::new(),
                expected_state: vec![("register".into(), "0x288".into(), 0x08, true)],
            },
            8,
            PcodeCfgLlvmStatus::Return,
            &events,
            None,
        );

        let mut store_snapshot = calls_fixture();
        store_snapshot.selected_function.instructions[1].pcode[1].inputs[2] = register("0x0", 8);
        let store_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013ad".into(),
        };
        let store_artifact = emit_pcode_cfg_llvm(&store_snapshot, Some(&store_start)).unwrap();
        verify(&store_artifact.llvm_ir);
        let mut store_seed = PcodeConcreteState::default();
        store_seed
            .write_varnode(&register("0x20", 8), 0x1008)
            .unwrap();
        let store_rust = store_snapshot
            .execute_concrete_path(&store_seed, Some(&store_start), 8, 4)
            .unwrap();
        assert!(matches!(
            store_rust.stop,
            PcodePathStop::EffectBoundary {
                boundary: hydir_ir::pcode::PcodeExecutionStop::MissingInput { input_index: 2, .. }
            }
        ));
        let events = source_event_ids(&store_artifact, &store_rust);
        assert_eq!(events.len(), 1);
        run_lli_with_guest(
            &store_artifact,
            &store_seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: vec![None; 8],
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            8,
            PcodeCfgLlvmStatus::UnknownInput,
            &events,
            None,
        );
    }
}
