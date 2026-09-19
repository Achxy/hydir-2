//! Lossless, bounded Irene3/Anvill interoperability boundary.
//!
//! The original protobuf bytes remain authoritative so forwarding an artifact
//! never discards unknown fields. The decoded pinned schema is a validated
//! view used by native HydIR compatibility services.

use hydir_api::specification::{
    Arch, BaseType, BlockContext, Callable, CodeBlock, FunctionLinkage, Os, Parameter,
    Specification, TypeSpec, Value, ValueMapping, Variable, program_address, type_spec, value,
    value_domain,
};
use hydir_backend::import_elf;
use hydir_core::{
    Address, AddressKind, ExitStackRelation, FactProvenance, FactSource, InteriorEntryEvidence,
    PhysicalLocationKind, PhysicalLocationSpec, REGION_SPEC_VERSION, RegionSpec,
    VariableLocationSpec, validate_region_spec,
};
use object::{Object, ObjectSegment};
use prost::Message;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const IRENE3_COMMIT: &str = "d97aee937ebb6d1cb8a362748c56414404eb75ff";
pub const ANVILL_SCHEMA_COMMIT: &str = "52f9638b023417c9bdbbb1791867cacc38c68888";
pub const UPSTREAM_CHUNK_BYTES: usize = 2_000_000;
pub const MAX_SPECIFICATION_BYTES: usize = 64 * 1024 * 1024;

const MAX_FUNCTIONS: usize = 8_192;
const MAX_BLOCKS: usize = 65_536;
const MAX_MEMORY_RANGES: usize = 4_096;
const MAX_GLOBALS: usize = 65_536;
const MAX_SYMBOLS: usize = 65_536;
const MAX_CALLSITES: usize = 65_536;
const MAX_TYPE_ALIASES: usize = 65_536;
const MAX_NAME_BYTES: usize = 4_096;
const MAX_TYPE_DEPTH: usize = 64;
const MAX_TYPE_NODES: usize = 1_000_000;
const MAX_VALUE_NODES: usize = 1_000_000;
const MAX_ITEMS_PER_FIELD: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inventory {
    pub functions: usize,
    pub blocks: usize,
    pub memory_ranges: usize,
    pub globals: usize,
    pub symbols: usize,
    pub callsites: usize,
}

#[derive(Clone, Debug)]
pub struct SpecificationDocument {
    original: Vec<u8>,
    source_sha256: String,
    specification: Specification,
    inventory: Inventory,
}

impl SpecificationDocument {
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_SPECIFICATION_BYTES {
            return Err(format!(
                "Anvill specification must be 1..={MAX_SPECIFICATION_BYTES} bytes"
            ));
        }
        let specification = Specification::decode(bytes)
            .map_err(|error| format!("invalid Anvill specification protobuf: {error}"))?;
        let inventory = validate_specification(&specification)?;
        Ok(Self {
            original: bytes.to_vec(),
            source_sha256: format!("{:x}", Sha256::digest(bytes)),
            specification,
            inventory,
        })
    }

    /// Byte-for-byte input, including fields newer than the pinned schema.
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Deterministic encoding of fields understood by the pinned schema.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.specification.encode_to_vec()
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub fn specification(&self) -> &Specification {
        &self.specification
    }

    pub fn inventory(&self) -> &Inventory {
        &self.inventory
    }

    pub fn require_stable_target(&self) -> Result<(), String> {
        if self.specification.arch != Arch::Amd64 as i32 {
            return Err("stable Irene3 compatibility requires ARCH_AMD64".to_owned());
        }
        if self.specification.operating_system != Os::Linux as i32 {
            return Err("stable Irene3 compatibility requires OS_LINUX".to_owned());
        }
        Ok(())
    }

    pub fn block(&self, uid: u64) -> Option<&CodeBlock> {
        self.specification
            .functions
            .iter()
            .find_map(|function| function.blocks.get(&uid))
    }

    /// Return an exact selected block extent only when one executable memory
    /// range contains it. Overlapping mappings are an ambiguity, not a tie to
    /// resolve heuristically.
    pub fn block_bytes(&self, uid: u64) -> Result<&[u8], String> {
        let block = self
            .block(uid)
            .ok_or_else(|| format!("Anvill block UID {uid} does not exist"))?;
        let end = block
            .address
            .checked_add(u64::from(block.size))
            .ok_or_else(|| format!("Anvill block UID {uid} address range overflows"))?;
        let mut result = None;
        for range in &self.specification.memory_ranges {
            let range_end = range
                .address
                .checked_add(range.values.len() as u64)
                .ok_or_else(|| "Anvill memory range address overflows".to_owned())?;
            if range.is_executable && range.address <= block.address && end <= range_end {
                if result.is_some() {
                    return Err(format!(
                        "Anvill block UID {uid} is covered by multiple executable memory ranges"
                    ));
                }
                let start_offset = usize::try_from(block.address - range.address)
                    .map_err(|_| "Anvill block offset does not fit usize".to_owned())?;
                let end_offset = start_offset
                    .checked_add(block.size as usize)
                    .ok_or_else(|| "Anvill block slice overflows".to_owned())?;
                result = Some(&range.values[start_offset..end_offset]);
            }
        }
        result.ok_or_else(|| {
            format!("Anvill block UID {uid} lacks one exact executable memory mapping")
        })
    }

    /// Convert one Anvill basic block into a canonical RegionSpec after
    /// proving its bytes against the supplied linked ELF. Imported liveness
    /// remains attributed to the interchange artifact and never becomes a
    /// native proof merely because the protobuf decoded successfully.
    pub fn region_spec_for_elf(&self, elf_bytes: &[u8], uid: u64) -> Result<RegionSpec, String> {
        self.require_stable_target()?;
        let program = import_elf(elf_bytes).map_err(|error| error.to_string())?;
        let file = object::File::parse(elf_bytes)
            .map_err(|error| format!("ELF parse failed during Anvill binding: {error}"))?;
        if file.kind() == object::ObjectKind::Relocatable {
            return Err("Anvill RegionSpec binding requires a linked ELF".to_owned());
        }
        let (function, block) = self
            .specification
            .functions
            .iter()
            .find_map(|function| function.blocks.get(&uid).map(|block| (function, block)))
            .ok_or_else(|| format!("Anvill block UID {uid} does not exist"))?;
        let spec_bytes = self.block_bytes(uid)?;
        let (binary_address, elf_region) = bind_elf_block(
            &file,
            function,
            block,
            self.specification.image_base,
            spec_bytes,
        )?;
        debug_assert_eq!(spec_bytes, elf_region);
        let address_bias = block.address.checked_sub(binary_address).ok_or_else(|| {
            "Anvill-to-ELF address translation uses an unsupported negative bias".to_owned()
        })?;
        let end = binary_address
            .checked_add(u64::from(block.size))
            .ok_or_else(|| format!("Anvill block UID {uid} address range overflows"))?;
        let provenance = interchange_provenance(self.source_sha256());
        let context = function.block_context.get(&uid);
        let (physical_live_in, entry_variables) = context.map_or_else(
            || Ok((Vec::new(), std::collections::BTreeMap::new())),
            |context| locations(&context.live_at_entries, &provenance),
        )?;
        let (physical_live_out, exit_variables) = context.map_or_else(
            || Ok((Vec::new(), std::collections::BTreeMap::new())),
            |context| locations(&context.live_at_exits, &provenance),
        )?;
        let variable_locations = entry_variables
            .into_iter()
            .filter_map(|(key, (variable, location))| {
                exit_variables
                    .contains_key(&key)
                    .then(|| VariableLocationSpec {
                        variable,
                        location,
                        valid_from: Address(binary_address),
                        valid_to: Address(end),
                        provenance: provenance.clone(),
                    })
            })
            .collect::<Vec<_>>();
        let stack_delta = context
            .map(|context| {
                let entry = stack_displacement(&context.symvals_at_entry)?;
                let exit = stack_displacement(&context.symvals_at_exit)?;
                match (entry, exit) {
                    (Some(entry), Some(exit)) => exit
                        .checked_sub(entry)
                        .map(Some)
                        .ok_or_else(|| "Anvill region stack delta overflows".to_owned()),
                    _ => Ok(None),
                }
            })
            .transpose()?
            .flatten();
        let exits = block
            .outgoing_blocks
            .iter()
            .map(|target| {
                function
                    .blocks
                    .get(target)
                    .map(|successor| {
                        normalize_address(successor.address, address_bias).map(Address)
                    })
                    .ok_or_else(|| format!("Anvill block UID {uid} has missing successor {target}"))
                    .and_then(|address| address)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let exit_stack_relations = stack_delta.map_or_else(Vec::new, |rsp_delta| {
            exits
                .iter()
                .copied()
                .map(|exit| ExitStackRelation {
                    exit,
                    rsp_delta,
                    alignment_mod_16: None,
                    provenance: provenance.clone(),
                })
                .collect()
        });
        let mut observed_interior_entries = Vec::new();
        for other_function in &self.specification.functions {
            for other in other_function.blocks.values() {
                let _ = other_function;
                let other_address = normalize_address(other.address, address_bias)?;
                if other.uid != uid && (binary_address + 1..end).contains(&other_address) {
                    observed_interior_entries.push(InteriorEntryEvidence {
                        entry: Address(other_address),
                        source: None,
                        reason: format!(
                            "Anvill block UID {} begins inside selected block UID {uid}",
                            other.uid
                        ),
                        provenance: provenance.clone(),
                    });
                }
            }
        }
        let relocations = program
            .relocations
            .into_iter()
            .filter(|relocation| {
                relocation.address_kind == AddressKind::Virtual
                    && (binary_address..end).contains(&relocation.location.0)
            })
            .collect();
        let mut unresolved_facts = vec![
            "stack alignment at region entry and exits is not established".to_owned(),
            "absence of undiscovered indirect interior entries is not proven".to_owned(),
            "global references and general memory effects are not yet recovered".to_owned(),
            "relocation applicability after patch placement is not analyzed".to_owned(),
        ];
        if context.is_none() {
            unresolved_facts
                .push("Anvill block context and physical live state are absent".to_owned());
        }
        if stack_delta.is_none() {
            unresolved_facts.push("Anvill block stack relation is unresolved".to_owned());
        }
        if !observed_interior_entries.is_empty() {
            unresolved_facts.push("another Anvill block starts inside this region".to_owned());
        }
        let symbol_name = if block.name.is_empty() {
            format!("irene3_uid_{uid}")
        } else {
            block.name.clone()
        };
        let region = RegionSpec {
            schema_version: REGION_SPEC_VERSION,
            binary_sha256: program.binary_sha256,
            symbol_name,
            address_kind: AddressKind::Virtual,
            entry: Address(binary_address),
            byte_length: u64::from(block.size),
            bytes_sha256: format!("{:x}", Sha256::digest(spec_bytes)),
            bytes_hex: spec_bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            exits,
            relocations,
            observed_interior_entries,
            live_in: None,
            live_out: None,
            physical_live_in,
            physical_live_out,
            stack_delta,
            stack_entry_alignment: None,
            exit_stack_relations,
            global_references: Vec::new(),
            variable_locations,
            assumptions: Vec::new(),
            unresolved_facts,
            replacement_ready: false,
            provenance,
        };
        validate_region_spec(&region)?;
        Ok(region)
    }
}

fn bind_elf_block<'a>(
    file: &'a object::File<'a>,
    function: &hydir_api::specification::Function,
    block: &CodeBlock,
    image_base: u64,
    expected: &[u8],
) -> Result<(u64, &'a [u8]), String> {
    let mut candidates = BTreeSet::from([block.address]);
    if image_base != 0
        && let Some(rebased) = block.address.checked_sub(image_base)
    {
        candidates.insert(rebased);
    }
    if let Ok(address) = binary_block_address(function, block, image_base) {
        candidates.insert(address);
    }
    let mut matches = Vec::new();
    for address in candidates {
        if let Ok(actual) = elf_bytes_at(file, address, u64::from(block.size))
            && actual == expected
        {
            matches.push((address, actual));
        }
    }
    match matches.as_slice() {
        [(address, bytes)] => Ok((*address, *bytes)),
        [] => Err(format!(
            "Anvill block UID {} has no byte-identical mapping in the supplied ELF",
            block.uid
        )),
        _ => Err(format!(
            "Anvill block UID {} matches multiple ELF address interpretations",
            block.uid
        )),
    }
}

fn normalize_address(specification_address: u64, bias: u64) -> Result<u64, String> {
    specification_address
        .checked_sub(bias)
        .ok_or_else(|| "Anvill-to-ELF address translation underflows".to_owned())
}

fn binary_block_address(
    function: &hydir_api::specification::Function,
    block: &CodeBlock,
    image_base: u64,
) -> Result<u64, String> {
    if let Some(binary) = function
        .binary_addr
        .as_ref()
        .and_then(|address| address.inner.as_ref())
    {
        match binary {
            program_address::Inner::InternalAddress(function_address) => {
                let displacement = block
                    .address
                    .checked_sub(function.entry_address)
                    .ok_or_else(|| {
                        format!(
                            "Anvill block UID {} precedes its function entry address",
                            block.uid
                        )
                    })?;
                return function_address
                    .checked_add(displacement)
                    .ok_or_else(|| "normalized Anvill block address overflows".to_owned());
            }
            program_address::Inner::ExtAddress(relative) => {
                let function_address = if relative.displacement >= 0 {
                    relative
                        .entry_vaddr
                        .checked_add(relative.displacement as u64)
                } else {
                    relative
                        .entry_vaddr
                        .checked_sub(relative.displacement.unsigned_abs())
                }
                .ok_or_else(|| "relative Anvill function address overflows".to_owned())?;
                let displacement = block
                    .address
                    .checked_sub(function.entry_address)
                    .ok_or_else(|| {
                        format!(
                            "Anvill block UID {} precedes its function entry address",
                            block.uid
                        )
                    })?;
                return function_address
                    .checked_add(displacement)
                    .ok_or_else(|| "normalized Anvill block address overflows".to_owned());
            }
        }
    }
    if image_base != 0 && block.address >= image_base {
        Ok(block.address - image_base)
    } else {
        Ok(block.address)
    }
}

fn elf_bytes_at<'a>(
    file: &'a object::File<'a>,
    address: u64,
    size: u64,
) -> Result<&'a [u8], String> {
    let end = address
        .checked_add(size)
        .ok_or_else(|| "ELF region address range overflows".to_owned())?;
    let mut result = None;
    for segment in file.segments() {
        let data = segment
            .data()
            .map_err(|error| format!("ELF segment read failed: {error}"))?;
        let segment_end = segment
            .address()
            .checked_add(data.len() as u64)
            .ok_or_else(|| "ELF segment address range overflows".to_owned())?;
        if segment.address() <= address && end <= segment_end {
            if result.is_some() {
                return Err("ELF region is covered by multiple file-backed segments".to_owned());
            }
            let start = usize::try_from(address - segment.address())
                .map_err(|_| "ELF region offset does not fit usize".to_owned())?;
            let finish = start
                .checked_add(size as usize)
                .ok_or_else(|| "ELF region slice overflows".to_owned())?;
            result = Some(&data[start..finish]);
        }
    }
    result.ok_or_else(|| "ELF region is not contained in one file-backed segment".to_owned())
}

type LocationKey = (String, String, u16, Option<String>);
type NamedLocations = std::collections::BTreeMap<LocationKey, (String, PhysicalLocationSpec)>;

fn locations(
    parameters: &[Parameter],
    provenance: &FactProvenance,
) -> Result<(Vec<PhysicalLocationSpec>, NamedLocations), String> {
    let mut physical = std::collections::BTreeMap::<LocationKey, PhysicalLocationSpec>::new();
    let mut named = NamedLocations::new();
    for (index, parameter) in parameters.iter().enumerate() {
        let variable_name = parameter
            .name
            .clone()
            .unwrap_or_else(|| format!("live_{index}"));
        let Some(variable) = &parameter.repr_var else {
            return Err(format!(
                "Anvill live variable {variable_name} lacks a representation"
            ));
        };
        let type_name = variable.r#type.as_ref().map(type_name);
        let type_width = variable.r#type.as_ref().and_then(type_width_bits);
        for location in &variable.values {
            let (name, kind, width_bits) = match &location.inner_value {
                Some(value::InnerValue::Reg(register)) => (
                    register.register_name.clone(),
                    PhysicalLocationKind::Register,
                    register
                        .subreg_sz
                        .and_then(|width| u16::try_from(width).ok())
                        .or(type_width),
                ),
                Some(value::InnerValue::Mem(memory)) => {
                    let width = memory
                        .size
                        .checked_mul(8)
                        .and_then(|width| u16::try_from(width).ok());
                    if let Some(base) = &memory.base_reg {
                        (
                            format!("[{base}{:+#x}]", memory.offset),
                            if base.eq_ignore_ascii_case("rsp") {
                                PhysicalLocationKind::Stack
                            } else {
                                PhysicalLocationKind::Memory
                            },
                            width,
                        )
                    } else {
                        (
                            format!("[0x{:x}]", memory.offset as u64),
                            PhysicalLocationKind::Memory,
                            width,
                        )
                    }
                }
                None => {
                    return Err(format!(
                        "Anvill live variable {variable_name} has an empty physical location"
                    ));
                }
            };
            let width_bits = width_bits.ok_or_else(|| {
                format!("Anvill live variable {variable_name} has no bounded physical width")
            })?;
            if !matches!(
                width_bits,
                1 | 8 | 16 | 24 | 32 | 64 | 80 | 96 | 128 | 256 | 512
            ) {
                return Err(format!(
                    "Anvill live variable {variable_name} uses unsupported width {width_bits}"
                ));
            }
            let kind_name = match kind {
                PhysicalLocationKind::Register => "register",
                PhysicalLocationKind::Flag => "flag",
                PhysicalLocationKind::Stack => "stack",
                PhysicalLocationKind::Memory => "memory",
            }
            .to_owned();
            let key = (name.clone(), kind_name, width_bits, type_name.clone());
            let fact = PhysicalLocationSpec {
                name,
                kind,
                width_bits,
                type_name: type_name.clone(),
                provenance: provenance.clone(),
            };
            physical.entry(key.clone()).or_insert_with(|| fact.clone());
            let variable_key = (
                format!("{variable_name}:{}", key.0),
                key.1.clone(),
                key.2,
                key.3.clone(),
            );
            named.insert(variable_key, (variable_name.clone(), fact));
        }
    }
    Ok((physical.into_values().collect(), named))
}

fn stack_displacement(mappings: &[ValueMapping]) -> Result<Option<i64>, String> {
    let mut result = None;
    for mapping in mappings {
        let is_rsp = mapping.target_value.as_ref().is_some_and(|variable| {
            variable.values.iter().any(|location| {
                matches!(
                    &location.inner_value,
                    Some(value::InnerValue::Reg(register))
                        if register.register_name.eq_ignore_ascii_case("rsp")
                )
            })
        });
        if !is_rsp {
            continue;
        }
        let displacement = mapping
            .curr_val
            .as_ref()
            .and_then(|domain| match domain.inner {
                Some(value_domain::Inner::StackDisp(value)) => Some(value),
                _ => None,
            });
        if let Some(displacement) = displacement {
            if result.is_some_and(|previous| previous != displacement) {
                return Err("Anvill block has conflicting RSP affine equalities".to_owned());
            }
            result = Some(displacement);
        }
    }
    Ok(result)
}

fn type_width_bits(r#type: &TypeSpec) -> Option<u16> {
    match r#type.r#type.as_ref()? {
        type_spec::Type::Base(base) => match BaseType::try_from(*base).ok()? {
            BaseType::BtBool => Some(1),
            BaseType::BtChar
            | BaseType::BtSchar
            | BaseType::BtUchar
            | BaseType::BtI8
            | BaseType::BtU8 => Some(8),
            BaseType::BtI16 | BaseType::BtU16 | BaseType::BtFl16 => Some(16),
            BaseType::BtI24 | BaseType::BtU24 => Some(24),
            BaseType::BtI32 | BaseType::BtU32 | BaseType::BtFl32 => Some(32),
            BaseType::BtI64 | BaseType::BtU64 | BaseType::BtFl64 | BaseType::BtM64 => Some(64),
            BaseType::BtFl80 => Some(80),
            BaseType::BtFl96 => Some(96),
            BaseType::BtI128 | BaseType::BtU128 | BaseType::BtFl128 => Some(128),
            BaseType::BtVoid | BaseType::BtPadding => None,
        },
        type_spec::Type::Pointer(_) | type_spec::Type::Function(_) => Some(64),
        type_spec::Type::Vector(vector) => type_width_bits(vector.base.as_deref()?)
            .and_then(|width| width.checked_mul(u16::try_from(vector.size).ok()?)),
        type_spec::Type::Array(array) => type_width_bits(array.base.as_deref()?)
            .and_then(|width| width.checked_mul(u16::try_from(array.size).ok()?)),
        type_spec::Type::Struct(_) | type_spec::Type::Unknown(_) | type_spec::Type::Alias(_) => {
            None
        }
    }
}

fn type_name(r#type: &TypeSpec) -> String {
    match r#type.r#type.as_ref() {
        Some(type_spec::Type::Base(base)) => BaseType::try_from(*base)
            .map(|base| {
                base.as_str_name()
                    .strip_prefix("BT_")
                    .unwrap_or(base.as_str_name())
                    .to_ascii_lowercase()
            })
            .unwrap_or_else(|_| format!("unknown_base_{base}")),
        Some(type_spec::Type::Pointer(_)) => "ptr".to_owned(),
        Some(type_spec::Type::Vector(vector)) => format!("vector[{}]", vector.size),
        Some(type_spec::Type::Array(array)) => format!("array[{}]", array.size),
        Some(type_spec::Type::Struct(structure)) => structure.identifier.map_or_else(
            || "struct".to_owned(),
            |identifier| format!("struct#{identifier}"),
        ),
        Some(type_spec::Type::Function(_)) => "function".to_owned(),
        Some(type_spec::Type::Unknown(width)) => format!("unknown[{width}]"),
        Some(type_spec::Type::Alias(alias)) => format!("alias#{alias}"),
        None => "unspecified".to_owned(),
    }
}

fn interchange_provenance(source_sha256: &str) -> FactProvenance {
    FactProvenance {
        source: FactSource::InterchangeImport,
        scope: format!(
            "Anvill protobuf from Irene3 {IRENE3_COMMIT}; source sha256:{source_sha256}"
        ),
    }
}

fn validate_specification(specification: &Specification) -> Result<Inventory, String> {
    bounded("functions", specification.functions.len(), MAX_FUNCTIONS)?;
    bounded(
        "memory ranges",
        specification.memory_ranges.len(),
        MAX_MEMORY_RANGES,
    )?;
    bounded(
        "global variables",
        specification.global_variables.len(),
        MAX_GLOBALS,
    )?;
    bounded("symbols", specification.symbols.len(), MAX_SYMBOLS)?;
    bounded("callsites", specification.callsites.len(), MAX_CALLSITES)?;
    bounded(
        "type aliases",
        specification.type_aliases.len(),
        MAX_TYPE_ALIASES,
    )?;
    bounded_name("image name", &specification.image_name)?;

    let mut total_memory = 0usize;
    for range in &specification.memory_ranges {
        range
            .address
            .checked_add(range.values.len() as u64)
            .ok_or_else(|| "Anvill memory range address overflows".to_owned())?;
        total_memory = total_memory
            .checked_add(range.values.len())
            .ok_or_else(|| "Anvill memory byte count overflows".to_owned())?;
        if total_memory > MAX_SPECIFICATION_BYTES {
            return Err("Anvill memory ranges exceed the 64 MiB byte limit".to_owned());
        }
    }

    let mut block_uids = BTreeSet::new();
    let mut block_count = 0usize;
    let mut type_nodes = 0usize;
    let mut value_nodes = 0usize;
    for function in &specification.functions {
        block_count = block_count
            .checked_add(function.blocks.len())
            .ok_or_else(|| "Anvill block count overflows".to_owned())?;
        bounded("blocks", block_count, MAX_BLOCKS)?;
        if function.blocks.is_empty()
            && function.func_linkage == FunctionLinkage::NormalUnspecified as i32
        {
            return Err(format!(
                "Anvill function at 0x{:x} has no code blocks",
                function.entry_address
            ));
        }
        if !function.blocks.is_empty() && !function.blocks.contains_key(&function.entry_uid) {
            return Err(format!(
                "Anvill function at 0x{:x} has a missing entry UID {}",
                function.entry_address, function.entry_uid
            ));
        }
        for (key, block) in &function.blocks {
            if *key != block.uid {
                return Err(format!(
                    "Anvill block map key {key} does not match embedded UID {}",
                    block.uid
                ));
            }
            if block.size == 0 {
                return Err(format!("Anvill block UID {key} has zero size"));
            }
            block
                .address
                .checked_add(u64::from(block.size))
                .ok_or_else(|| format!("Anvill block UID {key} address range overflows"))?;
            bounded_name("block name", &block.name)?;
            bounded(
                "block incoming edges",
                block.incoming_blocks.len(),
                MAX_ITEMS_PER_FIELD,
            )?;
            bounded(
                "block outgoing edges",
                block.outgoing_blocks.len(),
                MAX_ITEMS_PER_FIELD,
            )?;
            bounded(
                "block context assignments",
                block.context_assignments.len(),
                MAX_ITEMS_PER_FIELD,
            )?;
            for assignment in block.context_assignments.keys() {
                bounded_name("context assignment name", assignment)?;
            }
            if !block_uids.insert(*key) {
                return Err(format!("duplicate Anvill block UID {key}"));
            }
        }
        for (key, block) in &function.blocks {
            for edge in block.incoming_blocks.iter().chain(&block.outgoing_blocks) {
                if !function.blocks.contains_key(edge) {
                    return Err(format!(
                        "Anvill block UID {key} references missing same-function edge UID {edge}"
                    ));
                }
            }
        }
        for context_uid in function.block_context.keys() {
            if !function.blocks.contains_key(context_uid) {
                return Err(format!(
                    "Anvill block context references missing UID {context_uid}"
                ));
            }
        }
        for context in function.block_context.values() {
            validate_block_context(context, &mut type_nodes, &mut value_nodes)?;
        }
        if let Some(callable) = &function.callable {
            validate_callable(callable, &mut type_nodes, &mut value_nodes)?;
        }
        bounded(
            "function local variables",
            function.local_variables.len(),
            MAX_ITEMS_PER_FIELD,
        )?;
        for (name, variable) in &function.local_variables {
            bounded_name("local variable name", name)?;
            validate_variable(variable, &mut type_nodes, &mut value_nodes)?;
        }
        bounded(
            "function in-scope variables",
            function.in_scope_vars.len(),
            MAX_ITEMS_PER_FIELD,
        )?;
        for parameter in &function.in_scope_vars {
            validate_parameter(parameter, &mut type_nodes, &mut value_nodes)?;
        }
        bounded(
            "function type hints",
            function.type_hints.len(),
            MAX_ITEMS_PER_FIELD,
        )?;
        for hint in &function.type_hints {
            if let Some(variable) = &hint.target_var {
                validate_variable(variable, &mut type_nodes, &mut value_nodes)?;
            }
        }
        if let Some(effects) = &function.stack_effects {
            bounded(
                "stack allocations",
                effects.allocations.len(),
                MAX_ITEMS_PER_FIELD,
            )?;
            bounded("stack frees", effects.frees.len(), MAX_ITEMS_PER_FIELD)?;
            for variables in effects.allocations.values().chain(effects.frees.values()) {
                bounded(
                    "stack-effect variables",
                    variables.vars.len(),
                    MAX_ITEMS_PER_FIELD,
                )?;
                for variable in &variables.vars {
                    validate_variable(variable, &mut type_nodes, &mut value_nodes)?;
                }
            }
            bounded(
                "missed stack allocations",
                effects.missed_allocs.len(),
                MAX_ITEMS_PER_FIELD,
            )?;
            bounded(
                "missed stack frees",
                effects.missed_frees.len(),
                MAX_ITEMS_PER_FIELD,
            )?;
            for variable in effects.missed_allocs.iter().chain(&effects.missed_frees) {
                validate_variable(variable, &mut type_nodes, &mut value_nodes)?;
            }
        }
    }

    for symbol in &specification.symbols {
        bounded_name("symbol name", &symbol.name)?;
    }
    for required in &specification.required_globals {
        bounded_name("required global", required)?;
    }
    for name in specification.type_names.values() {
        bounded_name("type name", name)?;
    }
    for callsite in &specification.callsites {
        if let Some(callable) = &callsite.callable {
            validate_callable(callable, &mut type_nodes, &mut value_nodes)?;
        }
    }
    for r#type in specification.type_aliases.values().chain(
        specification
            .global_variables
            .iter()
            .filter_map(|global| global.r#type.as_ref()),
    ) {
        validate_type(r#type, 0, &mut type_nodes)?;
    }

    Ok(Inventory {
        functions: specification.functions.len(),
        blocks: block_count,
        memory_ranges: specification.memory_ranges.len(),
        globals: specification.global_variables.len(),
        symbols: specification.symbols.len(),
        callsites: specification.callsites.len(),
    })
}

fn validate_block_context(
    context: &BlockContext,
    type_nodes: &mut usize,
    value_nodes: &mut usize,
) -> Result<(), String> {
    bounded(
        "entry value mappings",
        context.symvals_at_entry.len(),
        MAX_ITEMS_PER_FIELD,
    )?;
    bounded(
        "exit value mappings",
        context.symvals_at_exit.len(),
        MAX_ITEMS_PER_FIELD,
    )?;
    for mapping in context
        .symvals_at_entry
        .iter()
        .chain(&context.symvals_at_exit)
    {
        if let Some(variable) = &mapping.target_value {
            validate_variable(variable, type_nodes, value_nodes)?;
        }
        if let Some(domain) = &mapping.curr_val
            && let Some(hydir_api::specification::value_domain::Inner::Symb(symbol)) = &domain.inner
        {
            bounded_name("high-symbol name", &symbol.name)?;
        }
    }
    bounded(
        "live entry parameters",
        context.live_at_entries.len(),
        MAX_ITEMS_PER_FIELD,
    )?;
    bounded(
        "live exit parameters",
        context.live_at_exits.len(),
        MAX_ITEMS_PER_FIELD,
    )?;
    for parameter in context.live_at_entries.iter().chain(&context.live_at_exits) {
        validate_parameter(parameter, type_nodes, value_nodes)?;
    }
    Ok(())
}

fn validate_callable(
    callable: &Callable,
    type_nodes: &mut usize,
    value_nodes: &mut usize,
) -> Result<(), String> {
    bounded(
        "callable parameters",
        callable.parameters.len(),
        MAX_ITEMS_PER_FIELD,
    )?;
    if let Some(address) = &callable.return_address {
        validate_value(address, value_nodes)?;
    }
    for parameter in &callable.parameters {
        validate_parameter(parameter, type_nodes, value_nodes)?;
    }
    if let Some(variable) = &callable.r#return {
        validate_variable(variable, type_nodes, value_nodes)?;
    }
    if let Some(r#type) = &callable.r#type {
        validate_type(r#type, 0, type_nodes)?;
    }
    if let Some(stack_pointer) = &callable.return_stack_pointer
        && let Some(register) = &stack_pointer.reg
    {
        bounded_name("return stack register", &register.register_name)?;
    }
    Ok(())
}

fn validate_parameter(
    parameter: &Parameter,
    type_nodes: &mut usize,
    value_nodes: &mut usize,
) -> Result<(), String> {
    if let Some(name) = &parameter.name {
        bounded_name("parameter name", name)?;
    }
    if let Some(variable) = &parameter.repr_var {
        validate_variable(variable, type_nodes, value_nodes)?;
    }
    Ok(())
}

fn validate_variable(
    variable: &Variable,
    type_nodes: &mut usize,
    value_nodes: &mut usize,
) -> Result<(), String> {
    bounded(
        "variable locations",
        variable.values.len(),
        MAX_ITEMS_PER_FIELD,
    )?;
    for location in &variable.values {
        validate_value(location, value_nodes)?;
    }
    if let Some(r#type) = &variable.r#type {
        validate_type(r#type, 0, type_nodes)?;
    }
    Ok(())
}

fn validate_value(location: &Value, value_nodes: &mut usize) -> Result<(), String> {
    *value_nodes = value_nodes
        .checked_add(1)
        .ok_or_else(|| "Anvill value node count overflows".to_owned())?;
    if *value_nodes > MAX_VALUE_NODES {
        return Err("Anvill value graph exceeds one million nodes".to_owned());
    }
    match &location.inner_value {
        Some(value::InnerValue::Reg(register)) => {
            bounded_name("register name", &register.register_name)?;
        }
        Some(value::InnerValue::Mem(memory)) => {
            if let Some(base) = &memory.base_reg {
                bounded_name("memory base register", base)?;
            }
        }
        None => {}
    }
    Ok(())
}

fn validate_type(r#type: &TypeSpec, depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > MAX_TYPE_DEPTH {
        return Err("Anvill type nesting exceeds 64 levels".to_owned());
    }
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "Anvill type node count overflows".to_owned())?;
    if *nodes > MAX_TYPE_NODES {
        return Err("Anvill type graph exceeds one million nodes".to_owned());
    }
    match r#type.r#type.as_ref() {
        Some(type_spec::Type::Pointer(pointer)) => {
            if let Some(pointee) = pointer.pointee.as_deref() {
                validate_type(pointee, depth + 1, nodes)?;
            }
        }
        Some(type_spec::Type::Vector(vector)) => {
            if vector.size == 0 {
                return Err("Anvill vector type has zero elements".to_owned());
            }
            if let Some(base) = vector.base.as_deref() {
                validate_type(base, depth + 1, nodes)?;
            }
        }
        Some(type_spec::Type::Array(array)) => {
            if let Some(base) = array.base.as_deref() {
                validate_type(base, depth + 1, nodes)?;
            }
        }
        Some(type_spec::Type::Struct(structure)) => {
            for member in &structure.members {
                validate_type(member, depth + 1, nodes)?;
            }
        }
        Some(type_spec::Type::Function(function)) => {
            if let Some(return_type) = function.return_type.as_deref() {
                validate_type(return_type, depth + 1, nodes)?;
            }
            for argument in &function.arguments {
                validate_type(argument, depth + 1, nodes)?;
            }
        }
        Some(
            type_spec::Type::Base(_) | type_spec::Type::Unknown(_) | type_spec::Type::Alias(_),
        )
        | None => {}
    }
    Ok(())
}

fn bounded(label: &str, actual: usize, maximum: usize) -> Result<(), String> {
    if actual > maximum {
        Err(format!("Anvill {label} exceed the limit of {maximum}"))
    } else {
        Ok(())
    }
}

fn bounded_name(label: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_NAME_BYTES || value.contains('\0') {
        Err(format!(
            "Anvill {label} must be at most {MAX_NAME_BYTES} bytes and contain no NUL"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_api::specification::{
        BlockContext, Function, MemoryRange, Register, ValueDomain, ValueMapping,
    };
    use hydir_backend::extract_symbol_code;
    use std::collections::BTreeMap;

    fn minimal() -> Specification {
        let block = CodeBlock {
            address: 0x401000,
            name: "entry".to_owned(),
            incoming_blocks: Vec::new(),
            outgoing_blocks: Vec::new(),
            size: 2,
            context_assignments: BTreeMap::new(),
            uid: 7,
        };
        Specification {
            arch: Arch::Amd64 as i32,
            operating_system: Os::Linux as i32,
            functions: vec![Function {
                entry_address: block.address,
                entry_uid: block.uid,
                blocks: BTreeMap::from([(block.uid, block)]),
                ..Default::default()
            }],
            memory_ranges: vec![MemoryRange {
                address: 0x401000,
                is_writeable: false,
                is_executable: true,
                values: vec![0x90, 0xc3],
            }],
            image_name: "fixture.elf".to_owned(),
            ..Default::default()
        }
    }

    #[test]
    fn preserves_original_wire_bytes_and_extracts_exact_block() {
        let canonical = minimal().encode_to_vec();
        let mut with_unknown = canonical.clone();
        // Unknown field 127, varint value 1. The pinned view intentionally
        // drops it, while original_bytes remains an exact forwarding form.
        with_unknown.extend_from_slice(&[0xf8, 0x07, 0x01]);
        let document = SpecificationDocument::decode(&with_unknown).unwrap();
        assert_eq!(document.original_bytes(), with_unknown);
        assert_eq!(document.canonical_bytes(), canonical);
        assert_eq!(document.block_bytes(7).unwrap(), [0x90, 0xc3]);
        assert_eq!(document.inventory().blocks, 1);
        document.require_stable_target().unwrap();
    }

    #[test]
    fn rejects_cross_function_duplicate_uids_and_ambiguous_bytes() {
        let mut spec = minimal();
        spec.functions.push(spec.functions[0].clone());
        assert!(
            SpecificationDocument::decode(&spec.encode_to_vec())
                .unwrap_err()
                .contains("duplicate Anvill block UID")
        );

        let mut spec = minimal();
        spec.memory_ranges.push(spec.memory_ranges[0].clone());
        let document = SpecificationDocument::decode(&spec.encode_to_vec()).unwrap();
        assert!(document.block_bytes(7).unwrap_err().contains("multiple"));
    }

    #[test]
    fn rejects_dangling_edges_and_wrong_stable_target() {
        let mut spec = minimal();
        spec.functions[0]
            .blocks
            .get_mut(&7)
            .unwrap()
            .outgoing_blocks
            .push(8);
        assert!(
            SpecificationDocument::decode(&spec.encode_to_vec())
                .unwrap_err()
                .contains("missing same-function edge")
        );

        let mut spec = minimal();
        spec.arch = Arch::Aarch64 as i32;
        let document = SpecificationDocument::decode(&spec.encode_to_vec()).unwrap();
        assert_eq!(
            document.require_stable_target().unwrap_err(),
            "stable Irene3 compatibility requires ARCH_AMD64"
        );
    }

    fn register_variable(name: &str) -> Variable {
        Variable {
            values: vec![Value {
                inner_value: Some(value::InnerValue::Reg(Register {
                    register_name: name.to_owned(),
                    subreg_sz: Some(64),
                })),
            }],
            r#type: Some(TypeSpec {
                r#type: Some(type_spec::Type::Base(BaseType::BtU64 as i32)),
            }),
        }
    }

    fn rsp_mapping(displacement: i64) -> ValueMapping {
        ValueMapping {
            target_value: Some(register_variable("RSP")),
            curr_val: Some(ValueDomain {
                inner: Some(value_domain::Inner::StackDisp(displacement)),
            }),
        }
    }

    #[test]
    fn binds_region_bytes_and_imported_live_state_to_exact_elf() {
        let elf = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let (code, address) = extract_symbol_code(elf, "hydir_max2").unwrap();
        let uid = 41;
        let block = CodeBlock {
            address,
            name: "hydir_max2".to_owned(),
            incoming_blocks: Vec::new(),
            outgoing_blocks: Vec::new(),
            size: code.len() as u32,
            context_assignments: BTreeMap::new(),
            uid,
        };
        let context = BlockContext {
            symvals_at_entry: vec![rsp_mapping(0)],
            symvals_at_exit: vec![rsp_mapping(8)],
            live_at_entries: vec![Parameter {
                name: Some("arg0".to_owned()),
                repr_var: Some(register_variable("RDI")),
            }],
            live_at_exits: vec![Parameter {
                name: Some("result".to_owned()),
                repr_var: Some(register_variable("RAX")),
            }],
        };
        let specification = Specification {
            arch: Arch::Amd64 as i32,
            operating_system: Os::Linux as i32,
            functions: vec![Function {
                entry_address: address,
                entry_uid: uid,
                blocks: BTreeMap::from([(uid, block)]),
                block_context: BTreeMap::from([(uid, context)]),
                ..Default::default()
            }],
            memory_ranges: vec![MemoryRange {
                address,
                is_writeable: false,
                is_executable: true,
                values: code.clone(),
            }],
            image_name: "max2.elf".to_owned(),
            ..Default::default()
        };
        let document = SpecificationDocument::decode(&specification.encode_to_vec()).unwrap();
        let region = document.region_spec_for_elf(elf, uid).unwrap();
        assert_eq!(region.entry, Address(address));
        assert_eq!(region.bytes_hex.len(), code.len() * 2);
        assert_eq!(region.stack_delta, Some(8));
        assert_eq!(region.physical_live_in[0].name, "RDI");
        assert_eq!(region.physical_live_out[0].name, "RAX");
        assert!(!region.replacement_ready);
        assert_eq!(region.provenance.source, FactSource::InterchangeImport);

        let mut mismatched = specification;
        mismatched.memory_ranges[0].values[0] ^= 1;
        let document = SpecificationDocument::decode(&mismatched.encode_to_vec()).unwrap();
        assert!(
            document
                .region_spec_for_elf(elf, uid)
                .unwrap_err()
                .contains("no byte-identical mapping")
        );
    }
}
