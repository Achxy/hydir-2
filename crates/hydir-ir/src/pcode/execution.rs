//! Concrete execution of a bounded raw P-code prefix or one selected path.
//!
//! Varnodes are byte ranges in named address spaces, as described in Ghidra's
//! P-Code Reference Manual (https://ghidra.re/ghidra_docs/languages/html/pcoderef.html).
//! This first executor is deliberately limited to x86-64 little-endian raw
//! P-code. Register offsets are byte offsets; overlapping slices alias at the
//! byte level. A write to a narrow slice changes only its bytes. Any wider
//! architectural effect (such as x86-64 32-bit register zero extension) must
//! appear as P-code operations; this executor does not invent it. Unique-space
//! temporaries are cleared at each machine-instruction boundary.
//!
//! The prefix trace follows listed instruction order. The path trace follows
//! raw branch targets and analyzed fallthrough edges. Both stop at the first
//! opaque or unavailable effect. Neither proves a complete function or
//! equivalence with the original machine instructions.

use super::semantics::lower_operation;
use super::{
    GhidraAddressSpace, GhidraFlowKind, GhidraSnapshot, PCODE_SEMANTIC_IR_VERSION, PcodeAddress,
    PcodeEffect, PcodeFunctionIr, PcodeOpaqueClass, PcodeOperation, PcodeSemanticFunctionIr,
    PcodeSemanticOperation, PcodeVarnode, hex_u64, validate_ghidra_snapshot,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PCODE_EXECUTION_TRACE_VERSION: u32 = 2;
const MAX_KNOWN_STATE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeConcreteState {
    register_bytes: BTreeMap<u64, u8>,
    unique_bytes: BTreeMap<u64, u8>,
    /// Each Ghidra memory address space has independent byte storage.
    memory_bytes: BTreeMap<String, BTreeMap<u64, u8>>,
}

impl PcodeConcreteState {
    fn known_byte_count(&self) -> usize {
        self.register_bytes
            .len()
            .saturating_add(self.unique_bytes.len())
            .saturating_add(self.memory_bytes.values().map(BTreeMap::len).sum::<usize>())
    }

    /// Set a complete 1..=8 byte register or unique varnode. The write is
    /// little-endian and preserves all bytes outside the addressed range.
    pub fn write_varnode(&mut self, node: &PcodeVarnode, value: u64) -> Result<(), String> {
        let offset = checked_range(node)?;
        let current_bytes = self.known_byte_count();
        let bytes = match node.space.as_str() {
            "register" => &mut self.register_bytes,
            "unique" => &mut self.unique_bytes,
            _ => return Err("concrete output must use register or unique space".to_owned()),
        };
        let missing = (0..node.size)
            .filter(|index| !bytes.contains_key(&(offset + u64::from(*index))))
            .count();
        if current_bytes.saturating_add(missing) > MAX_KNOWN_STATE_BYTES {
            return Err("concrete P-code state exceeds byte limit".to_owned());
        }
        for index in 0..node.size {
            bytes.insert(offset + u64::from(index), (value >> (index * 8)) as u8);
        }
        Ok(())
    }

    /// Read a fully known varnode. `None` means at least one required byte is
    /// unknown; it must not be silently replaced with zero. Constants are
    /// immediate values and are not stored in mutable state.
    pub fn read_varnode(&self, node: &PcodeVarnode) -> Result<Option<u64>, String> {
        if node.space == "const" {
            if !(1..=8).contains(&node.size) {
                return Err("concrete varnode width must be 1..=8 bytes".to_owned());
            }
            let offset = hex_u64(&node.offset)?;
            let mask = if node.size == 8 {
                u64::MAX
            } else {
                (1u64 << (node.size * 8)) - 1
            };
            return Ok(Some(offset & mask));
        }
        let offset = checked_range(node)?;
        let bytes = match node.space.as_str() {
            "register" => &self.register_bytes,
            "unique" => &self.unique_bytes,
            _ => return Err("concrete input must use register, unique or const space".to_owned()),
        };
        let mut value = 0u64;
        for index in 0..node.size {
            let Some(byte) = bytes.get(&(offset + u64::from(index))) else {
                return Ok(None);
            };
            value |= u64::from(*byte) << (index * 8);
        }
        Ok(Some(value))
    }

    fn clear_unique(&mut self) {
        self.unique_bytes.clear();
    }

    /// Seed or update fully known bytes in a named memory space. Execution
    /// checks the space ID and layout against the Ghidra artifact before use.
    pub fn write_memory(
        &mut self,
        space: &str,
        byte_offset: u64,
        size: u32,
        value: u64,
    ) -> Result<(), String> {
        checked_memory_range(byte_offset, size)?;
        if space.is_empty() || space.len() > 128 || space.chars().any(char::is_control) {
            return Err("concrete memory space name is invalid".to_owned());
        }
        let current_bytes = self.known_byte_count();
        let bytes = self.memory_bytes.entry(space.to_owned()).or_default();
        let missing = (0..size)
            .filter(|index| !bytes.contains_key(&(byte_offset + u64::from(*index))))
            .count();
        if current_bytes.saturating_add(missing) > MAX_KNOWN_STATE_BYTES {
            return Err("concrete P-code state exceeds byte limit".to_owned());
        }
        for index in 0..size {
            bytes.insert(byte_offset + u64::from(index), (value >> (index * 8)) as u8);
        }
        Ok(())
    }

    /// Read a complete little-endian memory value. Unknown bytes produce
    /// `None`; no default zero-filled memory is assumed.
    pub fn read_memory(
        &self,
        space: &str,
        byte_offset: u64,
        size: u32,
    ) -> Result<Option<u64>, String> {
        checked_memory_range(byte_offset, size)?;
        let Some(bytes) = self.memory_bytes.get(space) else {
            return Ok(None);
        };
        let mut value = 0u64;
        for index in 0..size {
            let Some(byte) = bytes.get(&(byte_offset + u64::from(index))) else {
                return Ok(None);
            };
            value |= u64::from(*byte) << (index * 8);
        }
        Ok(Some(value))
    }
}

fn checked_memory_range(byte_offset: u64, size: u32) -> Result<(), String> {
    if !(1..=8).contains(&size) {
        return Err("concrete memory access width must be 1..=8 bytes".to_owned());
    }
    if byte_offset.checked_add(u64::from(size - 1)).is_none() {
        return Err("concrete memory byte range overflows u64".to_owned());
    }
    Ok(())
}

fn checked_range(node: &PcodeVarnode) -> Result<u64, String> {
    if !(1..=8).contains(&node.size) {
        return Err("concrete varnode width must be 1..=8 bytes".to_owned());
    }
    let offset = hex_u64(&node.offset)?;
    if offset.checked_add(u64::from(node.size - 1)).is_none() {
        return Err("concrete varnode byte range overflows u64".to_owned());
    }
    Ok(offset)
}

/// Ghidra stores a P-code-relative branch displacement in the constant
/// varnode's offset, masked to its declared width by PcodeEmit. Interpret that
/// width as signed before adding it to the current operation index.
fn signed_relative_pcode_offset(node: &PcodeVarnode) -> Result<i64, String> {
    if node.space != "const" || !(1..=8).contains(&node.size) {
        return Err("relative P-code target requires a 1..=8 byte constant".to_owned());
    }
    let raw = hex_u64(&node.offset)?;
    let shift = 64 - node.size * 8;
    if raw > (u64::MAX >> shift) {
        return Err("relative P-code target exceeds its declared width".to_owned());
    }
    Ok(((raw << shift) as i64) >> shift)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeMemoryAccessKind {
    Load,
    Store,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeConcreteMemoryAccess {
    pub kind: PcodeMemoryAccessKind,
    pub space: String,
    pub space_id: i32,
    pub pointer_offset: u64,
    pub byte_offset: u64,
    pub width_bytes: u32,
    pub value: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeMemoryBoundaryKind {
    UnsupportedLayout,
    UnknownSpace,
    UnknownAlias,
    UnknownBytes,
    AddressOverflow,
    StateLimit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeExecutedOperation {
    /// Full source provenance and varnode ranges.
    pub source: PcodeOperation,
    /// Values in source input order, read before the output is written.
    pub input_values: Vec<u64>,
    /// STORE has no output varnode; its written value is in `memory_access`.
    pub output_value: Option<u64>,
    pub memory_access: Option<PcodeConcreteMemoryAccess>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PcodeExecutionStop {
    /// All listed operations were processed; this is not a function result.
    EndOfListedInstructions,
    OpaqueBoundary {
        source: PcodeOperation,
        effect: PcodeEffect,
    },
    MissingInput {
        source: PcodeOperation,
        input_index: u32,
        varnode: PcodeVarnode,
    },
    MemoryBoundary {
        source: PcodeOperation,
        space: Option<String>,
        pointer_offset: Option<u64>,
        reason: PcodeMemoryBoundaryKind,
        detail: String,
    },
    InvalidOperation {
        source: PcodeOperation,
        reason: String,
    },
    OperationBudget {
        next: PcodeOperation,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeExecutionTrace {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: PcodeAddress,
    pub executed: Vec<PcodeExecutedOperation>,
    pub final_state: PcodeConcreteState,
    pub stop: PcodeExecutionStop,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

pub const PCODE_PATH_TRACE_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodePathBranchKind {
    Branch,
    ConditionalBranch,
    IndirectBranch,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PcodePathDestination {
    /// A constant-space branch target or a conditional branch's next op.
    IntraInstruction {
        instruction: PcodeAddress,
        sequence_index: u32,
    },
    Instruction {
        address: PcodeAddress,
    },
    /// The condition was false at the end of this instruction; the next loop
    /// iteration must resolve its analyzed fallthrough edge.
    FallthroughPending,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PcodePathEvent {
    Effect {
        operation: PcodeExecutedOperation,
    },
    Branch {
        source: PcodeOperation,
        branch_kind: PcodePathBranchKind,
        taken: Option<bool>,
        destination: PcodePathDestination,
    },
    Fallthrough {
        source: PcodeAddress,
        target: PcodeAddress,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PcodePathStop {
    Call {
        source: PcodeOperation,
    },
    Return {
        source: PcodeOperation,
    },
    UnknownCondition {
        source: PcodeOperation,
        varnode: PcodeVarnode,
    },
    UnknownIndirectTarget {
        source: PcodeOperation,
        varnode: PcodeVarnode,
    },
    MalformedTarget {
        source: PcodeOperation,
        reason: String,
    },
    TargetNotSelected {
        source: PcodeOperation,
        target: PcodeAddress,
    },
    FallthroughTargetNotSelected {
        source: PcodeAddress,
        target: PcodeAddress,
    },
    UnresolvedFallthrough {
        source: PcodeAddress,
    },
    AmbiguousFallthrough {
        source: PcodeAddress,
    },
    EffectBoundary {
        boundary: PcodeExecutionStop,
    },
    OperationBudget {
        next: PcodeOperation,
    },
    VisitBudget {
        next_instruction: PcodeAddress,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodePathTrace {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub start: PcodeAddress,
    /// Each machine-instruction entry is recorded, including revisits.
    pub instruction_visits: Vec<PcodeAddress>,
    /// Effects and control transitions in concrete execution order.
    pub events: Vec<PcodePathEvent>,
    pub final_state: PcodeConcreteState,
    pub stop: PcodePathStop,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

fn memory_boundary(
    source: &PcodeOperation,
    space: Option<&str>,
    pointer_offset: Option<u64>,
    reason: PcodeMemoryBoundaryKind,
    detail: impl Into<String>,
) -> Box<PcodeExecutionStop> {
    Box::new(PcodeExecutionStop::MemoryBoundary {
        source: source.clone(),
        space: space.map(str::to_owned),
        pointer_offset,
        reason,
        detail: detail.into(),
    })
}

impl PcodeSemanticFunctionIr {
    fn memory_space(&self, id: u64) -> Option<&GhidraAddressSpace> {
        self.address_spaces
            .iter()
            .find(|space| u64::try_from(space.id).ok() == Some(id))
    }

    /// Perform one LOAD or STORE only when the space ID, pointer width,
    /// concrete address, access width and all read bytes are known. Ghidra's
    /// static semantic effect remains opaque: this is an exact *concrete*
    /// action under a seeded state, not an exact symbolic operation.
    fn execute_memory_operation(
        &self,
        operation: &PcodeSemanticOperation,
        state: &mut PcodeConcreteState,
    ) -> Result<PcodeExecutedOperation, Box<PcodeExecutionStop>> {
        let source = &operation.source;
        let kind = match (source.opcode, source.mnemonic.as_str()) {
            (2, "LOAD") if source.inputs.len() == 2 && source.output.is_some() => {
                PcodeMemoryAccessKind::Load
            }
            (3, "STORE") if source.inputs.len() == 3 && source.output.is_none() => {
                PcodeMemoryAccessKind::Store
            }
            _ => {
                return Err(memory_boundary(
                    source,
                    None,
                    None,
                    PcodeMemoryBoundaryKind::UnsupportedLayout,
                    "LOAD/STORE opcode, mnemonic, arity or output is invalid",
                ));
            }
        };
        let id_node = &source.inputs[0];
        if id_node.space != "const" || !(1..=8).contains(&id_node.size) {
            return Err(memory_boundary(
                source,
                None,
                None,
                PcodeMemoryBoundaryKind::UnsupportedLayout,
                "memory space ID must be a bounded constant varnode",
            ));
        }
        let id = hex_u64(&id_node.offset).map_err(|reason| {
            memory_boundary(
                source,
                None,
                None,
                PcodeMemoryBoundaryKind::UnsupportedLayout,
                reason,
            )
        })?;
        let id_mask = if id_node.size == 8 {
            u64::MAX
        } else {
            (1u64 << (id_node.size * 8)) - 1
        };
        if id > id_mask {
            return Err(memory_boundary(
                source,
                None,
                None,
                PcodeMemoryBoundaryKind::UnsupportedLayout,
                "memory space ID exceeds its constant varnode width",
            ));
        }
        let space = self.memory_space(id).ok_or_else(|| {
            memory_boundary(
                source,
                None,
                None,
                PcodeMemoryBoundaryKind::UnknownSpace,
                format!("no Ghidra address space has ID {id}"),
            )
        })?;
        // TYPE_RAM=1 in Ghidra. Stack and special spaces need signed/physical
        // mapping evidence that snapshot v2 does not provide.
        if space.space_type != 1 || matches!(space.name.as_str(), "const" | "register" | "unique") {
            return Err(memory_boundary(
                source,
                Some(&space.name),
                None,
                PcodeMemoryBoundaryKind::UnsupportedLayout,
                "only Ghidra RAM address spaces have concrete memory semantics",
            ));
        }
        let pointer_node = &source.inputs[1];
        if !(1..=8).contains(&space.pointer_size)
            || pointer_node.size != space.pointer_size
            || !matches!(pointer_node.space.as_str(), "register" | "unique" | "const")
        {
            return Err(memory_boundary(
                source,
                Some(&space.name),
                None,
                PcodeMemoryBoundaryKind::UnsupportedLayout,
                "pointer varnode must match the target space pointer width",
            ));
        }
        let width = match kind {
            PcodeMemoryAccessKind::Load => {
                let output = source.output.as_ref().expect("validated LOAD output");
                if !matches!(output.space.as_str(), "register" | "unique") {
                    return Err(memory_boundary(
                        source,
                        Some(&space.name),
                        None,
                        PcodeMemoryBoundaryKind::UnsupportedLayout,
                        "LOAD output must be register or unique storage",
                    ));
                }
                output.size
            }
            PcodeMemoryAccessKind::Store => {
                let data = &source.inputs[2];
                if !matches!(data.space.as_str(), "register" | "unique" | "const") {
                    return Err(memory_boundary(
                        source,
                        Some(&space.name),
                        None,
                        PcodeMemoryBoundaryKind::UnsupportedLayout,
                        "STORE data must be a bounded concrete varnode",
                    ));
                }
                data.size
            }
        };
        if !(1..=8).contains(&width) || space.addressable_unit_size == 0 {
            return Err(memory_boundary(
                source,
                Some(&space.name),
                None,
                PcodeMemoryBoundaryKind::UnsupportedLayout,
                "memory width or target addressable unit size is unsupported",
            ));
        }
        let pointer_offset = match state.read_varnode(pointer_node) {
            Ok(Some(value)) => value,
            Ok(None) => {
                return Err(memory_boundary(
                    source,
                    Some(&space.name),
                    None,
                    PcodeMemoryBoundaryKind::UnknownAlias,
                    "pointer bytes are unknown, so the memory alias is unresolved",
                ));
            }
            Err(reason) => {
                return Err(memory_boundary(
                    source,
                    Some(&space.name),
                    None,
                    PcodeMemoryBoundaryKind::UnsupportedLayout,
                    reason,
                ));
            }
        };
        let byte_offset = pointer_offset
            .checked_mul(u64::from(space.addressable_unit_size))
            .ok_or_else(|| {
                memory_boundary(
                    source,
                    Some(&space.name),
                    Some(pointer_offset),
                    PcodeMemoryBoundaryKind::AddressOverflow,
                    "pointer scaling overflows the supported byte offset",
                )
            })?;
        checked_memory_range(byte_offset, width).map_err(|reason| {
            memory_boundary(
                source,
                Some(&space.name),
                Some(pointer_offset),
                PcodeMemoryBoundaryKind::AddressOverflow,
                reason,
            )
        })?;
        let mut input_values = vec![id, pointer_offset];
        let value = match kind {
            PcodeMemoryAccessKind::Load => match state.read_memory(&space.name, byte_offset, width)
            {
                Ok(Some(value)) => value,
                Ok(None) => {
                    return Err(memory_boundary(
                        source,
                        Some(&space.name),
                        Some(pointer_offset),
                        PcodeMemoryBoundaryKind::UnknownBytes,
                        "one or more loaded memory bytes are unknown",
                    ));
                }
                Err(reason) => {
                    return Err(memory_boundary(
                        source,
                        Some(&space.name),
                        Some(pointer_offset),
                        PcodeMemoryBoundaryKind::AddressOverflow,
                        reason,
                    ));
                }
            },
            PcodeMemoryAccessKind::Store => {
                let data = &source.inputs[2];
                match state.read_varnode(data) {
                    Ok(Some(value)) => {
                        input_values.push(value);
                        value
                    }
                    Ok(None) => {
                        return Err(Box::new(PcodeExecutionStop::MissingInput {
                            source: source.clone(),
                            input_index: 2,
                            varnode: data.clone(),
                        }));
                    }
                    Err(reason) => {
                        return Err(memory_boundary(
                            source,
                            Some(&space.name),
                            Some(pointer_offset),
                            PcodeMemoryBoundaryKind::UnsupportedLayout,
                            reason,
                        ));
                    }
                }
            }
        };
        match kind {
            PcodeMemoryAccessKind::Load => {
                let output = source.output.as_ref().expect("validated LOAD output");
                state.write_varnode(output, value).map_err(|reason| {
                    memory_boundary(
                        source,
                        Some(&space.name),
                        Some(pointer_offset),
                        PcodeMemoryBoundaryKind::StateLimit,
                        reason,
                    )
                })?;
            }
            PcodeMemoryAccessKind::Store => {
                state
                    .write_memory(&space.name, byte_offset, width, value)
                    .map_err(|reason| {
                        memory_boundary(
                            source,
                            Some(&space.name),
                            Some(pointer_offset),
                            PcodeMemoryBoundaryKind::StateLimit,
                            reason,
                        )
                    })?;
            }
        }
        Ok(PcodeExecutedOperation {
            source: source.clone(),
            input_values,
            output_value: (kind == PcodeMemoryAccessKind::Load).then_some(value),
            memory_access: Some(PcodeConcreteMemoryAccess {
                kind,
                space: space.name.clone(),
                space_id: space.id,
                pointer_offset,
                byte_offset,
                width_bytes: width,
                value,
            }),
        })
    }

    fn execute_effect_operation(
        &self,
        operation: &PcodeSemanticOperation,
        state: &mut PcodeConcreteState,
    ) -> Result<PcodeExecutedOperation, Box<PcodeExecutionStop>> {
        let source = &operation.source;
        if source.inputs.len() > 256 || lower_operation(source) != operation.effect {
            return Err(Box::new(PcodeExecutionStop::InvalidOperation {
                source: source.clone(),
                reason: "exact operation disagrees with bounded raw P-code semantics".to_owned(),
            }));
        }
        if let PcodeEffect::Opaque { class, .. } = &operation.effect {
            if matches!(
                class,
                PcodeOpaqueClass::MemoryRead | PcodeOpaqueClass::MemoryWrite
            ) {
                return self.execute_memory_operation(operation, state);
            }
            return Err(Box::new(PcodeExecutionStop::OpaqueBoundary {
                source: source.clone(),
                effect: operation.effect.clone(),
            }));
        }
        let mut input_values = Vec::with_capacity(source.inputs.len());
        for (index, varnode) in source.inputs.iter().enumerate() {
            match state.read_varnode(varnode) {
                Ok(Some(value)) => input_values.push(value),
                Ok(None) => {
                    return Err(Box::new(PcodeExecutionStop::MissingInput {
                        source: source.clone(),
                        input_index: index as u32,
                        varnode: varnode.clone(),
                    }));
                }
                Err(reason) => {
                    return Err(Box::new(PcodeExecutionStop::InvalidOperation {
                        source: source.clone(),
                        reason,
                    }));
                }
            }
        }
        let value = match operation.evaluate_exact(&input_values) {
            Ok(Some(value)) => value,
            Ok(None) => {
                return Err(Box::new(PcodeExecutionStop::InvalidOperation {
                    source: source.clone(),
                    reason: "exact operation returned no concrete result".to_owned(),
                }));
            }
            Err(reason) => {
                return Err(Box::new(PcodeExecutionStop::InvalidOperation {
                    source: source.clone(),
                    reason,
                }));
            }
        };
        let Some(output) = &source.output else {
            return Err(Box::new(PcodeExecutionStop::InvalidOperation {
                source: source.clone(),
                reason: "exact operation has no output varnode".to_owned(),
            }));
        };
        state.write_varnode(output, value).map_err(|reason| {
            Box::new(PcodeExecutionStop::InvalidOperation {
                source: source.clone(),
                reason,
            })
        })?;
        Ok(PcodeExecutedOperation {
            source: source.clone(),
            input_values,
            output_value: Some(value),
            memory_access: None,
        })
    }

    fn validate_execution_setup(
        &self,
        initial_state: &PcodeConcreteState,
        max_operations: usize,
    ) -> Result<(), String> {
        if self.schema_version != PCODE_SEMANTIC_IR_VERSION
            || self.source != "ghidra_raw_pcode"
            || !self.flow_overrides_applied
        {
            return Err("unsupported P-code semantic artifact".to_owned());
        }
        if !self.language_id.starts_with("x86:LE:64:") {
            return Err(
                "concrete P-code execution currently requires x86-64 little endian".to_owned(),
            );
        }
        if max_operations > super::MAX_OPERATIONS {
            return Err("concrete P-code operation budget exceeds artifact limit".to_owned());
        }
        if self.instructions.len() > super::MAX_INSTRUCTIONS
            || self
                .instructions
                .iter()
                .map(|instruction| instruction.operations.len())
                .sum::<usize>()
                > super::MAX_OPERATIONS
        {
            return Err("P-code semantic artifact exceeds execution bounds".to_owned());
        }
        if self.address_spaces.len() > 256 {
            return Err("P-code semantic artifact exceeds address-space limit".to_owned());
        }
        let mut space_ids = BTreeSet::new();
        let mut space_names = BTreeSet::new();
        for space in &self.address_spaces {
            if !space_ids.insert(space.id) || !space_names.insert(space.name.as_str()) {
                return Err("ambiguous P-code address-space IDs or names".to_owned());
            }
        }
        if initial_state.known_byte_count() > MAX_KNOWN_STATE_BYTES {
            return Err("initial concrete P-code state exceeds byte limit".to_owned());
        }
        Ok(())
    }
}

impl GhidraSnapshot {
    /// Execute one concrete path through the selected function's raw P-code.
    /// Direct targets come from the P-code operation; analyzed fallthrough
    /// edges are required when execution reaches the end of an instruction.
    /// This is a bounded trace of seeded state, never a completeness or
    /// machine-code equivalence claim.
    pub fn execute_concrete_path(
        &self,
        initial_state: &PcodeConcreteState,
        start: Option<&PcodeAddress>,
        max_operations: usize,
        max_instruction_visits: usize,
    ) -> Result<PcodePathTrace, String> {
        validate_ghidra_snapshot(self, &self.binary_sha256)?;
        if max_instruction_visits > super::MAX_OPERATIONS {
            return Err("P-code path visit budget exceeds artifact limit".to_owned());
        }
        let semantic = self.pcode_function_ir()?.lower_semantics();
        semantic.validate_execution_setup(initial_state, max_operations)?;

        let mut instruction_index = BTreeMap::new();
        for (index, instruction) in semantic.instructions.iter().enumerate() {
            let key = (
                instruction.address.space.clone(),
                hex_u64(&instruction.address.offset)?,
            );
            instruction_index.insert(key, index);
        }
        let start = start.unwrap_or(&self.selected_function.entry).clone();
        let start_key = (start.space.clone(), hex_u64(&start.offset)?);
        let Some(mut current_instruction) = instruction_index.get(&start_key).copied() else {
            return Err("P-code path start is not a selected instruction".to_owned());
        };

        let mut fallthroughs =
            vec![Vec::<Option<PcodeAddress>>::new(); semantic.instructions.len()];
        for edge in &self.selected_function.flow_edges {
            if edge.kind == GhidraFlowKind::Fallthrough {
                let key = (edge.source.space.clone(), hex_u64(&edge.source.offset)?);
                let source_index = instruction_index[&key];
                fallthroughs[source_index].push(edge.target.clone());
            }
        }

        let mut final_state = initial_state.clone();
        let mut events = Vec::new();
        let mut instruction_visits = Vec::new();
        let mut operation_count = 0usize;
        let mut current_operation = 0usize;
        let mut entering_instruction = true;
        let stop = 'path: loop {
            let instruction = &semantic.instructions[current_instruction];
            if entering_instruction {
                if instruction_visits.len() >= max_instruction_visits {
                    break PcodePathStop::VisitBudget {
                        next_instruction: instruction.address.clone(),
                    };
                }
                instruction_visits.push(instruction.address.clone());
                final_state.clear_unique();
                entering_instruction = false;
            }
            if current_operation == instruction.operations.len() {
                let target = match fallthroughs[current_instruction].as_slice() {
                    [] | [None] => {
                        break PcodePathStop::UnresolvedFallthrough {
                            source: instruction.address.clone(),
                        };
                    }
                    [Some(target)] => target,
                    _ => {
                        break PcodePathStop::AmbiguousFallthrough {
                            source: instruction.address.clone(),
                        };
                    }
                };
                let key = (target.space.clone(), hex_u64(&target.offset)?);
                let Some(next_instruction) = instruction_index.get(&key).copied() else {
                    break PcodePathStop::FallthroughTargetNotSelected {
                        source: instruction.address.clone(),
                        target: target.clone(),
                    };
                };
                events.push(PcodePathEvent::Fallthrough {
                    source: instruction.address.clone(),
                    target: target.clone(),
                });
                current_instruction = next_instruction;
                current_operation = 0;
                entering_instruction = true;
                continue;
            }

            let operation = &instruction.operations[current_operation];
            let source = &operation.source;
            if operation_count >= max_operations {
                break PcodePathStop::OperationBudget {
                    next: source.clone(),
                };
            }
            match source.opcode {
                4 | 5 => {
                    let conditional = source.opcode == 5;
                    let mnemonic = if conditional { "CBRANCH" } else { "BRANCH" };
                    if source.mnemonic != mnemonic
                        || source.output.is_some()
                        || source.inputs.len() != if conditional { 2 } else { 1 }
                    {
                        break PcodePathStop::MalformedTarget {
                            source: source.clone(),
                            reason: "invalid direct branch opcode, mnemonic, output or arity"
                                .to_owned(),
                        };
                    }
                    let taken = if conditional {
                        let condition = &source.inputs[1];
                        if condition.size != 1 {
                            break PcodePathStop::MalformedTarget {
                                source: source.clone(),
                                reason: "CBRANCH condition must be one byte".to_owned(),
                            };
                        }
                        match final_state.read_varnode(condition) {
                            Ok(Some(value)) => value != 0,
                            Ok(None) => {
                                break PcodePathStop::UnknownCondition {
                                    source: source.clone(),
                                    varnode: condition.clone(),
                                };
                            }
                            Err(reason) => {
                                break PcodePathStop::MalformedTarget {
                                    source: source.clone(),
                                    reason,
                                };
                            }
                        }
                    } else {
                        true
                    };
                    if !taken {
                        let destination = if current_operation + 1 < instruction.operations.len() {
                            PcodePathDestination::IntraInstruction {
                                instruction: instruction.address.clone(),
                                sequence_index: (current_operation + 1) as u32,
                            }
                        } else {
                            PcodePathDestination::FallthroughPending
                        };
                        events.push(PcodePathEvent::Branch {
                            source: source.clone(),
                            branch_kind: PcodePathBranchKind::ConditionalBranch,
                            taken: Some(false),
                            destination,
                        });
                        operation_count += 1;
                        current_operation += 1;
                        continue;
                    }
                    let target_node = &source.inputs[0];
                    let (destination, next_instruction, next_operation, next_is_entry) =
                        if target_node.space == "const" {
                            // The encoded constant is a signed displacement
                            // in this instruction's P-code operation list.
                            let delta = match signed_relative_pcode_offset(target_node) {
                                Ok(value) => value,
                                Err(reason) => {
                                    break PcodePathStop::MalformedTarget {
                                        source: source.clone(),
                                        reason,
                                    };
                                }
                            };
                            let Some(target_index) = (current_operation as i64).checked_add(delta)
                            else {
                                break PcodePathStop::MalformedTarget {
                                    source: source.clone(),
                                    reason: "relative P-code branch index overflows".to_owned(),
                                };
                            };
                            if target_index < 0
                                || target_index as usize >= instruction.operations.len()
                            {
                                break PcodePathStop::MalformedTarget {
                                    source: source.clone(),
                                    reason:
                                        "relative P-code branch target is outside its instruction"
                                            .to_owned(),
                                };
                            }
                            (
                                PcodePathDestination::IntraInstruction {
                                    instruction: instruction.address.clone(),
                                    sequence_index: target_index as u32,
                                },
                                current_instruction,
                                target_index as usize,
                                false,
                            )
                        } else {
                            let target = PcodeAddress {
                                space: target_node.space.clone(),
                                offset: target_node.offset.clone(),
                            };
                            let key = (target.space.clone(), hex_u64(&target.offset)?);
                            let Some(next_instruction) = instruction_index.get(&key).copied()
                            else {
                                break PcodePathStop::TargetNotSelected {
                                    source: source.clone(),
                                    target,
                                };
                            };
                            (
                                PcodePathDestination::Instruction { address: target },
                                next_instruction,
                                0,
                                true,
                            )
                        };
                    events.push(PcodePathEvent::Branch {
                        source: source.clone(),
                        branch_kind: if conditional {
                            PcodePathBranchKind::ConditionalBranch
                        } else {
                            PcodePathBranchKind::Branch
                        },
                        taken: conditional.then_some(true),
                        destination,
                    });
                    operation_count += 1;
                    current_instruction = next_instruction;
                    current_operation = next_operation;
                    entering_instruction = next_is_entry;
                }
                6 => {
                    if source.mnemonic != "BRANCHIND"
                        || source.output.is_some()
                        || source.inputs.len() != 1
                    {
                        break PcodePathStop::MalformedTarget {
                            source: source.clone(),
                            reason: "invalid indirect branch opcode, mnemonic, output or arity"
                                .to_owned(),
                        };
                    }
                    let pointer = &source.inputs[0];
                    let Some(space) = semantic
                        .address_spaces
                        .iter()
                        .find(|space| space.name == instruction.address.space)
                    else {
                        break PcodePathStop::MalformedTarget {
                            source: source.clone(),
                            reason: "branch instruction address space is unknown".to_owned(),
                        };
                    };
                    if space.pointer_size == 0
                        || space.pointer_size > 8
                        || pointer.size != space.pointer_size
                    {
                        break PcodePathStop::MalformedTarget {
                            source: source.clone(),
                            reason:
                                "BRANCHIND input width differs from address-space pointer width"
                                    .to_owned(),
                        };
                    }
                    let value = match final_state.read_varnode(pointer) {
                        Ok(Some(value)) => value,
                        Ok(None) => {
                            break PcodePathStop::UnknownIndirectTarget {
                                source: source.clone(),
                                varnode: pointer.clone(),
                            };
                        }
                        Err(reason) => {
                            break PcodePathStop::MalformedTarget {
                                source: source.clone(),
                                reason,
                            };
                        }
                    };
                    let target = PcodeAddress {
                        space: instruction.address.space.clone(),
                        offset: format!("0x{value:x}"),
                    };
                    let key = (target.space.clone(), value);
                    let Some(next_instruction) = instruction_index.get(&key).copied() else {
                        break PcodePathStop::TargetNotSelected {
                            source: source.clone(),
                            target,
                        };
                    };
                    events.push(PcodePathEvent::Branch {
                        source: source.clone(),
                        branch_kind: PcodePathBranchKind::IndirectBranch,
                        taken: None,
                        destination: PcodePathDestination::Instruction { address: target },
                    });
                    operation_count += 1;
                    current_instruction = next_instruction;
                    current_operation = 0;
                    entering_instruction = true;
                }
                7 | 8 | 10 => {
                    let mnemonic = match source.opcode {
                        7 => "CALL",
                        8 => "CALLIND",
                        _ => "RETURN",
                    };
                    if source.mnemonic != mnemonic
                        || source.output.is_some()
                        || source.inputs.len() != 1
                    {
                        break PcodePathStop::MalformedTarget {
                            source: source.clone(),
                            reason: "invalid call or return opcode, mnemonic, output or arity"
                                .to_owned(),
                        };
                    }
                    break if source.opcode == 10 {
                        PcodePathStop::Return {
                            source: source.clone(),
                        }
                    } else {
                        PcodePathStop::Call {
                            source: source.clone(),
                        }
                    };
                }
                _ => match semantic.execute_effect_operation(operation, &mut final_state) {
                    Ok(executed) => {
                        events.push(PcodePathEvent::Effect {
                            operation: executed,
                        });
                        operation_count += 1;
                        current_operation += 1;
                    }
                    Err(boundary) => {
                        break 'path PcodePathStop::EffectBoundary {
                            boundary: *boundary,
                        };
                    }
                },
            }
        };
        Ok(PcodePathTrace {
            schema_version: PCODE_PATH_TRACE_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            start,
            instruction_visits,
            events,
            final_state,
            stop,
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        })
    }
}

impl PcodeFunctionIr {
    /// Execute an ordered exact prefix from raw P-code. The state is cloned;
    /// the caller's seed is never partially mutated on an opaque boundary.
    pub fn execute_exact_prefix(
        &self,
        initial_state: &PcodeConcreteState,
        max_operations: usize,
    ) -> Result<PcodeExecutionTrace, String> {
        self.lower_semantics()
            .execute_exact_prefix(initial_state, max_operations)
    }
}

impl PcodeSemanticFunctionIr {
    /// Execute individually validated exact operations and concrete RAM
    /// LOAD/STORE effects. Unknown memory aliases, unknown bytes, control,
    /// unsupported, invalid, and unavailable-input operations stop before
    /// changing state.
    pub fn execute_exact_prefix(
        &self,
        initial_state: &PcodeConcreteState,
        max_operations: usize,
    ) -> Result<PcodeExecutionTrace, String> {
        self.validate_execution_setup(initial_state, max_operations)?;
        let mut final_state = initial_state.clone();
        let mut executed = Vec::new();
        let mut stop = PcodeExecutionStop::EndOfListedInstructions;
        'instructions: for instruction in &self.instructions {
            final_state.clear_unique();
            for operation in &instruction.operations {
                let source = &operation.source;
                if executed.len() >= max_operations {
                    stop = PcodeExecutionStop::OperationBudget {
                        next: source.clone(),
                    };
                    break 'instructions;
                }
                match self.execute_effect_operation(operation, &mut final_state) {
                    Ok(step) => executed.push(step),
                    Err(boundary) => {
                        stop = *boundary;
                        break 'instructions;
                    }
                }
            }
        }
        Ok(PcodeExecutionTrace {
            schema_version: PCODE_EXECUTION_TRACE_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            entry: self.entry.clone(),
            executed,
            final_state,
            stop,
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{PcodeInstruction, PcodeVarnode, parse_ghidra_snapshot};

    fn node(space: &str, offset: &str, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.to_owned(),
            offset: offset.to_owned(),
            size,
        }
    }

    fn address(offset: &str) -> PcodeAddress {
        PcodeAddress {
            space: "ram".to_owned(),
            offset: offset.to_owned(),
        }
    }

    fn operation(
        opcode: u32,
        mnemonic: &str,
        sequence_index: u32,
        output: Option<PcodeVarnode>,
        inputs: Vec<PcodeVarnode>,
    ) -> PcodeOperation {
        PcodeOperation {
            mnemonic: mnemonic.to_owned(),
            opcode,
            sequence_index,
            sequence_time: sequence_index as i32,
            source_address: address("0x401000"),
            userop_name: None,
            output,
            inputs,
        }
    }

    fn function(ops: Vec<PcodeOperation>) -> PcodeFunctionIr {
        PcodeFunctionIr {
            schema_version: super::super::PCODE_IR_VERSION,
            binary_sha256: "a".repeat(64),
            source: "ghidra_raw_pcode".to_owned(),
            flow_overrides_applied: true,
            ghidra_version: "12.1.4".to_owned(),
            language_id: "x86:LE:64:default".to_owned(),
            compiler_spec_id: "gcc".to_owned(),
            address_spaces: Vec::new(),
            entry: address("0x401000"),
            name: "f".to_owned(),
            instructions: vec![PcodeInstruction {
                address: address("0x401000"),
                bytes: "90".to_owned(),
                parsed_bytes: "90".to_owned(),
                mnemonic: "NOP".to_owned(),
                pcode: ops,
            }],
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        }
    }

    fn real_calls_function() -> PcodeFunctionIr {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
        ));
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        parse_ghidra_snapshot(bytes, digest)
            .unwrap()
            .pcode_function_ir()
            .unwrap()
    }

    fn real_branch_snapshot() -> GhidraSnapshot {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
        ));
        parse_ghidra_snapshot(
            bytes,
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap()
    }

    fn single_instruction_snapshot(mut pcode: Vec<PcodeOperation>) -> GhidraSnapshot {
        let mut snapshot = real_branch_snapshot();
        let instruction = &mut snapshot.selected_function.instructions[0];
        for (index, operation) in pcode.iter_mut().enumerate() {
            operation.sequence_index = index as u32;
            operation.sequence_time = index as i32;
            operation.source_address = instruction.address.clone();
        }
        instruction.pcode = pcode;
        snapshot.selected_function.instructions.truncate(1);
        snapshot.selected_function.flow_edges.clear();
        snapshot
    }

    #[test]
    fn real_ghidra_conditional_branch_takes_both_concrete_paths() {
        let snapshot = real_branch_snapshot();
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&node("register", "0x0", 8), 0).unwrap();
        seed.write_varnode(&node("register", "0x20", 8), 0x1000)
            .unwrap();
        seed.write_memory("ram", 0x1000, 8, 0xdead).unwrap();
        let branch = address("0x2013d9");

        seed.write_varnode(&node("register", "0x206", 1), 1)
            .unwrap();
        let taken = snapshot
            .execute_concrete_path(&seed, Some(&branch), 16, 8)
            .unwrap();
        assert_eq!(
            taken.instruction_visits,
            vec![branch.clone(), address("0x2013e2")]
        );
        assert!(matches!(taken.stop, PcodePathStop::Return { .. }));
        assert!(matches!(
            taken.events[0],
            PcodePathEvent::Branch {
                taken: Some(true),
                branch_kind: PcodePathBranchKind::ConditionalBranch,
                ..
            }
        ));
        assert_eq!(
            taken
                .final_state
                .read_varnode(&node("register", "0x0", 8))
                .unwrap(),
            Some(0)
        );
        assert_eq!(taken.semantic_fidelity, SemanticFidelity::Unknown);

        seed.write_varnode(&node("register", "0x206", 1), 0)
            .unwrap();
        let not_taken = snapshot
            .execute_concrete_path(&seed, Some(&branch), 16, 8)
            .unwrap();
        assert_eq!(
            not_taken.instruction_visits,
            vec![branch, address("0x2013db"), address("0x2013e2")]
        );
        assert!(matches!(not_taken.stop, PcodePathStop::Return { .. }));
        assert!(matches!(
            not_taken.events[0],
            PcodePathEvent::Branch {
                taken: Some(false),
                ..
            }
        ));
        assert_eq!(
            not_taken
                .final_state
                .read_varnode(&node("register", "0x0", 8))
                .unwrap(),
            Some(1)
        );
    }

    #[test]
    fn path_stops_at_unknown_condition_or_effect_before_control() {
        let snapshot = real_branch_snapshot();
        let branch = snapshot
            .execute_concrete_path(
                &PcodeConcreteState::default(),
                Some(&address("0x2013d9")),
                8,
                8,
            )
            .unwrap();
        assert!(matches!(
            branch.stop,
            PcodePathStop::UnknownCondition { .. }
        ));
        assert!(branch.events.is_empty());

        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&node("register", "0x38", 8), 5).unwrap();
        seed.write_varnode(&node("register", "0x30", 8), 1).unwrap();
        let entry = snapshot.execute_concrete_path(&seed, None, 32, 8).unwrap();
        assert!(matches!(
            entry.stop,
            PcodePathStop::EffectBoundary {
                boundary: PcodeExecutionStop::OpaqueBoundary { .. }
            }
        ));
    }

    #[test]
    fn relative_pcode_branch_uses_signed_intra_instruction_index() {
        let snapshot = single_instruction_snapshot(vec![
            operation(4, "BRANCH", 0, None, vec![node("const", "0x2", 8)]),
            operation(
                1,
                "COPY",
                1,
                Some(node("register", "0x0", 8)),
                vec![node("const", "0x0", 8)],
            ),
            operation(
                1,
                "COPY",
                2,
                Some(node("register", "0x0", 8)),
                vec![node("const", "0x2a", 8)],
            ),
            operation(10, "RETURN", 3, None, vec![node("register", "0x0", 8)]),
        ]);
        let trace = snapshot
            .execute_concrete_path(&PcodeConcreteState::default(), None, 8, 2)
            .unwrap();
        assert!(matches!(trace.stop, PcodePathStop::Return { .. }));
        assert_eq!(trace.instruction_visits.len(), 1);
        assert_eq!(trace.events.len(), 2);
        assert_eq!(
            trace
                .final_state
                .read_varnode(&node("register", "0x0", 8))
                .unwrap(),
            Some(42)
        );
        assert!(matches!(
            trace.events[0],
            PcodePathEvent::Branch {
                destination: PcodePathDestination::IntraInstruction {
                    sequence_index: 2,
                    ..
                },
                ..
            }
        ));

        let narrow_negative = single_instruction_snapshot(vec![
            operation(4, "BRANCH", 0, None, vec![node("const", "0x2", 1)]),
            operation(10, "RETURN", 1, None, vec![node("register", "0x0", 8)]),
            operation(4, "BRANCH", 2, None, vec![node("const", "0xff", 1)]),
        ]);
        let back = narrow_negative
            .execute_concrete_path(&PcodeConcreteState::default(), None, 8, 1)
            .unwrap();
        assert!(matches!(back.stop, PcodePathStop::Return { .. }));
        assert!(matches!(
            back.events[1],
            PcodePathEvent::Branch {
                destination: PcodePathDestination::IntraInstruction {
                    sequence_index: 1,
                    ..
                },
                ..
            }
        ));

        let mut overwide = narrow_negative.clone();
        overwide.selected_function.instructions[0].pcode[2].inputs[0].offset = "0x1ff".to_owned();
        let rejected = overwide
            .execute_concrete_path(&PcodeConcreteState::default(), None, 8, 1)
            .unwrap();
        assert!(matches!(
            rejected.stop,
            PcodePathStop::MalformedTarget { .. }
        ));

        let loop_snapshot = single_instruction_snapshot(vec![
            operation(
                1,
                "COPY",
                0,
                Some(node("register", "0x0", 8)),
                vec![node("const", "0x1", 8)],
            ),
            operation(
                4,
                "BRANCH",
                1,
                None,
                vec![node("const", "0xffffffffffffffff", 8)],
            ),
        ]);
        let bounded = loop_snapshot
            .execute_concrete_path(&PcodeConcreteState::default(), None, 5, 1)
            .unwrap();
        assert!(matches!(
            bounded.stop,
            PcodePathStop::OperationBudget { .. }
        ));
        assert_eq!(bounded.instruction_visits.len(), 1);
        assert_eq!(bounded.events.len(), 5);
    }

    #[test]
    fn unresolved_targets_and_visit_budget_are_explicit() {
        let malformed = single_instruction_snapshot(vec![operation(
            4,
            "BRANCH",
            0,
            None,
            vec![node("const", "0x63", 8)],
        )]);
        let trace = malformed
            .execute_concrete_path(&PcodeConcreteState::default(), None, 4, 4)
            .unwrap();
        assert!(matches!(trace.stop, PcodePathStop::MalformedTarget { .. }));

        let indirect = single_instruction_snapshot(vec![operation(
            6,
            "BRANCHIND",
            0,
            None,
            vec![node("register", "0x0", 8)],
        )]);
        let unknown = indirect
            .execute_concrete_path(&PcodeConcreteState::default(), None, 4, 4)
            .unwrap();
        assert!(matches!(
            unknown.stop,
            PcodePathStop::UnknownIndirectTarget { .. }
        ));
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&node("register", "0x0", 8), 0x2013d9)
            .unwrap();
        let outside = indirect.execute_concrete_path(&seed, None, 4, 4).unwrap();
        assert!(matches!(
            outside.stop,
            PcodePathStop::TargetNotSelected { .. }
        ));
        seed.write_varnode(&node("register", "0x0", 8), 0x2013cf)
            .unwrap();
        let indirect_loop = indirect.execute_concrete_path(&seed, None, 8, 2).unwrap();
        assert!(matches!(
            indirect_loop.stop,
            PcodePathStop::VisitBudget { .. }
        ));
        assert!(matches!(
            indirect_loop.events[0],
            PcodePathEvent::Branch {
                branch_kind: PcodePathBranchKind::IndirectBranch,
                ..
            }
        ));

        let wrong_width = single_instruction_snapshot(vec![operation(
            6,
            "BRANCHIND",
            0,
            None,
            vec![node("register", "0x0", 4)],
        )]);
        let mismatch = wrong_width
            .execute_concrete_path(&seed, None, 4, 4)
            .unwrap();
        assert!(matches!(
            mismatch.stop,
            PcodePathStop::MalformedTarget { .. }
        ));

        let self_loop = single_instruction_snapshot(vec![operation(
            4,
            "BRANCH",
            0,
            None,
            vec![node("ram", "0x2013cf", 8)],
        )]);
        let visits = self_loop
            .execute_concrete_path(&PcodeConcreteState::default(), None, 8, 2)
            .unwrap();
        assert!(matches!(visits.stop, PcodePathStop::VisitBudget { .. }));
        assert_eq!(visits.instruction_visits.len(), 2);

        let no_flow = single_instruction_snapshot(vec![operation(
            1,
            "COPY",
            0,
            Some(node("register", "0x0", 8)),
            vec![node("const", "0x1", 8)],
        )]);
        let end = no_flow
            .execute_concrete_path(&PcodeConcreteState::default(), None, 4, 4)
            .unwrap();
        assert!(matches!(
            end.stop,
            PcodePathStop::UnresolvedFallthrough { .. }
        ));

        let call = single_instruction_snapshot(vec![operation(
            7,
            "CALL",
            0,
            None,
            vec![node("ram", "0x2013d9", 8)],
        )]);
        let call_trace = call
            .execute_concrete_path(&PcodeConcreteState::default(), None, 4, 4)
            .unwrap();
        assert!(matches!(call_trace.stop, PcodePathStop::Call { .. }));
        assert!(call_trace.events.is_empty());
    }

    #[test]
    fn overlapping_register_slices_and_read_before_write_are_little_endian() {
        let operations = vec![
            operation(
                1,
                "COPY",
                0,
                Some(node("register", "0x1", 1)),
                vec![node("const", "0xaa", 1)],
            ),
            operation(
                1,
                "COPY",
                1,
                Some(node("unique", "0x10", 8)),
                vec![node("register", "0x0", 8)],
            ),
            operation(
                19,
                "INT_ADD",
                2,
                Some(node("register", "0x0", 1)),
                vec![node("register", "0x0", 1), node("const", "0x1", 1)],
            ),
            operation(
                2,
                "LOAD",
                3,
                Some(node("register", "0x20", 8)),
                vec![node("const", "0x1", 8), node("register", "0x8", 8)],
            ),
        ];
        let mut initial = PcodeConcreteState::default();
        initial
            .write_varnode(&node("register", "0x0", 8), 0x1122_3344_5566_7788)
            .unwrap();
        let trace = function(operations)
            .execute_exact_prefix(&initial, 16)
            .unwrap();
        assert_eq!(trace.executed.len(), 3);
        assert_eq!(trace.executed[1].input_values, vec![0x1122_3344_5566_aa88]);
        assert_eq!(trace.executed[2].input_values, vec![0x88, 1]);
        assert_eq!(
            trace
                .final_state
                .read_varnode(&node("register", "0x0", 8))
                .unwrap(),
            Some(0x1122_3344_5566_aa89)
        );
        assert_eq!(
            trace
                .final_state
                .read_varnode(&node("unique", "0x10", 8))
                .unwrap(),
            Some(0x1122_3344_5566_aa88)
        );
        assert!(matches!(
            trace.stop,
            PcodeExecutionStop::MemoryBoundary {
                source: PcodeOperation { opcode: 2, .. },
                reason: PcodeMemoryBoundaryKind::UnknownSpace,
                ..
            }
        ));
        assert_eq!(trace.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(trace.verification, VerificationStatus::NotRun);
        assert_eq!(
            initial.read_varnode(&node("register", "0x0", 8)).unwrap(),
            Some(0x1122_3344_5566_7788)
        );
    }

    #[test]
    fn unique_temporaries_do_not_leak_between_instructions() {
        let mut f = function(vec![operation(
            1,
            "COPY",
            0,
            Some(node("unique", "0x10", 1)),
            vec![node("const", "0x2a", 1)],
        )]);
        f.instructions.push(PcodeInstruction {
            address: address("0x401001"),
            bytes: "90".to_owned(),
            parsed_bytes: "90".to_owned(),
            mnemonic: "NOP".to_owned(),
            pcode: vec![operation(
                1,
                "COPY",
                0,
                Some(node("register", "0x0", 1)),
                vec![node("unique", "0x10", 1)],
            )],
        });
        let trace = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 16)
            .unwrap();
        assert_eq!(trace.executed.len(), 1);
        assert!(matches!(
            trace.stop,
            PcodeExecutionStop::MissingInput { input_index: 0, .. }
        ));
    }

    #[test]
    fn real_ghidra_fixture_stops_at_first_unsupported_effect() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_snapshot_v2.json"
        ));
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        let f = parse_ghidra_snapshot(bytes, digest)
            .unwrap()
            .pcode_function_ir()
            .unwrap();
        let mut state = PcodeConcreteState::default();
        state
            .write_varnode(&node("register", "0x38", 8), 7)
            .unwrap();
        state
            .write_varnode(&node("register", "0x30", 8), 5)
            .unwrap();
        let trace = f.execute_exact_prefix(&state, 32).unwrap();
        assert_eq!(trace.executed.len(), 3);
        assert!(matches!(
            &trace.stop,
            PcodeExecutionStop::OpaqueBoundary {
                source: PcodeOperation { mnemonic, source_address, .. },
                ..
            } if mnemonic == "INT_SBORROW" && source_address.offset == "0x20137f"
        ));
        let roundtrip: PcodeExecutionTrace =
            serde_json::from_slice(&serde_json::to_vec(&trace).unwrap()).unwrap();
        assert_eq!(roundtrip, trace);
    }

    #[test]
    fn unknown_input_and_budget_are_explicit_stops() {
        let f = function(vec![operation(
            1,
            "COPY",
            0,
            Some(node("register", "0x0", 1)),
            vec![node("register", "0x1", 1)],
        )]);
        let missing = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 1)
            .unwrap();
        assert!(matches!(
            missing.stop,
            PcodeExecutionStop::MissingInput { .. }
        ));
        let budget = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 0)
            .unwrap();
        assert!(matches!(
            budget.stop,
            PcodeExecutionStop::OperationBudget { .. }
        ));
    }

    #[test]
    fn full_width_constants_and_control_boundaries_are_preserved() {
        let state = PcodeConcreteState::default();
        assert_eq!(
            state
                .read_varnode(&node("const", "0xffffffffffffffff", 8))
                .unwrap(),
            Some(u64::MAX)
        );
        let f = function(vec![operation(
            10,
            "RETURN",
            0,
            None,
            vec![node("register", "0x0", 8)],
        )]);
        let trace = f.execute_exact_prefix(&state, 1).unwrap();
        assert!(trace.executed.is_empty());
        assert!(matches!(
            trace.stop,
            PcodeExecutionStop::OpaqueBoundary {
                source: PcodeOperation { opcode: 10, .. },
                ..
            }
        ));
    }

    #[test]
    fn real_ghidra_call_store_and_return_load_are_exact_when_bytes_are_known() {
        let mut store_function = real_calls_function();
        store_function.instructions = vec![store_function.instructions[1].clone()];
        let mut state = PcodeConcreteState::default();
        state
            .write_varnode(&node("register", "0x20", 8), 0x1000)
            .unwrap();
        let store = store_function.execute_exact_prefix(&state, 16).unwrap();
        assert_eq!(store.executed.len(), 2);
        let access = store.executed[1].memory_access.as_ref().unwrap();
        assert_eq!(access.kind, PcodeMemoryAccessKind::Store);
        assert_eq!(access.space, "ram");
        assert_eq!(access.space_id, 433);
        assert_eq!(access.pointer_offset, 0xff8);
        assert_eq!(access.byte_offset, 0xff8);
        assert_eq!(access.value, 0x2013b2);
        assert_eq!(store.executed[1].output_value, None);
        assert_eq!(
            store.final_state.read_memory("ram", 0xff8, 8).unwrap(),
            Some(0x2013b2)
        );
        assert!(matches!(
            store.stop,
            PcodeExecutionStop::OpaqueBoundary {
                source: PcodeOperation { opcode: 7, .. },
                ..
            }
        ));

        let mut load_function = real_calls_function();
        load_function.instructions = vec![load_function.instructions[3].clone()];
        let load = load_function
            .execute_exact_prefix(&store.final_state, 16)
            .unwrap();
        assert_eq!(load.executed.len(), 2);
        let access = load.executed[0].memory_access.as_ref().unwrap();
        assert_eq!(access.kind, PcodeMemoryAccessKind::Load);
        assert_eq!(access.value, 0x2013b2);
        assert_eq!(load.executed[0].output_value, Some(0x2013b2));
        assert_eq!(
            load.final_state
                .read_varnode(&node("register", "0x288", 8))
                .unwrap(),
            Some(0x2013b2)
        );
        assert_eq!(
            load.final_state
                .read_varnode(&node("register", "0x20", 8))
                .unwrap(),
            Some(0x1000)
        );
        assert!(matches!(
            load.stop,
            PcodeExecutionStop::OpaqueBoundary {
                source: PcodeOperation { opcode: 10, .. },
                ..
            }
        ));
        let roundtrip: PcodeExecutionTrace =
            serde_json::from_slice(&serde_json::to_vec(&load).unwrap()).unwrap();
        assert_eq!(roundtrip, load);
    }

    #[test]
    fn unknown_pointer_bytes_and_mismatched_width_stop_before_memory_effect() {
        let mut f = real_calls_function();
        f.instructions = vec![f.instructions[3].clone()];
        f.instructions[0].pcode.truncate(1);
        let unknown_alias = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 4)
            .unwrap();
        assert!(matches!(
            unknown_alias.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::UnknownAlias,
                pointer_offset: None,
                ..
            }
        ));
        assert!(unknown_alias.executed.is_empty());

        let mut state = PcodeConcreteState::default();
        state
            .write_varnode(&node("register", "0x20", 8), 0x1000)
            .unwrap();
        let unknown_bytes = f.execute_exact_prefix(&state, 4).unwrap();
        assert!(matches!(
            unknown_bytes.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::UnknownBytes,
                pointer_offset: Some(0x1000),
                ..
            }
        ));
        assert!(unknown_bytes.executed.is_empty());

        f.instructions[0].pcode[0].inputs[1].size = 4;
        let bad_width = f.execute_exact_prefix(&state, 4).unwrap();
        assert!(matches!(
            bad_width.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::UnsupportedLayout,
                ..
            }
        ));
        assert!(bad_width.executed.is_empty());
    }

    #[test]
    fn address_spaces_do_not_alias_and_pointer_offsets_scale_by_unit_size() {
        let mut f = function(vec![
            operation(
                3,
                "STORE",
                0,
                None,
                vec![
                    node("const", "0x1", 8),
                    node("const", "0x10", 8),
                    node("const", "0xbeef", 2),
                ],
            ),
            operation(
                2,
                "LOAD",
                1,
                Some(node("register", "0x0", 2)),
                vec![node("const", "0x2", 8), node("const", "0x20", 8)],
            ),
        ]);
        f.address_spaces = vec![
            GhidraAddressSpace {
                name: "ram_a".to_owned(),
                id: 1,
                space_type: 1,
                addressable_unit_size: 2,
                pointer_size: 8,
            },
            GhidraAddressSpace {
                name: "ram_b".to_owned(),
                id: 2,
                space_type: 1,
                addressable_unit_size: 1,
                pointer_size: 8,
            },
        ];
        let trace = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 4)
            .unwrap();
        assert_eq!(trace.executed.len(), 1);
        assert_eq!(
            trace.executed[0]
                .memory_access
                .as_ref()
                .unwrap()
                .byte_offset,
            0x20
        );
        assert_eq!(
            trace.final_state.read_memory("ram_a", 0x20, 2).unwrap(),
            Some(0xbeef)
        );
        assert_eq!(
            trace.final_state.read_memory("ram_b", 0x20, 2).unwrap(),
            None
        );
        assert!(matches!(
            trace.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::UnknownBytes,
                ..
            }
        ));

        f.instructions[0].pcode[1].inputs[0].offset = "0x1".to_owned();
        f.instructions[0].pcode[1].inputs[1].offset = "0x10".to_owned();
        let loaded = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 4)
            .unwrap();
        assert_eq!(loaded.executed.len(), 2);
        assert_eq!(loaded.executed[1].output_value, Some(0xbeef));
    }

    #[test]
    fn unknown_space_overflow_and_non_ram_space_never_execute_as_exact_memory() {
        let mut f = function(vec![operation(
            2,
            "LOAD",
            0,
            Some(node("register", "0x0", 1)),
            vec![
                node("const", "0x3", 8),
                node("const", "0xffffffffffffffff", 8),
            ],
        )]);
        f.address_spaces = vec![GhidraAddressSpace {
            name: "ram_a".to_owned(),
            id: 1,
            space_type: 1,
            addressable_unit_size: 2,
            pointer_size: 8,
        }];
        let unknown = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 2)
            .unwrap();
        assert!(matches!(
            unknown.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::UnknownSpace,
                ..
            }
        ));
        f.instructions[0].pcode[0].inputs[0].offset = "0x1".to_owned();
        let overflow = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 2)
            .unwrap();
        assert!(matches!(
            overflow.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::AddressOverflow,
                ..
            }
        ));
        f.address_spaces[0].space_type = 5;
        let stack = f
            .execute_exact_prefix(&PcodeConcreteState::default(), 2)
            .unwrap();
        assert!(matches!(
            stack.stop,
            PcodeExecutionStop::MemoryBoundary {
                reason: PcodeMemoryBoundaryKind::UnsupportedLayout,
                ..
            }
        ));
    }
}
