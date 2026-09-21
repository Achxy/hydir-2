//! Versioned native intermediate representations for Hydir's decompiler.
//!
//! These artifacts deliberately retain machine addresses, effects, and
//! uncertainty.  Lowering may make an artifact easier to read, but it may not
//! silently turn an unknown fact into an exact one.

use hydir_core::{Address, Location};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const FUNCTION_INDEX_VERSION: u32 = 1;
pub const MACHINE_FUNCTION_IR_VERSION: u32 = 1;
pub const STATE_FUNCTION_IR_VERSION: u32 = 1;
pub const FUNCTION_IR_VERSION: u32 = 1;
pub const CIR_VERSION: u32 = 1;

const MAX_FUNCTIONS: usize = 1_000_000;
const MAX_BLOCKS: usize = 1_000_000;
const MAX_INSTRUCTIONS: usize = 5_000_000;
const MAX_DIAGNOSTICS: usize = 65_536;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralCompleteness {
    #[default]
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticFidelity {
    #[default]
    Unknown,
    Conservative,
    ExactUnderModel,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    #[default]
    NotRun,
    StaticallyValidated,
    DifferentiallyTested,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IrDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Location>,
    pub blocks_stable_operation: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionEvidenceState {
    Confirmed,
    Probable,
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionEvidence {
    pub kind: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<Location>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionExtent {
    pub start: Location,
    pub size: u64,
    pub evidence_kind: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedFunction {
    pub id: String,
    pub entry: Location,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub state: FunctionEvidenceState,
    #[serde(default)]
    pub block_entries: Vec<Location>,
    /// Candidate extents remain plural until CFG recovery proves exact block
    /// membership for the function.
    #[serde(default)]
    pub extents: Vec<FunctionExtent>,
    #[serde(default)]
    pub evidence: Vec<FunctionEvidence>,
    /// Bounded control-transfer destinations observed while recovering this
    /// function. They remain candidates until their own entry evidence is
    /// strong enough for a FunctionIndex row.
    #[serde(default)]
    pub candidate_targets: Vec<Location>,
    /// Direct terminal branches that may be tail calls. Evidence remains
    /// separate from normalized call facts so discovery never invents a call.
    #[serde(default)]
    pub tail_call_evidence: Vec<FunctionEvidence>,
    #[serde(default)]
    pub unresolved_conflicts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionIndex {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub functions: Vec<IndexedFunction>,
    #[serde(default)]
    pub diagnostics: Vec<IrDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineOperand {
    Register {
        name: String,
        width_bits: u16,
    },
    Immediate {
        value: u64,
        width_bits: u16,
    },
    Memory {
        segment: Option<String>,
        base: Option<String>,
        index: Option<String>,
        scale: u32,
        displacement: i64,
        absolute: Option<u64>,
        width_bits: u16,
    },
    Branch {
        target: Location,
    },
    /// A control operand whose encoded bytes are a linker placeholder. The
    /// optional target is derived from ELF relocation evidence, never from
    /// the placeholder displacement.
    RelocatedBranch {
        relocation: Location,
        target: Option<Location>,
        symbol: Option<String>,
        relocation_kind: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MachineOperation {
    Exact { family: String },
    OpaqueEffect { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineMemoryEffect {
    None,
    Read,
    Write,
    ReadWrite,
    /// Orders prior and subsequent memory operations without itself naming a
    /// byte range. StateIR threads every memory region through this effect.
    Fence,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineControlEffect {
    Next,
    DirectBranch,
    ConditionalBranch,
    DirectCall,
    IndirectCall,
    Return,
    IndirectBranch,
    Stop,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineEffects {
    #[serde(default)]
    pub read_registers: Vec<String>,
    #[serde(default)]
    pub written_registers: Vec<String>,
    #[serde(default)]
    pub read_flags: Vec<String>,
    #[serde(default)]
    pub written_flags: Vec<String>,
    /// Architectural flags whose post-instruction value is explicitly
    /// undefined. These are outputs, but must never be treated as carrying
    /// their prior value or as a deterministic write.
    #[serde(default)]
    pub undefined_flags: Vec<String>,
    pub memory: MachineMemoryEffect,
    pub control: MachineControlEffect,
    pub conservative: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MachineEdgeKind {
    Fallthrough,
    Taken,
    Direct,
    IndirectTarget,
    Call,
    /// Architecturally possible synchronous exception with an unresolved
    /// handler/dispatcher target.
    Exception,
    External,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineEdge {
    pub kind: MachineEdgeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Location>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct InstructionDecorators {
    /// EVEX writemask register. `None` means that every lane is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub op_mask: Option<String>,
    /// Inactive lanes become zero instead of retaining the old destination.
    #[serde(default)]
    pub zeroing: bool,
    /// A memory scalar is broadcast across vector lanes.
    #[serde(default)]
    pub broadcast: bool,
    /// Embedded EVEX rounding mode. Absence uses the MXCSR rounding mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rounding: Option<String>,
    /// EVEX suppress-all-exceptions decoration independent of embedded
    /// rounding. Rounding itself also suppresses exceptions architecturally.
    #[serde(default)]
    pub suppress_all_exceptions: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineInstruction {
    pub address: Location,
    pub bytes_hex: String,
    pub mnemonic: String,
    #[serde(default)]
    pub operands: Vec<MachineOperand>,
    #[serde(default)]
    pub decorators: InstructionDecorators,
    pub operation: MachineOperation,
    pub effects: MachineEffects,
    #[serde(default)]
    pub edges: Vec<MachineEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineBlock {
    pub label: String,
    pub address: Location,
    pub instructions: Vec<MachineInstruction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineFunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_id: String,
    pub name: String,
    pub entry: Location,
    pub byte_length: u64,
    pub blocks: Vec<MachineBlock>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    #[serde(default)]
    pub diagnostics: Vec<IrDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateOperation {
    Exact {
        address: Location,
        family: String,
        operands: Vec<MachineOperand>,
        #[serde(default)]
        decorators: InstructionDecorators,
        #[serde(default)]
        input_components: Vec<StateComponentVersion>,
        #[serde(default)]
        output_components: Vec<StateComponentVersion>,
        #[serde(default)]
        undefined_outputs: Vec<String>,
        input_state: u32,
        output_state: u32,
    },
    Unknown {
        address: Location,
        reason: String,
        #[serde(default)]
        input_components: Vec<StateComponentVersion>,
        #[serde(default)]
        output_components: Vec<StateComponentVersion>,
        input_state: u32,
        output_state: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateBlock {
    pub label: String,
    pub address: Location,
    pub operations: Vec<StateOperation>,
    pub edges: Vec<MachineEdge>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_flow: Option<StateBlockFlow>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateBlockFlow {
    pub input_state: u32,
    pub output_state: u32,
    #[serde(default)]
    pub incoming: Vec<StateIncoming>,
    #[serde(default)]
    pub component_phis: Vec<StateComponentPhi>,
    #[serde(default)]
    pub component_outputs: Vec<StateComponentVersion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct StateComponentVersion {
    pub component: String,
    pub version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateComponentPhi {
    pub component: String,
    pub output_version: u32,
    #[serde(default)]
    pub incoming: Vec<StateComponentIncoming>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateComponentIncoming {
    pub predecessor: Location,
    pub version: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateIncoming {
    pub predecessor: Location,
    pub state: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StateFunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_id: String,
    pub entry: Location,
    pub blocks: Vec<StateBlock>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    #[serde(default)]
    pub diagnostics: Vec<IrDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AbiValue {
    pub name: String,
    pub location: String,
    pub type_name: String,
    pub inferred: bool,
    #[serde(default)]
    pub evidence: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveredAccessKind {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StackObject {
    pub id: String,
    pub base_register: String,
    pub displacement: i64,
    pub width_bits: u16,
    pub access: RecoveredAccessKind,
    pub sites: Vec<Location>,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GlobalObject {
    pub id: String,
    pub location: Location,
    pub width_bits: u16,
    pub access: RecoveredAccessKind,
    pub sites: Vec<Location>,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub site: Location,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    pub indirect: bool,
    pub tail_call: bool,
    #[serde(default)]
    pub noreturn: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<String>,
    /// ABI locations and types for fixed call arguments when supported by
    /// direct evidence such as an audited external signature.
    #[serde(default)]
    pub arguments: Vec<AbiValue>,
    /// ABI locations and types for call results. Empty remains distinct from
    /// proving that a call returns no value unless the evidence says so.
    #[serde(default)]
    pub returns: Vec<AbiValue>,
    /// True only when the recovered prototype explicitly has an ellipsis.
    #[serde(default)]
    pub variadic: bool,
    pub evidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AliasSet {
    pub id: String,
    pub members: Vec<String>,
    pub evidence: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerOriginKind {
    Parameter,
    StackAddress,
    ImageAddress,
    TlsAddress,
    AllocatorReturn,
    MappedReturn,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PointerProvenance {
    pub id: String,
    pub value_location: String,
    pub origin: PointerOriginKind,
    pub target_regions: Vec<String>,
    pub sites: Vec<Location>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_id: String,
    pub name: String,
    pub entry: Location,
    pub calling_convention: String,
    #[serde(default)]
    pub parameters: Vec<AbiValue>,
    #[serde(default)]
    pub returns: Vec<AbiValue>,
    #[serde(default)]
    pub stack_objects: Vec<StackObject>,
    #[serde(default)]
    pub global_objects: Vec<GlobalObject>,
    #[serde(default)]
    pub calls: Vec<FunctionCall>,
    #[serde(default)]
    pub alias_sets: Vec<AliasSet>,
    #[serde(default)]
    pub pointer_provenance: Vec<PointerProvenance>,
    pub blocks: Vec<StateBlock>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    pub rewrite_ready: bool,
    #[serde(default)]
    pub diagnostics: Vec<IrDiagnostic>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CirStatement {
    Operation {
        address: Location,
        family: String,
        operands: Vec<MachineOperand>,
        #[serde(default)]
        decorators: InstructionDecorators,
        effects: MachineEffects,
    },
    OpaqueEffect {
        address: Location,
        bytes_hex: String,
        reason: String,
        effects: MachineEffects,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CirTerminator {
    Fallthrough {
        target: Location,
    },
    Goto {
        target: Location,
    },
    Branch {
        condition: String,
        taken: Location,
        fallthrough: Location,
    },
    Call {
        target: Option<Location>,
        /// The decoded register or memory expression used by an indirect
        /// call. Older CIR v1 artifacts omit this field; a missing operand
        /// therefore means that only an unresolved call event is known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_operand: Option<MachineOperand>,
        next: Option<Location>,
    },
    Switch {
        dispatch: Location,
        targets: Vec<Location>,
        unresolved_default: bool,
    },
    Return,
    Exit {
        target: Option<Location>,
    },
    Unresolved {
        reason: String,
        /// Decoded runtime control expression when the destination itself is
        /// unknown. This is additive within CIR v1 so older artifacts that
        /// only carried a reason continue to deserialize.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target_operand: Option<MachineOperand>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CirBlock {
    pub label: String,
    pub address: Location,
    #[serde(default)]
    pub statements: Vec<CirStatement>,
    pub terminator: CirTerminator,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Cir {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_id: String,
    pub name: String,
    pub entry: Location,
    pub blocks: Vec<CirBlock>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    pub rewrite_ready: bool,
    #[serde(default)]
    pub diagnostics: Vec<IrDiagnostic>,
}

fn validate_digest(digest: &str) -> Result<(), String> {
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("artifact binary_sha256 is not a lowercase-compatible SHA-256".to_owned());
    }
    Ok(())
}

fn validate_location(location: Location) -> Result<(), String> {
    if location.address_space > 1_000_000 {
        return Err("artifact location address space exceeds bound".to_owned());
    }
    Ok(())
}

fn validate_diagnostics(diagnostics: &[IrDiagnostic]) -> Result<(), String> {
    if diagnostics.len() > MAX_DIAGNOSTICS
        || diagnostics.iter().any(|diagnostic| {
            diagnostic.code.is_empty()
                || diagnostic.code.len() > 128
                || diagnostic.message.is_empty()
                || diagnostic.message.len() > 4096
        })
    {
        return Err("artifact diagnostics are invalid or exceed bounds".to_owned());
    }
    Ok(())
}

pub fn validate_function_index(index: &FunctionIndex) -> Result<(), String> {
    if index.schema_version != FUNCTION_INDEX_VERSION {
        return Err(format!(
            "unsupported FunctionIndex schema version {}",
            index.schema_version
        ));
    }
    validate_digest(&index.binary_sha256)?;
    validate_diagnostics(&index.diagnostics)?;
    if index.functions.len() > MAX_FUNCTIONS {
        return Err("FunctionIndex exceeds function bound".to_owned());
    }
    let mut ids = BTreeSet::new();
    let id_prefix = format!("sha256:{}:", index.binary_sha256);
    for function in &index.functions {
        validate_location(function.entry)?;
        if function.id.is_empty()
            || function.id.len() > 256
            || !function.id.starts_with(&id_prefix)
            || !ids.insert(function.id.as_str())
            || function.block_entries.is_empty()
            || !function.block_entries.contains(&function.entry)
            || function.block_entries.len() > MAX_BLOCKS
            || function.extents.len() > 4096
            || function.evidence.len() > 1024
            || function.candidate_targets.len() > MAX_BLOCKS
            || function.tail_call_evidence.len() > 1024
            || function.unresolved_conflicts.len() > 1024
            || function
                .unresolved_conflicts
                .iter()
                .any(|conflict| conflict.is_empty() || conflict.len() > 4096)
        {
            return Err("FunctionIndex contains an invalid function".to_owned());
        }
        for block_entry in &function.block_entries {
            validate_location(*block_entry)?;
            if block_entry.address_space != function.entry.address_space {
                return Err("FunctionIndex block entry changes address space".to_owned());
            }
        }
        for target in &function.candidate_targets {
            validate_location(*target)?;
        }
        for extent in &function.extents {
            validate_location(extent.start)?;
            if extent.start.address_space != function.entry.address_space
                || extent.size == 0
                || extent.start.value.0.checked_add(extent.size).is_none()
                || extent.evidence_kind.is_empty()
                || extent.evidence_kind.len() > 128
            {
                return Err("FunctionIndex contains an invalid extent".to_owned());
            }
        }
        for evidence in function.evidence.iter().chain(&function.tail_call_evidence) {
            if evidence.kind.is_empty()
                || evidence.kind.len() > 128
                || evidence.description.is_empty()
                || evidence.description.len() > 4096
            {
                return Err("FunctionIndex contains invalid evidence".to_owned());
            }
            if let Some(site) = evidence.site {
                validate_location(site)?;
            }
        }
    }
    Ok(())
}

pub fn validate_machine_function_ir(ir: &MachineFunctionIr) -> Result<(), String> {
    if ir.schema_version != MACHINE_FUNCTION_IR_VERSION {
        return Err(format!(
            "unsupported MachineFunctionIR schema version {}",
            ir.schema_version
        ));
    }
    validate_digest(&ir.binary_sha256)?;
    validate_location(ir.entry)?;
    validate_diagnostics(&ir.diagnostics)?;
    if ir.function_id.is_empty()
        || ir.name.is_empty()
        || ir.byte_length == 0
        || ir.blocks.is_empty()
        || ir.blocks.len() > MAX_BLOCKS
    {
        return Err("MachineFunctionIR identity or block count is invalid".to_owned());
    }
    let mut addresses = BTreeSet::new();
    let mut block_addresses = BTreeSet::new();
    let mut instruction_count = 0usize;
    let mut has_opaque = false;
    for block in &ir.blocks {
        validate_location(block.address)?;
        if block.address.address_space != ir.entry.address_space
            || block.label.is_empty()
            || block.instructions.is_empty()
            || !block_addresses.insert(block.address)
            || block.instructions[0].address != block.address
        {
            return Err("MachineFunctionIR contains an empty block".to_owned());
        }
        for instruction in &block.instructions {
            instruction_count = instruction_count
                .checked_add(1)
                .ok_or_else(|| "MachineFunctionIR instruction count overflows".to_owned())?;
            validate_location(instruction.address)?;
            if instruction.bytes_hex.is_empty()
                || instruction.bytes_hex.len() > 30
                || instruction.bytes_hex.len() % 2 != 0
                || !instruction
                    .bytes_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || instruction.mnemonic.is_empty()
                || !addresses.insert(instruction.address)
            {
                return Err("MachineFunctionIR contains an invalid instruction".to_owned());
            }
            if instruction.address.address_space != ir.entry.address_space {
                return Err("MachineFunctionIR instruction changes address space".to_owned());
            }
            let opaque = matches!(instruction.operation, MachineOperation::OpaqueEffect { .. });
            for operand in &instruction.operands {
                validate_machine_operand(operand, opaque)?;
            }
            validate_instruction_decorators(&instruction.decorators)?;
            validate_machine_effects(&instruction.effects)?;
            validate_edges(&instruction.edges)?;
            match instruction.operation {
                MachineOperation::Exact { .. } if instruction.effects.conservative => {
                    return Err(
                        "MachineFunctionIR exact operation has conservative effects".to_owned()
                    );
                }
                MachineOperation::OpaqueEffect { .. } => {
                    has_opaque = true;
                    if !instruction.effects.conservative {
                        return Err(
                            "MachineFunctionIR opaque operation is not conservative".to_owned()
                        );
                    }
                }
                MachineOperation::Exact { .. } => {}
            }
        }
    }
    if instruction_count > MAX_INSTRUCTIONS {
        return Err("MachineFunctionIR exceeds instruction bound".to_owned());
    }
    if !addresses.contains(&ir.entry) {
        return Err("MachineFunctionIR entry is not an instruction".to_owned());
    }
    if has_opaque && ir.semantic_fidelity == SemanticFidelity::ExactUnderModel {
        return Err("MachineFunctionIR with opaque operations claims exact semantics".to_owned());
    }
    Ok(())
}

fn validate_machine_effects(effects: &MachineEffects) -> Result<(), String> {
    for names in [
        &effects.read_registers,
        &effects.written_registers,
        &effects.read_flags,
        &effects.written_flags,
        &effects.undefined_flags,
    ] {
        if names.len() > 1024
            || names.iter().any(|name| name.is_empty() || name.len() > 64)
            || names.iter().collect::<BTreeSet<_>>().len() != names.len()
        {
            return Err("MachineFunctionIR contains invalid effect names".to_owned());
        }
    }
    if effects
        .undefined_flags
        .iter()
        .any(|flag| effects.written_flags.contains(flag))
    {
        return Err("MachineFunctionIR flag cannot be both written and undefined".to_owned());
    }
    Ok(())
}

fn validate_instruction_decorators(decorators: &InstructionDecorators) -> Result<(), String> {
    if decorators.zeroing && decorators.op_mask.is_none() {
        return Err("zeroing decoration requires an opmask register".to_owned());
    }
    if decorators.op_mask.as_deref().is_some_and(|name| {
        name.strip_prefix('k')
            .and_then(|index| index.parse::<u8>().ok())
            .is_none_or(|index| index >= 8)
    }) {
        return Err("instruction decorator has an invalid opmask register".to_owned());
    }
    if decorators
        .rounding
        .as_deref()
        .is_some_and(|mode| !matches!(mode, "nearest" | "down" | "up" | "toward_zero"))
    {
        return Err("instruction decorator has an invalid embedded rounding mode".to_owned());
    }
    Ok(())
}

fn validate_machine_operand(
    operand: &MachineOperand,
    allow_unknown_width: bool,
) -> Result<(), String> {
    match operand {
        MachineOperand::Register { name, width_bits } => {
            if name.is_empty() || name.len() > 32 || *width_bits == 0 || *width_bits > 512 {
                return Err("MachineFunctionIR contains an invalid register operand".to_owned());
            }
        }
        MachineOperand::Immediate { width_bits, .. } => {
            if *width_bits == 0 || *width_bits > 512 {
                return Err("MachineFunctionIR contains an invalid operand width".to_owned());
            }
        }
        MachineOperand::Memory { width_bits, .. } => {
            if *width_bits > 4096 || (*width_bits == 0 && !allow_unknown_width) {
                return Err("MachineFunctionIR contains an invalid memory width".to_owned());
            }
        }
        MachineOperand::Branch { target } => validate_location(*target)?,
        MachineOperand::RelocatedBranch {
            relocation,
            target,
            symbol,
            relocation_kind,
        } => {
            validate_location(*relocation)?;
            if let Some(target) = target {
                validate_location(*target)?;
            }
            if symbol.as_ref().is_some_and(|symbol| symbol.len() > 4096)
                || relocation_kind.is_empty()
                || relocation_kind.len() > 128
            {
                return Err(
                    "MachineFunctionIR contains invalid relocated branch metadata".to_owned(),
                );
            }
        }
    }
    Ok(())
}

fn validate_edges(edges: &[MachineEdge]) -> Result<(), String> {
    if edges.len() > 4096 {
        return Err("IR block edge count exceeds bound".to_owned());
    }
    for edge in edges {
        if let Some(target) = edge.target {
            validate_location(target)?;
        }
    }
    Ok(())
}

fn validate_state_blocks(blocks: &[StateBlock], entry: Location) -> Result<bool, String> {
    let mut addresses = BTreeSet::new();
    let mut state_definitions = BTreeSet::new();
    let mut component_definitions = BTreeSet::new();
    let mut block_outputs = std::collections::BTreeMap::new();
    let mut has_unknown = false;
    let mut has_component_ssa = false;
    for block in blocks {
        validate_location(block.address)?;
        validate_edges(&block.edges)?;
        if block.address.address_space != entry.address_space
            || block.label.is_empty()
            || !addresses.insert(block.address)
        {
            return Err("state IR contains an invalid or duplicate block".to_owned());
        }
        let mut expected_input = block.state_flow.as_ref().map(|flow| flow.input_state);
        if let Some(flow) = &block.state_flow {
            if flow.incoming.len() > 4096
                || !state_definitions.insert(flow.input_state)
                || flow
                    .incoming
                    .iter()
                    .any(|incoming| incoming.predecessor.address_space != entry.address_space)
            {
                return Err("state IR contains an invalid block-state merge".to_owned());
            }
            validate_component_versions(&flow.component_outputs)?;
            if !flow.component_phis.is_empty() || !flow.component_outputs.is_empty() {
                has_component_ssa = true;
                let output_names = flow
                    .component_outputs
                    .iter()
                    .map(|output| output.component.as_str())
                    .collect::<BTreeSet<_>>();
                let phi_names = flow
                    .component_phis
                    .iter()
                    .map(|phi| phi.component.as_str())
                    .collect::<BTreeSet<_>>();
                if flow.component_phis.len() > 256
                    || output_names != phi_names
                    || phi_names.len() != flow.component_phis.len()
                {
                    return Err("state IR contains invalid component flow".to_owned());
                }
                let expected_predecessors = flow
                    .incoming
                    .iter()
                    .map(|incoming| incoming.predecessor)
                    .collect::<BTreeSet<_>>();
                for phi in &flow.component_phis {
                    if !valid_component_name(&phi.component)
                        || !component_definitions
                            .insert((phi.component.clone(), phi.output_version))
                    {
                        return Err("state IR contains duplicate component definitions".to_owned());
                    }
                    let predecessors = phi
                        .incoming
                        .iter()
                        .map(|incoming| incoming.predecessor)
                        .collect::<BTreeSet<_>>();
                    if phi.incoming.len() > 4096
                        || predecessors.len() != phi.incoming.len()
                        || predecessors != expected_predecessors
                    {
                        return Err("state IR contains invalid component phi inputs".to_owned());
                    }
                }
            }
        }
        for operation in &block.operations {
            if let StateOperation::Exact { decorators, .. } = operation {
                validate_instruction_decorators(decorators)?;
            }
            if let StateOperation::Exact {
                undefined_outputs, ..
            } = operation
                && (undefined_outputs.len() > 1024
                    || undefined_outputs.iter().any(|name| {
                        name.is_empty() || name.len() > 80 || !name.starts_with("flag:")
                    })
                    || undefined_outputs.iter().collect::<BTreeSet<_>>().len()
                        != undefined_outputs.len())
            {
                return Err("state IR contains invalid undefined outputs".to_owned());
            }
            let (
                address,
                input_state,
                output_state,
                unknown,
                component_inputs,
                component_outputs,
                undefined_outputs,
            ) = match operation {
                StateOperation::Exact {
                    address,
                    input_state,
                    output_state,
                    input_components,
                    output_components,
                    undefined_outputs,
                    ..
                } => (
                    *address,
                    *input_state,
                    *output_state,
                    false,
                    input_components,
                    output_components,
                    Some(undefined_outputs),
                ),
                StateOperation::Unknown {
                    address,
                    input_state,
                    output_state,
                    input_components,
                    output_components,
                    ..
                } => (
                    *address,
                    *input_state,
                    *output_state,
                    true,
                    input_components,
                    output_components,
                    None,
                ),
            };
            validate_component_versions(component_inputs)?;
            validate_component_versions(component_outputs)?;
            has_component_ssa |= !component_inputs.is_empty() || !component_outputs.is_empty();
            for output in component_outputs {
                if !component_definitions.insert((output.component.clone(), output.version)) {
                    return Err("state IR contains duplicate component definitions".to_owned());
                }
            }
            if undefined_outputs.is_some_and(|undefined| {
                undefined.iter().any(|name| {
                    !component_outputs
                        .iter()
                        .any(|output| output.component == *name)
                })
            }) {
                return Err("state IR undefined output has no component definition".to_owned());
            }
            validate_location(address)?;
            if address.address_space != entry.address_space
                || output_state <= input_state
                || expected_input.is_some_and(|expected| input_state != expected)
                || !state_definitions.insert(output_state)
            {
                return Err("state IR contains an invalid state transition".to_owned());
            }
            expected_input = Some(output_state);
            has_unknown |= unknown;
        }
        if let Some(flow) = &block.state_flow {
            if expected_input != Some(flow.output_state) {
                return Err("state IR block output does not follow its operations".to_owned());
            }
            block_outputs.insert(block.address, flow.output_state);
        }
    }
    if !addresses.contains(&entry) {
        return Err("state IR entry is not a block".to_owned());
    }
    if has_component_ssa
        && blocks.iter().any(|block| {
            block.state_flow.as_ref().is_none_or(|flow| {
                flow.component_phis.is_empty() || flow.component_outputs.is_empty()
            })
        })
    {
        return Err("state IR has incomplete component SSA metadata".to_owned());
    }
    for block in blocks {
        if let Some(flow) = &block.state_flow {
            let mut predecessors = BTreeSet::new();
            for incoming in &flow.incoming {
                if !predecessors.insert(incoming.predecessor)
                    || block_outputs.get(&incoming.predecessor) != Some(&incoming.state)
                {
                    return Err("state IR incoming state does not match its predecessor".to_owned());
                }
            }
        }
    }
    Ok(has_unknown)
}

fn validate_component_versions(versions: &[StateComponentVersion]) -> Result<(), String> {
    if versions.len() > 1024
        || versions
            .iter()
            .any(|version| !valid_component_name(&version.component))
        || versions
            .iter()
            .map(|version| version.component.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != versions.len()
    {
        return Err("state IR contains invalid component versions".to_owned());
    }
    Ok(())
}

fn valid_component_name(name: &str) -> bool {
    name == "control"
        || ["register:", "flag:", "memory:"].iter().any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|suffix| !suffix.is_empty())
        })
}

pub fn validate_state_function_ir(ir: &StateFunctionIr) -> Result<(), String> {
    if ir.schema_version != STATE_FUNCTION_IR_VERSION {
        return Err(format!(
            "unsupported StateFunctionIR schema version {}",
            ir.schema_version
        ));
    }
    validate_digest(&ir.binary_sha256)?;
    validate_location(ir.entry)?;
    validate_diagnostics(&ir.diagnostics)?;
    if ir.function_id.is_empty() || ir.blocks.is_empty() || ir.blocks.len() > MAX_BLOCKS {
        return Err("StateFunctionIR identity or block count is invalid".to_owned());
    }
    let has_unknown = validate_state_blocks(&ir.blocks, ir.entry)?;
    if has_unknown && ir.semantic_fidelity == SemanticFidelity::ExactUnderModel {
        return Err("StateFunctionIR with unknown operations claims exact semantics".to_owned());
    }
    Ok(())
}

pub fn validate_function_ir(ir: &FunctionIr) -> Result<(), String> {
    if ir.schema_version != FUNCTION_IR_VERSION {
        return Err(format!(
            "unsupported FunctionIR schema version {}",
            ir.schema_version
        ));
    }
    validate_digest(&ir.binary_sha256)?;
    validate_location(ir.entry)?;
    validate_diagnostics(&ir.diagnostics)?;
    if ir.function_id.is_empty()
        || ir.name.is_empty()
        || ir.calling_convention.is_empty()
        || ir.blocks.is_empty()
        || ir.blocks.len() > MAX_BLOCKS
        || (ir.rewrite_ready
            && (ir.structural_completeness != StructuralCompleteness::Complete
                || ir.semantic_fidelity != SemanticFidelity::ExactUnderModel))
    {
        return Err("FunctionIR identity, blocks, or rewrite readiness is invalid".to_owned());
    }
    if ir.parameters.len() > 1024
        || ir.returns.len() > 16
        || ir.stack_objects.len() > 65_536
        || ir.global_objects.len() > 65_536
        || ir.calls.len() > 65_536
        || ir.alias_sets.len() > 65_536
        || ir.pointer_provenance.len() > 65_536
        || ir.parameters.iter().chain(&ir.returns).any(|value| {
            value.name.is_empty()
                || value.name.len() > 128
                || value.location.is_empty()
                || value.location.len() > 128
                || value.type_name.is_empty()
                || value.type_name.len() > 256
                || value.evidence.len() > 64
                || value
                    .evidence
                    .iter()
                    .any(|item| item.is_empty() || item.len() > 4096)
        })
    {
        return Err("FunctionIR ABI values are invalid or exceed bounds".to_owned());
    }
    if ir.stack_objects.iter().any(|object| {
        object.id.is_empty()
            || object.id.len() > 256
            || object.width_bits == 0
            || object.width_bits > 4096
            || object.sites.is_empty()
            || object.sites.len() > 65_536
            || object.evidence.is_empty()
            || object.evidence.len() > 4096
            || object
                .sites
                .iter()
                .any(|site| site.address_space != ir.entry.address_space)
    }) || ir.global_objects.iter().any(|object| {
        object.id.is_empty()
            || object.id.len() > 256
            || object.width_bits == 0
            || object.width_bits > 4096
            || object.sites.is_empty()
            || object.sites.len() > 65_536
            || object.evidence.is_empty()
            || object.evidence.len() > 4096
            || object
                .sites
                .iter()
                .any(|site| site.address_space != ir.entry.address_space)
    }) || ir.calls.iter().any(|call| {
        call.site.address_space != ir.entry.address_space
            || call
                .symbol
                .as_ref()
                .is_some_and(|symbol| symbol.len() > 4096)
            || call
                .prototype
                .as_ref()
                .is_some_and(|prototype| prototype.len() > 4096)
            || call.arguments.len() > 1024
            || call.returns.len() > 16
            || call.arguments.iter().chain(&call.returns).any(|value| {
                value.name.is_empty()
                    || value.name.len() > 256
                    || value.location.is_empty()
                    || value.location.len() > 256
                    || value.type_name.is_empty()
                    || value.type_name.len() > 4096
                    || value.evidence.len() > 256
                    || value
                        .evidence
                        .iter()
                        .any(|evidence| evidence.is_empty() || evidence.len() > 4096)
            })
            || call.evidence.is_empty()
            || call.evidence.len() > 4096
    }) || ir.alias_sets.iter().any(|set| {
        set.id.is_empty()
            || set.id.len() > 256
            || set.members.is_empty()
            || set.members.len() > 65_536
            || set.evidence.is_empty()
            || set.evidence.len() > 4096
    }) || ir.pointer_provenance.iter().any(|pointer| {
        pointer.id.is_empty()
            || pointer.id.len() > 256
            || pointer.value_location.is_empty()
            || pointer.value_location.len() > 256
            || pointer.target_regions.is_empty()
            || pointer.target_regions.len() > 16
            || pointer.target_regions.iter().any(|region| {
                !matches!(
                    region.as_str(),
                    "stack" | "image" | "tls" | "heap" | "volatile" | "unknown"
                )
            })
            || pointer.sites.is_empty()
            || pointer.sites.len() > 65_536
            || pointer
                .sites
                .iter()
                .any(|site| site.address_space != ir.entry.address_space)
            || pointer.evidence.is_empty()
            || pointer.evidence.len() > 64
            || pointer
                .evidence
                .iter()
                .any(|evidence| evidence.is_empty() || evidence.len() > 4096)
    }) {
        return Err("FunctionIR recovered object facts are invalid".to_owned());
    }
    if ir
        .pointer_provenance
        .iter()
        .map(|pointer| &pointer.id)
        .collect::<BTreeSet<_>>()
        .len()
        != ir.pointer_provenance.len()
    {
        return Err("FunctionIR pointer provenance IDs are not unique".to_owned());
    }
    let has_unknown = validate_state_blocks(&ir.blocks, ir.entry)?;
    if has_unknown && ir.semantic_fidelity == SemanticFidelity::ExactUnderModel {
        return Err("FunctionIR with unknown operations claims exact semantics".to_owned());
    }
    Ok(())
}

pub fn validate_cir(cir: &Cir) -> Result<(), String> {
    if cir.schema_version != CIR_VERSION {
        return Err(format!(
            "unsupported CIR schema version {}",
            cir.schema_version
        ));
    }
    validate_digest(&cir.binary_sha256)?;
    validate_location(cir.entry)?;
    validate_diagnostics(&cir.diagnostics)?;
    if cir.function_id.is_empty()
        || cir.name.is_empty()
        || cir.blocks.is_empty()
        || cir.blocks.len() > MAX_BLOCKS
        || (cir.rewrite_ready
            && (cir.structural_completeness != StructuralCompleteness::Complete
                || cir.semantic_fidelity != SemanticFidelity::ExactUnderModel))
    {
        return Err("CIR identity, blocks, or rewrite readiness is invalid".to_owned());
    }
    let mut addresses = BTreeSet::new();
    let mut has_opaque = false;
    for block in &cir.blocks {
        validate_location(block.address)?;
        if block.address.address_space != cir.entry.address_space
            || block.label.is_empty()
            || !addresses.insert(block.address)
        {
            return Err("CIR contains an invalid or duplicate block".to_owned());
        }
        for statement in &block.statements {
            let address = match statement {
                CirStatement::Operation {
                    address,
                    decorators,
                    ..
                } => {
                    validate_instruction_decorators(decorators)?;
                    *address
                }
                CirStatement::OpaqueEffect { address, .. } => {
                    has_opaque = true;
                    *address
                }
            };
            validate_location(address)?;
            if address.address_space != cir.entry.address_space {
                return Err("CIR statement changes address space".to_owned());
            }
        }
        validate_cir_terminator(&block.terminator)?;
    }
    if !addresses.contains(&cir.entry) {
        return Err("CIR entry is not a block".to_owned());
    }
    if has_opaque && cir.semantic_fidelity == SemanticFidelity::ExactUnderModel {
        return Err("CIR with opaque operations claims exact semantics".to_owned());
    }
    Ok(())
}

fn validate_cir_terminator(terminator: &CirTerminator) -> Result<(), String> {
    match terminator {
        CirTerminator::Fallthrough { target } | CirTerminator::Goto { target } => {
            validate_location(*target)
        }
        CirTerminator::Branch {
            condition,
            taken,
            fallthrough,
        } => {
            if condition.is_empty() || condition.len() > 256 {
                return Err("CIR branch condition is invalid".to_owned());
            }
            validate_location(*taken)?;
            validate_location(*fallthrough)
        }
        CirTerminator::Call {
            target,
            target_operand,
            next,
        } => {
            if let Some(target) = target {
                validate_location(*target)?;
            }
            if let Some(operand) = target_operand {
                validate_machine_operand(operand, false)?;
                if !matches!(
                    operand,
                    MachineOperand::Register { width_bits: 64, .. }
                        | MachineOperand::Memory { width_bits: 64, .. }
                ) {
                    return Err(
                        "CIR indirect-call target operand must be a 64-bit register or memory expression"
                            .to_owned(),
                    );
                }
            }
            if let Some(next) = next {
                validate_location(*next)?;
            }
            Ok(())
        }
        CirTerminator::Switch {
            dispatch, targets, ..
        } => {
            validate_location(*dispatch)?;
            if targets.is_empty() || targets.len() > 4096 {
                return Err("CIR switch target count is invalid".to_owned());
            }
            for target in targets {
                validate_location(*target)?;
            }
            Ok(())
        }
        CirTerminator::Exit { target } => {
            if let Some(target) = target {
                validate_location(*target)?;
            }
            Ok(())
        }
        CirTerminator::Unresolved {
            reason,
            target_operand,
        } => {
            if reason.is_empty() || reason.len() > 4096 {
                return Err("CIR unresolved terminator reason is invalid".to_owned());
            }
            if let Some(operand) = target_operand {
                validate_machine_operand(operand, false)?;
                if !matches!(
                    operand,
                    MachineOperand::Register { width_bits: 64, .. }
                        | MachineOperand::Memory { width_bits: 64, .. }
                ) {
                    return Err(
                        "CIR unresolved-control target operand must be a 64-bit register or memory expression"
                            .to_owned(),
                    );
                }
            }
            Ok(())
        }
        CirTerminator::Return => Ok(()),
    }
}

pub fn location(address_space: u32, value: u64) -> Location {
    Location {
        address_space,
        value: Address(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_index_rejects_duplicate_ids() {
        let function = IndexedFunction {
            id: format!("sha256:{}:f", "a".repeat(64)),
            entry: location(0, 0x1000),
            name: Some("f".to_owned()),
            state: FunctionEvidenceState::Confirmed,
            block_entries: vec![location(0, 0x1000)],
            extents: Vec::new(),
            evidence: Vec::new(),
            candidate_targets: Vec::new(),
            tail_call_evidence: Vec::new(),
            unresolved_conflicts: Vec::new(),
        };
        let index = FunctionIndex {
            schema_version: FUNCTION_INDEX_VERSION,
            binary_sha256: "a".repeat(64),
            functions: vec![function.clone(), function],
            diagnostics: Vec::new(),
        };
        assert!(validate_function_index(&index).is_err());
    }

    #[test]
    fn older_function_index_rows_default_new_evidence_collections() {
        let function: IndexedFunction = serde_json::from_str(&format!(
            r#"{{
                "id":"sha256:{}:f",
                "entry":{{"address_space":0,"value":"0x0000000000001000"}},
                "name":"f",
                "state":"confirmed",
                "block_entries":[],
                "extents":[],
                "evidence":[],
                "unresolved_conflicts":[]
            }}"#,
            "a".repeat(64)
        ))
        .unwrap();
        assert!(function.candidate_targets.is_empty());
        assert!(function.tail_call_evidence.is_empty());
    }

    #[test]
    fn machine_memory_width_accepts_bounded_architectural_state_images() {
        let operand = |width_bits| MachineOperand::Memory {
            segment: None,
            base: Some("rdi".to_owned()),
            index: None,
            scale: 1,
            displacement: 0,
            absolute: None,
            width_bits,
        };
        assert!(validate_machine_operand(&operand(4096), false).is_ok());
        assert!(validate_machine_operand(&operand(4097), false).is_err());
        assert!(validate_machine_operand(&operand(0), true).is_ok());
        assert!(validate_machine_operand(&operand(0), false).is_err());
    }

    #[test]
    fn rewrite_ready_requires_complete_exact_ir() {
        let ir = FunctionIr {
            schema_version: FUNCTION_IR_VERSION,
            binary_sha256: "b".repeat(64),
            function_id: "f".to_owned(),
            name: "f".to_owned(),
            entry: location(0, 0x1000),
            calling_convention: "sysv_amd64".to_owned(),
            parameters: Vec::new(),
            returns: Vec::new(),
            stack_objects: Vec::new(),
            global_objects: Vec::new(),
            calls: Vec::new(),
            alias_sets: Vec::new(),
            pointer_provenance: Vec::new(),
            blocks: vec![StateBlock {
                label: "b_1000".to_owned(),
                address: location(0, 0x1000),
                operations: Vec::new(),
                edges: Vec::new(),
                state_flow: None,
            }],
            structural_completeness: StructuralCompleteness::Partial,
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
            rewrite_ready: true,
            diagnostics: Vec::new(),
        };
        assert!(validate_function_ir(&ir).is_err());
        let mut legacy = serde_json::to_value(&ir).unwrap();
        legacy.as_object_mut().unwrap().remove("pointer_provenance");
        let decoded: FunctionIr = serde_json::from_value(legacy).unwrap();
        assert!(decoded.pointer_provenance.is_empty());
    }

    #[test]
    fn legacy_state_and_machine_effect_json_defaults_new_component_fields() {
        let effects: MachineEffects = serde_json::from_str(
            r#"{
                "read_registers":["rax"],
                "written_registers":["rax"],
                "read_flags":[],
                "written_flags":["zf"],
                "memory":"none",
                "control":"next",
                "conservative":false
            }"#,
        )
        .unwrap();
        assert!(effects.undefined_flags.is_empty());

        let operation: StateOperation = serde_json::from_str(
            r#"{
                "kind":"exact",
                "address":{"address_space":0,"value":"0x0000000000001000"},
                "family":"mov",
                "operands":[],
                "input_state":0,
                "output_state":1
            }"#,
        )
        .unwrap();
        assert!(matches!(
            operation,
            StateOperation::Exact {
                input_components,
                output_components,
                undefined_outputs,
                decorators,
                ..
            } if input_components.is_empty()
                && output_components.is_empty()
                && undefined_outputs.is_empty()
                && decorators == InstructionDecorators::default()
        ));

        let call: FunctionCall = serde_json::from_str(
            r#"{
                "site":{"address_space":0,"value":"0x0000000000001000"},
                "target":null,
                "symbol":"printf",
                "indirect":false,
                "tail_call":false,
                "noreturn":false,
                "prototype":"int printf(const char *format, ...)",
                "evidence":"legacy call fact"
            }"#,
        )
        .unwrap();
        assert!(call.arguments.is_empty());
        assert!(call.returns.is_empty());
        assert!(!call.variadic);

        let terminator: CirTerminator = serde_json::from_str(
            r#"{
                "kind":"call",
                "target":null,
                "next":{"address_space":0,"value":"0x0000000000001002"}
            }"#,
        )
        .unwrap();
        assert!(matches!(
            terminator,
            CirTerminator::Call {
                target: None,
                target_operand: None,
                next: Some(_)
            }
        ));

        let unresolved: CirTerminator = serde_json::from_str(
            r#"{
                "kind":"unresolved",
                "reason":"legacy unknown control"
            }"#,
        )
        .unwrap();
        assert!(matches!(
            unresolved,
            CirTerminator::Unresolved {
                target_operand: None,
                ..
            }
        ));
    }
}
