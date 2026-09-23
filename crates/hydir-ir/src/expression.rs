//! Width-aware, provenance-preserving expressions over StateIR components.
//!
//! A residual describes every effect that this graph has not normalized yet.
//! Consumers must keep residuals when simplifying or rendering the graph.

use crate::{
    InstructionDecorators, IrDiagnostic, MachineControlEffect, MachineEdge, MachineEdgeKind,
    MachineMemoryEffect, MachineOperand, SemanticFidelity, StateComponentPhi,
    StateComponentVersion, StructuralCompleteness, VerificationStatus, validate_diagnostics,
    validate_edges, validate_instruction_decorators, validate_location, validate_machine_operand,
};
use hydir_core::Location;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const EXPRESSION_FUNCTION_IR_VERSION: u32 = 1;
const MAX_EXPRESSION_BLOCKS: usize = 4096;
const MAX_EXPRESSION_INSTRUCTIONS: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryOperator {
    Add,
    Subtract,
    And,
    Or,
    Xor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonOperator {
    Equal,
    UnsignedLess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryByteOrder {
    Little,
}

/// A 64-bit x86 effective address. Segment-relative addressing remains a
/// residual until its segment base is represented as a state component.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AddressExpression {
    pub base: Option<Box<Expression>>,
    pub index: Option<Box<Expression>>,
    pub scale: u32,
    pub displacement: i64,
    pub absolute: Option<u64>,
}

/// An exact byte-range write with every possibly affected abstract memory
/// region. Consumers must preserve the whole input/output region set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryWrite {
    pub address: AddressExpression,
    pub value: Expression,
    pub width_bits: u16,
    pub byte_order: MemoryByteOrder,
    pub memory_inputs: Vec<StateComponentVersion>,
    pub memory_outputs: Vec<StateComponentVersion>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expression {
    Read {
        source: StateComponentVersion,
        width_bits: u16,
    },
    Constant {
        value: u64,
        width_bits: u16,
    },
    Extract {
        value: Box<Expression>,
        lsb_bits: u16,
        width_bits: u16,
    },
    ZeroExtend {
        value: Box<Expression>,
        width_bits: u16,
    },
    InsertBits {
        original: Box<Expression>,
        value: Box<Expression>,
        lsb_bits: u16,
        width_bits: u16,
    },
    Binary {
        operator: BinaryOperator,
        width_bits: u16,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    Compare {
        operator: ComparisonOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Even parity of the low eight bits, as defined by x86 PF.
    ParityEven {
        value: Box<Expression>,
    },
    MemoryRead {
        address: AddressExpression,
        width_bits: u16,
        byte_order: MemoryByteOrder,
        memory_inputs: Vec<StateComponentVersion>,
    },
    EffectiveAddress {
        address: AddressExpression,
    },
}

impl Expression {
    pub fn width_bits(&self) -> u16 {
        match self {
            Self::Read { width_bits, .. }
            | Self::Constant { width_bits, .. }
            | Self::Extract { width_bits, .. }
            | Self::ZeroExtend { width_bits, .. }
            | Self::InsertBits { width_bits, .. }
            | Self::Binary { width_bits, .. }
            | Self::MemoryRead { width_bits, .. } => *width_bits,
            Self::Compare { .. } | Self::ParityEven { .. } => 1,
            Self::EffectiveAddress { .. } => 64,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpressionAssignment {
    pub target: StateComponentVersion,
    pub value: Expression,
}

/// The inputs and outputs retain the StateIR versions of effects that still
/// need lowering. `outputs` must exactly cover the outputs not assigned above.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResidualEffect {
    pub family: String,
    pub reason: String,
    pub operands: Vec<MachineOperand>,
    pub decorators: InstructionDecorators,
    pub inputs: Vec<StateComponentVersion>,
    pub outputs: Vec<StateComponentVersion>,
    pub undefined_outputs: Vec<String>,
    pub memory: MachineMemoryEffect,
    pub control: MachineControlEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpressionInstruction {
    pub address: Location,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub input_components: Vec<StateComponentVersion>,
    pub output_components: Vec<StateComponentVersion>,
    pub assignments: Vec<ExpressionAssignment>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory_writes: Vec<MemoryWrite>,
    /// Taken-edge predicate for a supported conditional branch. The control
    /// output remains in the residual until control lowering is implemented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Expression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub residual: Option<ResidualEffect>,
    pub edges: Vec<MachineEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpressionBlock {
    pub address: Location,
    pub component_phis: Vec<StateComponentPhi>,
    pub instructions: Vec<ExpressionInstruction>,
    pub edges: Vec<MachineEdge>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpressionFunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_id: String,
    pub entry: Location,
    pub blocks: Vec<ExpressionBlock>,
    pub structural_completeness: StructuralCompleteness,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    pub diagnostics: Vec<IrDiagnostic>,
}

fn validate_memory_versions(
    versions: &[StateComponentVersion],
    available: &BTreeSet<StateComponentVersion>,
) -> Result<(), String> {
    if versions.is_empty()
        || versions.len() > 16
        || versions.iter().cloned().collect::<BTreeSet<_>>().len() != versions.len()
        || versions.iter().any(|version| {
            !version.component.starts_with("memory:") || !available.contains(version)
        })
    {
        return Err("ExpressionIR memory versions are missing or invalid".to_owned());
    }
    Ok(())
}

fn validate_address(
    address: &AddressExpression,
    inputs: &BTreeSet<StateComponentVersion>,
    depth: usize,
) -> Result<(), String> {
    if !matches!(address.scale, 1 | 2 | 4 | 8)
        || (address.index.is_none() && address.scale != 1)
        || (address.absolute.is_some()
            && (address.base.is_some() || address.index.is_some() || address.displacement != 0))
    {
        return Err("ExpressionIR effective address is invalid".to_owned());
    }
    for part in [&address.base, &address.index].into_iter().flatten() {
        validate_expression(part, inputs, depth + 1)?;
        if part.width_bits() != 64 {
            return Err("ExpressionIR effective address register is not 64-bit".to_owned());
        }
    }
    Ok(())
}

fn validate_expression(
    expression: &Expression,
    inputs: &BTreeSet<StateComponentVersion>,
    depth: usize,
) -> Result<(), String> {
    if depth > 64 || expression.width_bits() == 0 || expression.width_bits() > 512 {
        return Err("ExpressionIR expression depth or width is invalid".to_owned());
    }
    match expression {
        Expression::Constant { value, width_bits }
            if *width_bits > 64 || (*width_bits < 64 && *value >> *width_bits != 0) =>
        {
            Err("ExpressionIR constant cannot be represented at its width".to_owned())
        }
        Expression::Read { source, .. } if source.component.is_empty() => {
            Err("ExpressionIR reads an unnamed state component".to_owned())
        }
        Expression::Read { source, .. } if !inputs.contains(source) => {
            Err("ExpressionIR reads a state version absent from its instruction".to_owned())
        }
        Expression::Extract {
            value,
            lsb_bits,
            width_bits,
        } => {
            validate_expression(value, inputs, depth + 1)?;
            if u32::from(*lsb_bits) + u32::from(*width_bits) > u32::from(value.width_bits()) {
                return Err("ExpressionIR extract exceeds its source width".to_owned());
            }
            Ok(())
        }
        Expression::ZeroExtend { value, width_bits } => {
            validate_expression(value, inputs, depth + 1)?;
            if value.width_bits() >= *width_bits {
                return Err("ExpressionIR zero extension does not widen its source".to_owned());
            }
            Ok(())
        }
        Expression::InsertBits {
            original,
            value,
            lsb_bits,
            width_bits,
        } => {
            validate_expression(original, inputs, depth + 1)?;
            validate_expression(value, inputs, depth + 1)?;
            if original.width_bits() != *width_bits
                || u32::from(*lsb_bits) + u32::from(value.width_bits()) > u32::from(*width_bits)
            {
                return Err("ExpressionIR bit insertion exceeds its destination".to_owned());
            }
            Ok(())
        }
        Expression::Binary {
            width_bits,
            left,
            right,
            ..
        } => {
            validate_expression(left, inputs, depth + 1)?;
            validate_expression(right, inputs, depth + 1)?;
            if left.width_bits() != *width_bits || right.width_bits() != *width_bits {
                return Err("ExpressionIR binary operands have inconsistent widths".to_owned());
            }
            Ok(())
        }
        Expression::Compare { left, right, .. } => {
            validate_expression(left, inputs, depth + 1)?;
            validate_expression(right, inputs, depth + 1)?;
            if left.width_bits() != right.width_bits() {
                return Err("ExpressionIR comparison operands have inconsistent widths".to_owned());
            }
            Ok(())
        }
        Expression::ParityEven { value } => {
            validate_expression(value, inputs, depth + 1)?;
            if value.width_bits() < 8 {
                return Err("ExpressionIR parity input is narrower than one byte".to_owned());
            }
            Ok(())
        }
        Expression::MemoryRead {
            address,
            width_bits,
            memory_inputs,
            ..
        } => {
            if !matches!(*width_bits, 8 | 16 | 32 | 64) {
                return Err("ExpressionIR memory read width is unsupported".to_owned());
            }
            validate_address(address, inputs, depth + 1)?;
            validate_memory_versions(memory_inputs, inputs)?;
            if memory_inputs.iter().cloned().collect::<BTreeSet<_>>()
                != inputs
                    .iter()
                    .filter(|version| version.component.starts_with("memory:"))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            {
                return Err("ExpressionIR memory read omits an alias region".to_owned());
            }
            Ok(())
        }
        Expression::EffectiveAddress { address } => validate_address(address, inputs, depth + 1),
        _ => Ok(()),
    }
}

pub fn validate_expression_function_ir(ir: &ExpressionFunctionIr) -> Result<(), String> {
    if ir.schema_version != EXPRESSION_FUNCTION_IR_VERSION
        || ir.binary_sha256.len() != 64
        || !ir
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || ir.function_id.is_empty()
        || ir.function_id.len() > 256
        || ir.blocks.is_empty()
        || ir.blocks.len() > MAX_EXPRESSION_BLOCKS
        || ir.diagnostics.len() > 65_536
    {
        return Err("ExpressionIR identity, version, or block count is invalid".to_owned());
    }
    validate_location(ir.entry)?;
    validate_diagnostics(&ir.diagnostics)?;
    let mut block_addresses = BTreeSet::new();
    let mut instruction_addresses = BTreeSet::new();
    let mut instruction_count = 0usize;
    let mut has_residual = false;
    for block in &ir.blocks {
        validate_location(block.address)?;
        validate_edges(&block.edges)?;
        if block.address.address_space != ir.entry.address_space
            || !block_addresses.insert(block.address)
            || block.instructions.is_empty()
            || block.instructions[0].address != block.address
            || block.component_phis.len() > 4096
        {
            return Err("ExpressionIR contains an invalid block".to_owned());
        }
        let mut phi_outputs = BTreeSet::new();
        for phi in &block.component_phis {
            if phi.component.is_empty()
                || !phi_outputs.insert(phi.component.clone())
                || phi.incoming.len() > 4096
                || phi
                    .incoming
                    .iter()
                    .any(|incoming| incoming.predecessor.address_space != ir.entry.address_space)
                || phi
                    .incoming
                    .iter()
                    .map(|incoming| incoming.predecessor)
                    .collect::<BTreeSet<_>>()
                    .len()
                    != phi.incoming.len()
            {
                return Err("ExpressionIR contains an invalid component phi".to_owned());
            }
        }
        for instruction in &block.instructions {
            instruction_count += 1;
            validate_location(instruction.address)?;
            validate_edges(&instruction.edges)?;
            if instruction_count > MAX_EXPRESSION_INSTRUCTIONS
                || instruction.address.address_space != ir.entry.address_space
                || !instruction_addresses.insert(instruction.address)
                || instruction.bytes_hex.is_empty()
                || instruction.bytes_hex.len() > 30
                || instruction.bytes_hex.len() % 2 != 0
                || !instruction
                    .bytes_hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
                || instruction.mnemonic.is_empty()
            {
                return Err("ExpressionIR contains an invalid instruction".to_owned());
            }
            let inputs = instruction
                .input_components
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            let outputs = instruction
                .output_components
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if inputs.len() != instruction.input_components.len()
                || outputs.len() != instruction.output_components.len()
            {
                return Err("ExpressionIR has duplicate state component versions".to_owned());
            }
            let mut assigned = BTreeSet::new();
            for assignment in &instruction.assignments {
                if !outputs.contains(&assignment.target)
                    || !assigned.insert(assignment.target.clone())
                {
                    return Err("ExpressionIR assignment does not define one output".to_owned());
                }
                validate_expression(&assignment.value, &inputs, 0)?;
            }
            if instruction.memory_writes.len() > 16 {
                return Err("ExpressionIR has too many memory writes in one instruction".to_owned());
            }
            for write in &instruction.memory_writes {
                if !matches!(write.width_bits, 8 | 16 | 32 | 64)
                    || write.value.width_bits() != write.width_bits
                {
                    return Err("ExpressionIR memory write width is invalid".to_owned());
                }
                validate_address(&write.address, &inputs, 0)?;
                validate_expression(&write.value, &inputs, 0)?;
                validate_memory_versions(&write.memory_inputs, &inputs)?;
                validate_memory_versions(&write.memory_outputs, &outputs)?;
                if write.memory_inputs.iter().cloned().collect::<BTreeSet<_>>()
                    != inputs
                        .iter()
                        .filter(|version| version.component.starts_with("memory:"))
                        .cloned()
                        .collect::<BTreeSet<_>>()
                    || write
                        .memory_outputs
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        != outputs
                            .iter()
                            .filter(|version| version.component.starts_with("memory:"))
                            .cloned()
                            .collect::<BTreeSet<_>>()
                    || write
                        .memory_inputs
                        .iter()
                        .map(|version| &version.component)
                        .collect::<BTreeSet<_>>()
                        != write
                            .memory_outputs
                            .iter()
                            .map(|version| &version.component)
                            .collect::<BTreeSet<_>>()
                    || write
                        .memory_outputs
                        .iter()
                        .any(|version| !assigned.insert(version.clone()))
                {
                    return Err("ExpressionIR memory write loses an alias region".to_owned());
                }
            }
            if let Some(condition) = &instruction.condition {
                validate_expression(condition, &inputs, 0)?;
                if condition.width_bits() != 1
                    || !instruction.residual.as_ref().is_some_and(|residual| {
                        residual.control == MachineControlEffect::ConditionalBranch
                    })
                    || !instruction
                        .edges
                        .iter()
                        .any(|edge| edge.kind == MachineEdgeKind::Taken)
                {
                    return Err(
                        "ExpressionIR branch predicate lacks a conditional control effect"
                            .to_owned(),
                    );
                }
            }
            let remaining = outputs
                .difference(&assigned)
                .cloned()
                .collect::<BTreeSet<_>>();
            match &instruction.residual {
                Some(residual) => {
                    has_residual = true;
                    validate_instruction_decorators(&residual.decorators)?;
                    for operand in &residual.operands {
                        validate_machine_operand(operand, true)?;
                    }
                    if residual.family.is_empty()
                        || residual.family.len() > 128
                        || residual.reason.is_empty()
                        || residual.reason.len() > 4096
                        || residual.inputs != instruction.input_components
                        || residual.outputs.iter().cloned().collect::<BTreeSet<_>>() != remaining
                        || residual.outputs.len() != remaining.len()
                        || residual
                            .undefined_outputs
                            .iter()
                            .any(|name| !remaining.iter().any(|output| &output.component == name))
                    {
                        return Err(
                            "ExpressionIR residual does not account for remaining effects"
                                .to_owned(),
                        );
                    }
                }
                None if !remaining.is_empty() => {
                    return Err("ExpressionIR silently drops a state output".to_owned());
                }
                None => {}
            }
        }
        if block.edges != block.instructions.last().unwrap().edges {
            return Err("ExpressionIR block edges differ from its terminator".to_owned());
        }
    }
    if !block_addresses.contains(&ir.entry)
        || (has_residual && ir.semantic_fidelity == SemanticFidelity::ExactUnderModel)
    {
        return Err("ExpressionIR entry or semantic fidelity is invalid".to_owned());
    }
    Ok(())
}
