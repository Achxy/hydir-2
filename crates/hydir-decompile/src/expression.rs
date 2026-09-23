//! Normalize supported StateIR definitions without losing other effects.

use hydir_ir::expression::{
    BinaryOperator, EXPRESSION_FUNCTION_IR_VERSION, Expression, ExpressionAssignment,
    ExpressionBlock, ExpressionFunctionIr, ExpressionInstruction, ResidualEffect,
    validate_expression_function_ir,
};
use hydir_ir::{
    IrDiagnostic, MachineControlEffect, MachineFunctionIr, MachineMemoryEffect, MachineOperand,
    MachineOperation, SemanticFidelity, StateComponentVersion, StateFunctionIr, StateOperation,
    VerificationStatus, validate_machine_function_ir, validate_state_function_ir,
};

fn component_version(
    versions: &[StateComponentVersion],
    prefix: &str,
    name: &str,
) -> Option<StateComponentVersion> {
    let component = format!("{prefix}:{name}");
    versions
        .iter()
        .find(|version| version.component == component)
        .cloned()
}

fn register_value(
    operand: &MachineOperand,
    inputs: &[StateComponentVersion],
) -> Option<Expression> {
    match operand {
        MachineOperand::Register {
            name,
            width_bits: 64,
        } => Some(Expression::Read {
            source: component_version(inputs, "register", name)?,
            width_bits: 64,
        }),
        MachineOperand::Immediate {
            value,
            width_bits: 64,
        } => Some(Expression::Constant {
            value: *value,
            width_bits: 64,
        }),
        _ => None,
    }
}

fn normalized_register_assignment(
    family: &str,
    operands: &[MachineOperand],
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
    memory: MachineMemoryEffect,
    control: MachineControlEffect,
    conservative: bool,
    has_decorators: bool,
) -> Option<ExpressionAssignment> {
    if memory != MachineMemoryEffect::None
        || control != MachineControlEffect::Next
        || conservative
        || has_decorators
    {
        return None;
    }
    let [
        MachineOperand::Register {
            name,
            width_bits: 64,
        },
        source,
    ] = operands
    else {
        return None;
    };
    let target = component_version(outputs, "register", name)?;
    let right = register_value(source, inputs)?;
    let value = match family {
        "mov" => right,
        "add" | "sub" | "and" | "or" | "xor" => {
            let left = Expression::Read {
                source: component_version(inputs, "register", name)?,
                width_bits: 64,
            };
            let operator = match family {
                "add" => BinaryOperator::Add,
                "sub" => BinaryOperator::Subtract,
                "and" => BinaryOperator::And,
                "or" => BinaryOperator::Or,
                _ => BinaryOperator::Xor,
            };
            Expression::Binary {
                operator,
                width_bits: 64,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
        _ => return None,
    };
    Some(ExpressionAssignment { target, value })
}

/// The first ExpressionIR lowering slice normalizes full-width scalar GPR
/// definitions. Every unsupported flag, memory, control, and register effect
/// remains an explicit residual with its original StateIR component versions.
pub fn lower_expression_ir(
    machine: &MachineFunctionIr,
    state: &StateFunctionIr,
) -> Result<ExpressionFunctionIr, String> {
    validate_machine_function_ir(machine)?;
    validate_state_function_ir(state)?;
    if machine.binary_sha256 != state.binary_sha256
        || machine.function_id != state.function_id
        || machine.entry != state.entry
        || machine.blocks.len() != state.blocks.len()
    {
        return Err("MachineIR and StateIR identity or blocks differ".to_owned());
    }
    let mut blocks = Vec::with_capacity(machine.blocks.len());
    let mut residual_count = 0usize;
    let mut first_residual = None;
    for (machine_block, state_block) in machine.blocks.iter().zip(&state.blocks) {
        if machine_block.address != state_block.address
            || machine_block.instructions.len() != state_block.operations.len()
        {
            return Err("MachineIR and StateIR instructions differ".to_owned());
        }
        let flow = state_block
            .state_flow
            .as_ref()
            .ok_or("ExpressionIR requires component SSA block flow")?;
        let mut instructions = Vec::with_capacity(machine_block.instructions.len());
        for (machine_instruction, state_operation) in machine_block
            .instructions
            .iter()
            .zip(&state_block.operations)
        {
            let (address, family, inputs, outputs, undefined_outputs, unknown_reason) =
                match state_operation {
                    StateOperation::Exact {
                        address,
                        family,
                        input_components,
                        output_components,
                        undefined_outputs,
                        ..
                    } => (
                        *address,
                        family.as_str(),
                        input_components,
                        output_components,
                        undefined_outputs.as_slice(),
                        None,
                    ),
                    StateOperation::Unknown {
                        address,
                        reason,
                        input_components,
                        output_components,
                        ..
                    } => (
                        *address,
                        "unknown",
                        input_components,
                        output_components,
                        &[][..],
                        Some(reason.as_str()),
                    ),
                };
            if address != machine_instruction.address {
                return Err("MachineIR and StateIR operation addresses differ".to_owned());
            }
            if let MachineOperation::Exact {
                family: machine_family,
            } = &machine_instruction.operation
            {
                if machine_family != family {
                    return Err("MachineIR and StateIR operation families differ".to_owned());
                }
            }
            let assignment = unknown_reason
                .is_none()
                .then(|| {
                    normalized_register_assignment(
                        family,
                        &machine_instruction.operands,
                        inputs,
                        outputs,
                        machine_instruction.effects.memory,
                        machine_instruction.effects.control,
                        machine_instruction.effects.conservative,
                        machine_instruction.decorators != Default::default(),
                    )
                })
                .flatten();
            let assignments = assignment.into_iter().collect::<Vec<_>>();
            let remaining = outputs
                .iter()
                .filter(|output| {
                    !assignments
                        .iter()
                        .any(|assignment| assignment.target == **output)
                })
                .cloned()
                .collect::<Vec<_>>();
            let residual = if assignments.is_empty() || !remaining.is_empty() {
                residual_count += 1;
                first_residual.get_or_insert(address);
                Some(ResidualEffect {
                    family: family.to_owned(),
                    reason: unknown_reason
                        .unwrap_or(if assignments.is_empty() {
                            "operation has no normalized expression semantics"
                        } else {
                            "remaining flag or state effects require normalization"
                        })
                        .to_owned(),
                    operands: machine_instruction.operands.clone(),
                    decorators: machine_instruction.decorators.clone(),
                    inputs: inputs.clone(),
                    outputs: remaining,
                    undefined_outputs: undefined_outputs.to_vec(),
                    memory: machine_instruction.effects.memory,
                    control: machine_instruction.effects.control,
                })
            } else {
                None
            };
            instructions.push(ExpressionInstruction {
                address,
                bytes_hex: machine_instruction.bytes_hex.clone(),
                mnemonic: machine_instruction.mnemonic.clone(),
                input_components: inputs.clone(),
                output_components: outputs.clone(),
                assignments,
                residual,
                edges: machine_instruction.edges.clone(),
            });
        }
        blocks.push(ExpressionBlock {
            address: machine_block.address,
            component_phis: flow.component_phis.clone(),
            edges: state_block.edges.clone(),
            instructions,
        });
    }
    let mut diagnostics = state.diagnostics.clone();
    if residual_count != 0 {
        diagnostics.push(IrDiagnostic {
            code: "expression_residual_effects".to_owned(),
            message: format!(
                "{residual_count} instruction(s) retain effects outside the normalized expression subset"
            ),
            address: first_residual,
            blocks_stable_operation: true,
        });
    }
    let ir = ExpressionFunctionIr {
        schema_version: EXPRESSION_FUNCTION_IR_VERSION,
        binary_sha256: state.binary_sha256.clone(),
        function_id: state.function_id.clone(),
        entry: state.entry,
        blocks,
        structural_completeness: state.structural_completeness,
        semantic_fidelity: if residual_count == 0 {
            state.semantic_fidelity
        } else if state.semantic_fidelity == SemanticFidelity::Unknown {
            SemanticFidelity::Unknown
        } else {
            SemanticFidelity::Conservative
        },
        verification: VerificationStatus::StaticallyValidated,
        diagnostics,
    };
    validate_expression_function_ir(&ir)?;
    Ok(ir)
}
