//! Normalize supported StateIR definitions without losing other effects.

use hydir_ir::expression::{
    BinaryOperator, EXPRESSION_FUNCTION_IR_VERSION, Expression, ExpressionAssignment,
    ExpressionBlock, ExpressionFunctionIr, ExpressionInstruction, ResidualEffect,
    validate_expression_function_ir,
};
use hydir_ir::{
    IrDiagnostic, MachineControlEffect, MachineFunctionIr, MachineInstruction, MachineMemoryEffect,
    MachineOperand, MachineOperation, SemanticFidelity, StateComponentVersion, StateFunctionIr,
    StateOperation, VerificationStatus, validate_machine_function_ir, validate_state_function_ir,
};
use iced_x86::{Decoder, DecoderOptions, OpKind, Register};

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

fn register_bit_offset(instruction: &MachineInstruction, operand_index: u32) -> Option<u16> {
    let bytes = instruction
        .bytes_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digits = std::str::from_utf8(pair).ok()?;
            u8::from_str_radix(digits, 16).ok()
        })
        .collect::<Option<Vec<_>>>()?;
    let mut decoder = Decoder::with_ip(
        64,
        &bytes,
        instruction.address.value.0,
        DecoderOptions::NONE,
    );
    let decoded = decoder.decode();
    if decoded.is_invalid()
        || decoded.next_ip().checked_sub(instruction.address.value.0)? != bytes.len() as u64
        || operand_index >= decoded.op_count()
        || decoded.op_kind(operand_index) != OpKind::Register
    {
        return None;
    }
    Some(match decoded.op_register(operand_index) {
        Register::AH | Register::BH | Register::CH | Register::DH => 8,
        _ => 0,
    })
}

fn register_value(
    operand: &MachineOperand,
    operand_index: u32,
    instruction: &MachineInstruction,
    inputs: &[StateComponentVersion],
) -> Option<Expression> {
    match operand {
        MachineOperand::Register { name, width_bits }
            if matches!(*width_bits, 8 | 16 | 32 | 64) =>
        {
            let read = Expression::Read {
                source: component_version(inputs, "register", name)?,
                width_bits: 64,
            };
            if *width_bits == 64 {
                Some(read)
            } else {
                Some(Expression::Extract {
                    value: Box::new(read),
                    lsb_bits: if *width_bits == 8 {
                        register_bit_offset(instruction, operand_index)?
                    } else {
                        0
                    },
                    width_bits: *width_bits,
                })
            }
        }
        MachineOperand::Immediate { value, width_bits }
            if matches!(*width_bits, 8 | 16 | 32 | 64) =>
        {
            Some(Expression::Constant {
                value: if *width_bits == 64 {
                    *value
                } else {
                    *value & ((1u64 << *width_bits) - 1)
                },
                width_bits: *width_bits,
            })
        }
        _ => None,
    }
}

fn normalized_register_assignment(
    instruction: &MachineInstruction,
    family: &str,
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
) -> Option<ExpressionAssignment> {
    if instruction.effects.memory != MachineMemoryEffect::None
        || instruction.effects.control != MachineControlEffect::Next
        || instruction.effects.conservative
        || instruction.decorators != Default::default()
    {
        return None;
    }
    let [MachineOperand::Register { name, width_bits }, source] = instruction.operands.as_slice()
    else {
        return None;
    };
    if !matches!(*width_bits, 8 | 16 | 32 | 64) {
        return None;
    }
    let target = component_version(outputs, "register", name)?;
    let right = register_value(source, 1, instruction, inputs)?;
    if right.width_bits() != *width_bits {
        return None;
    }
    let narrow_value = match family {
        "mov" => right,
        "add" | "sub" | "and" | "or" | "xor" => {
            let left = register_value(&instruction.operands[0], 0, instruction, inputs)?;
            let operator = match family {
                "add" => BinaryOperator::Add,
                "sub" => BinaryOperator::Subtract,
                "and" => BinaryOperator::And,
                "or" => BinaryOperator::Or,
                _ => BinaryOperator::Xor,
            };
            Expression::Binary {
                operator,
                width_bits: *width_bits,
                left: Box::new(left),
                right: Box::new(right),
            }
        }
        _ => return None,
    };
    let value = match *width_bits {
        64 => narrow_value,
        32 => Expression::ZeroExtend {
            value: Box::new(narrow_value),
            width_bits: 64,
        },
        8 | 16 => Expression::InsertBits {
            original: Box::new(Expression::Read {
                source: component_version(inputs, "register", name)?,
                width_bits: 64,
            }),
            value: Box::new(narrow_value),
            lsb_bits: if *width_bits == 8 {
                register_bit_offset(instruction, 0)?
            } else {
                0
            },
            width_bits: 64,
        },
        _ => return None,
    };
    Some(ExpressionAssignment { target, value })
}

/// This ExpressionIR lowering slice normalizes width-aware scalar GPR
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
                    normalized_register_assignment(machine_instruction, family, inputs, outputs)
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
