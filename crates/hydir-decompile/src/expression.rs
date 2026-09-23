//! Normalize supported StateIR definitions without losing other effects.

use hydir_ir::expression::{
    AddressExpression, BinaryOperator, ComparisonOperator, EXPRESSION_FUNCTION_IR_VERSION,
    Expression, ExpressionAssignment, ExpressionBlock, ExpressionFunctionIr, ExpressionInstruction,
    MemoryByteOrder, MemoryWrite, ResidualEffect, validate_expression_function_ir,
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

fn decoded_instruction(instruction: &MachineInstruction) -> Option<iced_x86::Instruction> {
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
    {
        return None;
    }
    Some(decoded)
}

fn register_bit_offset(instruction: &MachineInstruction, operand_index: u32) -> Option<u16> {
    let decoded = decoded_instruction(instruction)?;
    if operand_index >= decoded.op_count() || decoded.op_kind(operand_index) != OpKind::Register {
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

fn memory_versions(versions: &[StateComponentVersion]) -> Vec<StateComponentVersion> {
    versions
        .iter()
        .filter(|version| version.component.starts_with("memory:"))
        .cloned()
        .collect()
}

fn address_expression(
    operand: &MachineOperand,
    instruction: &MachineInstruction,
    inputs: &[StateComponentVersion],
) -> Option<AddressExpression> {
    let MachineOperand::Memory {
        segment,
        base,
        index,
        scale,
        displacement,
        absolute,
        ..
    } = operand
    else {
        return None;
    };
    if segment.is_some() || (absolute.is_some() && instruction.address.address_space != 0) {
        return None;
    }
    let decoded = decoded_instruction(instruction)?;
    for register in [decoded.memory_base(), decoded.memory_index()] {
        if register != Register::None && register != Register::RIP && register.size() != 8 {
            return None;
        }
    }
    if base.is_none() && index.is_none() && absolute.is_none() {
        return None;
    }
    let register = |name: &str| {
        Some(Box::new(Expression::Read {
            source: component_version(inputs, "register", name)?,
            width_bits: 64,
        }))
    };
    Some(AddressExpression {
        base: match base.as_deref() {
            Some(name) => Some(register(name)?),
            None => None,
        },
        index: match index.as_deref() {
            Some(name) => Some(register(name)?),
            None => None,
        },
        scale: *scale,
        displacement: *displacement,
        absolute: *absolute,
    })
}

fn register_write_assignment(
    instruction: &MachineInstruction,
    name: &str,
    width_bits: u16,
    narrow_value: Expression,
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
) -> Option<ExpressionAssignment> {
    if narrow_value.width_bits() != width_bits {
        return None;
    }
    let target = component_version(outputs, "register", name)?;
    let value = match width_bits {
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
            lsb_bits: if width_bits == 8 {
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
    register_write_assignment(
        instruction,
        name,
        *width_bits,
        narrow_value,
        inputs,
        outputs,
    )
}

fn normalized_memory_load(
    instruction: &MachineInstruction,
    family: &str,
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
) -> Option<ExpressionAssignment> {
    if family != "mov"
        || instruction.effects.memory != MachineMemoryEffect::Read
        || instruction.effects.control != MachineControlEffect::Next
        || instruction.effects.conservative
        || instruction.decorators != Default::default()
    {
        return None;
    }
    let [
        MachineOperand::Register { name, width_bits },
        memory @ MachineOperand::Memory { .. },
    ] = instruction.operands.as_slice()
    else {
        return None;
    };
    if !matches!(*width_bits, 8 | 16 | 32 | 64)
        || !matches!(memory, MachineOperand::Memory { width_bits: memory_width, .. } if memory_width == width_bits)
    {
        return None;
    }
    let memory_inputs = memory_versions(inputs);
    if memory_inputs.is_empty() {
        return None;
    }
    let narrow_value = Expression::MemoryRead {
        address: address_expression(memory, instruction, inputs)?,
        width_bits: *width_bits,
        byte_order: MemoryByteOrder::Little,
        memory_inputs,
    };
    register_write_assignment(
        instruction,
        name,
        *width_bits,
        narrow_value,
        inputs,
        outputs,
    )
}

fn normalized_memory_store(
    instruction: &MachineInstruction,
    family: &str,
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
) -> Option<MemoryWrite> {
    if family != "mov"
        || instruction.effects.memory != MachineMemoryEffect::Write
        || instruction.effects.control != MachineControlEffect::Next
        || instruction.effects.conservative
        || instruction.decorators != Default::default()
    {
        return None;
    }
    let [memory @ MachineOperand::Memory { width_bits, .. }, source] =
        instruction.operands.as_slice()
    else {
        return None;
    };
    if !matches!(*width_bits, 8 | 16 | 32 | 64) {
        return None;
    }
    let value = register_value(source, 1, instruction, inputs)?;
    if value.width_bits() != *width_bits {
        return None;
    }
    let memory_inputs = memory_versions(inputs);
    let memory_outputs = memory_versions(outputs);
    if memory_inputs.is_empty()
        || memory_inputs
            .iter()
            .map(|version| version.component.as_str())
            .collect::<Vec<_>>()
            != memory_outputs
                .iter()
                .map(|version| version.component.as_str())
                .collect::<Vec<_>>()
    {
        return None;
    }
    Some(MemoryWrite {
        address: address_expression(memory, instruction, inputs)?,
        value,
        width_bits: *width_bits,
        byte_order: MemoryByteOrder::Little,
        memory_inputs,
        memory_outputs,
    })
}

fn normalized_lea_assignment(
    instruction: &MachineInstruction,
    family: &str,
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
) -> Option<ExpressionAssignment> {
    if family != "lea"
        || instruction.effects.memory != MachineMemoryEffect::None
        || instruction.effects.control != MachineControlEffect::Next
        || instruction.effects.conservative
        || instruction.decorators != Default::default()
    {
        return None;
    }
    let [
        MachineOperand::Register { name, width_bits },
        memory @ MachineOperand::Memory { .. },
    ] = instruction.operands.as_slice()
    else {
        return None;
    };
    if !matches!(*width_bits, 32 | 64) {
        return None;
    }
    let address = Expression::EffectiveAddress {
        address: address_expression(memory, instruction, inputs)?,
    };
    let narrow_value = if *width_bits == 32 {
        Expression::Extract {
            value: Box::new(address),
            lsb_bits: 0,
            width_bits: 32,
        }
    } else {
        address
    };
    register_write_assignment(
        instruction,
        name,
        *width_bits,
        narrow_value,
        inputs,
        outputs,
    )
}

fn binary(operator: BinaryOperator, left: Expression, right: Expression) -> Expression {
    Expression::Binary {
        operator,
        width_bits: left.width_bits(),
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn compare(operator: ComparisonOperator, left: Expression, right: Expression) -> Expression {
    Expression::Compare {
        operator,
        left: Box::new(left),
        right: Box::new(right),
    }
}

fn bit_not(value: Expression) -> Expression {
    binary(
        BinaryOperator::Xor,
        value,
        Expression::Constant {
            value: 1,
            width_bits: 1,
        },
    )
}

fn flag_read(inputs: &[StateComponentVersion], name: &str) -> Option<Expression> {
    Some(Expression::Read {
        source: component_version(inputs, "flag", name)?,
        width_bits: 1,
    })
}

fn normalized_scalar_flags(
    instruction: &MachineInstruction,
    family: &str,
    inputs: &[StateComponentVersion],
    outputs: &[StateComponentVersion],
) -> Option<Vec<ExpressionAssignment>> {
    if !matches!(
        family,
        "cmp" | "test" | "add" | "sub" | "and" | "or" | "xor"
    ) || instruction.effects.memory != MachineMemoryEffect::None
        || instruction.effects.control != MachineControlEffect::Next
        || instruction.effects.conservative
        || instruction.decorators != Default::default()
    {
        return None;
    }
    let [left_operand, right_operand] = instruction.operands.as_slice() else {
        return None;
    };
    let left = register_value(left_operand, 0, instruction, inputs)?;
    let right = register_value(right_operand, 1, instruction, inputs)?;
    if left.width_bits() != right.width_bits() {
        return None;
    }
    let width_bits = left.width_bits();
    let result = match family {
        "cmp" | "sub" => binary(BinaryOperator::Subtract, left.clone(), right.clone()),
        "add" => binary(BinaryOperator::Add, left.clone(), right.clone()),
        "test" | "and" => binary(BinaryOperator::And, left.clone(), right.clone()),
        "or" => binary(BinaryOperator::Or, left.clone(), right.clone()),
        "xor" => binary(BinaryOperator::Xor, left.clone(), right.clone()),
        _ => return None,
    };
    let zf = if family == "cmp" {
        compare(ComparisonOperator::Equal, left.clone(), right.clone())
    } else {
        compare(
            ComparisonOperator::Equal,
            result.clone(),
            Expression::Constant {
                value: 0,
                width_bits,
            },
        )
    };
    let sf = Expression::Extract {
        value: Box::new(result.clone()),
        lsb_bits: width_bits - 1,
        width_bits: 1,
    };
    let (cf, of) = match family {
        "cmp" | "sub" => {
            let overflow = binary(
                BinaryOperator::And,
                binary(BinaryOperator::Xor, left.clone(), right.clone()),
                binary(BinaryOperator::Xor, left.clone(), result.clone()),
            );
            (
                compare(
                    ComparisonOperator::UnsignedLess,
                    left.clone(),
                    right.clone(),
                ),
                Expression::Extract {
                    value: Box::new(overflow),
                    lsb_bits: width_bits - 1,
                    width_bits: 1,
                },
            )
        }
        "add" => {
            let mask = if width_bits == 64 {
                u64::MAX
            } else {
                (1u64 << width_bits) - 1
            };
            let same_sign = binary(
                BinaryOperator::Xor,
                binary(BinaryOperator::Xor, left.clone(), right.clone()),
                Expression::Constant {
                    value: mask,
                    width_bits,
                },
            );
            let overflow = binary(
                BinaryOperator::And,
                same_sign,
                binary(BinaryOperator::Xor, left.clone(), result.clone()),
            );
            (
                compare(
                    ComparisonOperator::UnsignedLess,
                    result.clone(),
                    left.clone(),
                ),
                Expression::Extract {
                    value: Box::new(overflow),
                    lsb_bits: width_bits - 1,
                    width_bits: 1,
                },
            )
        }
        _ => (
            Expression::Constant {
                value: 0,
                width_bits: 1,
            },
            Expression::Constant {
                value: 0,
                width_bits: 1,
            },
        ),
    };
    let mut flags = [("zf", zf), ("cf", cf), ("sf", sf), ("of", of)]
        .into_iter()
        .map(|(name, value)| {
            Some(ExpressionAssignment {
                target: component_version(outputs, "flag", name)?,
                value,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    flags.push(ExpressionAssignment {
        target: component_version(outputs, "flag", "pf")?,
        value: Expression::ParityEven {
            value: Box::new(result.clone()),
        },
    });
    if matches!(family, "cmp" | "add" | "sub") {
        flags.push(ExpressionAssignment {
            target: component_version(outputs, "flag", "af")?,
            value: Expression::Extract {
                value: Box::new(binary(
                    BinaryOperator::Xor,
                    binary(BinaryOperator::Xor, left, right),
                    result,
                )),
                lsb_bits: 4,
                width_bits: 1,
            },
        });
    }
    Some(flags)
}

fn normalized_branch_condition(
    instruction: &MachineInstruction,
    family: &str,
    inputs: &[StateComponentVersion],
) -> Option<Expression> {
    if instruction.effects.control != MachineControlEffect::ConditionalBranch
        || instruction.effects.conservative
        || instruction.decorators != Default::default()
    {
        return None;
    }
    let flag = |name| flag_read(inputs, name);
    let same_sign = || Some(compare(ComparisonOperator::Equal, flag("sf")?, flag("of")?));
    match family {
        "je" | "jz" => flag("zf"),
        "jne" | "jnz" => Some(bit_not(flag("zf")?)),
        "js" => flag("sf"),
        "jns" => Some(bit_not(flag("sf")?)),
        "jo" => flag("of"),
        "jno" => Some(bit_not(flag("of")?)),
        "jb" | "jc" | "jnae" => flag("cf"),
        "jae" | "jnb" | "jnc" => Some(bit_not(flag("cf")?)),
        "jbe" | "jna" => Some(binary(BinaryOperator::Or, flag("cf")?, flag("zf")?)),
        "ja" | "jnbe" => Some(binary(
            BinaryOperator::And,
            bit_not(flag("cf")?),
            bit_not(flag("zf")?),
        )),
        "jl" | "jnge" => Some(bit_not(same_sign()?)),
        "jge" | "jnl" => same_sign(),
        "jle" | "jng" => Some(binary(
            BinaryOperator::Or,
            flag("zf")?,
            bit_not(same_sign()?),
        )),
        "jg" | "jnle" => Some(binary(
            BinaryOperator::And,
            bit_not(flag("zf")?),
            same_sign()?,
        )),
        _ => None,
    }
}

/// This ExpressionIR lowering slice normalizes supported scalar GPR writes,
/// selected status flags, and taken-edge predicates. Every unsupported effect
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
                        .or_else(|| {
                            normalized_memory_load(machine_instruction, family, inputs, outputs)
                        })
                        .or_else(|| {
                            normalized_lea_assignment(machine_instruction, family, inputs, outputs)
                        })
                })
                .flatten();
            let mut assignments = assignment.into_iter().collect::<Vec<_>>();
            let memory_writes = unknown_reason
                .is_none()
                .then(|| normalized_memory_store(machine_instruction, family, inputs, outputs))
                .flatten()
                .into_iter()
                .collect::<Vec<_>>();
            if unknown_reason.is_none() {
                if let Some(flags) =
                    normalized_scalar_flags(machine_instruction, family, inputs, outputs)
                {
                    assignments.extend(flags);
                }
            }
            let condition = unknown_reason
                .is_none()
                .then(|| normalized_branch_condition(machine_instruction, family, inputs))
                .flatten();
            let remaining = outputs
                .iter()
                .filter(|output| {
                    !assignments
                        .iter()
                        .any(|assignment| assignment.target == **output)
                        && !memory_writes
                            .iter()
                            .flat_map(|write| &write.memory_outputs)
                            .any(|written| written == *output)
                })
                .cloned()
                .collect::<Vec<_>>();
            let residual =
                if (assignments.is_empty() && memory_writes.is_empty()) || !remaining.is_empty() {
                    residual_count += 1;
                    first_residual.get_or_insert(address);
                    Some(ResidualEffect {
                        family: family.to_owned(),
                        reason: unknown_reason
                            .unwrap_or(if condition.is_some() {
                                "branch control effect remains explicit"
                            } else if assignments.is_empty() {
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
                memory_writes,
                condition,
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
