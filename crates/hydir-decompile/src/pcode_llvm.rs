//! A standalone LLVM lowering for one validated Ghidra raw P-code value op.
//!
//! This intentionally does not lower an instruction, state, memory, or CFG.
//! Non-constant source inputs become parameters named by their source index;
//! constant varnodes are embedded. The function can therefore be checked or
//! differentially executed without implying whole-function equivalence.

use hydir_ir::pcode::{PcodeEffect, PcodeExactOp, PcodeSemanticOperation};

/// Emit a verifier-clean LLVM function for one exact operation (up to 64 bits).
/// The function is named `hydir_pcode_exact` and has an integer return type
/// equal to the output varnode width. Every non-constant source input is a
/// width-typed parameter `%inN`, where N is its source-input index.
pub fn emit_pcode_exact_operation_llvm(
    operation: &PcodeSemanticOperation,
) -> Result<String, String> {
    let PcodeEffect::Assign {
        operation: kind,
        result_width_bits: result_bits,
    } = operation.effect
    else {
        return Err("opaque P-code effect cannot be emitted as exact LLVM".to_owned());
    };

    // The public evaluator rechecks that the effect still matches the source
    // opcode, mnemonic, operand spaces, arity, and widths. Supply matching
    // values for constant varnodes so this also rejects forged artifacts.
    let witness = operation
        .source
        .inputs
        .iter()
        .map(|input| {
            if input.space == "const" {
                parse_constant(&input.offset)
            } else {
                Ok(0)
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    if operation.evaluate_exact(&witness)?.is_none() {
        return Err("P-code operation is not exact".to_owned());
    }

    let mut parameters = Vec::new();
    let mut operands = Vec::new();
    for (index, input) in operation.source.inputs.iter().enumerate() {
        let bits = input.size * 8;
        if input.space == "const" {
            operands.push(format!("{}", witness[index] & width_mask(bits)));
        } else {
            let name = format!("%in{index}");
            parameters.push(format!("i{bits} {name}"));
            operands.push(name);
        }
    }
    let result_type = format!("i{result_bits}");
    let mut body = String::new();
    let value = match kind {
        PcodeExactOp::Copy => operands[0].clone(),
        PcodeExactOp::ZeroExtend | PcodeExactOp::SignExtend => {
            let input_bits = operation.source.inputs[0].size * 8;
            let instruction = if kind == PcodeExactOp::ZeroExtend {
                "zext"
            } else {
                "sext"
            };
            body.push_str(&format!(
                "  %result = {instruction} i{input_bits} {} to {result_type}\n",
                operands[0]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::Add
        | PcodeExactOp::Sub
        | PcodeExactOp::Xor
        | PcodeExactOp::And
        | PcodeExactOp::Or => {
            let instruction = match kind {
                PcodeExactOp::Add => "add",
                PcodeExactOp::Sub => "sub",
                PcodeExactOp::Xor => "xor",
                PcodeExactOp::And => "and",
                PcodeExactOp::Or => "or",
                _ => unreachable!(),
            };
            body.push_str(&format!(
                "  %result = {instruction} {result_type} {}, {}\n",
                operands[0], operands[1]
            ));
            "%result".to_owned()
        }
        PcodeExactOp::Equal
        | PcodeExactOp::NotEqual
        | PcodeExactOp::UnsignedLess
        | PcodeExactOp::UnsignedLessEqual
        | PcodeExactOp::SignedLess
        | PcodeExactOp::SignedLessEqual => {
            let predicate = match kind {
                PcodeExactOp::Equal => "eq",
                PcodeExactOp::NotEqual => "ne",
                PcodeExactOp::UnsignedLess => "ult",
                PcodeExactOp::UnsignedLessEqual => "ule",
                PcodeExactOp::SignedLess => "slt",
                PcodeExactOp::SignedLessEqual => "sle",
                _ => unreachable!(),
            };
            let input_bits = operation.source.inputs[0].size * 8;
            body.push_str(&format!(
                "  %comparison = icmp {predicate} i{input_bits} {}, {}\n",
                operands[0], operands[1]
            ));
            body.push_str(&format!(
                "  %result = zext i1 %comparison to {result_type}\n"
            ));
            "%result".to_owned()
        }
        PcodeExactOp::ShiftLeft
        | PcodeExactOp::LogicalShiftRight
        | PcodeExactOp::ArithmeticShiftRight => {
            let count_bits = operation.source.inputs[1].size * 8;
            let count = if count_bits == result_bits {
                operands[1].clone()
            } else {
                let cast = if count_bits < result_bits {
                    "zext"
                } else {
                    "trunc"
                };
                body.push_str(&format!(
                    "  %count = {cast} i{count_bits} {} to {result_type}\n",
                    operands[1]
                ));
                "%count".to_owned()
            };
            // LLVM shifts by >= bitwidth are poison; raw P-code defines them.
            // Compare before narrowing the count, then shift only by a safe
            // count and select the P-code overshift value.
            body.push_str(&format!(
                "  %overshift = icmp uge i{count_bits} {}, {result_bits}\n",
                operands[1]
            ));
            body.push_str(&format!(
                "  %safe_count = select i1 %overshift, {result_type} 0, {result_type} {count}\n"
            ));
            let instruction = match kind {
                PcodeExactOp::ShiftLeft => "shl",
                PcodeExactOp::LogicalShiftRight => "lshr",
                PcodeExactOp::ArithmeticShiftRight => "ashr",
                _ => unreachable!(),
            };
            body.push_str(&format!(
                "  %shifted = {instruction} {result_type} {}, %safe_count\n",
                operands[0]
            ));
            let overshift = if kind == PcodeExactOp::ArithmeticShiftRight {
                body.push_str(&format!(
                    "  %sign_fill = ashr {result_type} {}, {}\n",
                    operands[0],
                    result_bits - 1
                ));
                "%sign_fill"
            } else {
                "0"
            };
            body.push_str(&format!(
                "  %result = select i1 %overshift, {result_type} {overshift}, {result_type} %shifted\n"
            ));
            "%result".to_owned()
        }
    };
    Ok(format!(
        "define {result_type} @hydir_pcode_exact({}) {{\nentry:\n{body}  ret {result_type} {value}\n}}\n",
        parameters.join(", ")
    ))
}

fn parse_constant(offset: &str) -> Result<u64, String> {
    let digits = offset
        .strip_prefix("0x")
        .ok_or_else(|| "P-code constant offset requires 0x prefix".to_owned())?;
    u64::from_str_radix(digits, 16).map_err(|_| "invalid P-code constant offset".to_owned())
}

fn width_mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_ir::pcode::{PcodeAddress, PcodeOperation, PcodeVarnode};
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn operation(
        opcode: u32,
        mnemonic: &str,
        output: u32,
        inputs: &[u32],
    ) -> PcodeSemanticOperation {
        let source = PcodeOperation {
            mnemonic: mnemonic.to_owned(),
            opcode,
            sequence_index: 0,
            sequence_time: 0,
            source_address: PcodeAddress {
                space: "ram".to_owned(),
                offset: "0x1000".to_owned(),
            },
            userop_name: None,
            output: Some(PcodeVarnode {
                space: "unique".to_owned(),
                offset: "0x0".to_owned(),
                size: output,
            }),
            inputs: inputs
                .iter()
                .map(|&size| PcodeVarnode {
                    space: "register".to_owned(),
                    offset: "0x0".to_owned(),
                    size,
                })
                .collect(),
        };
        let kind = match opcode {
            1 => PcodeExactOp::Copy,
            11 => PcodeExactOp::Equal,
            12 => PcodeExactOp::NotEqual,
            13 => PcodeExactOp::SignedLess,
            14 => PcodeExactOp::SignedLessEqual,
            15 => PcodeExactOp::UnsignedLess,
            16 => PcodeExactOp::UnsignedLessEqual,
            17 => PcodeExactOp::ZeroExtend,
            18 => PcodeExactOp::SignExtend,
            19 => PcodeExactOp::Add,
            20 => PcodeExactOp::Sub,
            26 => PcodeExactOp::Xor,
            27 => PcodeExactOp::And,
            28 => PcodeExactOp::Or,
            29 => PcodeExactOp::ShiftLeft,
            30 => PcodeExactOp::LogicalShiftRight,
            31 => PcodeExactOp::ArithmeticShiftRight,
            _ => panic!("unexpected opcode"),
        };
        PcodeSemanticOperation {
            source,
            effect: PcodeEffect::Assign {
                operation: kind,
                result_width_bits: output * 8,
            },
        }
    }

    fn run_opt(source: &str, args: &[&str]) -> Option<String> {
        if Command::new("opt").arg("--version").output().is_err() {
            return None;
        }
        let mut child = Command::new("opt")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(source.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "opt failed: {}\n{source}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(String::from_utf8(output.stdout).unwrap())
    }

    fn folded_return(op: &PcodeSemanticOperation) -> Option<u64> {
        let llvm = emit_pcode_exact_operation_llvm(op).unwrap();
        let folded = run_opt(&llvm, &["-S", "-O2", "-"])?;
        let return_line = folded
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("ret i"))
            .expect("optimized function must return an integer");
        let literal = return_line.split_whitespace().last().unwrap();
        let signed = literal
            .parse::<i128>()
            .expect("optimized result must be a constant");
        let bits = match op.effect {
            PcodeEffect::Assign {
                result_width_bits, ..
            } => result_width_bits,
            PcodeEffect::Opaque { .. } => unreachable!(),
        };
        Some((signed as u64) & width_mask(bits))
    }

    #[test]
    fn every_exact_kind_emits_valid_llvm() {
        for (opcode, mnemonic, output, inputs) in [
            (1, "COPY", 1, vec![1]),
            (11, "INT_EQUAL", 1, vec![8, 8]),
            (12, "INT_NOTEQUAL", 1, vec![8, 8]),
            (13, "INT_SLESS", 1, vec![8, 8]),
            (14, "INT_SLESSEQUAL", 1, vec![8, 8]),
            (15, "INT_LESS", 1, vec![8, 8]),
            (16, "INT_LESSEQUAL", 1, vec![8, 8]),
            (17, "INT_ZEXT", 8, vec![1]),
            (18, "INT_SEXT", 8, vec![1]),
            (19, "INT_ADD", 1, vec![1, 1]),
            (20, "INT_SUB", 1, vec![1, 1]),
            (26, "INT_XOR", 1, vec![1, 1]),
            (27, "INT_AND", 1, vec![1, 1]),
            (28, "INT_OR", 1, vec![1, 1]),
            (29, "INT_LEFT", 1, vec![1, 8]),
            (30, "INT_RIGHT", 1, vec![1, 8]),
            (31, "INT_SRIGHT", 1, vec![1, 8]),
        ] {
            let llvm =
                emit_pcode_exact_operation_llvm(&operation(opcode, mnemonic, output, &inputs))
                    .unwrap();
            let _ = run_opt(&llvm, &["-passes=verify", "-disable-output", "-"]);
        }
    }

    #[test]
    fn rejects_opaque_and_forged_exact_operations() {
        let mut op = operation(19, "INT_ADD", 1, &[1, 1]);
        op.effect = PcodeEffect::Opaque {
            class: hydir_ir::pcode::PcodeOpaqueClass::Unknown,
            reason: "test".to_owned(),
            may_read_memory: true,
            may_write_memory: true,
            may_change_control: true,
            may_write_output: true,
        };
        assert!(emit_pcode_exact_operation_llvm(&op).is_err());
        op.effect = PcodeEffect::Assign {
            operation: PcodeExactOp::Add,
            result_width_bits: 8,
        };
        op.source.inputs[1].size = 8;
        assert!(emit_pcode_exact_operation_llvm(&op).is_err());
        op.source.inputs[1].size = 1;
        op.source.mnemonic = "INT_SUB".to_owned();
        assert!(emit_pcode_exact_operation_llvm(&op).is_err());
    }

    #[test]
    fn overshifts_guard_llvm_poison_and_preserve_sign() {
        for (opcode, mnemonic, expected) in [
            (29, "INT_LEFT", 0),
            (30, "INT_RIGHT", 0),
            (31, "INT_SRIGHT", 255),
        ] {
            let mut op = operation(opcode, mnemonic, 1, &[1, 8]);
            op.source.inputs[0].space = "const".to_owned();
            op.source.inputs[0].offset = "0x80".to_owned();
            op.source.inputs[1].space = "const".to_owned();
            op.source.inputs[1].offset = "0x100".to_owned();
            assert_eq!(op.evaluate_exact(&[0x80, 0x100]).unwrap(), Some(expected));
            if let Some(actual) = folded_return(&op) {
                assert_eq!(actual, expected);
            }
        }
    }

    #[test]
    fn optimized_llvm_matches_exact_evaluator_on_representative_values() {
        let cases: &[(u32, &str, u32, &[u32], &[u64])] = &[
            (1, "COPY", 1, &[1], &[0xff]),
            (11, "INT_EQUAL", 1, &[1, 1], &[0x80, 0x80]),
            (12, "INT_NOTEQUAL", 1, &[1, 1], &[0x80, 0x7f]),
            (13, "INT_SLESS", 1, &[1, 1], &[0x80, 1]),
            (14, "INT_SLESSEQUAL", 1, &[1, 1], &[0x80, 0x80]),
            (15, "INT_LESS", 1, &[1, 1], &[0x80, 1]),
            (16, "INT_LESSEQUAL", 1, &[1, 1], &[0x80, 0x80]),
            (17, "INT_ZEXT", 8, &[1], &[0x80]),
            (18, "INT_SEXT", 8, &[1], &[0x80]),
            (19, "INT_ADD", 1, &[1, 1], &[0xff, 2]),
            (20, "INT_SUB", 1, &[1, 1], &[0, 1]),
            (26, "INT_XOR", 1, &[1, 1], &[0xf0, 0x0f]),
            (27, "INT_AND", 1, &[1, 1], &[0xf0, 0x0f]),
            (28, "INT_OR", 1, &[1, 1], &[0xf0, 0x0f]),
            (29, "INT_LEFT", 1, &[1, 8], &[3, 2]),
            (30, "INT_RIGHT", 1, &[1, 8], &[0x80, 2]),
            (31, "INT_SRIGHT", 1, &[1, 8], &[0x80, 2]),
            (31, "INT_SRIGHT", 1, &[1, 8], &[0x7f, 8]),
            (29, "INT_LEFT", 1, &[1, 8], &[3, 0x100]),
        ];
        for &(opcode, mnemonic, output, inputs, values) in cases {
            let mut op = operation(opcode, mnemonic, output, inputs);
            for (input, &value) in op.source.inputs.iter_mut().zip(values) {
                input.space = "const".to_owned();
                input.offset = format!("0x{value:x}");
            }
            let expected = op.evaluate_exact(values).unwrap().unwrap();
            if let Some(actual) = folded_return(&op) {
                assert_eq!(actual, expected, "{mnemonic} {values:?}");
            }
        }
    }
}
