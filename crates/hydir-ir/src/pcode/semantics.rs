//! Native, deliberately bounded semantics for Ghidra raw P-code.
//!
//! Operation numbers and width rules follow Ghidra's P-Code Operation
//! Reference (https://ghidra.re/ghidra_docs/languages/html/pcodedescription.html)
//! and `ghidra.program.model.pcode.PcodeOp`. This artifact describes only
//! individual P-code operations. It does not prove that Ghidra's lift is
//! equivalent to the original machine instruction or recover a CFG.

use super::{GhidraAddressSpace, PcodeAddress, PcodeFunctionIr, PcodeOperation};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};

pub const PCODE_SEMANTIC_IR_VERSION: u32 = 1;

/// A bitvector operation with its size and operands retained in `source`.
/// Input operands are read before the output varnode is written. Addition,
/// subtraction, and multiplication wrap modulo the output width; comparisons
/// produce a byte containing 0/1. Division is defined only on the checked
/// input domain (nonzero divisor, representable signed quotient).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeExactOp {
    Copy,
    Add,
    Sub,
    UnsignedCarry,
    SignedCarry,
    SignedBorrow,
    TwosComplement,
    BitwiseNegate,
    Xor,
    And,
    Or,
    Equal,
    NotEqual,
    UnsignedLess,
    UnsignedLessEqual,
    SignedLess,
    SignedLessEqual,
    ZeroExtend,
    SignExtend,
    ShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    Multiply,
    UnsignedDivide,
    SignedDivide,
    UnsignedRemainder,
    SignedRemainder,
    BooleanNegate,
    BooleanXor,
    BooleanAnd,
    BooleanOr,
    Piece,
    Subpiece,
    PopCount,
    LeadingZeroCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeOpaqueClass {
    MemoryRead,
    MemoryWrite,
    ControlTransfer,
    UserOperation,
    UnmodelledValue,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PcodeEffect {
    Assign {
        operation: PcodeExactOp,
        result_width_bits: u32,
    },
    Opaque {
        class: PcodeOpaqueClass,
        reason: String,
        may_read_memory: bool,
        may_write_memory: bool,
        may_change_control: bool,
        /// `source.output` remains a possible clobber when present.
        may_write_output: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeSemanticOperation {
    /// The complete Ghidra operation, including input/output varnode sizes,
    /// address spaces, source address, sequence index and sequence time.
    pub source: PcodeOperation,
    pub effect: PcodeEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeSemanticInstruction {
    pub address: PcodeAddress,
    pub bytes: String,
    pub parsed_bytes: String,
    pub mnemonic: String,
    pub operations: Vec<PcodeSemanticOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeSemanticDiagnostic {
    pub code: String,
    pub message: String,
    pub source_address: PcodeAddress,
    pub sequence_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeSemanticFunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub source: String,
    pub entry: PcodeAddress,
    pub name: String,
    pub ghidra_version: String,
    pub language_id: String,
    pub compiler_spec_id: String,
    pub flow_overrides_applied: bool,
    pub address_spaces: Vec<GhidraAddressSpace>,
    pub instructions: Vec<PcodeSemanticInstruction>,
    /// Unknown at function level until CFG and machine-level differential
    /// verification are available. Individual `Assign` effects are defined
    /// exactly under the documented P-code model only.
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    pub diagnostics: Vec<PcodeSemanticDiagnostic>,
}

impl PcodeFunctionIr {
    /// Every source operation appears exactly once and in the same order.
    /// Unsupported or malformed operations are retained as opaque effects.
    pub fn lower_semantics(&self) -> PcodeSemanticFunctionIr {
        let mut diagnostics = Vec::new();
        let instructions = self
            .instructions
            .iter()
            .map(|instruction| PcodeSemanticInstruction {
                address: instruction.address.clone(),
                bytes: instruction.bytes.clone(),
                parsed_bytes: instruction.parsed_bytes.clone(),
                mnemonic: instruction.mnemonic.clone(),
                operations: instruction
                    .pcode
                    .iter()
                    .map(|source| {
                        let effect = lower_operation(source);
                        if let PcodeEffect::Opaque { class, reason, .. } = &effect {
                            diagnostics.push(PcodeSemanticDiagnostic {
                                code: match class {
                                    PcodeOpaqueClass::Unknown => "pcode_unknown_effect",
                                    PcodeOpaqueClass::UnmodelledValue => "pcode_unmodelled_value",
                                    _ => "pcode_unmodelled_effect",
                                }
                                .to_owned(),
                                message: format!("{}: {reason}", source.mnemonic),
                                source_address: source.source_address.clone(),
                                sequence_index: source.sequence_index,
                            });
                        }
                        PcodeSemanticOperation {
                            source: source.clone(),
                            effect,
                        }
                    })
                    .collect(),
            })
            .collect();
        PcodeSemanticFunctionIr {
            schema_version: PCODE_SEMANTIC_IR_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            source: self.source.clone(),
            entry: self.entry.clone(),
            name: self.name.clone(),
            ghidra_version: self.ghidra_version.clone(),
            language_id: self.language_id.clone(),
            compiler_spec_id: self.compiler_spec_id.clone(),
            flow_overrides_applied: self.flow_overrides_applied,
            address_spaces: self.address_spaces.clone(),
            instructions,
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
            diagnostics,
        }
    }
}

impl PcodeSemanticOperation {
    /// Compatibility evaluator for concrete varnodes no wider than 64 bits.
    /// Wider values require `evaluate_exact_wide` so no result is truncated.
    pub fn evaluate_exact(&self, inputs: &[u64]) -> Result<Option<u64>, String> {
        if lower_operation(&self.source) != self.effect {
            return Err("exact P-code artifact has invalid opcode, arity, or width".to_owned());
        }
        if self
            .source
            .output
            .as_ref()
            .is_some_and(|node| node.size > 8)
            || self.source.inputs.iter().any(|node| node.size > 8)
        {
            return Err("64-bit P-code evaluator cannot represent a wide varnode".to_owned());
        }
        self.evaluate_exact_wide(
            &inputs
                .iter()
                .map(|&value| u128::from(value))
                .collect::<Vec<_>>(),
        )?
        .map(|value| u64::try_from(value).map_err(|_| "64-bit P-code result overflow".to_owned()))
        .transpose()
    }

    /// Evaluate one validated raw P-code scalar operation up to 128 bits.
    /// This does not execute memory, control flow, or a machine instruction.
    pub fn evaluate_exact_wide(&self, inputs: &[u128]) -> Result<Option<u128>, String> {
        let PcodeEffect::Assign {
            operation,
            result_width_bits,
        } = self.effect
        else {
            return Ok(None);
        };
        if lower_operation(&self.source) != self.effect {
            return Err("exact P-code artifact has invalid opcode, arity, or width".to_owned());
        }
        if inputs.len() != self.source.inputs.len() {
            return Err("concrete input count differs from P-code arity".to_owned());
        }
        for (input, &value) in self.source.inputs.iter().zip(inputs) {
            if input.space == "const" {
                let expected =
                    u128::from(super::hex_u64(&input.offset)?) & mask_wide(input.size * 8);
                if value & mask_wide(input.size * 8) != expected {
                    return Err("concrete input differs from constant varnode".to_owned());
                }
            }
        }
        let widths = self
            .source
            .inputs
            .iter()
            .map(|input| input.size * 8)
            .collect::<Vec<_>>();
        let values = inputs
            .iter()
            .zip(&widths)
            .map(|(&value, &bits)| value & mask_wide(bits))
            .collect::<Vec<_>>();
        let result = match operation {
            PcodeExactOp::Copy | PcodeExactOp::ZeroExtend => values[0],
            PcodeExactOp::SignExtend => signed_wide(values[0], widths[0]) as u128,
            PcodeExactOp::Add => values[0].wrapping_add(values[1]),
            PcodeExactOp::Sub => values[0].wrapping_sub(values[1]),
            PcodeExactOp::UnsignedCarry => {
                let (sum, overflow) = values[0].overflowing_add(values[1]);
                u128::from(overflow || sum > mask_wide(widths[0]))
            }
            PcodeExactOp::SignedCarry | PcodeExactOp::SignedBorrow => {
                let left = signed_wide(values[0], widths[0]);
                let right = signed_wide(values[1], widths[1]);
                let (result, host_overflow) = if operation == PcodeExactOp::SignedCarry {
                    left.overflowing_add(right)
                } else {
                    left.overflowing_sub(right)
                };
                let sign_bit = 1u128 << (widths[0] - 1);
                let left_sign = values[0] & sign_bit != 0;
                let right_sign = values[1] & sign_bit != 0;
                let result_sign = (result as u128) & sign_bit != 0;
                let overflow = if operation == PcodeExactOp::SignedCarry {
                    left_sign == right_sign && result_sign != left_sign
                } else {
                    left_sign != right_sign && result_sign != left_sign
                };
                u128::from(host_overflow || overflow)
            }
            PcodeExactOp::TwosComplement => values[0].wrapping_neg(),
            PcodeExactOp::BitwiseNegate => !values[0],
            PcodeExactOp::Xor => values[0] ^ values[1],
            PcodeExactOp::And => values[0] & values[1],
            PcodeExactOp::Or => values[0] | values[1],
            PcodeExactOp::Multiply => values[0].wrapping_mul(values[1]),
            PcodeExactOp::UnsignedDivide
            | PcodeExactOp::SignedDivide
            | PcodeExactOp::UnsignedRemainder
            | PcodeExactOp::SignedRemainder => {
                if values[1] == 0 {
                    return Err("P-code division or remainder by zero is undefined".to_owned());
                }
                match operation {
                    PcodeExactOp::UnsignedDivide => values[0] / values[1],
                    PcodeExactOp::UnsignedRemainder => values[0] % values[1],
                    PcodeExactOp::SignedDivide => {
                        let left = signed_wide(values[0], widths[0]);
                        let right = signed_wide(values[1], widths[1]);
                        // Ghidra's reference gives no representable result
                        // for MIN / -1 in the same-width signed output.
                        // Keep it an explicit boundary instead of asserting
                        // a wrap or depending on host signed overflow.
                        if left == signed_min(widths[0]) && right == -1 {
                            return Err(
                                "P-code signed division overflows its output width".to_owned()
                            );
                        }
                        (left / right) as u128
                    }
                    PcodeExactOp::SignedRemainder => {
                        let left = signed_wide(values[0], widths[0]);
                        let right = signed_wide(values[1], widths[1]);
                        // MIN % -1 is mathematically zero, but Rust's i128
                        // remainder overflows for that operand pair.
                        if left == i128::MIN && right == -1 {
                            0
                        } else {
                            (left % right) as u128
                        }
                    }
                    _ => unreachable!(),
                }
            }
            // Ghidra's emulator applies these to the full byte. Canonical
            // Boolean inputs still produce 0 or 1.
            PcodeExactOp::BooleanNegate => values[0] ^ 1,
            PcodeExactOp::BooleanXor => values[0] ^ values[1],
            PcodeExactOp::BooleanAnd => values[0] & values[1],
            PcodeExactOp::BooleanOr => values[0] | values[1],
            PcodeExactOp::Piece => (values[0] << widths[1]) | values[1],
            PcodeExactOp::Subpiece => values[0] >> (values[1] * 8),
            PcodeExactOp::Equal => u128::from(values[0] == values[1]),
            PcodeExactOp::NotEqual => u128::from(values[0] != values[1]),
            PcodeExactOp::UnsignedLess => u128::from(values[0] < values[1]),
            PcodeExactOp::UnsignedLessEqual => u128::from(values[0] <= values[1]),
            PcodeExactOp::SignedLess => {
                u128::from(signed_wide(values[0], widths[0]) < signed_wide(values[1], widths[1]))
            }
            PcodeExactOp::SignedLessEqual => {
                u128::from(signed_wide(values[0], widths[0]) <= signed_wide(values[1], widths[1]))
            }
            PcodeExactOp::ShiftLeft => {
                if values[1] >= u128::from(result_width_bits) {
                    0
                } else {
                    values[0] << values[1]
                }
            }
            PcodeExactOp::LogicalShiftRight => {
                if values[1] >= u128::from(result_width_bits) {
                    0
                } else {
                    values[0] >> values[1]
                }
            }
            PcodeExactOp::ArithmeticShiftRight => {
                let value = signed_wide(values[0], widths[0]);
                if values[1] >= u128::from(result_width_bits) {
                    if value < 0 { u128::MAX } else { 0 }
                } else {
                    (value >> values[1]) as u128
                }
            }
            PcodeExactOp::PopCount => u128::from(values[0].count_ones()),
            PcodeExactOp::LeadingZeroCount => {
                u128::from(values[0].leading_zeros() - (128 - widths[0]))
            }
        };
        Ok(Some(result & mask_wide(result_width_bits)))
    }
}

fn mask_wide(bits: u32) -> u128 {
    if bits == 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

fn signed_wide(value: u128, bits: u32) -> i128 {
    let shift = 128 - bits;
    ((value << shift) as i128) >> shift
}

fn signed_min(bits: u32) -> i128 {
    if bits == 128 {
        i128::MIN
    } else {
        -(1i128 << (bits - 1))
    }
}

#[cfg(test)]
fn mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn exact_opcode(opcode: u32) -> Option<(PcodeExactOp, &'static str)> {
    use PcodeExactOp as Op;
    Some(match opcode {
        1 => (Op::Copy, "COPY"),
        11 => (Op::Equal, "INT_EQUAL"),
        12 => (Op::NotEqual, "INT_NOTEQUAL"),
        13 => (Op::SignedLess, "INT_SLESS"),
        14 => (Op::SignedLessEqual, "INT_SLESSEQUAL"),
        15 => (Op::UnsignedLess, "INT_LESS"),
        16 => (Op::UnsignedLessEqual, "INT_LESSEQUAL"),
        17 => (Op::ZeroExtend, "INT_ZEXT"),
        18 => (Op::SignExtend, "INT_SEXT"),
        19 => (Op::Add, "INT_ADD"),
        20 => (Op::Sub, "INT_SUB"),
        21 => (Op::UnsignedCarry, "INT_CARRY"),
        22 => (Op::SignedCarry, "INT_SCARRY"),
        23 => (Op::SignedBorrow, "INT_SBORROW"),
        24 => (Op::TwosComplement, "INT_2COMP"),
        25 => (Op::BitwiseNegate, "INT_NEGATE"),
        26 => (Op::Xor, "INT_XOR"),
        27 => (Op::And, "INT_AND"),
        28 => (Op::Or, "INT_OR"),
        29 => (Op::ShiftLeft, "INT_LEFT"),
        30 => (Op::LogicalShiftRight, "INT_RIGHT"),
        31 => (Op::ArithmeticShiftRight, "INT_SRIGHT"),
        32 => (Op::Multiply, "INT_MULT"),
        33 => (Op::UnsignedDivide, "INT_DIV"),
        34 => (Op::SignedDivide, "INT_SDIV"),
        35 => (Op::UnsignedRemainder, "INT_REM"),
        36 => (Op::SignedRemainder, "INT_SREM"),
        37 => (Op::BooleanNegate, "BOOL_NEGATE"),
        38 => (Op::BooleanXor, "BOOL_XOR"),
        39 => (Op::BooleanAnd, "BOOL_AND"),
        40 => (Op::BooleanOr, "BOOL_OR"),
        62 => (Op::Piece, "PIECE"),
        63 => (Op::Subpiece, "SUBPIECE"),
        72 => (Op::PopCount, "POPCOUNT"),
        73 => (Op::LeadingZeroCount, "LZCOUNT"),
        _ => return None,
    })
}

pub(super) fn lower_operation(source: &PcodeOperation) -> PcodeEffect {
    if let Some((operation, expected_mnemonic)) = exact_opcode(source.opcode) {
        if source.mnemonic != expected_mnemonic {
            return opaque(
                PcodeOpaqueClass::Unknown,
                format!(
                    "opcode {} expects mnemonic {expected_mnemonic}",
                    source.opcode
                ),
                source.output.is_some(),
            );
        }
        let Some(output) = &source.output else {
            return opaque(
                PcodeOpaqueClass::Unknown,
                "value operation has no output".to_owned(),
                false,
            );
        };
        // Direct varnodes in RAM, stack, or other address spaces can read or
        // write memory even for a COPY. Until the state-space model handles
        // those effects, only register and unique storage is an exact target.
        if !matches!(output.space.as_str(), "register" | "unique") {
            return opaque(
                PcodeOpaqueClass::Unknown,
                format!(
                    "output address space {} lacks exact state semantics",
                    output.space
                ),
                true,
            );
        }
        if source
            .inputs
            .iter()
            .any(|input| !matches!(input.space.as_str(), "register" | "unique" | "const"))
        {
            return opaque(
                PcodeOpaqueClass::Unknown,
                "input address space lacks exact state semantics".to_owned(),
                true,
            );
        }
        if output.size == 0 || output.size > 16 {
            return opaque(
                PcodeOpaqueClass::UnmodelledValue,
                "output must be a varnode of 1..=16 bytes".to_owned(),
                true,
            );
        }
        if source
            .inputs
            .iter()
            .any(|input| input.size == 0 || input.size > 16)
        {
            return opaque(
                PcodeOpaqueClass::UnmodelledValue,
                "input exceeds supported 1..=16 byte bitvector width".to_owned(),
                true,
            );
        }
        let sizes = source.inputs.iter().map(|v| v.size).collect::<Vec<_>>();
        let valid = match operation {
            PcodeExactOp::Copy => sizes.as_slice() == [output.size],
            PcodeExactOp::TwosComplement | PcodeExactOp::BitwiseNegate => {
                sizes.as_slice() == [output.size]
            }
            PcodeExactOp::BooleanNegate => output.size == 1 && sizes.as_slice() == [1],
            PcodeExactOp::BooleanXor | PcodeExactOp::BooleanAnd | PcodeExactOp::BooleanOr => {
                output.size == 1 && sizes.as_slice() == [1, 1]
            }
            PcodeExactOp::Piece => sizes.len() == 2 && sizes[0] + sizes[1] == output.size,
            PcodeExactOp::Subpiece => {
                sizes.len() == 2
                    && source.inputs[1].space == "const"
                    && super::hex_u64(&source.inputs[1].offset)
                        .ok()
                        .and_then(|drop| drop.checked_add(u64::from(output.size)))
                        .is_some_and(|end| end <= u64::from(sizes[0]))
            }
            // Ghidra permits independent input and output widths. Within our
            // 128-bit bound the count (0..=128) fits even a one-byte output.
            PcodeExactOp::PopCount | PcodeExactOp::LeadingZeroCount => sizes.len() == 1,
            PcodeExactOp::ZeroExtend | PcodeExactOp::SignExtend => {
                sizes.len() == 1 && sizes[0] < output.size
            }
            PcodeExactOp::Equal
            | PcodeExactOp::NotEqual
            | PcodeExactOp::UnsignedLess
            | PcodeExactOp::UnsignedLessEqual
            | PcodeExactOp::SignedLess
            | PcodeExactOp::SignedLessEqual
            | PcodeExactOp::UnsignedCarry
            | PcodeExactOp::SignedCarry
            | PcodeExactOp::SignedBorrow => {
                sizes.len() == 2 && sizes[0] == sizes[1] && output.size == 1
            }
            PcodeExactOp::ShiftLeft
            | PcodeExactOp::LogicalShiftRight
            | PcodeExactOp::ArithmeticShiftRight => sizes.len() == 2 && sizes[0] == output.size,
            _ => sizes.as_slice() == [output.size, output.size],
        };
        if !valid {
            return opaque(
                PcodeOpaqueClass::UnmodelledValue,
                format!("invalid {expected_mnemonic} input/output widths or arity"),
                true,
            );
        }
        return PcodeEffect::Assign {
            operation,
            result_width_bits: output.size * 8,
        };
    }
    match source.opcode {
        2 => opaque(
            PcodeOpaqueClass::MemoryRead,
            "LOAD address-space and pointer semantics are not lowered".to_owned(),
            source.output.is_some(),
        ),
        3 => opaque(
            PcodeOpaqueClass::MemoryWrite,
            "STORE address-space and pointer semantics are not lowered".to_owned(),
            source.output.is_some(),
        ),
        4..=8 | 10 => opaque(
            PcodeOpaqueClass::ControlTransfer,
            "control transfer is retained without CFG edges".to_owned(),
            source.output.is_some(),
        ),
        9 => opaque(
            PcodeOpaqueClass::UserOperation,
            "CALLOTHER requires its user operation definition".to_owned(),
            source.output.is_some(),
        ),
        _ => opaque(
            PcodeOpaqueClass::Unknown,
            "P-code operation has no validated Rust semantics yet".to_owned(),
            source.output.is_some(),
        ),
    }
}

fn opaque(class: PcodeOpaqueClass, reason: String, may_write_output: bool) -> PcodeEffect {
    let (may_read_memory, may_write_memory, may_change_control) = match class {
        PcodeOpaqueClass::MemoryRead => (true, false, false),
        PcodeOpaqueClass::MemoryWrite => (false, true, false),
        PcodeOpaqueClass::ControlTransfer => (true, true, true),
        PcodeOpaqueClass::UserOperation | PcodeOpaqueClass::Unknown => (true, true, true),
        PcodeOpaqueClass::UnmodelledValue => (false, false, false),
    };
    PcodeEffect::Opaque {
        class,
        reason,
        may_read_memory,
        may_write_memory,
        may_change_control,
        may_write_output,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{PcodeInstruction, PcodeVarnode};

    fn address() -> PcodeAddress {
        PcodeAddress {
            space: "ram".to_owned(),
            offset: "0x401000".to_owned(),
        }
    }

    fn node(space: &str, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.to_owned(),
            offset: "0x0".to_owned(),
            size,
        }
    }

    fn op(opcode: u32, mnemonic: &str, out: Option<u32>, input_sizes: &[u32]) -> PcodeOperation {
        PcodeOperation {
            mnemonic: mnemonic.to_owned(),
            opcode,
            sequence_index: 0,
            sequence_time: 0,
            source_address: address(),
            userop_name: None,
            output: out.map(|size| node("register", size)),
            inputs: input_sizes
                .iter()
                .map(|&size| node("register", size))
                .collect(),
        }
    }

    fn lowered(source: PcodeOperation) -> PcodeSemanticOperation {
        PcodeSemanticOperation {
            effect: lower_operation(&source),
            source,
        }
    }

    #[test]
    fn arithmetic_wraps_at_varnode_width_and_comparisons_use_signedness() {
        assert_eq!(
            lowered(op(19, "INT_ADD", Some(1), &[1, 1]))
                .evaluate_exact(&[255, 1])
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            lowered(op(20, "INT_SUB", Some(1), &[1, 1]))
                .evaluate_exact(&[0, 1])
                .unwrap(),
            Some(255)
        );
        assert_eq!(
            lowered(op(13, "INT_SLESS", Some(1), &[1, 1]))
                .evaluate_exact(&[255, 1])
                .unwrap(),
            Some(1)
        );
        assert_eq!(
            lowered(op(15, "INT_LESS", Some(1), &[1, 1]))
                .evaluate_exact(&[255, 1])
                .unwrap(),
            Some(0)
        );
        assert_eq!(
            lowered(op(18, "INT_SEXT", Some(8), &[1]))
                .evaluate_exact(&[128])
                .unwrap(),
            Some(0xffffffffffffff80)
        );
        assert_eq!(
            lowered(op(17, "INT_ZEXT", Some(8), &[1]))
                .evaluate_exact(&[128])
                .unwrap(),
            Some(128)
        );
    }

    #[test]
    fn division_and_remainder_respect_width_sign_and_undefined_boundaries() {
        for (opcode, mnemonic, width, left, right, expected) in [
            (33, "INT_DIV", 1, 0xff, 2, 0x7f),
            (35, "INT_REM", 1, 0xff, 2, 1),
            (34, "INT_SDIV", 1, 0xf9, 2, 0xfd),
            (36, "INT_SREM", 1, 0xf9, 2, 0xff),
            (34, "INT_SDIV", 1, 7, 0xfe, 0xfd),
            (36, "INT_SREM", 1, 7, 0xfe, 1),
            (33, "INT_DIV", 8, u64::MAX, 2, i64::MAX as u64),
            (35, "INT_REM", 8, u64::MAX, 2, 1),
            (34, "INT_SDIV", 8, (-7i64) as u64, 2, (-3i64) as u64),
            (36, "INT_SREM", 8, (-7i64) as u64, 2, u64::MAX),
            (36, "INT_SREM", 8, i64::MIN as u64, u64::MAX, 0),
        ] {
            let operation = lowered(op(opcode, mnemonic, Some(width), &[width, width]));
            assert!(matches!(operation.effect, PcodeEffect::Assign { .. }));
            assert_eq!(
                operation.evaluate_exact(&[left, right]).unwrap(),
                Some(expected)
            );
            assert!(
                operation
                    .evaluate_exact(&[left, 0])
                    .unwrap_err()
                    .contains("zero")
            );
        }
        for width in [1, 2, 4, 8] {
            let minimum = 1u64 << (width * 8 - 1);
            let negative_one = mask(width * 8);
            let quotient = lowered(op(34, "INT_SDIV", Some(width), &[width, width]));
            assert!(
                quotient
                    .evaluate_exact(&[minimum, negative_one])
                    .unwrap_err()
                    .contains("overflows")
            );
            let remainder = lowered(op(36, "INT_SREM", Some(width), &[width, width]));
            assert_eq!(
                remainder.evaluate_exact(&[minimum, negative_one]).unwrap(),
                Some(0)
            );
        }
        for source in [
            op(33, "INT_DIV", Some(1), &[1, 2]),
            op(34, "INT_SDIV", Some(2), &[1, 1]),
            op(35, "INT_REM", Some(1), &[1]),
            op(36, "INT_SREM", None, &[1, 1]),
        ] {
            assert!(matches!(
                lower_operation(&source),
                PcodeEffect::Opaque { .. }
            ));
        }
    }

    #[test]
    fn wide_signed_multiply_and_high_half_match_ghidra_imul_shape() {
        let extend = lowered(op(18, "INT_SEXT", Some(16), &[8]));
        let multiply = lowered(op(32, "INT_MULT", Some(16), &[16, 16]));
        let mut source = op(63, "SUBPIECE", Some(8), &[16, 4]);
        source.inputs[1].space = "const".to_owned();
        source.inputs[1].offset = "0x8".to_owned();
        let high_half = lowered(source);
        let compare = lowered(op(12, "INT_NOTEQUAL", Some(1), &[16, 16]));

        let negative_three = extend
            .evaluate_exact_wide(&[u64::MAX as u128 - 2])
            .unwrap()
            .unwrap();
        assert_eq!(negative_three, u128::MAX - 2);
        let negative_twenty_one = multiply
            .evaluate_exact_wide(&[negative_three, 7])
            .unwrap()
            .unwrap();
        assert_eq!(negative_twenty_one, u128::MAX - 20);
        assert_eq!(
            high_half
                .evaluate_exact_wide(&[negative_twenty_one, 8])
                .unwrap(),
            Some(u64::MAX as u128)
        );
        assert_eq!(
            compare
                .evaluate_exact_wide(&[negative_twenty_one, negative_twenty_one])
                .unwrap(),
            Some(0)
        );

        let overflowing = multiply
            .evaluate_exact_wide(&[i64::MAX as u128, 2])
            .unwrap()
            .unwrap();
        assert_eq!(overflowing, 0xffff_ffff_ffff_fffe);
        assert_eq!(
            compare
                .evaluate_exact_wide(&[overflowing, u128::MAX - 1])
                .unwrap(),
            Some(1)
        );
        assert!(
            multiply
                .evaluate_exact(&[1, 2])
                .unwrap_err()
                .contains("wide")
        );
        assert!(matches!(
            lower_operation(&op(32, "INT_MULT", Some(17), &[17, 17])),
            PcodeEffect::Opaque { .. }
        ));
    }

    #[test]
    fn wide_arithmetic_boundaries_do_not_overflow_the_host() {
        let carry = lowered(op(21, "INT_CARRY", Some(1), &[16, 16]));
        assert_eq!(carry.evaluate_exact_wide(&[u128::MAX, 1]).unwrap(), Some(1));
        let signed_carry = lowered(op(22, "INT_SCARRY", Some(1), &[16, 16]));
        assert_eq!(
            signed_carry
                .evaluate_exact_wide(&[i128::MAX as u128, 1])
                .unwrap(),
            Some(1)
        );
        let quotient = lowered(op(34, "INT_SDIV", Some(16), &[16, 16]));
        assert!(
            quotient
                .evaluate_exact_wide(&[i128::MIN as u128, u128::MAX])
                .unwrap_err()
                .contains("overflows")
        );
        assert!(
            quotient
                .evaluate_exact_wide(&[1, 0])
                .unwrap_err()
                .contains("zero")
        );
        let remainder = lowered(op(36, "INT_SREM", Some(16), &[16, 16]));
        assert_eq!(
            remainder
                .evaluate_exact_wide(&[i128::MIN as u128, u128::MAX])
                .unwrap(),
            Some(0)
        );
    }

    #[test]
    fn shifts_do_not_apply_machine_shift_count_masking() {
        let left = lowered(op(29, "INT_LEFT", Some(1), &[1, 8]));
        let right = lowered(op(30, "INT_RIGHT", Some(1), &[1, 8]));
        let signed_right = lowered(op(31, "INT_SRIGHT", Some(1), &[1, 8]));
        assert_eq!(left.evaluate_exact(&[1, 8]).unwrap(), Some(0));
        assert_eq!(right.evaluate_exact(&[0xff, 64]).unwrap(), Some(0));
        assert_eq!(
            signed_right.evaluate_exact(&[0x80, 64]).unwrap(),
            Some(0xff)
        );
        assert_eq!(signed_right.evaluate_exact(&[0x7f, 64]).unwrap(), Some(0));
        assert_eq!(signed_right.evaluate_exact(&[0x80, 1]).unwrap(), Some(0xc0));
    }

    #[test]
    fn unary_multiply_and_boolean_operations_are_width_checked() {
        for (opcode, mnemonic, output, inputs, values, expected) in [
            (24, "INT_2COMP", 1, vec![1], vec![0x80], 0x80),
            (25, "INT_NEGATE", 1, vec![1], vec![0x80], 0x7f),
            (32, "INT_MULT", 1, vec![1, 1], vec![0x80, 3], 0x80),
            (
                32,
                "INT_MULT",
                8,
                vec![8, 8],
                vec![u64::MAX, 2],
                u64::MAX - 1,
            ),
            (37, "BOOL_NEGATE", 1, vec![1], vec![0], 1),
            (37, "BOOL_NEGATE", 1, vec![1], vec![1], 0),
        ] {
            let operation = lowered(op(opcode, mnemonic, Some(output), &inputs));
            assert!(matches!(operation.effect, PcodeEffect::Assign { .. }));
            assert_eq!(operation.evaluate_exact(&values).unwrap(), Some(expected));
        }
        for source in [
            op(24, "INT_2COMP", Some(2), &[1]),
            op(25, "INT_NEGATE", Some(1), &[1, 1]),
            op(32, "INT_MULT", Some(1), &[1, 2]),
            op(37, "BOOL_NEGATE", Some(2), &[1]),
            op(37, "BOOL_NEGATE", Some(1), &[2]),
        ] {
            assert!(matches!(
                lower_operation(&source),
                PcodeEffect::Opaque { .. }
            ));
        }
    }

    #[test]
    fn carry_and_signed_overflow_use_input_width() {
        for (opcode, mnemonic, width, left, right, expected) in [
            (21, "INT_CARRY", 1, 0xff, 1, 1),
            (21, "INT_CARRY", 1, 0x7f, 1, 0),
            (21, "INT_CARRY", 8, u64::MAX, 1, 1),
            (22, "INT_SCARRY", 1, 0x7f, 1, 1),
            (22, "INT_SCARRY", 1, 0x80, 0xff, 1),
            (22, "INT_SCARRY", 1, 0xff, 1, 0),
            (22, "INT_SCARRY", 8, i64::MAX as u64, 1, 1),
            (23, "INT_SBORROW", 1, 0x80, 1, 1),
            (23, "INT_SBORROW", 1, 0x7f, 0xff, 1),
            (23, "INT_SBORROW", 1, 0xff, 1, 0),
            (23, "INT_SBORROW", 8, i64::MIN as u64, 1, 1),
        ] {
            let operation = lowered(op(opcode, mnemonic, Some(1), &[width, width]));
            assert_eq!(
                operation.evaluate_exact(&[left, right]).unwrap(),
                Some(expected)
            );
        }
        for source in [
            op(21, "INT_CARRY", Some(2), &[1, 1]),
            op(22, "INT_SCARRY", Some(1), &[1, 2]),
            op(23, "INT_SBORROW", Some(1), &[1]),
        ] {
            assert!(matches!(
                lower_operation(&source),
                PcodeEffect::Opaque { .. }
            ));
        }
    }

    #[test]
    fn piece_and_subpiece_preserve_byte_positions_with_constant_offset() {
        let piece = lowered(op(62, "PIECE", Some(8), &[4, 4]));
        assert_eq!(
            piece.evaluate_exact(&[0x1122_3344, 0x5566_7788]).unwrap(),
            Some(0x1122_3344_5566_7788)
        );
        for (drop, output_size, expected) in [
            (0, 8, 0x1122_3344_5566_7788),
            (2, 4, 0x3344_5566),
            (7, 1, 0x11),
        ] {
            let mut source = op(63, "SUBPIECE", Some(output_size), &[8, 1]);
            source.inputs[1].space = "const".to_owned();
            source.inputs[1].offset = format!("0x{drop:x}");
            let subpiece = lowered(source);
            assert_eq!(
                subpiece
                    .evaluate_exact(&[0x1122_3344_5566_7788, drop])
                    .unwrap(),
                Some(expected)
            );
        }
        for mut source in [
            op(62, "PIECE", Some(8), &[4, 3]),
            op(63, "SUBPIECE", Some(4), &[8, 1]),
        ] {
            assert!(matches!(
                lower_operation(&source),
                PcodeEffect::Opaque { .. }
            ));
            source.inputs[1].space = "const".to_owned();
            source.inputs[1].offset = "0x5".to_owned();
            if source.opcode == 63 {
                assert!(matches!(
                    lower_operation(&source),
                    PcodeEffect::Opaque { .. }
                ));
            }
        }
    }

    #[test]
    fn malformed_widths_and_unknown_effects_are_not_silently_lowered() {
        assert!(matches!(
            lower_operation(&op(19, "INT_ADD", Some(1), &[1, 2])),
            PcodeEffect::Opaque {
                class: PcodeOpaqueClass::UnmodelledValue,
                ..
            }
        ));
        assert!(matches!(
            lower_operation(&op(17, "INT_ZEXT", Some(1), &[1])),
            PcodeEffect::Opaque { .. }
        ));
        assert!(matches!(
            lower_operation(&op(19, "COPY", Some(1), &[1, 1])),
            PcodeEffect::Opaque {
                class: PcodeOpaqueClass::Unknown,
                ..
            }
        ));
        let store = lower_operation(&op(3, "STORE", None, &[8, 8, 1]));
        assert!(matches!(
            store,
            PcodeEffect::Opaque {
                may_write_memory: true,
                ..
            }
        ));
        let userop = lower_operation(&op(9, "CALLOTHER", None, &[8]));
        assert!(matches!(
            userop,
            PcodeEffect::Opaque {
                may_change_control: true,
                may_write_memory: true,
                ..
            }
        ));
        let unknown = lower_operation(&op(73, "UNSUPPORTED", Some(8), &[8]));
        assert!(matches!(
            unknown,
            PcodeEffect::Opaque {
                may_read_memory: true,
                may_write_memory: true,
                may_change_control: true,
                may_write_output: true,
                ..
            }
        ));
    }

    #[test]
    fn popcount_counts_only_input_width_and_zero_extends_output() {
        for (input_bytes, output_bytes, input, expected) in [
            (1, 1, 0, 0),
            (1, 8, 0xff, 8),
            (2, 1, 0xffff, 16),
            (4, 4, 0x8000_0001, 2),
            (8, 1, u64::MAX, 64),
            (8, 8, 0xaaaa_aaaa_aaaa_aaaa, 32),
        ] {
            let operation = lowered(op(72, "POPCOUNT", Some(output_bytes), &[input_bytes]));
            assert!(matches!(
                operation.effect,
                PcodeEffect::Assign {
                    operation: PcodeExactOp::PopCount,
                    ..
                }
            ));
            assert_eq!(operation.evaluate_exact(&[input]).unwrap(), Some(expected));
        }
        assert_eq!(
            lowered(op(72, "POPCOUNT", Some(1), &[1]))
                .evaluate_exact(&[0x1ff])
                .unwrap(),
            Some(8)
        );
        for source in [
            op(72, "POPCOUNT", Some(1), &[]),
            op(72, "POPCOUNT", Some(1), &[1, 1]),
            op(72, "POPCOUNT", Some(1), &[17]),
            op(72, "POPCOUNT", None, &[8]),
        ] {
            assert!(matches!(
                lower_operation(&source),
                PcodeEffect::Opaque { .. }
            ));
        }
    }

    #[test]
    fn boolean_binary_and_lzcount_are_exact_only_for_valid_widths() {
        for (opcode, mnemonic, inputs, expected) in [
            (38, "BOOL_XOR", [1, 0], 1),
            (38, "BOOL_XOR", [2, 1], 3),
            (39, "BOOL_AND", [2, 1], 0),
            (39, "BOOL_AND", [2, 0], 0),
            (40, "BOOL_OR", [0, 2], 2),
            (40, "BOOL_OR", [0, 0], 0),
        ] {
            let operation = lowered(op(opcode, mnemonic, Some(1), &[1, 1]));
            assert!(matches!(operation.effect, PcodeEffect::Assign { .. }));
            assert_eq!(operation.evaluate_exact(&inputs).unwrap(), Some(expected));
        }
        assert_eq!(
            lowered(op(37, "BOOL_NEGATE", Some(1), &[1]))
                .evaluate_exact(&[2])
                .unwrap(),
            Some(3)
        );
        for (input_bytes, output_bytes, input, expected) in [
            (1, 1, 0, 8),
            (1, 8, 1, 7),
            (1, 1, 0x80, 0),
            (3, 1, 0x0080_0000, 0),
            (3, 8, 0x0000_0001, 23),
            (8, 1, 0, 64),
            (8, 8, 1, 63),
        ] {
            let operation = lowered(op(73, "LZCOUNT", Some(output_bytes), &[input_bytes]));
            assert!(matches!(
                operation.effect,
                PcodeEffect::Assign {
                    operation: PcodeExactOp::LeadingZeroCount,
                    ..
                }
            ));
            assert_eq!(operation.evaluate_exact(&[input]).unwrap(), Some(expected));
        }
        for source in [
            op(38, "BOOL_XOR", Some(2), &[1, 1]),
            op(39, "BOOL_AND", Some(1), &[2, 1]),
            op(40, "BOOL_OR", Some(1), &[1]),
            op(73, "LZCOUNT", Some(1), &[]),
            op(73, "LZCOUNT", Some(1), &[17]),
            op(73, "LZCOUNT", None, &[1]),
        ] {
            assert!(matches!(
                lower_operation(&source),
                PcodeEffect::Opaque { .. }
            ));
        }
    }

    #[test]
    fn direct_ram_varnodes_are_opaque_even_for_copy() {
        let mut memory_read = op(1, "COPY", Some(1), &[1]);
        memory_read.inputs[0].space = "ram".to_owned();
        assert!(matches!(
            lower_operation(&memory_read),
            PcodeEffect::Opaque {
                class: PcodeOpaqueClass::Unknown,
                may_read_memory: true,
                may_write_memory: true,
                may_change_control: true,
                may_write_output: true,
                ..
            }
        ));
        let mut memory_write = op(1, "COPY", Some(1), &[1]);
        memory_write.output.as_mut().unwrap().space = "ram".to_owned();
        assert!(matches!(
            lower_operation(&memory_write),
            PcodeEffect::Opaque {
                class: PcodeOpaqueClass::Unknown,
                may_write_memory: true,
                may_write_output: true,
                ..
            }
        ));
    }

    #[test]
    fn public_evaluator_rejects_forged_widths_and_wrong_constants() {
        let mut exact = lowered(op(1, "COPY", Some(1), &[1]));
        exact.source.inputs[0].size = 0;
        assert!(exact.evaluate_exact(&[0]).unwrap_err().contains("invalid"));
        exact.source.inputs[0].size = 4096;
        assert!(exact.evaluate_exact(&[0]).unwrap_err().contains("invalid"));
        exact.source.inputs[0].size = 1;
        exact.source.inputs[0].space = "const".to_owned();
        exact.source.inputs[0].offset = "0x2a".to_owned();
        assert!(exact.evaluate_exact(&[0]).unwrap_err().contains("constant"));
        assert_eq!(exact.evaluate_exact(&[42]).unwrap(), Some(42));
    }

    #[test]
    fn conversion_preserves_operation_order_provenance_and_uncertainty() {
        let mut first = op(1, "COPY", Some(8), &[8]);
        first.sequence_time = 4;
        let mut second = op(2, "LOAD", Some(8), &[8, 8]);
        second.sequence_index = 1;
        second.sequence_time = 9;
        let source = PcodeFunctionIr {
            schema_version: super::super::PCODE_IR_VERSION,
            binary_sha256: "a".repeat(64),
            source: "ghidra_raw_pcode".to_owned(),
            flow_overrides_applied: true,
            ghidra_version: "12.1.4".to_owned(),
            language_id: "x86:LE:64:default".to_owned(),
            compiler_spec_id: "gcc".to_owned(),
            address_spaces: Vec::new(),
            entry: address(),
            name: "f".to_owned(),
            instructions: vec![PcodeInstruction {
                address: address(),
                bytes: "90".to_owned(),
                parsed_bytes: "90".to_owned(),
                mnemonic: "NOP".to_owned(),
                pcode: vec![first.clone(), second.clone()],
            }],
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        };
        let result = source.lower_semantics();
        assert_eq!(result.schema_version, PCODE_SEMANTIC_IR_VERSION);
        assert_eq!(result.instructions[0].operations.len(), 2);
        assert_eq!(result.instructions[0].operations[0].source, first);
        assert_eq!(result.instructions[0].operations[1].source, second);
        assert_eq!(result.diagnostics.len(), 1);
        assert_eq!(result.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(result.verification, VerificationStatus::NotRun);
        let roundtrip: PcodeSemanticFunctionIr =
            serde_json::from_slice(&serde_json::to_vec(&result).unwrap()).unwrap();
        assert_eq!(roundtrip, result);
    }

    #[test]
    fn real_ghidra_fixture_keeps_every_effect_visible() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_snapshot_v2.json"
        );
        let bytes = std::fs::read(path).unwrap();
        let digest = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["binary_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        let raw = super::super::parse_ghidra_snapshot(&bytes, &digest)
            .unwrap()
            .pcode_function_ir()
            .unwrap();
        let semantic = raw.lower_semantics();
        let sources = raw
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.pcode)
            .collect::<Vec<_>>();
        let lowered = semantic
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.operations)
            .collect::<Vec<_>>();
        assert_eq!(sources.len(), 17);
        assert!(
            sources
                .iter()
                .zip(&lowered)
                .all(|(source, lowered)| *source == &lowered.source)
        );
        assert!(lowered.iter().any(|operation| {
            operation.source.mnemonic == "LOAD"
                && matches!(
                    operation.effect,
                    PcodeEffect::Opaque {
                        may_read_memory: true,
                        ..
                    }
                )
        }));
        assert!(lowered.iter().any(|operation| {
            operation.source.mnemonic == "CBRANCH"
                && matches!(
                    operation.effect,
                    PcodeEffect::Opaque {
                        may_change_control: true,
                        ..
                    }
                )
        }));
        assert_eq!(
            semantic.diagnostics.len(),
            lowered
                .iter()
                .filter(|operation| matches!(operation.effect, PcodeEffect::Opaque { .. }))
                .count()
        );
    }
}
