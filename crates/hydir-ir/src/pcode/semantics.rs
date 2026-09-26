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
/// Input operands are read before the output varnode is written. Arithmetic
/// wraps modulo the output width; comparisons produce a byte containing 0/1.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeExactOp {
    Copy,
    Add,
    Sub,
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
            source: "ghidra_raw_pcode".to_owned(),
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
    /// Evaluate an already lowered exact operation for concrete values up to
    /// 64 bits. Used by tests and later differential checks; this does not
    /// execute memory, control flow, or the enclosing machine instruction.
    pub fn evaluate_exact(&self, inputs: &[u64]) -> Result<Option<u64>, String> {
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
                let expected = super::hex_u64(&input.offset)? & mask(input.size * 8);
                if value & mask(input.size * 8) != expected {
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
            .map(|(&value, &bits)| value & mask(bits))
            .collect::<Vec<_>>();
        let result = match operation {
            PcodeExactOp::Copy | PcodeExactOp::ZeroExtend => values[0],
            PcodeExactOp::SignExtend => signed(values[0], widths[0]) as u64,
            PcodeExactOp::Add => values[0].wrapping_add(values[1]),
            PcodeExactOp::Sub => values[0].wrapping_sub(values[1]),
            PcodeExactOp::Xor => values[0] ^ values[1],
            PcodeExactOp::And => values[0] & values[1],
            PcodeExactOp::Or => values[0] | values[1],
            PcodeExactOp::Equal => u64::from(values[0] == values[1]),
            PcodeExactOp::NotEqual => u64::from(values[0] != values[1]),
            PcodeExactOp::UnsignedLess => u64::from(values[0] < values[1]),
            PcodeExactOp::UnsignedLessEqual => u64::from(values[0] <= values[1]),
            PcodeExactOp::SignedLess => {
                u64::from(signed(values[0], widths[0]) < signed(values[1], widths[1]))
            }
            PcodeExactOp::SignedLessEqual => {
                u64::from(signed(values[0], widths[0]) <= signed(values[1], widths[1]))
            }
            PcodeExactOp::ShiftLeft => {
                if values[1] >= u64::from(result_width_bits) {
                    0
                } else {
                    values[0] << values[1]
                }
            }
            PcodeExactOp::LogicalShiftRight => {
                if values[1] >= u64::from(result_width_bits) {
                    0
                } else {
                    values[0] >> values[1]
                }
            }
            PcodeExactOp::ArithmeticShiftRight => {
                let value = signed(values[0], widths[0]);
                if values[1] >= u64::from(result_width_bits) {
                    if value < 0 { u64::MAX } else { 0 }
                } else {
                    (value >> values[1]) as u64
                }
            }
        };
        Ok(Some(result & mask(result_width_bits)))
    }
}

fn mask(bits: u32) -> u64 {
    if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn signed(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
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
        26 => (Op::Xor, "INT_XOR"),
        27 => (Op::And, "INT_AND"),
        28 => (Op::Or, "INT_OR"),
        29 => (Op::ShiftLeft, "INT_LEFT"),
        30 => (Op::LogicalShiftRight, "INT_RIGHT"),
        31 => (Op::ArithmeticShiftRight, "INT_SRIGHT"),
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
        if output.size == 0 || output.size > 8 {
            return opaque(
                PcodeOpaqueClass::UnmodelledValue,
                "output must be a varnode of 1..=8 bytes".to_owned(),
                true,
            );
        }
        if source
            .inputs
            .iter()
            .any(|input| input.size == 0 || input.size > 8)
        {
            return opaque(
                PcodeOpaqueClass::UnmodelledValue,
                "input exceeds supported 1..=8 byte bitvector width".to_owned(),
                true,
            );
        }
        let sizes = source.inputs.iter().map(|v| v.size).collect::<Vec<_>>();
        let valid = match operation {
            PcodeExactOp::Copy => sizes.as_slice() == [output.size],
            PcodeExactOp::ZeroExtend | PcodeExactOp::SignExtend => {
                sizes.len() == 1 && sizes[0] < output.size
            }
            PcodeExactOp::Equal
            | PcodeExactOp::NotEqual
            | PcodeExactOp::UnsignedLess
            | PcodeExactOp::UnsignedLessEqual
            | PcodeExactOp::SignedLess
            | PcodeExactOp::SignedLessEqual => {
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
        let unknown = lower_operation(&op(72, "POPCOUNT", Some(8), &[8]));
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
