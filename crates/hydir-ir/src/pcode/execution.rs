//! Concrete execution of a bounded, ordered prefix of supported raw P-code.
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
//! The trace follows the listed instruction order only until the first opaque
//! or unavailable effect. It does not prove a CFG path, a complete function,
//! or equivalence with the original machine instructions.

use super::semantics::lower_operation;
use super::{
    PCODE_SEMANTIC_IR_VERSION, PcodeAddress, PcodeEffect, PcodeFunctionIr, PcodeOperation,
    PcodeSemanticFunctionIr, PcodeVarnode, hex_u64,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PCODE_EXECUTION_TRACE_VERSION: u32 = 1;
const MAX_KNOWN_STATE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeConcreteState {
    register_bytes: BTreeMap<u64, u8>,
    unique_bytes: BTreeMap<u64, u8>,
}

impl PcodeConcreteState {
    /// Set a complete 1..=8 byte register or unique varnode. The write is
    /// little-endian and preserves all bytes outside the addressed range.
    pub fn write_varnode(&mut self, node: &PcodeVarnode, value: u64) -> Result<(), String> {
        let offset = checked_range(node)?;
        let current_bytes = self
            .register_bytes
            .len()
            .saturating_add(self.unique_bytes.len());
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeExecutedOperation {
    /// Full source provenance and varnode ranges.
    pub source: PcodeOperation,
    /// Values in source input order, read before the output is written.
    pub input_values: Vec<u64>,
    pub output_value: u64,
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
    /// Execute only individually validated exact operations. The first memory,
    /// control, unsupported, invalid, or unavailable-input operation stops the
    /// trace before it changes concrete state.
    pub fn execute_exact_prefix(
        &self,
        initial_state: &PcodeConcreteState,
        max_operations: usize,
    ) -> Result<PcodeExecutionTrace, String> {
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
        if initial_state
            .register_bytes
            .len()
            .saturating_add(initial_state.unique_bytes.len())
            > MAX_KNOWN_STATE_BYTES
        {
            return Err("initial concrete P-code state exceeds byte limit".to_owned());
        }
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
                if let PcodeEffect::Opaque { .. } = &operation.effect {
                    stop = PcodeExecutionStop::OpaqueBoundary {
                        source: source.clone(),
                        effect: operation.effect.clone(),
                    };
                    break 'instructions;
                }
                if source.inputs.len() > 256 || lower_operation(source) != operation.effect {
                    stop = PcodeExecutionStop::InvalidOperation {
                        source: source.clone(),
                        reason: "exact operation disagrees with bounded raw P-code semantics"
                            .to_owned(),
                    };
                    break 'instructions;
                }
                let mut input_values = Vec::with_capacity(source.inputs.len());
                for (index, varnode) in source.inputs.iter().enumerate() {
                    match final_state.read_varnode(varnode) {
                        Ok(Some(value)) => input_values.push(value),
                        Ok(None) => {
                            stop = PcodeExecutionStop::MissingInput {
                                source: source.clone(),
                                input_index: index as u32,
                                varnode: varnode.clone(),
                            };
                            break 'instructions;
                        }
                        Err(reason) => {
                            stop = PcodeExecutionStop::InvalidOperation {
                                source: source.clone(),
                                reason,
                            };
                            break 'instructions;
                        }
                    }
                }
                let value = match operation.evaluate_exact(&input_values) {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        stop = PcodeExecutionStop::InvalidOperation {
                            source: source.clone(),
                            reason: "exact operation returned no concrete result".to_owned(),
                        };
                        break 'instructions;
                    }
                    Err(reason) => {
                        stop = PcodeExecutionStop::InvalidOperation {
                            source: source.clone(),
                            reason,
                        };
                        break 'instructions;
                    }
                };
                let Some(output) = &source.output else {
                    stop = PcodeExecutionStop::InvalidOperation {
                        source: source.clone(),
                        reason: "exact operation has no output varnode".to_owned(),
                    };
                    break 'instructions;
                };
                if let Err(reason) = final_state.write_varnode(output, value) {
                    stop = PcodeExecutionStop::InvalidOperation {
                        source: source.clone(),
                        reason,
                    };
                    break 'instructions;
                }
                executed.push(PcodeExecutedOperation {
                    source: source.clone(),
                    input_values,
                    output_value: value,
                });
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
            PcodeExecutionStop::OpaqueBoundary {
                source: PcodeOperation { opcode: 2, .. },
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
}
