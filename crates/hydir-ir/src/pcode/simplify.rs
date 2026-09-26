//! A bounded, source-linked rewrite of exact raw P-code value operations.
//!
//! This pass proves only the stated bitvector identity under the local P-code
//! model. It does not establish equivalence with the original machine code.

use super::semantics::lower_operation;
use super::{
    MAX_INSTRUCTIONS, MAX_OPERATIONS, PCODE_IR_VERSION, PcodeAddress, PcodeEffect, PcodeExactOp,
    PcodeFunctionIr, PcodeOperation, PcodeVarnode, hex_u64, offset, validate_varnode,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};

pub const PCODE_SIMPLIFICATION_VERSION: u32 = 1;
const SIMPLIFICATION_SOURCE: &str = "hydir_checked_pcode_simplification";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeSimplificationRule {
    AddZeroToCopy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSimplificationRewrite {
    /// Zero-based positions in both `before` and `after`; no operation moves.
    pub instruction_index: usize,
    pub operation_index: usize,
    pub source_address: PcodeAddress,
    pub sequence_index: u32,
    pub rule: PcodeSimplificationRule,
    pub reason: String,
    pub preconditions: Vec<String>,
    pub before: PcodeOperation,
    pub after: PcodeOperation,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSimplificationArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub source: String,
    pub before: PcodeFunctionIr,
    pub after: PcodeFunctionIr,
    pub rewrites: Vec<PcodeSimplificationRewrite>,
    /// Function and machine equivalence remain unproven by a local identity.
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

impl PcodeFunctionIr {
    /// Rewrite only validated `INT_ADD x, 0` or `INT_ADD 0, x` value operations.
    /// Each operation remains at its original position, and malformed or
    /// opaque operations are copied without modification.
    pub fn simplify_checked(&self) -> Result<PcodeSimplificationArtifact, String> {
        if self.schema_version != PCODE_IR_VERSION {
            return Err("unsupported raw P-code IR version".to_owned());
        }
        if self.source != "ghidra_raw_pcode" {
            return Err("checked simplification requires Ghidra raw P-code".to_owned());
        }
        if self.binary_sha256.len() != 64
            || !self
                .binary_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("raw P-code binary SHA-256 must be 64 lowercase hex digits".to_owned());
        }
        if self.instructions.len() > MAX_INSTRUCTIONS
            || self
                .instructions
                .iter()
                .any(|instruction| instruction.pcode.len() > 256)
            || self
                .instructions
                .iter()
                .map(|instruction| instruction.pcode.len())
                .sum::<usize>()
                > MAX_OPERATIONS
        {
            return Err("raw P-code exceeds checked simplification limits".to_owned());
        }

        let mut after = self.clone();
        after.source = SIMPLIFICATION_SOURCE.to_owned();
        after.semantic_fidelity = SemanticFidelity::Unknown;
        after.verification = VerificationStatus::NotRun;
        let mut rewrites = Vec::new();
        for (instruction_index, instruction) in after.instructions.iter_mut().enumerate() {
            if offset(&instruction.address).is_err() {
                continue;
            }
            for (operation_index, operation) in instruction.pcode.iter_mut().enumerate() {
                if operation.sequence_index as usize != operation_index
                    || operation.sequence_time < 0
                    || offset(&operation.source_address).is_err()
                {
                    continue;
                }
                let Some((replacement, preconditions)) = add_zero_replacement(operation) else {
                    continue;
                };
                let before = std::mem::replace(operation, replacement.clone());
                rewrites.push(PcodeSimplificationRewrite {
                    instruction_index,
                    operation_index,
                    source_address: before.source_address.clone(),
                    sequence_index: before.sequence_index,
                    rule: PcodeSimplificationRule::AddZeroToCopy,
                    reason:
                        "addition of the zero bitvector yields the other input at the same width"
                            .to_owned(),
                    preconditions,
                    before,
                    after: replacement,
                });
            }
        }
        Ok(PcodeSimplificationArtifact {
            schema_version: PCODE_SIMPLIFICATION_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            source: SIMPLIFICATION_SOURCE.to_owned(),
            before: self.clone(),
            after,
            rewrites,
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        })
    }
}

fn valid_value_varnode(node: &PcodeVarnode) -> bool {
    if validate_varnode(node).is_err() || !(1..=8).contains(&node.size) {
        return false;
    }
    hex_u64(&node.offset)
        .ok()
        .is_some_and(|start| start.checked_add(u64::from(node.size - 1)).is_some())
}

fn add_zero_replacement(source: &PcodeOperation) -> Option<(PcodeOperation, Vec<String>)> {
    if source.opcode != 19
        || source.mnemonic != "INT_ADD"
        || source.userop_name.is_some()
        || source.inputs.len() != 2
        || !matches!(
            lower_operation(source),
            PcodeEffect::Assign {
                operation: PcodeExactOp::Add,
                ..
            }
        )
    {
        return None;
    }
    let output = source.output.as_ref()?;
    if !valid_value_varnode(output) || source.inputs.iter().any(|node| !valid_value_varnode(node)) {
        return None;
    }
    let zero_index = source
        .inputs
        .iter()
        .position(|node| node.space == "const" && hex_u64(&node.offset).ok() == Some(0))?;
    let value = &source.inputs[1 - zero_index];
    if !matches!(value.space.as_str(), "register" | "unique") {
        return None;
    }

    let mut replacement = source.clone();
    replacement.mnemonic = "COPY".to_owned();
    replacement.opcode = 1;
    replacement.inputs = vec![value.clone()];
    if !matches!(
        lower_operation(&replacement),
        PcodeEffect::Assign {
            operation: PcodeExactOp::Copy,
            ..
        }
    ) {
        return None;
    }
    let preconditions = vec![
        "instruction and operation source addresses and operation sequence metadata are valid"
            .to_owned(),
        "opcode 19 has mnemonic INT_ADD, exactly two inputs, one output, and no user operation"
            .to_owned(),
        "output and inputs are validated 1..=8 byte varnodes of equal width with bounded offsets"
            .to_owned(),
        "output and retained input use register or unique storage; the removed input is literal const 0"
            .to_owned(),
        "both source INT_ADD and replacement COPY have exact local P-code value semantics"
            .to_owned(),
    ];
    Some((replacement, preconditions))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{PcodeConcreteState, PcodeInstruction};

    fn node(space: &str, offset: &str, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.to_owned(),
            offset: offset.to_owned(),
            size,
        }
    }

    fn address() -> PcodeAddress {
        PcodeAddress {
            space: "ram".to_owned(),
            offset: "0x1000".to_owned(),
        }
    }

    fn operation(output: PcodeVarnode, inputs: Vec<PcodeVarnode>) -> PcodeOperation {
        PcodeOperation {
            mnemonic: "INT_ADD".to_owned(),
            opcode: 19,
            sequence_index: 0,
            sequence_time: 5,
            source_address: address(),
            userop_name: None,
            output: Some(output),
            inputs,
        }
    }

    fn function(operations: Vec<PcodeOperation>) -> PcodeFunctionIr {
        PcodeFunctionIr {
            schema_version: PCODE_IR_VERSION,
            binary_sha256: "a".repeat(64),
            source: "ghidra_raw_pcode".to_owned(),
            flow_overrides_applied: true,
            ghidra_version: "test".to_owned(),
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
                pcode: operations,
            }],
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        }
    }

    #[test]
    fn add_zero_rewrite_matches_concrete_outcomes_across_widths_and_aliases() {
        for width in [1, 2, 4, 8] {
            for (space, input_offset, output_offset) in [
                ("register", "0x10", "0x10"),
                ("register", "0x10", "0x11"),
                ("unique", "0x10", "0x10"),
                ("unique", "0x10", "0x11"),
            ] {
                for zero_first in [false, true] {
                    let input = node(space, input_offset, width);
                    let output = node(space, output_offset, width);
                    let zero = node("const", "0x0", width);
                    let inputs = if zero_first {
                        vec![zero, input.clone()]
                    } else {
                        vec![input.clone(), zero]
                    };
                    let mut add = operation(output.clone(), inputs);
                    let mut operations = Vec::new();
                    let seed_node = if space == "unique" {
                        // Unique temporaries are cleared at an instruction
                        // boundary, so define one before reading it.
                        let register = node("register", "0x10", width);
                        operations.push(PcodeOperation {
                            mnemonic: "COPY".to_owned(),
                            opcode: 1,
                            sequence_index: 0,
                            sequence_time: 4,
                            source_address: address(),
                            userop_name: None,
                            output: Some(input.clone()),
                            inputs: vec![register.clone()],
                        });
                        add.sequence_index = 1;
                        register
                    } else {
                        input.clone()
                    };
                    operations.push(add);
                    let add_index = operations.len() - 1;
                    let original = function(operations);
                    let artifact = original.simplify_checked().unwrap();
                    assert_eq!(artifact.rewrites.len(), 1);
                    assert_eq!(artifact.before, original);
                    assert_eq!(
                        artifact.after.instructions[0].pcode[add_index].inputs,
                        vec![input.clone()]
                    );
                    assert_eq!(artifact.after.instructions[0].pcode[add_index].opcode, 1);
                    assert_eq!(artifact.rewrites[0].before.source_address, address());
                    assert_eq!(artifact.rewrites[0].before.sequence_time, 5);
                    for value in [0, 1, 0x5a, u64::MAX] {
                        let mut seed = PcodeConcreteState::default();
                        seed.write_varnode(&seed_node, value).unwrap();
                        let before = original.execute_exact_prefix(&seed, 2).unwrap();
                        let after = artifact.after.execute_exact_prefix(&seed, 2).unwrap();
                        assert_eq!(before.final_state, after.final_state);
                        assert_eq!(before.stop, after.stop);
                        assert_eq!(
                            before.final_state.read_varnode(&output).unwrap(),
                            after.final_state.read_varnode(&output).unwrap()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn malformed_and_opaque_operations_stay_in_place() {
        let value = node("register", "0x10", 4);
        let zero = node("const", "0x0", 4);
        let mut wrong_width =
            operation(value.clone(), vec![value.clone(), node("const", "0x0", 2)]);
        let mut wrong_opcode = operation(value.clone(), vec![value.clone(), zero.clone()]);
        wrong_opcode.opcode = 63;
        let mut invalid_offset = operation(value.clone(), vec![value.clone(), zero.clone()]);
        invalid_offset.inputs[0].offset = "not hex".to_owned();
        let mut invalid_source = operation(value.clone(), vec![value.clone(), zero.clone()]);
        invalid_source.source_address.offset = "not hex".to_owned();
        let mut memory = operation(node("ram", "0x2000", 4), vec![value.clone(), zero.clone()]);
        let mut nonzero = operation(value.clone(), vec![value.clone(), node("const", "0x1", 4)]);
        let mut valid = operation(value.clone(), vec![value, zero]);
        let mut ops = [
            &mut wrong_width,
            &mut wrong_opcode,
            &mut invalid_offset,
            &mut invalid_source,
            &mut memory,
            &mut nonzero,
            &mut valid,
        ];
        for (index, op) in ops.iter_mut().enumerate() {
            op.sequence_index = index as u32;
        }
        let original = function(vec![
            wrong_width,
            wrong_opcode,
            invalid_offset,
            invalid_source,
            memory,
            nonzero,
            valid,
        ]);
        let artifact = original.simplify_checked().unwrap();
        assert_eq!(artifact.rewrites.len(), 1);
        assert_eq!(artifact.rewrites[0].operation_index, 6);
        assert_eq!(artifact.after.instructions[0].pcode.len(), 7);
        assert_eq!(
            &artifact.after.instructions[0].pcode[..6],
            &original.instructions[0].pcode[..6]
        );
        assert_eq!(artifact.after.instructions[0].pcode[6].sequence_index, 6);
    }

    #[test]
    fn artifact_roundtrips_with_source_and_uncertainty() {
        let value = node("register", "0x10", 8);
        let original = function(vec![operation(
            value.clone(),
            vec![value, node("const", "0x0", 8)],
        )]);
        let artifact = original.simplify_checked().unwrap();
        assert_eq!(artifact.binary_sha256, original.binary_sha256);
        assert_eq!(artifact.after.source, SIMPLIFICATION_SOURCE);
        assert_eq!(artifact.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(artifact.verification, VerificationStatus::NotRun);
        assert_eq!(artifact.after.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(artifact.after.verification, VerificationStatus::NotRun);
        assert!(!artifact.rewrites[0].preconditions.is_empty());
        let decoded: PcodeSimplificationArtifact =
            serde_json::from_slice(&serde_json::to_vec(&artifact).unwrap()).unwrap();
        assert_eq!(decoded, artifact);
    }
}
