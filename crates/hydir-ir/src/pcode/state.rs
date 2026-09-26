//! Ordered state effects for a selected Ghidra P-code function.
//!
//! This is a source-linked effect inventory, not an executable whole-function
//! lift. In particular, it does not infer CFG edges, register aliases, memory
//! aliases, or calling-convention clobbers. Unmodelled operations remain
//! explicitly opaque, and function fidelity remains unknown.

use super::semantics::lower_operation;
use super::{
    GhidraAddressSpace, PcodeAddress, PcodeEffect, PcodeFunctionIr, PcodeOpaqueClass,
    PcodeOperation, PcodeSemanticDiagnostic, PcodeSemanticFunctionIr, PcodeVarnode,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};

pub const PCODE_STATE_IR_VERSION: u32 = 1;

/// Accesses are ordered: input operands precede the output of each P-code op.
/// A `const` operand is a literal value, not a read of mutable state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeStateAccessKind {
    Immediate,
    Read,
    MayRead,
    Write,
    MayWrite,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeStateAccess {
    pub kind: PcodeStateAccessKind,
    /// Zero-based source input position; absent only for the output.
    pub input_index: Option<u32>,
    pub varnode: PcodeVarnode,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeStateOperation {
    /// Contains Ghidra source address, sequence index/time, opcode and all
    /// varnodes. Its position within `instructions` is the operation order.
    pub source: PcodeOperation,
    pub effect: PcodeEffect,
    pub accesses: Vec<PcodeStateAccess>,
    /// Opaque control, user and unknown operations may affect registers or
    /// temporaries beyond a listed output. This flag prevents consumers from
    /// assuming that unlisted state is preserved across such an operation.
    pub may_clobber_unlisted_state: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeStateInstruction {
    pub address: PcodeAddress,
    pub bytes: String,
    pub parsed_bytes: String,
    pub mnemonic: String,
    pub operations: Vec<PcodeStateOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeStateFunctionIr {
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
    pub instructions: Vec<PcodeStateInstruction>,
    /// A list of ordered effects does not establish whole-function behavior.
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
    pub diagnostics: Vec<PcodeSemanticDiagnostic>,
}

impl PcodeFunctionIr {
    /// Convenience conversion from validated raw P-code through the bounded
    /// semantic lowering. Every source operation is retained exactly once.
    pub fn lower_state(&self) -> PcodeStateFunctionIr {
        self.lower_semantics().lower_state()
    }
}

impl PcodeSemanticFunctionIr {
    /// Build a function-level ordered effect inventory. The raw operation is
    /// rechecked before an `Assign` claim is carried forward, so a forged or
    /// stale semantic artifact cannot silently make an unsupported operation
    /// exact. A mismatch becomes maximally conservative and gets a diagnostic.
    pub fn lower_state(&self) -> PcodeStateFunctionIr {
        let mut diagnostics = self.diagnostics.clone();
        let instructions = self
            .instructions
            .iter()
            .map(|instruction| PcodeStateInstruction {
                address: instruction.address.clone(),
                bytes: instruction.bytes.clone(),
                parsed_bytes: instruction.parsed_bytes.clone(),
                mnemonic: instruction.mnemonic.clone(),
                operations: instruction
                    .operations
                    .iter()
                    .map(|operation| {
                        let source = operation.source.clone();
                        let canonical = lower_operation(&source);
                        let effect = if operation.effect == canonical {
                            canonical
                        } else {
                            diagnostics.push(PcodeSemanticDiagnostic {
                                code: "pcode_semantic_effect_mismatch".to_owned(),
                                message: format!(
                                    "{}: semantic effect disagrees with raw P-code",
                                    source.mnemonic
                                ),
                                source_address: source.source_address.clone(),
                                sequence_index: source.sequence_index,
                            });
                            PcodeEffect::Opaque {
                                class: PcodeOpaqueClass::Unknown,
                                reason: "semantic effect disagrees with raw P-code".to_owned(),
                                may_read_memory: true,
                                may_write_memory: true,
                                may_change_control: true,
                                may_write_output: source.output.is_some(),
                            }
                        };
                        let exact = matches!(effect, PcodeEffect::Assign { .. });
                        let mut accesses = source
                            .inputs
                            .iter()
                            .enumerate()
                            .map(|(index, varnode)| PcodeStateAccess {
                                kind: if varnode.space == "const" {
                                    PcodeStateAccessKind::Immediate
                                } else if exact {
                                    PcodeStateAccessKind::Read
                                } else {
                                    PcodeStateAccessKind::MayRead
                                },
                                input_index: Some(index as u32),
                                varnode: varnode.clone(),
                            })
                            .collect::<Vec<_>>();
                        if let Some(output) = &source.output {
                            accesses.push(PcodeStateAccess {
                                kind: if exact {
                                    PcodeStateAccessKind::Write
                                } else {
                                    PcodeStateAccessKind::MayWrite
                                },
                                input_index: None,
                                varnode: output.clone(),
                            });
                        }
                        let may_clobber_unlisted_state = matches!(
                            effect,
                            PcodeEffect::Opaque {
                                class: PcodeOpaqueClass::ControlTransfer
                                    | PcodeOpaqueClass::UserOperation
                                    | PcodeOpaqueClass::Unknown,
                                ..
                            }
                        );
                        PcodeStateOperation {
                            source,
                            effect,
                            accesses,
                            may_clobber_unlisted_state,
                        }
                    })
                    .collect(),
            })
            .collect();
        PcodeStateFunctionIr {
            schema_version: PCODE_STATE_IR_VERSION,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> PcodeFunctionIr {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_snapshot_v2.json"
        );
        let bytes = std::fs::read(path).unwrap();
        let digest = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["binary_sha256"]
            .as_str()
            .unwrap()
            .to_owned();
        super::super::parse_ghidra_snapshot(&bytes, &digest)
            .unwrap()
            .pcode_function_ir()
            .unwrap()
    }

    #[test]
    fn real_fixture_preserves_order_provenance_and_uncertainty() {
        let raw = fixture();
        let state = raw.lower_state();
        assert_eq!(state.schema_version, PCODE_STATE_IR_VERSION);
        assert_eq!(state.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(state.verification, VerificationStatus::NotRun);
        assert_eq!(state.instructions.len(), raw.instructions.len());
        let sources = raw
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.pcode)
            .collect::<Vec<_>>();
        let operations = state
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.operations)
            .collect::<Vec<_>>();
        assert_eq!(operations.len(), 17);
        assert!(
            sources
                .iter()
                .zip(&operations)
                .all(|(source, operation)| *source == &operation.source)
        );

        let first = operations[0];
        assert_eq!(first.source.source_address.offset, "0x20137c");
        assert_eq!(first.accesses.len(), 2);
        assert_eq!(first.accesses[0].kind, PcodeStateAccessKind::Read);
        assert_eq!(first.accesses[0].input_index, Some(0));
        assert_eq!(first.accesses[1].kind, PcodeStateAccessKind::Write);
        assert_eq!(first.accesses[1].input_index, None);

        let popcount = operations
            .iter()
            .find(|operation| operation.source.mnemonic == "POPCOUNT")
            .unwrap();
        assert_eq!(popcount.accesses[0].kind, PcodeStateAccessKind::MayRead);
        assert_eq!(popcount.accesses[1].kind, PcodeStateAccessKind::MayWrite);
        assert!(popcount.may_clobber_unlisted_state);
        assert!(matches!(
            popcount.effect,
            PcodeEffect::Opaque {
                may_read_memory: true,
                may_write_memory: true,
                may_change_control: true,
                ..
            }
        ));

        let branch = operations
            .iter()
            .find(|operation| operation.source.mnemonic == "CBRANCH")
            .unwrap();
        assert!(branch.may_clobber_unlisted_state);
        assert!(matches!(
            branch.effect,
            PcodeEffect::Opaque {
                may_change_control: true,
                ..
            }
        ));
        let load = operations
            .iter()
            .find(|operation| operation.source.mnemonic == "LOAD")
            .unwrap();
        assert_eq!(load.accesses[0].kind, PcodeStateAccessKind::Immediate);
        assert_eq!(load.accesses[1].kind, PcodeStateAccessKind::MayRead);
        assert_eq!(load.accesses[2].kind, PcodeStateAccessKind::MayWrite);
        assert!(!load.may_clobber_unlisted_state);
        assert!(matches!(
            load.effect,
            PcodeEffect::Opaque {
                may_read_memory: true,
                ..
            }
        ));

        let roundtrip: PcodeStateFunctionIr =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert_eq!(roundtrip, state);
    }

    #[test]
    fn forged_semantic_claim_is_downgraded_to_opaque() {
        let mut semantic = fixture().lower_semantics();
        semantic.instructions[0].operations[0].effect = PcodeEffect::Assign {
            operation: super::super::PcodeExactOp::Add,
            result_width_bits: 64,
        };
        let state = semantic.lower_state();
        let first = &state.instructions[0].operations[0];
        assert!(matches!(
            first.effect,
            PcodeEffect::Opaque {
                class: PcodeOpaqueClass::Unknown,
                may_read_memory: true,
                may_write_memory: true,
                may_change_control: true,
                ..
            }
        ));
        assert_eq!(first.accesses[0].kind, PcodeStateAccessKind::MayRead);
        assert_eq!(first.accesses[1].kind, PcodeStateAccessKind::MayWrite);
        assert_eq!(state.diagnostics.len(), semantic.diagnostics.len() + 1);
    }
}
