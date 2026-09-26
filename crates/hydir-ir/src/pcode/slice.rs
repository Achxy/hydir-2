//! Bounded backward value-dependency evidence for one imported P-code function.
//!
//! A slice is a candidate explanation of operands along a single analyzed
//! fallthrough chain. It is not a feasible-path proof, a memory alias analysis,
//! or a statement about the original machine code's equivalence to P-code.

use super::semantics::lower_operation;
use super::{
    GhidraFlowKind, GhidraSnapshot, PcodeCfgFunctionIr, PcodeEffect, PcodeOperation, PcodeVarnode,
    hex_u64,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PCODE_SLICE_VERSION: u32 = 1;
pub const MAX_PCODE_SLICE_OPERATIONS: usize = 512;
pub const MAX_PCODE_SLICE_INSTRUCTIONS: usize = 64;
pub const MAX_PCODE_SLICE_PENDING_VALUES: usize = 64;
pub const MAX_PCODE_SLICE_BOUNDARIES: usize = 1024;

/// Select an operation and optionally one of its inputs. With no input index,
/// the slice follows every input to the selected operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSliceTarget {
    pub instruction_index: u32,
    pub operation_index: u32,
    pub input_index: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSliceSite {
    pub instruction_index: u32,
    pub operation_index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeSliceBoundaryKind {
    /// Literal P-code input; its offset is the value, not a state address.
    Constant,
    /// A register value reaches function entry without a local definition.
    EntryValue,
    /// No unique, unconditional analyzed fallthrough predecessor is available.
    ControlFlow,
    /// LOAD or another explicit memory read is a value source; aliasing is
    /// deliberately not inferred from preceding STORE operations.
    MemoryRead,
    /// An operation may change the requested state but has no exact model.
    OpaqueEffect,
    /// A write overlaps only part of the requested varnode.
    PartialOverlap,
    /// A non-register/non-unique input is not tracked as scalar state.
    ExternalSpace,
    /// Ghidra unique-space temporaries are not carried across instructions.
    TemporaryLifetime,
    /// A fixed work or pending-value limit was reached.
    Budget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSliceBoundary {
    pub kind: PcodeSliceBoundaryKind,
    pub varnode: Option<PcodeVarnode>,
    pub site: Option<PcodeSliceSite>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSliceStep {
    pub site: PcodeSliceSite,
    /// Source address, sequence index and time remain on the raw operation.
    pub source: PcodeOperation,
    pub effect: PcodeEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeBackwardSlice {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_entry: super::PcodeAddress,
    pub function_name: String,
    pub target: PcodeSliceTarget,
    /// The selected operation comes first, then source operations in backward
    /// traversal order. Every item retains its original Ghidra provenance.
    pub steps: Vec<PcodeSliceStep>,
    /// Values whose origin is outside this explicitly bounded slice.
    pub boundaries: Vec<PcodeSliceBoundary>,
    pub operations_examined: u32,
    pub instructions_examined: u32,
    pub truncated: bool,
    /// This is always false in v1. An analyzed fallthrough is evidence, not
    /// an independently verified or necessarily feasible execution path.
    pub path_proven: bool,
}

impl GhidraSnapshot {
    pub fn backward_pcode_slice(
        &self,
        target: PcodeSliceTarget,
    ) -> Result<PcodeBackwardSlice, String> {
        let cfg = self.pcode_cfg_ir()?;
        slice_cfg(&cfg, target)
    }
}

fn slice_cfg(
    cfg: &PcodeCfgFunctionIr,
    target: PcodeSliceTarget,
) -> Result<PcodeBackwardSlice, String> {
    let instruction = cfg
        .state
        .instructions
        .get(target.instruction_index as usize)
        .ok_or("P-code slice instruction index is out of range")?;
    let operation = instruction
        .operations
        .get(target.operation_index as usize)
        .ok_or("P-code slice operation index is out of range")?;
    if let Some(input_index) = target.input_index {
        if input_index as usize >= operation.source.inputs.len() {
            return Err("P-code slice input index is out of range".to_owned());
        }
    }
    if cfg.nodes.len() != cfg.state.instructions.len()
        || cfg
            .nodes
            .get(target.instruction_index as usize)
            .is_none_or(|node| {
                node.instruction_index != target.instruction_index
                    || node.address != instruction.address
            })
    {
        return Err("P-code CFG nodes do not match state instructions".to_owned());
    }

    let site = PcodeSliceSite {
        instruction_index: target.instruction_index,
        operation_index: target.operation_index,
    };
    let mut result = PcodeBackwardSlice {
        schema_version: PCODE_SLICE_VERSION,
        binary_sha256: cfg.binary_sha256.clone(),
        function_entry: cfg.state.entry.clone(),
        function_name: cfg.state.name.clone(),
        target,
        steps: vec![PcodeSliceStep {
            site,
            source: operation.source.clone(),
            effect: lower_operation(&operation.source),
        }],
        boundaries: Vec::new(),
        operations_examined: 0,
        instructions_examined: 0,
        truncated: false,
        path_proven: false,
    };
    let mut pending = Vec::new();
    let selected_inputs: &[PcodeVarnode] = if let Some(input_index) = target.input_index {
        &operation.source.inputs[input_index as usize..input_index as usize + 1]
    } else {
        &operation.source.inputs
    };
    for input in selected_inputs {
        add_input(&mut result, &mut pending, input, site)?;
        if result.truncated {
            break;
        }
    }
    if pending.is_empty() || result.truncated {
        return Ok(result);
    }

    let mut current = target.instruction_index;
    let mut operation_end = target.operation_index as usize;
    let mut visited = BTreeSet::new();
    loop {
        if result.instructions_examined as usize >= MAX_PCODE_SLICE_INSTRUCTIONS {
            budget_boundary(&mut result, &pending, None);
            break;
        }
        if !visited.insert(current) {
            control_boundary(&mut result, &pending, None);
            break;
        }
        let instruction = &cfg.state.instructions[current as usize];
        result.instructions_examined += 1;
        for index in (0..operation_end).rev() {
            let site = PcodeSliceSite {
                instruction_index: current,
                operation_index: index as u32,
            };
            if result.operations_examined as usize >= MAX_PCODE_SLICE_OPERATIONS {
                budget_boundary(&mut result, &pending, Some(site));
                return Ok(result);
            }
            result.operations_examined += 1;
            let operation = &instruction.operations[index];
            let canonical = lower_operation(&operation.source);
            let effect = if operation.effect == canonical {
                canonical
            } else {
                // A stale or forged effect is never used as an exact write.
                opaque_boundary(
                    &mut result,
                    &pending,
                    site,
                    operation,
                    PcodeEffect::Opaque {
                        class: super::PcodeOpaqueClass::Unknown,
                        reason: "state effect disagrees with raw P-code".to_owned(),
                        may_read_memory: true,
                        may_write_memory: true,
                        may_change_control: true,
                        may_write_output: operation.source.output.is_some(),
                    },
                );
                return Ok(result);
            };
            if operation.may_clobber_unlisted_state
                || matches!(
                    effect,
                    PcodeEffect::Opaque {
                        class: super::PcodeOpaqueClass::ControlTransfer
                            | super::PcodeOpaqueClass::UserOperation
                            | super::PcodeOpaqueClass::Unknown,
                        ..
                    }
                )
            {
                opaque_boundary(&mut result, &pending, site, operation, effect);
                return Ok(result);
            }
            let Some(output) = &operation.source.output else {
                continue;
            };
            let mut matched = Vec::new();
            for (pending_index, value) in pending.iter().enumerate() {
                if overlaps(output, value)? {
                    matched.push((pending_index, output == value));
                }
            }
            if matched.is_empty() {
                continue;
            }
            result.steps.push(PcodeSliceStep {
                site,
                source: operation.source.clone(),
                effect: effect.clone(),
            });
            let mut new_inputs = Vec::new();
            for (pending_index, exact) in matched.into_iter().rev() {
                let value = pending.remove(pending_index);
                if !exact {
                    record_boundary(
                        &mut result,
                        PcodeSliceBoundaryKind::PartialOverlap,
                        Some(value),
                        Some(site),
                    );
                } else if let PcodeEffect::Opaque {
                    may_read_memory, ..
                } = &effect
                {
                    record_boundary(
                        &mut result,
                        if *may_read_memory {
                            PcodeSliceBoundaryKind::MemoryRead
                        } else {
                            PcodeSliceBoundaryKind::OpaqueEffect
                        },
                        Some(value),
                        Some(site),
                    );
                } else {
                    new_inputs.extend(operation.source.inputs.iter().cloned());
                }
            }
            for input in &new_inputs {
                add_input(&mut result, &mut pending, input, site)?;
                if result.truncated {
                    break;
                }
            }
            if pending.is_empty() || result.truncated {
                return Ok(result);
            }
        }
        if pending.is_empty() {
            break;
        }
        // Unique-space temporaries are only meaningful within an instruction.
        for index in (0..pending.len()).rev() {
            if pending[index].space == "unique" {
                let value = pending.remove(index);
                record_boundary(
                    &mut result,
                    PcodeSliceBoundaryKind::TemporaryLifetime,
                    Some(value),
                    None,
                );
            }
        }
        if result.truncated {
            return Ok(result);
        }
        if pending.is_empty() {
            break;
        }
        match unique_fallthrough_predecessor(cfg, current) {
            Some(predecessor) if !visited.contains(&predecessor) => {
                current = predecessor;
                operation_end = cfg.state.instructions[current as usize].operations.len();
            }
            _ => {
                let no_incoming = !cfg
                    .edges
                    .iter()
                    .any(|edge| edge.target_node == Some(current));
                if current == 0
                    && cfg.flow_evidence_present
                    && cfg.state.instructions[0].address == cfg.state.entry
                    && no_incoming
                {
                    for value in pending.drain(..) {
                        record_boundary(
                            &mut result,
                            PcodeSliceBoundaryKind::EntryValue,
                            Some(value),
                            None,
                        );
                    }
                } else {
                    control_boundary(&mut result, &pending, None);
                }
                break;
            }
        }
    }
    Ok(result)
}

fn unique_fallthrough_predecessor(cfg: &PcodeCfgFunctionIr, current: u32) -> Option<u32> {
    if !cfg.flow_evidence_present || current == 0 {
        return None;
    }
    let incoming = cfg
        .edges
        .iter()
        .enumerate()
        .filter(|(_, edge)| edge.target_node == Some(current))
        .collect::<Vec<_>>();
    if incoming.len() != 1 {
        return None;
    }
    let (edge_index, edge) = incoming[0];
    if edge.evidence.kind != GhidraFlowKind::Fallthrough
        || edge.evidence.conditional
        || edge.evidence.computed
    {
        return None;
    }
    let predecessor = cfg.nodes.get(edge.source_node as usize)?;
    if predecessor.instruction_index != edge.source_node
        || predecessor.has_unresolved_control
        || predecessor.may_have_opaque_control_effect
        || !predecessor.outgoing_calls.is_empty()
        || predecessor.outgoing_edges.len() != 1
        || predecessor.outgoing_edges[0] as usize != edge_index
    {
        return None;
    }
    Some(edge.source_node)
}

fn add_input(
    result: &mut PcodeBackwardSlice,
    pending: &mut Vec<PcodeVarnode>,
    input: &PcodeVarnode,
    site: PcodeSliceSite,
) -> Result<(), String> {
    let boundary = match input.space.as_str() {
        "const" => Some(PcodeSliceBoundaryKind::Constant),
        "register" | "unique" => None,
        _ => Some(PcodeSliceBoundaryKind::ExternalSpace),
    };
    if let Some(kind) = boundary {
        record_boundary(result, kind, Some(input.clone()), Some(site));
    } else if !pending.contains(input) {
        if pending.len() >= MAX_PCODE_SLICE_PENDING_VALUES {
            budget_boundary(result, pending, Some(site));
        } else {
            pending.push(input.clone());
        }
    }
    Ok(())
}

fn overlaps(a: &PcodeVarnode, b: &PcodeVarnode) -> Result<bool, String> {
    if a.space != b.space {
        return Ok(false);
    }
    let a_start = hex_u64(&a.offset)?;
    let b_start = hex_u64(&b.offset)?;
    let a_end = a_start
        .checked_add(u64::from(a.size))
        .ok_or("P-code varnode range overflows")?;
    let b_end = b_start
        .checked_add(u64::from(b.size))
        .ok_or("P-code varnode range overflows")?;
    Ok(a_start < b_end && b_start < a_end)
}

fn opaque_boundary(
    result: &mut PcodeBackwardSlice,
    pending: &[PcodeVarnode],
    site: PcodeSliceSite,
    operation: &super::PcodeStateOperation,
    effect: PcodeEffect,
) {
    result.steps.push(PcodeSliceStep {
        site,
        source: operation.source.clone(),
        effect,
    });
    for value in pending {
        record_boundary(
            result,
            PcodeSliceBoundaryKind::OpaqueEffect,
            Some(value.clone()),
            Some(site),
        );
    }
}

fn control_boundary(
    result: &mut PcodeBackwardSlice,
    pending: &[PcodeVarnode],
    site: Option<PcodeSliceSite>,
) {
    for value in pending {
        record_boundary(
            result,
            PcodeSliceBoundaryKind::ControlFlow,
            Some(value.clone()),
            site,
        );
    }
}

fn budget_boundary(
    result: &mut PcodeBackwardSlice,
    pending: &[PcodeVarnode],
    site: Option<PcodeSliceSite>,
) {
    result.truncated = true;
    if result.boundaries.len() < MAX_PCODE_SLICE_BOUNDARIES {
        result.boundaries.push(PcodeSliceBoundary {
            kind: PcodeSliceBoundaryKind::Budget,
            varnode: pending.first().cloned(),
            site,
        });
    }
}

fn record_boundary(
    result: &mut PcodeBackwardSlice,
    kind: PcodeSliceBoundaryKind,
    varnode: Option<PcodeVarnode>,
    site: Option<PcodeSliceSite>,
) {
    if result.truncated {
        return;
    }
    if result.boundaries.len() >= MAX_PCODE_SLICE_BOUNDARIES - 1 {
        result.truncated = true;
        result.boundaries.push(PcodeSliceBoundary {
            kind: PcodeSliceBoundaryKind::Budget,
            varnode,
            site,
        });
    } else {
        result.boundaries.push(PcodeSliceBoundary {
            kind,
            varnode,
            site,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::parse_ghidra_snapshot;

    const DIGEST: &str = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";

    fn fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            )),
            DIGEST,
        )
        .unwrap()
    }

    fn copy_to_register(size: u32, offset: &str) -> super::super::PcodeStateOperation {
        let cfg = fixture().pcode_cfg_ir().unwrap();
        let mut operation = cfg.state.instructions[0].operations[2].clone();
        operation.source.mnemonic = "COPY".to_owned();
        operation.source.opcode = 1;
        operation.source.sequence_index = 0;
        operation.source.output = Some(PcodeVarnode {
            space: "register".to_owned(),
            offset: offset.to_owned(),
            size,
        });
        operation.source.inputs = vec![PcodeVarnode {
            space: "const".to_owned(),
            offset: "0x5".to_owned(),
            size,
        }];
        operation.effect = lower_operation(&operation.source);
        operation.may_clobber_unlisted_state = false;
        operation
    }

    #[test]
    fn follows_exact_unique_definitions_but_stops_at_opaque_value() {
        let slice = fixture()
            .backward_pcode_slice(PcodeSliceTarget {
                instruction_index: 0,
                operation_index: 8,
                input_index: Some(0),
            })
            .unwrap();
        assert_eq!(slice.steps[0].source.mnemonic, "INT_EQUAL");
        assert_eq!(slice.steps[1].source.mnemonic, "INT_AND");
        assert_eq!(slice.steps[2].source.mnemonic, "POPCOUNT");
        assert!(slice.boundaries.iter().any(|boundary| {
            boundary.kind == PcodeSliceBoundaryKind::OpaqueEffect
                && boundary
                    .varnode
                    .as_ref()
                    .is_some_and(|node| node.space == "unique")
        }));
        assert!(!slice.path_proven);
    }

    #[test]
    fn memory_load_is_a_boundary_with_source_provenance() {
        let slice = fixture()
            .backward_pcode_slice(PcodeSliceTarget {
                instruction_index: 3,
                operation_index: 2,
                input_index: Some(0),
            })
            .unwrap();
        assert_eq!(slice.steps[0].source.mnemonic, "RETURN");
        assert_eq!(slice.steps[1].source.mnemonic, "LOAD");
        assert_eq!(slice.steps[1].source.source_address.offset, "0x2013b6");
        assert!(
            slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::MemoryRead)
        );
    }

    #[test]
    fn call_predecessor_does_not_become_a_value_proof() {
        let slice = fixture()
            .backward_pcode_slice(PcodeSliceTarget {
                instruction_index: 2,
                operation_index: 0,
                input_index: Some(0),
            })
            .unwrap();
        assert!(
            slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::ControlFlow)
        );
        assert!(
            slice
                .steps
                .iter()
                .all(|step| step.site.instruction_index == 2)
        );
    }

    #[test]
    fn follows_one_unambiguous_fallthrough_without_claiming_path_proof() {
        let mut cfg = fixture().pcode_cfg_ir().unwrap();
        cfg.state.instructions[0].operations = vec![copy_to_register(8, "0x20")];
        cfg.nodes[0].may_have_opaque_control_effect = false;
        let slice = slice_cfg(
            &cfg,
            PcodeSliceTarget {
                instruction_index: 1,
                operation_index: 0,
                input_index: Some(0),
            },
        )
        .unwrap();
        assert_eq!(slice.steps.len(), 2);
        assert_eq!(slice.steps[1].site.instruction_index, 0);
        assert_eq!(slice.steps[1].source.mnemonic, "COPY");
        assert!(
            slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::Constant)
        );
        assert!(!slice.path_proven);
    }

    #[test]
    fn overlapping_register_write_is_unresolved() {
        let mut cfg = fixture().pcode_cfg_ir().unwrap();
        cfg.state.instructions[0].operations = vec![copy_to_register(4, "0x20")];
        cfg.nodes[0].may_have_opaque_control_effect = false;
        let slice = slice_cfg(
            &cfg,
            PcodeSliceTarget {
                instruction_index: 1,
                operation_index: 0,
                input_index: Some(0),
            },
        )
        .unwrap();
        assert!(
            slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::PartialOverlap)
        );
        assert!(
            !slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::Constant)
        );
    }

    #[test]
    fn operation_budget_is_explicit() {
        let mut cfg = fixture().pcode_cfg_ir().unwrap();
        let target = cfg.state.instructions[1].operations[0].clone();
        cfg.state.instructions[1].operations =
            vec![copy_to_register(8, "0x900"); MAX_PCODE_SLICE_OPERATIONS + 1];
        cfg.state.instructions[1].operations.push(target);
        let slice = slice_cfg(
            &cfg,
            PcodeSliceTarget {
                instruction_index: 1,
                operation_index: (MAX_PCODE_SLICE_OPERATIONS + 1) as u32,
                input_index: Some(0),
            },
        )
        .unwrap();
        assert_eq!(
            slice.operations_examined as usize,
            MAX_PCODE_SLICE_OPERATIONS
        );
        assert!(slice.truncated);
        assert!(
            slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::Budget)
        );
    }

    #[test]
    fn ambiguous_incoming_edges_stop_the_slice() {
        let mut cfg = fixture().pcode_cfg_ir().unwrap();
        let extra = cfg.edges[0].clone();
        cfg.edges.push(super::super::PcodeCfgEdge {
            target_node: Some(1),
            ..extra
        });
        let slice = slice_cfg(
            &cfg,
            PcodeSliceTarget {
                instruction_index: 1,
                operation_index: 0,
                input_index: Some(0),
            },
        )
        .unwrap();
        assert_eq!(slice.steps.len(), 1);
        assert!(
            slice
                .boundaries
                .iter()
                .any(|boundary| boundary.kind == PcodeSliceBoundaryKind::ControlFlow)
        );
    }

    #[test]
    fn rejects_out_of_range_input_index() {
        assert!(
            fixture()
                .backward_pcode_slice(PcodeSliceTarget {
                    instruction_index: 3,
                    operation_index: 2,
                    input_index: Some(9),
                })
                .is_err()
        );
    }
}
