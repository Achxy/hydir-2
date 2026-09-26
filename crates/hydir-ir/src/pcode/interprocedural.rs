//! Bounded concrete paths across validated, directly called raw-P-code functions.
//! Each snapshot still represents one function. Calls are followed only when
//! the machine P-code target, Ghidra's call evidence, and a loaded callee agree.

use super::{
    GhidraFlowKind, GhidraSnapshot, MAX_OPERATIONS, PcodeAddress, PcodeConcreteState,
    PcodeOperation, PcodePathEvent, PcodePathStop, PcodePathTrace, hex_u64,
    validate_ghidra_snapshot,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const PCODE_CALL_PATH_VERSION: u32 = 1;
const MAX_SNAPSHOTS: usize = 128;
const MAX_SEGMENTS: usize = 128;
const MAX_CALL_DEPTH: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCallPathSegment {
    pub function_entry: PcodeAddress,
    pub snapshot_sha256: String,
    pub path: PcodePathTrace,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCallTransition {
    pub caller_entry: PcodeAddress,
    pub callee_entry: PcodeAddress,
    pub call_site: PcodeAddress,
    pub return_address: PcodeAddress,
    pub depth: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PcodeCallPathStop {
    Return {
        source: PcodeOperation,
    },
    CallBoundary {
        source: PcodeOperation,
        reason: String,
    },
    ReturnBoundary {
        source: PcodeOperation,
        reason: String,
    },
    PathBoundary {
        stop: PcodePathStop,
    },
    SegmentBudget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeInterproceduralTrace {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub root_entry: PcodeAddress,
    pub segments: Vec<PcodeCallPathSegment>,
    pub calls: Vec<PcodeCallTransition>,
    /// Worker collection failures can be attached by an orchestrator without
    /// turning a missing callee into an invented call effect.
    pub snapshot_diagnostics: Vec<String>,
    pub executed_operations: usize,
    pub instruction_visits: usize,
    pub final_state: PcodeConcreteState,
    pub stop: PcodeCallPathStop,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

#[derive(Clone)]
struct Frame {
    caller_index: usize,
    return_address: PcodeAddress,
}

fn key(address: &PcodeAddress) -> Result<(String, u64), String> {
    Ok((address.space.clone(), hex_u64(&address.offset)?))
}

fn call_target(
    snapshot: &GhidraSnapshot,
    source: &PcodeOperation,
    site: &PcodeAddress,
) -> Result<(PcodeAddress, PcodeAddress), String> {
    if source.opcode != 7 || source.mnemonic != "CALL" || source.inputs.len() != 1 {
        return Err("only direct CALL P-code can enter a callee".to_owned());
    }
    let input = &source.inputs[0];
    let space = snapshot
        .address_spaces
        .iter()
        .find(|space| space.name == input.space)
        .ok_or("direct CALL target has an unknown address space")?;
    if input.size != space.pointer_size || !(1..=8).contains(&input.size) {
        return Err("direct CALL target width differs from its address space".to_owned());
    }
    let target = PcodeAddress {
        space: input.space.clone(),
        offset: format!("0x{:x}", hex_u64(&input.offset)?),
    };
    let calls = snapshot
        .selected_function
        .call_targets
        .iter()
        .filter(|call| key(&call.call_site).ok() == key(site).ok())
        .collect::<Vec<_>>();
    if calls.len() != 1
        || calls[0].conditional
        || calls[0].computed
        || calls[0]
            .target
            .as_ref()
            .and_then(|evidence| key(evidence).ok())
            != Some(key(&target)?)
    {
        return Err(
            "direct CALL target disagrees with unique unconditional Ghidra call evidence"
                .to_owned(),
        );
    }
    let continuations = snapshot
        .selected_function
        .flow_edges
        .iter()
        .filter(|edge| {
            edge.kind == GhidraFlowKind::Fallthrough && key(&edge.source).ok() == key(site).ok()
        })
        .collect::<Vec<_>>();
    if continuations.len() != 1 {
        return Err("direct CALL has no unique analyzed fallthrough".to_owned());
    }
    let continuation = continuations[0]
        .target
        .as_ref()
        .ok_or("direct CALL fallthrough target is unresolved")?;
    if !snapshot
        .selected_function
        .instructions
        .iter()
        .any(|instruction| key(&instruction.address).ok() == key(continuation).ok())
    {
        return Err("direct CALL fallthrough is outside its caller".to_owned());
    }
    Ok((target, continuation.clone()))
}

/// Follow direct, nonrecursive calls in one bounded set of snapshots.
/// The first snapshot is the root. Unknown, indirect, mismatched, or missing
/// call evidence stops explicitly. Shared register and RAM state follows raw
/// P-code; no ABI clobbers or return values are invented.
pub fn execute_concrete_call_path(
    snapshots: &[GhidraSnapshot],
    initial_state: &PcodeConcreteState,
    max_operations: usize,
    max_instruction_visits: usize,
    max_call_depth: usize,
) -> Result<PcodeInterproceduralTrace, String> {
    let root = snapshots
        .first()
        .ok_or("call path requires a root snapshot")?;
    if snapshots.len() > MAX_SNAPSHOTS {
        return Err("call path snapshot limit exceeded".to_owned());
    }
    if max_operations > MAX_OPERATIONS
        || max_instruction_visits > MAX_OPERATIONS
        || max_call_depth > MAX_CALL_DEPTH
    {
        return Err("call path budget exceeds artifact limit".to_owned());
    }
    let mut index = BTreeMap::new();
    let mut digests = Vec::with_capacity(snapshots.len());
    for (number, snapshot) in snapshots.iter().enumerate() {
        validate_ghidra_snapshot(snapshot, &root.binary_sha256)?;
        if snapshot.program != root.program
            || snapshot.address_spaces != root.address_spaces
            || snapshot.functions != root.functions
            || snapshot.flow_overrides_applied != root.flow_overrides_applied
        {
            return Err("call path snapshots disagree on analyzed program identity".to_owned());
        }
        if index
            .insert(key(&snapshot.selected_function.entry)?, number)
            .is_some()
        {
            return Err("call path has duplicate selected function entries".to_owned());
        }
        let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
        digests.push(format!("{:x}", Sha256::digest(bytes)));
    }

    let mut current = 0usize;
    let mut start = root.selected_function.entry.clone();
    let mut state = initial_state.clone();
    let mut frames = Vec::<Frame>::new();
    let mut active_entries = BTreeSet::new();
    active_entries.insert(key(&start)?);
    let mut segments = Vec::new();
    let mut calls = Vec::new();
    let mut executed_operations = 0usize;
    let mut instruction_visits = 0usize;

    let stop = loop {
        if segments.len() >= MAX_SEGMENTS {
            break PcodeCallPathStop::SegmentBudget;
        }
        let snapshot = &snapshots[current];
        let path = snapshot.execute_concrete_path(
            &state,
            Some(&start),
            max_operations.saturating_sub(executed_operations),
            max_instruction_visits.saturating_sub(instruction_visits),
        )?;
        let events = path
            .events
            .iter()
            .filter(|event| !matches!(event, PcodePathEvent::Fallthrough { .. }))
            .count();
        let terminal = usize::from(matches!(
            path.stop,
            PcodePathStop::Call { .. } | PcodePathStop::Return { .. }
        ));
        executed_operations = executed_operations.saturating_add(events + terminal);
        instruction_visits = instruction_visits.saturating_add(path.instruction_visits.len());
        state = path.final_state.clone();
        let stop = path.stop.clone();
        let site = path.instruction_visits.last().cloned();
        segments.push(PcodeCallPathSegment {
            function_entry: snapshot.selected_function.entry.clone(),
            snapshot_sha256: digests[current].clone(),
            path,
        });
        match stop {
            PcodePathStop::Call { source } => {
                let Some(site) = site else {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: "CALL instruction was not visited".to_owned(),
                    };
                };
                let (target, continuation) = match call_target(snapshot, &source, &site) {
                    Ok(value) => value,
                    Err(reason) => break PcodeCallPathStop::CallBoundary { source, reason },
                };
                let Some(&callee) = index.get(&key(&target)?) else {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: "direct CALL callee snapshot is unavailable".to_owned(),
                    };
                };
                if frames.len() >= max_call_depth {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: "call depth budget exhausted".to_owned(),
                    };
                }
                if !active_entries.insert(key(&target)?) {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: "recursive call requires a separate bounded model".to_owned(),
                    };
                }
                calls.push(PcodeCallTransition {
                    caller_entry: snapshot.selected_function.entry.clone(),
                    callee_entry: target.clone(),
                    call_site: site,
                    return_address: continuation.clone(),
                    depth: frames.len() + 1,
                });
                frames.push(Frame {
                    caller_index: current,
                    return_address: continuation,
                });
                current = callee;
                start = target;
            }
            PcodePathStop::Return { source } => {
                let Some(frame) = frames.pop() else {
                    break PcodeCallPathStop::Return { source };
                };
                let Some(pointer) = source.inputs.first() else {
                    break PcodeCallPathStop::ReturnBoundary {
                        source,
                        reason: "RETURN has no target varnode".to_owned(),
                    };
                };
                let actual = match state.read_varnode(pointer) {
                    Ok(Some(value)) => value,
                    Ok(None) => {
                        break PcodeCallPathStop::ReturnBoundary {
                            source,
                            reason: "callee RETURN target is unknown".to_owned(),
                        };
                    }
                    Err(reason) => break PcodeCallPathStop::ReturnBoundary { source, reason },
                };
                if pointer.size
                    != snapshot
                        .address_spaces
                        .iter()
                        .find(|space| space.name == frame.return_address.space)
                        .map(|space| space.pointer_size)
                        .unwrap_or(0)
                    || actual != hex_u64(&frame.return_address.offset)?
                {
                    break PcodeCallPathStop::ReturnBoundary {
                        source,
                        reason: "callee RETURN target differs from analyzed caller continuation"
                            .to_owned(),
                    };
                }
                active_entries.remove(&key(&snapshot.selected_function.entry)?);
                current = frame.caller_index;
                start = frame.return_address;
            }
            stop => break PcodeCallPathStop::PathBoundary { stop },
        }
    };
    Ok(PcodeInterproceduralTrace {
        schema_version: PCODE_CALL_PATH_VERSION,
        binary_sha256: root.binary_sha256.clone(),
        root_entry: root.selected_function.entry.clone(),
        segments,
        calls,
        snapshot_diagnostics: Vec::new(),
        executed_operations,
        instruction_visits,
        final_state: state,
        stop,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{PcodeVarnode, parse_ghidra_snapshot};

    fn snapshots() -> Vec<GhidraSnapshot> {
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_leaf_add_v2.json"
            ))
            .as_slice(),
        ]
        .into_iter()
        .map(|bytes| parse_ghidra_snapshot(bytes, digest).unwrap())
        .collect()
    }

    fn register(offset: &str) -> PcodeVarnode {
        PcodeVarnode {
            space: "register".to_owned(),
            offset: offset.to_owned(),
            size: 8,
        }
    }

    fn seed(a: u64, b: u64) -> PcodeConcreteState {
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x38"), a).unwrap();
        seed.write_varnode(&register("0x30"), b).unwrap();
        seed.write_varnode(&register("0x20"), 0x700000).unwrap();
        seed.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
        seed
    }

    #[test]
    fn real_prism_direct_call_enters_leaf_and_resumes_caller() {
        let snapshots = snapshots();
        for (a, b) in [(0, 0), (7, 5), (u64::MAX, 1)] {
            let trace = execute_concrete_call_path(&snapshots, &seed(a, b), 128, 16, 4).unwrap();
            assert_eq!(trace.calls.len(), 1);
            assert_eq!(trace.calls[0].call_site.offset, "0x2013ad");
            assert_eq!(trace.calls[0].callee_entry.offset, "0x2013a2");
            assert_eq!(trace.calls[0].return_address.offset, "0x2013b2");
            assert_eq!(trace.segments.len(), 3);
            assert!(matches!(
                trace.segments[0].path.stop,
                PcodePathStop::Call { .. }
            ));
            assert!(matches!(
                trace.segments[1].path.stop,
                PcodePathStop::Return { .. }
            ));
            assert!(matches!(
                trace.segments[2].path.stop,
                PcodePathStop::Return { .. }
            ));
            assert!(matches!(trace.stop, PcodeCallPathStop::Return { .. }));
            assert_eq!(
                trace.final_state.read_varnode(&register("0x0")).unwrap(),
                Some(a.wrapping_add(b))
            );
            assert_eq!(
                trace.final_state.read_varnode(&register("0x20")).unwrap(),
                Some(0x700008)
            );
            assert_eq!(trace.verification, VerificationStatus::NotRun);
            assert_eq!(trace.semantic_fidelity, SemanticFidelity::Unknown);
        }
    }

    #[test]
    fn missing_callee_and_wrong_return_target_remain_explicit() {
        let snapshots = snapshots();
        let input = seed(7, 5);
        let missing = execute_concrete_call_path(&snapshots[..1], &input, 128, 16, 4).unwrap();
        assert!(
            matches!(missing.stop, PcodeCallPathStop::CallBoundary { ref reason, .. }
            if reason.contains("unavailable"))
        );
        assert_eq!(missing.segments.len(), 1);

        let mut wrong = snapshots;
        let call = &mut wrong[0].selected_function.instructions[1].pcode[1];
        assert_eq!(call.mnemonic, "STORE");
        call.inputs[2].offset = "0x2013b3".to_owned();
        let mismatch = execute_concrete_call_path(&wrong, &input, 128, 16, 4).unwrap();
        assert!(
            matches!(mismatch.stop, PcodeCallPathStop::ReturnBoundary { ref reason, .. }
            if reason.contains("differs"))
        );
        assert_eq!(mismatch.segments.len(), 2);
    }

    #[test]
    fn rejects_mixed_analysis_and_respects_global_depth_and_visit_budgets() {
        let snapshots = snapshots();
        let input = seed(7, 5);
        let depth = execute_concrete_call_path(&snapshots, &input, 128, 16, 0).unwrap();
        assert!(
            matches!(depth.stop, PcodeCallPathStop::CallBoundary { ref reason, .. }
            if reason.contains("depth"))
        );
        let visits = execute_concrete_call_path(&snapshots, &input, 128, 2, 4).unwrap();
        assert!(matches!(
            visits.stop,
            PcodeCallPathStop::PathBoundary {
                stop: PcodePathStop::VisitBudget { .. }
            }
        ));
        let mut mixed = snapshots;
        mixed[1].program.name = "another-analysis".to_owned();
        assert!(
            execute_concrete_call_path(&mixed, &input, 128, 16, 4)
                .unwrap_err()
                .contains("disagree")
        );
    }
}
