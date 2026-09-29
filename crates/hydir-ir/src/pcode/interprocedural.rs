//! Bounded concrete paths across validated raw-P-code functions.
//! Each snapshot still represents one function. Calls are followed only when
//! the machine P-code target, Ghidra's call evidence, and a loaded callee agree.

use super::{
    GhidraFlowKind, GhidraSnapshot, MAX_OPERATIONS, PcodeAddress, PcodeConcreteState,
    PcodeElfProcessMemory, PcodeOperation, PcodePathEvent, PcodePathStop, PcodePathTrace,
    PcodeProcessAllocations, hex_u64, validate_ghidra_snapshot,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PCODE_CALL_PATH_VERSION: u32 = 2;
pub const PCODE_CALL_PATH_ALLOCATED_PROCESS_VERSION: u32 = 3;
const MAX_SNAPSHOTS: usize = 128;
const MAX_SEGMENTS: usize = 128;
const MAX_CALL_DEPTH: usize = 16;
const MISSING_CALLEE_REASON: &str = "CALL callee snapshot is unavailable";

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
#[serde(deny_unknown_fields)]
pub struct PcodeCallProcessBinding {
    /// Digest of the canonical, binary-bound process image including its
    /// initial bytes and masks. The allocation contract carries the ELF and
    /// snapshot-layout digests.
    pub process_memory_sha256: String,
    pub allocations: PcodeProcessAllocations,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_binding: Option<PcodeCallProcessBinding>,
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
    state: &PcodeConcreteState,
) -> Result<(PcodeAddress, PcodeAddress), String> {
    if !matches!(source.opcode, 7 | 8)
        || source.mnemonic
            != if source.opcode == 7 {
                "CALL"
            } else {
                "CALLIND"
            }
        || source.inputs.len() != 1
        || source.output.is_some()
    {
        return Err("only validated CALL or CALLIND P-code can enter a callee".to_owned());
    }
    let input = &source.inputs[0];
    let target_space = if source.opcode == 7 {
        input.space.as_str()
    } else {
        site.space.as_str()
    };
    let space = snapshot
        .address_spaces
        .iter()
        .find(|space| space.name == target_space)
        .ok_or("CALL target has an unknown address space")?;
    if input.size != space.pointer_size || !(1..=8).contains(&input.size) {
        return Err("CALL target width differs from its address space".to_owned());
    }
    let value = if source.opcode == 7 {
        hex_u64(&input.offset)?
    } else {
        state
            .read_varnode(input)?
            .ok_or("CALLIND target is unknown in concrete state")?
    };
    let target = PcodeAddress {
        space: space.name.clone(),
        offset: format!("0x{value:x}"),
    };
    let calls = snapshot
        .selected_function
        .call_targets
        .iter()
        .filter(|call| key(&call.call_site).ok() == key(site).ok())
        .collect::<Vec<_>>();
    let evidence_ok = if source.opcode == 7 {
        calls.len() == 1
            && !calls[0].conditional
            && !calls[0].computed
            && calls[0]
                .target
                .as_ref()
                .and_then(|evidence| key(evidence).ok())
                == Some(key(&target)?)
    } else {
        calls.len() == 1
            && calls[0].computed
            && !calls[0].conditional
            && (calls[0].target.is_none()
                || calls[0]
                    .target
                    .as_ref()
                    .and_then(|evidence| key(evidence).ok())
                    == Some(key(&target)?))
    };
    if !evidence_ok {
        return Err("CALL target disagrees with Ghidra call evidence".to_owned());
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
        return Err("CALL has no unique analyzed fallthrough".to_owned());
    }
    let continuation = continuations[0]
        .target
        .as_ref()
        .ok_or("CALL fallthrough target is unresolved")?;
    if !snapshot
        .selected_function
        .instructions
        .iter()
        .any(|instruction| key(&instruction.address).ok() == key(continuation).ok())
    {
        return Err("CALL fallthrough is outside its caller".to_owned());
    }
    Ok((target, continuation.clone()))
}

/// Return a missing, Ghidra-indexed callee only when the current concrete
/// trace stopped at a validated call. An unknown target or conflicting call
/// evidence never requests another Ghidra export.
pub fn unloaded_call_target(
    snapshots: &[GhidraSnapshot],
    trace: &PcodeInterproceduralTrace,
) -> Result<Option<PcodeAddress>, String> {
    let PcodeCallPathStop::CallBoundary { source, reason } = &trace.stop else {
        return Ok(None);
    };
    if reason != MISSING_CALLEE_REASON {
        return Ok(None);
    }
    let Some(segment) = trace.segments.last() else {
        return Ok(None);
    };
    if !matches!(&segment.path.stop, PcodePathStop::Call { source: path_source } if path_source == source)
    {
        return Ok(None);
    }
    let Some(snapshot) = snapshots
        .iter()
        .find(|snapshot| snapshot.selected_function.entry == segment.function_entry)
    else {
        return Ok(None);
    };
    let Some(site) = segment.path.instruction_visits.last() else {
        return Ok(None);
    };
    let Ok((target, _)) = call_target(snapshot, source, site, &trace.final_state) else {
        return Ok(None);
    };
    if snapshots
        .iter()
        .any(|snapshot| snapshot.selected_function.entry == target)
        || !snapshot
            .functions
            .iter()
            .any(|function| function.entry == target)
    {
        return Ok(None);
    }
    Ok(Some(target))
}

/// Follow direct and concretely resolved indirect calls in a
/// bounded set of snapshots. The first snapshot is the root. Unknown,
/// mismatched, or missing call evidence stops explicitly. Shared register and RAM state follows raw
/// P-code; no ABI clobbers or return values are invented.
pub fn execute_concrete_call_path(
    snapshots: &[GhidraSnapshot],
    initial_state: &PcodeConcreteState,
    max_operations: usize,
    max_instruction_visits: usize,
    max_call_depth: usize,
) -> Result<PcodeInterproceduralTrace, String> {
    execute_concrete_call_path_inner(
        snapshots,
        initial_state,
        None,
        None,
        max_operations,
        max_instruction_visits,
        max_call_depth,
    )
}

/// Follow calls with immutable, binary-bound ELF LOAD bytes available in all
/// selected functions. The existing call-path trace format is preserved.
pub fn execute_concrete_call_path_with_image(
    snapshots: &[GhidraSnapshot],
    initial_state: &PcodeConcreteState,
    image: &super::PcodeReadOnlyElfImage,
    max_operations: usize,
    max_instruction_visits: usize,
    max_call_depth: usize,
) -> Result<PcodeInterproceduralTrace, String> {
    execute_concrete_call_path_inner(
        snapshots,
        initial_state,
        Some(image),
        None,
        max_operations,
        max_instruction_visits,
        max_call_depth,
    )
}

/// Follow loaded, internal x86-64 ELF calls with one binary-bound process and
/// explicit stack/heap allocation contract shared across every call segment.
/// Raw P-code supplies the call and return effects; external effects are not
/// synthesized.
pub fn execute_concrete_call_path_with_allocations(
    snapshots: &[GhidraSnapshot],
    initial_state: &PcodeConcreteState,
    process: &PcodeElfProcessMemory,
    allocations: &PcodeProcessAllocations,
    max_operations: usize,
    max_instruction_visits: usize,
    max_call_depth: usize,
) -> Result<PcodeInterproceduralTrace, String> {
    execute_concrete_call_path_inner(
        snapshots,
        initial_state,
        None,
        Some((process, allocations)),
        max_operations,
        max_instruction_visits,
        max_call_depth,
    )
}

fn internal_process_target(
    snapshot: &GhidraSnapshot,
    process: &PcodeElfProcessMemory,
    target: &PcodeAddress,
) -> bool {
    if target.space != process.space() {
        return false;
    }
    let Ok(address) = hex_u64(&target.offset) else {
        return false;
    };
    process.is_mapped(&target.space, address)
        && process.initial_byte(&target.space, address).is_some()
        && snapshot.memory_blocks.iter().any(|block| {
            block.start.space == target.space
                && block.loaded
                && block.execute
                && !block.overlay
                && (block.name == ".text" || block.name.starts_with(".text."))
                && hex_u64(&block.start.offset).is_ok_and(|start| start <= address)
                && hex_u64(&block.end.offset).is_ok_and(|end| address <= end)
        })
}

fn execute_concrete_call_path_inner(
    snapshots: &[GhidraSnapshot],
    initial_state: &PcodeConcreteState,
    image: Option<&super::PcodeReadOnlyElfImage>,
    allocated: Option<(&PcodeElfProcessMemory, &PcodeProcessAllocations)>,
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
        if let Some((process, allocations)) = allocated {
            allocations.validate_for(snapshot, process)?;
        }
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
    let mut segments = Vec::new();
    let mut calls = Vec::new();
    let mut executed_operations = 0usize;
    let mut instruction_visits = 0usize;

    let stop = loop {
        if segments.len() >= MAX_SEGMENTS {
            break PcodeCallPathStop::SegmentBudget;
        }
        let snapshot = &snapshots[current];
        let remaining_operations = max_operations.saturating_sub(executed_operations);
        let remaining_visits = max_instruction_visits.saturating_sub(instruction_visits);
        let path = if let Some((process, allocations)) = allocated {
            snapshot.execute_concrete_path_with_allocations(
                &state,
                process,
                allocations,
                Some(&start),
                remaining_operations,
                remaining_visits,
            )?
        } else if let Some(image) = image {
            snapshot.execute_concrete_path_with_image(
                &state,
                image,
                Some(&start),
                remaining_operations,
                remaining_visits,
            )?
        } else {
            snapshot.execute_concrete_path(
                &state,
                Some(&start),
                remaining_operations,
                remaining_visits,
            )?
        };
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
                let (target, continuation) = match call_target(snapshot, &source, &site, &state) {
                    Ok(value) => value,
                    Err(reason) => break PcodeCallPathStop::CallBoundary { source, reason },
                };
                if let Some((process, _)) = allocated
                    && !internal_process_target(snapshot, process, &target)
                {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: "CALL target is not a loaded internal executable ELF function"
                            .to_owned(),
                    };
                }
                if frames.len() >= max_call_depth {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: "call depth budget exhausted".to_owned(),
                    };
                }
                let Some(&callee) = index.get(&key(&target)?) else {
                    break PcodeCallPathStop::CallBoundary {
                        source,
                        reason: MISSING_CALLEE_REASON.to_owned(),
                    };
                };
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
                current = frame.caller_index;
                start = frame.return_address;
            }
            stop => break PcodeCallPathStop::PathBoundary { stop },
        }
    };
    Ok(PcodeInterproceduralTrace {
        schema_version: if allocated.is_some() {
            PCODE_CALL_PATH_ALLOCATED_PROCESS_VERSION
        } else {
            PCODE_CALL_PATH_VERSION
        },
        binary_sha256: root.binary_sha256.clone(),
        process_binding: allocated
            .map(
                |(process, allocations)| -> Result<PcodeCallProcessBinding, String> {
                    Ok(PcodeCallProcessBinding {
                        process_memory_sha256: format!(
                            "{:x}",
                            Sha256::digest(
                                serde_json::to_vec(process).map_err(|error| error.to_string())?
                            )
                        ),
                        allocations: allocations.clone(),
                    })
                },
            )
            .transpose()?,
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
    use crate::pcode::{
        PcodeExecutionStop, PcodeMemoryBoundaryKind, PcodeProcessAllocation,
        PcodeProcessAllocationKind, PcodeVarnode, parse_ghidra_snapshot,
    };

    fn choose_snapshots() -> Vec<GhidraSnapshot> {
        let digest = "dc459793ce9edcc543c9ffcadbecc27c6a2e1976782f1da4d3adc2119dd27723";
        [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_choose_root_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_choose_right_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_choose_left_v2.json"
            ))
            .as_slice(),
        ]
        .into_iter()
        .map(|bytes| parse_ghidra_snapshot(bytes, digest).unwrap())
        .collect()
    }

    #[test]
    fn allocated_process_calls_share_stack_and_stop_before_crossing_store() {
        let snapshots = choose_snapshots();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_choose_calls.elf"
        ));
        let process = PcodeElfProcessMemory::from_elf(binary, &snapshots[0], 64 * 1024).unwrap();
        for (argument, expected, callee) in [(1, 2, "0x201185"), (0, 1, "0x20118d")] {
            let allocations = PcodeProcessAllocations::new(
                &snapshots[0],
                &process,
                vec![PcodeProcessAllocation {
                    kind: PcodeProcessAllocationKind::Stack,
                    space: "ram".into(),
                    base: 0x6ffff8,
                    byte_len: 16,
                }],
            )
            .unwrap();
            let mut input = PcodeConcreteState::default();
            input.write_varnode(&register("0x38"), argument).unwrap();
            input.write_varnode(&register("0x20"), 0x700000).unwrap();
            input.write_memory("ram", 0x700000, 8, 0x201195).unwrap();
            let trace = execute_concrete_call_path_with_allocations(
                &snapshots,
                &input,
                &process,
                &allocations,
                128,
                16,
                4,
            )
            .unwrap();
            assert_eq!(
                trace.schema_version,
                PCODE_CALL_PATH_ALLOCATED_PROCESS_VERSION
            );
            assert_eq!(
                trace.process_binding.as_ref().unwrap().allocations,
                allocations
            );
            assert!(matches!(trace.stop, PcodeCallPathStop::Return { .. }));
            assert_eq!(trace.calls.len(), 1);
            assert_eq!(trace.calls[0].callee_entry.offset, callee);
            assert_eq!(
                trace.final_state.read_varnode(&register("0x0")).unwrap(),
                Some(expected)
            );
            assert_eq!(
                trace.final_state.read_memory("ram", 0x6ffff8, 8).unwrap(),
                Some(if argument == 1 { 0x20117e } else { 0x201184 })
            );

            let narrow = PcodeProcessAllocations::new(
                &snapshots[0],
                &process,
                vec![PcodeProcessAllocation {
                    kind: PcodeProcessAllocationKind::Stack,
                    space: "ram".into(),
                    base: 0x6ffffc,
                    byte_len: 12,
                }],
            )
            .unwrap();
            let stopped = execute_concrete_call_path_with_allocations(
                &snapshots, &input, &process, &narrow, 128, 16, 4,
            )
            .unwrap();
            assert!(matches!(
                &stopped.stop,
                PcodeCallPathStop::PathBoundary {
                    stop: PcodePathStop::EffectBoundary {
                        boundary: PcodeExecutionStop::MemoryBoundary {
                            source,
                            reason: PcodeMemoryBoundaryKind::UnmappedWrite,
                            ..
                        }
                    }
                } if source.mnemonic == "STORE" && source.source_address == stopped.segments[0].path.instruction_visits.last().unwrap().clone()
            ));
            assert_eq!(stopped.calls.len(), 0);
            assert_eq!(
                stopped.final_state.read_memory("ram", 0x6ffff8, 8).unwrap(),
                None
            );
        }
    }

    #[test]
    fn allocated_process_call_stops_at_plt_without_external_effects() {
        let mut snapshots = choose_snapshots();
        for snapshot in &mut snapshots {
            snapshot
                .memory_blocks
                .iter_mut()
                .find(|block| block.name == ".text")
                .unwrap()
                .name = ".plt".into();
        }
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_choose_calls.elf"
        ));
        let process = PcodeElfProcessMemory::from_elf(binary, &snapshots[0], 64 * 1024).unwrap();
        let allocations = PcodeProcessAllocations::new(
            &snapshots[0],
            &process,
            vec![PcodeProcessAllocation {
                kind: PcodeProcessAllocationKind::Stack,
                space: "ram".into(),
                base: 0x6ffff8,
                byte_len: 16,
            }],
        )
        .unwrap();
        let mut input = PcodeConcreteState::default();
        input.write_varnode(&register("0x38"), 1).unwrap();
        input.write_varnode(&register("0x20"), 0x700000).unwrap();
        input.write_memory("ram", 0x700000, 8, 0x201195).unwrap();
        let trace = execute_concrete_call_path_with_allocations(
            &snapshots,
            &input,
            &process,
            &allocations,
            128,
            16,
            4,
        )
        .unwrap();
        assert!(matches!(
            trace.stop,
            PcodeCallPathStop::CallBoundary { ref source, ref reason }
                if source.source_address.offset == "0x201179" && reason.contains("internal executable")
        ));
        assert!(trace.calls.is_empty());
    }

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
            assert_eq!(trace.schema_version, PCODE_CALL_PATH_VERSION);
            assert!(trace.process_binding.is_none());
            assert!(
                !serde_json::to_string(&trace)
                    .unwrap()
                    .contains("process_binding")
            );
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

    #[test]
    fn real_computed_call_uses_concrete_target_and_matching_ghidra_evidence() {
        let digest = "9568944aec254be3cb78235667b0575d3104cd063101428abc4055dacb067582";
        let mut snapshots = [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_root_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_leaf_v2.json"
            ))
            .as_slice(),
        ]
        .into_iter()
        .map(|bytes| parse_ghidra_snapshot(bytes, digest).unwrap())
        .collect::<Vec<_>>();
        let seed = super::super::parse_pcode_seed(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_seed_v1.json"
            )),
            &snapshots[0],
        )
        .unwrap();
        let trace = execute_concrete_call_path(&snapshots, &seed, 128, 16, 4).unwrap();
        assert_eq!(trace.calls.len(), 1);
        assert_eq!(trace.calls[0].callee_entry.offset, "0x201174");
        assert_eq!(trace.calls[0].return_address.offset, "0x20117e");
        assert_eq!(trace.segments.len(), 3);
        assert!(matches!(trace.stop, PcodeCallPathStop::Return { .. }));
        assert_eq!(
            trace
                .final_state
                .read_varnode(&super::super::PcodeVarnode {
                    space: "register".to_owned(),
                    offset: "0x0".to_owned(),
                    size: 8,
                })
                .unwrap(),
            Some(7)
        );

        let missing = execute_concrete_call_path(&snapshots[..1], &seed, 128, 16, 4).unwrap();
        assert!(matches!(
            missing.stop,
            PcodeCallPathStop::CallBoundary { ref reason, .. } if reason.contains("unavailable")
        ));
        assert_eq!(
            unloaded_call_target(&snapshots[..1], &missing)
                .unwrap()
                .unwrap()
                .offset,
            "0x201174"
        );
        let depth = execute_concrete_call_path(&snapshots[..1], &seed, 128, 16, 0).unwrap();
        assert!(matches!(
            depth.stop,
            PcodeCallPathStop::CallBoundary { ref reason, .. } if reason.contains("depth")
        ));
        assert!(
            unloaded_call_target(&snapshots[..1], &depth)
                .unwrap()
                .is_none()
        );
        let mut unknown = PcodeConcreteState::default();
        unknown
            .write_varnode(
                &super::super::PcodeVarnode {
                    space: "register".to_owned(),
                    offset: "0x20".to_owned(),
                    size: 8,
                },
                0x700000,
            )
            .unwrap();
        unknown
            .write_memory("ram", 0x700000, 8, 0xdeadbeef)
            .unwrap();
        let unknown = execute_concrete_call_path(&snapshots, &unknown, 128, 16, 4).unwrap();
        assert!(matches!(
            unknown.stop,
            PcodeCallPathStop::PathBoundary {
                stop: super::super::PcodePathStop::EffectBoundary { .. }
            }
        ));
        assert!(unknown.calls.is_empty());
        assert!(
            unloaded_call_target(&snapshots, &unknown)
                .unwrap()
                .is_none()
        );
        snapshots[0].selected_function.call_targets[0].computed = false;
        let source = snapshots[0].selected_function.instructions[0]
            .pcode
            .iter()
            .find(|operation| operation.opcode == 8)
            .unwrap();
        assert!(
            call_target(
                &snapshots[0],
                source,
                &snapshots[0].selected_function.entry,
                &trace.segments[0].path.final_state,
            )
            .unwrap_err()
            .contains("disagrees")
        );
    }
}
