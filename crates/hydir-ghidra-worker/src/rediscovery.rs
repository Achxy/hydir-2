//! A bounded changed-address worklist from byte-verified runtime call targets.
//! It does not rewrite Ghidra flow evidence: a computed call stays unresolved
//! even when this trace supplies one or more candidate targets.

use super::{GHIDRA_VERSION, analysis_cache_key, validate_cached_snapshot};
use hydir_backend::extract_executable_window;
use hydir_execution::{DynamicTrace, InputSpec, TraceEventKind, validate_dynamic_trace};
use hydir_ir::pcode::{GhidraFlowKind, PcodeAddress};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const OBSERVED_CALL_REDISCOVERY_VERSION: u32 = 1;
const MAX_CHANGED_CALL_SITES: usize = 64;
const MAX_CHANGED_TARGETS: usize = 256;
const MAX_EVENT_SEQUENCES_PER_TARGET: usize = 8;

/// A trace-derived candidate for targeted Ghidra reanalysis. The source and
/// target witness bytes were both checked against executable ELF file bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedCallTarget {
    pub call_site: PcodeAddress,
    pub target: PcodeAddress,
    pub source_original_bytes_hex: String,
    pub target_original_bytes_hex: String,
    pub event_sequences: Vec<u64>,
    pub target_in_function_index: bool,
}

/// The cache key changes with the input, trace, snapshot, or worker analysis
/// identity. `unresolved_call_sites` is copied from the static snapshot; the
/// observation does not prove that its computed call target set is complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedCallRediscoveryPlan {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub input_sha256: String,
    pub ghidra_version: String,
    pub snapshot_sha256: String,
    pub trace_sha256: String,
    pub cache_key: String,
    pub selected_function: PcodeAddress,
    pub changed_targets: Vec<ObservedCallTarget>,
    pub omitted_targets: usize,
    pub unresolved_call_sites: Vec<PcodeAddress>,
    /// Static artifacts for these entries need regeneration if a candidate is
    /// applied. Callers outside the selected snapshot must be discovered then.
    pub invalidate_function_entries: Vec<PcodeAddress>,
}

fn address_offset(address: &PcodeAddress) -> Result<u64, String> {
    let hex = address
        .offset
        .strip_prefix("0x")
        .ok_or("Ghidra address is not 0x-prefixed")?;
    u64::from_str_radix(hex, 16).map_err(|_| "invalid Ghidra address offset".into())
}

fn ram_address(offset: u64) -> PcodeAddress {
    PcodeAddress {
        space: "ram".into(),
        offset: format!("0x{offset:x}"),
    }
}

/// Build a deterministic worklist for one selected Ghidra function. The trace
/// must name this exact snapshot and pass DynamicTrace's ELF byte and input
/// checks. Only Call events at unresolved computed call instructions qualify;
/// block-order adjacency and unnormalized runtime addresses are ignored.
pub fn plan_observed_calls(
    elf: &[u8],
    input: &InputSpec,
    trace: &DynamicTrace,
    snapshot_json: &[u8],
) -> Result<ObservedCallRediscoveryPlan, String> {
    validate_dynamic_trace(elf, input, trace)?;
    let snapshot = validate_cached_snapshot(
        snapshot_json,
        &trace.binary_sha256,
        Some(trace.selected_elf_vaddr),
    )?;
    // `observe frida --snapshot` binds the parsed, canonical serialization.
    // Ghidra's exported JSON may include a trailing newline, so hashing the
    // raw file would reject the trace produced by Hydir itself.
    let snapshot_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?)
    );
    if trace.ghidra_snapshot_sha256.as_deref() != Some(snapshot_sha256.as_str()) {
        return Err("DynamicTrace does not bind the selected Ghidra snapshot".into());
    }
    let entry = &snapshot.selected_function.entry;
    if entry.space != "ram" || address_offset(entry)? != trace.selected_elf_vaddr {
        return Err("selected function is not the traced ELF entry".into());
    }
    let instructions: BTreeMap<u64, (&str, usize)> = snapshot
        .selected_function
        .instructions
        .iter()
        .filter(|instruction| instruction.address.space == "ram")
        .map(|instruction| {
            address_offset(&instruction.address).map(|address| {
                (
                    address,
                    (instruction.parsed_bytes.as_str(), instruction.bytes.len()),
                )
            })
        })
        .collect::<Result<_, _>>()?;
    let unresolved: BTreeSet<u64> = snapshot
        .selected_function
        .call_targets
        .iter()
        .filter(|call| call.target.is_none() && call.computed && call.call_site.space == "ram")
        .map(|call| address_offset(&call.call_site))
        .collect::<Result<_, _>>()?;
    let indexed: BTreeSet<u64> = snapshot
        .functions
        .iter()
        .filter(|function| function.entry.space == "ram")
        .map(|function| address_offset(&function.entry))
        .collect::<Result<_, _>>()?;
    let static_targets: BTreeSet<(u64, u64)> = snapshot
        .selected_function
        .call_targets
        .iter()
        .filter_map(|call| {
            let target = call.target.as_ref()?;
            (call.call_site.space == "ram" && target.space == "ram")
                .then(|| (address_offset(&call.call_site), address_offset(target)))
        })
        .map(|(source, target)| Ok((source?, target?)))
        .collect::<Result<_, String>>()?;
    // Require a matching unresolved flow too. A call-target record alone does
    // not warrant changing the selected function's CFG.
    let unresolved_flow: BTreeSet<u64> = snapshot
        .selected_function
        .flow_edges
        .iter()
        .filter(|edge| {
            edge.kind == GhidraFlowKind::Call
                && edge.computed
                && edge.target.is_none()
                && edge.source.space == "ram"
        })
        .map(|edge| address_offset(&edge.source))
        .collect::<Result<_, _>>()?;

    let mut candidates = BTreeMap::<(u64, u64), ObservedCallTarget>::new();
    let mut verified_sources = BTreeMap::<u64, bool>::new();
    for event in &trace.events {
        if event.kind != TraceEventKind::Call {
            continue;
        }
        let (Some(source), Some(target)) = (
            event.source.elf_vaddr,
            event.target.as_ref().and_then(|target| target.elf_vaddr),
        ) else {
            continue;
        };
        let Some(&(parsed_bytes, instruction_bytes_length)) = instructions.get(&source) else {
            continue;
        };
        // The trace may witness only the first eight bytes of an instruction.
        // Keep Ghidra's complete instruction length and verify every parsed
        // byte against the file-backed ELF before passing it to the worklist.
        let source_bytes = event.source.original_bytes_hex.as_deref().unwrap();
        let common_length = parsed_bytes.len().min(source_bytes.len());
        if parsed_bytes.len() != instruction_bytes_length
            || parsed_bytes.len() > 32
            || !parsed_bytes[..common_length].eq_ignore_ascii_case(&source_bytes[..common_length])
            || !unresolved.contains(&source)
            || !unresolved_flow.contains(&source)
            || static_targets.contains(&(source, target))
        {
            continue;
        }
        let source_verified = verified_sources.entry(source).or_insert_with(|| {
            extract_executable_window(elf, source, parsed_bytes.len() / 2).is_ok_and(|bytes| {
                bytes.len() * 2 == parsed_bytes.len()
                    && bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                        .eq_ignore_ascii_case(parsed_bytes)
            })
        });
        if !*source_verified {
            continue;
        }
        let witness = event.target.as_ref().unwrap();
        let candidate = candidates
            .entry((source, target))
            .or_insert_with(|| ObservedCallTarget {
                call_site: ram_address(source),
                target: ram_address(target),
                source_original_bytes_hex: parsed_bytes.to_owned(),
                target_original_bytes_hex: witness.original_bytes_hex.clone().unwrap(),
                event_sequences: Vec::new(),
                target_in_function_index: indexed.contains(&target),
            });
        if candidate.event_sequences.len() < MAX_EVENT_SEQUENCES_PER_TARGET {
            candidate.event_sequences.push(event.sequence);
        }
    }
    let mut sites = BTreeSet::new();
    let mut changes = Vec::new();
    let mut omitted_targets = 0;
    for ((source, _), candidate) in candidates {
        if changes.len() == MAX_CHANGED_TARGETS
            || (!sites.contains(&source) && sites.len() == MAX_CHANGED_CALL_SITES)
        {
            omitted_targets += 1;
            continue;
        }
        sites.insert(source);
        changes.push(candidate);
    }
    let trace_sha256 = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(trace).map_err(|error| error.to_string())?)
    );
    let mut hash = Sha256::new();
    hash.update(b"hydir-observed-call-rediscovery-v1\0");
    hash.update(analysis_cache_key(
        &trace.binary_sha256,
        Some(trace.selected_elf_vaddr),
    ));
    hash.update(&snapshot_sha256);
    hash.update(&trace_sha256);
    let mut invalidate = BTreeSet::new();
    if !changes.is_empty() {
        invalidate.insert(trace.selected_elf_vaddr);
        for change in &changes {
            let target = address_offset(&change.target)?;
            if indexed.contains(&target) {
                invalidate.insert(target);
            }
        }
    }
    Ok(ObservedCallRediscoveryPlan {
        schema_version: OBSERVED_CALL_REDISCOVERY_VERSION,
        binary_sha256: trace.binary_sha256.clone(),
        input_sha256: trace.input_sha256.clone(),
        ghidra_version: GHIDRA_VERSION.into(),
        snapshot_sha256,
        trace_sha256,
        cache_key: format!("{:x}", hash.finalize()),
        selected_function: entry.clone(),
        changed_targets: changes,
        omitted_targets,
        unresolved_call_sites: unresolved.into_iter().map(ram_address).collect(),
        invalidate_function_entries: invalidate.into_iter().map(ram_address).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_execution::{
        DYNAMIC_TRACE_VERSION, INPUT_SPEC_VERSION, ReplayBudget, ReplayGoal, TraceBudget,
        TraceEvent, TraceStatus, TraceWitness, input_sha256,
    };
    use serde_json::json;

    const ELF: &[u8] = include_bytes!("../../../tests/fixtures/ghidra_indirect_call.elf");
    const SNAPSHOT: &[u8] = include_bytes!("../../../tests/fixtures/ghidra_indirect_root_v2.json");
    const CALL_SITE: u64 = 0x20117c;
    const LEAF: u64 = 0x201174;

    fn snapshot_digest(bytes: &[u8]) -> String {
        let snapshot: hydir_ir::pcode::GhidraSnapshot = serde_json::from_slice(bytes).unwrap();
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        )
    }

    fn witness(address: u64, bytes: &str) -> TraceWitness {
        TraceWitness {
            runtime_address: address,
            elf_vaddr: Some(address),
            original_bytes_hex: Some(bytes.into()),
        }
    }

    fn fixture() -> (InputSpec, DynamicTrace) {
        let binary_sha256 = format!("{:x}", Sha256::digest(ELF));
        let input = InputSpec {
            schema_version: INPUT_SPEC_VERSION,
            binary_sha256: binary_sha256.clone(),
            argv_hex: vec![],
            stdin_hex: String::new(),
            files: vec![],
            origins: vec![],
            goal: ReplayGoal {
                exit_code: Some(0),
                stdout_contains_hex: None,
                stderr_contains_hex: None,
            },
            budget: ReplayBudget {
                timeout_ms: 2000,
                memory_bytes: 1024 * 1024 * 1024,
                output_bytes: 1024,
            },
        };
        let entry = witness(CALL_SITE, "ffd0");
        let trace = DynamicTrace {
            schema_version: DYNAMIC_TRACE_VERSION,
            binary_sha256,
            input_sha256: input_sha256(&input).unwrap(),
            selected_elf_vaddr: CALL_SITE,
            ghidra_snapshot_sha256: Some(snapshot_digest(SNAPSHOT)),
            observer: "test".into(),
            frida_version: "17.9.5".into(),
            agent_sha256: format!("{:x}", Sha256::digest(b"test")),
            runtime_module_base: Some(0x200000),
            elf_load_bias: Some(0),
            budget: TraceBudget {
                max_events: 8,
                timeout_ms: 1000,
            },
            status: TraceStatus::Completed,
            lost_events: 0,
            stdout_hex: String::new(),
            stderr_hex: String::new(),
            diagnostics: vec![],
            jump_evidence: vec![],
            events: vec![
                TraceEvent {
                    sequence: 0,
                    thread_id: 1,
                    kind: TraceEventKind::Entry,
                    source: entry.clone(),
                    target: None,
                    registers: None,
                },
                TraceEvent {
                    sequence: 1,
                    thread_id: 1,
                    kind: TraceEventKind::Call,
                    source: entry.clone(),
                    target: Some(witness(LEAF, "48c7c007000000")),
                    registers: None,
                },
                TraceEvent {
                    sequence: 2,
                    thread_id: 1,
                    kind: TraceEventKind::Exit,
                    source: entry,
                    target: None,
                    registers: None,
                },
            ],
        };
        (input, trace)
    }

    fn bind_snapshot(trace: &mut DynamicTrace, snapshot: &[u8]) {
        trace.ghidra_snapshot_sha256 = Some(snapshot_digest(snapshot));
    }

    #[test]
    fn fixture_call_is_a_bounded_candidate_and_not_a_resolved_edge() {
        let (input, mut trace) = fixture();
        trace.events.insert(2, trace.events[1].clone());
        trace.events[2].sequence = 2;
        trace.events[3].sequence = 3;
        let plan = plan_observed_calls(ELF, &input, &trace, SNAPSHOT).unwrap();
        assert_eq!(plan.input_sha256, trace.input_sha256);
        assert_eq!(plan.changed_targets.len(), 1);
        assert_eq!(plan.changed_targets[0].call_site, ram_address(CALL_SITE));
        assert_eq!(plan.changed_targets[0].target, ram_address(LEAF));
        assert_eq!(plan.changed_targets[0].source_original_bytes_hex, "ffd0");
        assert_eq!(plan.changed_targets[0].event_sequences, vec![1, 2]);
        assert!(plan.changed_targets[0].target_in_function_index);
        assert_eq!(plan.unresolved_call_sites, vec![ram_address(CALL_SITE)]);
        assert_eq!(
            plan.invalidate_function_entries,
            vec![ram_address(LEAF), ram_address(CALL_SITE)]
        );
        assert_eq!(plan.omitted_targets, 0);
        assert_eq!(
            plan,
            plan_observed_calls(ELF, &input, &trace, SNAPSHOT).unwrap()
        );
    }

    #[test]
    fn repeated_witnesses_are_capped_and_unindexed_targets_stay_candidates() {
        let (input, mut trace) = fixture();
        let entry = trace.events.remove(0);
        let call = trace.events.remove(0);
        let exit = trace.events.remove(0);
        trace.events = vec![entry];
        for sequence in 1..=10 {
            let mut repeated = call.clone();
            repeated.sequence = sequence;
            trace.events.push(repeated);
        }
        let mut unindexed = call;
        unindexed.sequence = 11;
        unindexed.target = Some(witness(0x20117b, "c3"));
        trace.events.push(unindexed);
        let mut exit = exit;
        exit.sequence = 12;
        trace.events.push(exit);
        trace.budget.max_events = 16;

        let plan = plan_observed_calls(ELF, &input, &trace, SNAPSHOT).unwrap();
        assert_eq!(plan.changed_targets.len(), 2);
        assert_eq!(
            plan.changed_targets[0].event_sequences,
            (1..=8).collect::<Vec<_>>()
        );
        assert_eq!(plan.changed_targets[1].target, ram_address(0x20117b));
        assert!(!plan.changed_targets[1].target_in_function_index);
        assert_eq!(plan.invalidate_function_entries.len(), 2);
    }

    #[test]
    fn missing_flow_and_known_static_target_do_not_become_changes() {
        let (input, mut trace) = fixture();
        let mut snapshot: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        snapshot["selected_function"]["flow_edges"] = json!([]);
        let without_flow = serde_json::to_vec(&snapshot).unwrap();
        bind_snapshot(&mut trace, &without_flow);
        let plan = plan_observed_calls(ELF, &input, &trace, &without_flow).unwrap();
        assert!(plan.changed_targets.is_empty());
        assert_eq!(plan.unresolved_call_sites, vec![ram_address(CALL_SITE)]);

        snapshot["selected_function"]["flow_edges"] = json!([
            {"source": ram_address(CALL_SITE), "target": null, "kind": "call", "conditional": false, "computed": true},
            {"source": ram_address(CALL_SITE), "target": ram_address(LEAF), "kind": "call", "conditional": false, "computed": true}
        ]);
        snapshot["selected_function"]["call_targets"]
            .as_array_mut()
            .unwrap()
            .push(json!({
                "call_site": ram_address(CALL_SITE), "target": ram_address(LEAF),
                "conditional": false, "computed": true
            }));
        let known_target = serde_json::to_vec(&snapshot).unwrap();
        bind_snapshot(&mut trace, &known_target);
        let plan = plan_observed_calls(ELF, &input, &trace, &known_target).unwrap();
        assert!(plan.changed_targets.is_empty());
        assert!(plan.invalidate_function_entries.is_empty());
    }

    #[test]
    fn snapshot_binding_and_verified_bytes_are_required() {
        let (input, mut trace) = fixture();
        trace.ghidra_snapshot_sha256 = None;
        assert!(plan_observed_calls(ELF, &input, &trace, SNAPSHOT).is_err());
        bind_snapshot(&mut trace, SNAPSHOT);
        trace.events[1].target.as_mut().unwrap().original_bytes_hex = Some("9090".into());
        assert!(plan_observed_calls(ELF, &input, &trace, SNAPSHOT).is_err());
        trace.events[1].target.as_mut().unwrap().original_bytes_hex = Some("48c7c007000000".into());

        let mut snapshot: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();
        snapshot["selected_function"]["instructions"][0]["parsed_bytes"] = json!("9090");
        let mismatched = serde_json::to_vec(&snapshot).unwrap();
        bind_snapshot(&mut trace, &mismatched);
        assert!(
            plan_observed_calls(ELF, &input, &trace, &mismatched)
                .unwrap()
                .changed_targets
                .is_empty()
        );
    }

    #[test]
    fn short_trace_witness_emits_the_complete_elf_verified_instruction() {
        let (input, mut trace) = fixture();
        trace.events[1].source.original_bytes_hex = Some("ff".into());
        let plan = plan_observed_calls(ELF, &input, &trace, SNAPSHOT).unwrap();
        assert_eq!(plan.changed_targets.len(), 1);
        assert_eq!(plan.changed_targets[0].source_original_bytes_hex, "ffd0");
    }

    #[test]
    fn instruction_length_and_unwitnessed_tail_must_match_elf() {
        let (input, mut trace) = fixture();
        trace.events[1].source.original_bytes_hex = Some("ff".into());
        let mut snapshot: serde_json::Value = serde_json::from_slice(SNAPSHOT).unwrap();

        snapshot["selected_function"]["instructions"][0]["parsed_bytes"] = json!("ff");
        let shortened = serde_json::to_vec(&snapshot).unwrap();
        bind_snapshot(&mut trace, &shortened);
        assert!(
            plan_observed_calls(ELF, &input, &trace, &shortened)
                .unwrap()
                .changed_targets
                .is_empty()
        );

        snapshot["selected_function"]["instructions"][0]["parsed_bytes"] = json!("ff90");
        snapshot["selected_function"]["instructions"][0]["bytes"] = json!("ff90");
        let wrong_tail = serde_json::to_vec(&snapshot).unwrap();
        bind_snapshot(&mut trace, &wrong_tail);
        assert!(
            plan_observed_calls(ELF, &input, &trace, &wrong_tail)
                .unwrap()
                .changed_targets
                .is_empty()
        );

        snapshot["selected_function"]["instructions"][0]["parsed_bytes"] =
            json!("ffd090909090909090");
        snapshot["selected_function"]["instructions"][0]["bytes"] = json!("ffd090909090909090");
        let long_tail = serde_json::to_vec(&snapshot).unwrap();
        bind_snapshot(&mut trace, &long_tail);
        assert!(
            plan_observed_calls(ELF, &input, &trace, &long_tail)
                .unwrap()
                .changed_targets
                .is_empty()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires HYDIR_GHIDRA_HOME pointing to the pinned Ghidra 12.1.4 installation"]
    fn headless_rediscovery_preserves_unresolved_call() {
        assert!(
            std::env::var_os("HYDIR_GHIDRA_HOME").is_some(),
            "set HYDIR_GHIDRA_HOME to the Ghidra 12.1.4 directory"
        );
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/ghidra_indirect_call.elf");
        let scratch = tempfile::tempdir().unwrap();
        let output = scratch.path().join("static-snapshot.json");
        super::super::analyze(&binary, Some(CALL_SITE), &output).unwrap();
        let static_json = std::fs::read(&output).unwrap();
        let (input, mut trace) = fixture();
        bind_snapshot(&mut trace, &static_json);
        let plan = plan_observed_calls(ELF, &input, &trace, &static_json).unwrap();
        assert_eq!(plan.changed_targets.len(), 1);

        let updated =
            super::super::reanalyze_observed_calls(&binary, &input, &trace, &static_json).unwrap();
        let calls = &updated.selected_function.call_targets;
        assert!(calls.iter().any(|call| {
            call.call_site == ram_address(CALL_SITE) && call.computed && call.target.is_none()
        }));
        assert!(calls.iter().any(|call| {
            call.call_site == ram_address(CALL_SITE)
                && call.computed
                && call.target == Some(ram_address(LEAF))
        }));
        assert!(updated.selected_function.flow_edges.iter().any(|edge| {
            edge.source == ram_address(CALL_SITE)
                && edge.kind == GhidraFlowKind::Call
                && edge.computed
                && edge.target.is_none()
        }));
        assert_eq!(std::fs::read(&output).unwrap(), static_json);
    }
}
