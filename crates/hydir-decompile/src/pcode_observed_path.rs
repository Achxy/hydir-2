//! Compare one observed function invocation with one bounded P-code path.
//! This is path evidence only; it says nothing about state equivalence or CFG coverage.

use hydir_execution::{
    DynamicTrace, InputSpec, TraceEventKind, TraceStatus, validate_dynamic_trace,
};
use hydir_ir::pcode::{
    GhidraSnapshot, PCODE_PATH_TRACE_VERSION, PcodeAddress, PcodeInstruction, PcodeOperation,
    PcodePathDestination, PcodePathEvent, PcodePathStop, PcodePathTrace, validate_ghidra_snapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PCODE_OBSERVED_PATH_COMPARISON_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedPathVerdict {
    /// The supplied path and observed events disagree. This is not a lifter
    /// correctness verdict because the path's initial state is unbound.
    Diverged,
    MatchedObservedPath,
    Inconclusive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedPathDifferenceKind {
    Block,
    Call,
    CallTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstObservedPathDifference {
    pub kind: ObservedPathDifferenceKind,
    /// Source instruction in the selected P-code function.
    pub source: PcodeAddress,
    pub observed_event_index: Option<usize>,
    pub expected: Option<PcodeAddress>,
    pub observed: Option<PcodeAddress>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeObservedPathComparison {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_entry: PcodeAddress,
    pub verdict: ObservedPathVerdict,
    pub first_difference: Option<FirstObservedPathDifference>,
    pub inconclusive_reasons: Vec<String>,
    pub compared_blocks: usize,
    pub compared_calls: usize,
    /// The v2 path trace does not carry an authenticated seed or input binding.
    #[serde(default)]
    pub same_initial_state_proven: bool,
}

fn address(value: &PcodeAddress) -> Result<u64, String> {
    if value.space != "ram" {
        return Err("observed path needs RAM P-code addresses".into());
    }
    offset(&value.offset)
}

fn offset(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or("P-code address lacks 0x prefix")?;
    u64::from_str_radix(digits, 16).map_err(|_| "invalid P-code address".into())
}

fn normalized(value: u64) -> PcodeAddress {
    PcodeAddress {
        space: "ram".into(),
        offset: format!("0x{value:x}"),
    }
}

fn operation_on_instruction(operation: &PcodeOperation, instruction: &PcodeInstruction) -> bool {
    instruction.pcode.get(operation.sequence_index as usize) == Some(operation)
}

fn result(
    trace: &DynamicTrace,
    entry: &PcodeAddress,
    verdict: ObservedPathVerdict,
    first_difference: Option<FirstObservedPathDifference>,
    inconclusive_reasons: Vec<String>,
    compared_blocks: usize,
    compared_calls: usize,
) -> PcodeObservedPathComparison {
    PcodeObservedPathComparison {
        schema_version: PCODE_OBSERVED_PATH_COMPARISON_VERSION,
        binary_sha256: trace.binary_sha256.clone(),
        function_entry: entry.clone(),
        verdict,
        first_difference,
        inconclusive_reasons,
        compared_blocks,
        compared_calls,
        same_initial_state_proven: false,
    }
}

fn inconclusive(
    trace: &DynamicTrace,
    entry: &PcodeAddress,
    reason: &str,
) -> PcodeObservedPathComparison {
    result(
        trace,
        entry,
        ObservedPathVerdict::Inconclusive,
        None,
        vec![reason.into()],
        0,
        0,
    )
}

fn difference(
    trace: &DynamicTrace,
    entry: &PcodeAddress,
    kind: ObservedPathDifferenceKind,
    source: PcodeAddress,
    observed_event_index: Option<usize>,
    expected: Option<PcodeAddress>,
    observed: Option<PcodeAddress>,
    compared_blocks: usize,
    compared_calls: usize,
) -> PcodeObservedPathComparison {
    result(
        trace,
        entry,
        ObservedPathVerdict::Diverged,
        Some(FirstObservedPathDifference {
            kind,
            source,
            observed_event_index,
            expected,
            observed,
        }),
        vec![],
        compared_blocks,
        compared_calls,
    )
}

/// Compare only normalized blocks and calls from one completed invocation.
/// The ELF and InputSpec validate the observation; the snapshot identifies
/// selected instructions and binds P-code source sites to that function.
pub fn compare_pcode_observed_path(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &GhidraSnapshot,
    trace: &DynamicTrace,
    path: &PcodePathTrace,
) -> Result<PcodeObservedPathComparison, String> {
    validate_dynamic_trace(elf, input, trace)?;
    validate_ghidra_snapshot(snapshot, &input.binary_sha256)?;
    let entry = &snapshot.selected_function.entry;
    if trace.selected_elf_vaddr != address(entry)?
        || path.schema_version != PCODE_PATH_TRACE_VERSION
        || path.binary_sha256 != trace.binary_sha256
        || address(&path.start)? != address(entry)?
        || snapshot.binary_sha256 != trace.binary_sha256
    {
        return Err(
            "P-code path and observation do not identify the same binary and function".into(),
        );
    }
    if let Some(digest) = &trace.ghidra_snapshot_sha256 {
        let actual = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(snapshot).map_err(|error| error.to_string())?)
        );
        if digest != &actual {
            return Err("observation is bound to a different Ghidra snapshot".into());
        }
    }
    let mut selected = BTreeMap::new();
    for instruction in &snapshot.selected_function.instructions {
        selected.insert(address(&instruction.address)?, instruction);
    }
    if path.instruction_visits.first().map(address).transpose()? != Some(address(entry)?) {
        return Err("P-code path does not visit its selected entry first".into());
    }
    let mut visit_numbers = Vec::with_capacity(path.instruction_visits.len());
    for visit in &path.instruction_visits {
        let value = address(visit)?;
        if !selected.contains_key(&value) {
            return Err("P-code path visits an instruction outside the selected function".into());
        }
        visit_numbers.push(value);
    }
    for event in &path.events {
        match event {
            PcodePathEvent::Effect { .. } => {}
            PcodePathEvent::Branch {
                source,
                destination,
                ..
            } => {
                let target_selected = match destination {
                    PcodePathDestination::Instruction { address: target } => {
                        selected.contains_key(&address(target)?)
                    }
                    _ => true,
                };
                if !matches!(source.opcode, 4..=6) || !target_selected {
                    return Err("P-code branch lacks a selected source operation".into());
                }
            }
            PcodePathEvent::Fallthrough { source, target } => {
                if !selected.contains_key(&address(source)?)
                    || !selected.contains_key(&address(target)?)
                {
                    return Err("P-code fallthrough leaves the selected function".into());
                }
            }
        }
    }
    let stop_instruction = selected
        .get(visit_numbers.last().expect("nonempty path"))
        .expect("visited instruction is selected");
    let call = match &path.stop {
        PcodePathStop::Call { source } => {
            if !matches!(source.opcode, 7 | 8)
                || !operation_on_instruction(source, stop_instruction)
            {
                return Err("P-code call lacks a selected source operation".into());
            }
            Some(source)
        }
        PcodePathStop::Return { source } => {
            if source.opcode != 10 || !operation_on_instruction(source, stop_instruction) {
                return Err("P-code return lacks a selected source operation".into());
            }
            None
        }
        _ => {
            return Ok(inconclusive(
                trace,
                entry,
                "P-code path stops at an unsupported or incomplete boundary",
            ));
        }
    };
    let stop_address = &stop_instruction.address;
    if !matches!(trace.status, TraceStatus::Completed) || trace.lost_events != 0 {
        return Ok(inconclusive(
            trace,
            entry,
            "observation is incomplete or lost events",
        ));
    }
    let entries = trace
        .events
        .iter()
        .filter(|event| event.kind == TraceEventKind::Entry)
        .count();
    let exits = trace
        .events
        .iter()
        .filter(|event| event.kind == TraceEventKind::Exit)
        .count();
    if entries != 1
        || exits != 1
        || trace
            .events
            .first()
            .is_none_or(|event| event.kind != TraceEventKind::Entry)
        || trace
            .events
            .last()
            .is_none_or(|event| event.kind != TraceEventKind::Exit)
        || trace
            .events
            .iter()
            .any(|event| event.thread_id != trace.events[0].thread_id)
    {
        return Ok(inconclusive(
            trace,
            entry,
            "observation does not isolate one ordered invocation",
        ));
    }
    if trace.events.iter().any(|event| {
        matches!(event.kind, TraceEventKind::Block | TraceEventKind::Call)
            && event
                .source
                .elf_vaddr
                .is_none_or(|value| !selected.contains_key(&value))
    }) {
        return Ok(inconclusive(
            trace,
            entry,
            "observed execution leaves the selected function or lacks a source link",
        ));
    }
    let entry_runtime = trace.events[0].source.runtime_address;
    if trace.events.iter().any(|event| {
        event.kind == TraceEventKind::Call
            && event
                .target
                .as_ref()
                .is_some_and(|target| target.runtime_address == entry_runtime)
    }) {
        return Ok(inconclusive(
            trace,
            entry,
            "observed call re-enters the selected function",
        ));
    }
    if !trace
        .events
        .iter()
        .any(|event| event.kind == TraceEventKind::Block)
    {
        return Ok(inconclusive(
            trace,
            entry,
            "observation has no block witnesses",
        ));
    }

    // A P-code instruction visit is not necessarily a Stalker block start.
    // Machine-level branch destinations and fallthroughs after a branch at
    // the end of an instruction are mandatory block starts. Relative P-code
    // branches within one instruction do not imply a Stalker block boundary.
    let mut mandatory = vec![(0usize, entry.clone(), entry.clone())];
    let mut current_visit = 0usize;
    let mut pending_fallthrough = None;
    for event in &path.events {
        match event {
            PcodePathEvent::Effect { operation } => {
                let instruction = selected
                    .get(&visit_numbers[current_visit])
                    .expect("visited instruction is selected");
                if !operation_on_instruction(&operation.source, instruction) {
                    return Err("P-code effect does not belong to its instruction visit".into());
                }
            }
            PcodePathEvent::Branch {
                source,
                destination,
                ..
            } => {
                let instruction = selected
                    .get(&visit_numbers[current_visit])
                    .expect("visited instruction is selected");
                if !operation_on_instruction(source, instruction) {
                    return Err("P-code branch does not belong to its instruction visit".into());
                }
                let source_instruction = &instruction.address;
                pending_fallthrough = None;
                match destination {
                    PcodePathDestination::Instruction { address: target } => {
                        let next = current_visit + 1;
                        if visit_numbers.get(next) != Some(&address(target)?) {
                            return Err(
                                "P-code branch target is not the next instruction visit".into()
                            );
                        }
                        mandatory.push((next, source_instruction.clone(), target.clone()));
                        current_visit = next;
                    }
                    PcodePathDestination::FallthroughPending => {
                        pending_fallthrough = Some(source_instruction.clone());
                    }
                    PcodePathDestination::IntraInstruction { instruction, .. } => {
                        if address(instruction)? != visit_numbers[current_visit] {
                            return Err("P-code relative branch leaves its instruction".into());
                        }
                    }
                }
            }
            PcodePathEvent::Fallthrough { source, target } => {
                let next = current_visit + 1;
                if address(source)? != visit_numbers[current_visit]
                    || visit_numbers.get(next) != Some(&address(target)?)
                {
                    return Err("P-code fallthrough disagrees with instruction visits".into());
                }
                if let Some(source) = pending_fallthrough.take() {
                    mandatory.push((next, source, target.clone()));
                }
                current_visit = next;
            }
        }
    }
    if current_visit + 1 != visit_numbers.len() || pending_fallthrough.is_some() {
        return Err("P-code events do not account for all instruction visits".into());
    }

    let mut visit_cursor = 0usize;
    let mut required_cursor = 0usize;
    let mut compared_blocks = 0;
    let mut compared_calls = 0;
    let mut observed_call = None;
    for (event_index, event) in trace.events.iter().enumerate() {
        match event.kind {
            TraceEventKind::Block => {
                let observed_value = event.source.elf_vaddr.expect("checked source link");
                let observed = normalized(observed_value);
                let position = visit_numbers[visit_cursor..]
                    .iter()
                    .position(|visit| *visit == observed_value)
                    .map(|relative| visit_cursor + relative);
                let Some(position) = position else {
                    let (source, expected) = mandatory
                        .get(required_cursor)
                        .map(|(_, source, target)| (source.clone(), Some(target.clone())))
                        .unwrap_or_else(|| {
                            (
                                path.instruction_visits[visit_cursor.saturating_sub(1)].clone(),
                                path.instruction_visits.get(visit_cursor).cloned(),
                            )
                        });
                    return Ok(difference(
                        trace,
                        entry,
                        ObservedPathDifferenceKind::Block,
                        source,
                        Some(event_index),
                        expected,
                        Some(observed),
                        compared_blocks,
                        compared_calls,
                    ));
                };
                if let Some((_, source, target)) = mandatory.get(required_cursor)
                    && mandatory[required_cursor].0 < position
                {
                    return Ok(difference(
                        trace,
                        entry,
                        ObservedPathDifferenceKind::Block,
                        source.clone(),
                        Some(event_index),
                        Some(target.clone()),
                        Some(observed),
                        compared_blocks,
                        compared_calls,
                    ));
                }
                if mandatory
                    .get(required_cursor)
                    .is_some_and(|item| item.0 == position)
                {
                    required_cursor += 1;
                }
                visit_cursor = position + 1;
                compared_blocks += 1;
            }
            TraceEventKind::Call => {
                observed_call = Some((event_index, event));
                break;
            }
            TraceEventKind::Entry | TraceEventKind::Exit => {}
        }
    }
    if let Some((_, source, target)) = mandatory.get(required_cursor) {
        return Ok(difference(
            trace,
            entry,
            ObservedPathDifferenceKind::Block,
            source.clone(),
            observed_call.map(|(index, _)| index),
            Some(target.clone()),
            observed_call
                .map(|(_, event)| normalized(event.source.elf_vaddr.expect("checked source link"))),
            compared_blocks,
            compared_calls,
        ));
    }
    match (call, observed_call) {
        (Some(source), Some((event_index, event))) => {
            let observed = normalized(event.source.elf_vaddr.expect("checked source link"));
            if address(&observed)? != address(stop_address)? {
                return Ok(difference(
                    trace,
                    entry,
                    ObservedPathDifferenceKind::Call,
                    stop_address.clone(),
                    Some(event_index),
                    Some(stop_address.clone()),
                    Some(observed),
                    compared_blocks,
                    compared_calls,
                ));
            }
            compared_calls = 1;
            if source.opcode == 7 && source.inputs.len() == 1 && source.inputs[0].space == "ram" {
                let expected = PcodeAddress {
                    space: "ram".into(),
                    offset: source.inputs[0].offset.clone(),
                };
                let actual = event
                    .target
                    .as_ref()
                    .and_then(|target| target.elf_vaddr)
                    .map(normalized);
                if let Some(actual) = actual {
                    if address(&actual)? != address(&expected)? {
                        return Ok(difference(
                            trace,
                            entry,
                            ObservedPathDifferenceKind::CallTarget,
                            stop_address.clone(),
                            Some(event_index),
                            Some(expected),
                            Some(actual),
                            compared_blocks,
                            compared_calls,
                        ));
                    }
                } else {
                    return Ok(result(
                        trace,
                        entry,
                        ObservedPathVerdict::Inconclusive,
                        None,
                        vec!["observed call target lacks a normalized source link".into()],
                        compared_blocks,
                        compared_calls,
                    ));
                }
            }
            Ok(result(
                trace,
                entry,
                ObservedPathVerdict::Inconclusive,
                None,
                vec!["P-code path ends at a call boundary".into()],
                compared_blocks,
                compared_calls,
            ))
        }
        (Some(_source), None) => Ok(difference(
            trace,
            entry,
            ObservedPathDifferenceKind::Call,
            stop_address.clone(),
            None,
            Some(stop_address.clone()),
            None,
            compared_blocks,
            compared_calls,
        )),
        (None, Some((event_index, event))) => Ok(difference(
            trace,
            entry,
            ObservedPathDifferenceKind::Call,
            entry.clone(),
            Some(event_index),
            None,
            Some(normalized(
                event.source.elf_vaddr.expect("checked source link"),
            )),
            compared_blocks,
            compared_calls,
        )),
        (None, None) if compared_blocks == 0 => Ok(inconclusive(
            trace,
            entry,
            "observation has no block witnesses",
        )),
        (None, None) => Ok(result(
            trace,
            entry,
            ObservedPathVerdict::Inconclusive,
            None,
            vec!["supplied P-code path has no authenticated initial-state provenance".into()],
            compared_blocks,
            compared_calls,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_execution::{
        DYNAMIC_TRACE_VERSION, INPUT_SPEC_VERSION, ReplayBudget, ReplayGoal, TraceBudget,
        TraceEvent, TraceWitness, input_sha256,
    };
    use hydir_ir::pcode::{PcodeConcreteState, parse_ghidra_snapshot};
    use hydir_ir::{SemanticFidelity, VerificationStatus};

    fn evidence() -> (
        Vec<u8>,
        InputSpec,
        GhidraSnapshot,
        DynamicTrace,
        PcodePathTrace,
    ) {
        let elf = include_bytes!("../../../tests/fixtures/ghidra_add_zero.elf").to_vec();
        let digest = format!("{:x}", Sha256::digest(&elf));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!("../../../tests/fixtures/ghidra_add_zero_v2.json"),
            &digest,
        )
        .unwrap();
        let input = InputSpec {
            schema_version: INPUT_SPEC_VERSION,
            binary_sha256: digest.clone(),
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
        let entry = &snapshot.selected_function.instructions[0];
        let entry_address = address(&entry.address).unwrap();
        let entry_witness = TraceWitness {
            runtime_address: entry_address,
            elf_vaddr: Some(entry_address),
            original_bytes_hex: Some(entry.bytes.clone()),
        };
        let make_event = |sequence, kind, witness| TraceEvent {
            sequence,
            thread_id: 1,
            kind,
            source: witness,
            target: None,
            registers: None,
        };
        let trace = DynamicTrace {
            schema_version: DYNAMIC_TRACE_VERSION,
            binary_sha256: digest.clone(),
            input_sha256: input_sha256(&input).unwrap(),
            selected_elf_vaddr: entry_address,
            ghidra_snapshot_sha256: Some(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
            )),
            observer: "test".into(),
            frida_version: "17.9.5".into(),
            agent_sha256: format!("{:x}", Sha256::digest(b"test")),
            runtime_module_base: Some(address(&snapshot.program.image_base).unwrap()),
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
            events: vec![
                make_event(0, TraceEventKind::Entry, entry_witness.clone()),
                make_event(1, TraceEventKind::Block, entry_witness.clone()),
                make_event(2, TraceEventKind::Exit, entry_witness),
            ],
            jump_evidence: vec![],
        };
        let instructions = &snapshot.selected_function.instructions;
        let path = PcodePathTrace {
            schema_version: PCODE_PATH_TRACE_VERSION,
            binary_sha256: digest,
            start: entry.address.clone(),
            instruction_visits: instructions
                .iter()
                .map(|instruction| instruction.address.clone())
                .collect(),
            events: vec![
                PcodePathEvent::Fallthrough {
                    source: instructions[0].address.clone(),
                    target: instructions[1].address.clone(),
                },
                PcodePathEvent::Fallthrough {
                    source: instructions[1].address.clone(),
                    target: instructions[2].address.clone(),
                },
            ],
            final_state: PcodeConcreteState::default(),
            stop: PcodePathStop::Return {
                source: instructions[2].pcode.last().unwrap().clone(),
            },
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        };
        (elf, input, snapshot, trace, path)
    }

    fn block(snapshot: &GhidraSnapshot, index: usize, sequence: u64) -> TraceEvent {
        let instruction = &snapshot.selected_function.instructions[index];
        let value = address(&instruction.address).unwrap();
        TraceEvent {
            sequence,
            thread_id: 1,
            kind: TraceEventKind::Block,
            source: TraceWitness {
                runtime_address: value,
                elf_vaddr: Some(value),
                original_bytes_hex: Some(instruction.bytes.clone()),
            },
            target: None,
            registers: None,
        }
    }

    #[test]
    fn aligned_blocks_remain_inconclusive_without_seed_provenance() {
        let (elf, input, snapshot, trace, path) = evidence();
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Inconclusive);
        assert_eq!(comparison.compared_blocks, 1);
        assert!(comparison.first_difference.is_none());
        assert!(!comparison.same_initial_state_proven);
        assert!(comparison.inconclusive_reasons[0].contains("provenance"));
    }

    #[test]
    fn first_reordered_block_is_source_linked() {
        let (elf, input, snapshot, mut trace, path) = evidence();
        trace.events.insert(2, block(&snapshot, 2, 2));
        trace.events.insert(3, block(&snapshot, 1, 3));
        trace.events[4].sequence = 4;
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Diverged);
        let difference = comparison.first_difference.unwrap();
        assert_eq!(difference.kind, ObservedPathDifferenceKind::Block);
        assert_eq!(
            difference.source,
            snapshot.selected_function.instructions[2].address
        );
        assert_eq!(
            difference.observed,
            Some(snapshot.selected_function.instructions[1].address.clone())
        );
        assert_eq!(difference.observed_event_index, Some(3));
    }

    #[test]
    fn incomplete_and_multiple_invocations_are_inconclusive() {
        let (elf, input, snapshot, mut trace, path) = evidence();
        trace.lost_events = 1;
        trace.status = TraceStatus::Truncated;
        trace.budget.max_events = trace.events.len();
        assert_eq!(
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path)
                .unwrap()
                .verdict,
            ObservedPathVerdict::Inconclusive
        );

        let (elf, input, snapshot, mut trace, path) = evidence();
        let extra = trace.events[0].clone();
        trace.events.insert(2, extra);
        for (index, event) in trace.events.iter_mut().enumerate() {
            event.sequence = index as u64;
        }
        assert_eq!(
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path)
                .unwrap()
                .verdict,
            ObservedPathVerdict::Inconclusive
        );
    }

    #[test]
    fn unsupported_path_and_outside_observation_are_inconclusive() {
        let (elf, input, snapshot, trace, mut path) = evidence();
        path.stop = PcodePathStop::OperationBudget {
            next: snapshot.selected_function.instructions[2].pcode[0].clone(),
        };
        assert_eq!(
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path)
                .unwrap()
                .verdict,
            ObservedPathVerdict::Inconclusive
        );

        let (elf, input, snapshot, mut trace, path) = evidence();
        trace.events.insert(
            2,
            TraceEvent {
                sequence: 2,
                thread_id: 1,
                kind: TraceEventKind::Block,
                source: TraceWitness {
                    runtime_address: 0x7fff0000,
                    elf_vaddr: None,
                    original_bytes_hex: None,
                },
                target: None,
                registers: None,
            },
        );
        trace.events[3].sequence = 3;
        assert_eq!(
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path)
                .unwrap()
                .verdict,
            ObservedPathVerdict::Inconclusive
        );
    }

    #[test]
    fn mismatched_binary_or_function_is_rejected() {
        let (elf, input, snapshot, trace, mut path) = evidence();
        path.binary_sha256 = "0".repeat(64);
        assert!(compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).is_err());
        path.binary_sha256 = trace.binary_sha256.clone();
        path.start = snapshot.selected_function.instructions[1].address.clone();
        assert!(compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).is_err());
    }

    #[test]
    fn call_target_discrepancy_has_a_selected_call_site() {
        let (elf, input, mut snapshot, mut trace, mut path) = evidence();
        let entry = snapshot.selected_function.instructions[0].address.clone();
        let source = snapshot.selected_function.instructions[2]
            .pcode
            .last_mut()
            .unwrap();
        source.opcode = 7;
        source.mnemonic = "CALL".into();
        source.inputs[0].space = "ram".into();
        source.inputs[0].offset = entry.offset.clone();
        let call_source = source.clone();
        path.stop = PcodePathStop::Call {
            source: call_source.clone(),
        };
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let call_site = &snapshot.selected_function.instructions[2];
        let target = &snapshot.selected_function.instructions[1];
        let call_site_address = address(&call_site.address).unwrap();
        let target_address = address(&target.address).unwrap();
        trace.events.insert(
            2,
            TraceEvent {
                sequence: 2,
                thread_id: 1,
                kind: TraceEventKind::Call,
                source: TraceWitness {
                    runtime_address: call_site_address,
                    elf_vaddr: Some(call_site_address),
                    original_bytes_hex: Some(call_site.bytes.clone()),
                },
                target: Some(TraceWitness {
                    runtime_address: target_address,
                    elf_vaddr: Some(target_address),
                    original_bytes_hex: Some(target.bytes.clone()),
                }),
                registers: None,
            },
        );
        trace.events[3].sequence = 3;
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Diverged);
        let difference = comparison.first_difference.unwrap();
        assert_eq!(difference.kind, ObservedPathDifferenceKind::CallTarget);
        assert_eq!(difference.source, call_source.source_address);
        assert_eq!(difference.expected, Some(entry));
        assert_eq!(difference.observed, Some(target.address.clone()));

        let source = snapshot.selected_function.instructions[2]
            .pcode
            .last_mut()
            .unwrap();
        source.inputs[0].offset = format!("0x0{target_address:x}");
        path.stop = PcodePathStop::Call {
            source: source.clone(),
        };
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Inconclusive);
        assert!(comparison.first_difference.is_none());
    }

    #[test]
    fn branch_destination_requires_an_observed_block() {
        let (elf, input, mut snapshot, mut trace, mut path) = evidence();
        let target = snapshot.selected_function.instructions[2].address.clone();
        let source = snapshot.selected_function.instructions[1]
            .pcode
            .last_mut()
            .unwrap();
        source.opcode = 4;
        source.mnemonic = "BRANCH".into();
        source.output = None;
        source.inputs.truncate(1);
        source.inputs[0].space = "ram".into();
        source.inputs[0].offset = target.offset.clone();
        let source = source.clone();
        path.events.truncate(1);
        path.events.push(PcodePathEvent::Branch {
            source: source.clone(),
            branch_kind: hydir_ir::pcode::PcodePathBranchKind::Branch,
            taken: None,
            destination: PcodePathDestination::Instruction {
                address: target.clone(),
            },
        });
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Diverged);
        let difference = comparison.first_difference.unwrap();
        assert_eq!(difference.kind, ObservedPathDifferenceKind::Block);
        assert_eq!(difference.source, source.source_address);
        assert_eq!(difference.expected, Some(target));
        assert_eq!(difference.observed, None);
    }

    #[test]
    fn padded_snapshot_addresses_compare_numerically() {
        let (elf, input, mut snapshot, mut trace, mut path) = evidence();
        let padded = format!("0x0{:x}", trace.selected_elf_vaddr);
        snapshot.selected_function.entry.offset = padded.clone();
        snapshot.selected_function.instructions[0].address.offset = padded.clone();
        path.start.offset = padded.clone();
        path.instruction_visits[0].offset = padded;
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Inconclusive);
        assert_eq!(comparison.compared_blocks, 1);
        assert!(comparison.first_difference.is_none());
    }

    #[test]
    fn branch_target_is_found_after_its_source_visit() {
        let (elf, input, mut snapshot, mut trace, mut path) = evidence();
        let instructions = &mut snapshot.selected_function.instructions;
        let target_offset = instructions[1].address.offset.clone();
        let source = &mut instructions[2].pcode[0];
        source.opcode = 4;
        source.mnemonic = "BRANCH".into();
        source.output = None;
        source.inputs.truncate(1);
        source.inputs[0].space = "ram".into();
        source.inputs[0].offset = target_offset;
        let branch = source.clone();
        let entry = instructions[0].address.clone();
        let a = instructions[1].address.clone();
        let b = instructions[2].address.clone();
        path.instruction_visits = vec![entry.clone(), a.clone(), b.clone(), a.clone(), b.clone()];
        path.events = vec![
            PcodePathEvent::Fallthrough {
                source: entry,
                target: a.clone(),
            },
            PcodePathEvent::Fallthrough {
                source: a.clone(),
                target: b.clone(),
            },
            PcodePathEvent::Branch {
                source: branch.clone(),
                branch_kind: hydir_ir::pcode::PcodePathBranchKind::Branch,
                taken: None,
                destination: PcodePathDestination::Instruction { address: a.clone() },
            },
            PcodePathEvent::Fallthrough {
                source: a.clone(),
                target: b,
            },
        ];
        trace.events.insert(2, block(&snapshot, 1, 2));
        trace.events[3].sequence = 3;
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Diverged);
        let difference = comparison.first_difference.unwrap();
        assert_eq!(difference.kind, ObservedPathDifferenceKind::Block);
        assert_eq!(
            difference.source,
            snapshot.selected_function.instructions[2].address
        );
        assert_eq!(difference.expected, Some(a));
    }

    #[test]
    fn intra_instruction_branch_does_not_require_a_new_block() {
        let (elf, input, mut snapshot, mut trace, mut path) = evidence();
        let source = &mut snapshot.selected_function.instructions[1].pcode[0];
        source.opcode = 4;
        source.mnemonic = "BRANCH".into();
        source.output = None;
        source.inputs.truncate(1);
        source.inputs[0].space = "const".into();
        source.inputs[0].offset = "0x1".into();
        let branch = source.clone();
        let instruction = snapshot.selected_function.instructions[1].address.clone();
        path.events.insert(
            1,
            PcodePathEvent::Branch {
                source: branch,
                branch_kind: hydir_ir::pcode::PcodePathBranchKind::Branch,
                taken: None,
                destination: PcodePathDestination::IntraInstruction {
                    instruction,
                    sequence_index: 1,
                },
            },
        );
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Inconclusive);
        assert!(comparison.first_difference.is_none());
    }

    #[test]
    fn self_call_and_delay_slot_source_are_handled_conservatively() {
        let (elf, input, mut snapshot, mut trace, mut path) = evidence();
        let prior = snapshot.selected_function.instructions[1].address.clone();
        snapshot.selected_function.instructions[2]
            .pcode
            .last_mut()
            .unwrap()
            .source_address = prior;
        if let PcodePathStop::Return { source } = &mut path.stop {
            *source = snapshot.selected_function.instructions[2]
                .pcode
                .last()
                .unwrap()
                .clone();
        }
        trace.ghidra_snapshot_sha256 = Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
        ));
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Inconclusive);
        assert_eq!(comparison.compared_blocks, 1);

        let call_site = &snapshot.selected_function.instructions[2];
        let call_address = address(&call_site.address).unwrap();
        trace.events.insert(
            2,
            TraceEvent {
                sequence: 2,
                thread_id: 1,
                kind: TraceEventKind::Call,
                source: TraceWitness {
                    runtime_address: call_address,
                    elf_vaddr: Some(call_address),
                    original_bytes_hex: Some(call_site.bytes.clone()),
                },
                target: Some(TraceWitness {
                    runtime_address: trace.selected_elf_vaddr,
                    elf_vaddr: None,
                    original_bytes_hex: None,
                }),
                registers: None,
            },
        );
        trace.events[3].sequence = 3;
        let comparison =
            compare_pcode_observed_path(&elf, &input, &snapshot, &trace, &path).unwrap();
        assert_eq!(comparison.verdict, ObservedPathVerdict::Inconclusive);
        assert!(comparison.inconclusive_reasons[0].contains("re-enters"));
    }
}
