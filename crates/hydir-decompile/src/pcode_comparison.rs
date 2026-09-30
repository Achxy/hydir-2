//! Bounded, source-addressed comparison of independently collected executions.
//! A matching watch set proves only the bytes and steps named by the inputs.

use hydir_ir::pcode::PcodeAddress;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PCODE_EXECUTION_COMPARISON_VERSION: u32 = 1;
const MAX_STEPS: usize = 2048;
const MAX_WATCHES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonEngine {
    Ghidra,
    HydirRust,
    CompiledLlvm,
    Native,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchedByte {
    pub space: String,
    pub offset: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachineStepWitness {
    pub address: PcodeAddress,
    /// State after this machine instruction; None means the byte is unknown.
    pub bytes: Vec<Option<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineExecutionEvidence {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub seed_sha256: String,
    pub engine: ComparisonEngine,
    /// Identical ordered watch sets are required before byte comparison.
    pub watches: Vec<WatchedByte>,
    pub steps: Vec<MachineStepWitness>,
    pub stop_kind: String,
    pub stop_reason: String,
    /// True only for a terminal result under the collector's explicit contract.
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonVerdict {
    Diverged,
    MatchedObservedContract,
    Inconclusive,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DifferenceKind {
    InstructionPath,
    StateByte,
    StopKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstMachineDifference {
    pub kind: DifferenceKind,
    pub address: PcodeAddress,
    pub step_index: usize,
    pub compared_engine: ComparisonEngine,
    pub watch: Option<WatchedByte>,
    pub expected: String,
    pub actual: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeExecutionComparison {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub seed_sha256: String,
    pub verdict: ComparisonVerdict,
    pub first_difference: Option<FirstMachineDifference>,
    pub missing_engines: Vec<ComparisonEngine>,
    pub inconclusive_reasons: Vec<String>,
    pub compared_steps: usize,
    pub watched_bytes: usize,
    pub engines: Vec<EngineExecutionEvidence>,
}

fn hex_address(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or("machine address requires 0x prefix")?;
    if digits.is_empty() || digits.len() > 16 || (digits.len() > 1 && digits.starts_with('0')) {
        return Err("machine address is not canonical hexadecimal".into());
    }
    u64::from_str_radix(digits, 16).map_err(|_| "invalid machine address".into())
}

fn validate(evidence: &EngineExecutionEvidence) -> Result<(), String> {
    if evidence.schema_version != PCODE_EXECUTION_COMPARISON_VERSION {
        return Err("unsupported execution evidence version".into());
    }
    if evidence.binary_sha256.len() != 64
        || evidence.seed_sha256.len() != 64
        || !evidence
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || !evidence
            .seed_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("execution evidence needs binary and seed SHA-256 identities".into());
    }
    if evidence.steps.len() > MAX_STEPS || evidence.watches.len() > MAX_WATCHES {
        return Err("execution evidence exceeds comparison limits".into());
    }
    if evidence.stop_kind.is_empty()
        || evidence.stop_kind.len() > 64
        || evidence.stop_reason.len() > 1024
    {
        return Err("execution evidence has invalid stop metadata".into());
    }
    let mut seen = BTreeSet::new();
    for watch in &evidence.watches {
        if watch.space.is_empty() || watch.space.len() > 64 {
            return Err("invalid watched address space".into());
        }
        let key = (watch.space.as_str(), hex_address(&watch.offset)?);
        if !seen.insert(key) {
            return Err("duplicate watched byte".into());
        }
    }
    for step in &evidence.steps {
        if step.address.space != "ram" || step.bytes.len() != evidence.watches.len() {
            return Err("machine step needs a RAM address and one value per watched byte".into());
        }
        hex_address(&step.address.offset)?;
    }
    Ok(())
}

/// Compare four bounded runs. A concrete path or byte mismatch wins over
/// incomplete evidence; absent/unknown evidence can never produce a match.
pub fn compare_pcode_executions(
    mut engines: Vec<EngineExecutionEvidence>,
) -> Result<PcodeExecutionComparison, String> {
    if engines.is_empty() || engines.len() > 4 {
        return Err("comparison needs one to four engine results".into());
    }
    for engine in &engines {
        validate(engine)?;
    }
    engines.sort_by_key(|engine| match engine.engine {
        ComparisonEngine::Ghidra => 0,
        ComparisonEngine::HydirRust => 1,
        ComparisonEngine::CompiledLlvm => 2,
        ComparisonEngine::Native => 3,
    });
    for pair in engines.windows(2) {
        if pair[0].engine == pair[1].engine {
            return Err("duplicate comparison engine".into());
        }
    }
    let reference = &engines[0];
    for engine in &engines[1..] {
        if engine.binary_sha256 != reference.binary_sha256
            || engine.seed_sha256 != reference.seed_sha256
        {
            return Err("comparison engines have different binary or seed identities".into());
        }
        if engine.watches != reference.watches {
            return Err("comparison engines have different watched byte contracts".into());
        }
    }
    let required = [
        ComparisonEngine::Ghidra,
        ComparisonEngine::HydirRust,
        ComparisonEngine::CompiledLlvm,
        ComparisonEngine::Native,
    ];
    let missing_engines = required
        .into_iter()
        .filter(|required| !engines.iter().any(|engine| engine.engine == *required))
        .collect::<Vec<_>>();
    let mut inconclusive_reasons = Vec::new();
    if !missing_engines.is_empty() {
        inconclusive_reasons.push("one or more independent engines were not run".into());
    }
    if reference.watches.is_empty() {
        inconclusive_reasons.push("no machine state bytes were watched".into());
    }
    for engine in &engines {
        if engine.steps.is_empty() {
            inconclusive_reasons.push(format!(
                "{:?} has no machine instruction witnesses",
                engine.engine
            ));
        }
        if !engine.complete {
            inconclusive_reasons.push(format!(
                "{:?} stopped without a terminal result: {}",
                engine.engine, engine.stop_reason
            ));
        }
        if engine.steps.iter().any(|step| step.bytes.contains(&None)) {
            inconclusive_reasons.push(format!(
                "{:?} has unknown watched state bytes",
                engine.engine
            ));
        }
    }
    let mut first_difference = None;
    let mut compared_steps = reference.steps.len();
    for engine in &engines[1..] {
        let shared = reference.steps.len().min(engine.steps.len());
        compared_steps = compared_steps.min(shared);
        let mut candidate = None;
        for index in 0..shared {
            let expected = &reference.steps[index];
            let actual = &engine.steps[index];
            if expected.address != actual.address {
                // The preceding machine instruction selected a different next
                // address. At index zero, the entry address itself differs.
                let source = if index == 0 {
                    &expected.address
                } else {
                    &reference.steps[index - 1].address
                };
                candidate = Some(FirstMachineDifference {
                    kind: DifferenceKind::InstructionPath,
                    address: source.clone(),
                    step_index: index,
                    compared_engine: engine.engine.clone(),
                    watch: None,
                    expected: expected.address.offset.clone(),
                    actual: actual.address.offset.clone(),
                });
                break;
            }
            for (byte_index, (left, right)) in expected.bytes.iter().zip(&actual.bytes).enumerate()
            {
                if let (Some(left), Some(right)) = (left, right) {
                    if left != right {
                        candidate = Some(FirstMachineDifference {
                            kind: DifferenceKind::StateByte,
                            address: expected.address.clone(),
                            step_index: index,
                            compared_engine: engine.engine.clone(),
                            watch: Some(reference.watches[byte_index].clone()),
                            expected: format!("0x{left:02x}"),
                            actual: format!("0x{right:02x}"),
                        });
                        break;
                    }
                }
            }
            if candidate.is_some() {
                break;
            }
        }
        if candidate.is_none()
            && reference.complete
            && engine.complete
            && reference.steps.len() != engine.steps.len()
        {
            let index = shared;
            let source = reference
                .steps
                .get(shared.saturating_sub(1))
                .or_else(|| engine.steps.first())
                .ok_or("cannot locate divergent empty execution path")?;
            candidate = Some(FirstMachineDifference {
                kind: DifferenceKind::InstructionPath,
                address: source.address.clone(),
                step_index: index,
                compared_engine: engine.engine.clone(),
                watch: None,
                expected: reference
                    .steps
                    .get(index)
                    .map_or("<stopped>".into(), |step| step.address.offset.clone()),
                actual: engine
                    .steps
                    .get(index)
                    .map_or("<stopped>".into(), |step| step.address.offset.clone()),
            });
        }
        if candidate.is_none()
            && reference.complete
            && engine.complete
            && reference.stop_kind != engine.stop_kind
        {
            let source = reference
                .steps
                .last()
                .or_else(|| engine.steps.last())
                .ok_or("cannot locate divergent empty execution stop")?;
            candidate = Some(FirstMachineDifference {
                kind: DifferenceKind::StopKind,
                address: source.address.clone(),
                step_index: shared,
                compared_engine: engine.engine.clone(),
                watch: None,
                expected: reference.stop_kind.clone(),
                actual: engine.stop_kind.clone(),
            });
        }
        if let Some(candidate) = candidate {
            if first_difference
                .as_ref()
                .is_none_or(|current: &FirstMachineDifference| {
                    candidate.step_index < current.step_index
                })
            {
                first_difference = Some(candidate);
            }
        }
    }
    let verdict = if first_difference.is_some() {
        ComparisonVerdict::Diverged
    } else if inconclusive_reasons.is_empty() {
        ComparisonVerdict::MatchedObservedContract
    } else {
        ComparisonVerdict::Inconclusive
    };
    Ok(PcodeExecutionComparison {
        schema_version: PCODE_EXECUTION_COMPARISON_VERSION,
        binary_sha256: reference.binary_sha256.clone(),
        seed_sha256: reference.seed_sha256.clone(),
        verdict,
        first_difference,
        missing_engines,
        inconclusive_reasons,
        compared_steps,
        watched_bytes: reference.watches.len(),
        engines,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(offset: &str) -> PcodeAddress {
        PcodeAddress {
            space: "ram".into(),
            offset: offset.into(),
        }
    }

    fn evidence(engine: ComparisonEngine) -> EngineExecutionEvidence {
        EngineExecutionEvidence {
            schema_version: 1,
            binary_sha256: "a".repeat(64),
            seed_sha256: "b".repeat(64),
            engine,
            watches: vec![WatchedByte {
                space: "register".into(),
                offset: "0x0".into(),
            }],
            steps: vec![
                MachineStepWitness {
                    address: address("0x401000"),
                    bytes: vec![Some(0)],
                },
                MachineStepWitness {
                    address: address("0x401004"),
                    bytes: vec![Some(1)],
                },
            ],
            stop_kind: "return".into(),
            stop_reason: "returned".into(),
            complete: true,
        }
    }

    fn four() -> Vec<EngineExecutionEvidence> {
        [
            ComparisonEngine::Ghidra,
            ComparisonEngine::HydirRust,
            ComparisonEngine::CompiledLlvm,
            ComparisonEngine::Native,
        ]
        .into_iter()
        .map(evidence)
        .collect()
    }

    #[test]
    fn four_complete_engines_match_only_the_watched_contract() {
        let result = compare_pcode_executions(four()).unwrap();
        assert_eq!(result.verdict, ComparisonVerdict::MatchedObservedContract);
        assert_eq!(result.watched_bytes, 1);
        assert!(result.first_difference.is_none());
    }

    #[test]
    fn state_and_branch_faults_identify_machine_source() {
        let mut state = four();
        state[2].steps[1].bytes[0] = Some(2);
        let result = compare_pcode_executions(state).unwrap();
        let first = result.first_difference.unwrap();
        assert_eq!(first.kind, DifferenceKind::StateByte);
        assert_eq!(first.address, address("0x401004"));
        assert_eq!(first.expected, "0x01");
        assert_eq!(first.actual, "0x02");

        let mut branch = four();
        branch[3].steps[1].address = address("0x401100");
        let result = compare_pcode_executions(branch).unwrap();
        let first = result.first_difference.unwrap();
        assert_eq!(first.kind, DifferenceKind::InstructionPath);
        assert_eq!(first.address, address("0x401000"));

        let mut memory = four();
        for engine in &mut memory {
            engine.watches[0].space = "ram".into();
            engine.watches[0].offset = "0x700000".into();
        }
        memory[1].steps[0].bytes[0] = Some(0xff);
        let first = compare_pcode_executions(memory)
            .unwrap()
            .first_difference
            .unwrap();
        assert_eq!(first.kind, DifferenceKind::StateByte);
        assert_eq!(first.address, address("0x401000"));
        assert_eq!(first.watch.unwrap().offset, "0x700000");
    }

    #[test]
    fn earliest_difference_wins_across_all_engines() {
        let mut rows = four();
        rows[1].steps[1].bytes[0] = Some(9);
        rows[3].steps[0].bytes[0] = Some(7);
        let first = compare_pcode_executions(rows)
            .unwrap()
            .first_difference
            .unwrap();
        assert_eq!(first.step_index, 0);
        assert_eq!(first.compared_engine, ComparisonEngine::Native);
    }

    #[test]
    fn unknown_and_missing_evidence_never_become_matches() {
        let mut unknown = four();
        unknown[1].steps[0].bytes[0] = None;
        assert_eq!(
            compare_pcode_executions(unknown).unwrap().verdict,
            ComparisonVerdict::Inconclusive
        );
        let only = compare_pcode_executions(vec![evidence(ComparisonEngine::HydirRust)]).unwrap();
        assert_eq!(only.verdict, ComparisonVerdict::Inconclusive);
        assert_eq!(only.missing_engines.len(), 3);
        let mut stopped = four();
        stopped[1].complete = false;
        assert_eq!(
            compare_pcode_executions(stopped).unwrap().verdict,
            ComparisonVerdict::Inconclusive
        );
    }

    #[test]
    fn mismatched_identity_and_watch_sets_fail_closed() {
        let mut rows = four();
        rows[1].seed_sha256 = "c".repeat(64);
        assert!(compare_pcode_executions(rows).is_err());
        let mut rows = four();
        rows[1].watches[0].offset = "0x1".into();
        assert!(compare_pcode_executions(rows).is_err());
    }
}
