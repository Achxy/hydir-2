//! A reproducible bounded solve recipe and a claim scoped to one native replay.

use super::validate_snapshot_bridge_result;
use hydir_execution::{
    ANALYSIS_RECIPE_VERSION, AnalysisRecipe, ChangedOriginByte, ClaimDependency, ExecutionSnapshot,
    INVESTIGATION_CLAIM_VERSION, InputSpec, InvestigationClaim, NativeReplayReport, OriginProbe,
    ReplayStatus, SnapshotResumePlan, decode_hex, input_sha256, input_with_origin_candidate,
    validate_execution_snapshot, validate_origin_probe, validate_replay_report,
    validate_snapshot_resume_plan,
};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;

fn digest_json<T: Serialize>(artifact: &T) -> Result<String, Box<dyn Error>> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(artifact)?)
    ))
}

fn dependency(kind: &str, sha256: String) -> ClaimDependency {
    ClaimDependency {
        kind: kind.into(),
        sha256,
    }
}

fn build_claim(
    original: &InputSpec,
    plan: &SnapshotResumePlan,
    bridge: &Value,
    candidate: &InputSpec,
    replay: &NativeReplayReport,
) -> Result<InvestigationClaim, Box<dyn Error>> {
    if bridge["status"] != "function_witness" || replay.status != ReplayStatus::GoalMatched {
        return Err("a native-goal claim requires a function witness and matched replay".into());
    }
    let candidate_hex = bridge["candidate_hex"]
        .as_str()
        .ok_or("recipe function witness has no candidate bytes")?;
    let seed = decode_hex(&plan.seed_hex, 32)?;
    let bytes = decode_hex(candidate_hex, 32)?;
    if seed.len() != bytes.len() || bytes.len() != plan.symbolic_origin.length {
        return Err("recipe candidate differs from symbolic origin length".into());
    }
    let slice = &bridge["input_condition_slice"];
    let decisions = slice["decisions"]
        .as_array()
        .ok_or("recipe has no completed failing-seed slice")?;
    let failed = decisions
        .iter()
        .find(|decision| {
            decision["kind"] == "branch"
                && decision["origin_offsets"]
                    .as_array()
                    .is_some_and(|offsets| !offsets.is_empty())
        })
        .or_else(|| decisions.last())
        .ok_or("recipe slice has no failed decision")?;
    let relevant_origin_offsets = slice["relevant_origin_offsets"]
        .as_array()
        .ok_or("recipe slice has no origin offsets")?
        .iter()
        .map(|value| value.as_u64().map(|offset| offset as usize))
        .collect::<Option<Vec<_>>>()
        .ok_or("recipe slice has an invalid origin offset")?;
    let unresolved_dependencies = slice["unresolved_dependencies"]
        .as_array()
        .ok_or("recipe slice has no uncertainty list")?
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect::<Option<Vec<_>>>()
        .ok_or("recipe slice has an invalid uncertainty entry")?;
    let changed_bytes = seed
        .iter()
        .zip(&bytes)
        .enumerate()
        .filter(|(_, (before, after))| before != after)
        .map(|(origin_offset, (before, after))| ChangedOriginByte {
            origin_offset,
            channel_offset: plan.symbolic_origin.offset + origin_offset,
            before: *before,
            after: *after,
        })
        .collect();
    let original_input_sha256 = input_sha256(original)?;
    let candidate_input_sha256 = input_sha256(candidate)?;
    let plan_sha256 = digest_json(plan)?;
    let bridge_sha256 = digest_json(bridge)?;
    let slice_sha256 = digest_json(slice)?;
    let replay_sha256 = digest_json(replay)?;
    let invalidation_dependencies = vec![
        dependency("binary", plan.binary_sha256.clone()),
        dependency("original_input", original_input_sha256.clone()),
        dependency("candidate_input", candidate_input_sha256.clone()),
        dependency("snapshot", plan.snapshot_sha256.clone()),
        dependency("origin_probe", plan.probe_sha256.clone()),
        dependency("resume_plan", plan_sha256.clone()),
        dependency("triton_result", bridge_sha256.clone()),
        dependency("failed_seed_slice", slice_sha256.clone()),
        dependency("native_replay", replay_sha256.clone()),
    ];
    Ok(InvestigationClaim {
        schema_version: INVESTIGATION_CLAIM_VERSION,
        kind: "candidate_reached_declared_goal".into(),
        statement:
            "One fresh execution of the original ELF met the candidate input's declared goal".into(),
        evidence_kind: "native_replay_observation".into(),
        binary_sha256: plan.binary_sha256.clone(),
        original_input_sha256,
        candidate_input_sha256,
        snapshot_sha256: plan.snapshot_sha256.clone(),
        probe_sha256: plan.probe_sha256.clone(),
        plan_sha256,
        bridge_sha256,
        slice_sha256,
        replay_sha256,
        origin_id: plan.symbolic_origin.id.clone(),
        origin_channel: plan.symbolic_origin.channel.clone(),
        failed_decision_address: failed["address"]
            .as_u64()
            .ok_or("recipe failed decision has no address")?,
        failed_decision_occurrence: failed["occurrence"]
            .as_u64()
            .ok_or("recipe failed decision has no occurrence")?
            as usize,
        failed_decision_kind: failed["kind"]
            .as_str()
            .ok_or("recipe failed decision has no kind")?
            .into(),
        relevant_origin_offsets,
        changed_bytes,
        model_revision: None,
        assumptions: plan.assumptions.clone(),
        unresolved_dependencies,
        coverage: "one_captured_seed_trace_and_one_fresh_native_replay".into(),
        verification: "recorded_observation_requires_fresh_replay".into(),
        invalidation_dependencies,
    })
}

pub(super) fn build_recipe(
    elf: &[u8],
    original: &InputSpec,
    snapshot: &ExecutionSnapshot,
    probe: &OriginProbe,
    plan: &SnapshotResumePlan,
    bridge: &Value,
    candidate: &InputSpec,
    replay: &NativeReplayReport,
) -> Result<AnalysisRecipe, Box<dyn Error>> {
    let claim = build_claim(original, plan, bridge, candidate, replay)?;
    let recipe = AnalysisRecipe {
        schema_version: ANALYSIS_RECIPE_VERSION,
        kind: "captured_pure_validator_return".into(),
        hydir_version: env!("CARGO_PKG_VERSION").into(),
        original_input: original.clone(),
        snapshot: snapshot.clone(),
        origin_probe: probe.clone(),
        resume_plan: plan.clone(),
        bridge_result: bridge.clone(),
        candidate_input: candidate.clone(),
        recorded_native_replay: replay.clone(),
        claim,
    };
    validate_recipe(elf, &recipe)?;
    Ok(recipe)
}

pub(super) fn validate_recipe(elf: &[u8], recipe: &AnalysisRecipe) -> Result<(), Box<dyn Error>> {
    if recipe.schema_version != ANALYSIS_RECIPE_VERSION
        || recipe.kind != "captured_pure_validator_return"
        || recipe.hydir_version.is_empty()
        || recipe.hydir_version.len() > 64
    {
        return Err("AnalysisRecipe version, kind, or tool identity is invalid".into());
    }
    validate_execution_snapshot(elf, &recipe.original_input, &recipe.snapshot)?;
    validate_origin_probe(
        elf,
        &recipe.original_input,
        &recipe.snapshot,
        &recipe.origin_probe,
    )?;
    validate_snapshot_resume_plan(
        elf,
        &recipe.original_input,
        &recipe.snapshot,
        &recipe.origin_probe,
        &recipe.resume_plan,
    )?;
    validate_snapshot_bridge_result(&recipe.resume_plan, &recipe.bridge_result)?;
    if recipe.bridge_result["status"] != "function_witness" {
        return Err("AnalysisRecipe has no function witness".into());
    }
    let candidate_hex = recipe.bridge_result["candidate_hex"]
        .as_str()
        .ok_or("AnalysisRecipe witness has no candidate bytes")?;
    let expected_candidate = input_with_origin_candidate(
        elf,
        &recipe.original_input,
        &recipe.resume_plan.symbolic_origin.id,
        candidate_hex,
    )?;
    if recipe.candidate_input != expected_candidate {
        return Err("AnalysisRecipe candidate changes bytes outside the declared origin".into());
    }
    validate_replay_report(elf, &recipe.candidate_input, &recipe.recorded_native_replay)?;
    if recipe.recorded_native_replay.status != ReplayStatus::GoalMatched {
        return Err("AnalysisRecipe recorded replay did not meet the goal".into());
    }
    let expected_claim = build_claim(
        &recipe.original_input,
        &recipe.resume_plan,
        &recipe.bridge_result,
        &recipe.candidate_input,
        &recipe.recorded_native_replay,
    )?;
    if recipe.claim != expected_claim {
        return Err("InvestigationClaim differs from bound recipe evidence".into());
    }
    if serde_json::to_vec(recipe)?.len() > hydir_execution::MAX_ANALYSIS_RECIPE_JSON_BYTES {
        return Err("AnalysisRecipe exceeds 8 MiB JSON limit".into());
    }
    Ok(())
}
