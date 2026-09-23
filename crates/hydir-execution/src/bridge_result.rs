//! Validate the bounded Triton result and failed-seed structural slice.

use crate::SnapshotResumePlan;
use serde_json::json;
use sha2::Digest;

pub fn validate_snapshot_bridge_result(
    plan: &SnapshotResumePlan,
    result: &serde_json::Value,
) -> Result<(), String> {
    if result["schema_version"] != 1
        || result["operation"] != "snapshot_return"
        || result["backend"] != "triton"
        || result["binary_sha256"] != plan.binary_sha256
        || result["input_sha256"] != plan.input_sha256
        || result["snapshot_sha256"] != plan.snapshot_sha256
        || result["probe_sha256"] != plan.probe_sha256
        || result["origin_id"] != plan.symbolic_origin.id
        || result["origin_probe_evidence"] != "byte_equality_only"
        || result["assumptions"]
            != json!([
                "analyst_selected_origin_address_has_input_channel_bytes",
                "selected_code_extent_and_captured_pages_cover_this_function_path"
            ])
        || result["return_equals"] != plan.return_equals
    {
        return Err("Triton snapshot result identity or scope mismatch".into());
    }
    let status = result["status"]
        .as_str()
        .ok_or("Triton snapshot result status is missing")?;
    if result["backend_version"]
        .as_str()
        .is_none_or(|version| version.is_empty() || version.len() > 64)
    {
        return Err("Triton snapshot backend version is missing".into());
    }
    if !matches!(
        status,
        "function_witness"
            | "budget_exhausted"
            | "unsupported_effect"
            | "solver_timeout"
            | "solver_unknown"
            | "search_exhausted"
    ) {
        return Err("Triton snapshot result status is invalid".into());
    }
    if result["explored_seeds"]
        .as_u64()
        .is_none_or(|count| count > u64::from(plan.max_seeds))
        || result["processed_instructions"]
            .as_u64()
            .is_none_or(|count| {
                count > u64::from(plan.max_seeds) * u64::from(plan.max_instructions_per_seed) * 2
            })
        || result["unsupported_paths"]
            .as_u64()
            .is_none_or(|count| count > u64::from(plan.max_seeds))
        || result["solver_queries"]
            .as_u64()
            .is_none_or(|count| count > u64::from(plan.max_solver_queries))
    {
        return Err("Triton snapshot result exceeds declared budget".into());
    }
    let candidate = result["candidate_hex"].as_str();
    if status == "function_witness" {
        let bytes = crate::decode_hex(
            candidate.ok_or("function witness has no candidate bytes")?,
            32,
        )?;
        if bytes.len() != plan.symbolic_origin.length {
            return Err("function witness candidate length differs from origin".into());
        }
    } else if !result["candidate_hex"].is_null() {
        return Err("non-witness Triton result contains candidate bytes".into());
    }
    if result["diagnostic"]
        .as_str()
        .is_some_and(|message| message.len() > 512)
    {
        return Err("Triton snapshot diagnostic exceeds limit".into());
    }
    validate_input_condition_slice(plan, &result["input_condition_slice"])?;
    Ok(())
}

fn slice_indices(value: &serde_json::Value, limit: usize) -> Result<Vec<u64>, String> {
    let values = value
        .as_array()
        .ok_or("Triton slice index list is missing")?;
    if values.len() > limit {
        return Err("Triton slice index list exceeds limit".into());
    }
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let index = value.as_u64().ok_or("Triton slice index is invalid")?;
        if result.last().is_some_and(|previous| *previous >= index) {
            return Err("Triton slice indices must be strictly increasing".into());
        }
        result.push(index);
    }
    Ok(result)
}

pub fn validate_input_condition_slice(
    plan: &SnapshotResumePlan,
    slice: &serde_json::Value,
) -> Result<(), String> {
    if slice.is_null() {
        return Ok(());
    }
    let code = crate::decode_hex(&plan.code_hex, 4096)?;
    let code_end = plan
        .code_address
        .checked_add(code.len() as u64)
        .ok_or("Triton slice code address overflows")?;
    if slice["schema_version"] != 1
        || slice["kind"] != "input_condition_slice"
        || slice["scope"] != "captured_seed_trace_structural_dependencies"
        || slice["binary_sha256"] != plan.binary_sha256
        || slice["input_sha256"] != plan.input_sha256
        || slice["snapshot_sha256"] != plan.snapshot_sha256
        || slice["probe_sha256"] != plan.probe_sha256
        || slice["code_sha256"] != format!("{:x}", sha2::Sha256::digest(&code))
        || slice["code_address"] != plan.code_address
        || slice["origin_id"] != plan.symbolic_origin.id
        || slice["channel"]
            != serde_json::to_value(&plan.symbolic_origin.channel)
                .map_err(|error| error.to_string())?
        || slice["channel_offset"] != plan.symbolic_origin.offset
        || slice["seed_hex"] != plan.seed_hex
        || slice["return_equals"] != plan.return_equals
    {
        return Err("Triton input-condition slice identity or scope mismatch".into());
    }
    let observed = slice["observed_return"]
        .as_u64()
        .ok_or("Triton slice observed return is missing")?;
    if observed == plan.return_equals {
        return Err("Triton slice does not describe a failed seed".into());
    }
    let complete = slice["ast_walk_complete"]
        .as_bool()
        .ok_or("Triton slice completeness flag is missing")?;
    let unresolved = slice["unresolved_dependencies"]
        .as_array()
        .ok_or("Triton slice unresolved dependencies are missing")?;
    if unresolved.len() < 3
        || unresolved.len() > 5
        || unresolved[0] != "origin_channel_provenance_unproven_byte_equality_only"
        || unresolved[1] != "other_paths_and_environment_not_in_this_trace"
        || unresolved[2] != "symbolic_memory_address_dependencies_not_analyzed"
        || unresolved.iter().any(|item| item.as_str().is_none())
        || (complete && unresolved.len() != 3)
        || (!complete && unresolved.len() == 3)
        || unresolved[3..].iter().enumerate().any(|(index, item)| {
            let expected = if index == 0 {
                "slice_ast_or_decision_budget_exhausted"
            } else {
                "unmapped_symbolic_variable"
            };
            item != expected
                && !(index == 0 && unresolved.len() == 4 && item == "unmapped_symbolic_variable")
        })
    {
        return Err("Triton slice uncertainty statement is invalid".into());
    }
    let instructions = slice["instructions"]
        .as_array()
        .ok_or("Triton slice instructions are missing")?;
    if instructions.is_empty() || instructions.len() > plan.max_instructions_per_seed as usize {
        return Err("Triton slice instruction count exceeds path budget".into());
    }
    for (index, instruction) in instructions.iter().enumerate() {
        let address = instruction["address"]
            .as_u64()
            .ok_or("Triton slice instruction address is invalid")?;
        if instruction["index"] != index
            || !(plan.code_address..code_end).contains(&address)
            || instruction["code_offset"] != address - plan.code_address
            || instruction["disassembly"]
                .as_str()
                .is_none_or(|text| text.is_empty() || text.len() > 256)
        {
            return Err("Triton slice instruction is outside captured code".into());
        }
    }
    let decisions = slice["decisions"]
        .as_array()
        .ok_or("Triton slice decisions are missing")?;
    if decisions.is_empty() || decisions.len() > 65 {
        return Err("Triton slice decision count exceeds limit".into());
    }
    let mut all_offsets = std::collections::BTreeSet::new();
    let mut all_sources = std::collections::BTreeSet::new();
    for (position, decision) in decisions.iter().enumerate() {
        let occurrence = decision["occurrence"]
            .as_u64()
            .ok_or("Triton slice decision occurrence is invalid")?
            as usize;
        if occurrence >= instructions.len()
            || decision["address"] != instructions[occurrence]["address"]
        {
            return Err("Triton slice decision is outside captured trace".into());
        }
        let kind = decision["kind"]
            .as_str()
            .ok_or("Triton slice decision kind is missing")?;
        if (position + 1 == decisions.len()) != (kind == "return") {
            return Err("Triton slice must end with one return decision".into());
        }
        if kind == "return" {
            if decision["observed_value"] != observed {
                return Err("Triton slice return observation differs".into());
            }
        } else if kind != "branch" || decision["taken_target"].as_u64().is_none() {
            return Err("Triton slice branch decision is invalid".into());
        }
        let offsets = slice_indices(&decision["origin_offsets"], plan.symbolic_origin.length)?;
        let sources = slice_indices(&decision["source_occurrences"], instructions.len())?;
        if offsets
            .iter()
            .any(|offset| *offset >= plan.symbolic_origin.length as u64)
            || sources.iter().any(|source| *source > occurrence as u64)
        {
            return Err("Triton slice dependency is outside origin or trace".into());
        }
        if !offsets.is_empty() {
            all_offsets.extend(offsets);
            all_sources.extend(sources);
        }
    }
    if slice_indices(
        &slice["relevant_origin_offsets"],
        plan.symbolic_origin.length,
    )? != all_offsets.into_iter().collect::<Vec<_>>()
        || slice_indices(&slice["source_occurrences"], instructions.len())?
            != all_sources.into_iter().collect::<Vec<_>>()
    {
        return Err("Triton slice summary differs from decision dependencies".into());
    }
    Ok(())
}
