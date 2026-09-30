//! Seed-specific capability evidence for a validated Ghidra P-code function.
//! This artifact records what one bounded run reached, not binary equivalence.

use crate::emit_pcode_interprocedural_cfg_llvm;
use hydir_ir::pcode::{
    GhidraSnapshot, PcodeAddress, PcodeCapabilityReport, PcodeConcreteMemoryAccess,
    PcodeInterproceduralTrace, PcodePathEvent, PcodeReadOnlyElfImage, execute_concrete_call_path,
    execute_concrete_call_path_with_image, parse_pcode_seed, validate_ghidra_snapshot,
};
use hydir_ir::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PCODE_FUNCTION_ASSESSMENT_VERSION: u32 = 1;
const MAX_MEMORY_WITNESSES: usize = 256;
const MAX_CALL_SITES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeAssessedCall {
    pub call_site: PcodeAddress,
    pub target: Option<PcodeAddress>,
    pub computed: bool,
    /// A loaded snapshot is available. This does not prove that the call can execute.
    pub snapshot_loaded: bool,
    /// A transition reached this callee on the supplied seed.
    pub reached: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeMemoryWitness {
    pub source: PcodeAddress,
    pub sequence_index: u32,
    pub access: PcodeConcreteMemoryAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeLlvmAssessment {
    /// Module construction succeeded; no LLVM execution or equivalence was checked.
    pub emitted: bool,
    pub source_operations: usize,
    pub explicit_stop_sites: usize,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeFunctionAssessment {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub snapshot_sha256: Vec<String>,
    pub seed_sha256: String,
    pub entry: PcodeAddress,
    pub static_capability: PcodeCapabilityReport,
    pub calls: Vec<PcodeAssessedCall>,
    pub omitted_call_sites: usize,
    pub memory_witnesses: Vec<PcodeMemoryWitness>,
    pub omitted_memory_witnesses: usize,
    pub read_only_elf_image_available: bool,
    pub llvm: PcodeLlvmAssessment,
    pub trace: PcodeInterproceduralTrace,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

/// Assess the actual bounded path for a caller-supplied, validated seed.
/// Snapshot 0 is the selected root; later snapshots are available callees.
pub fn assess_pcode_function(
    snapshots: &[GhidraSnapshot],
    seed_json: &[u8],
    image: Option<&PcodeReadOnlyElfImage>,
    max_operations: usize,
    max_instruction_visits: usize,
    max_call_depth: usize,
) -> Result<PcodeFunctionAssessment, String> {
    let root = snapshots
        .first()
        .ok_or("assessment needs a root snapshot")?;
    if seed_json.is_empty() {
        return Err("assessment needs a validated seed document".into());
    }
    for snapshot in snapshots {
        validate_ghidra_snapshot(snapshot, &root.binary_sha256)?;
    }
    let seed = parse_pcode_seed(seed_json, root)?;
    let static_capability = root.pcode_capability_report()?;
    let loaded = snapshots
        .iter()
        .map(|snapshot| {
            (
                snapshot.selected_function.entry.space.clone(),
                snapshot.selected_function.entry.offset.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    let trace = if let Some(image) = image {
        execute_concrete_call_path_with_image(
            snapshots,
            &seed,
            image,
            max_operations,
            max_instruction_visits,
            max_call_depth,
        )?
    } else {
        execute_concrete_call_path(
            snapshots,
            &seed,
            max_operations,
            max_instruction_visits,
            max_call_depth,
        )?
    };
    // The executor validates all snapshots as one analyzed program. Build the
    // static call inventory only after that check succeeds.
    let mut calls = Vec::new();
    let mut call_count = 0usize;
    for snapshot in snapshots {
        for call in snapshot.pcode_cfg_ir()?.calls {
            call_count += 1;
            if calls.len() >= MAX_CALL_SITES {
                continue;
            }
            let target = call.evidence.target;
            let snapshot_loaded = target.as_ref().is_some_and(|target| {
                loaded.contains(&(target.space.clone(), target.offset.clone()))
            });
            let reached = trace.calls.iter().any(|visit| {
                visit.call_site == call.evidence.call_site
                    && target
                        .as_ref()
                        .is_none_or(|target| target == &visit.callee_entry)
            });
            calls.push(PcodeAssessedCall {
                call_site: call.evidence.call_site,
                target,
                computed: call.evidence.computed,
                snapshot_loaded,
                reached,
            });
        }
    }
    let mut memory_witnesses = Vec::new();
    let mut memory_count = 0usize;
    for segment in &trace.segments {
        for event in &segment.path.events {
            if let PcodePathEvent::Effect { operation } = event {
                if let Some(access) = &operation.memory_access {
                    memory_count += 1;
                    if memory_witnesses.len() < MAX_MEMORY_WITNESSES {
                        memory_witnesses.push(PcodeMemoryWitness {
                            source: operation.source.source_address.clone(),
                            sequence_index: operation.source.sequence_index,
                            access: access.clone(),
                        });
                    }
                }
            }
        }
    }
    let llvm = match emit_pcode_interprocedural_cfg_llvm(snapshots, max_call_depth) {
        Ok(module) => PcodeLlvmAssessment {
            emitted: true,
            source_operations: module.llvm.source_operations.len(),
            explicit_stop_sites: module.llvm.stop_sites.len(),
            error: None,
        },
        Err(error) => PcodeLlvmAssessment {
            emitted: false,
            source_operations: 0,
            explicit_stop_sites: 0,
            error: Some(error),
        },
    };
    // Keep the root and each supplied callee in input order, including those
    // that were not reached on this seed.
    let snapshot_sha256 = snapshots
        .iter()
        .map(|snapshot| {
            let bytes = serde_json::to_vec(snapshot).map_err(|error| error.to_string())?;
            Ok(format!("{:x}", Sha256::digest(bytes)))
        })
        .collect::<Result<Vec<String>, String>>()?;
    Ok(PcodeFunctionAssessment {
        schema_version: PCODE_FUNCTION_ASSESSMENT_VERSION,
        binary_sha256: root.binary_sha256.clone(),
        snapshot_sha256,
        seed_sha256: format!("{:x}", Sha256::digest(seed_json)),
        entry: root.selected_function.entry.clone(),
        static_capability,
        calls,
        omitted_call_sites: call_count.saturating_sub(MAX_CALL_SITES),
        memory_witnesses,
        omitted_memory_witnesses: memory_count.saturating_sub(MAX_MEMORY_WITNESSES),
        read_only_elf_image_available: image.is_some(),
        llvm,
        trace,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}
