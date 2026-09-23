//! Portable, versioned evidence for one bounded captured-state investigation.
//! The recorded native observation is independently rechecked by recipe replay.

use crate::{
    ExecutionSnapshot, InputChannel, InputSpec, NativeReplayReport, OriginProbe, SnapshotResumePlan,
};
use serde::{Deserialize, Serialize};

pub const INVESTIGATION_CLAIM_VERSION: u32 = 1;
pub const ANALYSIS_RECIPE_VERSION: u32 = 1;
pub const MAX_ANALYSIS_RECIPE_JSON_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedOriginByte {
    pub origin_offset: usize,
    pub channel_offset: usize,
    pub before: u8,
    pub after: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDependency {
    pub kind: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvestigationClaim {
    pub schema_version: u32,
    pub kind: String,
    pub statement: String,
    pub evidence_kind: String,
    pub binary_sha256: String,
    pub original_input_sha256: String,
    pub candidate_input_sha256: String,
    pub snapshot_sha256: String,
    pub probe_sha256: String,
    pub plan_sha256: String,
    pub bridge_sha256: String,
    pub slice_sha256: String,
    pub replay_sha256: String,
    pub origin_id: String,
    pub origin_channel: InputChannel,
    pub failed_decision_address: u64,
    pub failed_decision_occurrence: usize,
    pub failed_decision_kind: String,
    pub relevant_origin_offsets: Vec<usize>,
    pub changed_bytes: Vec<ChangedOriginByte>,
    /// No model is used by the current captured-state solve path.
    pub model_revision: Option<u64>,
    pub assumptions: Vec<String>,
    pub unresolved_dependencies: Vec<String>,
    pub coverage: String,
    pub verification: String,
    pub invalidation_dependencies: Vec<ClaimDependency>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisRecipe {
    pub schema_version: u32,
    pub kind: String,
    pub hydir_version: String,
    pub original_input: InputSpec,
    pub snapshot: ExecutionSnapshot,
    pub origin_probe: OriginProbe,
    pub resume_plan: SnapshotResumePlan,
    /// The validated Triton bridge result, including the failed-seed slice.
    pub bridge_result: serde_json::Value,
    pub candidate_input: InputSpec,
    pub recorded_native_replay: NativeReplayReport,
    pub claim: InvestigationClaim,
}

pub fn parse_analysis_recipe(json: &[u8]) -> Result<AnalysisRecipe, String> {
    if json.len() > MAX_ANALYSIS_RECIPE_JSON_BYTES {
        return Err("AnalysisRecipe exceeds 8 MiB JSON limit".into());
    }
    serde_json::from_slice(json).map_err(|error| format!("invalid AnalysisRecipe JSON: {error}"))
}
