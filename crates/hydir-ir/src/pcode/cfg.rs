//! Instruction-level control-flow evidence over ordered P-code state effects.
//!
//! Ghidra's analyzed flows are useful targets, not a proof that every target
//! or every machine instruction was recovered. Calls are kept apart from
//! intraprocedural edges. An unknown target stays unknown, and this version
//! cannot represent a complete CFG claim.

use super::{
    GhidraCallTarget, GhidraFlowEdge, GhidraFlowKind, GhidraSnapshot, PcodeAddress, PcodeEffect,
    PcodeStateFunctionIr, hex_u64, validate_ghidra_snapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const PCODE_CFG_IR_VERSION: u32 = 1;

/// Complete requires independent coverage and target verification, which this
/// Ghidra snapshot does not provide. A serialized `"complete"` claim fails to
/// deserialize instead of being silently accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeCfgCompleteness {
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCfgEdge {
    /// Index into `nodes`, whose instruction address equals `evidence.source`.
    pub source_node: u32,
    /// Present only when the target is one of the selected instructions. A
    /// concrete address outside those instructions remains in `evidence`.
    pub target_node: Option<u32>,
    pub evidence: GhidraFlowEdge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCfgCall {
    pub source_node: u32,
    pub evidence: GhidraCallTarget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCfgNode {
    pub instruction_index: u32,
    pub address: PcodeAddress,
    /// Indices into `edges`; call edges never appear here.
    pub outgoing_edges: Vec<u32>,
    /// Indices into `calls`.
    pub outgoing_calls: Vec<u32>,
    /// A missing analyzed successor or an explicitly unknown target prevents
    /// consumers from interpreting an empty edge list as a terminal node.
    pub has_unresolved_control: bool,
    /// At least one P-code effect on this instruction may alter control but
    /// has no exact Rust state semantics.
    pub may_have_opaque_control_effect: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCfgFunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    /// The selected instruction's ordered P-code effects and provenance.
    pub state: PcodeStateFunctionIr,
    pub nodes: Vec<PcodeCfgNode>,
    /// Ghidra fallthrough, branch and other non-call flow evidence.
    pub edges: Vec<PcodeCfgEdge>,
    /// Ghidra call evidence, including unresolved indirect targets.
    pub calls: Vec<PcodeCfgCall>,
    /// False for legacy v2 snapshots with no flow or call evidence, and also
    /// for a selected function whose exporter observed no such edges.
    pub flow_evidence_present: bool,
    pub cfg_completeness: PcodeCfgCompleteness,
}

type AddressKey = (String, u64);
type CallKey = (AddressKey, Option<AddressKey>, bool, bool);

fn address_key(address: &PcodeAddress) -> Result<AddressKey, String> {
    Ok((address.space.clone(), hex_u64(&address.offset)?))
}

fn call_key(call: &GhidraCallTarget) -> Result<CallKey, String> {
    Ok((
        address_key(&call.call_site)?,
        call.target.as_ref().map(address_key).transpose()?,
        call.conditional,
        call.computed,
    ))
}

impl GhidraSnapshot {
    /// Construct a bounded instruction CFG from a validated snapshot. Each
    /// state instruction becomes one node; no basic-block or path-completeness
    /// assertion is made. Missing v2 flow arrays produce unresolved nodes.
    pub fn pcode_cfg_ir(&self) -> Result<PcodeCfgFunctionIr, String> {
        validate_ghidra_snapshot(self, &self.binary_sha256)?;
        let state = self.pcode_function_ir()?.lower_state();
        let mut index = BTreeMap::new();
        let mut nodes = Vec::with_capacity(state.instructions.len());
        for (instruction_index, instruction) in state.instructions.iter().enumerate() {
            let address = instruction.address.clone();
            index.insert(address_key(&address)?, instruction_index as u32);
            nodes.push(PcodeCfgNode {
                instruction_index: instruction_index as u32,
                address,
                outgoing_edges: Vec::new(),
                outgoing_calls: Vec::new(),
                has_unresolved_control: false,
                may_have_opaque_control_effect: instruction.operations.iter().any(|operation| {
                    matches!(
                        &operation.effect,
                        PcodeEffect::Opaque {
                            may_change_control: true,
                            ..
                        }
                    )
                }),
            });
        }

        let mut edges = Vec::new();
        let mut call_evidence = self.selected_function.call_targets.clone();
        let mut call_keys = call_evidence
            .iter()
            .map(call_key)
            .collect::<Result<BTreeSet<_>, _>>()?;
        for evidence in &self.selected_function.flow_edges {
            if evidence.kind == GhidraFlowKind::Call {
                let call = GhidraCallTarget {
                    call_site: evidence.source.clone(),
                    target: evidence.target.clone(),
                    conditional: evidence.conditional,
                    computed: evidence.computed,
                };
                if call_keys.insert(call_key(&call)?) {
                    call_evidence.push(call);
                }
                continue;
            }
            let source_node = *index
                .get(&address_key(&evidence.source)?)
                .ok_or("validated flow source is missing from CFG nodes")?;
            let target_node = evidence
                .target
                .as_ref()
                .map(|target| address_key(target).map(|key| index.get(&key).copied()))
                .transpose()?
                .flatten();
            let edge_index = edges.len() as u32;
            edges.push(PcodeCfgEdge {
                source_node,
                target_node,
                evidence: evidence.clone(),
            });
            nodes[source_node as usize].outgoing_edges.push(edge_index);
        }

        let mut calls = Vec::with_capacity(call_evidence.len());
        for evidence in call_evidence {
            let source_node = *index
                .get(&address_key(&evidence.call_site)?)
                .ok_or("validated call site is missing from CFG nodes")?;
            let call_index = calls.len() as u32;
            calls.push(PcodeCfgCall {
                source_node,
                evidence,
            });
            nodes[source_node as usize].outgoing_calls.push(call_index);
        }

        for node in &mut nodes {
            let instruction = &state.instructions[node.instruction_index as usize];
            let raw_branch = instruction
                .operations
                .iter()
                .any(|operation| matches!(operation.source.opcode, 4..=6));
            let raw_call = instruction
                .operations
                .iter()
                .any(|operation| matches!(operation.source.opcode, 7 | 8));
            let raw_return = instruction
                .operations
                .iter()
                .any(|operation| operation.source.opcode == 10);
            let unknown_edge = node
                .outgoing_edges
                .iter()
                .any(|&i| edges[i as usize].evidence.target.is_none());
            let unknown_call = node
                .outgoing_calls
                .iter()
                .any(|&i| calls[i as usize].evidence.target.is_none());
            node.has_unresolved_control = unknown_edge
                || unknown_call
                || (raw_branch && node.outgoing_edges.is_empty())
                || (raw_call && node.outgoing_calls.is_empty())
                || (node.outgoing_edges.is_empty()
                    && node.outgoing_calls.is_empty()
                    && !raw_return);
        }

        Ok(PcodeCfgFunctionIr {
            schema_version: PCODE_CFG_IR_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            state,
            nodes,
            edges,
            calls,
            flow_evidence_present: !self.selected_function.flow_edges.is_empty()
                || !self.selected_function.call_targets.is_empty(),
            cfg_completeness: PcodeCfgCompleteness::Incomplete,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::parse_ghidra_snapshot;

    const DIGEST: &str = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";

    fn calls_fixture() -> GhidraSnapshot {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
        ));
        parse_ghidra_snapshot(bytes, DIGEST).unwrap()
    }

    #[test]
    fn real_call_fixture_separates_calls_from_cfg_edges() {
        let snapshot = calls_fixture();
        let cfg = snapshot.pcode_cfg_ir().unwrap();
        assert_eq!(cfg.schema_version, PCODE_CFG_IR_VERSION);
        assert_eq!(cfg.cfg_completeness, PcodeCfgCompleteness::Incomplete);
        assert!(cfg.flow_evidence_present);
        assert_eq!(cfg.nodes.len(), 4);
        assert_eq!(cfg.edges.len(), 3);
        assert_eq!(cfg.calls.len(), 1);
        assert!(
            cfg.edges
                .iter()
                .all(|edge| edge.evidence.kind != GhidraFlowKind::Call)
        );
        let call_node = cfg
            .nodes
            .iter()
            .find(|node| node.address.offset == "0x2013ad")
            .unwrap();
        assert_eq!(call_node.outgoing_edges.len(), 1);
        assert_eq!(call_node.outgoing_calls.len(), 1);
        let call = &cfg.calls[call_node.outgoing_calls[0] as usize];
        assert_eq!(call.evidence.target.as_ref().unwrap().offset, "0x2013a2");
        assert_eq!(call.source_node, call_node.instruction_index);
        let fallthrough = &cfg.edges[call_node.outgoing_edges[0] as usize];
        assert_eq!(fallthrough.evidence.kind, GhidraFlowKind::Fallthrough);
        assert_eq!(
            fallthrough.evidence.target.as_ref().unwrap().offset,
            "0x2013b2"
        );
        assert_eq!(fallthrough.target_node, Some(2));
        assert_eq!(cfg.state.instructions.len(), cfg.nodes.len());
        assert!(cfg.state.instructions.iter().any(|instruction| {
            instruction
                .operations
                .iter()
                .any(|operation| operation.source.mnemonic == "CALL")
        }));
        let roundtrip: PcodeCfgFunctionIr =
            serde_json::from_slice(&serde_json::to_vec(&cfg).unwrap()).unwrap();
        assert_eq!(roundtrip, cfg);
    }

    #[test]
    fn old_v2_fixture_has_no_invented_fallthrough_edges() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_snapshot_v2.json"
        ));
        let cfg = parse_ghidra_snapshot(bytes, DIGEST)
            .unwrap()
            .pcode_cfg_ir()
            .unwrap();
        assert!(!cfg.flow_evidence_present);
        assert!(cfg.edges.is_empty());
        assert!(cfg.calls.is_empty());
        let branch = cfg
            .nodes
            .iter()
            .find(|node| node.address.offset == "0x201382")
            .unwrap();
        assert!(branch.has_unresolved_control);
    }

    #[test]
    fn unresolved_computed_target_stays_visible_and_complete_claim_is_rejected() {
        let mut snapshot = calls_fixture();
        let call = &mut snapshot.selected_function.call_targets[0];
        call.target = None;
        call.computed = true;
        let call_edge = snapshot
            .selected_function
            .flow_edges
            .iter_mut()
            .find(|edge| edge.kind == GhidraFlowKind::Call)
            .unwrap();
        call_edge.target = None;
        call_edge.computed = true;
        let cfg = snapshot.pcode_cfg_ir().unwrap();
        assert!(cfg.calls[0].evidence.computed);
        assert!(cfg.calls[0].evidence.target.is_none());
        let node = &cfg.nodes[cfg.calls[0].source_node as usize];
        assert!(node.has_unresolved_control);
        let mut json = serde_json::to_value(&cfg).unwrap();
        json["cfg_completeness"] = serde_json::json!("complete");
        assert!(serde_json::from_value::<PcodeCfgFunctionIr>(json).is_err());
    }
}
