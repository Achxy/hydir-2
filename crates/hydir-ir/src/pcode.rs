//! Bounded Ghidra raw-P-code interchange and its versioned Hydir artifact.
//!
//! Import preserves Ghidra address-space names and operation order. No P-code
//! operation is claimed to have Hydir state semantics at this boundary.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub mod cfg;
pub mod semantics;
pub mod state;
pub use cfg::{
    PCODE_CFG_IR_VERSION, PcodeCfgCall, PcodeCfgCompleteness, PcodeCfgEdge, PcodeCfgFunctionIr,
    PcodeCfgNode,
};
pub use semantics::{
    PCODE_SEMANTIC_IR_VERSION, PcodeEffect, PcodeExactOp, PcodeOpaqueClass,
    PcodeSemanticDiagnostic, PcodeSemanticFunctionIr, PcodeSemanticInstruction,
    PcodeSemanticOperation,
};
pub use state::{
    PCODE_STATE_IR_VERSION, PcodeStateAccess, PcodeStateAccessKind, PcodeStateFunctionIr,
    PcodeStateInstruction, PcodeStateOperation,
};

pub const GHIDRA_SNAPSHOT_VERSION: u32 = 2;
pub const PCODE_IR_VERSION: u32 = 1;
pub const MAX_GHIDRA_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 65_536;
const MAX_INSTRUCTIONS: usize = 16_384;
const MAX_OPERATIONS: usize = 262_144;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeAddress {
    pub space: String,
    pub offset: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeVarnode {
    pub space: String,
    pub offset: String,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeOperation {
    pub mnemonic: String,
    pub opcode: u32,
    pub sequence_index: u32,
    pub sequence_time: i32,
    pub source_address: PcodeAddress,
    #[serde(default)]
    pub userop_name: Option<String>,
    pub output: Option<PcodeVarnode>,
    pub inputs: Vec<PcodeVarnode>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeInstruction {
    pub address: PcodeAddress,
    /// Effective instruction bytes in order, without a prefix.
    pub bytes: String,
    /// Original parsed bytes before Ghidra length/flow overrides.
    pub parsed_bytes: String,
    pub mnemonic: String,
    pub pcode: Vec<PcodeOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraProgram {
    pub name: String,
    pub ghidra_version: String,
    pub language_id: String,
    pub compiler_spec_id: String,
    pub image_base: PcodeAddress,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraAddressSpace {
    pub name: String,
    pub id: i32,
    #[serde(rename = "type")]
    pub space_type: i32,
    pub addressable_unit_size: u32,
    pub pointer_size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraFunctionIndexEntry {
    pub entry: PcodeAddress,
    pub name: String,
    pub size: u64,
}

/// Ghidra's analyzed instruction flow, including overrides and references.
/// A missing target is an unresolved flow, not a proven absent edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GhidraFlowKind {
    Fallthrough,
    Branch,
    Call,
    Other,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraFlowEdge {
    pub source: PcodeAddress,
    pub target: Option<PcodeAddress>,
    pub kind: GhidraFlowKind,
    pub conditional: bool,
    pub computed: bool,
}

/// Call evidence from Ghidra instruction flow; indirect calls may have both
/// known candidate targets and an unresolved target.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraCallTarget {
    pub call_site: PcodeAddress,
    pub target: Option<PcodeAddress>,
    pub conditional: bool,
    pub computed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraSelectedFunction {
    pub entry: PcodeAddress,
    pub instructions: Vec<PcodeInstruction>,
    /// Optional in v2; legacy snapshots without this evidence remain readable.
    #[serde(default)]
    pub flow_edges: Vec<GhidraFlowEdge>,
    /// Optional in v2; derived from Ghidra's analyzed call flows.
    #[serde(default)]
    pub call_targets: Vec<GhidraCallTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GhidraSnapshot {
    pub schema_version: u32,
    pub source: String,
    pub flow_overrides_applied: bool,
    pub binary_sha256: String,
    pub program: GhidraProgram,
    pub address_spaces: Vec<GhidraAddressSpace>,
    pub functions: Vec<GhidraFunctionIndexEntry>,
    pub selected_function: GhidraSelectedFunction,
}

/// The imported function is source-linked but has not yet been lowered or
/// tested for semantic equivalence with the original machine code.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeFunctionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub source: String,
    pub flow_overrides_applied: bool,
    pub ghidra_version: String,
    pub language_id: String,
    pub compiler_spec_id: String,
    pub address_spaces: Vec<GhidraAddressSpace>,
    pub entry: PcodeAddress,
    pub name: String,
    pub instructions: Vec<PcodeInstruction>,
    pub semantic_fidelity: super::SemanticFidelity,
    pub verification: super::VerificationStatus,
}

fn bounded_text(value: &str, label: &str, max: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} must be nonempty, printable, and at most {max} bytes"
        ));
    }
    Ok(())
}

fn offset(address: &PcodeAddress) -> Result<u64, String> {
    bounded_text(&address.space, "P-code address space", 128)?;
    hex_u64(&address.offset)
}

fn hex_u64(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("expected lowercase 0x-prefixed offset, got {value:?}"))?;
    if digits.is_empty()
        || digits.len() > 16
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("invalid lowercase hexadecimal offset {value:?}"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| format!("invalid offset {value:?}"))
}

fn validate_varnode(varnode: &PcodeVarnode) -> Result<(), String> {
    bounded_text(&varnode.space, "P-code varnode space", 128)?;
    hex_u64(&varnode.offset)?;
    if !(1..=4096).contains(&varnode.size) {
        return Err("P-code varnode size must be 1..=4096 bytes".to_owned());
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("binary_sha256 must be 64 lowercase hex characters".to_owned());
    }
    Ok(())
}

pub fn parse_ghidra_snapshot(bytes: &[u8], binary_sha256: &str) -> Result<GhidraSnapshot, String> {
    if bytes.is_empty() || bytes.len() > MAX_GHIDRA_SNAPSHOT_BYTES {
        return Err(format!(
            "Ghidra snapshot must be 1..={MAX_GHIDRA_SNAPSHOT_BYTES} bytes"
        ));
    }
    let snapshot: GhidraSnapshot = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid Ghidra snapshot JSON: {error}"))?;
    validate_ghidra_snapshot(&snapshot, binary_sha256)?;
    Ok(snapshot)
}

pub fn validate_ghidra_snapshot(
    snapshot: &GhidraSnapshot,
    binary_sha256: &str,
) -> Result<(), String> {
    if snapshot.schema_version != GHIDRA_SNAPSHOT_VERSION || snapshot.source != "ghidra" {
        return Err("unsupported Ghidra snapshot schema or source".to_owned());
    }
    if !snapshot.flow_overrides_applied {
        return Err("Ghidra snapshot must record applied flow overrides".to_owned());
    }
    validate_digest(binary_sha256)?;
    validate_digest(&snapshot.binary_sha256)?;
    if snapshot.binary_sha256 != binary_sha256 {
        return Err("Ghidra snapshot binary digest does not match supplied binary".to_owned());
    }
    bounded_text(&snapshot.program.name, "program name", 4096)?;
    bounded_text(&snapshot.program.ghidra_version, "Ghidra version", 128)?;
    bounded_text(&snapshot.program.language_id, "Ghidra language ID", 256)?;
    bounded_text(
        &snapshot.program.compiler_spec_id,
        "Ghidra compiler spec ID",
        256,
    )?;
    offset(&snapshot.program.image_base)?;
    if snapshot.address_spaces.is_empty() || snapshot.address_spaces.len() > 256 {
        return Err("Ghidra snapshot must have 1..=256 address spaces".to_owned());
    }
    let mut space_names = BTreeSet::new();
    let mut space_ids = BTreeSet::new();
    for space in &snapshot.address_spaces {
        bounded_text(&space.name, "Ghidra address space name", 128)?;
        if !space_names.insert(space.name.as_str()) || !space_ids.insert(space.id) {
            return Err("duplicate Ghidra address space name or ID".to_owned());
        }
        if space.addressable_unit_size == 0
            || space.addressable_unit_size > 4096
            || space.pointer_size > 64
        {
            return Err("Ghidra address space unit or pointer size exceeds limit".to_owned());
        }
    }
    if !space_names.contains(snapshot.program.image_base.space.as_str()) {
        return Err("image base references an unknown address space".to_owned());
    }
    if snapshot.functions.is_empty() || snapshot.functions.len() > MAX_FUNCTIONS {
        return Err(format!(
            "Ghidra function index must have 1..={MAX_FUNCTIONS} entries"
        ));
    }
    let mut entries = BTreeSet::new();
    for function in &snapshot.functions {
        let key = (function.entry.space.as_str(), offset(&function.entry)?);
        if !space_names.contains(key.0) {
            return Err("function entry references an unknown address space".to_owned());
        }
        bounded_text(&function.name, "function name", 4096)?;
        if function.size == 0 {
            return Err("Ghidra function size must be nonzero".to_owned());
        }
        if !entries.insert((function.entry.space.clone(), key.1)) {
            return Err("duplicate Ghidra function entry".to_owned());
        }
    }
    let selected_key = (
        snapshot.selected_function.entry.space.clone(),
        offset(&snapshot.selected_function.entry)?,
    );
    if !entries.contains(&selected_key) {
        return Err("selected function is absent from Ghidra function index".to_owned());
    }
    let instructions = &snapshot.selected_function.instructions;
    if instructions.is_empty() || instructions.len() > MAX_INSTRUCTIONS {
        return Err(format!(
            "selected function must have 1..={MAX_INSTRUCTIONS} instructions"
        ));
    }
    let mut previous_instruction = None;
    let mut instruction_addresses = BTreeSet::new();
    let mut operation_count = 0usize;
    for instruction in instructions {
        let address = offset(&instruction.address)?;
        if !space_names.contains(instruction.address.space.as_str()) {
            return Err("instruction references an unknown address space".to_owned());
        }
        if instruction.address.space != selected_key.0 {
            return Err("instruction address space differs from function entry".to_owned());
        }
        if previous_instruction.is_some_and(|prior| prior >= address) {
            return Err("Ghidra instructions must be strictly sorted by address".to_owned());
        }
        previous_instruction = Some(address);
        instruction_addresses.insert((instruction.address.space.clone(), address));
        bounded_text(&instruction.mnemonic, "instruction mnemonic", 128)?;
        for bytes in [&instruction.bytes, &instruction.parsed_bytes] {
            if bytes.is_empty()
                || bytes.len() > 64
                || bytes.len() % 2 != 0
                || !bytes
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err("instruction bytes must be 1..=32 bytes of lowercase hex".to_owned());
            }
        }
        operation_count = operation_count.saturating_add(instruction.pcode.len());
        if instruction.pcode.len() > 256 || operation_count > MAX_OPERATIONS {
            return Err("Ghidra snapshot exceeds P-code operation limit".to_owned());
        }
        for (index, operation) in instruction.pcode.iter().enumerate() {
            if operation.sequence_index as usize != index {
                return Err(
                    "P-code operations must have contiguous per-instruction sequence indices"
                        .to_owned(),
                );
            }
            bounded_text(&operation.mnemonic, "P-code mnemonic", 128)?;
            if let Some(name) = &operation.userop_name {
                bounded_text(name, "P-code userop name", 256)?;
            }
            if operation.sequence_time < 0 {
                return Err("P-code sequence time must be nonnegative".to_owned());
            }
            offset(&operation.source_address)?;
            if !space_names.contains(operation.source_address.space.as_str()) {
                return Err("P-code source references an unknown address space".to_owned());
            }
            if operation.opcode > 65_535 || operation.inputs.len() > 256 {
                return Err("P-code opcode or input count exceeds limit".to_owned());
            }
            if let Some(output) = &operation.output {
                validate_varnode(output)?;
                if !space_names.contains(output.space.as_str()) {
                    return Err("P-code output references an unknown address space".to_owned());
                }
            }
            for input in &operation.inputs {
                validate_varnode(input)?;
                if !space_names.contains(input.space.as_str()) {
                    return Err("P-code input references an unknown address space".to_owned());
                }
            }
        }
    }
    if snapshot.selected_function.flow_edges.len() > MAX_OPERATIONS
        || snapshot.selected_function.call_targets.len() > MAX_OPERATIONS
    {
        return Err("Ghidra flow or call evidence exceeds limit".to_owned());
    }
    let mut flow_keys = BTreeSet::new();
    for edge in &snapshot.selected_function.flow_edges {
        let source = (edge.source.space.clone(), offset(&edge.source)?);
        if !instruction_addresses.contains(&source) {
            return Err("Ghidra flow source is not a selected instruction".to_owned());
        }
        let target = match &edge.target {
            Some(target) => {
                let value = (target.space.clone(), offset(target)?);
                if !space_names.contains(value.0.as_str()) {
                    return Err("Ghidra flow target references an unknown address space".to_owned());
                }
                Some(value)
            }
            None => None,
        };
        if edge.kind == GhidraFlowKind::Fallthrough && (edge.conditional || edge.computed) {
            return Err("Ghidra fallthrough cannot be conditional or computed".to_owned());
        }
        if !flow_keys.insert((source, target, edge.kind, edge.conditional, edge.computed)) {
            return Err("duplicate Ghidra flow edge".to_owned());
        }
    }
    let mut call_keys = BTreeSet::new();
    for call in &snapshot.selected_function.call_targets {
        let source = (call.call_site.space.clone(), offset(&call.call_site)?);
        if !instruction_addresses.contains(&source) {
            return Err("Ghidra call site is not a selected instruction".to_owned());
        }
        let target = match &call.target {
            Some(target) => {
                let value = (target.space.clone(), offset(target)?);
                if !space_names.contains(value.0.as_str()) {
                    return Err("Ghidra call target references an unknown address space".to_owned());
                }
                Some(value)
            }
            None => None,
        };
        let key = (source, target, call.conditional, call.computed);
        if !call_keys.insert(key.clone()) {
            return Err("duplicate Ghidra call target".to_owned());
        }
        if !flow_keys.is_empty()
            && !flow_keys.contains(&(key.0, key.1, GhidraFlowKind::Call, key.2, key.3))
        {
            return Err("Ghidra call target has no matching call flow edge".to_owned());
        }
    }
    Ok(())
}

impl GhidraSnapshot {
    pub fn pcode_function_ir(&self) -> Result<PcodeFunctionIr, String> {
        validate_ghidra_snapshot(self, &self.binary_sha256)?;
        let selected_offset = offset(&self.selected_function.entry)?;
        let function = self
            .functions
            .iter()
            .find(|function| {
                function.entry.space == self.selected_function.entry.space
                    && hex_u64(&function.entry.offset).ok() == Some(selected_offset)
            })
            .ok_or_else(|| "selected function is absent from Ghidra function index".to_owned())?;
        Ok(PcodeFunctionIr {
            schema_version: PCODE_IR_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            source: "ghidra_raw_pcode".to_owned(),
            flow_overrides_applied: self.flow_overrides_applied,
            ghidra_version: self.program.ghidra_version.clone(),
            language_id: self.program.language_id.clone(),
            compiler_spec_id: self.program.compiler_spec_id.clone(),
            address_spaces: self.address_spaces.clone(),
            entry: self.selected_function.entry.clone(),
            name: function.name.clone(),
            instructions: self.selected_function.instructions.clone(),
            semantic_fidelity: super::SemanticFidelity::Unknown,
            verification: super::VerificationStatus::NotRun,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> serde_json::Value {
        json!({
            "schema_version": 2, "source": "ghidra", "flow_overrides_applied": true,
            "binary_sha256": "a".repeat(64),
            "program": {"name": "fixture", "ghidra_version": "12.1.4", "language_id": "x86:LE:64:default", "compiler_spec_id": "gcc", "image_base": {"space": "ram", "offset": "0x400000"}},
            "address_spaces": [
                {"name": "ram", "id": 0, "type": 1, "addressable_unit_size": 1, "pointer_size": 8},
                {"name": "const", "id": 1, "type": 0, "addressable_unit_size": 1, "pointer_size": 8}
            ],
            "functions": [{"entry": {"space": "ram", "offset": "0x401000"}, "name": "f", "size": 1}],
            "selected_function": {"entry": {"space": "ram", "offset": "0x401000"}, "instructions": [{
                "address": {"space": "ram", "offset": "0x401000"}, "bytes": "c3", "parsed_bytes": "c3", "mnemonic": "RET",
                "pcode": [{"mnemonic": "RETURN", "opcode": 10, "sequence_index": 0, "sequence_time": 0,
                    "source_address": {"space": "ram", "offset": "0x401000"}, "output": null,
                    "inputs": [{"space": "const", "offset": "0x0", "size": 8}]}]
            }]}
        })
    }

    #[test]
    fn imports_bound_raw_pcode_without_claiming_equivalence() {
        let snapshot =
            parse_ghidra_snapshot(&serde_json::to_vec(&fixture()).unwrap(), &"a".repeat(64))
                .unwrap();
        let ir = snapshot.pcode_function_ir().unwrap();
        assert_eq!(ir.instructions[0].pcode[0].sequence_index, 0);
        assert_eq!(ir.instructions[0].pcode[0].inputs[0].space, "const");
        assert_eq!(
            ir.semantic_fidelity,
            super::super::SemanticFidelity::Unknown
        );
    }

    #[test]
    fn rejects_wrong_binary_and_broken_order() {
        let mut value = fixture();
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(
            parse_ghidra_snapshot(&bytes, &"b".repeat(64))
                .unwrap_err()
                .contains("digest")
        );
        value["selected_function"]["instructions"][0]["pcode"][0]["sequence_index"] = json!(1);
        assert!(
            parse_ghidra_snapshot(&serde_json::to_vec(&value).unwrap(), &"a".repeat(64))
                .unwrap_err()
                .contains("sequence")
        );
    }

    #[test]
    fn optional_flow_and_call_evidence_is_validated_without_bumping_v2() {
        let mut value = fixture();
        let source = json!({"space": "ram", "offset": "0x401000"});
        let target = json!({"space": "ram", "offset": "0x402000"});
        value["selected_function"]["flow_edges"] = json!([{
            "source": source, "target": target, "kind": "call",
            "conditional": false, "computed": false
        }]);
        value["selected_function"]["call_targets"] = json!([{
            "call_site": source, "target": target,
            "conditional": false, "computed": false
        }]);
        let snapshot =
            parse_ghidra_snapshot(&serde_json::to_vec(&value).unwrap(), &"a".repeat(64)).unwrap();
        assert_eq!(snapshot.schema_version, GHIDRA_SNAPSHOT_VERSION);
        assert_eq!(snapshot.selected_function.flow_edges.len(), 1);
        assert_eq!(snapshot.selected_function.call_targets.len(), 1);

        let mut bad_source = value.clone();
        bad_source["selected_function"]["flow_edges"][0]["source"]["offset"] = json!("0x401001");
        assert!(
            parse_ghidra_snapshot(&serde_json::to_vec(&bad_source).unwrap(), &"a".repeat(64))
                .unwrap_err()
                .contains("flow source")
        );

        let mut bad_target = value.clone();
        bad_target["selected_function"]["call_targets"][0]["target"]["space"] = json!("unknown");
        assert!(
            parse_ghidra_snapshot(&serde_json::to_vec(&bad_target).unwrap(), &"a".repeat(64))
                .unwrap_err()
                .contains("call target")
        );

        let mut mismatch = value.clone();
        mismatch["selected_function"]["call_targets"][0]["computed"] = json!(true);
        assert!(
            parse_ghidra_snapshot(&serde_json::to_vec(&mismatch).unwrap(), &"a".repeat(64))
                .unwrap_err()
                .contains("matching call flow")
        );

        let mut duplicate = value.clone();
        let edge = duplicate["selected_function"]["flow_edges"][0].clone();
        duplicate["selected_function"]["flow_edges"] = json!([edge.clone(), edge]);
        assert!(
            parse_ghidra_snapshot(&serde_json::to_vec(&duplicate).unwrap(), &"a".repeat(64))
                .unwrap_err()
                .contains("duplicate Ghidra flow")
        );
    }

    #[test]
    fn real_ghidra_call_fixture_keeps_call_and_fallthrough_separate() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
        ));
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        let snapshot = parse_ghidra_snapshot(bytes, digest).unwrap();
        assert_eq!(snapshot.selected_function.entry.offset, "0x2013a9");
        let calls = &snapshot.selected_function.call_targets;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].call_site.offset, "0x2013ad");
        assert_eq!(calls[0].target.as_ref().unwrap().offset, "0x2013a2");
        assert!(!calls[0].computed);
        let edges = &snapshot.selected_function.flow_edges;
        assert!(edges.iter().any(|edge| {
            edge.source.offset == "0x2013ad"
                && edge.kind == GhidraFlowKind::Call
                && edge
                    .target
                    .as_ref()
                    .is_some_and(|target| target.offset == "0x2013a2")
        }));
        assert!(edges.iter().any(|edge| {
            edge.source.offset == "0x2013ad"
                && edge.kind == GhidraFlowKind::Fallthrough
                && edge
                    .target
                    .as_ref()
                    .is_some_and(|target| target.offset == "0x2013b2")
        }));
    }
}
