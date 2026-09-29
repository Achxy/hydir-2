//! Static operation inventory for a validated Ghidra raw-P-code snapshot.
//! Counts describe Hydir's current P-code lowering, not binary equivalence.

use super::{
    GhidraAddressSpace, GhidraSnapshot, PcodeAddress, PcodeEffect, PcodeExactOp, PcodeOpaqueClass,
    PcodeOperation, hex_u64,
};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PCODE_COVERAGE_VERSION: u32 = 1;
pub const PCODE_CAPABILITY_VERSION: u32 = 1;
const MAX_OPAQUE_SITES: usize = 256;
const MAX_CAPABILITY_SITES: usize = 256;

/// A static inventory of what the selected raw-P-code function can attempt.
/// Every count describes the selected snapshot, never all code in the binary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCapabilityReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    /// SHA-256 of this validated snapshot serialized with serde_json.
    pub snapshot_sha256: String,
    pub snapshot_source: String,
    pub ghidra_version: String,
    pub language_id: String,
    pub entry: PcodeAddress,
    pub instructions: usize,
    pub operations: usize,
    pub discovery: PcodeDiscoveryCapability,
    pub execution: PcodeExecutionCapability,
    pub memory: PcodeMemoryCapability,
    pub calls: PcodeCallCapability,
    /// Source-linked static boundaries; includes conditional runtime stops.
    pub stop_sites: Vec<PcodeCapabilitySite>,
    pub omitted_stop_sites: usize,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeDiscoveryCapability {
    pub instruction_nodes: usize,
    /// An analyzed edge whose target is among the selected instructions.
    pub known_edges: usize,
    pub unresolved_nodes: usize,
    /// Call target addresses observed by Ghidra, including computed candidates.
    pub known_calls: usize,
    pub unresolved_calls: usize,
    /// Ghidra flow evidence is not an independent completeness proof.
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeExecutionCapability {
    /// Exact value effects in the Rust evaluator, subject to known inputs.
    pub exact_value_operations: usize,
    pub conditional_memory_operations: usize,
    pub conditional_control_operations: usize,
    /// Operations that end or block a single-function concrete path.
    pub stopping_operations: usize,
    /// Value effects with supported LLVM widths/kinds, before module checks.
    pub llvm_candidate_values: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeMemoryCapability {
    pub reads: usize,
    pub writes: usize,
    /// Requires a concrete RAM window or validated read-only image and bytes.
    pub conditional_reads: usize,
    pub conditional_writes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCallCapability {
    pub call_operations: usize,
    /// Noncomputed Ghidra call target; a callee snapshot may still be absent.
    pub direct_targets: usize,
    /// Includes computed calls even when one candidate target was observed.
    pub unresolved_targets: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeCapabilityKind {
    Discovery,
    Value,
    MemoryRead,
    MemoryWrite,
    Control,
    Call,
    UserOperation,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeCapabilityStatus {
    RequiresConcreteState,
    Stops,
    Unresolved,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCapabilitySite {
    pub address: PcodeAddress,
    /// None for a CFG node with no corresponding raw operation.
    pub sequence_index: Option<u32>,
    pub opcode: Option<u32>,
    pub mnemonic: String,
    pub kind: PcodeCapabilityKind,
    pub status: PcodeCapabilityStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeOpcodeCoverage {
    pub opcode: u32,
    pub mnemonic: String,
    pub operations: usize,
    pub exact_assignments: usize,
    pub opaque_effects: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeOpaqueSite {
    pub address: PcodeAddress,
    pub sequence_index: u32,
    pub opcode: u32,
    pub mnemonic: String,
    pub class: PcodeOpaqueClass,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCoverageReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub entry: PcodeAddress,
    pub instructions: usize,
    pub operations: usize,
    /// Pure value assignments modelled exactly under Hydir's P-code rules.
    pub exact_assignments: usize,
    /// Includes control, memory, user operations, and unmodelled values.
    pub opaque_effects: usize,
    pub by_opcode: Vec<PcodeOpcodeCoverage>,
    /// Source-linked examples, bounded to keep the artifact manageable.
    pub opaque_sites: Vec<PcodeOpaqueSite>,
    pub omitted_opaque_sites: usize,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

impl GhidraSnapshot {
    pub fn pcode_coverage_report(&self) -> Result<PcodeCoverageReport, String> {
        let semantics = self.pcode_function_ir()?.lower_semantics();
        let mut by_opcode = BTreeMap::<(u32, String), PcodeOpcodeCoverage>::new();
        let mut opaque_sites = Vec::new();
        let mut operations = 0;
        let mut exact_assignments = 0;
        let mut opaque_effects = 0;
        for instruction in &semantics.instructions {
            for operation in &instruction.operations {
                operations += 1;
                let source = &operation.source;
                let row = by_opcode
                    .entry((source.opcode, source.mnemonic.clone()))
                    .or_insert_with(|| PcodeOpcodeCoverage {
                        opcode: source.opcode,
                        mnemonic: source.mnemonic.clone(),
                        operations: 0,
                        exact_assignments: 0,
                        opaque_effects: 0,
                    });
                row.operations += 1;
                match &operation.effect {
                    PcodeEffect::Assign { .. } => {
                        exact_assignments += 1;
                        row.exact_assignments += 1;
                    }
                    PcodeEffect::Opaque { class, reason, .. } => {
                        opaque_effects += 1;
                        row.opaque_effects += 1;
                        if opaque_sites.len() < MAX_OPAQUE_SITES {
                            opaque_sites.push(PcodeOpaqueSite {
                                address: source.source_address.clone(),
                                sequence_index: source.sequence_index,
                                opcode: source.opcode,
                                mnemonic: source.mnemonic.clone(),
                                class: *class,
                                reason: reason.clone(),
                            });
                        }
                    }
                }
            }
        }
        Ok(PcodeCoverageReport {
            schema_version: PCODE_COVERAGE_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            entry: semantics.entry,
            instructions: semantics.instructions.len(),
            operations,
            exact_assignments,
            opaque_effects,
            by_opcode: by_opcode.into_values().collect(),
            omitted_opaque_sites: opaque_effects - opaque_sites.len(),
            opaque_sites,
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        })
    }

    /// Inspect the selected function without executing it or claiming binary
    /// equivalence. Conditional operations may still stop on a given input.
    pub fn pcode_capability_report(&self) -> Result<PcodeCapabilityReport, String> {
        let cfg = self.pcode_cfg_ir()?;
        let semantics = self.pcode_function_ir()?.lower_semantics();
        let snapshot_sha256 = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).map_err(|error| error.to_string())?)
        );
        let discovery = PcodeDiscoveryCapability {
            instruction_nodes: cfg.nodes.len(),
            known_edges: cfg
                .edges
                .iter()
                .filter(|edge| edge.target_node.is_some())
                .count(),
            unresolved_nodes: cfg
                .nodes
                .iter()
                .filter(|node| {
                    node.has_unresolved_control
                        || node
                            .outgoing_calls
                            .iter()
                            .any(|&index| cfg.calls[index as usize].evidence.computed)
                })
                .count(),
            known_calls: cfg
                .calls
                .iter()
                .filter(|call| call.evidence.target.is_some())
                .count(),
            unresolved_calls: cfg
                .calls
                .iter()
                .filter(|call| call.evidence.target.is_none() || call.evidence.computed)
                .count(),
            complete: false,
        };
        let mut execution = PcodeExecutionCapability {
            exact_value_operations: 0,
            conditional_memory_operations: 0,
            conditional_control_operations: 0,
            stopping_operations: 0,
            llvm_candidate_values: 0,
        };
        let mut memory = PcodeMemoryCapability {
            reads: 0,
            writes: 0,
            conditional_reads: 0,
            conditional_writes: 0,
        };
        let mut calls = PcodeCallCapability {
            call_operations: 0,
            direct_targets: cfg
                .calls
                .iter()
                .filter(|call| call.evidence.target.is_some() && !call.evidence.computed)
                .count(),
            unresolved_targets: discovery.unresolved_calls,
        };
        let mut sites = Vec::new();
        let mut site_count: usize = 0;
        for node in &cfg.nodes {
            if node.has_unresolved_control
                || node
                    .outgoing_calls
                    .iter()
                    .any(|&index| cfg.calls[index as usize].evidence.computed)
            {
                site_count += 1;
                push_capability_site(
                    &mut sites,
                    PcodeCapabilitySite {
                        address: node.address.clone(),
                        sequence_index: None,
                        opcode: None,
                        mnemonic: "FLOW".to_owned(),
                        kind: PcodeCapabilityKind::Discovery,
                        status: PcodeCapabilityStatus::Unresolved,
                        reason: "analyzed control flow has a missing or unselected successor"
                            .to_owned(),
                    },
                );
            }
        }
        for instruction in &semantics.instructions {
            for operation in &instruction.operations {
                let source = &operation.source;
                let capability = match &operation.effect {
                    PcodeEffect::Assign {
                        operation: exact,
                        result_width_bits,
                    } => {
                        execution.exact_value_operations += 1;
                        if llvm_value_candidate(*exact, *result_width_bits, source) {
                            execution.llvm_candidate_values += 1;
                        }
                        None
                    }
                    PcodeEffect::Opaque { class, reason, .. } => {
                        let result = classify_opaque(source, *class, reason, &self.address_spaces);
                        match result.0 {
                            PcodeCapabilityKind::MemoryRead => {
                                memory.reads += 1;
                                if result.1 == PcodeCapabilityStatus::RequiresConcreteState {
                                    memory.conditional_reads += 1;
                                    execution.conditional_memory_operations += 1;
                                }
                            }
                            PcodeCapabilityKind::MemoryWrite => {
                                memory.writes += 1;
                                if result.1 == PcodeCapabilityStatus::RequiresConcreteState {
                                    memory.conditional_writes += 1;
                                    execution.conditional_memory_operations += 1;
                                }
                            }
                            PcodeCapabilityKind::Control => {
                                if result.1 == PcodeCapabilityStatus::RequiresConcreteState {
                                    execution.conditional_control_operations += 1;
                                }
                            }
                            PcodeCapabilityKind::Call => calls.call_operations += 1,
                            _ => {}
                        }
                        if result.1 == PcodeCapabilityStatus::Stops {
                            execution.stopping_operations += 1;
                        }
                        Some(result)
                    }
                };
                if let Some((kind, status, reason)) = capability {
                    site_count += 1;
                    push_capability_site(
                        &mut sites,
                        PcodeCapabilitySite {
                            address: source.source_address.clone(),
                            sequence_index: Some(source.sequence_index),
                            opcode: Some(source.opcode),
                            mnemonic: source.mnemonic.clone(),
                            kind,
                            status,
                            reason,
                        },
                    );
                }
            }
        }
        let operations = semantics
            .instructions
            .iter()
            .map(|instruction| instruction.operations.len())
            .sum();
        Ok(PcodeCapabilityReport {
            schema_version: PCODE_CAPABILITY_VERSION,
            binary_sha256: self.binary_sha256.clone(),
            snapshot_sha256,
            snapshot_source: self.source.clone(),
            ghidra_version: self.program.ghidra_version.clone(),
            language_id: self.program.language_id.clone(),
            entry: semantics.entry,
            instructions: semantics.instructions.len(),
            operations,
            discovery,
            execution,
            memory,
            calls,
            stop_sites: sites,
            omitted_stop_sites: site_count.saturating_sub(MAX_CAPABILITY_SITES),
            semantic_fidelity: SemanticFidelity::Unknown,
            verification: VerificationStatus::NotRun,
        })
    }
}

fn push_capability_site(sites: &mut Vec<PcodeCapabilitySite>, site: PcodeCapabilitySite) {
    if sites.len() < MAX_CAPABILITY_SITES {
        sites.push(site);
    }
}

fn llvm_value_candidate(kind: PcodeExactOp, result_bits: u32, source: &PcodeOperation) -> bool {
    let wide = result_bits > 64 || source.inputs.iter().any(|input| input.size > 8);
    !wide
        || matches!(
            kind,
            PcodeExactOp::Copy
                | PcodeExactOp::ZeroExtend
                | PcodeExactOp::SignExtend
                | PcodeExactOp::TwosComplement
                | PcodeExactOp::BitwiseNegate
                | PcodeExactOp::Piece
                | PcodeExactOp::Multiply
                | PcodeExactOp::Subpiece
                | PcodeExactOp::Add
                | PcodeExactOp::Sub
                | PcodeExactOp::Xor
                | PcodeExactOp::And
                | PcodeExactOp::Or
                | PcodeExactOp::Equal
                | PcodeExactOp::NotEqual
                | PcodeExactOp::UnsignedLess
                | PcodeExactOp::UnsignedLessEqual
                | PcodeExactOp::SignedLess
                | PcodeExactOp::SignedLessEqual
                | PcodeExactOp::ShiftLeft
                | PcodeExactOp::LogicalShiftRight
                | PcodeExactOp::ArithmeticShiftRight
                | PcodeExactOp::PackSignedWordsToBytes
        )
}

fn classify_opaque(
    source: &PcodeOperation,
    class: PcodeOpaqueClass,
    lowered_reason: &str,
    spaces: &[GhidraAddressSpace],
) -> (PcodeCapabilityKind, PcodeCapabilityStatus, String) {
    use PcodeCapabilityKind as Kind;
    use PcodeCapabilityStatus as Status;
    match class {
        PcodeOpaqueClass::MemoryRead | PcodeOpaqueClass::MemoryWrite => {
            let kind = if class == PcodeOpaqueClass::MemoryRead {
                Kind::MemoryRead
            } else {
                Kind::MemoryWrite
            };
            match concrete_memory_shape(source, spaces) {
                Ok(()) => (
                    kind,
                    Status::RequiresConcreteState,
                    "requires a bound RAM window or validated image, a known address, and known input bytes; access can stop at runtime".to_owned(),
                ),
                Err(reason) => (kind, Status::Stops, reason),
            }
        }
        PcodeOpaqueClass::ControlTransfer => match (source.opcode, source.mnemonic.as_str()) {
            (4, "BRANCH") | (5, "CBRANCH") | (6, "BRANCHIND")
                if branch_shape_supported(source, spaces) =>
            {
                (
                    Kind::Control,
                    Status::RequiresConcreteState,
                    "requires a selected target and, for conditional or indirect branches, known input bytes; may stop on unresolved flow".to_owned(),
                )
            }
            (7, "CALL") | (8, "CALLIND") if call_shape_supported(source) => (
                Kind::Call,
                Status::Stops,
                "ends a single-function path; an interprocedural run requires a loaded callee snapshot and bounded call depth".to_owned(),
            ),
            (10, "RETURN") if call_shape_supported(source) => (
                Kind::Control,
                Status::Stops,
                "terminates the selected function path".to_owned(),
            ),
            _ => (
                Kind::Control,
                Status::Stops,
                "control-transfer shape has no checked path semantics".to_owned(),
            ),
        },
        PcodeOpaqueClass::UserOperation => (
            Kind::UserOperation,
            Status::Stops,
            lowered_reason.to_owned(),
        ),
        PcodeOpaqueClass::UnmodelledValue => (
            Kind::Value,
            Status::Stops,
            lowered_reason.to_owned(),
        ),
        PcodeOpaqueClass::Unknown => (
            Kind::Unknown,
            Status::Stops,
            lowered_reason.to_owned(),
        ),
    }
}

fn call_shape_supported(source: &PcodeOperation) -> bool {
    source.output.is_none() && source.inputs.len() == 1
}

fn branch_shape_supported(source: &PcodeOperation, spaces: &[GhidraAddressSpace]) -> bool {
    if source.output.is_some() {
        return false;
    }
    match source.opcode {
        4 => source.inputs.len() == 1,
        5 => source.inputs.len() == 2 && source.inputs[1].size == 1,
        6 => {
            source.inputs.len() == 1
                && spaces.iter().any(|space| {
                    space.name == source.source_address.space
                        && (1..=8).contains(&space.pointer_size)
                        && source.inputs[0].size == space.pointer_size
                        && matches!(
                            source.inputs[0].space.as_str(),
                            "register" | "unique" | "const"
                        )
                })
        }
        _ => false,
    }
}

fn concrete_memory_shape(
    source: &PcodeOperation,
    spaces: &[GhidraAddressSpace],
) -> Result<(), String> {
    if source.opcode == 1 && source.mnemonic == "COPY" {
        let (Some(input), Some(output)) = (source.inputs.first(), source.output.as_ref()) else {
            return Err("direct RAM COPY requires an input and output".to_owned());
        };
        let supported = source.inputs.len() == 1
            && input.size == output.size
            && (1..=16).contains(&input.size)
            && matches!(output.space.as_str(), "register" | "unique")
            && spaces.iter().any(|space| {
                space.name == input.space
                    && space.space_type == 1
                    && space.pointer_size == 8
                    && space.addressable_unit_size != 0
            })
            && hex_u64(&input.offset).is_ok();
        return supported
            .then_some(())
            .ok_or_else(|| "direct RAM COPY layout is unsupported".to_owned());
    }
    let (is_load, value) = match (source.opcode, source.mnemonic.as_str()) {
        (2, "LOAD") if source.inputs.len() == 2 => (true, source.output.as_ref()),
        (3, "STORE") if source.inputs.len() == 3 && source.output.is_none() => {
            (false, source.inputs.get(2))
        }
        _ => return Err("memory opcode, mnemonic, arity or output is unsupported".to_owned()),
    };
    let Some(value) = value else {
        return Err("memory value varnode is absent".to_owned());
    };
    let id_node = &source.inputs[0];
    if id_node.space != "const" || !(1..=8).contains(&id_node.size) {
        return Err("memory space ID must be a bounded constant".to_owned());
    }
    let id = hex_u64(&id_node.offset)?;
    let mask = if id_node.size == 8 {
        u64::MAX
    } else {
        (1u64 << (id_node.size * 8)) - 1
    };
    if id > mask {
        return Err("memory space ID exceeds its varnode width".to_owned());
    }
    let Some(space) = spaces
        .iter()
        .find(|space| u64::try_from(space.id).ok() == Some(id))
    else {
        return Err("memory space ID has no Ghidra address space".to_owned());
    };
    let pointer = &source.inputs[1];
    if space.space_type != 1
        || matches!(space.name.as_str(), "const" | "register" | "unique")
        || !(1..=8).contains(&space.pointer_size)
        || pointer.size != space.pointer_size
        || !matches!(pointer.space.as_str(), "register" | "unique" | "const")
        || space.addressable_unit_size == 0
        || !(1..=8).contains(&value.size)
        || !matches!(value.space.as_str(), "register" | "unique" | "const")
        || (is_load && value.space == "const")
    {
        return Err("memory operation requires a supported RAM layout and value width".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::parse_ghidra_snapshot;

    #[test]
    fn real_prism_inventory_preserves_unknown_sites_and_does_not_claim_fidelity() {
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap();
        let report = snapshot.pcode_coverage_report().unwrap();
        assert_eq!(
            report.operations,
            report.exact_assignments + report.opaque_effects
        );
        assert!(report.exact_assignments >= 10);
        assert!(report.opaque_effects > 0);
        assert!(report.by_opcode.iter().any(|row| row.mnemonic == "POPCOUNT"
            && row.exact_assignments == 1
            && row.opaque_effects == 0));
        assert!(
            report
                .opaque_sites
                .iter()
                .any(|site| site.mnemonic == "CBRANCH")
        );
        assert_eq!(report.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(report.verification, VerificationStatus::NotRun);
        let json = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<PcodeCoverageReport>(&json).unwrap(),
            report
        );
    }

    #[test]
    fn call_fixture_reports_concrete_memory_and_single_function_call_boundary() {
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap();
        let report = snapshot.pcode_capability_report().unwrap();
        assert_eq!(report.schema_version, PCODE_CAPABILITY_VERSION);
        assert_eq!(report.snapshot_sha256.len(), 64);
        assert_eq!(
            report.snapshot_sha256,
            snapshot.pcode_capability_report().unwrap().snapshot_sha256
        );
        assert_eq!(report.discovery.instruction_nodes, 4);
        assert_eq!(report.discovery.known_calls, 1);
        assert!(!report.discovery.complete);
        assert_eq!(report.calls.call_operations, 1);
        assert_eq!(report.calls.direct_targets, 1);
        assert!(report.memory.conditional_reads > 0);
        assert!(report.memory.conditional_writes > 0);
        assert!(report.execution.exact_value_operations > 0);
        assert_eq!(
            report.operations,
            report.execution.exact_value_operations
                + report.execution.conditional_memory_operations
                + report.execution.conditional_control_operations
                + report.execution.stopping_operations
        );
        assert!(report.stop_sites.iter().any(|site| {
            site.mnemonic == "CALL"
                && site.kind == PcodeCapabilityKind::Call
                && site.status == PcodeCapabilityStatus::Stops
        }));
        assert!(report.stop_sites.iter().any(|site| {
            site.mnemonic == "LOAD"
                && site.kind == PcodeCapabilityKind::MemoryRead
                && site.status == PcodeCapabilityStatus::RequiresConcreteState
        }));
        assert_eq!(report.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(report.verification, VerificationStatus::NotRun);
        let json = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<PcodeCapabilityReport>(&json).unwrap(),
            report
        );
    }

    #[test]
    fn malformed_memory_width_is_an_explicit_stop() {
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap();
        let mut load = snapshot
            .selected_function
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.pcode)
            .find(|operation| operation.mnemonic == "LOAD")
            .unwrap()
            .clone();
        assert!(concrete_memory_shape(&load, &snapshot.address_spaces).is_ok());
        load.inputs[1].size = 4;
        assert!(concrete_memory_shape(&load, &snapshot.address_spaces).is_err());
    }

    #[test]
    fn wide_rust_value_is_not_claimed_as_an_llvm_candidate() {
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap();
        let mut popcount = snapshot
            .selected_function
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.pcode)
            .find(|operation| operation.mnemonic == "POPCOUNT")
            .unwrap()
            .clone();
        popcount.inputs[0].size = 16;
        assert!(!llvm_value_candidate(PcodeExactOp::PopCount, 8, &popcount));
    }

    #[test]
    fn unknown_userop_fixture_is_a_source_linked_stop() {
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_userop_rdtsc_v2.json"
            )),
            "75f384ca5c4dc59d1af2f56e92d677fc7acae43b6faf0213bd203ef6426f2667",
        )
        .unwrap();
        let report = snapshot.pcode_capability_report().unwrap();
        assert!(report.stop_sites.iter().any(|site| {
            site.mnemonic == "CALLOTHER"
                && site.kind == PcodeCapabilityKind::UserOperation
                && site.status == PcodeCapabilityStatus::Stops
                && site.address == snapshot.selected_function.instructions[0].address
        }));
    }
}
