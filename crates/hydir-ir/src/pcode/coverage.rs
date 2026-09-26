//! Static operation inventory for a validated Ghidra raw-P-code snapshot.
//! Counts describe Hydir's current P-code lowering, not binary equivalence.

use super::{GhidraSnapshot, PcodeAddress, PcodeEffect, PcodeOpaqueClass};
use crate::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PCODE_COVERAGE_VERSION: u32 = 1;
const MAX_OPAQUE_SITES: usize = 256;

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
        assert!(report.exact_assignments >= 7);
        assert!(report.opaque_effects > 0);
        assert!(
            report
                .opaque_sites
                .iter()
                .any(|site| site.mnemonic == "POPCOUNT")
        );
        assert_eq!(report.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(report.verification, VerificationStatus::NotRun);
        let json = serde_json::to_vec(&report).unwrap();
        assert_eq!(
            serde_json::from_slice::<PcodeCoverageReport>(&json).unwrap(),
            report
        );
    }
}
