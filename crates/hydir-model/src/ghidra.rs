//! Conservative import of Ghidra function discovery into AnalysisModel.
//! Names are evidence. Existing names are retained and disagreements visible.

use super::{
    AnalysisModel, ModelConflict, ModelEvidence, ModelFunction, ModelSource, validate_model,
};
use hydir_core::{Address, Location, annotation_address_in_spec};
use hydir_ir::pcode::{GhidraSnapshot, validate_ghidra_snapshot};
use hydir_loader::import_elf;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GhidraModelImportReport {
    pub binary_sha256: String,
    pub selected_function: Location,
    pub added_functions: usize,
    pub matched_functions: usize,
    pub conflicting_names: usize,
    pub skipped_unmapped: usize,
    pub model_revision: u64,
}

/// Import Ghidra's linked-ELF function index without asserting prototypes or
/// changing existing names. Repeating the same import does not advance the
/// model revision or duplicate evidence and conflicts.
pub fn import_ghidra_functions(
    bytes: &[u8],
    model: &mut AnalysisModel,
    snapshot: &GhidraSnapshot,
) -> Result<GhidraModelImportReport, String> {
    validate_model(bytes, model)?;
    validate_ghidra_snapshot(snapshot, &model.binary_sha256)?;
    if !snapshot.program.language_id.starts_with("x86:LE:64:") {
        return Err("Ghidra model import currently requires x86-64 little endian".to_owned());
    }
    if snapshot.selected_function.entry.space != "ram" {
        return Err("Ghidra selected function is outside the linked ELF RAM space".to_owned());
    }
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let mut candidate = model.clone();
    let mut added_functions = 0;
    let mut matched_functions = 0;
    let mut conflicting_names = 0;
    let mut skipped_unmapped = 0;
    let mut indexed = BTreeMap::new();
    for (index, function) in candidate.functions.iter().enumerate() {
        indexed.insert(function.entry, index);
    }
    for function in &snapshot.functions {
        if function.entry.space != "ram" {
            skipped_unmapped += 1;
            continue;
        }
        let address = u64::from_str_radix(
            function
                .entry
                .offset
                .strip_prefix("0x")
                .ok_or("Ghidra function offset lacks 0x prefix")?,
            16,
        )
        .map_err(|_| "invalid Ghidra function offset")?;
        if !annotation_address_in_spec(&spec, Address(address)) {
            skipped_unmapped += 1;
            continue;
        }
        let location = Location {
            address_space: 0,
            value: Address(address),
        };
        let evidence = ModelEvidence {
            source: ModelSource::GhidraAnalysis,
            detail: format!("Ghidra function index name: {}", function.name),
            site: Some(location),
        };
        if let Some(index) = indexed.get(&location).copied() {
            let existing = &mut candidate.functions[index];
            let mut conflicting_evidence = existing.evidence.clone();
            if !existing.evidence.contains(&evidence) {
                existing.evidence.push(evidence.clone());
            }
            if existing.name == function.name {
                matched_functions += 1;
            } else {
                conflicting_names += 1;
                if !conflicting_evidence.contains(&evidence) {
                    conflicting_evidence.push(evidence);
                }
                let conflict = ModelConflict {
                    subject: format!("function:0x{address:x}:name"),
                    detail: format!(
                        "retained model name {:?}; Ghidra reports {:?}",
                        existing.name, function.name
                    ),
                    evidence: conflicting_evidence,
                };
                if !candidate.conflicts.contains(&conflict) {
                    candidate.conflicts.push(conflict);
                }
            }
        } else {
            let index = candidate.functions.len();
            candidate.functions.push(ModelFunction {
                entry: location,
                name: function.name.clone(),
                prototype: None,
                inferred_parameters: BTreeMap::new(),
                evidence: vec![evidence],
            });
            indexed.insert(location, index);
            added_functions += 1;
        }
    }
    candidate.functions.sort_by_key(|function| function.entry);
    if candidate != *model {
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or("analysis model revision overflow")?;
    }
    validate_model(bytes, &candidate)?;
    let report = GhidraModelImportReport {
        binary_sha256: candidate.binary_sha256.clone(),
        selected_function: Location {
            address_space: 0,
            value: Address(
                u64::from_str_radix(&snapshot.selected_function.entry.offset[2..], 16)
                    .map_err(|_| "invalid selected function offset")?,
            ),
        },
        added_functions,
        matched_functions,
        conflicting_names,
        skipped_unmapped,
        model_revision: candidate.revision,
    };
    *model = candidate;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init_model;
    use hydir_ir::pcode::parse_ghidra_snapshot;

    #[test]
    fn real_snapshot_adds_mapped_functions_and_preserves_analyst_name() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../demo/hydir-prism.elf"
        ));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_metadata_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap();
        let mut model = init_model(bytes).unwrap();
        let missing = Location {
            address_space: 0,
            value: Address(0x2013cf),
        };
        model.functions.retain(|function| function.entry != missing);
        let selected = Location {
            address_space: 0,
            value: Address(0x20137c),
        };
        model
            .functions
            .retain(|function| function.entry != selected);
        model.functions.push(ModelFunction {
            entry: selected,
            name: "analyst_decision".to_owned(),
            prototype: None,
            inferred_parameters: BTreeMap::new(),
            evidence: vec![ModelEvidence {
                source: ModelSource::AnalystAssertion,
                detail: "analyst rename".to_owned(),
                site: Some(selected),
            }],
        });
        validate_model(bytes, &model).unwrap();
        let before_revision = model.revision;
        let report = import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert!(report.added_functions > 0);
        assert!(report.conflicting_names > 0);
        assert_eq!(model.revision, before_revision + 1);
        let decision = model
            .functions
            .iter()
            .find(|function| function.entry == selected)
            .unwrap();
        assert_eq!(decision.name, "analyst_decision");
        assert!(
            decision
                .evidence
                .iter()
                .any(|item| item.source == ModelSource::GhidraAnalysis)
        );
        assert!(
            model
                .conflicts
                .iter()
                .any(|conflict| conflict.subject == "function:0x20137c:name")
        );
        let after_first = model.clone();
        import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert_eq!(model, after_first);

        let mut wrong_binary = snapshot.clone();
        wrong_binary.binary_sha256 = "0".repeat(64);
        assert!(import_ghidra_functions(bytes, &mut model, &wrong_binary).is_err());
        assert_eq!(model, after_first);
    }
}
