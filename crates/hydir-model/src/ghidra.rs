//! Conservative import of Ghidra function discovery into AnalysisModel.
//! Names are evidence. Existing names are retained and disagreements visible.

use super::{
    AnalysisModel, MAX_HIGH_PCODE_HINT_BYTES, MAX_HIGH_PCODE_HINTS, ModelConflict, ModelEvidence,
    ModelField, ModelFunction, ModelHighPcodeHint, ModelParameter, ModelPrototype, ModelSource,
    PrimitiveType, TypeDefinitionKind, TypeRef, valid_identifier, validate_model,
};
use hydir_core::{Address, Location, annotation_address_in_spec};
use hydir_ir::pcode::{
    GhidraDataTypeEvidence, GhidraDataTypeKind, GhidraFieldEvidence, GhidraFunctionPrototype,
    GhidraHighPcodeStatus, GhidraHighVarnodeEvidence, GhidraSnapshot, validate_ghidra_snapshot,
};
use hydir_loader::import_elf;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GhidraModelImportReport {
    pub binary_sha256: String,
    pub selected_function: Location,
    pub added_functions: usize,
    pub matched_functions: usize,
    pub conflicting_names: usize,
    pub imported_prototypes: usize,
    pub matched_prototypes: usize,
    pub conflicting_prototypes: usize,
    pub unresolved_prototypes: usize,
    pub skipped_unmapped: usize,
    #[serde(default)]
    pub imported_high_pcode_hints: usize,
    #[serde(default)]
    pub skipped_high_pcode_hints: usize,
    pub model_revision: u64,
}

fn parse_snapshot_offset(offset: &str) -> Result<u64, String> {
    let digits = offset
        .strip_prefix("0x")
        .ok_or("Ghidra address lacks 0x prefix")?;
    u64::from_str_radix(digits, 16).map_err(|_| "invalid Ghidra address offset".to_owned())
}

fn linked_elf_address(address: u64, ghidra_base: u64, elf_base: u64) -> Option<u64> {
    address.checked_sub(ghidra_base)?.checked_add(elf_base)
}

fn primitive_type(name: &str, size: Option<u32>) -> Option<PrimitiveType> {
    let primitive = match name.trim().to_ascii_lowercase().as_str() {
        "void" => PrimitiveType::Void,
        "bool" | "boolean" => PrimitiveType::Bool,
        "uchar" | "unsigned char" | "uint8_t" | "uint8" => PrimitiveType::U8,
        "schar" | "signed char" | "int8_t" | "int8" => PrimitiveType::I8,
        "ushort" | "unsigned short" | "uint16_t" | "uint16" => PrimitiveType::U16,
        "short" | "short int" | "signed short" | "int16_t" | "int16" => PrimitiveType::I16,
        "uint" | "unsigned int" | "uint32_t" | "uint32" => PrimitiveType::U32,
        "int" | "signed int" | "int32_t" | "int32" => PrimitiveType::I32,
        "ulong" | "unsigned long" | "uint64_t" | "uint64" => PrimitiveType::U64,
        "long" | "long int" | "signed long" | "int64_t" | "int64" => PrimitiveType::I64,
        "float" => PrimitiveType::F32,
        "double" => PrimitiveType::F64,
        _ => return None,
    };
    if (primitive == PrimitiveType::Void && matches!(size, None | Some(0)))
        || primitive.size_bytes().map(|value| value as u32) == size
    {
        Some(primitive)
    } else {
        None
    }
}

fn model_type(
    evidence: &GhidraDataTypeEvidence,
    model: &AnalysisModel,
    depth: usize,
) -> Option<(TypeRef, Option<u64>)> {
    if evidence.detail_truncated || depth > 8 {
        return None;
    }
    let size = evidence.size_bytes.map(u64::from);
    match evidence.kind {
        GhidraDataTypeKind::Primitive => {
            let primitive = primitive_type(&evidence.display_name, evidence.size_bytes)?;
            Some((TypeRef::Primitive { name: primitive }, size))
        }
        GhidraDataTypeKind::Pointer if size == Some(8) => {
            let (target, _) = model_type(evidence.target_type.as_deref()?, model, depth + 1)?;
            Some((
                TypeRef::Pointer {
                    to: Box::new(target),
                },
                size,
            ))
        }
        GhidraDataTypeKind::Array => {
            let count = u64::from(evidence.element_count?);
            if count == 0 {
                return None;
            }
            let (element, element_size) =
                model_type(evidence.target_type.as_deref()?, model, depth + 1)?;
            if element_size?.checked_mul(count)? != size? {
                return None;
            }
            Some((
                TypeRef::Array {
                    of: Box::new(element),
                    count,
                },
                size,
            ))
        }
        GhidraDataTypeKind::Struct
        | GhidraDataTypeKind::Union
        | GhidraDataTypeKind::Enum
        | GhidraDataTypeKind::Typedef => {
            let mut matches = model.types.iter().filter(|definition| {
                Some(definition.size_bytes) == size
                    && matches!(
                        (&evidence.kind, &definition.kind),
                        (
                            GhidraDataTypeKind::Struct,
                            TypeDefinitionKind::Struct { .. }
                        ) | (GhidraDataTypeKind::Union, TypeDefinitionKind::Union { .. })
                            | (GhidraDataTypeKind::Enum, TypeDefinitionKind::Enum { .. })
                            | (
                                GhidraDataTypeKind::Typedef,
                                TypeDefinitionKind::Alias { .. }
                            )
                    )
                    && (definition.name == evidence.display_name
                        || (definition
                            .name
                            .starts_with(&format!("{}_dwarf_", evidence.display_name))
                            && definition
                                .evidence
                                .iter()
                                .any(|item| item.source == ModelSource::Dwarf)))
            });
            if let Some(definition) = matches.next().filter(|_| matches.next().is_none()) {
                return Some((
                    TypeRef::Named {
                        id: definition.id.clone(),
                    },
                    size,
                ));
            }
            if evidence.kind == GhidraDataTypeKind::Typedef {
                model_type(evidence.target_type.as_deref()?, model, depth + 1)
            } else {
                None
            }
        }
        _ => None,
    }
}

fn model_prototype(
    evidence: &GhidraFunctionPrototype,
    model: &AnalysisModel,
    snapshot: &GhidraSnapshot,
) -> Option<ModelPrototype> {
    // Ghidra 12.1.4's x86-64 gcc cspec labels its SysV default prototype
    // "__stdcall". The label alone is not an ABI identification.
    let known_sysv_default = snapshot.program.ghidra_version == "12.1.4"
        && snapshot.program.language_id == "x86:LE:64:default"
        && snapshot.program.compiler_spec_id == "gcc"
        && matches!(
            evidence.calling_convention.as_deref(),
            Some("__stdcall" | "default")
        );
    if !matches!(
        evidence.signature_source.as_str(),
        "IMPORTED" | "USER_DEFINED"
    ) || !known_sysv_default
        || evidence
            .parameters
            .iter()
            .any(|parameter| parameter.auto_parameter)
    {
        return None;
    }
    let (return_type, _) = model_type(&evidence.return_type, model, 0)?;
    let mut parameters = Vec::with_capacity(evidence.parameters.len());
    let mut names = BTreeSet::new();
    for (index, parameter) in evidence.parameters.iter().enumerate() {
        let (ty, _) = model_type(&parameter.data_type, model, 0)?;
        if matches!(
            ty,
            TypeRef::Primitive {
                name: PrimitiveType::Void
            }
        ) {
            return None;
        }
        let name = if valid_identifier(&parameter.name) && names.insert(parameter.name.clone()) {
            parameter.name.clone()
        } else {
            let fallback = format!("arg{index}");
            if !names.insert(fallback.clone()) {
                return None;
            }
            fallback
        };
        parameters.push(ModelParameter { name, ty });
    }
    Some(ModelPrototype {
        parameters,
        return_type,
        calling_convention: "sysv_amd64".to_owned(),
        variadic: evidence.has_varargs,
    })
}

// A type reached through an imported signature can refine an existing, uniquely
// identified struct. Decompiler high types remain hints and never take this path.
fn imported_struct_fields(
    evidence: &GhidraDataTypeEvidence,
    model: &mut AnalysisModel,
    site: Location,
    depth: usize,
) {
    if evidence.detail_truncated || depth > 8 {
        return;
    }
    if matches!(
        evidence.kind,
        GhidraDataTypeKind::Pointer | GhidraDataTypeKind::Array | GhidraDataTypeKind::Typedef
    ) {
        if let Some(target) = evidence.target_type.as_deref() {
            imported_struct_fields(target, model, site, depth + 1);
        }
        return;
    }
    if evidence.kind != GhidraDataTypeKind::Struct
        || evidence.fields.is_empty()
        || evidence.fields.len() > 64
    {
        return;
    }
    let Some((TypeRef::Named { id }, _)) = model_type(evidence, model, 0) else {
        return;
    };
    let Some(index) = model
        .types
        .iter()
        .position(|definition| definition.id == id)
    else {
        return;
    };
    if model.types[index].size_is_lower_bound {
        return;
    }
    let size = model.types[index].size_bytes;
    let mut proposed = Vec::with_capacity(evidence.fields.len());
    let mut names = BTreeSet::new();
    let mut previous_end = 0;
    for field in &evidence.fields {
        let Some(name) = field.name.as_ref().filter(|name| valid_identifier(name)) else {
            return;
        };
        let offset = u64::from(field.offset_bytes);
        let field_size = u64::from(field.size_bytes);
        let Some(end) = offset.checked_add(field_size) else {
            return;
        };
        if !names.insert(name.clone()) || field_size == 0 || offset < previous_end || end > size {
            return;
        }
        previous_end = end;
        if let Some((ty, Some(type_size))) = model_type(&field.data_type, model, 0)
            && type_size == field_size
        {
            proposed.push((name.clone(), offset, field_size, ty, field));
        }
    }
    let mut spans = {
        let defs = model
            .types
            .iter()
            .map(|definition| (definition.id.as_str(), definition))
            .collect::<BTreeMap<_, _>>();
        let TypeDefinitionKind::Struct { fields } = &model.types[index].kind else {
            return;
        };
        fields
            .iter()
            .map(|field| {
                let size = super::type_size(&field.ty, &defs, &mut BTreeSet::new(), 0)
                    .ok()
                    .flatten()?;
                Some((
                    field.name.clone(),
                    field.offset_bytes,
                    field.offset_bytes.checked_add(size)?,
                ))
            })
            .collect::<Option<Vec<_>>>()
    };
    let Some(mut spans) = spans.take() else {
        return;
    };
    let definition = &mut model.types[index];
    let TypeDefinitionKind::Struct { fields } = &mut definition.kind else {
        return;
    };
    for (name, offset, field_size, ty, source) in proposed {
        let detail = imported_field_detail(source, &id);
        let field_evidence = ModelEvidence {
            source: ModelSource::GhidraAnalysis,
            detail,
            site: Some(site),
        };
        if let Some(existing_index) = spans.iter().position(|(old_name, start, end)| {
            old_name == &name || *start < offset + field_size && offset < *end
        }) {
            let existing = &mut fields[existing_index];
            if existing.name == name && existing.offset_bytes == offset && existing.ty == ty {
                if !existing.evidence.contains(&field_evidence) && existing.evidence.len() < 256 {
                    existing.evidence.push(field_evidence);
                }
            } else {
                let mut evidence = existing
                    .evidence
                    .iter()
                    .take(255)
                    .cloned()
                    .collect::<Vec<_>>();
                evidence.push(field_evidence);
                let conflict = ModelConflict {
                    subject: format!("type:{id}:field:{offset}"),
                    detail: bounded_detail(format!(
                        "retained model field {:?} at {} with type {:?}; Ghidra reports {:?} at {} with type {:?}",
                        existing.name, existing.offset_bytes, existing.ty, name, offset, ty
                    )),
                    evidence,
                };
                if !model.conflicts.contains(&conflict) {
                    model.conflicts.push(conflict);
                }
            }
        } else if fields.len() < super::MAX_FIELDS {
            fields.push(ModelField {
                name: name.clone(),
                offset_bytes: offset,
                ty,
                evidence: vec![field_evidence],
            });
            spans.push((name, offset, offset + field_size));
        }
    }
    fields.sort_by_key(|field| field.offset_bytes);
}

fn imported_field_detail(field: &GhidraFieldEvidence, id: &str) -> String {
    bounded_detail(format!(
        "Ghidra imported struct {id} field {:?} at {} ({} bytes; type {:?})",
        field.name, field.offset_bytes, field.size_bytes, field.data_type.display_name
    ))
}

fn bounded_detail(mut detail: String) -> String {
    if detail.len() > 4096 {
        let mut end = 4096;
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        detail.truncate(end);
    }
    detail
}

fn prototype_evidence(prototype: &GhidraFunctionPrototype, location: Location) -> ModelEvidence {
    let detail = serde_json::to_string(prototype)
        .ok()
        .filter(|detail| detail.len() <= 4096)
        .unwrap_or_else(|| {
            format!(
                "Ghidra prototype source {}; return {}; {} parameters (full evidence in snapshot)",
                prototype.signature_source,
                prototype
                    .return_type
                    .display_name
                    .chars()
                    .take(128)
                    .collect::<String>(),
                prototype.parameters.len()
            )
        });
    ModelEvidence {
        source: ModelSource::GhidraAnalysis,
        detail,
        site: Some(location),
    }
}

fn high_pcode_hint(
    node: &GhidraHighVarnodeEvidence,
    function_entry: Location,
    source_site: Location,
    operation_index: u32,
    input_index: Option<u16>,
    ghidra_base: u64,
    elf_base: u64,
    spec: &hydir_core::ProgramSpec,
) -> Result<ModelHighPcodeHint, String> {
    let linked_ram_address = if node.varnode.space == "ram" {
        linked_elf_address(
            parse_snapshot_offset(&node.varnode.offset)?,
            ghidra_base,
            elf_base,
        )
        .filter(|address| annotation_address_in_spec(spec, Address(*address)))
        .map(|address| Location {
            address_space: 0,
            value: Address(address),
        })
    } else {
        None
    };
    Ok(ModelHighPcodeHint {
        function_entry,
        source_site,
        operation_index,
        input_index,
        ssa_id: node.ssa_id,
        is_input: node.is_input,
        varnode: node.varnode.clone(),
        linked_ram_address,
        high_name: node.high_name.clone(),
        high_type: node.high_type.clone(),
        source: ModelSource::GhidraAnalysis,
    })
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
    if snapshot.program.image_base.space != "ram" {
        return Err("Ghidra image base is outside the linked ELF RAM space".to_owned());
    }
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let elf_base = spec
        .mapped_segments
        .iter()
        .filter(|segment| segment.address_space == 0 && segment.memory_size > 0)
        .map(|segment| segment.virtual_address.0)
        .min()
        .ok_or("linked ELF has no mapped process image")?;
    let ghidra_base = parse_snapshot_offset(&snapshot.program.image_base.offset)?;
    let selected_address = linked_elf_address(
        parse_snapshot_offset(&snapshot.selected_function.entry.offset)?,
        ghidra_base,
        elf_base,
    )
    .ok_or("Ghidra selected function cannot be mapped to the ELF image")?;
    if !annotation_address_in_spec(&spec, Address(selected_address)) {
        return Err("Ghidra selected function is outside the linked ELF image".to_owned());
    }
    let mut candidate = model.clone();
    let mut added_functions = 0;
    let mut matched_functions = 0;
    let mut conflicting_names = 0;
    let mut imported_prototypes = 0;
    let mut matched_prototypes = 0;
    let mut conflicting_prototypes = 0;
    let mut unresolved_prototypes = 0;
    let mut skipped_unmapped = 0;
    let mut imported_high_pcode_hints = 0;
    let mut skipped_high_pcode_hints = 0;
    let mut indexed = BTreeMap::new();
    for (index, function) in candidate.functions.iter().enumerate() {
        indexed.insert(function.entry, index);
    }
    for function in &snapshot.functions {
        if function.entry.space != "ram" {
            skipped_unmapped += 1;
            continue;
        }
        let Some(address) = linked_elf_address(
            parse_snapshot_offset(&function.entry.offset)?,
            ghidra_base,
            elf_base,
        ) else {
            skipped_unmapped += 1;
            continue;
        };
        if !annotation_address_in_spec(&spec, Address(address)) {
            skipped_unmapped += 1;
            continue;
        }
        let location = Location {
            address_space: 0,
            value: Address(address),
        };
        let mut name_detail = format!(
            "Ghidra function index name: {} at ram:{}",
            function.name, function.entry.offset
        );
        if name_detail.len() > 4096 {
            name_detail = format!(
                "Ghidra function index name at ram:{} (full name in function record)",
                function.entry.offset
            );
        }
        let evidence = ModelEvidence {
            source: ModelSource::GhidraAnalysis,
            detail: name_detail,
            site: Some(location),
        };
        let prototype_evidence = function
            .prototype
            .as_ref()
            .map(|prototype| prototype_evidence(prototype, location));
        let mapped_prototype = function
            .prototype
            .as_ref()
            .and_then(|prototype| model_prototype(prototype, &candidate, snapshot));
        if mapped_prototype.is_some() {
            if let Some(prototype) = &function.prototype
                && matches!(
                    prototype.signature_source.as_str(),
                    "IMPORTED" | "USER_DEFINED"
                )
            {
                if matches!(
                    prototype.return_source.as_str(),
                    "IMPORTED" | "USER_DEFINED"
                ) {
                    imported_struct_fields(&prototype.return_type, &mut candidate, location, 0);
                }
                for parameter in &prototype.parameters {
                    if matches!(parameter.source_type.as_str(), "IMPORTED" | "USER_DEFINED") {
                        imported_struct_fields(&parameter.data_type, &mut candidate, location, 0);
                    }
                }
            }
        }
        if function.prototype.is_some() && mapped_prototype.is_none() {
            unresolved_prototypes += 1;
        }
        if let Some(index) = indexed.get(&location).copied() {
            let existing = &mut candidate.functions[index];
            let mut conflicting_evidence = existing.evidence.clone();
            if !existing.evidence.contains(&evidence) {
                existing.evidence.push(evidence.clone());
            }
            if let Some(prototype_evidence) = &prototype_evidence {
                if !existing.evidence.contains(prototype_evidence) {
                    existing.evidence.push(prototype_evidence.clone());
                }
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
            if let Some(mapped) = mapped_prototype {
                match &existing.prototype {
                    None => {
                        existing.prototype = Some(mapped);
                        imported_prototypes += 1;
                    }
                    Some(current) if *current != mapped => {
                        conflicting_prototypes += 1;
                        let prototype_evidence = prototype_evidence
                            .expect("mapped prototype always has Ghidra evidence");
                        let mut evidence = existing
                            .evidence
                            .iter()
                            .filter(|item| **item != prototype_evidence)
                            .take(255)
                            .cloned()
                            .collect::<Vec<_>>();
                        evidence.push(prototype_evidence);
                        let conflict = ModelConflict {
                            subject: format!("function:0x{address:x}:prototype"),
                            detail: format!(
                                "retained model prototype {:?}; Ghidra reports {:?}",
                                current, mapped
                            ),
                            evidence,
                        };
                        if !candidate.conflicts.contains(&conflict) {
                            candidate.conflicts.push(conflict);
                        }
                    }
                    Some(_) => matched_prototypes += 1,
                }
            }
        } else {
            let index = candidate.functions.len();
            let mut evidence = vec![evidence];
            if let Some(prototype_evidence) = prototype_evidence {
                evidence.push(prototype_evidence);
            }
            if mapped_prototype.is_some() {
                imported_prototypes += 1;
            }
            candidate.functions.push(ModelFunction {
                entry: location,
                name: function.name.clone(),
                prototype: mapped_prototype,
                inferred_parameters: BTreeMap::new(),
                evidence,
            });
            indexed.insert(location, index);
            added_functions += 1;
        }
    }
    candidate.functions.sort_by_key(|function| function.entry);
    if let Some(high) = &snapshot.selected_function.high_pcode
        && high.status == GhidraHighPcodeStatus::Complete
    {
        let function_entry = Location {
            address_space: 0,
            value: Address(selected_address),
        };
        let mut seen_hints = BTreeSet::new();
        let mut hint_bytes = 0usize;
        for hint in &candidate.high_pcode_hints {
            let encoded = serde_json::to_vec(hint)
                .map_err(|error| format!("cannot encode existing high-P-code hint: {error}"))?;
            hint_bytes += encoded.len();
            seen_hints.insert(encoded);
        }
        let model_bytes_before_hints = serde_json::to_vec(&candidate)
            .map_err(|error| format!("cannot encode analysis model: {error}"))?
            .len();
        let mut added_model_bytes = 0usize;
        for operation in &high.operations {
            let source_address = if operation.source_address.space == "ram" {
                linked_elf_address(
                    parse_snapshot_offset(&operation.source_address.offset)?,
                    ghidra_base,
                    elf_base,
                )
                .filter(|address| annotation_address_in_spec(&spec, Address(*address)))
            } else {
                None
            };
            let nodes = operation.output.iter().map(|node| (None, node)).chain(
                operation
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(index, node)| (Some(index as u16), node)),
            );
            for (input_index, node) in nodes {
                let Some(address) = source_address else {
                    skipped_high_pcode_hints += 1;
                    continue;
                };
                let hint = high_pcode_hint(
                    node,
                    function_entry,
                    Location {
                        address_space: 0,
                        value: Address(address),
                    },
                    operation.index,
                    input_index,
                    ghidra_base,
                    elf_base,
                    &spec,
                )?;
                let encoded = serde_json::to_vec(&hint)
                    .map_err(|error| format!("cannot encode high-P-code hint: {error}"))?;
                if seen_hints.contains(&encoded) {
                    continue;
                }
                let encoded_len = encoded.len();
                if candidate.high_pcode_hints.len() >= MAX_HIGH_PCODE_HINTS
                    || hint_bytes.saturating_add(encoded_len) > MAX_HIGH_PCODE_HINT_BYTES
                    || model_bytes_before_hints
                        .saturating_add(added_model_bytes)
                        .saturating_add(encoded_len)
                        .saturating_add(64)
                        > super::MAX_MODEL_BYTES
                {
                    skipped_high_pcode_hints += 1;
                    continue;
                }
                candidate.high_pcode_hints.push(hint);
                seen_hints.insert(encoded);
                hint_bytes += encoded_len;
                added_model_bytes += encoded_len + 1;
                imported_high_pcode_hints += 1;
            }
        }
    }
    if candidate != *model {
        candidate.revision = candidate
            .revision
            .checked_add(1)
            .ok_or("analysis model revision overflow")?;
    }
    validate_model(bytes, &candidate)?;
    if serde_json::to_vec(&candidate)
        .map_err(|error| format!("cannot encode analysis model: {error}"))?
        .len()
        > super::MAX_MODEL_BYTES
    {
        return Err("analysis model exceeds 16 MiB after Ghidra import".to_owned());
    }
    let report = GhidraModelImportReport {
        binary_sha256: candidate.binary_sha256.clone(),
        selected_function: Location {
            address_space: 0,
            value: Address(selected_address),
        },
        added_functions,
        matched_functions,
        conflicting_names,
        imported_prototypes,
        matched_prototypes,
        conflicting_prototypes,
        unresolved_prototypes,
        skipped_unmapped,
        imported_high_pcode_hints,
        skipped_high_pcode_hints,
        model_revision: candidate.revision,
    };
    *model = candidate;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{import_dwarf, init_model, parse_model, record_analyst_edits};
    use hydir_ir::pcode::{GhidraParameterEvidence, parse_ghidra_snapshot};

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

    #[test]
    fn supported_imported_prototype_is_typed_but_analysis_hint_stays_evidence() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../demo/hydir-prism.elf"
        ));
        let mut snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_metadata_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap();
        let entry = Location {
            address_space: 0,
            value: Address(0x20137c),
        };
        let function = snapshot
            .functions
            .iter_mut()
            .find(|function| function.entry.offset == "0x20137c")
            .unwrap();
        let integer = GhidraDataTypeEvidence {
            display_name: "int".to_owned(),
            path: "/int".to_owned(),
            size_bytes: Some(4),
            kind: GhidraDataTypeKind::Primitive,
            target_type: None,
            element_count: None,
            detail_truncated: false,
            fields: Vec::new(),
        };
        function.prototype = Some(GhidraFunctionPrototype {
            signature_source: "IMPORTED".to_owned(),
            calling_convention: Some("__stdcall".to_owned()),
            has_varargs: false,
            return_type: integer.clone(),
            return_source: "IMPORTED".to_owned(),
            parameters: vec![GhidraParameterEvidence {
                name: "value".to_owned(),
                data_type: integer,
                source_type: "IMPORTED".to_owned(),
                auto_parameter: false,
            }],
        });
        let mut model = init_model(bytes).unwrap();
        let report = import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert_eq!(report.imported_prototypes, 1);
        let imported = model
            .functions
            .iter()
            .find(|function| function.entry == entry)
            .unwrap();
        assert_eq!(imported.prototype.as_ref().unwrap().parameters.len(), 1);
        assert_eq!(
            imported.prototype.as_ref().unwrap().return_type,
            TypeRef::Primitive {
                name: PrimitiveType::I32
            }
        );
        let after_first = model.clone();
        import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert_eq!(model, after_first);

        let mut edited = model.clone();
        let function = edited
            .functions
            .iter_mut()
            .find(|function| function.entry == entry)
            .unwrap();
        function.prototype.as_mut().unwrap().return_type = TypeRef::Primitive {
            name: PrimitiveType::U64,
        };
        function.evidence.push(ModelEvidence {
            source: ModelSource::AnalystAssertion,
            detail: "analyst return-type correction".to_owned(),
            site: Some(entry),
        });
        let report = import_ghidra_functions(bytes, &mut edited, &snapshot).unwrap();
        assert_eq!(report.conflicting_prototypes, 1);
        assert_eq!(
            edited
                .functions
                .iter()
                .find(|function| function.entry == entry)
                .unwrap()
                .prototype
                .as_ref()
                .unwrap()
                .return_type,
            TypeRef::Primitive {
                name: PrimitiveType::U64
            }
        );
        assert!(
            edited
                .conflicts
                .iter()
                .any(|conflict| { conflict.subject == "function:0x20137c:prototype" })
        );

        let function = snapshot
            .functions
            .iter_mut()
            .find(|function| function.entry.offset == "0x20137c")
            .unwrap();
        function.prototype.as_mut().unwrap().signature_source = "ANALYSIS".to_owned();
        let mut hinted = init_model(bytes).unwrap();
        let report = import_ghidra_functions(bytes, &mut hinted, &snapshot).unwrap();
        assert_eq!(report.imported_prototypes, 0);
        assert_eq!(report.unresolved_prototypes, 1);
        let hinted_function = hinted
            .functions
            .iter()
            .find(|function| function.entry == entry)
            .unwrap();
        assert!(hinted_function.prototype.is_none());
        assert!(hinted_function.evidence.iter().any(|evidence| {
            evidence.source == ModelSource::GhidraAnalysis && evidence.detail.contains("ANALYSIS")
        }));

        let function = snapshot
            .functions
            .iter_mut()
            .find(|function| function.entry.offset == "0x20137c")
            .unwrap();
        let prototype = function.prototype.as_mut().unwrap();
        prototype.signature_source = "IMPORTED".to_owned();
        prototype.calling_convention = Some("__cdecl".to_owned());
        let mut unknown_abi = init_model(bytes).unwrap();
        let report = import_ghidra_functions(bytes, &mut unknown_abi, &snapshot).unwrap();
        assert_eq!(report.imported_prototypes, 0);
        assert_eq!(report.unresolved_prototypes, 1);
    }

    #[test]
    fn real_dwarf_prototype_links_recursive_struct_after_dwarf_import() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prototype.elf"
        ));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prototype_dwarf_v2.json"
            )),
            "7d9b81be8caadbca522b8fc5c1d89b0c2650e8902791e8d777b3c8c87ed4ed09",
        )
        .unwrap();
        let mut model = init_model(bytes).unwrap();
        import_dwarf(bytes, &mut model).unwrap();
        let report = import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert_eq!(report.imported_prototypes, 0);
        assert_eq!(report.matched_prototypes, 1);
        assert_eq!(report.unresolved_prototypes, 1);
        let walk = model
            .functions
            .iter()
            .find(|function| function.name == "walk")
            .unwrap();
        let prototype = walk.prototype.as_ref().unwrap();
        assert_eq!(prototype.parameters.len(), 2);
        assert!(matches!(
            prototype.parameters[0].ty,
            TypeRef::Pointer { .. }
        ));
        assert_eq!(
            prototype.parameters[1].ty,
            TypeRef::Primitive {
                name: PrimitiveType::I32
            }
        );
    }

    #[test]
    fn imported_struct_field_refines_existing_type_and_preserves_conflict() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prototype.elf"
        ));
        let digest = "7d9b81be8caadbca522b8fc5c1d89b0c2650e8902791e8d777b3c8c87ed4ed09";
        let mut snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prototype_dwarf_v2.json"
            )),
            digest,
        )
        .unwrap();
        let high = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prototype_high_v2.json"
            )),
            digest,
        )
        .unwrap();
        let node_pointer = high
            .selected_function
            .high_pcode
            .as_ref()
            .unwrap()
            .operations
            .iter()
            .flat_map(|operation| operation.output.iter().chain(&operation.inputs))
            .find(|node| node.ssa_id == 217 && node.high_name.as_deref() == Some("node"))
            .unwrap()
            .high_type
            .clone()
            .unwrap();
        assert_eq!(node_pointer.target_type.as_ref().unwrap().fields.len(), 2);
        snapshot
            .functions
            .iter_mut()
            .find(|function| function.name == "walk")
            .unwrap()
            .prototype
            .as_mut()
            .unwrap()
            .parameters[0]
            .data_type = node_pointer;

        let mut model = init_model(bytes).unwrap();
        import_dwarf(bytes, &mut model).unwrap();
        let definition = model
            .types
            .iter_mut()
            .find(|definition| definition.name.starts_with("Node_dwarf_"))
            .unwrap();
        let id = definition.id.clone();
        let TypeDefinitionKind::Struct { fields } = &mut definition.kind else {
            panic!("Node must be a struct");
        };
        fields.clear();
        validate_model(bytes, &model).unwrap();
        let empty = model.clone();

        import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        let TypeDefinitionKind::Struct { fields } = &model
            .types
            .iter()
            .find(|definition| definition.id == id)
            .unwrap()
            .kind
        else {
            unreachable!();
        };
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].name, "value");
        assert_eq!(fields[0].offset_bytes, 0);
        assert_eq!(
            fields[0].ty,
            TypeRef::Primitive {
                name: PrimitiveType::I32
            }
        );
        assert_eq!(fields[0].evidence[0].source, ModelSource::GhidraAnalysis);
        let imported = model.clone();
        import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert_eq!(model, imported);

        let mut overlapping_snapshot = snapshot.clone();
        overlapping_snapshot
            .functions
            .iter_mut()
            .find(|function| function.name == "walk")
            .unwrap()
            .prototype
            .as_mut()
            .unwrap()
            .parameters[0]
            .data_type
            .target_type
            .as_mut()
            .unwrap()
            .fields[1]
            .offset_bytes = 0;
        let mut ambiguous = empty.clone();
        import_ghidra_functions(bytes, &mut ambiguous, &overlapping_snapshot).unwrap();
        let TypeDefinitionKind::Struct { fields } = &ambiguous
            .types
            .iter()
            .find(|definition| definition.id == id)
            .unwrap()
            .kind
        else {
            unreachable!();
        };
        assert!(fields.is_empty());

        let mut conflicting = empty;
        let TypeDefinitionKind::Struct { fields } = &mut conflicting
            .types
            .iter_mut()
            .find(|definition| definition.id == id)
            .unwrap()
            .kind
        else {
            unreachable!();
        };
        fields.push(ModelField {
            name: "value".to_owned(),
            offset_bytes: 0,
            ty: TypeRef::Primitive {
                name: PrimitiveType::U32,
            },
            evidence: vec![ModelEvidence {
                source: ModelSource::AnalystAssertion,
                detail: "analyst field type".to_owned(),
                site: None,
            }],
        });
        import_ghidra_functions(bytes, &mut conflicting, &snapshot).unwrap();
        let TypeDefinitionKind::Struct { fields } = &conflicting
            .types
            .iter()
            .find(|definition| definition.id == id)
            .unwrap()
            .kind
        else {
            unreachable!();
        };
        assert_eq!(
            fields[0].ty,
            TypeRef::Primitive {
                name: PrimitiveType::U32
            }
        );
        assert!(conflicting.conflicts.iter().any(|conflict| {
            conflict.subject == format!("type:{id}:field:0")
                && conflict
                    .evidence
                    .iter()
                    .any(|item| item.source == ModelSource::GhidraAnalysis)
        }));
        let first_conflict = conflicting.clone();
        import_ghidra_functions(bytes, &mut conflicting, &snapshot).unwrap();
        assert_eq!(conflicting, first_conflict);
    }

    #[test]
    fn real_high_pcode_hints_are_structured_linked_evidence_and_idempotent() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prototype.elf"
        ));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prototype_high_v2.json"
            )),
            "7d9b81be8caadbca522b8fc5c1d89b0c2650e8902791e8d777b3c8c87ed4ed09",
        )
        .unwrap();
        let mut model = init_model(bytes).unwrap();
        let report = import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert!(report.imported_high_pcode_hints > 30);
        assert_eq!(report.skipped_high_pcode_hints, 0);
        assert_eq!(
            model.high_pcode_hints.len(),
            report.imported_high_pcode_hints
        );
        let first = model.high_pcode_hints[0].clone();
        assert_eq!(first.function_entry.value, Address(0x1320));
        assert_eq!(first.source_site.value, Address(0x1320));
        assert_eq!(first.ssa_id, 10);
        assert_eq!(first.high_type.as_ref().unwrap().display_name, "bool");
        assert!(model.high_pcode_hints.iter().any(|hint| {
            hint.ssa_id == 217
                && hint.high_name.as_deref() == Some("node")
                && hint.high_type.as_ref().unwrap().display_name == "Node *"
                && hint
                    .high_type
                    .as_ref()
                    .unwrap()
                    .target_type
                    .as_ref()
                    .unwrap()
                    .fields
                    .iter()
                    .map(|field| (field.name.as_deref(), field.offset_bytes))
                    .collect::<Vec<_>>()
                    == vec![(Some("value"), 0), (Some("next"), 8)]
        }));
        assert!(model.types.is_empty());
        assert!(model.stack_objects.is_empty());
        let encoded = serde_json::to_vec(&model).unwrap();
        assert_eq!(parse_model(&encoded).unwrap(), model);
        let mut legacy_json = serde_json::to_value(&model).unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("high_pcode_hints");
        assert!(
            parse_model(&serde_json::to_vec(&legacy_json).unwrap())
                .unwrap()
                .high_pcode_hints
                .is_empty()
        );
        let first_import = model.clone();
        let repeat = import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        assert_eq!(repeat.imported_high_pcode_hints, 0);
        assert_eq!(model, first_import);

        let mut changed_snapshot = snapshot.clone();
        changed_snapshot
            .selected_function
            .high_pcode
            .as_mut()
            .unwrap()
            .operations[0]
            .output
            .as_mut()
            .unwrap()
            .high_name = Some("different_analysis_name".to_owned());
        let mut revised_evidence = model.clone();
        let changed_report =
            import_ghidra_functions(bytes, &mut revised_evidence, &changed_snapshot).unwrap();
        assert_eq!(changed_report.imported_high_pcode_hints, 1);
        assert!(revised_evidence.high_pcode_hints.contains(&first));
        assert!(revised_evidence.high_pcode_hints.iter().any(|hint| {
            hint.operation_index == 0
                && hint.input_index.is_none()
                && hint.high_name.as_deref() == Some("different_analysis_name")
        }));

        let mut edited = model.clone();
        edited.high_pcode_hints.clear(); // An older editor omitted the optional field.
        let function = edited
            .functions
            .iter_mut()
            .find(|function| function.entry.value == Address(0x1320))
            .unwrap();
        function.name = "analyst_walk".to_owned();
        record_analyst_edits(&model, &mut edited).unwrap();
        assert_eq!(edited.high_pcode_hints, model.high_pcode_hints);
        import_ghidra_functions(bytes, &mut edited, &snapshot).unwrap();
        assert_eq!(
            edited
                .functions
                .iter()
                .find(|function| function.entry.value == Address(0x1320))
                .unwrap()
                .name,
            "analyst_walk"
        );
        assert_eq!(edited.high_pcode_hints, model.high_pcode_hints);
    }

    #[test]
    fn high_pcode_hints_reject_unmapped_sites_and_duplicates() {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prototype.elf"
        ));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prototype_high_v2.json"
            )),
            "7d9b81be8caadbca522b8fc5c1d89b0c2650e8902791e8d777b3c8c87ed4ed09",
        )
        .unwrap();
        let mut model = init_model(bytes).unwrap();
        import_ghidra_functions(bytes, &mut model, &snapshot).unwrap();
        let mut bad = model.clone();
        bad.high_pcode_hints[0].source_site.value = Address(u64::MAX);
        assert!(validate_model(bytes, &bad).is_err());
        let mut bad = model.clone();
        bad.high_pcode_hints.push(bad.high_pcode_hints[0].clone());
        assert!(validate_model(bytes, &bad).is_err());
        let mut bad = model.clone();
        bad.high_pcode_hints[0].high_name = Some("x".repeat(4097));
        assert!(validate_model(bytes, &bad).is_err());
    }
}
