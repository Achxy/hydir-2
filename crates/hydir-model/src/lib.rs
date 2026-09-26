//! Editable, digest-bound analyst model. Inference never silently replaces
//! analyst assertions or converts an unresolved observation into a proof.

use hydir_core::{Address, FactSource, Location, ProgramSpec, ScalarType, TypedModel};
use hydir_loader::import_elf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod dwarf;
mod ghidra;
mod infer;
pub use dwarf::import_dwarf;
pub use ghidra::{GhidraModelImportReport, import_ghidra_functions};
pub use infer::{InferenceReport, infer_model};

pub const ANALYSIS_MODEL_VERSION: u32 = 1;
pub const MAX_MODEL_BYTES: usize = 16 * 1024 * 1024;
const MAX_TYPES: usize = 16_384;
const MAX_FUNCTIONS: usize = 65_536;
const MAX_FIELDS: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSource {
    ElfMetadata,
    Dwarf,
    GhidraAnalysis,
    NativeAnalysis,
    AnalystAssertion,
    LegacyTypedModel,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelEvidence {
    pub source: ModelSource,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<Location>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveType {
    Void,
    Bool,
    U8,
    U16,
    U32,
    U64,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
}

impl PrimitiveType {
    pub fn size_bytes(self) -> Option<u64> {
        match self {
            Self::Void => None,
            Self::Bool | Self::U8 | Self::I8 => Some(1),
            Self::U16 | Self::I16 => Some(2),
            Self::U32 | Self::I32 | Self::F32 => Some(4),
            Self::U64 | Self::I64 | Self::F64 => Some(8),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeRef {
    Primitive {
        name: PrimitiveType,
    },
    Named {
        id: String,
    },
    Pointer {
        to: Box<TypeRef>,
    },
    Array {
        of: Box<TypeRef>,
        count: u64,
    },
    /// Bytes with no inferred source type; used for uncertain layout spans.
    Bytes {
        size: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelField {
    pub name: String,
    pub offset_bytes: u64,
    pub ty: TypeRef,
    pub evidence: Vec<ModelEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeDefinitionKind {
    Struct {
        fields: Vec<ModelField>,
    },
    Union {
        fields: Vec<ModelField>,
    },
    Enum {
        underlying: PrimitiveType,
        variants: BTreeMap<String, i64>,
    },
    Alias {
        target: TypeRef,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TypeDefinition {
    pub id: String,
    pub name: String,
    pub size_bytes: u64,
    /// Native inference knows only the largest observed end offset. DWARF and
    /// analyst layouts can assert an exact object size.
    #[serde(default)]
    pub size_is_lower_bound: bool,
    pub kind: TypeDefinitionKind,
    pub evidence: Vec<ModelEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelParameter {
    pub name: String,
    pub ty: TypeRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelPrototype {
    pub parameters: Vec<ModelParameter>,
    pub return_type: TypeRef,
    pub calling_convention: String,
    #[serde(default)]
    pub variadic: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelFunction {
    pub entry: Location,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prototype: Option<ModelPrototype>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub inferred_parameters: BTreeMap<String, TypeRef>,
    pub evidence: Vec<ModelEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelStackObject {
    pub function_entry: Location,
    pub entry_rsp_offset: i64,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ty: Option<TypeRef>,
    pub evidence: Vec<ModelEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ModelConflict {
    pub subject: String,
    pub detail: String,
    pub evidence: Vec<ModelEvidence>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisModel {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub target_triple: String,
    pub revision: u64,
    pub types: Vec<TypeDefinition>,
    pub functions: Vec<ModelFunction>,
    pub stack_objects: Vec<ModelStackObject>,
    #[serde(default)]
    pub conflicts: Vec<ModelConflict>,
}

pub fn init_model(bytes: &[u8]) -> Result<AnalysisModel, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let functions = spec
        .functions
        .iter()
        .map(|function| ModelFunction {
            entry: function.location.unwrap_or(Location {
                address_space: 0,
                value: function.address,
            }),
            name: function.name.clone(),
            prototype: None,
            inferred_parameters: BTreeMap::new(),
            evidence: vec![ModelEvidence {
                source: ModelSource::ElfMetadata,
                detail: function.provenance.clone(),
                site: None,
            }],
        })
        .collect();
    let mut model = AnalysisModel {
        schema_version: ANALYSIS_MODEL_VERSION,
        binary_sha256: spec.binary_sha256.clone(),
        target_triple: spec.target_triple.clone(),
        revision: 1,
        types: Vec::new(),
        functions,
        stack_objects: Vec::new(),
        conflicts: Vec::new(),
    };
    import_legacy_typed_model(&mut model, &spec)?;
    validate_model(bytes, &model)?;
    Ok(model)
}

pub fn parse_model(bytes: &[u8]) -> Result<AnalysisModel, String> {
    if bytes.len() > MAX_MODEL_BYTES {
        return Err("analysis model exceeds 16 MiB".to_owned());
    }
    let model: AnalysisModel = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid analysis model JSON: {error}"))?;
    validate_structure(&model)?;
    Ok(model)
}

fn preserve_evidence(
    previous: &[ModelEvidence],
    current: &mut Vec<ModelEvidence>,
    changed: bool,
    detail: &str,
) -> Result<(), String> {
    let new_machine_evidence = current
        .iter()
        .any(|item| item.source != ModelSource::AnalystAssertion && !previous.contains(item));
    for item in previous {
        if item.source != ModelSource::AnalystAssertion && !current.contains(item) {
            current.push(item.clone());
        }
    }
    if changed && !new_machine_evidence {
        let assertion = ModelEvidence {
            source: ModelSource::AnalystAssertion,
            detail: detail.to_owned(),
            site: None,
        };
        if !current.contains(&assertion) {
            current.push(assertion);
        }
    }
    if current.len() > 256 {
        return Err("edited model fact exceeds 256 evidence items".to_owned());
    }
    Ok(())
}

/// Record semantic edits made to an existing local model. Newly imported
/// DWARF/native evidence keeps its own provenance; unchanged machine evidence
/// survives a JSON edit, including when the editor omitted it from the file.
pub fn record_analyst_edits(
    previous: &AnalysisModel,
    candidate: &mut AnalysisModel,
) -> Result<(), String> {
    if previous.binary_sha256 != candidate.binary_sha256 {
        return Err("cannot compare models for different binaries".to_owned());
    }
    let mut edit_conflicts = Vec::new();
    for definition in &mut candidate.types {
        if let Some(old) = previous.types.iter().find(|old| old.id == definition.id) {
            let changed = old.name != definition.name
                || old.size_bytes != definition.size_bytes
                || old.size_is_lower_bound != definition.size_is_lower_bound
                || std::mem::discriminant(&old.kind) != std::mem::discriminant(&definition.kind)
                || matches!(
                    (&old.kind, &definition.kind),
                    (
                        TypeDefinitionKind::Enum { .. },
                        TypeDefinitionKind::Enum { .. }
                    ) | (
                        TypeDefinitionKind::Alias { .. },
                        TypeDefinitionKind::Alias { .. }
                    )
                ) && old.kind != definition.kind;
            preserve_evidence(
                &old.evidence,
                &mut definition.evidence,
                changed,
                "local type edit",
            )?;
            if let (
                TypeDefinitionKind::Struct { fields: old_fields }
                | TypeDefinitionKind::Union { fields: old_fields },
                TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields },
            ) = (&old.kind, &mut definition.kind)
            {
                for field in fields {
                    if let Some(old_field) = old_fields.iter().find(|prior| {
                        prior.offset_bytes == field.offset_bytes || prior.name == field.name
                    }) {
                        let analyst_type_change = old_field.ty != field.ty
                            && !field.evidence.iter().any(|item| {
                                item.source != ModelSource::AnalystAssertion
                                    && !old_field.evidence.contains(item)
                            });
                        let changed = old_field.name != field.name
                            || old_field.offset_bytes != field.offset_bytes
                            || old_field.ty != field.ty;
                        preserve_evidence(
                            &old_field.evidence,
                            &mut field.evidence,
                            changed,
                            "local field edit",
                        )?;
                        if analyst_type_change {
                            let evidence = old_field
                                .evidence
                                .iter()
                                .filter(|item| item.source != ModelSource::AnalystAssertion)
                                .cloned()
                                .collect::<Vec<_>>();
                            if !evidence.is_empty() {
                                edit_conflicts.push(ModelConflict {
                                    subject: format!(
                                        "type:{}:field:{}",
                                        definition.id, old_field.offset_bytes
                                    ),
                                    detail: format!(
                                        "analyst type {:?} differs from prior model type {:?}; earlier evidence retained",
                                        field.ty, old_field.ty
                                    ),
                                    evidence,
                                });
                            }
                        }
                    } else {
                        preserve_evidence(&[], &mut field.evidence, true, "local field addition")?;
                    }
                }
            }
        } else {
            preserve_evidence(&[], &mut definition.evidence, true, "local type addition")?;
            if let TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } =
                &mut definition.kind
            {
                for field in fields {
                    preserve_evidence(&[], &mut field.evidence, true, "local field addition")?;
                }
            }
        }
    }
    for function in &mut candidate.functions {
        if let Some(old) = previous
            .functions
            .iter()
            .find(|old| old.entry == function.entry)
        {
            let changed = old.name != function.name || old.prototype != function.prototype;
            preserve_evidence(
                &old.evidence,
                &mut function.evidence,
                changed,
                "local function edit",
            )?;
        } else {
            preserve_evidence(&[], &mut function.evidence, true, "local function addition")?;
        }
    }
    for object in &mut candidate.stack_objects {
        if let Some(old) = previous.stack_objects.iter().find(|old| {
            old.function_entry == object.function_entry
                && old.entry_rsp_offset == object.entry_rsp_offset
        }) {
            let changed = old.size_bytes != object.size_bytes || old.ty != object.ty;
            preserve_evidence(
                &old.evidence,
                &mut object.evidence,
                changed,
                "local stack object edit",
            )?;
        } else {
            preserve_evidence(
                &[],
                &mut object.evidence,
                true,
                "local stack object addition",
            )?;
        }
    }
    for conflict in edit_conflicts {
        if !candidate.conflicts.iter().any(|existing| {
            existing.subject == conflict.subject && existing.detail == conflict.detail
        }) {
            candidate.conflicts.push(conflict);
        }
    }
    Ok(())
}

pub fn validate_model(bytes: &[u8], model: &AnalysisModel) -> Result<(), String> {
    validate_structure(model)?;
    if model.binary_sha256 != format!("{:x}", Sha256::digest(bytes)) {
        return Err("analysis model binary digest differs from supplied ELF".to_owned());
    }
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    if model.target_triple != spec.target_triple {
        return Err("analysis model target triple differs from supplied ELF".to_owned());
    }
    Ok(())
}

fn valid_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !matches!(
            name,
            "auto"
                | "break"
                | "case"
                | "char"
                | "const"
                | "continue"
                | "default"
                | "do"
                | "double"
                | "else"
                | "enum"
                | "extern"
                | "float"
                | "for"
                | "goto"
                | "if"
                | "int"
                | "long"
                | "register"
                | "return"
                | "short"
                | "signed"
                | "sizeof"
                | "static"
                | "struct"
                | "switch"
                | "typedef"
                | "union"
                | "unsigned"
                | "void"
                | "volatile"
                | "while"
                | "_Bool"
        )
}

fn type_size(
    ty: &TypeRef,
    defs: &BTreeMap<&str, &TypeDefinition>,
    stack: &mut BTreeSet<String>,
    depth: usize,
) -> Result<Option<u64>, String> {
    if depth > 32 {
        return Err("type reference depth exceeds 32".to_owned());
    }
    match ty {
        TypeRef::Primitive { name } => Ok(name.size_bytes()),
        TypeRef::Pointer { to } => {
            // Pointers break by-value recursion, but their referents must exist.
            validate_type_ref(to, defs, depth + 1)?;
            Ok(Some(8))
        }
        TypeRef::Array { of, count } => {
            if *count == 0 || *count > 1_000_000 {
                return Err("array count is outside 1..=1000000".to_owned());
            }
            let elem = type_size(of, defs, stack, depth + 1)?
                .ok_or("array element has incomplete size")?;
            elem.checked_mul(*count)
                .map(Some)
                .ok_or("array byte size overflows".to_owned())
        }
        TypeRef::Bytes { size } => {
            if *size == 0 || *size > 1_048_576 {
                return Err("byte span is outside 1..=1048576".to_owned());
            }
            Ok(Some(*size))
        }
        TypeRef::Named { id } => {
            let def = defs
                .get(id.as_str())
                .ok_or_else(|| format!("unknown type id {id}"))?;
            if def.size_is_lower_bound {
                return Err(format!(
                    "incomplete inferred type {id} cannot be used by value"
                ));
            }
            if !stack.insert(id.clone()) {
                return Err(format!("by-value recursive type {id}"));
            }
            match &def.kind {
                TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } => {
                    for field in fields {
                        type_size(&field.ty, defs, stack, depth + 1)?;
                    }
                }
                TypeDefinitionKind::Alias { target } => {
                    type_size(target, defs, stack, depth + 1)?;
                }
                TypeDefinitionKind::Enum { .. } => {}
            }
            stack.remove(id);
            Ok(Some(def.size_bytes))
        }
    }
}

fn validate_type_ref(
    ty: &TypeRef,
    defs: &BTreeMap<&str, &TypeDefinition>,
    depth: usize,
) -> Result<(), String> {
    if depth > 32 {
        return Err("type reference depth exceeds 32".to_owned());
    }
    match ty {
        TypeRef::Named { id } if !defs.contains_key(id.as_str()) => {
            Err(format!("unknown type id {id}"))
        }
        TypeRef::Pointer { to } => validate_type_ref(to, defs, depth + 1),
        TypeRef::Array { of, count } => {
            if *count == 0 || *count > 1_000_000 {
                return Err("array count is outside 1..=1000000".to_owned());
            }
            validate_type_ref(of, defs, depth + 1)
        }
        TypeRef::Bytes { size } if *size == 0 || *size > 1_048_576 => {
            Err("byte span is outside 1..=1048576".to_owned())
        }
        _ => Ok(()),
    }
}

fn validate_evidence(evidence: &[ModelEvidence]) -> Result<(), String> {
    if evidence.is_empty()
        || evidence.len() > 256
        || evidence
            .iter()
            .any(|item| item.detail.trim().is_empty() || item.detail.len() > 4096)
    {
        return Err("each model fact needs 1..=256 nonempty bounded evidence items".to_owned());
    }
    Ok(())
}

pub fn validate_structure(model: &AnalysisModel) -> Result<(), String> {
    if model.schema_version != ANALYSIS_MODEL_VERSION {
        return Err("unsupported analysis model schema version".to_owned());
    }
    if model.revision == 0 {
        return Err("analysis model revision must be positive".to_owned());
    }
    if model.binary_sha256.len() != 64
        || !model.binary_sha256.bytes().all(|ch| ch.is_ascii_hexdigit())
    {
        return Err("invalid analysis model binary digest".to_owned());
    }
    if model.target_triple.is_empty() || model.target_triple.len() > 256 {
        return Err("invalid analysis model target triple".to_owned());
    }
    if model.types.len() > MAX_TYPES
        || model.functions.len() > MAX_FUNCTIONS
        || model.stack_objects.len() > MAX_FUNCTIONS
        || model.conflicts.len() > MAX_FUNCTIONS
    {
        return Err("analysis model row limit exceeded".to_owned());
    }
    let mut defs = BTreeMap::new();
    let mut names = BTreeSet::new();
    for def in &model.types {
        if !valid_identifier(&def.id)
            || !valid_identifier(&def.name)
            || !defs.insert(def.id.as_str(), def).is_none()
            || !names.insert(def.name.as_str())
        {
            return Err("duplicate or invalid type id/name".to_owned());
        }
        if def.size_bytes == 0 || def.size_bytes > 1_048_576 {
            return Err(format!("type {} has invalid size", def.id));
        }
        validate_evidence(&def.evidence)?;
    }
    for def in &model.types {
        match &def.kind {
            TypeDefinitionKind::Struct { fields } | TypeDefinitionKind::Union { fields } => {
                if fields.len() > MAX_FIELDS {
                    return Err(format!("type {} has too many fields", def.id));
                }
                let is_union = matches!(def.kind, TypeDefinitionKind::Union { .. });
                let mut end_prev = 0;
                let mut field_names = BTreeSet::new();
                for field in fields {
                    if !valid_identifier(&field.name) || !field_names.insert(field.name.as_str()) {
                        return Err(format!(
                            "type {} has duplicate or invalid field name",
                            def.id
                        ));
                    }
                    validate_evidence(&field.evidence)?;
                    if is_union && field.offset_bytes != 0 {
                        return Err(format!("union {} field has nonzero offset", def.id));
                    }
                    let size =
                        type_size(&field.ty, &defs, &mut BTreeSet::from([def.id.clone()]), 0)?
                            .ok_or("field has void type")?;
                    let end = field
                        .offset_bytes
                        .checked_add(size)
                        .ok_or("field end overflows")?;
                    if end > def.size_bytes || (!is_union && field.offset_bytes < end_prev) {
                        return Err(format!(
                            "type {} has overlapping or out-of-bounds fields",
                            def.id
                        ));
                    }
                    if !is_union {
                        end_prev = end;
                    }
                }
            }
            TypeDefinitionKind::Enum {
                underlying,
                variants,
            } => {
                if underlying.size_bytes() != Some(def.size_bytes)
                    || variants.len() > MAX_FIELDS
                    || variants.keys().any(|name| !valid_identifier(name))
                {
                    return Err(format!("enum {} has invalid layout", def.id));
                }
            }
            TypeDefinitionKind::Alias { target } => {
                if type_size(target, &defs, &mut BTreeSet::from([def.id.clone()]), 0)?
                    != Some(def.size_bytes)
                {
                    return Err(format!("alias {} size differs from target", def.id));
                }
            }
        }
    }
    let mut entries = BTreeSet::new();
    for function in &model.functions {
        if !entries.insert(function.entry) || function.name.is_empty() || function.name.len() > 4096
        {
            return Err("duplicate function entry or invalid name".to_owned());
        }
        validate_evidence(&function.evidence)?;
        if let Some(proto) = &function.prototype {
            if proto.parameters.len() > 256 || proto.calling_convention != "sysv_amd64" {
                return Err("invalid model prototype ABI/arity".to_owned());
            }
            validate_type_ref(&proto.return_type, &defs, 0)?;
            if !matches!(
                proto.return_type,
                TypeRef::Primitive {
                    name: PrimitiveType::Void
                }
            ) {
                type_size(&proto.return_type, &defs, &mut BTreeSet::new(), 0)?
                    .ok_or("incomplete model return type")?;
            }
            let mut parameter_names = BTreeSet::new();
            for param in &proto.parameters {
                if !valid_identifier(&param.name)
                    || !parameter_names.insert(param.name.as_str())
                    || matches!(
                        param.ty,
                        TypeRef::Primitive {
                            name: PrimitiveType::Void
                        }
                    )
                {
                    return Err("invalid model parameter".to_owned());
                }
                validate_type_ref(&param.ty, &defs, 0)?;
                type_size(&param.ty, &defs, &mut BTreeSet::new(), 0)?
                    .ok_or("incomplete model parameter type")?;
            }
        }
        for (location, ty) in &function.inferred_parameters {
            if !matches!(
                location.as_str(),
                "rdi" | "rsi" | "rdx" | "rcx" | "r8" | "r9"
            ) {
                return Err("inferred parameter location is not a SysV GPR argument".to_owned());
            }
            validate_type_ref(ty, &defs, 0)?;
        }
    }
    for object in &model.stack_objects {
        if object.size_bytes == 0
            || object.size_bytes > 1_048_576
            || !entries.contains(&object.function_entry)
        {
            return Err("invalid stack object bounds/function".to_owned());
        }
        validate_evidence(&object.evidence)?;
        if let Some(ty) = &object.ty {
            if type_size(ty, &defs, &mut BTreeSet::new(), 0)? != Some(object.size_bytes) {
                return Err("stack object type size differs from object size".to_owned());
            }
        }
    }
    for conflict in &model.conflicts {
        if conflict.subject.trim().is_empty() || conflict.detail.trim().is_empty() {
            return Err("empty model conflict".to_owned());
        }
        validate_evidence(&conflict.evidence)?;
    }
    Ok(())
}

pub fn import_legacy_typed_model(
    model: &mut AnalysisModel,
    spec: &ProgramSpec,
) -> Result<(), String> {
    let TypedModel {
        prototypes,
        stack_facts,
        ..
    } = &spec.typed_model;
    for old in prototypes {
        let entry = Location {
            address_space: 0,
            value: old.entry,
        };
        let Some(function) = model
            .functions
            .iter_mut()
            .find(|function| function.entry == entry)
        else {
            continue;
        };
        if function.prototype.is_some() {
            continue;
        }
        let cvt = |ty: ScalarType| TypeRef::Primitive {
            name: match ty {
                ScalarType::U64 => PrimitiveType::U64,
                ScalarType::Void => PrimitiveType::Void,
            },
        };
        function.prototype = Some(ModelPrototype {
            parameters: old
                .parameters
                .iter()
                .enumerate()
                .map(|(i, ty)| ModelParameter {
                    name: format!("arg_{i}"),
                    ty: cvt(*ty),
                })
                .collect(),
            return_type: cvt(old.return_type),
            calling_convention: "sysv_amd64".to_owned(),
            variadic: false,
        });
        function.evidence.push(ModelEvidence {
            source: ModelSource::LegacyTypedModel,
            detail: old.provenance.scope.clone(),
            site: None,
        });
    }
    for old in stack_facts {
        let entry = Location {
            address_space: 0,
            value: old.function_entry,
        };
        if !model
            .functions
            .iter()
            .any(|function| function.entry == entry)
        {
            continue;
        }
        let size = u64::from(old.width_bits).div_ceil(8);
        if size == 0 {
            continue;
        }
        model.stack_objects.push(ModelStackObject {
            function_entry: entry,
            entry_rsp_offset: old.entry_rsp_offset,
            size_bytes: size,
            ty: None,
            evidence: vec![ModelEvidence {
                source: match old.provenance.source {
                    FactSource::AnalystAssertion => ModelSource::AnalystAssertion,
                    _ => ModelSource::LegacyTypedModel,
                },
                detail: old.provenance.scope.clone(),
                site: None,
            }],
        });
    }
    Ok(())
}

pub fn location_from_address(address: u64) -> Location {
    Location {
        address_space: 0,
        value: Address(address),
    }
}
