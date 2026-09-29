//! Private typed-C cache. Entries are keyed by binary, model revision,
//! analysis version, options, and function entry. On a model edit we carry
//! only entries whose type dependencies and transitive callees are unchanged.

use super::{LocalProject, LocalProjectStore, db_error};
use hydir_core::{Address, Location};
use hydir_hlc::{
    HIGH_LEVEL_CFG_CIR_VERSION, HIGH_LEVEL_CIR_VERSION, HighCfgStatement, HighExpr,
    HighLevelCfgCir, HighLevelCir, HighStatement, emit_typed_c, emit_typed_cfg_c,
};
use hydir_ir::{FunctionIr, MachineFunctionIr};
use hydir_model::{AnalysisModel, TypeDefinitionKind, TypeRef, validate_structure};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// Bump when typed lowering/emission behavior changes without a CIR schema bump.
// Version 2 also invalidates rows written before source IR fingerprints existed.
const ANALYSIS_VERSION: i64 = 2;
const MAX_C_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_ROWS: usize = 4096;

fn options_hash(options: &str) -> Result<String, String> {
    if options.len() > 1024 {
        return Err("typed C cache options exceed 1024 bytes".to_owned());
    }
    Ok(format!("{:x}", Sha256::digest(options.as_bytes())))
}

fn source_options_hash(
    options: &str,
    machine: &MachineFunctionIr,
    function: &FunctionIr,
) -> Result<String, String> {
    options_hash(options)?;
    if machine.binary_sha256 != function.binary_sha256 || machine.entry != function.entry {
        return Err("typed C cache source IR identities differ".to_owned());
    }
    let machine_json = serde_json::to_vec(machine).map_err(|error| error.to_string())?;
    let function_json = serde_json::to_vec(function).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    for part in [options.as_bytes(), &machine_json, &function_json] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn entry_value(entry: Location) -> String {
    format!("{:016x}", entry.value.0)
}

fn cache_digest(content: &[u8], type_ids_json: &[u8], calls_json: &[u8]) -> String {
    let mut hasher = Sha256::new();
    for part in [content, type_ids_json, calls_json] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    format!("{:x}", hasher.finalize())
}

fn collect_types(ty: &TypeRef, model: &AnalysisModel, ids: &mut BTreeSet<String>) {
    match ty {
        TypeRef::Named { id } => {
            if !ids.insert(id.clone()) {
                return;
            }
            if let Some(definition) = model.types.iter().find(|definition| definition.id == *id) {
                match &definition.kind {
                    TypeDefinitionKind::Struct { fields }
                    | TypeDefinitionKind::Union { fields } => {
                        for field in fields {
                            collect_types(&field.ty, model, ids);
                        }
                    }
                    TypeDefinitionKind::Alias { target } => collect_types(target, model, ids),
                    TypeDefinitionKind::Enum { .. } => {}
                }
            }
        }
        TypeRef::Pointer { to } => collect_types(to, model, ids),
        TypeRef::Array { of, .. } => collect_types(of, model, ids),
        TypeRef::Primitive { .. } | TypeRef::Bytes { .. } => {}
    }
}

fn collect_expr_call_types(expr: &HighExpr, model: &AnalysisModel, ids: &mut BTreeSet<String>) {
    match expr {
        HighExpr::Call {
            callee, arguments, ..
        } => {
            if let Some(prototype) = model
                .functions
                .iter()
                .find(|row| row.entry == *callee)
                .and_then(|row| row.prototype.as_ref())
            {
                collect_types(&prototype.return_type, model, ids);
                for parameter in &prototype.parameters {
                    collect_types(&parameter.ty, model, ids);
                }
            }
            for argument in arguments {
                collect_expr_call_types(argument, model, ids);
            }
        }
        HighExpr::Binary { left, right, .. } => {
            collect_expr_call_types(left, model, ids);
            collect_expr_call_types(right, model, ids);
        }
        HighExpr::Field { base, .. } => collect_expr_call_types(base, model, ids),
        HighExpr::Variable { .. } | HighExpr::Constant { .. } => {}
    }
}

fn used_type_ids(ir: &HighLevelCir, model: &AnalysisModel) -> Vec<String> {
    let mut ids = BTreeSet::new();
    collect_types(&ir.return_type, model, &mut ids);
    for parameter in &ir.parameters {
        collect_types(&parameter.ty, model, &mut ids);
    }
    for statement in &ir.statements {
        match statement {
            HighStatement::Let { ty, value, .. } => {
                collect_types(ty, model, &mut ids);
                collect_expr_call_types(value, model, &mut ids);
            }
            HighStatement::StoreField { base, value, .. } => {
                collect_expr_call_types(base, model, &mut ids);
                collect_expr_call_types(value, model, &mut ids);
            }
            HighStatement::Return { value, .. } => {
                collect_expr_call_types(value, model, &mut ids);
            }
        }
    }
    ids.into_iter().collect()
}

fn used_cfg_type_ids(ir: &HighLevelCfgCir, model: &AnalysisModel) -> Vec<String> {
    let mut ids = BTreeSet::new();
    collect_types(&ir.return_type, model, &mut ids);
    for parameter in &ir.parameters {
        collect_types(&parameter.ty, model, &mut ids);
    }
    for block in &ir.blocks {
        for statement in &block.statements {
            let field_view = match statement {
                HighCfgStatement::Load { field_view, .. }
                | HighCfgStatement::Store { field_view, .. } => field_view.as_ref(),
                HighCfgStatement::Assign { .. } => None,
            };
            if let Some(view) = field_view {
                collect_types(
                    &TypeRef::Named {
                        id: view.type_id.clone(),
                    },
                    model,
                    &mut ids,
                );
                if let Some(element) = &view.array_element {
                    collect_types(
                        &TypeRef::Named {
                            id: element.element_type_id.clone(),
                        },
                        model,
                        &mut ids,
                    );
                }
            }
        }
    }
    ids.into_iter().collect()
}

fn cfg_cache_options(options: &str) -> String {
    format!("typed-cfg-v{HIGH_LEVEL_CFG_CIR_VERSION}:{options}")
}

impl LocalProjectStore {
    pub fn cached_typed_cfg_c(
        &self,
        project: &LocalProject,
        model: &AnalysisModel,
        machine: &MachineFunctionIr,
        function: &FunctionIr,
        options: &str,
    ) -> Result<Option<String>, String> {
        self.cached_typed_c(
            project,
            model,
            machine,
            function,
            &cfg_cache_options(options),
        )
    }

    pub fn cached_typed_c(
        &self,
        project: &LocalProject,
        model: &AnalysisModel,
        machine: &MachineFunctionIr,
        function: &FunctionIr,
        options: &str,
    ) -> Result<Option<String>, String> {
        self.verify_current(project)?;
        validate_structure(model)?;
        if model.binary_sha256 != project.binary_sha256
            || machine.binary_sha256 != model.binary_sha256
            || function.binary_sha256 != model.binary_sha256
        {
            return Err("typed C cache model belongs to another binary".to_owned());
        }
        let stored_model: Option<Vec<u8>> = self.conn.query_row(
            "SELECT model_json FROM local_models WHERE project_id=?1 AND binary_sha256=?2 AND created_revision<=?3 ORDER BY created_revision DESC LIMIT 1",
            params![project.id, project.binary_sha256, project.revision as i64],
            |row| row.get(0),
        ).optional().map_err(db_error)?;
        if stored_model
            .as_deref()
            .map(hydir_model::parse_model)
            .transpose()?
            .as_ref()
            != Some(model)
        {
            return Err("typed C cache model differs from the saved project model".to_owned());
        }
        let options_sha256 = source_options_hash(options, machine, function)?;
        let row: Option<(String, Vec<u8>, Vec<u8>, Vec<u8>)> = self.conn.query_row(
            "SELECT content_sha256,content,type_ids_json,calls_json FROM local_typed_c_cache WHERE project_id=?1 AND binary_sha256=?2 AND model_revision=?3 AND analysis_version=?4 AND options_sha256=?5 AND entry_address_space=?6 AND entry_value=?7",
            params![project.id, project.binary_sha256, model.revision as i64, ANALYSIS_VERSION, options_sha256, machine.entry.address_space, entry_value(machine.entry)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional().map_err(db_error)?;
        let Some((digest, content, type_ids_json, calls_json)) = row else {
            return Ok(None);
        };
        if content.len() > MAX_C_BYTES
            || type_ids_json.len() > 1024 * 1024
            || calls_json.len() > 1024 * 1024
            || digest != cache_digest(&content, &type_ids_json, &calls_json)
        {
            return Ok(None);
        }
        Ok(String::from_utf8(content).ok())
    }

    pub fn cache_typed_c(
        &mut self,
        project: &LocalProject,
        model: &AnalysisModel,
        ir: &HighLevelCir,
        machine: &MachineFunctionIr,
        function: &FunctionIr,
        content: &str,
        options: &str,
    ) -> Result<(), String> {
        self.verify_current(project)?;
        validate_structure(model)?;
        if model.binary_sha256 != project.binary_sha256
            || ir.binary_sha256 != model.binary_sha256
            || ir.model_revision != model.revision
            || ir.schema_version != HIGH_LEVEL_CIR_VERSION
            || machine.binary_sha256 != model.binary_sha256
            || machine.entry != ir.entry
            || function.binary_sha256 != model.binary_sha256
            || function.entry != ir.entry
        {
            return Err("typed C cache artifact identity differs from model".to_owned());
        }
        if content.len() > MAX_C_BYTES || emit_typed_c(ir, model)? != content {
            return Err("typed C cache content differs from validated emission".to_owned());
        }
        let options_sha256 = source_options_hash(options, machine, function)?;
        let type_ids_json =
            serde_json::to_vec(&used_type_ids(ir, model)).map_err(|error| error.to_string())?;
        let calls = function
            .calls
            .iter()
            .filter_map(|call| call.target)
            .collect::<BTreeSet<_>>();
        let calls_json = serde_json::to_vec(&calls).map_err(|error| error.to_string())?;
        if let Some(existing) = self.cached_typed_c(project, model, machine, function, options)? {
            return if existing == content {
                Ok(())
            } else {
                Err("typed C cache key has a different emission".to_owned())
            };
        }
        let content_sha256 = cache_digest(content.as_bytes(), &type_ids_json, &calls_json);
        self.conn.execute(
            "INSERT OR REPLACE INTO local_typed_c_cache(project_id,binary_sha256,model_revision,analysis_version,options_sha256,entry_address_space,entry_value,content_sha256,content,type_ids_json,calls_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![project.id, project.binary_sha256, model.revision as i64, ANALYSIS_VERSION, options_sha256, ir.entry.address_space, entry_value(ir.entry), content_sha256, content.as_bytes(), type_ids_json, calls_json],
        ).map_err(db_error)?;
        Ok(())
    }

    pub fn cache_typed_cfg_c(
        &mut self,
        project: &LocalProject,
        model: &AnalysisModel,
        ir: &HighLevelCfgCir,
        machine: &MachineFunctionIr,
        function: &FunctionIr,
        content: &str,
        options: &str,
    ) -> Result<(), String> {
        self.verify_current(project)?;
        validate_structure(model)?;
        if model.binary_sha256 != project.binary_sha256
            || ir.binary_sha256 != model.binary_sha256
            || ir.model_revision != model.revision
            || ir.schema_version != HIGH_LEVEL_CFG_CIR_VERSION
            || machine.binary_sha256 != model.binary_sha256
            || machine.entry != ir.entry
            || function.binary_sha256 != model.binary_sha256
            || function.entry != ir.entry
        {
            return Err("typed CFG cache artifact identity differs from model".to_owned());
        }
        if content.len() > MAX_C_BYTES || emit_typed_cfg_c(ir, model)? != content {
            return Err("typed CFG cache content differs from validated emission".to_owned());
        }
        let keyed_options = cfg_cache_options(options);
        let options_sha256 = source_options_hash(&keyed_options, machine, function)?;
        let type_ids_json =
            serde_json::to_vec(&used_cfg_type_ids(ir, model)).map_err(|error| error.to_string())?;
        let calls = function
            .calls
            .iter()
            .filter_map(|call| call.target)
            .collect::<BTreeSet<_>>();
        let calls_json = serde_json::to_vec(&calls).map_err(|error| error.to_string())?;
        if let Some(existing) =
            self.cached_typed_cfg_c(project, model, machine, function, options)?
        {
            return if existing == content {
                Ok(())
            } else {
                Err("typed CFG cache key has a different emission".to_owned())
            };
        }
        let content_sha256 = cache_digest(content.as_bytes(), &type_ids_json, &calls_json);
        self.conn.execute(
            "INSERT OR REPLACE INTO local_typed_c_cache(project_id,binary_sha256,model_revision,analysis_version,options_sha256,entry_address_space,entry_value,content_sha256,content,type_ids_json,calls_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![project.id, project.binary_sha256, model.revision as i64, ANALYSIS_VERSION, options_sha256, ir.entry.address_space, entry_value(ir.entry), content_sha256, content.as_bytes(), type_ids_json, calls_json],
        ).map_err(db_error)?;
        Ok(())
    }
}

struct CacheRow {
    entry: Location,
    options_sha256: String,
    content_sha256: String,
    content: Vec<u8>,
    type_ids_json: Vec<u8>,
    calls_json: Vec<u8>,
    type_ids: BTreeSet<String>,
    calls: BTreeSet<Location>,
}

fn type_output_changed(
    old: &hydir_model::TypeDefinition,
    new: &hydir_model::TypeDefinition,
) -> bool {
    if old.name != new.name
        || old.size_bytes != new.size_bytes
        || old.size_is_lower_bound != new.size_is_lower_bound
    {
        return true;
    }
    match (&old.kind, &new.kind) {
        (
            TypeDefinitionKind::Struct { fields: old_fields },
            TypeDefinitionKind::Struct { fields: new_fields },
        )
        | (
            TypeDefinitionKind::Union { fields: old_fields },
            TypeDefinitionKind::Union { fields: new_fields },
        ) => {
            old_fields.len() != new_fields.len()
                || old_fields.iter().zip(new_fields).any(|(old, new)| {
                    old.name != new.name || old.offset_bytes != new.offset_bytes || old.ty != new.ty
                })
        }
        (
            TypeDefinitionKind::Enum {
                underlying: old_underlying,
                variants: old_variants,
            },
            TypeDefinitionKind::Enum {
                underlying: new_underlying,
                variants: new_variants,
            },
        ) => old_underlying != new_underlying || old_variants != new_variants,
        (
            TypeDefinitionKind::Alias { target: old_target },
            TypeDefinitionKind::Alias { target: new_target },
        ) => old_target != new_target,
        _ => true,
    }
}

fn changed_model_facts(
    old: &AnalysisModel,
    new: &AnalysisModel,
) -> (BTreeSet<String>, BTreeSet<Location>) {
    let old_types = old
        .types
        .iter()
        .map(|ty| (ty.id.as_str(), ty))
        .collect::<BTreeMap<_, _>>();
    let new_types = new
        .types
        .iter()
        .map(|ty| (ty.id.as_str(), ty))
        .collect::<BTreeMap<_, _>>();
    let type_ids = old_types
        .keys()
        .chain(new_types.keys())
        .filter(|id| match (old_types.get(**id), new_types.get(**id)) {
            (Some(old), Some(new)) => type_output_changed(old, new),
            _ => true,
        })
        .map(|id| (*id).to_owned())
        .collect();
    let old_functions = old
        .functions
        .iter()
        .map(|row| (row.entry, row))
        .collect::<BTreeMap<_, _>>();
    let new_functions = new
        .functions
        .iter()
        .map(|row| (row.entry, row))
        .collect::<BTreeMap<_, _>>();
    let mut functions: BTreeSet<Location> = old_functions
        .keys()
        .chain(new_functions.keys())
        .filter(
            |entry| match (old_functions.get(entry), new_functions.get(entry)) {
                (Some(old), Some(new)) => {
                    old.name != new.name
                        || old.prototype != new.prototype
                        || old.inferred_parameters != new.inferred_parameters
                }
                _ => true,
            },
        )
        .copied()
        .collect();
    let old_stack = old
        .stack_objects
        .iter()
        .map(|row| ((row.function_entry, row.entry_rsp_offset), row))
        .collect::<BTreeMap<_, _>>();
    let new_stack = new
        .stack_objects
        .iter()
        .map(|row| ((row.function_entry, row.entry_rsp_offset), row))
        .collect::<BTreeMap<_, _>>();
    functions.extend(
        old_stack
            .keys()
            .chain(new_stack.keys())
            .filter(|key| match (old_stack.get(key), new_stack.get(key)) {
                (Some(old), Some(new)) => old.size_bytes != new.size_bytes || old.ty != new.ty,
                _ => true,
            })
            .map(|key| key.0),
    );
    (type_ids, functions)
}

pub(super) fn carry_typed_c_cache(
    tx: &Transaction<'_>,
    project: &LocalProject,
    old: &AnalysisModel,
    new: &AnalysisModel,
) -> Result<(), String> {
    if old.binary_sha256 != new.binary_sha256 || old.binary_sha256 != project.binary_sha256 {
        return Ok(());
    }
    let (changed_types, changed_functions) = changed_model_facts(old, new);
    let mut statement = tx.prepare(
        "SELECT entry_address_space,entry_value,options_sha256,content_sha256,content,type_ids_json,calls_json FROM local_typed_c_cache WHERE project_id=?1 AND binary_sha256=?2 AND model_revision=?3 AND analysis_version=?4 LIMIT ?5"
    ).map_err(db_error)?;
    let rows = statement
        .query_map(
            params![
                project.id,
                project.binary_sha256,
                old.revision as i64,
                ANALYSIS_VERSION,
                (MAX_CACHE_ROWS + 1) as i64
            ],
            |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            },
        )
        .map_err(db_error)?;
    let mut cached = Vec::new();
    for row in rows {
        // Every row participates in the caller graph, including entries
        // emitted with different options. A partial graph could preserve a
        // caller whose changed transitive callee was omitted or corrupt.
        if cached.len() == MAX_CACHE_ROWS {
            return Ok(());
        }
        let (
            address_space,
            value,
            options_sha256,
            content_sha256,
            content,
            type_ids_json,
            calls_json,
        ) = match row {
            Ok(row) => row,
            Err(_) => return Ok(()),
        };
        if content.len() > MAX_C_BYTES
            || type_ids_json.len() > 1024 * 1024
            || calls_json.len() > 1024 * 1024
            || content_sha256 != cache_digest(&content, &type_ids_json, &calls_json)
            || options_sha256.len() != 64
        {
            return Ok(());
        }
        let Ok(value) = u64::from_str_radix(&value, 16) else {
            return Ok(());
        };
        let entry = Location {
            address_space,
            value: Address(value),
        };
        let Ok(type_ids) = serde_json::from_slice::<BTreeSet<String>>(&type_ids_json) else {
            return Ok(());
        };
        let Ok(calls) = serde_json::from_slice::<BTreeSet<Location>>(&calls_json) else {
            return Ok(());
        };
        if type_ids.len() > 16_384 || calls.len() > 512 {
            return Ok(());
        }
        cached.push(CacheRow {
            entry,
            options_sha256,
            content_sha256,
            content,
            type_ids_json,
            calls_json,
            type_ids,
            calls,
        });
    }
    drop(statement);
    let cached_entries = cached.iter().map(|row| row.entry).collect::<BTreeSet<_>>();
    let mut dirty = changed_functions;
    if !dirty.is_empty() {
        // A missing intermediate cache row has no call summary. It could
        // reach any changed function, so carry neither that caller nor its
        // transitive callers across this model revision.
        dirty.extend(
            cached
                .iter()
                .filter(|row| {
                    row.calls
                        .iter()
                        .any(|callee| !cached_entries.contains(callee))
                })
                .map(|row| row.entry),
        );
    }
    dirty.extend(
        cached
            .iter()
            .filter(|row| !row.type_ids.is_disjoint(&changed_types))
            .map(|row| row.entry),
    );
    loop {
        let before = dirty.len();
        let callers = cached
            .iter()
            .filter(|row| !row.calls.is_disjoint(&dirty))
            .map(|row| row.entry)
            .collect::<Vec<_>>();
        dirty.extend(callers);
        if dirty.len() == before {
            break;
        }
    }
    for row in cached.into_iter().filter(|row| !dirty.contains(&row.entry)) {
        tx.execute(
            "INSERT OR IGNORE INTO local_typed_c_cache(project_id,binary_sha256,model_revision,analysis_version,options_sha256,entry_address_space,entry_value,content_sha256,content,type_ids_json,calls_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![project.id, project.binary_sha256, new.revision as i64, ANALYSIS_VERSION, row.options_sha256, row.entry.address_space, entry_value(row.entry), row.content_sha256, row.content, row.type_ids_json, row.calls_json],
        ).map_err(db_error)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_decompile::decompile_symbol;
    use hydir_hlc::{emit_typed_cfg_c, lower_high_level_cfg_cir, lower_high_level_cir};
    use hydir_loader::import_elf;
    use hydir_model::{
        ANALYSIS_MODEL_VERSION, ModelEvidence, ModelField, ModelFunction, ModelSource,
        PrimitiveType, TypeDefinition, TypeDefinitionKind, TypeRef, import_dwarf, init_model,
    };
    use std::{fs, path::Path, process::Command};

    #[test]
    fn cache_carries_only_unaffected_function_and_type_dependencies() {
        let directory = tempfile::tempdir().unwrap();
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/typed_pair.c");
        let binary = directory.path().join("pair.o");
        let output = Command::new("clang")
            .args(["--target=x86_64-unknown-linux-gnu", "-g", "-O2", "-c"])
            .arg(&fixture)
            .arg("-o")
            .arg(&binary)
            .output();
        let Ok(output) = output else { return };
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&binary).unwrap();
        let spec = import_elf(&bytes).unwrap();
        let mut model = init_model(&bytes).unwrap();
        import_dwarf(&bytes, &mut model).unwrap();
        let mut store = LocalProjectStore::open(&directory.path().join("cache.sqlite")).unwrap();
        let initial = store.open_binary(&binary, &spec).unwrap();
        let project = store.save_model(&initial, &model, "initial-model").unwrap();
        let model = store.load_model(&project).unwrap().unwrap();
        let sum = decompile_symbol(&bytes, "hydir_pair_sum").unwrap();
        let xor = decompile_symbol(&bytes, "hydir_pair_xor").unwrap();
        for native in [&sum, &xor] {
            let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
            let c = emit_typed_c(&ir, &model).unwrap();
            store
                .cache_typed_c(
                    &project,
                    &model,
                    &ir,
                    &native.machine_ir,
                    &native.function_ir,
                    &c,
                    "default",
                )
                .unwrap();
            assert_eq!(
                store
                    .cached_typed_c(
                        &project,
                        &model,
                        &native.machine_ir,
                        &native.function_ir,
                        "default"
                    )
                    .unwrap()
                    .as_deref(),
                Some(c.as_str())
            );
            assert!(
                store
                    .cached_typed_c(
                        &project,
                        &model,
                        &native.machine_ir,
                        &native.function_ir,
                        "other"
                    )
                    .unwrap()
                    .is_none()
            );
        }
        let mut changed_source = sum.machine_ir.clone();
        changed_source.name.push_str("_rediscovered");
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &model,
                    &changed_source,
                    &sum.function_ir,
                    "default",
                )
                .unwrap()
                .is_none(),
            "a changed source IR must not reuse the previous typed C"
        );
        let mut edited = model.clone();
        edited
            .functions
            .iter_mut()
            .find(|row| row.entry == xor.machine_ir.entry)
            .unwrap()
            .name = "renamed_xor".to_owned();
        let project = store.save_model(&project, &edited, "rename-xor").unwrap();
        let edited = store.load_model(&project).unwrap().unwrap();
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &edited,
                    &sum.machine_ir,
                    &sum.function_ir,
                    "default"
                )
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &edited,
                    &xor.machine_ir,
                    &xor.function_ir,
                    "default"
                )
                .unwrap()
                .is_none()
        );

        let mut edited_again = edited.clone();
        let TypeDefinitionKind::Struct { fields } = &mut edited_again.types[0].kind else {
            panic!("struct expected")
        };
        fields[0].name = "renamed_left".to_owned();
        let project = store
            .save_model(&project, &edited_again, "rename-field")
            .unwrap();
        let edited_again = store.load_model(&project).unwrap().unwrap();
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &edited_again,
                    &sum.machine_ir,
                    &sum.function_ir,
                    "default"
                )
                .unwrap()
                .is_none()
        );

        for native in [&sum, &xor] {
            let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &edited_again)
                .unwrap();
            let c = emit_typed_c(&ir, &edited_again).unwrap();
            store
                .cache_typed_c(
                    &project,
                    &edited_again,
                    &ir,
                    &native.machine_ir,
                    &native.function_ir,
                    &c,
                    "default",
                )
                .unwrap();
        }
        // A future call-capable typed artifact can depend on a callee even
        // when its own model row and referenced types have not changed.
        let calls = serde_json::to_vec(&BTreeSet::from([xor.machine_ir.entry])).unwrap();
        let (content, type_ids): (Vec<u8>, Vec<u8>) = store.conn.query_row(
            "SELECT content,type_ids_json FROM local_typed_c_cache WHERE project_id=?1 AND model_revision=?2 AND entry_address_space=?3 AND entry_value=?4",
            params![project.id, edited_again.revision as i64, sum.machine_ir.entry.address_space, entry_value(sum.machine_ir.entry)],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        let digest = cache_digest(&content, &type_ids, &calls);
        store.conn.execute(
            "UPDATE local_typed_c_cache SET calls_json=?1,content_sha256=?2 WHERE project_id=?3 AND model_revision=?4 AND entry_address_space=?5 AND entry_value=?6",
            params![calls, digest, project.id, edited_again.revision as i64, sum.machine_ir.entry.address_space, entry_value(sum.machine_ir.entry)],
        ).unwrap();
        let mut renamed_callee = edited_again.clone();
        renamed_callee
            .functions
            .iter_mut()
            .find(|row| row.entry == xor.machine_ir.entry)
            .unwrap()
            .name = "renamed_xor_again".to_owned();
        let project = store
            .save_model(&project, &renamed_callee, "rename-callee-again")
            .unwrap();
        let renamed_callee = store.load_model(&project).unwrap().unwrap();
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &renamed_callee,
                    &sum.machine_ir,
                    &sum.function_ir,
                    "default"
                )
                .unwrap()
                .is_none()
        );
        let ir = lower_high_level_cir(&sum.machine_ir, &sum.function_ir, &renamed_callee).unwrap();
        let c = emit_typed_c(&ir, &renamed_callee).unwrap();
        store
            .cache_typed_c(
                &project,
                &renamed_callee,
                &ir,
                &sum.machine_ir,
                &sum.function_ir,
                &c,
                "default",
            )
            .unwrap();
        store.conn.execute(
            "UPDATE local_typed_c_cache SET calls_json=x'ff' WHERE project_id=?1 AND model_revision=?2 AND entry_address_space=?3 AND entry_value=?4",
            params![project.id, renamed_callee.revision as i64, sum.machine_ir.entry.address_space, entry_value(sum.machine_ir.entry)],
        ).unwrap();
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &renamed_callee,
                    &sum.machine_ir,
                    &sum.function_ir,
                    "default"
                )
                .unwrap()
                .is_none()
        );
        let mut edited_after_corruption = renamed_callee.clone();
        edited_after_corruption
            .functions
            .iter_mut()
            .find(|row| row.entry == xor.machine_ir.entry)
            .unwrap()
            .name = "third_xor_name".to_owned();
        let project = store
            .save_model(&project, &edited_after_corruption, "edit-after-corruption")
            .unwrap();
        let edited_after_corruption = store.load_model(&project).unwrap().unwrap();
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &edited_after_corruption,
                    &sum.machine_ir,
                    &sum.function_ir,
                    "default"
                )
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cfg_typed_c_cache_carries_unaffected_rows_and_rejects_changed_layouts() {
        let directory = tempfile::tempdir().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hydir_aggregate_walk.c");
        let binary = directory.path().join("walk.elf");
        let mut build = Command::new("clang");
        if cfg!(windows) {
            build.args(["--target=x86_64-unknown-linux-gnu", "-fuse-ld=lld"]);
        }
        let output = build
            .args([
                "-O2",
                "-g",
                "-fno-stack-protector",
                "-fno-builtin",
                "-nostdlib",
                "-static",
                "-no-pie",
                "-Wl,--build-id=none",
                "-Wl,-e,_start",
            ])
            .arg(&fixture)
            .arg("-o")
            .arg(&binary)
            .output()
            .expect("Clang is required for the typed CFG cache fixture");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&binary).unwrap();
        let spec = import_elf(&bytes).unwrap();
        let mut model = init_model(&bytes).unwrap();
        import_dwarf(&bytes, &mut model).unwrap();
        let mut store = LocalProjectStore::open(&directory.path().join("cache.sqlite")).unwrap();
        let initial = store.open_binary(&binary, &spec).unwrap();
        let project = store
            .save_model(&initial, &model, "initial-cfg-model")
            .unwrap();
        let model = store.load_model(&project).unwrap().unwrap();
        let native = decompile_symbol(&bytes, "hydir_walk_nodes64").unwrap();
        let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model).unwrap();
        assert!(ir.blocks.len() > 2);
        let c = emit_typed_cfg_c(&ir, &model).unwrap();
        store
            .cache_typed_cfg_c(
                &project,
                &model,
                &ir,
                &native.machine_ir,
                &native.function_ir,
                &c,
                "",
            )
            .unwrap();
        assert_eq!(
            store
                .cached_typed_cfg_c(
                    &project,
                    &model,
                    &native.machine_ir,
                    &native.function_ir,
                    "",
                )
                .unwrap()
                .as_deref(),
            Some(c.as_str())
        );
        assert!(
            store
                .cached_typed_c(
                    &project,
                    &model,
                    &native.machine_ir,
                    &native.function_ir,
                    "",
                )
                .unwrap()
                .is_none()
        );

        let mut changed_source = native.function_ir.clone();
        changed_source.name.push_str("_rediscovered");
        assert!(
            store
                .cached_typed_cfg_c(&project, &model, &native.machine_ir, &changed_source, "",)
                .unwrap()
                .is_none()
        );

        let mut unrelated = model.clone();
        unrelated.types.push(TypeDefinition {
            id: "cache_unrelated".to_owned(),
            name: "CacheUnrelated".to_owned(),
            size_bytes: 8,
            size_is_lower_bound: false,
            kind: TypeDefinitionKind::Struct {
                fields: vec![ModelField {
                    name: "other".to_owned(),
                    offset_bytes: 0,
                    ty: TypeRef::Primitive {
                        name: PrimitiveType::U64,
                    },
                    evidence: vec![],
                }],
            },
            evidence: vec![],
        });
        let project = store
            .save_model(&project, &unrelated, "add-unrelated-type")
            .unwrap();
        let unrelated = store.load_model(&project).unwrap().unwrap();
        assert_eq!(
            store
                .cached_typed_cfg_c(
                    &project,
                    &unrelated,
                    &native.machine_ir,
                    &native.function_ir,
                    "",
                )
                .unwrap()
                .as_deref(),
            Some(c.as_str()),
            "an unrelated model addition should preserve the CFG artifact"
        );

        let mut changed_layout = unrelated.clone();
        let node = changed_layout
            .types
            .iter_mut()
            .find(|ty| ty.name.starts_with("Node64_"))
            .expect("DWARF Node64 layout");
        let TypeDefinitionKind::Struct { fields } = &mut node.kind else {
            panic!("Node64 struct")
        };
        fields[0].name = "payload".to_owned();
        let project = store
            .save_model(&project, &changed_layout, "rename-node-field")
            .unwrap();
        let changed_layout = store.load_model(&project).unwrap().unwrap();
        assert!(
            store
                .cached_typed_cfg_c(
                    &project,
                    &changed_layout,
                    &native.machine_ir,
                    &native.function_ir,
                    "",
                )
                .unwrap()
                .is_none()
        );
    }

    fn insert_dependency_row(
        conn: &rusqlite::Connection,
        project: &LocalProject,
        revision: u64,
        entry: Location,
        calls: &[Location],
        malformed_calls: bool,
    ) {
        let content = b"/* cache sentinel */";
        let type_ids_json = b"[]";
        let calls_json = if malformed_calls {
            vec![0xff]
        } else {
            serde_json::to_vec(calls).unwrap()
        };
        let digest = cache_digest(content, type_ids_json, &calls_json);
        conn.execute(
            "INSERT INTO local_typed_c_cache(project_id,binary_sha256,model_revision,analysis_version,options_sha256,entry_address_space,entry_value,content_sha256,content,type_ids_json,calls_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![project.id, project.binary_sha256, revision as i64, ANALYSIS_VERSION, options_hash("").unwrap(), entry.address_space, entry_value(entry), digest, content, type_ids_json, calls_json],
        )
        .unwrap();
    }

    fn rows_at_revision(conn: &rusqlite::Connection, revision: u64) -> i64 {
        conn.query_row(
            "SELECT count(*) FROM local_typed_c_cache WHERE model_revision=?1",
            [revision as i64],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn cache_carry_requires_a_complete_dependency_graph() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = LocalProjectStore::open(&directory.path().join("cache.sqlite")).unwrap();
        let project = LocalProject {
            id: "dependency-test".to_owned(),
            path: directory.path().join("unused.elf"),
            revision: 1,
            binary_sha256: "a".repeat(64),
        };
        store.conn.execute(
            "INSERT INTO local_projects(id,canonical_path,current_revision,binary_sha256) VALUES(?1,?2,1,?3)",
            params![project.id, project.path.to_str().unwrap(), project.binary_sha256],
        ).unwrap();
        let location = |value| Location {
            address_space: 0,
            value: Address(value),
        };
        let caller = location(0x10);
        let intermediate = location(0x20);
        let changed_callee = location(0x30);
        let independent = location(0x40);
        let old = AnalysisModel {
            schema_version: ANALYSIS_MODEL_VERSION,
            binary_sha256: project.binary_sha256.clone(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            revision: 1,
            types: vec![],
            functions: vec![ModelFunction {
                entry: changed_callee,
                name: "callee".to_owned(),
                prototype: None,
                inferred_parameters: BTreeMap::new(),
                evidence: vec![],
            }],
            stack_objects: vec![],
            conflicts: vec![],
            high_pcode_hints: vec![],
        };
        let mut evidence_only = old.clone();
        evidence_only.functions[0].evidence.push(ModelEvidence {
            source: ModelSource::AnalystAssertion,
            detail: "new observation".to_owned(),
            site: None,
        });
        assert_eq!(changed_model_facts(&old, &evidence_only).1.len(), 0);
        let mut type_with_evidence = TypeDefinition {
            id: "struct_1".to_owned(),
            name: "struct_1".to_owned(),
            size_bytes: 8,
            size_is_lower_bound: false,
            kind: TypeDefinitionKind::Struct {
                fields: vec![ModelField {
                    name: "value".to_owned(),
                    offset_bytes: 0,
                    ty: TypeRef::Primitive {
                        name: PrimitiveType::U64,
                    },
                    evidence: vec![],
                }],
            },
            evidence: vec![],
        };
        let original_type = type_with_evidence.clone();
        type_with_evidence.evidence = evidence_only.functions[0].evidence.clone();
        let TypeDefinitionKind::Struct { fields } = &mut type_with_evidence.kind else {
            unreachable!()
        };
        fields[0].evidence = evidence_only.functions[0].evidence.clone();
        assert!(!type_output_changed(&original_type, &type_with_evidence));
        let TypeDefinitionKind::Struct { fields } = &mut type_with_evidence.kind else {
            unreachable!()
        };
        fields[0].name = "renamed_value".to_owned();
        assert!(type_output_changed(&original_type, &type_with_evidence));
        let mut renamed = old.clone();
        renamed.revision = 2;
        renamed.functions[0].name = "renamed_callee".to_owned();
        insert_dependency_row(&store.conn, &project, 1, caller, &[intermediate], false);
        insert_dependency_row(
            &store.conn,
            &project,
            1,
            intermediate,
            &[changed_callee],
            false,
        );
        insert_dependency_row(&store.conn, &project, 1, independent, &[], false);
        let tx = store.conn.transaction().unwrap();
        carry_typed_c_cache(&tx, &project, &old, &renamed).unwrap();
        tx.commit().unwrap();
        // Transitive callers are dirty; an unrelated function survives.
        assert_eq!(rows_at_revision(&store.conn, 2), 1);

        let mut renamed_again = renamed.clone();
        renamed_again.revision = 3;
        renamed_again.functions[0].name = "renamed_again".to_owned();
        insert_dependency_row(&store.conn, &project, 2, caller, &[intermediate], false);
        insert_dependency_row(&store.conn, &project, 2, intermediate, &[], true);
        let tx = store.conn.transaction().unwrap();
        carry_typed_c_cache(&tx, &project, &renamed, &renamed_again).unwrap();
        tx.commit().unwrap();
        // The malformed intermediate could conceal a path to the changed
        // callee, so even the otherwise independent row is not copied.
        assert_eq!(rows_at_revision(&store.conn, 3), 0);

        let tx = store.conn.transaction().unwrap();
        for index in 0..=MAX_CACHE_ROWS {
            insert_dependency_row(
                &tx,
                &project,
                3,
                location(0x1000 + index as u64),
                &[],
                index == MAX_CACHE_ROWS,
            );
        }
        tx.commit().unwrap();
        let mut final_model = renamed_again.clone();
        final_model.revision = 4;
        final_model.functions[0].name = "final_name".to_owned();
        let tx = store.conn.transaction().unwrap();
        carry_typed_c_cache(&tx, &project, &renamed_again, &final_model).unwrap();
        tx.commit().unwrap();
        // A bounded read must not copy a subset of more than 4096 rows.
        assert_eq!(rows_at_revision(&store.conn, 4), 0);
    }

    #[test]
    fn cache_carry_drops_callers_when_an_intermediate_summary_is_missing() {
        let directory = tempfile::tempdir().unwrap();
        let mut store = LocalProjectStore::open(&directory.path().join("cache.sqlite")).unwrap();
        let project = LocalProject {
            id: "missing-intermediate".to_owned(),
            path: directory.path().join("unused.elf"),
            revision: 1,
            binary_sha256: "b".repeat(64),
        };
        store.conn.execute(
            "INSERT INTO local_projects(id,canonical_path,current_revision,binary_sha256) VALUES(?1,?2,1,?3)",
            params![project.id, project.path.to_str().unwrap(), project.binary_sha256],
        ).unwrap();
        let location = |value| Location {
            address_space: 0,
            value: Address(value),
        };
        let caller = location(0x10);
        let uncached_intermediate = location(0x20);
        let changed_callee = location(0x30);
        let independent = location(0x40);
        let old = AnalysisModel {
            schema_version: ANALYSIS_MODEL_VERSION,
            binary_sha256: project.binary_sha256.clone(),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            revision: 1,
            types: vec![],
            functions: vec![ModelFunction {
                entry: changed_callee,
                name: "old_name".to_owned(),
                prototype: None,
                inferred_parameters: BTreeMap::new(),
                evidence: vec![],
            }],
            stack_objects: vec![],
            conflicts: vec![],
            high_pcode_hints: vec![],
        };
        let mut edited = old.clone();
        edited.revision = 2;
        edited.functions[0].name = "new_name".to_owned();
        insert_dependency_row(
            &store.conn,
            &project,
            1,
            caller,
            &[uncached_intermediate],
            false,
        );
        insert_dependency_row(&store.conn, &project, 1, independent, &[], false);
        let tx = store.conn.transaction().unwrap();
        carry_typed_c_cache(&tx, &project, &old, &edited).unwrap();
        tx.commit().unwrap();
        let carried: String = store.conn.query_row(
            "SELECT entry_value FROM local_typed_c_cache WHERE project_id=?1 AND model_revision=2",
            [&project.id],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(carried, entry_value(independent));
        assert_eq!(rows_at_revision(&store.conn, 2), 1);
    }

    #[test]
    fn version_three_local_projects_gain_the_typed_cache_table() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("migration.sqlite");
        let store = LocalProjectStore::open(&path).unwrap();
        store
            .conn
            .execute_batch("DROP TABLE local_typed_c_cache; PRAGMA user_version=3;")
            .unwrap();
        drop(store);
        let reopened = LocalProjectStore::open(&path).unwrap();
        let version: i64 = reopened
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);
        let count: i64 = reopened
            .conn
            .query_row("SELECT count(*) FROM local_typed_c_cache", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
