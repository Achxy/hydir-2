//! Private typed-C cache. Entries are keyed by binary, model revision,
//! analysis version, options, and function entry. On a model edit we carry
//! only entries whose type dependencies and transitive callees are unchanged.

use super::{LocalProject, LocalProjectStore, db_error};
use hydir_core::{Address, Location};
use hydir_hlc::{HIGH_LEVEL_CIR_VERSION, HighExpr, HighLevelCir, HighStatement, emit_typed_c};
use hydir_ir::FunctionIr;
use hydir_model::{AnalysisModel, TypeDefinitionKind, TypeRef, validate_structure};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const ANALYSIS_VERSION: i64 = 1;
const MAX_C_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_ROWS: usize = 4096;

fn options_hash(options: &str) -> Result<String, String> {
    if options.len() > 1024 {
        return Err("typed C cache options exceed 1024 bytes".to_owned());
    }
    Ok(format!("{:x}", Sha256::digest(options.as_bytes())))
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

impl LocalProjectStore {
    pub fn cached_typed_c(
        &self,
        project: &LocalProject,
        model: &AnalysisModel,
        entry: Location,
        options: &str,
    ) -> Result<Option<String>, String> {
        self.verify_current(project)?;
        validate_structure(model)?;
        if model.binary_sha256 != project.binary_sha256 {
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
        let options_sha256 = options_hash(options)?;
        let row: Option<(String, Vec<u8>, Vec<u8>, Vec<u8>)> = self.conn.query_row(
            "SELECT content_sha256,content,type_ids_json,calls_json FROM local_typed_c_cache WHERE project_id=?1 AND binary_sha256=?2 AND model_revision=?3 AND analysis_version=?4 AND options_sha256=?5 AND entry_address_space=?6 AND entry_value=?7",
            params![project.id, project.binary_sha256, model.revision as i64, ANALYSIS_VERSION, options_sha256, entry.address_space, entry_value(entry)],
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
            || function.binary_sha256 != model.binary_sha256
            || function.entry != ir.entry
        {
            return Err("typed C cache artifact identity differs from model".to_owned());
        }
        if content.len() > MAX_C_BYTES || emit_typed_c(ir, model)? != content {
            return Err("typed C cache content differs from validated emission".to_owned());
        }
        let options_sha256 = options_hash(options)?;
        let type_ids_json =
            serde_json::to_vec(&used_type_ids(ir, model)).map_err(|error| error.to_string())?;
        let calls = function
            .calls
            .iter()
            .filter_map(|call| call.target)
            .collect::<BTreeSet<_>>();
        let calls_json = serde_json::to_vec(&calls).map_err(|error| error.to_string())?;
        if let Some(existing) = self.cached_typed_c(project, model, ir.entry, options)? {
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
        .filter(|id| old_types.get(**id) != new_types.get(**id))
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
        .filter(|entry| old_functions.get(entry) != new_functions.get(entry))
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
            .filter(|key| old_stack.get(key) != new_stack.get(key))
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
            Err(_) => continue,
        };
        if content.len() > MAX_C_BYTES
            || type_ids_json.len() > 1024 * 1024
            || calls_json.len() > 1024 * 1024
            || content_sha256 != cache_digest(&content, &type_ids_json, &calls_json)
            || options_sha256.len() != 64
        {
            continue;
        }
        let Ok(value) = u64::from_str_radix(&value, 16) else {
            continue;
        };
        let entry = Location {
            address_space,
            value: Address(value),
        };
        let Ok(type_ids) = serde_json::from_slice::<BTreeSet<String>>(&type_ids_json) else {
            continue;
        };
        let Ok(calls) = serde_json::from_slice::<BTreeSet<Location>>(&calls_json) else {
            continue;
        };
        if type_ids.len() > 16_384 || calls.len() > 512 {
            continue;
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
    if cached.len() > MAX_CACHE_ROWS {
        return Ok(());
    }
    let mut dirty = changed_functions;
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
    use hydir_hlc::lower_high_level_cir;
    use hydir_loader::import_elf;
    use hydir_model::{TypeDefinitionKind, import_dwarf, init_model};
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
                .cache_typed_c(&project, &model, &ir, &native.function_ir, &c, "default")
                .unwrap();
            assert_eq!(
                store
                    .cached_typed_c(&project, &model, ir.entry, "default")
                    .unwrap()
                    .as_deref(),
                Some(c.as_str())
            );
            assert!(
                store
                    .cached_typed_c(&project, &model, ir.entry, "other")
                    .unwrap()
                    .is_none()
            );
        }
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
                .cached_typed_c(&project, &edited, sum.machine_ir.entry, "default")
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .cached_typed_c(&project, &edited, xor.machine_ir.entry, "default")
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
                .cached_typed_c(&project, &edited_again, sum.machine_ir.entry, "default")
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
                .cached_typed_c(&project, &renamed_callee, sum.machine_ir.entry, "default")
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
                .cached_typed_c(&project, &renamed_callee, sum.machine_ir.entry, "default")
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
                    sum.machine_ir.entry,
                    "default"
                )
                .unwrap()
                .is_none()
        );
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
        assert_eq!(version, 4);
        let count: i64 = reopened
            .conn
            .query_row("SELECT count(*) FROM local_typed_c_cache", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
