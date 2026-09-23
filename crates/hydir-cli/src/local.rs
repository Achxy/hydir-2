//! Explicit local-project operations backed by the same analyst fact model.

use super::{decompile_native_selection, read_binary, resolve_native_function};
use hydir_analysis::analyze_spec_elf;
use hydir_backend::import_elf;
use hydir_core::{AnnotationKind, overlay_analyst_assumptions, parse_annotation_address};
use hydir_hlc::{emit_typed_c, emit_typed_cfg_c, lower_high_level_cfg_cir, lower_high_level_cir};
use hydir_model::{init_model, parse_model};
use hydir_project::{LocalAnnotationInput, LocalProject, LocalProjectStore};
use serde_json::json;
use std::{error::Error, fs, path::Path};

const HELP: &str = "Local project operations:
  hydirctl local project <elf> [--db <private-sqlite>]
  hydirctl local inspect <elf> [--db <private-sqlite>]
  hydirctl local analyze-spec <elf> [--db <private-sqlite>]
  hydirctl local annotations <elf> [--db <private-sqlite>]
  hydirctl local annotate <elf> <revision> <idempotency-key> <name|comment|assumption> <hex-address|-> <scope> <value> [--db <private-sqlite>]
  hydirctl local model <elf> [--db <private-sqlite>]
  hydirctl local model-put <elf> <revision> <idempotency-key> <model.json> [--db <private-sqlite>]
  hydirctl local decompile-typed <elf> <function-id-or-symbol> [--db <private-sqlite>]

The project is keyed by the canonical ELF path. Changed bytes advance its
revision; facts for another binary digest are not applied. The original ELF
is never modified. Set HYDIR_LOCAL_DB to an absolute path to share a private
database with the HydIR GUI, or use --db for this command.
";

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (operation, db_path) = if args.len() >= 2 && args[args.len() - 2] == "--db" {
        (&args[..args.len() - 2], Some(args[args.len() - 1].as_str()))
    } else {
        (args, None)
    };
    let mut store = if let Some(path) = db_path {
        LocalProjectStore::open(Path::new(path))?
    } else {
        LocalProjectStore::open_default()?
    };
    match operation {
        [command, binary]
            if matches!(
                command.as_str(),
                "project" | "inspect" | "analyze-spec" | "annotations"
            ) =>
        {
            let bytes = read_binary(binary)?;
            let mut spec = import_elf(&bytes)?;
            let project = store.open_binary(Path::new(binary), &spec)?;
            if command == "project" {
                println!("{}", serde_json::to_string_pretty(&project_json(&project))?);
            } else {
                let annotations = store.list_annotations(&project)?;
                if command == "annotations" {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "schema_version": 1,
                            "project_id": project.id,
                            "revision": project.revision,
                            "binary_sha256": project.binary_sha256,
                            "annotations": annotations,
                        }))?
                    );
                } else {
                    if command == "analyze-spec" {
                        spec = analyze_spec_elf(&bytes)?;
                    }
                    overlay_analyst_assumptions(&mut spec, &annotations);
                    println!("{}", serde_json::to_string_pretty(&spec)?);
                }
            }
        }
        [command, binary, expected, key, kind, address, scope, value] if command == "annotate" => {
            let bytes = read_binary(binary)?;
            let spec = import_elf(&bytes)?;
            let project = store.open_binary(Path::new(binary), &spec)?;
            let expected: u64 = expected.parse()?;
            let requested = LocalProject {
                revision: expected,
                ..project
            };
            let kind = AnnotationKind::parse(kind)?;
            let address = parse_annotation_address(address)?;
            let updated = store.add_annotation(
                &requested,
                &spec,
                LocalAnnotationInput {
                    kind,
                    address,
                    value,
                    scope,
                    idempotency_key: key,
                },
            )?;
            println!("{}", serde_json::to_string_pretty(&project_json(&updated))?);
        }
        [command, binary] if command == "model" => {
            let bytes = read_binary(binary)?;
            let spec = import_elf(&bytes)?;
            let project = store.open_binary(Path::new(binary), &spec)?;
            let model = store
                .load_model(&project)?
                .map_or_else(|| init_model(&bytes), Ok)?;
            println!("{}", serde_json::to_string_pretty(&model)?);
        }
        [command, binary, expected, key, model_path] if command == "model-put" => {
            let bytes = read_binary(binary)?;
            let spec = import_elf(&bytes)?;
            let project = store.open_binary(Path::new(binary), &spec)?;
            let requested = LocalProject {
                revision: expected.parse()?,
                ..project
            };
            let model = parse_model(&fs::read(model_path)?)?;
            let updated = store.save_model(&requested, &model, key)?;
            println!("{}", serde_json::to_string_pretty(&project_json(&updated))?);
        }
        [command, binary, selector] if command == "decompile-typed" => {
            let bytes = read_binary(binary)?;
            let spec = import_elf(&bytes)?;
            let project = store.open_binary(Path::new(binary), &spec)?;
            let model = store
                .load_model(&project)?
                .ok_or("Local project has no saved analysis model")?;
            let selected = resolve_native_function(&bytes, selector)?;
            let native = decompile_native_selection(&bytes, &selected)?;
            if let Some(cached) =
                store.cached_typed_c(&project, &model, native.machine_ir.entry, "")?
            {
                print!("{cached}");
            } else {
                match lower_high_level_cir(&native.machine_ir, &native.function_ir, &model) {
                    Ok(ir) => {
                        let c = emit_typed_c(&ir, &model)?;
                        store.cache_typed_c(&project, &model, &ir, &native.function_ir, &c, "")?;
                        print!("{c}");
                    }
                    Err(_) => {
                        let ir = lower_high_level_cfg_cir(
                            &native.machine_ir,
                            &native.function_ir,
                            &model,
                        )?;
                        print!("{}", emit_typed_cfg_c(&ir, &model)?);
                    }
                }
            }
        }
        _ => return Err(HELP.into()),
    }
    Ok(())
}

fn project_json(project: &LocalProject) -> serde_json::Value {
    json!({
        "project_id": project.id,
        "path": project.path,
        "revision": project.revision,
        "binary_sha256": project.binary_sha256,
    })
}
