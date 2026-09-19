//! Explicit local-project operations backed by the same analyst fact model.

use super::read_binary;
use hydir_analysis::analyze_spec_elf;
use hydir_backend::import_elf;
use hydir_core::{AnnotationKind, overlay_analyst_assumptions, parse_annotation_address};
use hydir_project::{LocalAnnotationInput, LocalProject, LocalProjectStore};
use serde_json::json;
use std::{error::Error, path::Path};

const HELP: &str = "Local project operations:
  hydirctl local project <elf> [--db <private-sqlite>]
  hydirctl local inspect <elf> [--db <private-sqlite>]
  hydirctl local analyze-spec <elf> [--db <private-sqlite>]
  hydirctl local annotations <elf> [--db <private-sqlite>]
  hydirctl local annotate <elf> <revision> <idempotency-key> <name|comment|assumption> <hex-address|-> <scope> <value> [--db <private-sqlite>]

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
