#![recursion_limit = "256"]

use hydir_analysis::{analyze_elf, analyze_spec_elf};
use hydir_backend::{
    MAX_BINARY_BYTES, disassemble_elf, extract_symbol_code, import_elf, lift_at,
    lift_physical_region, lift_region_decision, lift_symbol, proven_stack_local_offsets,
    recover_at_cfg, recover_region_cfg, recover_symbol_cfg, region_contract,
};
use hydir_c::{
    build_decision_decompilation_unit, build_decompilation_unit, emit_decision_region_c,
    emit_decision_region_llvm, emit_structured_c,
};
use hydir_core::{
    CallingConvention, Location, ScalarType, annotation_address_in_spec, parse_program_spec_json,
};
use hydir_decompile::{
    NativeDecompilation, decompile_function_at, decompile_function_unit_at,
    decompile_indexed_function, decompile_indexed_function_unit, decompile_symbol,
    decompile_symbol_unit, discover_function_candidates, discover_functions,
    export_function_ir_llvm, lift_machine_function, lift_machine_function_at, lower_cir,
    lower_expression_ir, lower_function_ir, lower_state_ir, measure_native_coverage,
};
use hydir_hlc::{emit_typed_c, lower_high_level_cir};
use hydir_interchange::{MAX_SPECIFICATION_BYTES, SpecificationDocument};
use hydir_ir::MachineFunctionIr;
use hydir_model::{import_dwarf, infer_model, init_model, parse_model, validate_model};
use hydir_vm::{VmProfile, explore_profile, validate_profile};
mod local;
mod passes;
mod patch;
use hydir_recompile as recompile;
mod remote;
use serde_json::json;
use sha2::Digest;
use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

const HELP: &str = "HydIR native x86-64 ELF vertical slice

Usage:
  hydirctl doctor
  hydirctl inspect <elf>
  hydirctl disassemble <elf>
  hydirctl discover <elf>
  hydirctl triton <elf> <function-symbol>
  hydirctl triton-console < request.json
  hydirctl analyze <linked-elf>
  hydirctl analyze-spec <linked-elf>
  hydirctl hydir-spec-inspect <hydir-spec.pb> [--canonical-output <canonical.pb>]
  hydirctl hydir-spec-region <hydir-spec.pb> <linked-elf> <block-uid> [--output <region.json>]
  hydirctl hydir-spec-lift <hydir-spec.pb> <linked-elf> <block-uid> [--output <physical-region-ir.json>]
  hydirctl hydir-spec-decompile <hydir-spec.pb> <linked-elf> <block-uid> [--output <unit.json>]
  hydirctl hydir-spec-report <hydir-spec.pb> <linked-elf>
  hydirctl cfg <elf> <function-symbol>
  hydirctl region <elf> <function-symbol>
  hydirctl cfg-at <linked-elf> <virtual-address-hex> <size-bytes>
  hydirctl lift <elf> <function-symbol> --assume-u64x2 [--output <file.ll>]
  hydirctl lift <elf> --function <function-id-or-symbol> --ir <machine|state|expression|function|cir|llvm>
  hydirctl lift <elf> --function <function-id-or-symbol> --ir high-level --model <model.json>
  hydirctl lift-model <linked-elf> <function-symbol> <program-spec.json> [--output <file.ll>]
  hydirctl lift-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 [--output <file.ll>]
  hydirctl decompile <elf> <function-symbol> --assume-u64x2 [--output <file.c>]
  hydirctl decompile <elf> --function <function-id-or-symbol> --view <low|structured|unit>
  hydirctl decompile <elf> --function <function-id-or-symbol> --view typed --model <model.json>
  hydirctl decompile-all <elf> --output-dir <new-directory>
  hydirctl explain <elf> --function <function-id-or-symbol> [--address <hex-address>]
  hydirctl coverage <elf>
  hydirctl model init <elf> [--output <model.json>]
  hydirctl model verify <elf> <model.json>
  hydirctl model import-dwarf <elf> <model.json> [--output <new-model.json>]
  hydirctl model infer <elf> <model.json> [--output <new-model.json>]
  hydirctl vm-profile <linked-elf> <profile.json>
  hydirctl vm-explore <linked-elf> <profile.json>
  hydirctl decompile-unit <elf> <function-symbol> --assume-u64x2 [--output <unit.json>]
  hydirctl decompile-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 [--output <file.c>]
  hydirctl patch <linked-elf> <patch-v1.json> --trusted-fixture --assume-u64x2 --assume-entry-only --output <new.elf>
  hydirctl transform <elf> <function-symbol> --assume-u64x2 --trusted-fixture --passes <comma-list> --output-dir <new-directory> [--opt <path>]
  hydirctl rebuild <linked-elf> --trusted-fixture --output-dir <new-directory> [--clang <path>]
  hydirctl validate <elf> <function-symbol> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>] [--cases-file <json>] [--model <ProgramSpec.json>]
  hydirctl validate-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>]
  hydirctl validate-c <elf> <function-symbol> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>] [--cases-file <json>] [--model <ProgramSpec.json>]
  hydirctl validate-c-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>]
  hydirctl local <project|inspect|analyze-spec|annotations> <elf> [--db <private-sqlite>]
  hydirctl local annotate <elf> <revision> <idempotency-key> <name|comment|assumption> <hex-address|-> <scope> <value> [--db <private-sqlite>]
  hydirctl local model <elf> [--db <private-sqlite>]
  hydirctl local model-put <elf> <revision> <idempotency-key> <model.json> [--db <private-sqlite>]
  hydirctl local decompile-typed <elf> <function-id-or-symbol> [--db <private-sqlite>]
  hydirctl remote <operation> ...

Legacy symbol mode requires a non-stripped function symbol. Native --function
mode also accepts a FunctionIndex ID discovered from ELF entry, dynamic symbol,
unwind FDE, init/fini, or direct-call evidence; candidate extents remain partial. Legacy
symbol-backed native lifting supports linked and relocatable ELF files;
relocatable control targets come from ELF relocations, never placeholder bytes.
address mode requires an analyst-supplied virtual entry and exact byte extent,
and works on stripped linked ELF files. --assume-u64x2 explicitly
asserts a u64(u64,u64) SysV prototype. Validation runs the original binary
and generated code without a sandbox; use only trusted fixtures.
Rebuild supports local and authenticated-loopback operations for a narrow
freestanding static x86-64 ELF subset; it requires pinned Clang/LLVM 14.0.6
and is not a hostile-binary sandbox. The remote server never executes samples.
Remote operations require HYDIR_ENDPOINT and a HYDIR_TOKEN_FILE containing a
credential created by hydird. Remote upload is always an explicit command.
Local project annotations use a private SQLite database in the user data
directory, or the absolute HYDIR_LOCAL_DB path. --db overrides it for one
command. ELF bytes are never written to that database.
";

const EMBEDDED_TRITON_HELPER: &str = include_str!("../../../scripts/triton_bridge.py");

fn main() {
    if let Err(err) = run() {
        eprintln!("hydirctl: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("model")
            if args.get(1).map(String::as_str) == Some("init")
                && (args.len() == 3 || args.len() == 5) =>
        {
            let output = if args.len() == 5 {
                if args[3] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[4].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[2])?;
            let model = init_model(&bytes)?;
            let json = serde_json::to_vec_pretty(&model)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("model") if args.get(1).map(String::as_str) == Some("verify") && args.len() == 4 => {
            let bytes = read_binary(&args[2])?;
            let model = parse_model(&fs::read(&args[3])?)?;
            validate_model(&bytes, &model)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &json!({"schema_version": 1, "valid": true, "binary_sha256": model.binary_sha256, "model_revision": model.revision, "types": model.types.len(), "functions": model.functions.len()})
                )?
            );
        }
        Some("model")
            if args.get(1).map(String::as_str) == Some("import-dwarf")
                && (args.len() == 4 || args.len() == 6) =>
        {
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[2])?;
            let mut model = parse_model(&fs::read(&args[3])?)?;
            validate_model(&bytes, &model)?;
            import_dwarf(&bytes, &mut model)?;
            let json = serde_json::to_vec_pretty(&model)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("model")
            if args.get(1).map(String::as_str) == Some("infer")
                && (args.len() == 4 || args.len() == 6) =>
        {
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[2])?;
            let mut model = parse_model(&fs::read(&args[3])?)?;
            validate_model(&bytes, &model)?;
            let index = discover_function_candidates(&bytes)?;
            let mut native = Vec::new();
            let mut lift_failures = Vec::new();
            for row in index.functions.iter().take(256) {
                match decompile_indexed_function(&bytes, &index, &row.id) {
                    Ok(value) => native.push(value),
                    Err(error) => {
                        lift_failures.push(json!({"function_id": row.id, "error": error}))
                    }
                }
            }
            let inputs = native
                .iter()
                .map(|unit| (&unit.machine_ir, &unit.function_ir))
                .collect::<Vec<_>>();
            let mut report = infer_model(&mut model, &inputs)?;
            report.skipped_functions +=
                index.functions.len().saturating_sub(256) + lift_failures.len();
            report.bounded |= index.functions.len() > 256 || !lift_failures.is_empty();
            validate_model(&bytes, &model)?;
            let json = serde_json::to_vec_pretty(&model)?;
            let summary = json!({"inference": report, "index_functions": index.functions.len(), "lift_failures": lift_failures});
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
                eprintln!("inference: {}", serde_json::to_string(&summary)?);
            }
        }
        Some("disassemble") if args.len() == 2 => {
            let bytes = read_binary(&args[1])?;
            println!(
                "{}",
                serde_json::to_string_pretty(&disassemble_elf(&bytes)?)?
            );
        }
        Some("discover") if args.len() == 2 => {
            let bytes = read_binary(&args[1])?;
            println!(
                "{}",
                serde_json::to_string_pretty(&discover_functions(&bytes)?)?
            );
        }
        Some("coverage") if args.len() == 2 => {
            let bytes = read_binary(&args[1])?;
            println!(
                "{}",
                serde_json::to_string_pretty(&measure_native_coverage(&bytes)?)?
            );
        }
        Some("vm-profile" | "vm-explore") if args.len() == 3 => {
            const MAX_VM_PROFILE_BYTES: u64 = 1024 * 1024;
            if fs::metadata(&args[2])?.len() > MAX_VM_PROFILE_BYTES {
                return Err("VM profile exceeds the 1 MiB size limit".into());
            }
            let bytes = read_binary(&args[1])?;
            let profile: VmProfile = serde_json::from_slice(&fs::read(&args[2])?)?;
            if args[0] == "vm-profile" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&validate_profile(&bytes, &profile)?)?
                );
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&explore_profile(&bytes, &profile)?)?
                );
            }
        }
        Some("explain") if (args.len() == 4 || args.len() == 6) && args[2] == "--function" => {
            let requested_address = if args.len() == 6 {
                if args[4] != "--address" {
                    return Err(HELP.into());
                }
                Some(parse_u64_auto(&args[5], "instruction address")?)
            } else {
                None
            };
            let bytes = read_binary(&args[1])?;
            let selection = resolve_native_function(&bytes, &args[3])?;
            let machine = lift_native_selection(&bytes, &selection)?;
            let instructions = machine
                .blocks
                .iter()
                .flat_map(|block| block.instructions.iter())
                .filter(|instruction| {
                    requested_address.is_none_or(|address| instruction.address.value.0 == address)
                })
                .collect::<Vec<_>>();
            if requested_address.is_some() && instructions.is_empty() {
                return Err(
                    "requested address is not a recovered instruction in this function".into(),
                );
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "function_id": machine.function_id,
                    "name": machine.name,
                    "entry": machine.entry,
                    "structural_completeness": machine.structural_completeness,
                    "semantic_fidelity": machine.semantic_fidelity,
                    "verification": machine.verification,
                    "instructions": instructions,
                    "diagnostics": machine.diagnostics,
                    "rewrite_ready": false,
                }))?
            );
        }
        Some("doctor") if args.len() == 1 => {
            let clang = Command::new("clang").arg("--version").output();
            let clang_version = clang
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.lines().next().map(str::to_owned));
            let opt_version = Command::new("opt")
                .arg("--version")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.lines().next().map(str::to_owned));
            let triton_python = configured_triton_python();
            let triton_helper = triton_helper_path();
            let triton_python_version = Command::new(&triton_python)
                .arg("--version")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| {
                    let bytes = if output.stdout.is_empty() {
                        output.stderr
                    } else {
                        output.stdout
                    };
                    String::from_utf8(bytes).ok()
                })
                .and_then(|value| value.lines().next().map(str::to_owned));
            let triton_module_version = Command::new(&triton_python)
                .args([
                    "-c",
                    "import triton; print(getattr(triton, '__version__', 'installed'))",
                ])
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.lines().next().map(str::to_owned));
            let triton_helper_available =
                triton_helper.exists() || env::var_os("HYDIR_TRITON_HELPER").is_none();
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "hydir_version": env!("CARGO_PKG_VERSION"),
                    "license": env!("CARGO_PKG_LICENSE"),
                    "host": format!("{}-{}", env::consts::ARCH, env::consts::OS),
                    "elf_parser": "object 0.39.1 (Cargo.lock)",
                    "decoder": "iced-x86 1.21.0 (Cargo.lock)",
                    "triton_bridge": triton_helper_available && triton_module_version.is_some(),
                    "triton_python": triton_python,
                    "triton_python_version": triton_python_version,
                    "triton_module_version": triton_module_version,
                    "triton_helper": if triton_helper.exists() {
                        triton_helper.display().to_string()
                    } else if env::var_os("HYDIR_TRITON_HELPER").is_none() {
                        "<embedded>".to_owned()
                    } else {
                        triton_helper.display().to_string()
                    },
                    "native_elf_import": true,
                    "native_decompiler": true,
                    "native_decompiler_scope": "ProgramSpec v5 -> FunctionIndex v1 -> MachineIR -> StateIR -> FunctionIR -> CIR -> C11; symbol, unwind-FDE, entry, direct-call and init/fini seeds; partial results fail closed",
                    "analysis_model_v1": true,
                    "analysis_model_scope": "ELF SHA-256-bound JSON with bounded DWARF import, aggregate inference, visible conflicts, and revision-checked local analyst edits",
                    "expression_ir_v1": true,
                    "expression_ir_scope": "supported scalar register writes, defined flags for supported register CMP/TEST/arithmetic operations, conditional branch predicates, and component SSA joins; remaining effects retain explicit residuals",
                    "typed_c_v1": true,
                    "typed_c_scope": "complete linear functions with supported 64-bit operations, fixed frame spills, aggregate fields, and bounded fixed direct calls; other functions retain low-level C",
                    "typed_c_local_cache": true,
                    "vm_profile_v1": true,
                    "vm_explorer_scope": "bounded host/VPC exploration; guest CFG and rewrite readiness are not established",
                    "native_loader_metadata": "ELF64 program headers, GNU-versioned dynamic symbols, location-aware relocations, PLT/GOT/TLS ranges, linked .eh_frame FDEs, init/fini arrays, and symbol-backed ET_REL lifting",
                    "direct_cfg_scalar_llvm_lift": true,
                    "symbol_scoped_cfg_export": true,
                    "conservative_global_effect_analysis": true,
                    "trusted_fixture_validation_available": env::consts::OS == "linux" && env::consts::ARCH == "x86_64" && clang_version.is_some(),
                    "clang": clang_version,
                    "llvm_opt": opt_version,
                    "named_pass_pipeline_available": opt_version.as_deref().is_some_and(|version| version.contains("LLVM version 14.0.6")),
                    "ghidra_required": false,
                    "remote_api": true,
                    "local_project_annotations": true,
                    "local_project_scope": "private path-bound SQLite ledger, digest-scoped names/comments/assumptions, revisioned CLI/GUI writes; no automatic remote sync",
                    "remote_scope": "authenticated loopback project/upload/inspect/analyze/cfg/lift/decompile/transform/rebuild/patch/annotations/artifact and durable lift-job subset",
                    "remote_execution": false,
                    "remote_non_loopback": false,
                    "c_output": true,
                    "c_output_scope": "raw lifted scalar LLVM-to-C, explicit CFG/goto and parallel SSA edge copies; u64(u64,u64) only",
                    "patching": true,
                    "patching_scope": "trusted linked x86-64 ELF, one complete scalar u64x2 function, entry-only assertion, exact in-place size bound; local CLI and owner-scoped remote revision",
                    "whole_executable_rebuild": env::consts::OS == "linux" && env::consts::ARCH == "x86_64" && clang_version.as_deref().is_some_and(|version| version.contains("14.0.6")),
                    "whole_executable_rebuild_scope": "trusted freestanding static symbolized x86-64 ELF; direct calls/branches, bounded mapped data, read/write/exit only; local and authenticated-loopback operations"
                }))?
            );
        }
        Some("inspect") if args.len() == 2 => {
            let bytes = read_binary(&args[1])?;
            let spec = import_elf(&bytes)?;
            println!("{}", serde_json::to_string_pretty(&spec)?);
        }
        Some("triton") if args.len() == 3 => {
            let bytes = read_binary(&args[1])?;
            let (code, address) = extract_symbol_code(&bytes, &args[2])?;
            let request = json!({
                "schema_version": 1,
                "binary_sha256": format!("{:x}", sha2::Sha256::digest(&bytes)),
                "function_symbol": args[2],
                "entry_address": address,
                "code_hex": hex_encode(&code),
            });
            let result = run_triton_bridge(&request)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("triton-console") if args.len() == 1 => {
            let mut input = Vec::new();
            std::io::stdin()
                .take((MAX_TRITON_REQUEST_BYTES + 1) as u64)
                .read_to_end(&mut input)?;
            if input.len() > MAX_TRITON_REQUEST_BYTES {
                return Err("Triton console request exceeds 128 KiB limit".into());
            }
            let request: serde_json::Value = serde_json::from_slice(&input)
                .map_err(|error| format!("invalid Triton console request: {error}"))?;
            if request.get("operation").and_then(serde_json::Value::as_str) != Some("console") {
                return Err("Triton console request must use operation=console".into());
            }
            let result = run_triton_bridge(&request)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        Some("analyze") if args.len() == 2 => {
            let bytes = read_binary(&args[1])?;
            let report = analyze_elf(&bytes)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Some("analyze-spec") if args.len() == 2 => {
            let bytes = read_binary(&args[1])?;
            let spec = analyze_spec_elf(&bytes)?;
            println!("{}", serde_json::to_string_pretty(&spec)?);
        }
        Some("hydir-spec-inspect") if args.len() == 2 || args.len() == 4 => {
            let output = if args.len() == 4 {
                if args[2] != "--canonical-output" {
                    return Err(HELP.into());
                }
                Some(args[3].as_str())
            } else {
                None
            };
            let metadata = fs::metadata(&args[1])?;
            if metadata.len() == 0 || metadata.len() > MAX_SPECIFICATION_BYTES as u64 {
                return Err(format!(
                    "HydIR specification must be 1..={MAX_SPECIFICATION_BYTES} bytes"
                )
                .into());
            }
            let document = SpecificationDocument::decode(&fs::read(&args[1])?)?;
            if let Some(path) = output {
                write_new_or_identical(path, &document.canonical_bytes())?;
            }
            let inventory = document.inventory();
            let mut exact_executable_blocks = 0usize;
            let mut block_byte_errors = Vec::new();
            let mut block_inventory = Vec::new();
            for function in &document.specification().functions {
                for uid in function.blocks.keys() {
                    let block = &function.blocks[uid];
                    block_inventory.push(json!({
                        "uid": uid,
                        "address": format!("0x{:016x}", block.address),
                        "size": block.size,
                        "name": block.name,
                    }));
                    match document.block_bytes(*uid) {
                        Ok(_) => exact_executable_blocks += 1,
                        Err(error) if block_byte_errors.len() < 32 => block_byte_errors.push(error),
                        Err(_) => {}
                    }
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema": "HydIR interchange specification protobuf",
                    "reference_commit": hydir_interchange::EXTERNAL_REFERENCE_COMMIT,
                    "interchange_schema_reference": hydir_interchange::INTERCHANGE_SCHEMA_REFERENCE,
                    "source_sha256": document.source_sha256(),
                    "source_bytes": document.original_bytes().len(),
                    "canonical_bytes": document.canonical_bytes().len(),
                    "stable_target": document.require_stable_target().is_ok(),
                    "arch": document.specification().arch,
                    "operating_system": document.specification().operating_system,
                    "image_name": document.specification().image_name,
                    "image_base": format!("0x{:016x}", document.specification().image_base),
                    "functions": inventory.functions,
                    "blocks": inventory.blocks,
                    "exact_executable_blocks": exact_executable_blocks,
                    "block_byte_errors": block_byte_errors,
                    "block_inventory": block_inventory,
                    "memory_ranges": inventory.memory_ranges,
                    "globals": inventory.globals,
                    "symbols": inventory.symbols,
                    "callsites": inventory.callsites,
                }))?
            );
        }
        Some("hydir-spec-region") if args.len() == 4 || args.len() == 6 => {
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let metadata = fs::metadata(&args[1])?;
            if metadata.len() == 0 || metadata.len() > MAX_SPECIFICATION_BYTES as u64 {
                return Err(format!(
                    "HydIR specification must be 1..={MAX_SPECIFICATION_BYTES} bytes"
                )
                .into());
            }
            let document = SpecificationDocument::decode(&fs::read(&args[1])?)?;
            let elf = read_binary(&args[2])?;
            let uid = parse_u64_auto(&args[3], "block UID")?;
            let json = serde_json::to_vec_pretty(&document.region_spec_for_elf(&elf, uid)?)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("hydir-spec-lift") if args.len() == 4 || args.len() == 6 => {
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let metadata = fs::metadata(&args[1])?;
            if metadata.len() == 0 || metadata.len() > MAX_SPECIFICATION_BYTES as u64 {
                return Err(format!(
                    "HydIR specification must be 1..={MAX_SPECIFICATION_BYTES} bytes"
                )
                .into());
            }
            let document = SpecificationDocument::decode(&fs::read(&args[1])?)?;
            let elf = read_binary(&args[2])?;
            let uid = parse_u64_auto(&args[3], "block UID")?;
            let region = document.region_spec_for_elf(&elf, uid)?;
            let json = serde_json::to_vec_pretty(&lift_physical_region(&region)?)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("hydir-spec-decompile") if args.len() == 4 || args.len() == 6 => {
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let metadata = fs::metadata(&args[1])?;
            if metadata.len() == 0 || metadata.len() > MAX_SPECIFICATION_BYTES as u64 {
                return Err(format!(
                    "HydIR specification must be 1..={MAX_SPECIFICATION_BYTES} bytes"
                )
                .into());
            }
            let document = SpecificationDocument::decode(&fs::read(&args[1])?)?;
            let elf = read_binary(&args[2])?;
            let uid = parse_u64_auto(&args[3], "block UID")?;
            let region = document.region_spec_for_elf(&elf, uid)?;
            let decision_ir = lift_region_decision(&region)?;
            let unit = build_decision_decompilation_unit(
                region,
                decision_ir,
                concat!("hydir/", env!("CARGO_PKG_VERSION")),
            )?;
            let json = serde_json::to_vec_pretty(&unit)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("hydir-spec-report") if args.len() == 3 => {
            let metadata = fs::metadata(&args[1])?;
            if metadata.len() == 0 || metadata.len() > MAX_SPECIFICATION_BYTES as u64 {
                return Err(format!(
                    "HydIR specification must be 1..={MAX_SPECIFICATION_BYTES} bytes"
                )
                .into());
            }
            let document = SpecificationDocument::decode(&fs::read(&args[1])?)?;
            let elf = read_binary(&args[2])?;
            let mut regions = Vec::new();
            let mut bound = 0usize;
            let mut cfg_recovered = 0usize;
            let mut physical_ir_lifted = 0usize;
            let mut structured_ir_lifted = 0usize;
            let mut c_emitted = 0usize;
            for function in &document.specification().functions {
                for uid in function.blocks.keys() {
                    let mut result = json!({
                        "uid": uid,
                        "bound": false,
                        "cfg_recovered": false,
                        "physical_ir_lifted": false,
                        "structured_ir_lifted": false,
                        "c_emitted": false,
                    });
                    match document.region_spec_for_elf(&elf, *uid) {
                        Ok(region) => {
                            bound += 1;
                            result["bound"] = json!(true);
                            result["entry"] = json!(format!("0x{:016x}", region.entry.0));
                            result["bytes"] = json!(region.byte_length);
                            match recover_region_cfg(&region) {
                                Ok(cfg) => {
                                    cfg_recovered += 1;
                                    result["cfg_recovered"] = json!(true);
                                    result["cfg_sha256"] = json!(format!(
                                        "{:x}",
                                        sha2::Sha256::digest(serde_json::to_vec(&cfg)?)
                                    ));
                                }
                                Err(error) => result["cfg_diagnostic"] = json!(error.to_string()),
                            }
                            match lift_physical_region(&region) {
                                Ok(physical_ir) => {
                                    physical_ir_lifted += 1;
                                    result["physical_ir_lifted"] = json!(true);
                                    result["physical_ir_kind"] = json!("physical_v1");
                                    result["physical_ir_instructions"] =
                                        json!(physical_ir.instructions.len());
                                    result["physical_ir_sha256"] = json!(format!(
                                        "{:x}",
                                        sha2::Sha256::digest(serde_json::to_vec(&physical_ir)?)
                                    ));
                                    result["lowering_ready"] = json!(physical_ir.lowering_ready);
                                    result["unresolved_fact_count"] =
                                        json!(physical_ir.unresolved_facts.len());
                                }
                                Err(error) => {
                                    result["physical_ir_diagnostic"] = json!(error.to_string())
                                }
                            }
                            match lift_region_decision(&region) {
                                Ok(decision_ir) => {
                                    let llvm = emit_decision_region_llvm(&decision_ir, &region)?;
                                    structured_ir_lifted += 1;
                                    result["structured_ir_lifted"] = json!(true);
                                    result["structured_ir_kind"] = json!("decision_v1");
                                    result["llvm_sha256"] =
                                        json!(format!("{:x}", sha2::Sha256::digest(&llvm)));
                                    match emit_decision_region_c(&decision_ir, &region) {
                                        Ok(c) => {
                                            c_emitted += 1;
                                            result["c_emitted"] = json!(true);
                                            result["c_sha256"] =
                                                json!(format!("{:x}", sha2::Sha256::digest(&c)));
                                        }
                                        Err(error) => result["diagnostic"] = json!(error),
                                    }
                                }
                                Err(error) => result["diagnostic"] = json!(error.to_string()),
                            }
                        }
                        Err(error) => result["diagnostic"] = json!(error),
                    }
                    regions.push(result);
                }
            }
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema_version": 2,
                    "source_sha256": document.source_sha256(),
                    "binary_sha256": format!("{:x}", sha2::Sha256::digest(&elf)),
                    "total_regions": document.inventory().blocks,
                    "bound_regions": bound,
                    "cfg_recovered_regions": cfg_recovered,
                    "physical_ir_regions": physical_ir_lifted,
                    "structured_ir_regions": structured_ir_lifted,
                    "c_regions": c_emitted,
                    "regions": regions,
                }))?
            );
        }
        Some("cfg") if args.len() == 3 => {
            let bytes = read_binary(&args[1])?;
            let cfg = recover_symbol_cfg(&bytes, &args[2])?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Some("region") if args.len() == 3 => {
            let bytes = read_binary(&args[1])?;
            println!(
                "{}",
                serde_json::to_string_pretty(&region_contract(&bytes, &args[2])?)?
            );
        }
        Some("cfg-at") if args.len() == 4 => {
            let bytes = read_binary(&args[1])?;
            let (address, size) = parse_address_extent(&args[2], &args[3])?;
            let cfg = recover_at_cfg(&bytes, address, size)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Some("lift")
            if args.len() == 8
                && args[2] == "--function"
                && args[4] == "--ir"
                && args[5] == "high-level"
                && args[6] == "--model" =>
        {
            let bytes = read_binary(&args[1])?;
            let model = parse_model(&fs::read(&args[7])?)?;
            validate_model(&bytes, &model)?;
            let selection = resolve_native_function(&bytes, &args[3])?;
            let native = decompile_native_selection(&bytes, &selection)?;
            let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &model)?;
            println!("{}", serde_json::to_string_pretty(&ir)?);
        }
        Some("lift") if args.len() == 6 && args[2] == "--function" && args[4] == "--ir" => {
            let bytes = read_binary(&args[1])?;
            let selection = resolve_native_function(&bytes, &args[3])?;
            let machine = lift_native_selection(&bytes, &selection)?;
            match args[5].as_str() {
                "machine" => println!("{}", serde_json::to_string_pretty(&machine)?),
                "state" => println!(
                    "{}",
                    serde_json::to_string_pretty(&lower_state_ir(&machine)?)?
                ),
                "expression" => {
                    let state = lower_state_ir(&machine)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&lower_expression_ir(&machine, &state)?)?
                    );
                }
                "function" => {
                    let state = lower_state_ir(&machine)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&lower_function_ir(&machine, &state)?)?
                    );
                }
                "cir" => {
                    let state = lower_state_ir(&machine)?;
                    let function = lower_function_ir(&machine, &state)?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&lower_cir(&machine, &function)?)?
                    );
                }
                "llvm" => {
                    let state = lower_state_ir(&machine)?;
                    let function = lower_function_ir(&machine, &state)?;
                    print!("{}", export_function_ir_llvm(&function)?);
                }
                _ => {
                    return Err(
                        "native --ir must be machine, state, expression, function, cir, or llvm"
                            .into(),
                    );
                }
            }
        }
        Some("lift") if args.len() == 4 || args.len() == 6 => {
            if args[3] != "--assume-u64x2" {
                return Err("lift requires explicit --assume-u64x2 prototype assertion".into());
            }
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[1])?;
            let ir = lift_symbol(&bytes, &args[2])?;
            if let Some(path) = output {
                write_new_or_identical(path, ir.as_bytes())?;
            } else {
                print!("{ir}");
            }
        }
        Some("lift-model") if args.len() == 4 || args.len() == 6 => {
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[1])?;
            let (ir, _) = typed_model_lift(&bytes, &args[2], &args[3])?;
            if let Some(path) = output {
                write_new_or_identical(path, ir.as_bytes())?;
            } else {
                print!("{ir}");
            }
        }
        Some("lift") if args.len() == 3 => {
            return Err("lift requires explicit --assume-u64x2 prototype assertion".into());
        }
        Some("lift-at") if args.len() == 5 || args.len() == 7 => {
            if args[4] != "--assume-u64x2" {
                return Err("lift-at requires explicit --assume-u64x2 prototype assertion".into());
            }
            let output = if args.len() == 7 {
                if args[5] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[6].as_str())
            } else {
                None
            };
            let (address, size) = parse_address_extent(&args[2], &args[3])?;
            let bytes = read_binary(&args[1])?;
            let ir = lift_at(&bytes, address, size)?;
            if let Some(path) = output {
                write_new_or_identical(path, ir.as_bytes())?;
            } else {
                print!("{ir}");
            }
        }
        Some("decompile")
            if args.len() == 8
                && args[2] == "--function"
                && args[4] == "--view"
                && args[5] == "typed"
                && args[6] == "--model" =>
        {
            let bytes = read_binary(&args[1])?;
            let model = parse_model(&fs::read(&args[7])?)?;
            validate_model(&bytes, &model)?;
            let selection = resolve_native_function(&bytes, &args[3])?;
            let native = decompile_native_selection(&bytes, &selection)?;
            let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &model)?;
            print!("{}", emit_typed_c(&ir, &model)?);
        }
        Some("decompile") if args.len() == 6 && args[2] == "--function" && args[4] == "--view" => {
            let bytes = read_binary(&args[1])?;
            let selection = resolve_native_function(&bytes, &args[3])?;
            match args[5].as_str() {
                "low" => print!(
                    "{}",
                    decompile_native_selection(&bytes, &selection)?.low_level_c
                ),
                "structured" => {
                    let native = decompile_native_selection(&bytes, &selection)?;
                    let source = native.structured_c.ok_or(
                        "structured C is unavailable for this function; request --view low or unit",
                    )?;
                    print!("{source}");
                }
                "unit" => match &selection {
                    NativeFunctionSelection::Symbol(symbol) => println!(
                        "{}",
                        serde_json::to_string_pretty(&decompile_symbol_unit(&bytes, symbol)?)?
                    ),
                    NativeFunctionSelection::Discovered(entry) => println!(
                        "{}",
                        serde_json::to_string_pretty(&decompile_function_unit_at(&bytes, *entry)?)?
                    ),
                },
                _ => return Err("native --view must be low, structured, or unit".into()),
            }
        }
        Some("decompile-all") if args.len() == 4 && args[2] == "--output-dir" => {
            let bytes = read_binary(&args[1])?;
            let index = discover_function_candidates(&bytes)?;
            let output_dir = Path::new(&args[3]);
            if output_dir.exists() {
                return Err(format!(
                    "output directory {} already exists; refusing to merge or overwrite",
                    output_dir.display()
                )
                .into());
            }
            fs::create_dir(output_dir)?;
            let mut results = Vec::new();
            let mut attempted = std::collections::BTreeSet::new();
            for function in &index.functions {
                if !attempted.insert(function.id.clone()) {
                    continue;
                }
                let display_name = function
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("sub_{:x}", function.entry.value.0));
                let stem = format!(
                    "{:05}-{}",
                    results.len(),
                    native_file_component(&display_name)
                );
                let symbol_backed = function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "elf_symbol");
                if !symbol_backed {
                    match decompile_indexed_function_unit(&bytes, &index, &function.id) {
                        Ok(unit) => {
                            let unit_path = output_dir.join(format!("{stem}.unit.json"));
                            let low_path = output_dir.join(format!("{stem}.low.c"));
                            write_new_or_identical(&unit_path, &serde_json::to_vec_pretty(&unit)?)?;
                            write_new_or_identical(
                                &low_path,
                                unit.low_level_c
                                    .as_deref()
                                    .unwrap_or(&unit.c_source)
                                    .as_bytes(),
                            )?;
                            let structured_path = if let Some(source) = unit.structured_c.as_deref()
                            {
                                let path = output_dir.join(format!("{stem}.structured.c"));
                                write_new_or_identical(&path, source.as_bytes())?;
                                Some(
                                    path.file_name()
                                        .unwrap_or_default()
                                        .to_string_lossy()
                                        .to_string(),
                                )
                            } else {
                                None
                            };
                            results.push(json!({
                                "function_id": function.id,
                                "name": display_name,
                                "status": "decompiled",
                                "unit": unit_path.file_name().unwrap_or_default().to_string_lossy(),
                                "low_level_c": low_path.file_name().unwrap_or_default().to_string_lossy(),
                                "structured_c": structured_path,
                                "structural_completeness": unit.structural_completeness,
                                "semantic_fidelity": unit.semantic_fidelity,
                                "rewrite_ready": unit.rewrite_ready,
                            }));
                        }
                        Err(error) => results.push(json!({
                            "function_id": function.id,
                            "name": display_name,
                            "status": "diagnostic",
                            "diagnostic": error,
                        })),
                    }
                    continue;
                }
                let Some(symbol) = function.name.as_deref() else {
                    results.push(json!({
                        "function_id": function.id,
                        "name": display_name,
                        "status": "diagnostic",
                        "diagnostic": "ELF symbol evidence has no name",
                    }));
                    continue;
                };
                match decompile_symbol_unit(&bytes, symbol) {
                    Ok(unit) => {
                        let unit_path = output_dir.join(format!("{stem}.unit.json"));
                        let low_path = output_dir.join(format!("{stem}.low.c"));
                        write_new_or_identical(&unit_path, &serde_json::to_vec_pretty(&unit)?)?;
                        write_new_or_identical(
                            &low_path,
                            unit.low_level_c
                                .as_deref()
                                .unwrap_or(&unit.c_source)
                                .as_bytes(),
                        )?;
                        let structured_path = if let Some(source) = unit.structured_c.as_deref() {
                            let path = output_dir.join(format!("{stem}.structured.c"));
                            write_new_or_identical(&path, source.as_bytes())?;
                            Some(
                                path.file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string(),
                            )
                        } else {
                            None
                        };
                        results.push(json!({
                            "function_id": function.id,
                            "symbol": symbol,
                            "status": "decompiled",
                            "unit": unit_path.file_name().unwrap_or_default().to_string_lossy(),
                            "low_level_c": low_path.file_name().unwrap_or_default().to_string_lossy(),
                            "structured_c": structured_path,
                            "structural_completeness": unit.structural_completeness,
                            "semantic_fidelity": unit.semantic_fidelity,
                            "rewrite_ready": unit.rewrite_ready,
                        }));
                    }
                    Err(error) => results.push(json!({
                        "function_id": function.id,
                        "symbol": symbol,
                        "status": "diagnostic",
                        "diagnostic": error,
                    })),
                }
            }
            let manifest = json!({
                "schema_version": 1,
                "binary_sha256": index.binary_sha256,
                "function_index_schema_version": index.schema_version,
                "results": results,
            });
            write_new_or_identical(
                output_dir.join("manifest.json"),
                &serde_json::to_vec_pretty(&manifest)?,
            )?;
            println!("{}", serde_json::to_string_pretty(&manifest)?);
        }
        Some("decompile") if args.len() == 4 || args.len() == 6 => {
            if args[3] != "--assume-u64x2" {
                return Err(
                    "decompile requires explicit --assume-u64x2 prototype assertion".into(),
                );
            }
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[1])?;
            let c = emit_structured_c(&lift_symbol(&bytes, &args[2])?)?;
            if let Some(path) = output {
                write_new_or_identical(path, c.as_bytes())?;
            } else {
                print!("{c}");
            }
        }
        Some("decompile-unit") if args.len() == 4 || args.len() == 6 => {
            if args[3] != "--assume-u64x2" {
                return Err(
                    "decompile-unit requires explicit --assume-u64x2 prototype assertion".into(),
                );
            }
            let output = if args.len() == 6 {
                if args[4] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[5].as_str())
            } else {
                None
            };
            let bytes = read_binary(&args[1])?;
            let region = region_contract(&bytes, &args[2])?;
            let raw_llvm = lift_symbol(&bytes, &args[2])?;
            let unit = build_decompilation_unit(
                region,
                raw_llvm,
                concat!("hydir/", env!("CARGO_PKG_VERSION")),
            )?;
            let json = serde_json::to_vec_pretty(&unit)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("decompile-at") if args.len() == 5 || args.len() == 7 => {
            if args[4] != "--assume-u64x2" {
                return Err(
                    "decompile-at requires explicit --assume-u64x2 prototype assertion".into(),
                );
            }
            let output = if args.len() == 7 {
                if args[5] != "--output" {
                    return Err(HELP.into());
                }
                Some(args[6].as_str())
            } else {
                None
            };
            let (address, size) = parse_address_extent(&args[2], &args[3])?;
            let bytes = read_binary(&args[1])?;
            let c = emit_structured_c(&lift_at(&bytes, address, size)?)?;
            if let Some(path) = output {
                write_new_or_identical(path, c.as_bytes())?;
            } else {
                print!("{c}");
            }
        }
        Some("transform") => passes::run(&args[1..])?,
        Some("patch") => patch::run(&args[1..])?,
        Some("rebuild") => recompile::run(&args[1..])?,
        Some("validate") if args.len() >= 4 => validate(&args[1..], false, false)?,
        Some("validate-at") if args.len() >= 5 => validate(&args[1..], true, false)?,
        Some("validate-c") if args.len() >= 4 => validate(&args[1..], false, true)?,
        Some("validate-c-at") if args.len() >= 5 => validate(&args[1..], true, true)?,
        Some("local") if args.len() >= 3 => local::run(&args[1..])?,
        Some("remote") if args.len() >= 2 => {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(remote::run(&args[1..]))?;
        }
        Some("help") | Some("--help") | Some("-h") if args.len() == 1 => print!("{HELP}"),
        _ => return Err(HELP.into()),
    }
    Ok(())
}

enum NativeFunctionSelection {
    Symbol(String),
    Discovered(Location),
}

fn resolve_native_function(
    bytes: &[u8],
    selector: &str,
) -> Result<NativeFunctionSelection, Box<dyn Error>> {
    let index = discover_function_candidates(bytes)?;
    let mut matches = index
        .functions
        .iter()
        .filter(|function| function.id == selector || function.name.as_deref() == Some(selector));
    let function = matches
        .next()
        .ok_or_else(|| format!("native function selector {selector:?} was not discovered"))?;
    if matches.next().is_some() {
        return Err(format!(
            "native function selector {selector:?} is ambiguous; use the FunctionIndex id"
        )
        .into());
    }
    if function
        .evidence
        .iter()
        .any(|evidence| evidence.kind == "elf_symbol")
    {
        function
            .name
            .clone()
            .map(NativeFunctionSelection::Symbol)
            .ok_or_else(|| "ELF symbol evidence has no symbol name".into())
    } else {
        Ok(NativeFunctionSelection::Discovered(function.entry))
    }
}

fn lift_native_selection(
    bytes: &[u8],
    selection: &NativeFunctionSelection,
) -> Result<MachineFunctionIr, Box<dyn Error>> {
    Ok(match selection {
        NativeFunctionSelection::Symbol(symbol) => lift_machine_function(bytes, symbol)?,
        NativeFunctionSelection::Discovered(entry) => lift_machine_function_at(bytes, *entry)?,
    })
}

fn decompile_native_selection(
    bytes: &[u8],
    selection: &NativeFunctionSelection,
) -> Result<NativeDecompilation, Box<dyn Error>> {
    Ok(match selection {
        NativeFunctionSelection::Symbol(symbol) => decompile_symbol(bytes, symbol)?,
        NativeFunctionSelection::Discovered(entry) => decompile_function_at(bytes, *entry)?,
    })
}

fn native_file_component(value: &str) -> String {
    let mut component = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.') {
                character
            } else {
                '_'
            }
        })
        .take(96)
        .collect::<String>();
    if component.is_empty() || component == "." || component == ".." {
        component = "function".to_owned();
    }
    component
}

fn parse_address_extent(address: &str, size: &str) -> Result<(u64, u64), Box<dyn Error>> {
    let digits = address
        .strip_prefix("0x")
        .ok_or("virtual address must use 0x-prefixed hexadecimal")?;
    if digits.is_empty() {
        return Err("virtual address has no hex digits".into());
    }
    let address = u64::from_str_radix(digits, 16)?;
    let size = size.parse::<u64>()?;
    if size == 0 || size > 4096 {
        return Err("size must be 1..=4096 bytes".into());
    }
    Ok((address, size))
}

fn parse_u64_auto(value: &str, label: &str) -> Result<u64, Box<dyn Error>> {
    if let Some(digits) = value.strip_prefix("0x") {
        if digits.is_empty() {
            return Err(format!("{label} has no hexadecimal digits").into());
        }
        Ok(u64::from_str_radix(digits, 16)?)
    } else {
        Ok(value.parse::<u64>()?)
    }
}

fn typed_model_lift(
    bytes: &[u8],
    symbol: &str,
    model_path: &str,
) -> Result<(String, serde_json::Value), Box<dyn Error>> {
    let actual = import_elf(bytes)?;
    if fs::metadata(model_path)?.len() > 2 * 1024 * 1024 {
        return Err("typed ProgramSpec exceeds 2 MiB".into());
    }
    let model = parse_program_spec_json(&fs::read(model_path)?)?;
    if model.binary_sha256 != actual.binary_sha256 {
        return Err("typed ProgramSpec binary digest does not match ELF".into());
    }
    let function = actual
        .functions
        .iter()
        .find(|function| function.name == symbol)
        .ok_or("function symbol missing from binary inventory")?;
    let prototype = model
        .typed_model
        .prototypes
        .iter()
        .find(|prototype| prototype.entry == function.address)
        .ok_or("typed prototype assertion missing for function entry")?;
    if !annotation_address_in_spec(&actual, prototype.entry)
        || prototype.return_type != ScalarType::U64
        || prototype.parameters != [ScalarType::U64, ScalarType::U64]
        || prototype.calling_convention != CallingConvention::SysvAmd64
    {
        return Err("typed prototype is not the supported SysV u64(u64,u64) contract".into());
    }
    let model_json = serde_json::to_vec(&model.typed_model)?;
    let model_sha256 = format!("{:x}", sha2::Sha256::digest(&model_json));
    let body = lift_symbol(bytes, symbol)?;
    let facts: Vec<_> = model
        .typed_model
        .stack_facts
        .iter()
        .filter(|fact| fact.function_entry == function.address)
        .collect();
    if !facts.is_empty() {
        let offsets = proven_stack_local_offsets(bytes, symbol)?;
        for fact in &facts {
            if fact.width_bits != 64 || !offsets.contains(&fact.entry_rsp_offset) {
                return Err(format!(
                    "stack assertion {} is not a proven eight-byte local in this function",
                    fact.id
                )
                .into());
            }
        }
    }
    let mut ir = format!(
        "; HydIR binary sha256: {}\n; HydIR typed model sha256: {model_sha256}\n; prototype assertion: {}\n",
        actual.binary_sha256, prototype.id
    );
    for fact in &facts {
        ir.push_str(&format!(
            "; stack assertion: {} offset {} width 64\n",
            fact.id, fact.entry_rsp_offset
        ));
    }
    ir.push_str(&body);
    let evidence = json!({
        "binary_sha256": actual.binary_sha256,
        "typed_model_sha256": model_sha256,
        "prototype_assertion": prototype.id,
        "stack_assertions": facts.iter().map(|fact| fact.id.as_str()).collect::<Vec<_>>(),
    });
    Ok((ir, evidence))
}

fn validate(args: &[String], by_address: bool, c_backend: bool) -> Result<(), Box<dyn Error>> {
    if env::consts::OS != "linux" || env::consts::ARCH != "x86_64" {
        return Err(
            "validation executes only on Linux x86-64; import and lift are portable".into(),
        );
    }
    let mut trusted = false;
    let mut assume_u64x2 = false;
    let mut clang = "clang";
    let mut random_cases = 1000usize;
    let mut cases_file = None;
    let mut model_file = None;
    let mut index = if by_address { 3 } else { 2 };
    while index < args.len() {
        match args[index].as_str() {
            "--trusted-fixture" if !trusted => trusted = true,
            "--assume-u64x2" if !assume_u64x2 => assume_u64x2 = true,
            "--clang" if index + 1 < args.len() => {
                index += 1;
                clang = &args[index];
            }
            "--random-cases" if index + 1 < args.len() => {
                index += 1;
                random_cases = args[index].parse()?;
            }
            "--cases-file" if cases_file.is_none() && index + 1 < args.len() => {
                index += 1;
                cases_file = Some(args[index].as_str());
            }
            "--model" if model_file.is_none() && index + 1 < args.len() => {
                index += 1;
                model_file = Some(args[index].as_str());
            }
            _ => {
                return Err(
                    format!("invalid or duplicate validation option: {}", args[index]).into(),
                );
            }
        }
        index += 1;
    }
    if !trusted {
        return Err(
            "validation is unsandboxed; pass --trusted-fixture only for a trusted test binary"
                .into(),
        );
    }
    if !assume_u64x2 {
        return Err("validation requires explicit --assume-u64x2 prototype assertion".into());
    }
    let binary = fs::canonicalize(&args[0])?;
    let address_extent = if by_address {
        Some(parse_address_extent(&args[1], &args[2])?)
    } else {
        None
    };
    let label = if let Some((address, size)) = address_extent {
        format!("analyst_entry_0x{address:x}_size_{size}")
    } else {
        args[1].clone()
    };
    if random_cases > 10_000 {
        return Err("--random-cases is limited to 10000".into());
    }
    let bytes = read_binary(&binary)?;
    let (ir, model_evidence) = if let Some(model_path) = model_file {
        if by_address {
            return Err("typed model validation requires a named function symbol".into());
        }
        let (ir, evidence) = typed_model_lift(&bytes, &args[1], model_path)?;
        (ir, Some(evidence))
    } else if let Some((address, size)) = address_extent {
        (lift_at(&bytes, address, size)?, None)
    } else {
        (lift_symbol(&bytes, &args[1])?, None)
    };
    let directory = tempfile::tempdir()?;
    let ir_path = directory.path().join("lifted.ll");
    let c_path = directory.path().join("lifted.c");
    let harness_path = directory.path().join("harness.c");
    let lifted_path = directory.path().join("lifted-runner");
    let source_path = if c_backend {
        fs::write(&c_path, emit_structured_c(&ir)?)?;
        &c_path
    } else {
        fs::write(&ir_path, ir)?;
        &ir_path
    };
    fs::write(&harness_path, HARNESS)?;
    let compile = Command::new(clang)
        .args(["-O0", "-o"])
        .arg(&lifted_path)
        .arg(source_path)
        .arg(&harness_path)
        .output()?;
    if !compile.status.success() {
        return Err(format!(
            "lifted {} compilation failed: {}",
            if c_backend { "C" } else { "LLVM" },
            String::from_utf8_lossy(&compile.stderr)
        )
        .into());
    }
    let mut cases = vec![
        (0, 0),
        (1, 2),
        (u64::MAX, 1),
        (u64::MAX, u64::MAX),
        (1 << 63, 1 << 63),
        (1 << 63, 0),
        (0, u64::MAX),
        (42, 999),
    ];
    let seed = 0x6859_6449_5220_3236u64;
    let mut rng = seed;
    for _ in 0..random_cases {
        let a = next_random(&mut rng);
        let b = next_random(&mut rng);
        cases.push((a, b));
    }
    let external_cases = if let Some(path) = cases_file {
        read_validation_cases(path)?
    } else {
        Vec::new()
    };
    let external_case_count = external_cases.len();
    cases.extend(external_cases);
    let mut mismatches = Vec::new();
    let mut mismatch_count = 0usize;
    for (a, b) in &cases {
        let native = run_case(&binary, *a, *b)?;
        let lifted = run_case(&lifted_path, *a, *b)?;
        if native.status != lifted.status
            || native.stdout != lifted.stdout
            || native.stderr != lifted.stderr
        {
            mismatch_count += 1;
            if mismatches.len() < 8 {
                mismatches.push(json!({
                    "input": [a.to_string(), b.to_string()],
                    "original": describe(&native),
                    "lifted": describe(&lifted)
                }));
            }
        }
    }
    let matched = cases.len() - mismatch_count;
    let report = json!({
        "scope": "trusted two-u64 function fixture; stdout/stderr/exit status",
        "backend": if c_backend { "HydIR scalar LLVM-to-C" } else { "raw LLVM" },
        "binary": binary,
        "function": label,
        "entry_assumption": address_extent.map(|(address, size)| json!({"virtual_address": format!("0x{address:016x}"), "size_bytes": size, "provenance": "analyst-supplied"})),
        "typed_model_evidence": model_evidence,
        "seed": format!("0x{seed:016x}"),
        "cases_attempted": cases.len(),
        "external_cases_attempted": external_case_count,
        "cases_matched": matched,
        "cases_mismatched": mismatch_count,
        "mismatches": mismatches,
        "result": if matched == cases.len() { "pass" } else { "fail" },
        "sandbox": "none; trusted fixtures only"
    });
    println!("{}", serde_json::to_string_pretty(&report)?);
    if matched != cases.len() {
        return Err("differential validation failed".into());
    }
    Ok(())
}

fn read_validation_cases(path: &str) -> Result<Vec<(u64, u64)>, Box<dyn Error>> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > 64 * 1024 {
        return Err("validation cases file exceeds 64 KiB".into());
    }
    let value: serde_json::Value = serde_json::from_reader(file)?;
    let rows = value
        .as_array()
        .ok_or("validation cases must be a JSON array")?;
    if rows.len() > 256 {
        return Err("validation cases are limited to 256 pairs".into());
    }
    rows.iter()
        .map(|row| {
            let pair = row.as_array().ok_or("validation case must be a pair")?;
            if pair.len() != 2 {
                return Err("validation case must contain exactly two values".into());
            }
            let parse = |value: &serde_json::Value| -> Result<u64, Box<dyn Error>> {
                value
                    .as_str()
                    .ok_or_else(|| "validation input must be a decimal u64 string".into())
                    .and_then(|number| Ok(number.parse::<u64>()?))
            };
            Ok((parse(&pair[0])?, parse(&pair[1])?))
        })
        .collect()
}

fn read_binary(path: impl AsRef<Path>) -> Result<Vec<u8>, Box<dyn Error>> {
    let path = path.as_ref();
    if fs::metadata(path)?.len() > MAX_BINARY_BYTES as u64 {
        return Err("binary exceeds 64 MiB import limit".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((MAX_BINARY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BINARY_BYTES {
        return Err("binary changed during read and exceeds 64 MiB import limit".into());
    }
    Ok(bytes)
}

const MAX_TRITON_REQUEST_BYTES: usize = 128 * 1024;
const MAX_TRITON_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_TRITON_STDERR_BYTES: usize = 64 * 1024;
const TRITON_TIMEOUT: Duration = Duration::from_secs(30);

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn triton_helper_path() -> std::path::PathBuf {
    if let Ok(path) = env::var("HYDIR_TRITON_HELPER") {
        return Path::new(&path).to_owned();
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/triton_bridge.py")
}

fn configured_triton_python() -> String {
    if let Ok(path) = env::var("HYDIR_TRITON_PYTHON") {
        return path;
    }
    let mut candidates = vec!["python".to_owned(), "python3".to_owned()];
    #[cfg(windows)]
    if let Ok(output) = Command::new("py").args(["-0p"]).output()
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        candidates.extend(text.lines().filter_map(|line| {
            line.split_whitespace()
                .find(|token| token.to_ascii_lowercase().ends_with(".exe"))
                .map(str::to_owned)
        }));
    }
    candidates
        .iter()
        .find(|candidate| {
            Command::new(candidate)
                .args(["-c", "import triton"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        })
        .cloned()
        .unwrap_or_else(|| "python".to_owned())
}

fn run_triton_bridge(request: &serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    let python = configured_triton_python();
    let helper = triton_helper_path();
    let use_embedded = !helper.is_file() && env::var_os("HYDIR_TRITON_HELPER").is_none();
    if !helper.is_file() && !use_embedded {
        return Err(format!("Triton bridge helper not found: {}", helper.display()).into());
    }
    let input = serde_json::to_vec(request)?;
    if input.len() > MAX_TRITON_REQUEST_BYTES {
        return Err("Triton bridge request exceeds 128 KiB limit".into());
    }
    let mut command = Command::new(&python);
    if use_embedded {
        command.args(["-c", EMBEDDED_TRITON_HELPER]);
    } else {
        command.arg(&helper);
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("unable to start Triton Python bridge {python:?}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Triton bridge stdout unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Triton bridge stderr unavailable")?;
    let stdout_reader = thread::spawn(move || read_limited(stdout, MAX_TRITON_OUTPUT_BYTES));
    let stderr_reader = thread::spawn(move || read_limited(stderr, MAX_TRITON_STDERR_BYTES));
    child
        .stdin
        .take()
        .ok_or("Triton bridge stdin unavailable")?
        .write_all(&input)?;
    let deadline = Instant::now() + TRITON_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("Triton bridge timed out after 30 seconds".into());
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "Triton bridge stdout reader panicked")??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "Triton bridge stderr reader panicked")??;
    if !status.success() {
        let detail = String::from_utf8_lossy(&stderr);
        return Err(format!("Triton bridge failed: {}", detail.trim()).into());
    }
    if stdout.len() > MAX_TRITON_OUTPUT_BYTES {
        return Err("Triton bridge output exceeds 1 MiB limit".into());
    }
    let result: serde_json::Value = serde_json::from_slice(&stdout)
        .map_err(|error| format!("Triton bridge returned invalid JSON: {error}"))?;
    if result.get("binary_sha256") != request.get("binary_sha256") {
        return Err("Triton bridge binary identity mismatch".into());
    }
    Ok(result)
}

fn read_limited<R: Read>(mut reader: R, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(output);
        }
        if output.len() <= limit {
            let remaining = limit + 1 - output.len();
            output.extend_from_slice(&buffer[..count.min(remaining)]);
        }
    }
}

fn write_new_or_identical(path: impl AsRef<Path>, content: &[u8]) -> Result<(), Box<dyn Error>> {
    let path = path.as_ref();
    if path.exists() {
        if fs::read(path)? == content {
            return Ok(());
        }
        return Err(format!(
            "output {} already exists with different content; refusing to overwrite it",
            path.display()
        )
        .into());
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(content)?;
    match temporary.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(_) if fs::read(path).is_ok_and(|existing| existing == content) => Ok(()),
        Err(failure) => Err(format!(
            "could not create {} without overwrite: {}",
            path.display(),
            failure.error
        )
        .into()),
    }
}

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn run_case(path: &Path, a: u64, b: u64) -> Result<Output, Box<dyn Error>> {
    Ok(Command::new(path)
        .arg(a.to_string())
        .arg(b.to_string())
        .env_clear()
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()?)
}

fn describe(output: &Output) -> serde_json::Value {
    json!({
        "exit_code": output.status.code(),
        "stdout": String::from_utf8_lossy(&output.stdout),
        "stderr": String::from_utf8_lossy(&output.stderr)
    })
}

const HARNESS: &str = r#"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
extern uint64_t hydir_lifted(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    uint64_t a = strtoull(argv[1], 0, 10);
    uint64_t b = strtoull(argv[2], 0, 10);
    printf("%llu\n", (unsigned long long)hydir_lifted(a, b, 0, 0, 0, 0));
    return 0;
}
"#;

#[cfg(test)]
mod tests {
    use super::read_validation_cases;

    #[test]
    fn external_cases_preserve_full_width_inputs() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cases.json");
        std::fs::write(&path, r#"[["18446744073709551615","0"],["1","2"]]"#).unwrap();
        assert_eq!(
            read_validation_cases(path.to_str().unwrap()).unwrap(),
            vec![(u64::MAX, 0), (1, 2)]
        );
        std::fs::write(&path, r#"[[18446744073709551615,"0"]]"#).unwrap();
        assert!(read_validation_cases(path.to_str().unwrap()).is_err());
    }
}
