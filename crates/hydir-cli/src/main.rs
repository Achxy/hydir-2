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
use hydir_execution::{
    InputSpec, ProbeLocation, ReplayBudget, ReplayGoal, build_snapshot_resume_plan,
    input_with_origin_candidate, parse_execution_snapshot, parse_input_spec, parse_origin_probe,
    parse_snapshot_resume_plan, probe_origin, validate_execution_snapshot, validate_input_spec,
    validate_origin_probe, validate_snapshot_bridge_result, validate_snapshot_resume_plan,
};
use hydir_hlc::{emit_typed_c, emit_typed_cfg_c, lower_high_level_cfg_cir, lower_high_level_cir};
use hydir_interchange::{MAX_SPECIFICATION_BYTES, SpecificationDocument};
use hydir_ir::MachineFunctionIr;
use hydir_ir::pcode::{
    MAX_GHIDRA_SNAPSHOT_BYTES, MAX_PCODE_SEED_BYTES, parse_ghidra_snapshot, parse_pcode_seed,
};
use hydir_model::{import_dwarf, infer_model, init_model, parse_model, validate_model};
use hydir_vm::{VmProfile, explore_profile, validate_profile};
mod ghidra_worker;
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
  hydirctl ghidra analyze <binary> --output <snapshot.json> [--function <0xhex>]
  hydirctl ghidra-snapshot verify <binary> <snapshot.json>
  hydirctl ghidra-snapshot pcode <binary> <snapshot.json> [--output <pcode-ir.json>]
  hydirctl ghidra-snapshot semantics <binary> <snapshot.json> [--output <semantic-ir.json>]
  hydirctl ghidra-snapshot state <binary> <snapshot.json> [--output <state-ir.json>]
  hydirctl ghidra-snapshot cfg <binary> <snapshot.json> [--output <cfg-ir.json>]
  hydirctl ghidra-snapshot llvm-prefix <binary> <snapshot.json> [--output <prefix.json>]
  hydirctl ghidra-snapshot llvm-standalone <binary> <snapshot.json> [--output <standalone.json>]
  hydirctl ghidra-snapshot llvm-cfg <binary> <snapshot.json> [--start <0xaddress>] [--output <cfg-llvm.json>]
  hydirctl ghidra-snapshot trace-prefix <binary> <snapshot.json> <seed.json> [--max-ops <n>] [--output <trace.json>]
  hydirctl ghidra-snapshot trace-path <binary> <snapshot.json> <seed.json> [--start <0xaddress>] [--max-ops <n>] [--max-visits <n>] [--output <trace.json>]
  hydirctl ghidra-snapshot llvm-op <binary> <snapshot.json> --instruction <hex> --op <index> [--output <file.ll>]
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
  hydirctl lift <elf> --function <function-id-or-symbol> --ir <high-level|high-level-cfg> --model <model.json>
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
  hydirctl replay init <linked-elf> [--output <input.json>]
  hydirctl replay verify <linked-elf> <input.json>
  hydirctl replay <linked-elf> <input.json> [--output <report.json>]
  hydirctl capture <linked-elf> <input.json> (--function <symbol> | --address <elf-vaddr>) [--output <snapshot.json>]
  hydirctl snapshot verify <linked-elf> <input.json> <snapshot.json>
  hydirctl snapshot probe-origin <linked-elf> <input.json> <snapshot.json> <origin-id> --register <name> [--output <probe.json>]
  hydirctl snapshot verify-origin <linked-elf> <input.json> <snapshot.json> <probe.json>
  hydirctl snapshot plan-return <linked-elf> <input.json> <snapshot.json> <probe.json> --code-bytes <n> --return <u64> [--output <plan.json>]
  hydirctl snapshot verify-plan <linked-elf> <input.json> <snapshot.json> <probe.json> <plan.json>
  hydirctl solve snapshot-return <linked-elf> <input.json> <snapshot.json> <probe.json> <plan.json> [--candidate-output <input.json>] [--slice-output <slice.json>] [--claim-output <claim.json>] [--recipe-output <recipe.json>] [--output <report.json>]
  hydirctl recipe verify <linked-elf> <recipe.json> [--output <verification.json>]
  hydirctl recipe replay <linked-elf> <recipe.json> [--output <replay.json>]
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
Replay uses an experimental local Linux Bubblewrap runner. Other hosts return
an unsupported-host report. See docs/REPLAY_PROTOCOL.md for its current scope.
Capture uses GDB/MI in the same Linux isolation and stops at a simple C symbol
or a file-backed executable ELF virtual address, including stripped PIE code.
It currently supports one thread and emits a sparse snapshot.
An origin probe checks bytes at an analyst-selected register location against
one InputSpec origin. A match is byte equality, not channel provenance.
Snapshot return solving is experimental and limited to a captured pure code
extent. A Triton function witness becomes native-validated only after fresh
original-ELF replay meets the InputSpec goal.
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

fn probe_bubblewrap_isolation() -> bool {
    if env::consts::OS != "linux" || env::consts::ARCH != "x86_64" {
        return false;
    }
    let Ok(mut child) = Command::new("bwrap")
        .args([
            "--unshare-user",
            "--unshare-net",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("hydirctl: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("ghidra-snapshot") if args.len() >= 4 && args[1] == "llvm-cfg" => {
            let mut start_address = None;
            let mut output_path = None;
            let mut options = args[4..].chunks_exact(2);
            for pair in &mut options {
                match pair[0].as_str() {
                    "--start" if start_address.is_none() => {
                        start_address = Some(parse_u64_auto(&pair[1], "P-code start address")?);
                    }
                    "--output" if output_path.is_none() => output_path = Some(pair[1].as_str()),
                    _ => return Err(HELP.into()),
                }
            }
            if !options.remainder().is_empty() {
                return Err(HELP.into());
            }
            let binary = read_binary(&args[2])?;
            let digest = format!("{:x}", sha2::Sha256::digest(&binary));
            let snapshot = parse_ghidra_snapshot(
                &read_bounded_json(&args[3], MAX_GHIDRA_SNAPSHOT_BYTES)?,
                &digest,
            )?;
            let start = start_address.map(|address| hydir_ir::pcode::PcodeAddress {
                space: snapshot.selected_function.entry.space.clone(),
                offset: format!("0x{address:x}"),
            });
            let artifact = hydir_decompile::emit_pcode_cfg_llvm(&snapshot, start.as_ref())?;
            let bytes = serde_json::to_vec_pretty(&artifact)?;
            if let Some(path) = output_path {
                write_new_or_identical(path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Some("ghidra-snapshot") if args.len() >= 5 && args[1] == "trace-path" => {
            let mut max_operations = 4096usize;
            let mut max_visits = 1024usize;
            let mut start_address = None;
            let mut output_path = None;
            let mut options = args[5..].chunks_exact(2);
            for pair in &mut options {
                match pair[0].as_str() {
                    "--start" if start_address.is_none() => {
                        start_address = Some(parse_u64_auto(&pair[1], "P-code start address")?);
                    }
                    "--max-ops" => {
                        max_operations = pair[1].parse()?;
                        if max_operations > 262_144 {
                            return Err(
                                "P-code path operation budget exceeds artifact limit".into()
                            );
                        }
                    }
                    "--max-visits" => {
                        max_visits = pair[1].parse()?;
                        if max_visits > 262_144 {
                            return Err("P-code path visit budget exceeds artifact limit".into());
                        }
                    }
                    "--output" if output_path.is_none() => output_path = Some(pair[1].as_str()),
                    _ => return Err(HELP.into()),
                }
            }
            if !options.remainder().is_empty() {
                return Err(HELP.into());
            }
            let binary = read_binary(&args[2])?;
            let digest = format!("{:x}", sha2::Sha256::digest(&binary));
            let snapshot = parse_ghidra_snapshot(
                &read_bounded_json(&args[3], MAX_GHIDRA_SNAPSHOT_BYTES)?,
                &digest,
            )?;
            let initial = parse_pcode_seed(
                &read_bounded_json(&args[4], MAX_PCODE_SEED_BYTES)?,
                &snapshot,
            )?;
            let start = start_address.map(|address| hydir_ir::pcode::PcodeAddress {
                space: snapshot.selected_function.entry.space.clone(),
                offset: format!("0x{address:x}"),
            });
            let trace = snapshot.execute_concrete_path(
                &initial,
                start.as_ref(),
                max_operations,
                max_visits,
            )?;
            let bytes = serde_json::to_vec_pretty(&trace)?;
            if let Some(path) = output_path {
                write_new_or_identical(path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Some("ghidra-snapshot") if args.len() >= 5 && args[1] == "trace-prefix" => {
            let mut max_operations = 4096usize;
            let mut output_path = None;
            let mut options = args[5..].chunks_exact(2);
            for pair in &mut options {
                match pair[0].as_str() {
                    "--max-ops" => {
                        max_operations = pair[1].parse()?;
                        if max_operations > 262_144 {
                            return Err(
                                "P-code trace operation budget exceeds artifact limit".into()
                            );
                        }
                    }
                    "--output" if output_path.is_none() => output_path = Some(pair[1].as_str()),
                    _ => return Err(HELP.into()),
                }
            }
            if !options.remainder().is_empty() {
                return Err(HELP.into());
            }
            let binary = read_binary(&args[2])?;
            let digest = format!("{:x}", sha2::Sha256::digest(&binary));
            let snapshot = parse_ghidra_snapshot(
                &read_bounded_json(&args[3], MAX_GHIDRA_SNAPSHOT_BYTES)?,
                &digest,
            )?;
            let initial = parse_pcode_seed(
                &read_bounded_json(&args[4], MAX_PCODE_SEED_BYTES)?,
                &snapshot,
            )?;
            let trace = snapshot
                .pcode_function_ir()?
                .execute_exact_prefix(&initial, max_operations)?;
            let bytes = serde_json::to_vec_pretty(&trace)?;
            if let Some(path) = output_path {
                write_new_or_identical(path, &bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
        }
        Some("ghidra-snapshot")
            if (args.len() == 8 || args.len() == 10 && args[8] == "--output")
                && args[1] == "llvm-op"
                && args[4] == "--instruction"
                && args[6] == "--op" =>
        {
            let binary = read_binary(&args[2])?;
            let digest = format!("{:x}", sha2::Sha256::digest(&binary));
            let snapshot = parse_ghidra_snapshot(
                &read_bounded_json(&args[3], MAX_GHIDRA_SNAPSHOT_BYTES)?,
                &digest,
            )?;
            let requested_address = parse_u64_auto(&args[5], "P-code instruction address")?;
            let operation_index = args[7].parse::<usize>()?;
            let semantic = snapshot.pcode_function_ir()?.lower_semantics();
            let mut matches = semantic.instructions.iter().filter(|instruction| {
                parse_u64_auto(&instruction.address.offset, "P-code instruction address").ok()
                    == Some(requested_address)
            });
            let instruction = matches
                .next()
                .ok_or("P-code instruction address is absent from snapshot")?;
            if matches.next().is_some() {
                return Err("P-code instruction address is ambiguous across address spaces".into());
            }
            let operation = instruction
                .operations
                .get(operation_index)
                .ok_or("P-code operation index is absent from instruction")?;
            let llvm = hydir_decompile::emit_pcode_exact_operation_llvm(operation)?;
            if args.len() == 10 {
                write_new_or_identical(&args[9], llvm.as_bytes())?;
            } else {
                print!("{llvm}");
            }
        }
        Some("ghidra")
            if (args.len() == 5 || args.len() == 7 && args[5] == "--function")
                && args[1] == "analyze"
                && args[3] == "--output" =>
        {
            let selected = if args.len() == 7 {
                Some(parse_u64_auto(&args[6], "Ghidra function entry")?)
            } else {
                None
            };
            let snapshot =
                ghidra_worker::analyze(Path::new(&args[2]), selected, Path::new(&args[4]))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "snapshot_path": args[4],
                    "binary_sha256": snapshot.binary_sha256,
                    "functions": snapshot.functions.len(),
                    "selected_function": snapshot.selected_function.entry,
                    "instructions": snapshot.selected_function.instructions.len(),
                    "flow_edges": snapshot.selected_function.flow_edges.len(),
                    "call_targets": snapshot.selected_function.call_targets.len(),
                }))?
            );
        }
        Some("ghidra-snapshot")
            if (args.len() == 4 || args.len() == 6 && args[4] == "--output")
                && matches!(
                    args[1].as_str(),
                    "verify"
                        | "pcode"
                        | "semantics"
                        | "state"
                        | "cfg"
                        | "llvm-prefix"
                        | "llvm-standalone"
                ) =>
        {
            if args[1] == "verify" && args.len() != 4 {
                return Err(HELP.into());
            }
            let binary = read_binary(&args[2])?;
            let digest = format!("{:x}", sha2::Sha256::digest(&binary));
            let snapshot = parse_ghidra_snapshot(
                &read_bounded_json(&args[3], MAX_GHIDRA_SNAPSHOT_BYTES)?,
                &digest,
            )?;
            let ir = snapshot.pcode_function_ir()?;
            if args[1] == "verify" {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "schema_version": snapshot.schema_version,
                        "binary_sha256": snapshot.binary_sha256,
                        "program": snapshot.program.name,
                        "language_id": snapshot.program.language_id,
                        "functions": snapshot.functions.len(),
                        "selected_function": ir.entry,
                        "instructions": ir.instructions.len(),
                        "pcode_operations": ir.instructions.iter().map(|instruction| instruction.pcode.len()).sum::<usize>(),
                        "flow_edges": snapshot.selected_function.flow_edges.len(),
                        "call_targets": snapshot.selected_function.call_targets.len(),
                        "semantic_fidelity": ir.semantic_fidelity,
                    }))?
                );
            } else {
                let output = match args[1].as_str() {
                    "semantics" => serde_json::to_vec_pretty(&ir.lower_semantics())?,
                    "state" => serde_json::to_vec_pretty(&ir.lower_state())?,
                    "cfg" => serde_json::to_vec_pretty(&snapshot.pcode_cfg_ir()?)?,
                    "llvm-prefix" => serde_json::to_vec_pretty(
                        &hydir_decompile::emit_pcode_linear_prefix_llvm(&snapshot)?,
                    )?,
                    "llvm-standalone" => serde_json::to_vec_pretty(
                        &hydir_decompile::emit_pcode_standalone_prefix_llvm(&snapshot)?,
                    )?,
                    _ => serde_json::to_vec_pretty(&ir)?,
                };
                if args.len() == 6 {
                    write_new_or_identical(&args[5], &output)?;
                } else {
                    println!("{}", String::from_utf8(output)?);
                }
            }
        }
        Some("capture")
            if (args.len() == 5 || args.len() == 7 && args[5] == "--output")
                && matches!(args[3].as_str(), "--function" | "--address") =>
        {
            let bytes = read_binary(&args[1])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[2],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            validate_input_spec(&bytes, &spec)?;
            let address = if args[3] == "--address" {
                Some(parse_u64_auto(&args[4], "ELF virtual address")?)
            } else {
                None
            };
            #[cfg(target_os = "linux")]
            let snapshot = if let Some(address) = address {
                hydir_execution::capture_elf_address(&bytes, &spec, address)?
            } else {
                hydir_execution::capture_function_entry(&bytes, &spec, &args[4])?
            };
            #[cfg(not(target_os = "linux"))]
            let _ = address;
            #[cfg(not(target_os = "linux"))]
            let snapshot = hydir_execution::ExecutionSnapshot {
                schema_version: hydir_execution::EXECUTION_SNAPSHOT_VERSION,
                binary_sha256: spec.binary_sha256.clone(),
                input_sha256: hydir_execution::input_sha256(&spec)?,
                status: hydir_execution::SnapshotStatus::UnsupportedHost,
                stop: None,
                thread_id: None,
                thread_count: 0,
                registers: Default::default(),
                mappings: Vec::new(),
                pages: Vec::new(),
                runner: "unavailable".into(),
                diagnostics: vec![
                    "native capture currently requires Linux, Bubblewrap, and GDB".into(),
                ],
            };
            validate_execution_snapshot(&bytes, &spec, &snapshot)?;
            let json = serde_json::to_vec_pretty(&snapshot)?;
            if args.len() == 7 {
                write_new_or_identical(&args[6], &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("snapshot")
            if args.get(1).map(String::as_str) == Some("probe-origin")
                && (args.len() == 8 || args.len() == 10 && args[8] == "--output")
                && args[6] == "--register" =>
        {
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            let snapshot = parse_execution_snapshot(&read_bounded_json(
                &args[4],
                hydir_execution::MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
            )?)?;
            let report = probe_origin(
                &bytes,
                &spec,
                &snapshot,
                &args[5],
                ProbeLocation::Register {
                    name: args[7].clone(),
                    offset: 0,
                },
            )?;
            let json = serde_json::to_vec_pretty(&report)?;
            if args.len() == 10 {
                write_new_or_identical(&args[9], &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("snapshot")
            if args.get(1).map(String::as_str) == Some("verify-origin") && args.len() == 6 =>
        {
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            let snapshot = parse_execution_snapshot(&read_bounded_json(
                &args[4],
                hydir_execution::MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
            )?)?;
            let report = parse_origin_probe(&read_bounded_json(
                &args[5],
                hydir_execution::MAX_ORIGIN_PROBE_JSON_BYTES,
            )?)?;
            validate_origin_probe(&bytes, &spec, &snapshot, &report)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema_version": report.schema_version,
                    "valid": true,
                    "origin_id": report.origin_id,
                    "status": report.status,
                    "evidence": report.evidence,
                    "runtime_address": report.runtime_address,
                }))?
            );
        }
        Some("snapshot")
            if args.get(1).map(String::as_str) == Some("plan-return")
                && (args.len() == 10 || args.len() == 12 && args[10] == "--output")
                && args[6] == "--code-bytes"
                && args[8] == "--return" =>
        {
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            let snapshot = parse_execution_snapshot(&read_bounded_json(
                &args[4],
                hydir_execution::MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
            )?)?;
            let probe = parse_origin_probe(&read_bounded_json(
                &args[5],
                hydir_execution::MAX_ORIGIN_PROBE_JSON_BYTES,
            )?)?;
            let code_bytes = args[7].parse::<usize>()?;
            let return_equals = parse_u64_auto(&args[9], "return value")?;
            let plan = build_snapshot_resume_plan(
                &bytes,
                &spec,
                &snapshot,
                &probe,
                code_bytes,
                return_equals,
            )?;
            let json = serde_json::to_vec_pretty(&plan)?;
            if args.len() == 12 {
                write_new_or_identical(&args[11], &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("snapshot")
            if args.get(1).map(String::as_str) == Some("verify-plan") && args.len() == 7 =>
        {
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            let snapshot = parse_execution_snapshot(&read_bounded_json(
                &args[4],
                hydir_execution::MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
            )?)?;
            let probe = parse_origin_probe(&read_bounded_json(
                &args[5],
                hydir_execution::MAX_ORIGIN_PROBE_JSON_BYTES,
            )?)?;
            let plan = parse_snapshot_resume_plan(&read_bounded_json(
                &args[6],
                hydir_execution::MAX_SNAPSHOT_RESUME_JSON_BYTES,
            )?)?;
            validate_snapshot_resume_plan(&bytes, &spec, &snapshot, &probe, &plan)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema_version": plan.schema_version,
                    "valid": true,
                    "operation": plan.operation,
                    "binary_sha256": plan.binary_sha256,
                    "snapshot_sha256": plan.snapshot_sha256,
                    "origin_id": plan.symbolic_origin.id,
                    "code_bytes": plan.code_hex.len() / 2,
                    "present_pages": plan.pages.len(),
                }))?
            );
        }
        Some("snapshot")
            if args.get(1).map(String::as_str) == Some("verify") && args.len() == 5 =>
        {
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            let snapshot = parse_execution_snapshot(&read_bounded_json(
                &args[4],
                hydir_execution::MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
            )?)?;
            validate_execution_snapshot(&bytes, &spec, &snapshot)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema_version": snapshot.schema_version,
                    "valid": true,
                    "status": snapshot.status,
                    "binary_sha256": snapshot.binary_sha256,
                    "input_sha256": snapshot.input_sha256,
                    "thread_count": snapshot.thread_count,
                    "mappings": snapshot.mappings.len(),
                    "present_pages": snapshot.pages.iter().filter(|page| matches!(page.value, hydir_execution::MemoryPageState::Present { .. })).count(),
                    "unavailable_pages": snapshot.pages.iter().filter(|page| matches!(page.value, hydir_execution::MemoryPageState::Unavailable { .. })).count(),
                    "stop": snapshot.stop,
                }))?
            );
        }
        Some("solve")
            if args.get(1).map(String::as_str) == Some("snapshot-return")
                && (7..=17).contains(&args.len())
                && args.len() % 2 == 1 =>
        {
            let mut candidate_output = None;
            let mut slice_output = None;
            let mut claim_output = None;
            let mut recipe_output = None;
            let mut report_output = None;
            for pair in args[7..].chunks_exact(2) {
                match pair[0].as_str() {
                    "--candidate-output" if candidate_output.is_none() => {
                        candidate_output = Some(pair[1].as_str());
                    }
                    "--slice-output" if slice_output.is_none() => {
                        slice_output = Some(pair[1].as_str());
                    }
                    "--claim-output" if claim_output.is_none() => {
                        claim_output = Some(pair[1].as_str());
                    }
                    "--recipe-output" if recipe_output.is_none() => {
                        recipe_output = Some(pair[1].as_str());
                    }
                    "--output" if report_output.is_none() => {
                        report_output = Some(pair[1].as_str());
                    }
                    _ => return Err(HELP.into()),
                }
            }
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            let snapshot = parse_execution_snapshot(&read_bounded_json(
                &args[4],
                hydir_execution::MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
            )?)?;
            let probe = parse_origin_probe(&read_bounded_json(
                &args[5],
                hydir_execution::MAX_ORIGIN_PROBE_JSON_BYTES,
            )?)?;
            let plan = parse_snapshot_resume_plan(&read_bounded_json(
                &args[6],
                hydir_execution::MAX_SNAPSHOT_RESUME_JSON_BYTES,
            )?)?;
            validate_snapshot_resume_plan(&bytes, &spec, &snapshot, &probe, &plan)?;
            let request = serde_json::to_value(&plan)?;
            let bridge = run_triton_bridge(&request)?;
            validate_snapshot_bridge_result(&plan, &bridge)?;
            if let Some(path) = slice_output {
                if bridge["input_condition_slice"].is_null() {
                    return Err("no completed failing seed trace is available for a slice".into());
                }
                write_new_or_identical(
                    path,
                    &serde_json::to_vec_pretty(&bridge["input_condition_slice"])?,
                )?;
            }
            let mut claim = "no_function_witness";
            let mut candidate_spec = None;
            let mut native_replay = None;
            if let Some(candidate_hex) = bridge["candidate_hex"].as_str() {
                let candidate = input_with_origin_candidate(
                    &bytes,
                    &spec,
                    &plan.symbolic_origin.id,
                    candidate_hex,
                )?;
                if let Some(path) = candidate_output {
                    write_new_or_identical(path, &serde_json::to_vec_pretty(&candidate)?)?;
                }
                #[cfg(target_os = "linux")]
                let replay = hydir_execution::replay_local(&bytes, &candidate)?;
                #[cfg(not(target_os = "linux"))]
                let replay = hydir_execution::NativeReplayReport {
                    schema_version: hydir_execution::NATIVE_REPLAY_REPORT_VERSION,
                    binary_sha256: candidate.binary_sha256.clone(),
                    input_sha256: hydir_execution::input_sha256(&candidate)?,
                    status: hydir_execution::ReplayStatus::UnsupportedHost,
                    exit_code: None,
                    signal: None,
                    stdout_hex: String::new(),
                    stderr_hex: String::new(),
                    elapsed_ms: 0,
                    runner: "unavailable".into(),
                    diagnostic: Some("native replay requires Linux with Bubblewrap".into()),
                };
                hydir_execution::validate_replay_report(&bytes, &candidate, &replay)?;
                claim = if replay.status == hydir_execution::ReplayStatus::GoalMatched {
                    "native_validated_candidate"
                } else {
                    "function_witness"
                };
                candidate_spec = Some(candidate);
                native_replay = Some(replay);
            }
            #[cfg(target_os = "linux")]
            let original_replay = if native_replay
                .as_ref()
                .is_some_and(|replay| replay.status == hydir_execution::ReplayStatus::GoalMatched)
                && !bridge["input_condition_slice"].is_null()
            {
                let observed = hydir_execution::replay_local(&bytes, &spec)?;
                hydir_execution::validate_replay_report(&bytes, &spec, &observed)?;
                Some(observed)
            } else {
                None
            };
            #[cfg(not(target_os = "linux"))]
            let original_replay: Option<hydir_execution::NativeReplayReport> = None;
            let recipe = match (&candidate_spec, &native_replay, &original_replay) {
                (Some(candidate), Some(replay), Some(original))
                    if replay.status == hydir_execution::ReplayStatus::GoalMatched
                        && original.status == hydir_execution::ReplayStatus::GoalMismatched
                        && !bridge["input_condition_slice"].is_null()
                        && hydir_execution::candidate_links_failed_trace(&plan, &bridge) =>
                {
                    Some(hydir_execution::build_analysis_recipe(
                        &bytes, &spec, &snapshot, &probe, &plan, &bridge, candidate, original,
                        replay,
                    )?)
                }
                _ => None,
            };
            if let Some(path) = claim_output {
                let claim = &recipe
                    .as_ref()
                    .ok_or("no native-validated failing-seed claim is available")?
                    .claim;
                write_new_or_identical(path, &serde_json::to_vec_pretty(claim)?)?;
            }
            if let Some(path) = recipe_output {
                let recipe = recipe
                    .as_ref()
                    .ok_or("no native-validated failing-seed recipe is available")?;
                write_new_or_identical(path, &serde_json::to_vec_pretty(recipe)?)?;
            }
            let report = json!({
                "schema_version": 1,
                "operation": "snapshot_return",
                "claim": claim,
                "binary_sha256": plan.binary_sha256,
                "input_sha256": plan.input_sha256,
                "snapshot_sha256": plan.snapshot_sha256,
                "probe_sha256": plan.probe_sha256,
                "origin_probe_evidence": plan.origin_probe_evidence,
                "assumptions": plan.assumptions,
                "bridge": bridge,
                "candidate_input": candidate_spec,
                "original_replay": original_replay,
                "native_replay": native_replay,
                "investigation_claim": recipe.as_ref().map(|recipe| &recipe.claim),
            });
            let json = serde_json::to_vec_pretty(&report)?;
            if let Some(path) = report_output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("recipe")
            if matches!(args.get(1).map(String::as_str), Some("verify" | "replay"))
                && (args.len() == 4 || args.len() == 6 && args[4] == "--output") =>
        {
            let bytes = read_binary(&args[2])?;
            let recipe = hydir_execution::parse_analysis_recipe(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_ANALYSIS_RECIPE_JSON_BYTES,
            )?)?;
            hydir_execution::validate_analysis_recipe(&bytes, &recipe)?;
            let result = if args[1] == "verify" {
                json!({
                    "schema_version": 1,
                    "operation": "recipe_verify",
                    "valid": true,
                    "claim": recipe.claim,
                    "verification_scope": "recorded_artifact_consistency_only",
                    "fresh_original_replay": null,
                    "fresh_candidate_replay": null,
                })
            } else {
                #[cfg(target_os = "linux")]
                let original = hydir_execution::replay_local(&bytes, &recipe.original_input)?;
                #[cfg(target_os = "linux")]
                let replay = hydir_execution::replay_local(&bytes, &recipe.candidate_input)?;
                #[cfg(not(target_os = "linux"))]
                let original = hydir_execution::NativeReplayReport {
                    schema_version: hydir_execution::NATIVE_REPLAY_REPORT_VERSION,
                    binary_sha256: recipe.original_input.binary_sha256.clone(),
                    input_sha256: hydir_execution::input_sha256(&recipe.original_input)?,
                    status: hydir_execution::ReplayStatus::UnsupportedHost,
                    exit_code: None,
                    signal: None,
                    stdout_hex: String::new(),
                    stderr_hex: String::new(),
                    elapsed_ms: 0,
                    runner: "unavailable".into(),
                    diagnostic: Some("recipe replay requires Linux with Bubblewrap".into()),
                };
                #[cfg(not(target_os = "linux"))]
                let replay = hydir_execution::NativeReplayReport {
                    schema_version: hydir_execution::NATIVE_REPLAY_REPORT_VERSION,
                    binary_sha256: recipe.candidate_input.binary_sha256.clone(),
                    input_sha256: hydir_execution::input_sha256(&recipe.candidate_input)?,
                    status: hydir_execution::ReplayStatus::UnsupportedHost,
                    exit_code: None,
                    signal: None,
                    stdout_hex: String::new(),
                    stderr_hex: String::new(),
                    elapsed_ms: 0,
                    runner: "unavailable".into(),
                    diagnostic: Some("recipe replay requires Linux with Bubblewrap".into()),
                };
                hydir_execution::validate_replay_report(&bytes, &recipe.original_input, &original)?;
                hydir_execution::validate_replay_report(&bytes, &recipe.candidate_input, &replay)?;
                json!({
                    "schema_version": 1,
                    "operation": "recipe_replay",
                    "claim_reproduced": original.status == hydir_execution::ReplayStatus::GoalMismatched
                        && replay.status == hydir_execution::ReplayStatus::GoalMatched,
                    "recorded_original_replay": recipe.recorded_original_replay,
                    "recorded_candidate_replay": recipe.recorded_native_replay,
                    "fresh_original_replay": original,
                    "fresh_candidate_replay": replay,
                    "claim": recipe.claim,
                })
            };
            let output = serde_json::to_vec_pretty(&result)?;
            if args.len() == 6 {
                write_new_or_identical(&args[5], &output)?;
            } else {
                std::io::stdout().write_all(&output)?;
                println!();
            }
        }
        Some("replay")
            if !matches!(args.get(1).map(String::as_str), Some("init" | "verify"))
                && (args.len() == 3 || args.len() == 5 && args[3] == "--output") =>
        {
            let bytes = read_binary(&args[1])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[2],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            validate_input_spec(&bytes, &spec)?;
            #[cfg(target_os = "linux")]
            let report = hydir_execution::replay_local(&bytes, &spec)?;
            #[cfg(not(target_os = "linux"))]
            let report = hydir_execution::NativeReplayReport {
                schema_version: hydir_execution::NATIVE_REPLAY_REPORT_VERSION,
                binary_sha256: spec.binary_sha256.clone(),
                input_sha256: hydir_execution::input_sha256(&spec)?,
                status: hydir_execution::ReplayStatus::UnsupportedHost,
                exit_code: None,
                signal: None,
                stdout_hex: String::new(),
                stderr_hex: String::new(),
                elapsed_ms: 0,
                runner: "unavailable".into(),
                diagnostic: Some("native replay currently requires Linux with Bubblewrap".into()),
            };
            hydir_execution::validate_replay_report(&bytes, &spec, &report)?;
            let json = serde_json::to_vec_pretty(&report)?;
            if args.len() == 5 {
                write_new_or_identical(&args[4], &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("replay")
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
            let spec = InputSpec {
                schema_version: hydir_execution::INPUT_SPEC_VERSION,
                binary_sha256: format!("{:x}", sha2::Sha256::digest(&bytes)),
                argv_hex: Vec::new(),
                stdin_hex: String::new(),
                files: Vec::new(),
                origins: Vec::new(),
                goal: ReplayGoal {
                    exit_code: Some(0),
                    stdout_contains_hex: None,
                    stderr_contains_hex: None,
                },
                budget: ReplayBudget {
                    timeout_ms: 5000,
                    memory_bytes: 256 * 1024 * 1024,
                    output_bytes: 64 * 1024,
                },
            };
            validate_input_spec(&bytes, &spec)?;
            let json = serde_json::to_vec_pretty(&spec)?;
            if let Some(path) = output {
                write_new_or_identical(path, &json)?;
            } else {
                std::io::stdout().write_all(&json)?;
                println!();
            }
        }
        Some("replay") if args.get(1).map(String::as_str) == Some("verify") && args.len() == 4 => {
            let bytes = read_binary(&args[2])?;
            let spec = parse_input_spec(&read_bounded_json(
                &args[3],
                hydir_execution::MAX_INPUT_SPEC_BYTES,
            )?)?;
            validate_input_spec(&bytes, &spec)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "schema_version": 1,
                    "valid": true,
                    "binary_sha256": spec.binary_sha256,
                    "input_sha256": hydir_execution::input_sha256(&spec)?,
                    "argv": spec.argv_hex.len(),
                    "files": spec.files.len(),
                    "origins": spec.origins.len(),
                }))?
            );
        }
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
            let gdb_version = Command::new("gdb")
                .arg("--version")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.lines().next().map(str::to_owned));
            let bwrap_version = Command::new("bwrap")
                .arg("--version")
                .output()
                .ok()
                .filter(|output| output.status.success())
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .and_then(|value| value.lines().next().map(str::to_owned));
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
            let bubblewrap_isolation_ready =
                bwrap_version.is_some() && probe_bubblewrap_isolation();
            let replay_ready = bubblewrap_isolation_ready;
            let capture_ready = replay_ready && gdb_version.is_some();
            let snapshot_solve_ready =
                capture_ready && triton_helper_available && triton_module_version.is_some();
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
                    "expression_ir_scope": "supported scalar writes, condition flags/predicates, little-endian MOV loads/stores with complete alias-region dependencies, 64/32-bit LEA, and component SSA joins; unsupported effects remain residual",
                    "typed_c_v1": true,
                    "typed_c_scope": "v1: complete linear functions with supported 64-bit operations, fixed frame spills, aggregate fields, and bounded fixed direct calls; v3 CFG: supported 64-bit scalar branches, joins and loops, normalized MOV memory effects, LEA, model-backed fields and arrays, with goto fallback; unsupported functions retain low-level C",
                    "typed_cfg_v2": false,
                    "typed_cfg_v3": true,
                    "typed_c_local_cache": true,
                    "execution_snapshot_v1": capture_ready,
                    "execution_snapshot_schema_v1": true,
                    "gdb_mi_parser_v1": true,
                    "gdb_mi_parser_scope": "bounded result, async, and stream records with nested tuples/lists and C-style escaped bytes; named and stripped PIE address capture passed the Ubuntu 24.04 semantic gate",
                    "gdb_capture_v1": capture_ready,
                    "gdb_capture_scope": "experimental single-thread x86-64 ELF capture at a named function or relocated file-backed address; up to eight selected pages; missing state and runner failures remain explicit",
                    "input_spec_v1": true,
                    "origin_probe_v1": true,
                    "origin_probe_scope": "analyst-selected captured register versus input-origin bytes; exact snapshot-bound byte equality only, not channel provenance",
                    "snapshot_resume_plan_v1": true,
                    "snapshot_resume_scope": "exact digest-bound snapshot/probe/code/page/register handoff for up to 32 original bytes and a selected 4096-byte pure validator; one captured-state solve and native replay passed the Ubuntu 24.04 semantic gate",
                    "snapshot_return_solve_v1": snapshot_solve_ready,
                    "snapshot_return_solve_scope": "experimental pure validator return goal from matched captured origin bytes; bounded seeds, instructions, solver queries and wall time; a function witness is not a native success until fresh replay matches",
                    "native_replay_v1": replay_ready,
                    "native_replay_scope": "local Linux x86-64 Bubblewrap replay with private network namespace, bounded argv/stdin/files, exact exit/output goals and explicit setup/timeout/output-limit failures; Ubuntu 24.04 smoke gate passed",
                    "bubblewrap_installed": bwrap_version.is_some(),
                    "bubblewrap_isolation_ready": bubblewrap_isolation_ready,
                    "bubblewrap_version": bwrap_version,
                    "gdb_installed": gdb_version.is_some(),
                    "gdb_version": gdb_version,
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
                && matches!(args[5].as_str(), "high-level" | "high-level-cfg")
                && args[6] == "--model" =>
        {
            let bytes = read_binary(&args[1])?;
            let model = parse_model(&fs::read(&args[7])?)?;
            validate_model(&bytes, &model)?;
            let selection = resolve_native_function(&bytes, &args[3])?;
            let native = decompile_native_selection(&bytes, &selection)?;
            if args[5] == "high-level-cfg" {
                let ir = lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)?;
                println!("{}", serde_json::to_string_pretty(&ir)?);
            } else {
                let ir = lower_high_level_cir(&native.machine_ir, &native.function_ir, &model)?;
                println!("{}", serde_json::to_string_pretty(&ir)?);
            }
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
            match lower_high_level_cir(&native.machine_ir, &native.function_ir, &model) {
                Ok(ir) => print!("{}", emit_typed_c(&ir, &model)?),
                Err(linear_error) => {
                    let ir =
                        lower_high_level_cfg_cir(&native.machine_ir, &native.function_ir, &model)
                            .map_err(|cfg_error| {
                            format!("typed C unavailable: linear: {linear_error}; CFG: {cfg_error}")
                        })?;
                    print!("{}", emit_typed_cfg_c(&ir, &model)?);
                }
            }
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

fn read_bounded_json(path: impl AsRef<Path>, limit: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err("JSON artifact exceeds size limit".into());
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
    use hydir_execution::{candidate_links_failed_trace, validate_input_condition_slice};
    use sha2::Digest;

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

    #[test]
    fn input_condition_slice_rejects_changed_identity_and_origin_range() {
        let plan = hydir_execution::SnapshotResumePlan {
            schema_version: 1,
            operation: "snapshot_return".into(),
            binary_sha256: "0".repeat(64),
            input_sha256: "1".repeat(64),
            snapshot_sha256: "2".repeat(64),
            probe_sha256: "3".repeat(64),
            code_address: 0x1000,
            code_hex: "c3".into(),
            registers: Default::default(),
            pages: vec![],
            symbolic_origin: hydir_execution::InputOrigin {
                id: "byte0".into(),
                channel: hydir_execution::InputChannel::Stdin,
                offset: 0,
                length: 1,
                encoding: hydir_execution::InputEncoding::Raw,
                alphabet_hex: String::new(),
            },
            origin_address: 0x2000,
            seed_hex: "42".into(),
            origin_probe_evidence: hydir_execution::ProbeEvidence::ByteEqualityOnly,
            assumptions: vec![],
            return_equals: 1,
            max_seeds: 4,
            max_instructions_per_seed: 8,
            max_solver_queries: 4,
            wall_timeout_ms: 1000,
            solver_timeout_ms: 100,
        };
        let mut slice = serde_json::json!({
            "schema_version": 1,
            "kind": "input_condition_slice",
            "scope": "captured_seed_trace_structural_dependencies",
            "binary_sha256": plan.binary_sha256,
            "input_sha256": plan.input_sha256,
            "snapshot_sha256": plan.snapshot_sha256,
            "probe_sha256": plan.probe_sha256,
            "code_sha256": format!("{:x}", sha2::Sha256::digest([0xc3])),
            "code_address": 0x1000,
            "origin_id": "byte0",
            "channel": {"kind": "stdin"},
            "channel_offset": 0,
            "seed_hex": "42",
            "observed_return": 0,
            "return_equals": 1,
            "ast_walk_complete": true,
            "relevant_origin_offsets": [0],
            "source_occurrences": [],
            "instructions": [{"index": 0, "address": 0x1000,
                              "code_offset": 0, "disassembly": "ret"}],
            "decisions": [{"kind": "return", "occurrence": 0,
                           "address": 0x1000, "observed_value": 0,
                           "origin_offsets": [0], "source_occurrences": []}],
            "unresolved_dependencies": [
                "origin_channel_provenance_unproven_byte_equality_only",
                "other_paths_and_environment_not_in_this_trace",
                "symbolic_memory_address_dependencies_not_analyzed"
            ]
        });
        validate_input_condition_slice(&plan, &slice).unwrap();
        slice["decisions"][0]["origin_offsets"] = serde_json::json!([1]);
        assert!(validate_input_condition_slice(&plan, &slice).is_err());
        slice["decisions"][0]["origin_offsets"] = serde_json::json!([0]);
        slice["code_sha256"] = serde_json::json!("4".repeat(64));
        assert!(validate_input_condition_slice(&plan, &slice).is_err());
        slice["code_sha256"] = serde_json::json!(format!("{:x}", sha2::Sha256::digest([0xc3])));
        slice["ast_walk_complete"] = serde_json::json!(false);
        assert!(validate_input_condition_slice(&plan, &slice).is_err());

        let mut bridge = serde_json::json!({
            "candidate_hex": "41",
            "input_condition_slice": {"relevant_origin_offsets": [0]}
        });
        assert!(candidate_links_failed_trace(&plan, &bridge));
        bridge["input_condition_slice"]["relevant_origin_offsets"] = serde_json::json!([]);
        assert!(!candidate_links_failed_trace(&plan, &bridge));
    }
}
