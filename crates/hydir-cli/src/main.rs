use hydir_analysis::{analyze_elf, analyze_spec_elf};
use hydir_backend::{
    MAX_BINARY_BYTES, import_elf, lift_at, lift_symbol, recover_at_cfg, recover_symbol_cfg,
};
use hydir_c::emit_c;
mod local;
mod passes;
mod patch;
use hydir_recompile as recompile;
mod remote;
use serde_json::json;
use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Output},
};

const HELP: &str = "HydIR native x86-64 ELF vertical slice

Usage:
  hydirctl doctor
  hydirctl inspect <elf>
  hydirctl analyze <linked-elf>
  hydirctl analyze-spec <linked-elf>
  hydirctl cfg <elf> <function-symbol>
  hydirctl cfg-at <linked-elf> <virtual-address-hex> <size-bytes>
  hydirctl lift <elf> <function-symbol> --assume-u64x2 [--output <file.ll>]
  hydirctl lift-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 [--output <file.ll>]
  hydirctl decompile <elf> <function-symbol> --assume-u64x2 [--output <file.c>]
  hydirctl decompile-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 [--output <file.c>]
  hydirctl patch <linked-elf> <patch-v1.json> --trusted-fixture --assume-u64x2 --assume-entry-only --output <new.elf>
  hydirctl transform <elf> <function-symbol> --assume-u64x2 --trusted-fixture --passes <comma-list> --output-dir <new-directory> [--opt <path>]
  hydirctl rebuild <linked-elf> --trusted-fixture --output-dir <new-directory> [--clang <path>]
  hydirctl validate <elf> <function-symbol> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>]
  hydirctl validate-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>]
  hydirctl validate-c <elf> <function-symbol> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>]
  hydirctl validate-c-at <linked-elf> <virtual-address-hex> <size-bytes> --assume-u64x2 --trusted-fixture [--clang <path>] [--random-cases <n>]
  hydirctl local <project|inspect|analyze-spec|annotations> <elf> [--db <private-sqlite>]
  hydirctl local annotate <elf> <revision> <idempotency-key> <name|comment|assumption> <hex-address|-> <scope> <value> [--db <private-sqlite>]
  hydirctl remote <operation> ...

Symbol mode requires a non-stripped function symbol. Address mode requires an
analyst-supplied virtual entry and exact byte extent, and works on stripped
linked ELF files. --assume-u64x2 explicitly
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

fn main() {
    if let Err(err) = run() {
        eprintln!("hydirctl: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(String::as_str) {
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
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "hydir_version": env!("CARGO_PKG_VERSION"),
                    "license": env!("CARGO_PKG_LICENSE"),
                    "host": format!("{}-{}", env::consts::ARCH, env::consts::OS),
                    "elf_parser": "object 0.39.1 (Cargo.lock)",
                    "decoder": "iced-x86 1.21.0 (Cargo.lock)",
                    "native_elf_import": true,
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
        Some("cfg") if args.len() == 3 => {
            let bytes = read_binary(&args[1])?;
            let cfg = recover_symbol_cfg(&bytes, &args[2])?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
        }
        Some("cfg-at") if args.len() == 4 => {
            let bytes = read_binary(&args[1])?;
            let (address, size) = parse_address_extent(&args[2], &args[3])?;
            let cfg = recover_at_cfg(&bytes, address, size)?;
            println!("{}", serde_json::to_string_pretty(&cfg)?);
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
            let c = emit_c(&lift_symbol(&bytes, &args[2])?)?;
            if let Some(path) = output {
                write_new_or_identical(path, c.as_bytes())?;
            } else {
                print!("{c}");
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
            let c = emit_c(&lift_at(&bytes, address, size)?)?;
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
    let ir = if let Some((address, size)) = address_extent {
        lift_at(&bytes, address, size)?
    } else {
        lift_symbol(&bytes, &args[1])?
    };
    let directory = tempfile::tempdir()?;
    let ir_path = directory.path().join("lifted.ll");
    let c_path = directory.path().join("lifted.c");
    let harness_path = directory.path().join("harness.c");
    let lifted_path = directory.path().join("lifted-runner");
    let source_path = if c_backend {
        fs::write(&c_path, emit_c(&ir)?)?;
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
        "seed": format!("0x{seed:016x}"),
        "cases_attempted": cases.len(),
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
extern uint64_t hydir_lifted(uint64_t, uint64_t);
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    uint64_t a = strtoull(argv[1], 0, 10);
    uint64_t b = strtoull(argv[2], 0, 10);
    printf("%llu\n", (unsigned long long)hydir_lifted(a, b));
    return 0;
}
"#;
