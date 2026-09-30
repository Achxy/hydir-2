//! CLI orchestration for bounded calls across analyzed Ghidra functions.

use super::{read_binary, read_bounded_json, write_new_or_identical};
use hydir_ghidra_worker as ghidra_worker;
use hydir_ir::pcode::{
    GhidraSnapshot, MAX_GHIDRA_SNAPSHOT_BYTES, MAX_PCODE_PROCESS_ALLOCATIONS_JSON_BYTES,
    MAX_PCODE_SEED_BYTES, PCODE_ELF_PROCESS_MEMORY_MAX_BYTES, PcodeElfProcessMemory,
    PcodeProcessAllocations, execute_concrete_call_path,
    execute_concrete_call_path_with_allocations, execute_concrete_call_path_with_image,
    execute_concrete_call_path_with_imports, parse_ghidra_snapshot, parse_pcode_seed,
    unloaded_call_target,
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, error::Error, path::Path};

const MAX_FUNCTIONS: usize = 32;
const MAX_OPERATIONS: usize = 262_144;
const MAX_DEPTH: usize = 16;

struct Options<'a> {
    function: Option<u64>,
    callees: Vec<&'a str>,
    max_functions: usize,
    max_operations: usize,
    max_visits: usize,
    max_depth: usize,
    output: Option<&'a str>,
    allocations: Option<&'a str>,
}

fn parse_options<'a>(args: &'a [String], automatic: bool) -> Result<Options<'a>, Box<dyn Error>> {
    let mut options = Options {
        function: None,
        callees: Vec::new(),
        max_functions: 8,
        max_operations: 4096,
        max_visits: 1024,
        max_depth: 8,
        output: None,
        allocations: None,
    };
    let mut pairs = args.chunks_exact(2);
    for pair in &mut pairs {
        match pair[0].as_str() {
            "--function" if automatic && options.function.is_none() => {
                options.function = Some(super::parse_u64_auto(&pair[1], "Ghidra function entry")?);
            }
            "--callee" if !automatic => options.callees.push(&pair[1]),
            "--max-functions" if automatic => options.max_functions = pair[1].parse()?,
            "--max-ops" => options.max_operations = pair[1].parse()?,
            "--max-visits" => options.max_visits = pair[1].parse()?,
            "--max-depth" => options.max_depth = pair[1].parse()?,
            "--output" if options.output.is_none() => options.output = Some(&pair[1]),
            "--allocations" if options.allocations.is_none() => {
                options.allocations = Some(&pair[1]);
            }
            _ => return Err("invalid Ghidra call-path option".into()),
        }
    }
    if !pairs.remainder().is_empty() || automatic && options.function.is_none() {
        return Err("Ghidra call path requires --function and option/value pairs".into());
    }
    if !(1..=MAX_FUNCTIONS).contains(&options.max_functions)
        || options.max_operations > MAX_OPERATIONS
        || options.max_visits > MAX_OPERATIONS
        || options.max_depth > MAX_DEPTH
        || options.callees.len() >= MAX_FUNCTIONS
    {
        return Err("Ghidra call-path budget exceeds artifact limit".into());
    }
    Ok(options)
}

fn strict_allocations(
    snapshots: &[GhidraSnapshot],
    binary: &[u8],
    path: &str,
) -> Result<(PcodeElfProcessMemory, PcodeProcessAllocations), Box<dyn Error>> {
    let snapshot = snapshots.first().ok_or("missing root Ghidra snapshot")?;
    let process =
        PcodeElfProcessMemory::from_elf(binary, snapshot, PCODE_ELF_PROCESS_MEMORY_MAX_BYTES)?;
    let allocations = PcodeProcessAllocations::parse_declared(
        &read_bounded_json(path, MAX_PCODE_PROCESS_ALLOCATIONS_JSON_BYTES)?,
        snapshot,
        &process,
    )?;
    Ok((process, allocations))
}

fn emit(
    snapshots: &[GhidraSnapshot],
    binary: &[u8],
    seed_path: &str,
    options: &Options<'_>,
    diagnostics: Vec<String>,
    with_imports: bool,
) -> Result<(), Box<dyn Error>> {
    if with_imports && options.allocations.is_none() {
        return Err("checked import calls require --allocations".into());
    }
    let seed = parse_pcode_seed(
        &read_bounded_json(seed_path, MAX_PCODE_SEED_BYTES)?,
        &snapshots[0],
    )?;
    let image = if options.allocations.is_none() {
        super::pcode_image_or_legacy(binary, &snapshots[0])?
    } else {
        None
    };
    let mut trace = if let Some(path) = options.allocations {
        let (process, allocations) = strict_allocations(snapshots, binary, path)?;
        if with_imports {
            execute_concrete_call_path_with_imports(
                snapshots,
                &seed,
                binary,
                &process,
                &allocations,
                options.max_operations,
                options.max_visits,
                options.max_depth,
            )?
        } else {
            execute_concrete_call_path_with_allocations(
                snapshots,
                &seed,
                &process,
                &allocations,
                options.max_operations,
                options.max_visits,
                options.max_depth,
            )?
        }
    } else if let Some(image) = &image {
        execute_concrete_call_path_with_image(
            snapshots,
            &seed,
            image,
            options.max_operations,
            options.max_visits,
            options.max_depth,
        )?
    } else {
        execute_concrete_call_path(
            snapshots,
            &seed,
            options.max_operations,
            options.max_visits,
            options.max_depth,
        )?
    };
    trace.snapshot_diagnostics = diagnostics;
    let bytes = serde_json::to_vec_pretty(&trace)?;
    if let Some(path) = options.output {
        write_new_or_identical(path, &bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

fn emit_assessment(
    snapshots: &[GhidraSnapshot],
    binary: &[u8],
    seed_path: &str,
    options: &Options<'_>,
    diagnostics: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    if options.allocations.is_some() {
        return Err("seeded assessment does not yet support declared process allocations".into());
    }
    let seed_json = read_bounded_json(seed_path, MAX_PCODE_SEED_BYTES)?;
    let image = super::pcode_image_or_legacy(binary, &snapshots[0])?;
    let mut assessment = hydir_decompile::assess_pcode_function(
        snapshots,
        &seed_json,
        image.as_ref(),
        options.max_operations,
        options.max_visits,
        options.max_depth,
    )?;
    assessment.trace.snapshot_diagnostics = diagnostics;
    let bytes = serde_json::to_vec_pretty(&assessment)?;
    if let Some(path) = options.output {
        write_new_or_identical(path, &bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

pub fn run_assessment_snapshots(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, root, seed, options @ ..] = args else {
        return Err("assess needs binary, root snapshot, and seed".into());
    };
    let options = parse_options(options, false)?;
    let binary_bytes = read_binary(binary)?;
    let digest = format!("{:x}", Sha256::digest(&binary_bytes));
    let mut snapshots = Vec::with_capacity(options.callees.len() + 1);
    for path in std::iter::once(root.as_str()).chain(options.callees.iter().copied()) {
        snapshots.push(parse_ghidra_snapshot(
            &read_bounded_json(path, MAX_GHIDRA_SNAPSHOT_BYTES)?,
            &digest,
        )?);
    }
    emit_assessment(&snapshots, &binary_bytes, seed, &options, Vec::new())
}

pub fn run_assessment_automatic(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, seed, options @ ..] = args else {
        return Err("assess needs binary and seed".into());
    };
    let options = parse_options(options, true)?;
    let (snapshots, diagnostics) = collect_automatic(binary, seed, &options, false)?;
    let binary_bytes = read_binary(binary)?;
    emit_assessment(&snapshots, &binary_bytes, seed, &options, diagnostics)
}

pub fn run_snapshots(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, root, seed, options @ ..] = args else {
        return Err("trace-calls needs binary, root snapshot, and seed".into());
    };
    let options = parse_options(options, false)?;
    let binary_bytes = read_binary(binary)?;
    let digest = format!("{:x}", Sha256::digest(&binary_bytes));
    let mut snapshots = Vec::with_capacity(options.callees.len() + 1);
    for path in std::iter::once(root.as_str()).chain(options.callees.iter().copied()) {
        snapshots.push(parse_ghidra_snapshot(
            &read_bounded_json(path, MAX_GHIDRA_SNAPSHOT_BYTES)?,
            &digest,
        )?);
    }
    emit(&snapshots, &binary_bytes, seed, &options, Vec::new(), false)
}

pub fn run_snapshots_imports(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, root, seed, options @ ..] = args else {
        return Err("trace-calls-imports needs binary, root snapshot, and seed".into());
    };
    let options = parse_options(options, false)?;
    let binary_bytes = read_binary(binary)?;
    let digest = format!("{:x}", Sha256::digest(&binary_bytes));
    let mut snapshots = Vec::with_capacity(options.callees.len() + 1);
    for path in std::iter::once(root.as_str()).chain(options.callees.iter().copied()) {
        snapshots.push(parse_ghidra_snapshot(
            &read_bounded_json(path, MAX_GHIDRA_SNAPSHOT_BYTES)?,
            &digest,
        )?);
    }
    emit(&snapshots, &binary_bytes, seed, &options, Vec::new(), true)
}

pub fn run_automatic(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, seed, options @ ..] = args else {
        return Err("trace-calls needs binary and seed".into());
    };
    let options = parse_options(options, true)?;
    let (snapshots, diagnostics) = collect_automatic(binary, seed, &options, false)?;
    let binary_bytes = read_binary(binary)?;
    emit(
        &snapshots,
        &binary_bytes,
        seed,
        &options,
        diagnostics,
        false,
    )
}

pub fn run_automatic_imports(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, seed, options @ ..] = args else {
        return Err("trace-calls-imports needs binary and seed".into());
    };
    let options = parse_options(options, true)?;
    let (snapshots, diagnostics) = collect_automatic(binary, seed, &options, true)?;
    let binary_bytes = read_binary(binary)?;
    emit(&snapshots, &binary_bytes, seed, &options, diagnostics, true)
}

pub fn run_automatic_llvm(args: &[String]) -> Result<(), Box<dyn Error>> {
    run_automatic_llvm_inner(args, false)
}

pub fn run_automatic_llvm_imports(args: &[String]) -> Result<(), Box<dyn Error>> {
    run_automatic_llvm_inner(args, true)
}

fn run_automatic_llvm_inner(args: &[String], with_imports: bool) -> Result<(), Box<dyn Error>> {
    let [binary, seed, options @ ..] = args else {
        return Err("llvm-cfg-calls needs binary and seed".into());
    };
    let options = parse_options(options, true)?;
    if with_imports && options.allocations.is_none() {
        return Err("import LLVM contracts require --allocations".into());
    }
    let (snapshots, diagnostics) = collect_automatic(binary, seed, &options, with_imports)?;
    let mut artifact = if let Some(path) = options.allocations {
        let binary_bytes = read_binary(binary)?;
        let (process, allocations) = strict_allocations(&snapshots, &binary_bytes, path)?;
        if with_imports {
            hydir_decompile::emit_pcode_interprocedural_cfg_llvm_with_imports(
                &snapshots,
                &binary_bytes,
                options.max_depth,
                &process,
                &allocations,
            )?
        } else {
            hydir_decompile::emit_pcode_interprocedural_cfg_llvm_with_allocations(
                &snapshots,
                options.max_depth,
                &process,
                &allocations,
            )?
        }
    } else {
        hydir_decompile::emit_pcode_interprocedural_cfg_llvm(&snapshots, options.max_depth)?
    };
    artifact.snapshot_diagnostics = diagnostics;
    let bytes = serde_json::to_vec_pretty(&artifact)?;
    if let Some(path) = options.output {
        write_new_or_identical(path, &bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

fn collect_automatic(
    binary: &str,
    seed: &str,
    options: &Options<'_>,
    with_imports: bool,
) -> Result<(Vec<GhidraSnapshot>, Vec<String>), Box<dyn Error>> {
    let root_entry = options.function.ok_or("missing Ghidra function entry")?;
    let binary_bytes = read_binary(binary)?;
    let digest = format!("{:x}", Sha256::digest(&binary_bytes));
    let scratch = tempfile::tempdir()?;
    let root_output = scratch.path().join("function-0.json");
    let root = ghidra_worker::analyze(Path::new(binary), Some(root_entry), &root_output)?;
    if root.binary_sha256 != digest
        || root.selected_function.entry.offset != format!("0x{root_entry:x}")
    {
        return Err("Ghidra worker returned a different binary or function".into());
    }
    let mut snapshots = vec![root.clone()];
    let mut seen = BTreeSet::from([root_entry]);
    let mut diagnostics = Vec::new();
    let parsed_seed = parse_pcode_seed(&read_bounded_json(seed, MAX_PCODE_SEED_BYTES)?, &root)?;
    let image = if options.allocations.is_none() {
        super::pcode_image_or_legacy(&binary_bytes, &root)?
    } else {
        None
    };
    loop {
        let trace = if let Some(path) = options.allocations {
            let (process, allocations) = strict_allocations(&snapshots, &binary_bytes, path)?;
            if with_imports {
                execute_concrete_call_path_with_imports(
                    &snapshots,
                    &parsed_seed,
                    &binary_bytes,
                    &process,
                    &allocations,
                    options.max_operations,
                    options.max_visits,
                    options.max_depth,
                )?
            } else {
                execute_concrete_call_path_with_allocations(
                    &snapshots,
                    &parsed_seed,
                    &process,
                    &allocations,
                    options.max_operations,
                    options.max_visits,
                    options.max_depth,
                )?
            }
        } else if let Some(image) = &image {
            execute_concrete_call_path_with_image(
                &snapshots,
                &parsed_seed,
                image,
                options.max_operations,
                options.max_visits,
                options.max_depth,
            )?
        } else {
            execute_concrete_call_path(
                &snapshots,
                &parsed_seed,
                options.max_operations,
                options.max_visits,
                options.max_depth,
            )?
        };
        let Some(target) = unloaded_call_target(&snapshots, &trace)? else {
            break;
        };
        let entry = super::parse_u64_auto(&target.offset, "reached call target")?;
        if snapshots.len() >= options.max_functions {
            diagnostics.push(format!(
                "function collection limit reached before callee 0x{entry:x}"
            ));
            break;
        }
        if !seen.insert(entry) {
            break;
        }
        let output = scratch
            .path()
            .join(format!("function-{}.json", snapshots.len()));
        let snapshot = match ghidra_worker::analyze(Path::new(binary), Some(entry), &output) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                diagnostics.push(format!("callee 0x{entry:x} export failed: {error}"));
                break;
            }
        };
        if snapshot.binary_sha256 != digest
            || snapshot.selected_function.entry != target
            || snapshot.program != root.program
            || snapshot.address_spaces != root.address_spaces
            || snapshot.functions != root.functions
            || snapshot.flow_overrides_applied != root.flow_overrides_applied
        {
            diagnostics.push(format!(
                "callee 0x{entry:x} has inconsistent analysis identity"
            ));
            break;
        }
        snapshots.push(snapshot);
    }
    Ok((snapshots, diagnostics))
}
