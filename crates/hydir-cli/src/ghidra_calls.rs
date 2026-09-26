//! CLI orchestration for bounded calls across analyzed Ghidra functions.

use super::{read_binary, read_bounded_json, write_new_or_identical};
use hydir_ghidra_worker as ghidra_worker;
use hydir_ir::pcode::{
    GhidraSnapshot, MAX_GHIDRA_SNAPSHOT_BYTES, MAX_PCODE_SEED_BYTES, execute_concrete_call_path,
    parse_ghidra_snapshot, parse_pcode_seed,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, VecDeque},
    error::Error,
    path::Path,
};

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

fn emit(
    snapshots: &[GhidraSnapshot],
    seed_path: &str,
    options: &Options<'_>,
    diagnostics: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    let seed = parse_pcode_seed(
        &read_bounded_json(seed_path, MAX_PCODE_SEED_BYTES)?,
        &snapshots[0],
    )?;
    let mut trace = execute_concrete_call_path(
        snapshots,
        &seed,
        options.max_operations,
        options.max_visits,
        options.max_depth,
    )?;
    trace.snapshot_diagnostics = diagnostics;
    let bytes = serde_json::to_vec_pretty(&trace)?;
    if let Some(path) = options.output {
        write_new_or_identical(path, &bytes)?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

pub fn run_snapshots(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, root, seed, options @ ..] = args else {
        return Err("trace-calls needs binary, root snapshot, and seed".into());
    };
    let options = parse_options(options, false)?;
    let digest = format!("{:x}", Sha256::digest(read_binary(binary)?));
    let mut snapshots = Vec::with_capacity(options.callees.len() + 1);
    for path in std::iter::once(root.as_str()).chain(options.callees.iter().copied()) {
        snapshots.push(parse_ghidra_snapshot(
            &read_bounded_json(path, MAX_GHIDRA_SNAPSHOT_BYTES)?,
            &digest,
        )?);
    }
    emit(&snapshots, seed, &options, Vec::new())
}

pub fn run_automatic(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [binary, seed, options @ ..] = args else {
        return Err("trace-calls needs binary and seed".into());
    };
    let options = parse_options(options, true)?;
    let root_entry = options.function.ok_or("missing Ghidra function entry")?;
    let digest = format!("{:x}", Sha256::digest(read_binary(binary)?));
    let scratch = tempfile::tempdir()?;
    let mut pending = VecDeque::from([root_entry]);
    let mut seen = BTreeSet::from([root_entry]);
    let mut snapshots = Vec::<GhidraSnapshot>::new();
    let mut diagnostics = Vec::new();
    while let Some(entry) = pending.pop_front() {
        if snapshots.len() >= options.max_functions {
            diagnostics.push(format!(
                "function collection limit reached before 0x{entry:x}"
            ));
            break;
        }
        let output = scratch
            .path()
            .join(format!("function-{}.json", snapshots.len()));
        let snapshot = match ghidra_worker::analyze(Path::new(binary), Some(entry), &output) {
            Ok(snapshot) => snapshot,
            Err(error) if entry != root_entry => {
                diagnostics.push(format!("callee 0x{entry:x} export failed: {error}"));
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if snapshot.binary_sha256 != digest
            || snapshot.selected_function.entry.offset != format!("0x{entry:x}")
        {
            return Err("Ghidra worker returned a different binary or function".into());
        }
        if let Some(root) = snapshots.first() {
            if snapshot.program != root.program
                || snapshot.address_spaces != root.address_spaces
                || snapshot.functions != root.functions
                || snapshot.flow_overrides_applied != root.flow_overrides_applied
            {
                diagnostics.push(format!(
                    "callee 0x{entry:x} has inconsistent analysis identity"
                ));
                continue;
            }
        }
        for call in &snapshot.selected_function.call_targets {
            if call.computed || call.conditional {
                continue;
            }
            let Some(target) = &call.target else { continue };
            let Ok(target_entry) = super::parse_u64_auto(&target.offset, "call target") else {
                continue;
            };
            if snapshot
                .functions
                .iter()
                .any(|function| function.entry == *target)
                && seen.insert(target_entry)
            {
                pending.push_back(target_entry);
            }
        }
        snapshots.push(snapshot);
    }
    emit(&snapshots, seed, &options, diagnostics)
}
