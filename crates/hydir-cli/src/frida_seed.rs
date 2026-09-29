use super::{read_binary, read_bounded_json, write_new_or_identical};
use hydir_decompile::frida_entry_pcode_seed;
use hydir_execution::{
    MAX_DYNAMIC_TRACE_JSON_BYTES, MAX_INPUT_SPEC_BYTES, parse_dynamic_trace, parse_input_spec,
};
use hydir_ir::pcode::{MAX_GHIDRA_SNAPSHOT_BYTES, parse_ghidra_snapshot};
use std::{error::Error, path::Path};

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    if !(args.len() == 4 || args.len() == 6 && args[4] == "--output") {
        return Err("usage: hydirctl observe seed <elf> <input.json> <snapshot.json> <trace.json> [--output <seed.json>]".into());
    }
    let elf = read_binary(&args[0])?;
    let input = parse_input_spec(&read_bounded_json(&args[1], MAX_INPUT_SPEC_BYTES)?)?;
    let snapshot = parse_ghidra_snapshot(
        &read_bounded_json(&args[2], MAX_GHIDRA_SNAPSHOT_BYTES)?,
        &input.binary_sha256,
    )?;
    let trace = parse_dynamic_trace(&read_bounded_json(&args[3], MAX_DYNAMIC_TRACE_JSON_BYTES)?)?;
    let seed = frida_entry_pcode_seed(&elf, &input, &snapshot, &trace)?;
    if args.len() == 6 {
        write_new_or_identical(Path::new(&args[5]), &seed)?;
    } else {
        println!("{}", String::from_utf8(seed)?);
    }
    eprintln!("hydirctl: entry registers mapped; uncaptured stack and memory remain unknown");
    Ok(())
}
