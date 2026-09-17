//! Trusted-fixture CLI wrapper over the shared named LLVM pass experiment.

use super::read_binary;
use hydir_backend::lift_symbol;
use hydir_transform::transform;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};

const HELP: &str = "hydirctl transform <elf> <function-symbol> --assume-u64x2 --trusted-fixture --passes <comma-list> --output-dir <new-directory> [--opt <path>]\nAllowed passes: instcombine,sccp,simplifycfg,dce. The LLVM opt executable must report version 14.0.6.";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    if !(args.len() == 8 || args.len() == 10)
        || args[2] != "--assume-u64x2"
        || args[3] != "--trusted-fixture"
        || args[4] != "--passes"
        || args[6] != "--output-dir"
        || (args.len() == 10 && args[8] != "--opt")
    {
        return Err(HELP.into());
    }
    let opt = if args.len() == 10 { &args[9] } else { "opt" };
    let binary = read_binary(&args[0])?;
    let raw_ir = lift_symbol(&binary, &args[1])?;
    let result = transform(&raw_ir, &args[5], Path::new(opt))?;
    let output_dir = Path::new(&args[7]);
    fs::create_dir(output_dir)?;
    fs::write(output_dir.join("raw.ll"), &result.raw)?;
    fs::write(output_dir.join("before.ll"), &result.before)?;
    fs::write(output_dir.join("after.ll"), &result.after)?;
    let report = json!({
        "scope": "trusted function fixture; LLVM verification only, not behavioral equivalence",
        "binary_sha256": digest(&binary),
        "function": args[1],
        "prototype_assertion": "u64(u64,u64) System V AMD64",
        "pipeline": result.pipeline,
        "llvm_version": result.llvm_version,
        "raw_ir_sha256": digest(&result.raw),
        "before_ir_sha256": digest(&result.before),
        "after_ir_sha256": digest(&result.after),
        "ir_text_changed": result.before != result.after,
        "llvm_verified": true,
        "output_dir": output_dir,
    });
    let encoded = serde_json::to_vec_pretty(&report)?;
    fs::write(output_dir.join("report.json"), &encoded)?;
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}
