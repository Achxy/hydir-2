//! Trusted-fixture LLVM pass experiment with an exact allowlist and snapshots.

use super::read_binary;
use hydir_backend::lift_symbol;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path, process::Command};

const HELP: &str = "hydirctl transform <elf> <function-symbol> --assume-u64x2 --trusted-fixture --passes <comma-list> --output-dir <new-directory> [--opt <path>]\nAllowed passes: instcombine,sccp,simplifycfg,dce. The LLVM opt executable must report version 14.0.6.";

fn parse_passes(value: &str) -> Result<Vec<&str>, Box<dyn Error>> {
    let passes: Vec<_> = value.split(',').collect();
    if passes.is_empty()
        || passes.len() > 4
        || passes
            .iter()
            .any(|pass| !matches!(*pass, "instcombine" | "sccp" | "simplifycfg" | "dce"))
        || passes
            .iter()
            .enumerate()
            .any(|(index, pass)| passes[..index].contains(pass))
    {
        return Err("pass list must be 1..=4 unique, allowlisted pass names".into());
    }
    Ok(passes)
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn opt_step(opt: &str, input: &Path, output: &Path, pipeline: &str) -> Result<(), Box<dyn Error>> {
    let result = Command::new(opt)
        .arg("-S")
        .arg(format!("-passes={pipeline}"))
        .arg("-verify-each")
        .arg(input)
        .arg("-o")
        .arg(output)
        .output()?;
    if !result.status.success() {
        return Err(format!(
            "LLVM opt pipeline {pipeline:?} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(())
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
    let passes = parse_passes(&args[5])?;
    let pipeline = passes.join(",");
    let opt = if args.len() == 10 { &args[9] } else { "opt" };
    let version = Command::new(opt).arg("--version").output()?;
    let version_text = String::from_utf8_lossy(&version.stdout);
    if !version.status.success() || !version_text.contains("LLVM version 14.0.6") {
        return Err("transform requires the pinned LLVM opt 14.0.6; use --opt to select it".into());
    }
    let binary = read_binary(&args[0])?;
    let raw_ir = lift_symbol(&binary, &args[1])?;
    let output_dir = Path::new(&args[7]);
    fs::create_dir(output_dir)?; // new directory only; never overwrite an experiment
    let raw_path = output_dir.join("raw.ll");
    let before_path = output_dir.join("before.ll");
    let after_path = output_dir.join("after.ll");
    fs::write(&raw_path, raw_ir.as_bytes())?;
    opt_step(opt, &raw_path, &before_path, "verify")?;
    opt_step(opt, &before_path, &after_path, &pipeline)?;
    let checked = Command::new(opt)
        .args(["-passes=verify", "-disable-output"])
        .arg(&after_path)
        .output()?;
    if !checked.status.success() {
        return Err(format!(
            "transformed IR failed LLVM verification: {}",
            String::from_utf8_lossy(&checked.stderr)
        )
        .into());
    }
    let before = fs::read(&before_path)?;
    let after = fs::read(&after_path)?;
    let report = json!({
        "scope": "trusted function fixture; LLVM verification only, not behavioral equivalence",
        "binary_sha256": digest(&binary),
        "function": args[1],
        "prototype_assertion": "u64(u64,u64) System V AMD64",
        "pipeline": passes,
        "llvm_version": version_text.lines().next().unwrap_or_default(),
        "raw_ir_sha256": digest(raw_ir.as_bytes()),
        "before_ir_sha256": digest(&before),
        "after_ir_sha256": digest(&after),
        "ir_text_changed": before != after,
        "llvm_verified": true,
        "output_dir": output_dir,
    });
    let encoded = serde_json::to_vec_pretty(&report)?;
    fs::write(output_dir.join("report.json"), &encoded)?;
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_passes;

    #[test]
    fn pass_allowlist_rejects_plugins_and_duplicates() {
        assert_eq!(
            parse_passes("instcombine,sccp").unwrap(),
            ["instcombine", "sccp"]
        );
        assert!(parse_passes("instcombine,instcombine").is_err());
        assert!(parse_passes("default<O3>").is_err());
        assert!(parse_passes("load=/tmp/plugin.so").is_err());
        assert!(parse_passes("").is_err());
    }
}
