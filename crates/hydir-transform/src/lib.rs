//! Allowlisted LLVM 14.0.6 scalar IR pass experiment.
//!
//! This invokes a separately installed `opt` executable with literal
//! arguments. It never accepts plugin paths or arbitrary pass syntax.

use std::{fs, path::Path, process::Command};

pub const MAX_IR_BYTES: usize = 16 * 1024 * 1024;

pub struct TransformArtifacts {
    pub raw: Vec<u8>,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    pub pipeline: Vec<String>,
    pub llvm_version: String,
}

pub fn parse_passes(value: &str) -> Result<Vec<String>, String> {
    if value.len() > 64 {
        return Err("pass list must be at most 64 bytes".to_owned());
    }
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
        return Err("pass list must be 1..=4 unique, allowlisted pass names".to_owned());
    }
    Ok(passes.into_iter().map(str::to_owned).collect())
}

fn opt_step(opt: &Path, input: &Path, output: &Path, pipeline: &str) -> Result<(), String> {
    let result = Command::new(opt)
        .arg("-S")
        .arg(format!("-passes={pipeline}"))
        .arg("-verify-each")
        .arg(input)
        .arg("-o")
        .arg(output)
        .output()
        .map_err(|error| format!("cannot start pinned LLVM opt: {error}"))?;
    if !result.status.success() {
        return Err(format!(
            "LLVM opt pipeline {pipeline:?} failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }
    Ok(())
}

pub fn transform(raw: &str, passes: &str, opt: &Path) -> Result<TransformArtifacts, String> {
    if raw.is_empty() || raw.len() > MAX_IR_BYTES {
        return Err("raw IR must be 1..=16 MiB".to_owned());
    }
    let pipeline = parse_passes(passes)?;
    let version = Command::new(opt)
        .arg("--version")
        .output()
        .map_err(|error| format!("cannot query LLVM opt: {error}"))?;
    let version_text = String::from_utf8_lossy(&version.stdout);
    if !version.status.success() || !version_text.contains("LLVM version 14.0.6") {
        return Err("transform requires pinned LLVM opt 14.0.6".to_owned());
    }
    let directory =
        tempfile::tempdir().map_err(|error| format!("temporary IR directory: {error}"))?;
    let raw_path = directory.path().join("raw.ll");
    let before_path = directory.path().join("before.ll");
    let after_path = directory.path().join("after.ll");
    fs::write(&raw_path, raw).map_err(|error| format!("cannot write raw IR: {error}"))?;
    opt_step(opt, &raw_path, &before_path, "verify")?;
    opt_step(opt, &before_path, &after_path, &pipeline.join(","))?;
    let checked = Command::new(opt)
        .args(["-passes=verify", "-disable-output"])
        .arg(&after_path)
        .output()
        .map_err(|error| format!("cannot verify transformed IR: {error}"))?;
    if !checked.status.success() {
        return Err(format!(
            "transformed IR failed LLVM verification: {}",
            String::from_utf8_lossy(&checked.stderr)
        ));
    }
    let bounded_read = |path: &Path| -> Result<Vec<u8>, String> {
        let size = fs::metadata(path)
            .map_err(|error| format!("cannot inspect LLVM output: {error}"))?
            .len();
        if size > MAX_IR_BYTES as u64 {
            return Err("LLVM output exceeded 16 MiB".to_owned());
        }
        fs::read(path).map_err(|error| format!("cannot read LLVM output: {error}"))
    };
    Ok(TransformArtifacts {
        raw: raw.as_bytes().to_vec(),
        before: bounded_read(&before_path)?,
        after: bounded_read(&after_path)?,
        pipeline,
        llvm_version: version_text.lines().next().unwrap_or_default().to_owned(),
    })
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
        assert!(parse_passes(&"dce,".repeat(100)).is_err());
    }
}
