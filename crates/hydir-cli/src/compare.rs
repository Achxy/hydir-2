use hydir_decompile::{EngineExecutionEvidence, compare_pcode_executions};
use sha2::{Digest, Sha256};
use std::{error::Error, fs, path::Path};

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    if args.len() < 3 {
        return Err("usage: hydirctl compare-executions <elf> <seed.json> <engine-evidence.json>... [--output <comparison.json>]".into());
    }
    let mut evidence_paths = Vec::new();
    let mut output = None;
    let mut index = 2;
    while index < args.len() {
        if args[index] == "--output" {
            if output.is_some() || index + 1 >= args.len() {
                return Err("comparison output path is missing or repeated".into());
            }
            output = Some(&args[index + 1]);
            index += 2;
        } else {
            evidence_paths.push(&args[index]);
            index += 1;
        }
    }
    if evidence_paths.is_empty() || evidence_paths.len() > 4 {
        return Err("comparison needs one to four engine evidence files".into());
    }
    let binary = fs::read(&args[0])?;
    let seed = fs::read(&args[1])?;
    let binary_digest = format!("{:x}", Sha256::digest(&binary));
    let seed_digest = format!("{:x}", Sha256::digest(&seed));
    let mut evidence = Vec::new();
    for path in evidence_paths {
        let bytes = fs::read(path)?;
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("engine evidence exceeds 16 MiB".into());
        }
        let item: EngineExecutionEvidence = serde_json::from_slice(&bytes)?;
        if item.binary_sha256 != binary_digest || item.seed_sha256 != seed_digest {
            return Err(format!("engine evidence in {path} belongs to another ELF or seed").into());
        }
        evidence.push(item);
    }
    let comparison = compare_pcode_executions(evidence)?;
    let result = serde_json::to_vec_pretty(&comparison)?;
    if let Some(path) = output {
        super::write_new_or_identical(Path::new(path), &result)?;
    } else {
        println!("{}", String::from_utf8(result)?);
    }
    Ok(())
}
