//! Explicit, trusted-fixture CLI boundary for versioned scalar ELF patches.

use super::read_binary;
use hydir_patch::{parse_patch_json, patch_binary};
use serde_json::json;
use std::{error::Error, fs, io::Write, path::Path};

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let [
        input,
        patch_file,
        trusted,
        prototype,
        entry,
        output_flag,
        output,
    ] = args
    else {
        return Err("patch <linked-elf> <patch-v1.json> --trusted-fixture --assume-u64x2 --assume-entry-only --output <new.elf>".into());
    };
    if trusted != "--trusted-fixture"
        || prototype != "--assume-u64x2"
        || entry != "--assume-entry-only"
        || output_flag != "--output"
    {
        return Err("patch requires explicit --trusted-fixture --assume-u64x2 --assume-entry-only --output flags".into());
    }
    let input_path = fs::canonicalize(input)?;
    let binary = read_binary(&input_path)?;
    if fs::metadata(patch_file)?.len() > hydir_patch::MAX_PATCH_BYTES as u64 {
        return Err("patch document exceeds 4096 bytes".into());
    }
    let patch = parse_patch_json(&fs::read(patch_file)?)?;
    let result = patch_binary(&binary, &patch)?;
    let output_path = Path::new(output);
    if output_path.exists() {
        return Err("patch output exists; refusing to overwrite it".into());
    }
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&result.content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&input_path)?.permissions().mode() & 0o777;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))?;
    }
    temporary.persist_noclobber(output_path)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema_version": patch.document.schema_version,
            "input": input_path,
            "output": output_path,
            "function_symbol": patch.document.function_symbol,
            "function_address": format!("0x{:016x}", result.function_address),
            "region_size_bytes": result.function_size,
            "original_sha256": result.original_sha256,
            "patched_sha256": result.patched_sha256,
            "original_region_hex": result.original_region.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "region_bytes_sha256": result.region_bytes_sha256,
            "region_exit": format!("0x{:016x}", result.region_exit),
            "exit_rsp_delta": result.exit_rsp_delta,
            "replacement_hex": result.replacement_bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
            "assumptions": ["trusted fixture", "u64(u64,u64) SysV ABI", "no incoming control-flow edges to function interior"],
            "behavior_validation": "not run by patch command; validate intended change and unchanged effects separately",
        }))?
    );
    Ok(())
}
