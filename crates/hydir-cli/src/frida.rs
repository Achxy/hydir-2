//! Invoke the separately bundled Linux observer and check every returned claim.

use super::{parse_u64_auto, read_binary, read_bounded_json, read_limited, write_new_or_identical};
use hydir_execution::{
    MAX_DYNAMIC_TRACE_JSON_BYTES, MAX_INPUT_SPEC_BYTES, parse_dynamic_trace, parse_input_spec,
    validate_dynamic_trace, validate_input_spec,
};
use hydir_ir::pcode::{MAX_GHIDRA_SNAPSHOT_BYTES, parse_ghidra_snapshot};
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Options<'a> {
    function: u64,
    snapshot: Option<&'a str>,
    output: Option<&'a str>,
}

fn options(args: &[String]) -> Result<Options<'_>, Box<dyn Error>> {
    if args.len() < 5 || args[1] != "frida" {
        return Err("usage: hydirctl observe frida <elf> <input.json> --function <0xelf-vaddr> [--snapshot <snapshot.json>] [--output <trace.json>]".into());
    }
    let mut function = None;
    let mut snapshot = None;
    let mut output = None;
    let mut pairs = args[4..].chunks_exact(2);
    for pair in &mut pairs {
        match pair[0].as_str() {
            "--function" if function.is_none() => {
                function = Some(parse_u64_auto(&pair[1], "observed function entry")?);
            }
            "--snapshot" if snapshot.is_none() => snapshot = Some(pair[1].as_str()),
            "--output" if output.is_none() => output = Some(pair[1].as_str()),
            _ => return Err("invalid Frida observation option".into()),
        }
    }
    if !pairs.remainder().is_empty() {
        return Err("Frida observation options require values".into());
    }
    Ok(Options {
        function: function.ok_or("Frida observation requires --function")?,
        snapshot,
        output,
    })
}

pub(super) fn helper_path() -> Result<PathBuf, Box<dyn Error>> {
    if let Some(path) = env::var_os("HYDIR_FRIDA_OBSERVER") {
        return Ok(PathBuf::from(path));
    }
    Ok(env::current_exe()?.with_file_name("hydir-frida-observer"))
}

pub(super) fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    let options = options(args)?;
    if env::consts::OS != "linux" || env::consts::ARCH != "x86_64" {
        return Err("Frida observation requires the Linux x86-64 release".into());
    }
    let elf = read_binary(&args[2])?;
    let input = parse_input_spec(&read_bounded_json(&args[3], MAX_INPUT_SPEC_BYTES)?)?;
    validate_input_spec(&elf, &input)?;
    let expected_snapshot = if let Some(path) = options.snapshot {
        let snapshot = parse_ghidra_snapshot(
            &read_bounded_json(path, MAX_GHIDRA_SNAPSHOT_BYTES)?,
            &input.binary_sha256,
        )?;
        let entry = &snapshot.selected_function.entry;
        let elf_base = super::import_elf(&elf)?
            .mapped_segments
            .iter()
            .filter(|segment| segment.address_space == 0 && segment.memory_size > 0)
            .map(|segment| segment.virtual_address.0)
            .min()
            .ok_or("ELF has no mapped RAM segment")?;
        let snapshot_base =
            parse_u64_auto(&snapshot.program.image_base.offset, "Ghidra image base")?;
        let snapshot_entry = parse_u64_auto(&entry.offset, "Ghidra function entry")?;
        let linked_entry = snapshot_entry
            .checked_sub(snapshot_base)
            .and_then(|offset| elf_base.checked_add(offset))
            .ok_or("Ghidra function entry cannot be normalized to ELF")?;
        if entry.space != "ram"
            || snapshot.program.image_base.space != "ram"
            || linked_entry != options.function
        {
            return Err("Ghidra snapshot entry differs from observed ELF address".into());
        }
        Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&snapshot)?)
        ))
    } else {
        None
    };
    let helper = helper_path()?;
    if !helper.is_file() {
        return Err(format!(
            "Frida observer is unavailable at {}; install the Linux release bundle or set HYDIR_FRIDA_OBSERVER",
            helper.display()
        )
        .into());
    }
    let mut child = Command::new(&helper)
        .arg(&args[2])
        .arg(&args[3])
        .arg(format!("{:x}", options.function))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Frida observer stdout unavailable")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Frida observer stderr unavailable")?;
    let stdout_reader = thread::spawn(move || read_limited(stdout, MAX_DYNAMIC_TRACE_JSON_BYTES));
    let stderr_reader = thread::spawn(move || read_limited(stderr, 8192));
    let deadline =
        Instant::now() + Duration::from_millis(input.budget.timeout_ms.saturating_add(8_000));
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err("Frida observer exceeded the InputSpec wall-clock budget".into());
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| "Frida stdout reader panicked")??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "Frida stderr reader panicked")??;
    if !status.success() {
        return Err(format!(
            "Frida observer failed: {}",
            String::from_utf8_lossy(&stderr).trim()
        )
        .into());
    }
    let mut trace = parse_dynamic_trace(&stdout)?;
    if trace.selected_elf_vaddr != options.function {
        return Err("Frida trace selected address differs from request".into());
    }
    validate_dynamic_trace(&elf, &input, &trace)?;
    if trace.ghidra_snapshot_sha256.is_some() {
        return Err("Frida helper asserted an unexpected Ghidra snapshot".into());
    }
    trace.ghidra_snapshot_sha256 = expected_snapshot;
    validate_dynamic_trace(&elf, &input, &trace)?;
    let content = serde_json::to_vec_pretty(&trace)?;
    if let Some(path) = options.output {
        write_new_or_identical(path, &content)?;
    } else {
        println!("{}", String::from_utf8(content)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::options;

    #[test]
    fn requires_one_entry_and_rejects_duplicate_options() {
        let args = [
            "observe",
            "frida",
            "binary",
            "input.json",
            "--function",
            "0x401000",
        ]
        .map(str::to_owned);
        assert_eq!(options(&args).unwrap().function, 0x401000);
        assert!(options(&args[..4]).is_err());
        let mut duplicate = args.to_vec();
        duplicate.extend(["--function".into(), "0x401001".into()]);
        assert!(options(&duplicate).is_err());
    }
}
