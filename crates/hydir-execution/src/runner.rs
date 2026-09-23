use super::{
    InputSpec, NATIVE_REPLAY_REPORT_VERSION, NativeReplayReport, ReplayStatus, decode_hex,
    encode_hex, input_sha256, validate_input_spec,
};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStringExt, fs::PermissionsExt, process::CommandExt},
    },
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

/// Runs one fresh Linux process in a read-only Bubblewrap filesystem and
/// private network/PID namespaces. The caller must still treat binaries as
/// untrusted native code sharing the host kernel.
pub fn replay_local(elf: &[u8], input: &InputSpec) -> Result<NativeReplayReport, String> {
    validate_input_spec(elf, input)?;
    let input_digest = input_sha256(input)?;
    let mut report = NativeReplayReport {
        schema_version: NATIVE_REPLAY_REPORT_VERSION,
        binary_sha256: input.binary_sha256.clone(),
        input_sha256: input_digest,
        status: ReplayStatus::RunnerError,
        exit_code: None,
        signal: None,
        stdout_hex: String::new(),
        stderr_hex: String::new(),
        elapsed_ms: 0,
        runner: "bubblewrap-linux-local-v1".into(),
        diagnostic: None,
    };
    let scratch =
        tempfile::tempdir().map_err(|error| format!("scratch creation failed: {error}"))?;
    let program = scratch.path().join(".hydir-program");
    fs::write(&program, elf).map_err(|error| format!("program staging failed: {error}"))?;
    fs::set_permissions(&program, fs::Permissions::from_mode(0o500))
        .map_err(|error| format!("program permissions failed: {error}"))?;
    for file in &input.files {
        let path = scratch.path().join(&file.path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("input directory failed: {error}"))?;
        }
        fs::write(&path, decode_hex(&file.bytes_hex, super::MAX_INPUT_BYTES)?)
            .map_err(|error| format!("input staging failed: {error}"))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .map_err(|error| format!("input permissions failed: {error}"))?;
    }

    let mut status_file =
        tempfile::tempfile().map_err(|error| format!("status channel failed: {error}"))?;
    let status_fd = status_file.as_raw_fd();
    let mut command = Command::new("bwrap");
    command.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--setenv",
        "HOME",
        "/work",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "LC_ALL",
        "C",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind-try",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/bin",
        "/bin",
        "--ro-bind-try",
        "/etc/ld.so.cache",
        "/etc/ld.so.cache",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--ro-bind",
    ]);
    command.arg(scratch.path()).arg("/work");
    command.args([
        "--chdir",
        "/work",
        "--json-status-fd",
        "3",
        "--",
        "/work/.hydir-program",
    ]);
    for arg in &input.argv_hex {
        command.arg(std::ffi::OsString::from_vec(decode_hex(arg, 4096)?));
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let memory = input.budget.memory_bytes;
    let seconds = input.budget.timeout_ms.div_ceil(1000).saturating_add(1);
    // SAFETY: pre_exec only invokes async-signal-safe libc operations. FDs and
    // limits are fixed before spawning; no allocation or locking occurs here.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(status_fd, 3) == -1 || libc::fcntl(3, libc::F_SETFD, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, limit) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, seconds),
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_FSIZE, 1024 * 1024),
            ] {
                let rlimit = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &rlimit) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let start = Instant::now();
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            report.diagnostic = Some(format!("bwrap launch failed: {error}"));
            return Ok(report);
        }
    };
    let exceeded = Arc::new(AtomicBool::new(false));
    let output_seen = Arc::new(AtomicUsize::new(0));
    let cap = input.budget.output_bytes as usize;
    let stdout = read_bounded(
        child.stdout.take().ok_or("stdout pipe missing")?,
        cap,
        exceeded.clone(),
        output_seen.clone(),
    );
    let stderr = read_bounded(
        child.stderr.take().ok_or("stderr pipe missing")?,
        cap,
        exceeded.clone(),
        output_seen,
    );
    let stdin = decode_hex(&input.stdin_hex, super::MAX_INPUT_BYTES)?;
    let stdin_writer = child.stdin.take().ok_or("stdin pipe missing")?;
    let writer = thread::spawn(move || {
        let mut pipe = stdin_writer;
        let _ = pipe.write_all(&stdin);
    });
    let timeout = Duration::from_millis(input.budget.timeout_ms);
    let mut timed_out = false;
    let mut output_limited = false;
    let mut wait_error = None;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) => {
                wait_error = Some(error.to_string());
                kill_group(child.id());
                break;
            }
        }
        if exceeded.load(Ordering::Relaxed) {
            output_limited = true;
            kill_group(child.id());
            break;
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            kill_group(child.id());
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let _ = child.wait();
    let _ = writer.join();
    let stdout_bytes = stdout.join().map_err(|_| "stdout reader panicked")??;
    let stderr_bytes = stderr.join().map_err(|_| "stderr reader panicked")??;
    report.elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
    report.stdout_hex = encode_hex(&stdout_bytes);
    report.stderr_hex = encode_hex(&stderr_bytes);
    if let Some(error) = wait_error {
        report.diagnostic = Some(format!("process wait failed: {error}"));
        return Ok(report);
    }
    if timed_out {
        report.status = ReplayStatus::TimedOut;
        report.diagnostic = Some("wall-clock budget exhausted".into());
        return Ok(report);
    }
    if output_limited || exceeded.load(Ordering::Relaxed) {
        report.status = ReplayStatus::OutputLimit;
        report.diagnostic = Some("captured output exceeded budget".into());
        return Ok(report);
    }
    let status = read_bwrap_status(&mut status_file)?;
    let Some(exit_code) = status else {
        report.diagnostic = Some("Bubblewrap did not confirm child execution and exit".into());
        return Ok(report);
    };
    report.exit_code = Some(exit_code);
    if exit_code >= 128 {
        report.diagnostic =
            Some("exit value may encode a signal; Bubblewrap does not distinguish it".into());
    }
    let stdout_goal = input
        .goal
        .stdout_contains_hex
        .as_ref()
        .map(|hex| decode_hex(hex, 4096))
        .transpose()?;
    let stderr_goal = input
        .goal
        .stderr_contains_hex
        .as_ref()
        .map(|hex| decode_hex(hex, 4096))
        .transpose()?;
    let matched = input
        .goal
        .exit_code
        .is_none_or(|wanted| wanted == exit_code)
        && stdout_goal
            .as_ref()
            .is_none_or(|needle| contains(&stdout_bytes, needle))
        && stderr_goal
            .as_ref()
            .is_none_or(|needle| contains(&stderr_bytes, needle));
    report.status = if matched {
        ReplayStatus::GoalMatched
    } else {
        ReplayStatus::GoalMismatched
    };
    Ok(report)
}

fn read_bounded(
    mut stream: impl Read + Send + 'static,
    cap: usize,
    exceeded: Arc<AtomicBool>,
    output_seen: Arc<AtomicUsize>,
) -> thread::JoinHandle<Result<Vec<u8>, String>> {
    thread::spawn(move || {
        let mut data = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let size = stream
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if size == 0 {
                break;
            }
            let previous = output_seen.fetch_add(size, Ordering::Relaxed);
            let remaining = cap.saturating_sub(previous);
            data.extend_from_slice(&buffer[..size.min(remaining)]);
            if size > remaining {
                exceeded.store(true, Ordering::Relaxed);
                break;
            }
        }
        Ok(data)
    })
}

fn read_bwrap_status(file: &mut File) -> Result<Option<i32>, String> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(4097)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 4096 {
        return Ok(None);
    }
    let mut started = false;
    let mut exit = None;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let value: Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        if value.get("child-pid").and_then(Value::as_u64).is_some() {
            started = true;
        }
        if let Some(code) = value.get("exit-code").and_then(Value::as_i64) {
            exit = i32::try_from(code).ok();
        }
    }
    Ok(if started { exit } else { None })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn kill_group(pid: u32) {
    // SAFETY: pid is the spawned child's process-group ID after setpgid in pre_exec.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_requires_confirmed_start_and_exit() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"{\"child-pid\":321}\n{\"exit-code\":0}\n")
            .unwrap();
        assert_eq!(read_bwrap_status(&mut file).unwrap(), Some(0));
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"{\"exit-code\":0}\n").unwrap();
        assert_eq!(read_bwrap_status(&mut file).unwrap(), None);
    }
}
