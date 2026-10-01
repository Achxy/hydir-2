//! Entrypoints used by the Windows host. The target still runs through observe()
//! and its private Bubblewrap namespaces, resource limits and witness checks.
use crate::transport::{FRIDA_VERSION, PROTOCOL_VERSION, read_request};
use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

pub fn doctor() -> Result<(), String> {
    let isolation = Command::new("/usr/bin/timeout")
        .args([
            "5",
            "bwrap",
            "--unshare-user",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-ipc",
            "--unshare-uts",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success());
    let _frida = unsafe { frida::Frida::obtain() };
    println!(
        "{}",
        serde_json::json!({
            "worker": "hydir-frida-wsl", "protocol_version": PROTOCOL_VERSION,
            "frida_version": frida::Frida::version(), "isolation_ready": isolation,
            "kernel": fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim(),
        })
    );
    if frida::Frida::version() != FRIDA_VERSION {
        return Err("Frida version mismatch".into());
    }
    Ok(())
}

fn job_path(token: &str) -> Result<PathBuf, String> {
    if token.len() != 32 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Invalid Frida worker job ID".into());
    }
    // Installed by the rootfs builder with owner hydir and mode 0700. It is not
    // mounted into the target's namespace, and is never resolved from target input.
    Ok(PathBuf::from("/home/hydir/.cache/hydir-frida").join(token))
}

struct Job(PathBuf);
impl Drop for Job {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn request(token: &str) -> Result<(), String> {
    let path = job_path(token)?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("Cannot register worker job: {error}"))?;
    let _job = Job(path);
    writeln!(file, "{}", std::process::id()).map_err(|error| error.to_string())?;
    let request = read_request(std::io::stdin().lock())?;
    let input = hydir_execution::parse_input_spec(&request.input)?;
    let trace = crate::observe(&request.elf, &input, request.function)?;
    println!(
        "{}",
        serde_json::to_string(&trace).map_err(|error| error.to_string())?
    );
    Ok(())
}

pub fn cancel(token: &str) -> Result<(), String> {
    let path = job_path(token)?;
    let mut contents = String::new();
    match fs::File::open(&path) {
        Ok(file) => {
            file.take(32)
                .read_to_string(&mut contents)
                .map_err(|e| e.to_string())?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    }
    let pid: i32 = contents.trim().parse().map_err(|_| "Invalid worker PID")?;
    if pid <= 1 {
        return Err("Invalid worker PID".into());
    }
    // Do not kill a reused PID. Both argument boundaries and the per-request
    // random token must match the process we registered.
    let cmdline = fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
    let args: Vec<_> = cmdline
        .split(|byte| *byte == 0)
        .filter(|arg| !arg.is_empty())
        .collect();
    if args.len() == 3
        && args[0] == b"/opt/hydir/hydir-frida-observer"
        && args[1] == b"--request"
        && args[2] == token.as_bytes()
    {
        // Bubblewrap --die-with-parent tears down the observed process too.
        if unsafe { libc::kill(pid, libc::SIGKILL) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
    }
    let _ = fs::remove_file(path);
    Ok(())
}
