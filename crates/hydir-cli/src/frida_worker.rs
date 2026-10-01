//! Lifecycle and pipe transport for the separately packaged WSL2 distribution.
use hydir_frida_observer::transport::{
    FRIDA_VERSION, PROTOCOL_VERSION, WorkerStatus, write_request,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    error::Error,
    fs,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const DISTRO: &str = "HydIR-Frida-v1";
const HELPER: &str = "/opt/hydir/hydir-frida-observer";
const ROOTFS: &str = "rootfs.tar.gz";

pub(super) fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args {
        [operation] if operation == "status" => {}
        [operation] if operation == "install" => install()?,
        _ => return Err("usage: hydirctl frida-worker <status|install>".into()),
    }
    println!("{}", serde_json::to_string_pretty(&status())?);
    Ok(())
}

fn wsl() -> Command {
    // Do not resolve a project-local executable named wsl.exe.
    let system = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let mut command = Command::new(system.join("System32/wsl.exe"));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    command.current_dir(env::temp_dir());
    command
}

fn worker_command() -> Command {
    let mut command = wsl();
    command.args([
        "--distribution",
        DISTRO,
        "--user",
        "hydir",
        "--cd",
        "/home/hydir",
        "--exec",
    ]);
    command
}

// WSL's management output is UTF-16LE on some Windows releases; Linux stdout is UTF-8.
fn management_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.iter().take(128).any(|byte| *byte == 0) {
        String::from_utf16_lossy(
            &bytes
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect::<Vec<_>>(),
        )
        .trim_start_matches('\u{feff}')
        .trim()
        .to_owned()
    } else {
        String::from_utf8_lossy(bytes).trim().to_owned()
    }
}

fn control(command: &mut Command, timeout: Duration) -> Result<Output, Box<dyn Error>> {
    let mut stdout = tempfile::tempfile()?;
    let mut stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(match result {
                    Err(error) => error.to_string(),
                    _ => "WSL worker command timed out; check its status before retrying".into(),
                }
                .into());
            }
        }
    };
    stdout.rewind()?;
    stderr.rewind()?;
    Ok(Output {
        status,
        stdout: super::read_limited(stdout, 65536)?,
        stderr: super::read_limited(stderr, 65536)?,
    })
}

fn distribution_names() -> Result<Vec<String>, Box<dyn Error>> {
    let output = control(wsl().args(["--list", "--quiet"]), Duration::from_secs(10))?;
    if !output.status.success() {
        return Err("WSL2 is not available. In Administrator PowerShell run: wsl --install --no-distribution. Restart Windows if requested, then recheck the worker.".into());
    }
    Ok(management_text(&output.stdout)
        .lines()
        .map(|name| name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .collect())
}

fn bundle_dir() -> Result<PathBuf, Box<dyn Error>> {
    let directory = match env::var_os("HYDIR_FRIDA_WORKER_BUNDLE") {
        Some(path) => PathBuf::from(path),
        None => env::current_exe()?
            .parent()
            .ok_or("No executable directory")?
            .join("workers")
            .join("frida"),
    };
    // Management commands run from the temporary directory, so resolve a
    // developer's relative override before passing the archive to wsl.exe.
    Ok(absolute_bundle_dir(directory, &env::current_dir()?))
}

fn absolute_bundle_dir(directory: PathBuf, working_directory: &Path) -> PathBuf {
    let directory = if directory.is_absolute() {
        directory
    } else {
        working_directory.join(directory)
    };
    // wsl.exe --import rejects mixed separators even though Windows file I/O accepts them.
    directory.components().collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    target: String,
    protocol_version: u32,
    frida_version: String,
    rootfs_sha256: String,
}

fn manifest(directory: &Path) -> Result<Manifest, Box<dyn Error>> {
    let bytes = super::read_bounded_json(directory.join("manifest.json"), 4096)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.schema_version != 1
        || manifest.target != "windows-wsl2-x86_64"
        || manifest.protocol_version != PROTOCOL_VERSION
        || manifest.frida_version != FRIDA_VERSION
        || manifest.rootfs_sha256.len() != 64
        || !manifest
            .rootfs_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("Incompatible Frida worker bundle manifest".into());
    }
    if !directory.join(ROOTFS).is_file() {
        return Err("Frida worker rootfs is missing".into());
    }
    Ok(manifest)
}

fn verify_bundle(directory: &Path) -> Result<Manifest, Box<dyn Error>> {
    let manifest = manifest(directory)?;
    let mut file = fs::File::open(directory.join(ROOTFS))?;
    if file.metadata()?.len() > 2 * 1024 * 1024 * 1024u64 {
        return Err("Frida worker rootfs exceeds 2 GiB".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    if format!("{:x}", hash.finalize()) != manifest.rootfs_sha256 {
        return Err("Frida worker rootfs SHA-256 mismatch; restore the release bundle".into());
    }
    Ok(manifest)
}

fn check_doctor(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    if value["worker"] != "hydir-frida-wsl"
        || value["protocol_version"] != PROTOCOL_VERSION
        || value["frida_version"] != FRIDA_VERSION
    {
        return Err("Installed Frida worker has an incompatible identity/version".into());
    }
    if !value["kernel"]
        .as_str()
        .is_some_and(|kernel| kernel.to_ascii_lowercase().contains("wsl2"))
    {
        return Err(
            "HydIR Frida requires WSL2; this distribution is not using a WSL2 kernel".into(),
        );
    }
    if value["isolation_ready"] != true {
        return Err(
            "Worker found, but its Bubblewrap isolation probe failed. Observation is disabled."
                .into(),
        );
    }
    Ok(())
}

pub(super) fn status() -> WorkerStatus {
    let mut report = WorkerStatus {
        ready: false,
        mode: "unsupported".into(),
        installed: false,
        can_install: false,
        detail: "Frida observation requires x86-64 Linux or Windows with the WSL2 worker.".into(),
    };
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        report.mode = "linux".into();
        report.installed = super::frida::helper_path().is_ok_and(|path| path.is_file());
        report.ready = super::probe_bubblewrap_isolation()
            && super::frida::helper_path().is_ok_and(|path| super::frida::helper_ready(&path));
        report.detail = if report.ready {
            "Frida 17.9.5 · Linux observer ready"
        } else {
            "Install the Linux Frida bundle and enable working Bubblewrap user/network namespaces."
        }
        .into();
        return report;
    }
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return report;
    }
    report.mode = "wsl2".into();
    let result = (|| -> Result<(), Box<dyn Error>> {
        let names = distribution_names()?;
        report.installed = names.iter().any(|name| name == DISTRO);
        if !report.installed {
            let directory = bundle_dir()?;
            if manifest(&directory).is_err() {
                return Err(format!("Frida worker bundle missing or incompatible at {}. Use the Windows release containing workers/frida.", directory.display()).into());
            }
            report.can_install = true;
            return Err(
                "Packaged Linux worker available. Install it once to enable Frida ELF observation."
                    .into(),
            );
        }
        let output = control(
            worker_command().args(["/usr/bin/timeout", "10", HELPER, "--worker-doctor"]),
            Duration::from_secs(15),
        )?;
        if !output.status.success() {
            return Err(format!(
                "Frida worker probe failed: {} {}",
                management_text(&output.stderr),
                management_text(&output.stdout)
            )
            .into());
        }
        check_doctor(&output.stdout)?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            report.ready = true;
            report.detail =
                "Frida 17.9.5 · WSL2 worker ready · Bubblewrap isolation verified".into();
        }
        Err(error) => report.detail = error.to_string(),
    }
    report
}

fn install() -> Result<(), Box<dyn Error>> {
    if !cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        return Err("Managed Frida worker installation requires Windows x86-64".into());
    }
    let names = distribution_names()?;
    if names.iter().any(|name| name == DISTRO) {
        let report = status();
        return if report.ready {
            Ok(())
        } else {
            Err(format!("Existing {DISTRO} was left intact: {}", report.detail).into())
        };
    }
    let directory = bundle_dir()?;
    verify_bundle(&directory)?;
    let local = env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is unavailable")?;
    let destination = PathBuf::from(local)
        .join("HydIR")
        .join("workers")
        .join("frida-v1");
    // Never overwrite or unregister an existing distro or leftover installation.
    if destination.exists() {
        return Err(format!(
            "Worker directory already exists: {}; inspect it before retrying installation",
            destination.display()
        )
        .into());
    }
    fs::create_dir_all(destination.parent().ok_or("No worker parent")?)?;
    let output = control(
        wsl()
            .arg("--import")
            .arg(DISTRO)
            .arg(&destination)
            .arg(directory.join(ROOTFS))
            .args(["--version", "2"]),
        Duration::from_secs(180),
    )?;
    if !output.status.success() {
        return Err(format!(
            "WSL2 worker import failed: {} {}",
            management_text(&output.stderr),
            management_text(&output.stdout)
        )
        .into());
    }
    let report = status();
    if !report.ready {
        return Err(report.detail.into());
    }
    Ok(())
}

pub(super) fn observation(
    elf: &[u8],
    input: &[u8],
    function: u64,
    timeout_ms: u64,
) -> Result<(Command, String), Box<dyn Error>> {
    let report = status();
    if !report.ready {
        return Err(report.detail.into());
    }
    let token = uuid::Uuid::new_v4().simple().to_string();
    let mut request = tempfile::tempfile()?;
    write_request(&mut request, elf, input, function)?;
    request.seek(SeekFrom::Start(0))?;
    let mut command = worker_command();
    command.args([
        "/usr/bin/timeout",
        "--signal=KILL",
        &timeout_ms.div_ceil(1000).saturating_add(6).to_string(),
        HELPER,
        "--request",
        &token,
    ]);
    command.stdin(request);
    Ok((command, token))
}

pub(super) fn cancel(token: &str) {
    // Cancel only this request, never shut down a user's other WSL work.
    let _ = control(
        worker_command().args(["/usr/bin/timeout", "1", HELPER, "--cancel", token]),
        Duration::from_millis(1800),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    #[test]
    fn wsl_import_bundle_paths_use_windows_separators() {
        let working = Path::new(r"C:\HydIR checkout");
        for directory in [
            PathBuf::from("target/debug/workers/frida"),
            PathBuf::from("C:/HydIR checkout/target/debug/workers/frida"),
        ] {
            assert_eq!(
                absolute_bundle_dir(directory, working).as_os_str(),
                std::ffi::OsStr::new(r"C:\HydIR checkout\target\debug\workers\frida")
            );
        }
    }

    #[test]
    fn relative_bundle_override_keeps_the_callers_directory() {
        let working = env::current_dir().unwrap();
        assert_eq!(
            absolute_bundle_dir(PathBuf::from("worker bundle"), &working),
            working.join("worker bundle")
        );
        assert_eq!(
            absolute_bundle_dir(working.join("worker bundle"), &env::temp_dir()),
            working.join("worker bundle")
        );
    }
    #[test]
    fn decodes_both_wsl_output_encodings() {
        let encoded: Vec<_> = format!("\u{feff}{DISTRO}\r\n")
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(management_text(&encoded), DISTRO);
        assert_eq!(management_text(format!("{DISTRO}\n").as_bytes()), DISTRO);
    }
    #[test]
    fn readiness_requires_protocol_kernel_version_and_isolation() {
        let good = serde_json::json!({"worker":"hydir-frida-wsl", "protocol_version":1, "frida_version":FRIDA_VERSION, "kernel":"6.6.87.2-microsoft-standard-WSL2", "isolation_ready":true});
        assert!(check_doctor(&serde_json::to_vec(&good).unwrap()).is_ok());
        for (key, value) in [
            ("isolation_ready", serde_json::json!(false)),
            ("protocol_version", serde_json::json!(2)),
            ("kernel", serde_json::json!("4.4.0-Microsoft")),
            ("frida_version", serde_json::json!("0.0")),
        ] {
            let mut invalid = good.clone();
            invalid[key] = value;
            assert!(check_doctor(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
    }
    #[test]
    fn refuses_modified_or_incompatible_rootfs_before_import() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = b"test archive";
        fs::write(dir.path().join(ROOTFS), rootfs).unwrap();
        let mut info = serde_json::json!({"schema_version":1,"target":"windows-wsl2-x86_64","protocol_version":1,"frida_version":FRIDA_VERSION,"rootfs_sha256":format!("{:x}",Sha256::digest(rootfs))});
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        assert!(verify_bundle(dir.path()).is_ok());
        fs::write(dir.path().join(ROOTFS), b"modified").unwrap();
        assert!(verify_bundle(dir.path()).is_err());
        info["target"] = "other".into();
        fs::write(
            dir.path().join("manifest.json"),
            serde_json::to_vec(&info).unwrap(),
        )
        .unwrap();
        assert!(verify_bundle(dir.path()).is_err());
    }
}
