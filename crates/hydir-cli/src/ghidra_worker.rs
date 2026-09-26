//! Automatic, bounded Ghidra headless frontend. The Java script only exports
//! analyzed project facts; all snapshot validation and lifting stays in Rust.

use hydir_backend::MAX_BINARY_BYTES;
use hydir_ir::pcode::{GhidraSnapshot, MAX_GHIDRA_SNAPSHOT_BYTES, parse_ghidra_snapshot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const GHIDRA_VERSION: &str = "12.1.4";
const DOCKERFILE: &str = include_str!("../../../integrations/ghidra/Dockerfile.worker");
const EXPORTER: &str = include_str!("../../../integrations/ghidra/HydIRSnapshot.java");
const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const BUILD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const DOCKER_LOG_BYTES: u64 = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    schema_version: u32,
    key: String,
    snapshot_sha256: String,
}

fn digest_file(path: &Path) -> Result<String, String> {
    let mut file =
        File::open(path).map_err(|e| format!("cannot open binary {}: {e}", path.display()))?;
    let mut hash = Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut chunk)
            .map_err(|e| format!("cannot read binary: {e}"))?;
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn snapshot_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let size = fs::metadata(path)
        .map_err(|e| format!("Ghidra did not create snapshot {}: {e}", path.display()))?
        .len();
    if size == 0 || size > MAX_GHIDRA_SNAPSHOT_BYTES as u64 {
        return Err(format!(
            "Ghidra snapshot size {size} exceeds Hydir's 16 MiB limit"
        ));
    }
    fs::read(path).map_err(|e| format!("cannot read Ghidra snapshot: {e}"))
}

fn selected_offset(snapshot: &GhidraSnapshot) -> Result<u64, String> {
    let text = snapshot
        .selected_function
        .entry
        .offset
        .trim_start_matches("0x");
    u64::from_str_radix(text, 16).map_err(|_| "invalid selected function entry".to_owned())
}

fn validate_output(
    bytes: &[u8],
    binary_digest: &str,
    selected_entry: Option<u64>,
) -> Result<GhidraSnapshot, String> {
    let snapshot = parse_ghidra_snapshot(bytes, binary_digest)?;
    if snapshot.program.ghidra_version != GHIDRA_VERSION {
        return Err(format!(
            "Ghidra worker version mismatch: expected {GHIDRA_VERSION}, got {}",
            snapshot.program.ghidra_version
        ));
    }
    if let Some(entry) = selected_entry {
        if selected_offset(&snapshot)? != entry {
            return Err(format!(
                "Ghidra selected 0x{:x} instead of requested 0x{entry:x}",
                selected_offset(&snapshot)?
            ));
        }
    }
    Ok(snapshot)
}

fn cache_key(binary_digest: &str, selected_entry: Option<u64>, mode: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"hydir-ghidra-worker-v1\0");
    hash.update(GHIDRA_VERSION.as_bytes());
    hash.update(b"\0raw-pcode-flow-overrides\0");
    hash.update(binary_digest.as_bytes());
    hash.update(b"\0");
    hash.update(EXPORTER.as_bytes());
    hash.update(b"\0");
    hash.update(DOCKERFILE.as_bytes());
    hash.update(b"\0");
    hash.update(mode.as_bytes());
    hash.update(b"\0");
    hash.update(format!("{selected_entry:?}").as_bytes());
    format!("{:x}", hash.finalize())
}

fn cache_path(output: &Path) -> PathBuf {
    let mut path = output.as_os_str().to_os_string();
    path.push(".hydir-cache.json");
    PathBuf::from(path)
}

fn lock_output(output: &Path) -> Result<File, String> {
    let mut path = output.as_os_str().to_os_string();
    path.push(".hydir-lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(PathBuf::from(path))
        .map_err(|e| format!("cannot open Ghidra output lock: {e}"))?;
    // An OS file lock is released when a crashed worker's process exits. It
    // serializes competing UI/CLI jobs pointed at the same output artifact.
    let deadline = Instant::now() + BUILD_TIMEOUT + ANALYSIS_TIMEOUT + Duration::from_secs(60);
    loop {
        match lock.try_lock() {
            Ok(()) => return Ok(lock),
            Err(std::fs::TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "timed out waiting for Ghidra output lock {}",
                        output.display()
                    ));
                }
                thread::sleep(Duration::from_millis(200));
            }
            Err(error) => {
                return Err(format!(
                    "cannot lock Ghidra output {}: {error}",
                    output.display()
                ));
            }
        }
    }
}

fn try_cached(
    output: &Path,
    binary_digest: &str,
    selected_entry: Option<u64>,
    key: &str,
) -> Option<GhidraSnapshot> {
    let record: CacheRecord = serde_json::from_slice(&fs::read(cache_path(output)).ok()?).ok()?;
    if record.schema_version != 1 || record.key != key {
        return None;
    }
    let bytes = snapshot_bytes(output).ok()?;
    if format!("{:x}", Sha256::digest(&bytes)) != record.snapshot_sha256 {
        return None;
    }
    validate_output(&bytes, binary_digest, selected_entry).ok()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| format!("cannot stage {}: {e}", path.display()))?;
    staged
        .write_all(bytes)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    staged
        .flush()
        .map_err(|e| format!("cannot flush {}: {e}", path.display()))?;
    staged
        .persist(path)
        .map_err(|e| format!("cannot publish {}: {e}", path.display()))?;
    Ok(())
}

fn log_tail(path: &Path) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let Ok(size) = file.metadata().map(|m| m.len()) else {
        return String::new();
    };
    let _ = file.seek(SeekFrom::Start(size.saturating_sub(DOCKER_LOG_BYTES)));
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    String::from_utf8_lossy(&bytes).into_owned()
}

fn run_bounded(
    command: &mut Command,
    action: &str,
    timeout: Duration,
    log_path: &Path,
    container_name: Option<&str>,
) -> Result<(), String> {
    let log = File::create(log_path).map_err(|e| format!("cannot create Ghidra log: {e}"))?;
    let err = log
        .try_clone()
        .map_err(|e| format!("cannot clone Ghidra log: {e}"))?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(err))
        .spawn()
        .map_err(|e| format!("cannot start {action}: {e}"))?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return Ok(()),
            Ok(Some(status)) => {
                return Err(format!("{action} exited {status}: {}", log_tail(log_path)));
            }
            Ok(None) if Instant::now() >= deadline => {
                if let Some(name) = container_name {
                    let _ = Command::new("docker")
                        .args(["rm", "--force", name])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                #[cfg(windows)]
                if container_name.is_none() {
                    // analyzeHeadless.bat starts Java as a child process. Killing
                    // only cmd.exe would leave an unbounded analyzer behind.
                    let _ = Command::new("taskkill")
                        .args(["/PID", &child.id().to_string(), "/T", "/F"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{action} timed out after {}s: {}",
                    timeout.as_secs(),
                    log_tail(log_path)
                ));
            }
            Ok(None) => thread::sleep(Duration::from_millis(200)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot monitor {action}: {error}"));
            }
        }
    }
}

fn image_tag() -> String {
    let mut hash = Sha256::new();
    hash.update(DOCKERFILE.as_bytes());
    hash.update(EXPORTER.as_bytes());
    let hex = format!("{:x}", hash.finalize());
    format!("hydir-ghidra:12.1.4-{}", &hex[..16])
}

fn provision_image(work: &Path) -> Result<String, String> {
    let info = Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .map_err(|e| format!("Docker is required for automatic Ghidra analysis: {e}; install and start Docker, or set HYDIR_GHIDRA_HOME to a local Ghidra 12.1.4 installation"))?;
    if !info.status.success() {
        return Err(format!(
            "Docker engine is unavailable: {}; start Docker or set HYDIR_GHIDRA_HOME",
            String::from_utf8_lossy(&info.stderr).trim()
        ));
    }
    let tag = image_tag();
    if Command::new("docker")
        .args(["image", "inspect", &tag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
    {
        return Ok(tag);
    }
    let context = work.join("build-context");
    fs::create_dir(&context).map_err(|e| format!("cannot create Ghidra build context: {e}"))?;
    fs::write(context.join("Dockerfile"), DOCKERFILE)
        .map_err(|e| format!("cannot stage Ghidra Dockerfile: {e}"))?;
    fs::write(context.join("HydIRSnapshot.java"), EXPORTER)
        .map_err(|e| format!("cannot stage Ghidra exporter: {e}"))?;
    let mut build = Command::new("docker");
    build.arg("build").arg("--tag").arg(&tag).arg(&context);
    run_bounded(
        &mut build,
        "building pinned Ghidra worker image",
        BUILD_TIMEOUT,
        &work.join("build.log"),
        None,
    )?;
    Ok(tag)
}

fn script_args(selected_entry: Option<u64>, snapshot: &str, binary: &str) -> Vec<String> {
    let mut args = vec![
        "-postScript".to_owned(),
        "HydIRSnapshot.java".to_owned(),
        snapshot.to_owned(),
        binary.to_owned(),
    ];
    if let Some(entry) = selected_entry {
        args.push(format!("0x{entry:x}"));
    }
    args
}

fn docker_run_args(
    tag: &str,
    name: &str,
    binary: &Path,
    work: &Path,
    selected_entry: Option<u64>,
) -> Vec<String> {
    let mut args = vec![
        "run".into(),
        "--rm".into(),
        "--name".into(),
        name.into(),
        "--network".into(),
        "none".into(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--cpus".into(),
        "2".into(),
        "--memory".into(),
        "4g".into(),
        "--memory-swap".into(),
        "4g".into(),
        "--pids-limit".into(),
        "256".into(),
        "--tmpfs".into(),
        "/tmp:rw,nosuid,nodev,size=512m".into(),
        "--tmpfs".into(),
        "/home/hydir:rw,nosuid,nodev,size=256m,mode=1777".into(),
        "--mount".into(),
        format!(
            "type=bind,source={},target=/input/binary,readonly",
            binary.display()
        ),
        "--mount".into(),
        format!("type=bind,source={},target=/work", work.display()),
        tag.into(),
        "/work/projects".into(),
        "HydirAuto".into(),
        "-import".into(),
        "/input/binary".into(),
        "-scriptPath".into(),
        "/opt/hydir/scripts".into(),
        "-deleteProject".into(),
    ];
    args.extend(script_args(
        selected_entry,
        "/work/snapshot.json",
        "/input/binary",
    ));
    args
}

fn local_analyze(
    home: &Path,
    binary: &Path,
    work: &Path,
    selected_entry: Option<u64>,
) -> Result<(), String> {
    fs::create_dir_all(work.join("projects"))
        .map_err(|e| format!("cannot create Ghidra project directory: {e}"))?;
    let script_dir = work.join("scripts");
    fs::create_dir(&script_dir)
        .map_err(|e| format!("cannot create Ghidra script directory: {e}"))?;
    fs::write(script_dir.join("HydIRSnapshot.java"), EXPORTER)
        .map_err(|e| format!("cannot stage Ghidra exporter: {e}"))?;
    let executable = home.join("support").join(if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    });
    if !executable.is_file() {
        return Err(format!("HYDIR_GHIDRA_HOME lacks {}", executable.display()));
    }
    let snapshot = work.join("snapshot.json");
    let mut command = Command::new(&executable);
    command
        .arg(work.join("projects"))
        .arg("HydirAuto")
        .arg("-import")
        .arg(binary)
        .arg("-scriptPath")
        .arg(&script_dir)
        .arg("-deleteProject");
    command.args(script_args(
        selected_entry,
        &snapshot.display().to_string(),
        &binary.display().to_string(),
    ));
    run_bounded(
        &mut command,
        "Ghidra headless analysis",
        ANALYSIS_TIMEOUT,
        &work.join("analysis.log"),
        None,
    )
}

fn docker_analyze(binary: &Path, work: &Path, selected_entry: Option<u64>) -> Result<(), String> {
    let tag = provision_image(work)?;
    let staging = work.join("container-work");
    fs::create_dir(&staging).map_err(|e| format!("cannot stage Ghidra project: {e}"))?;
    let projects = staging.join("projects");
    fs::create_dir(&projects).map_err(|e| format!("cannot stage Ghidra project directory: {e}"))?;
    // The image runs as uid 10001. The private outer temporary directory still
    // limits host access, while this bind-mounted leaf is writable by that uid.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o777))
            .map_err(|e| format!("cannot grant Ghidra scratch access: {e}"))?;
        fs::set_permissions(&projects, fs::Permissions::from_mode(0o777))
            .map_err(|e| format!("cannot grant Ghidra project access: {e}"))?;
    }
    let name = format!(
        "hydir-ghidra-{}-{}",
        std::process::id(),
        work.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
    );
    let args = docker_run_args(&tag, &name, binary, &staging, selected_entry);
    let mut command = Command::new("docker");
    command.args(&args);
    let result = run_bounded(
        &mut command,
        "Ghidra container analysis",
        ANALYSIS_TIMEOUT,
        &work.join("analysis.log"),
        Some(&name),
    );
    if result.is_ok() {
        fs::copy(staging.join("snapshot.json"), work.join("snapshot.json"))
            .map_err(|e| format!("Ghidra did not export a snapshot: {e}"))?;
    }
    result
}

/// Import and analyze a binary without requiring a user-operated Ghidra step.
/// A validated output plus matching sidecar is reused; otherwise an isolated
/// headless job produces a fresh snapshot. HYDIR_GHIDRA_HOME opts into local
/// Ghidra for development; the default provisions the pinned Docker worker.
pub fn analyze(
    binary: &Path,
    selected_entry: Option<u64>,
    output: &Path,
) -> Result<GhidraSnapshot, String> {
    let binary = fs::canonicalize(binary)
        .map_err(|e| format!("cannot resolve binary {}: {e}", binary.display()))?;
    if !binary.is_file() {
        return Err(format!(
            "input is not a regular binary file: {}",
            binary.display()
        ));
    }
    let output_abs = if output.is_absolute() {
        output.to_owned()
    } else {
        env::current_dir()
            .map_err(|e| format!("cannot resolve output directory: {e}"))?
            .join(output)
    };
    let parent = output_abs
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| "snapshot output needs a filename".to_owned())?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create output directory: {e}"))?;
    let output_abs = fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve output directory: {e}"))?
        .join(
            output_abs
                .file_name()
                .ok_or_else(|| "snapshot output needs a filename".to_owned())?,
        );
    if output_abs == binary
        || (output_abs.exists()
            && fs::canonicalize(&output_abs).is_ok_and(|canonical| canonical == binary))
    {
        return Err("snapshot output must not replace the input binary".into());
    }
    let size = fs::metadata(&binary)
        .map_err(|e| format!("cannot stat binary: {e}"))?
        .len();
    if size == 0 || size > MAX_BINARY_BYTES as u64 {
        return Err(format!(
            "binary size {size} exceeds Hydir's 64 MiB input limit"
        ));
    }
    let binary_digest = digest_file(&binary)?;
    let local_home = env::var_os("HYDIR_GHIDRA_HOME");
    let mode = if local_home.is_some() {
        "local-12.1.4"
    } else {
        "docker-12.1.4"
    };
    let key = cache_key(&binary_digest, selected_entry, mode);
    let _output_lock = lock_output(&output_abs)?;
    if let Some(snapshot) = try_cached(&output_abs, &binary_digest, selected_entry, &key) {
        return Ok(snapshot);
    }
    let scratch = tempfile::Builder::new()
        .prefix("hydir-ghidra-")
        .tempdir()
        .map_err(|e| format!("cannot create Ghidra scratch directory: {e}"))?;
    if let Some(home) = local_home {
        local_analyze(Path::new(&home), &binary, scratch.path(), selected_entry)?;
    } else {
        docker_analyze(&binary, scratch.path(), selected_entry)?;
    }
    let bytes = snapshot_bytes(&scratch.path().join("snapshot.json")).map_err(|e| {
        format!(
            "{e}; headless log: {}",
            log_tail(&scratch.path().join("analysis.log"))
        )
    })?;
    let snapshot = validate_output(&bytes, &binary_digest, selected_entry).map_err(|e| {
        format!(
            "{e}; headless log: {}",
            log_tail(&scratch.path().join("analysis.log"))
        )
    })?;
    atomic_write(&output_abs, &bytes)?;
    let record = CacheRecord {
        schema_version: 1,
        key,
        snapshot_sha256: format!("{:x}", Sha256::digest(&bytes)),
    };
    atomic_write(
        &cache_path(&output_abs),
        &serde_json::to_vec(&record)
            .map_err(|e| format!("cannot encode Ghidra cache record: {e}"))?,
    )?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_args_isolate_worker_and_preserve_selected_address() {
        let args = docker_run_args(
            "hydir-ghidra:test",
            "hydir-test",
            Path::new("/tmp/input"),
            Path::new("/tmp/scratch"),
            Some(0x401080),
        );
        assert!(args.windows(2).any(|w| w == ["--network", "none"]));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(
            args.iter()
                .any(|a| a.contains("target=/input/binary,readonly"))
        );
        assert!(args.iter().any(|a| a == "no-new-privileges"));
        assert_eq!(args.last().unwrap(), "0x401080");
    }

    #[test]
    fn cache_key_tracks_binary_function_and_exporter() {
        assert_ne!(
            cache_key(&"a".repeat(64), None, "docker"),
            cache_key(&"b".repeat(64), None, "docker")
        );
        assert_ne!(
            cache_key(&"a".repeat(64), None, "docker"),
            cache_key(&"a".repeat(64), Some(1), "docker")
        );
        assert_ne!(
            cache_key(&"a".repeat(64), None, "docker"),
            cache_key(&"a".repeat(64), None, "local")
        );
    }

    #[test]
    fn invalid_cached_output_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let output = dir.path().join("snapshot.json");
        fs::write(&output, b"{}").unwrap();
        let key = cache_key(&"a".repeat(64), None, "docker");
        let record = CacheRecord {
            schema_version: 1,
            key: key.clone(),
            snapshot_sha256: format!("{:x}", Sha256::digest(b"{}")),
        };
        fs::write(cache_path(&output), serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(try_cached(&output, &"a".repeat(64), None, &key).is_none());
    }
}
