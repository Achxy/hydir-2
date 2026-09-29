//! Automatic, bounded Ghidra headless frontend. The Java script only exports
//! analyzed project facts; all snapshot validation and lifting stays in Rust.

use hydir_backend::MAX_BINARY_BYTES;
use hydir_ir::pcode::{GhidraSnapshot, MAX_GHIDRA_SNAPSHOT_BYTES, parse_ghidra_snapshot};
use quick_xml::{
    Reader, Writer, XmlVersion,
    events::{BytesStart, Event},
};
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
const MAX_PROJECT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_PROJECT_ENTRIES: usize = 100_000;
const MAX_PROJECT_DEPTH: usize = 32;
const MAX_PROJECT_PROPERTY_BYTES: u64 = 64 * 1024;
const EXPERT_PROJECT_USER: &str = "hydir";
const EXPERT_JAVA_OPTIONS: &str = "-Duser.name=hydir";

fn offline_requested() -> bool {
    env::var_os("HYDIR_OFFLINE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

#[derive(Debug)]
struct ProjectSelector {
    headless_name: String,
    leaf: String,
    domain_path: String,
}

fn project_selector(project_name: &str, program: &str) -> Result<ProjectSelector, String> {
    if project_name.is_empty()
        || program.is_empty()
        || program.starts_with('/')
        || program.contains('\\')
        || program.contains(':')
    {
        return Err("program must be a project-relative path separated by /".into());
    }
    let parts: Vec<_> = program.split('/').collect();
    if parts.iter().any(|part| {
        part.is_empty()
            || *part == "."
            || *part == ".."
            || part
                .chars()
                .any(|ch| ch.is_control() || matches!(ch, '*' | '?' | '[' | ']'))
    }) {
        return Err(
            "program selector contains traversal, a wildcard, or an empty component".into(),
        );
    }
    let leaf = parts.last().unwrap().to_string();
    let headless_name = if parts.len() == 1 {
        project_name.to_owned()
    } else {
        format!("{project_name}/{}", parts[..parts.len() - 1].join("/"))
    };
    Ok(ProjectSelector {
        headless_name,
        leaf,
        domain_path: format!("/{program}"),
    })
}

fn checked_source_metadata(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("cannot inspect project entry {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Ghidra project contains a link: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(format!(
                "Ghidra project contains a reparse point: {}",
                path.display()
            ));
        }
    }
    Ok(metadata)
}

fn check_project_ancestors(path: &Path) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|e| format!("cannot resolve project path: {e}"))?
            .join(path)
    };
    for ancestor in absolute.ancestors() {
        checked_source_metadata(ancestor)?;
    }
    Ok(())
}

fn copy_project_file(source: &Path, target: &Path, remaining: &mut u64) -> Result<(), String> {
    let metadata = checked_source_metadata(source)?;
    if !metadata.is_file() {
        return Err(format!(
            "project entry is not a regular file: {}",
            source.display()
        ));
    }
    if metadata.len() > *remaining {
        return Err("Ghidra project exceeds 2 GiB staging limit".into());
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let mut input = options
        .open(source)
        .map_err(|e| format!("cannot open project entry {}: {e}", source.display()))?;
    if !input.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err(format!(
            "project entry changed while staging: {}",
            source.display()
        ));
    }
    let mut output = File::create(target)
        .map_err(|e| format!("cannot stage project entry {}: {e}", target.display()))?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = input
            .read(&mut buffer)
            .map_err(|e| format!("cannot read project entry {}: {e}", source.display()))?;
        if count == 0 {
            break;
        }
        if count as u64 > *remaining {
            return Err("Ghidra project exceeds 2 GiB staging limit".into());
        }
        *remaining -= count as u64;
        output
            .write_all(&buffer[..count])
            .map_err(|e| format!("cannot stage project entry {}: {e}", target.display()))?;
    }
    if metadata.len() != input.metadata().map_err(|e| e.to_string())?.len() {
        return Err(format!(
            "project entry changed while staging: {}",
            source.display()
        ));
    }
    Ok(())
}

fn owner_state(element: &BytesStart<'_>) -> Result<bool, String> {
    if element.name().as_ref() != b"STATE" {
        return Ok(false);
    }
    let mut name = None;
    let mut state_type = None;
    let mut value = None;
    let mut count = 0;
    for attribute in element.attributes() {
        let attribute = attribute.map_err(|e| format!("invalid Ghidra project owner XML: {e}"))?;
        let decoded = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|e| format!("invalid Ghidra project owner XML value: {e}"))?;
        match attribute.key.as_ref() {
            b"NAME" => name = Some(decoded.into_owned()),
            b"TYPE" => state_type = Some(decoded.into_owned()),
            b"VALUE" => value = Some(decoded.into_owned()),
            _ => {}
        }
        count += 1;
    }
    if name.as_deref() != Some("OWNER") {
        return Ok(false);
    }
    let owner = value.ok_or("Ghidra project OWNER state has no value")?;
    if count != 3
        || state_type.as_deref() != Some("string")
        || owner.is_empty()
        || owner.len() > 256
        || owner.chars().any(char::is_control)
    {
        return Err("Ghidra project OWNER state is malformed".into());
    }
    Ok(true)
}

fn normalized_project_owner_xml(bytes: &[u8]) -> Result<Vec<u8>, String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_PROJECT_PROPERTY_BYTES {
        return Err("Ghidra project.prp exceeds 64 KiB property limit".into());
    }
    std::str::from_utf8(bytes).map_err(|e| format!("Ghidra project.prp is not UTF-8 XML: {e}"))?;
    let mut reader = Reader::from_reader(bytes);
    let mut writer = Writer::new(Vec::new());
    let mut path: Vec<Vec<u8>> = Vec::new();
    let mut root_seen = false;
    let mut owner_count = 0;
    loop {
        let event = reader
            .read_event()
            .map_err(|e| format!("invalid Ghidra project.prp XML: {e}"))?;
        match event {
            Event::Start(ref element) => {
                if path.is_empty() {
                    if root_seen || element.name().as_ref() != b"FILE_INFO" {
                        return Err("Ghidra project.prp must have one FILE_INFO root".into());
                    }
                    root_seen = true;
                }
                if owner_state(element)? {
                    return Err("Ghidra project OWNER state must be an empty element".into());
                }
                path.push(element.name().as_ref().to_vec());
                writer.write_event(event).map_err(|e| e.to_string())?;
            }
            Event::Empty(ref element) => {
                if path.is_empty() {
                    return Err("Ghidra project.prp must have one FILE_INFO root".into());
                }
                if owner_state(element)? {
                    if path.as_slice() != [b"FILE_INFO".as_slice(), b"BASIC_INFO".as_slice()]
                        || owner_count != 0
                    {
                        return Err(
                            "Ghidra project.prp has misplaced or duplicate OWNER state".into()
                        );
                    }
                    owner_count += 1;
                    let mut replacement = BytesStart::new("STATE");
                    for attribute in element.attributes() {
                        let attribute = attribute
                            .map_err(|e| format!("invalid Ghidra project owner XML: {e}"))?;
                        if attribute.key.as_ref() == b"VALUE" {
                            replacement.push_attribute(("VALUE", EXPERT_PROJECT_USER));
                        } else {
                            replacement.push_attribute(attribute);
                        }
                    }
                    writer
                        .write_event(Event::Empty(replacement))
                        .map_err(|e| e.to_string())?;
                } else {
                    writer.write_event(event).map_err(|e| e.to_string())?;
                }
            }
            Event::End(ref element) => {
                if path.pop().as_deref() != Some(element.name().as_ref()) {
                    return Err("Ghidra project.prp has mismatched XML elements".into());
                }
                writer.write_event(event).map_err(|e| e.to_string())?;
            }
            Event::DocType(_) => return Err("Ghidra project.prp must not contain a DTD".into()),
            Event::Eof => break,
            _ => writer.write_event(event).map_err(|e| e.to_string())?,
        }
    }
    if !root_seen || !path.is_empty() || owner_count != 1 {
        return Err("Ghidra project.prp requires exactly one OWNER state".into());
    }
    let normalized = writer.into_inner();
    if normalized.len() as u64 > MAX_PROJECT_PROPERTY_BYTES {
        return Err("Ghidra project.prp exceeds 64 KiB property limit".into());
    }
    Ok(normalized)
}

fn normalize_staged_project_owner(repository: &Path) -> Result<(), String> {
    let property = repository.join("project.prp");
    let size = fs::metadata(&property)
        .map_err(|e| format!("Ghidra project lacks project.prp: {e}"))?
        .len();
    if size == 0 || size > MAX_PROJECT_PROPERTY_BYTES {
        return Err("Ghidra project.prp exceeds 64 KiB property limit".into());
    }
    let bytes =
        fs::read(&property).map_err(|e| format!("cannot read staged Ghidra project.prp: {e}"))?;
    let normalized = normalized_project_owner_xml(&bytes)?;
    atomic_write(&property, &normalized)
}

fn stage_closed_project(project_file: &Path, staging: &Path) -> Result<String, String> {
    if !project_file
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.eq_ignore_ascii_case("gpr"))
    {
        return Err("Ghidra project must be a .gpr file".into());
    }
    let name = project_file
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .ok_or("Ghidra project name must be valid UTF-8")?;
    let repository = project_file.with_extension("rep");
    check_project_ancestors(project_file)?;
    check_project_ancestors(&repository)?;
    if !checked_source_metadata(project_file)?.is_file()
        || !checked_source_metadata(&repository)?.is_dir()
    {
        return Err("Ghidra project needs a regular .gpr and matching .rep directory".into());
    }
    fs::create_dir(staging)
        .map_err(|e| format!("cannot create isolated Ghidra project staging: {e}"))?;
    let mut remaining = MAX_PROJECT_BYTES;
    copy_project_file(
        project_file,
        &staging.join(project_file.file_name().unwrap()),
        &mut remaining,
    )?;
    let staged_repository = staging.join(repository.file_name().unwrap());
    fs::create_dir(&staged_repository)
        .map_err(|e| format!("cannot stage Ghidra repository: {e}"))?;
    let mut entries = 1usize;
    let mut dirs = vec![(repository, staged_repository.clone(), 0usize)];
    while let Some((source, target, depth)) = dirs.pop() {
        checked_source_metadata(&source)?;
        for entry in fs::read_dir(&source)
            .map_err(|e| format!("cannot list project folder {}: {e}", source.display()))?
        {
            let entry = entry.map_err(|e| format!("cannot list project entry: {e}"))?;
            entries += 1;
            if entries > MAX_PROJECT_ENTRIES {
                return Err("Ghidra project exceeds 100,000 staging entries".into());
            }
            let source_path = entry.path();
            let target_path = target.join(entry.file_name());
            let metadata = checked_source_metadata(&source_path)?;
            if metadata.is_dir() {
                if depth >= MAX_PROJECT_DEPTH {
                    return Err("Ghidra project exceeds staging depth 32".into());
                }
                fs::create_dir(&target_path)
                    .map_err(|e| format!("cannot stage project folder: {e}"))?;
                dirs.push((source_path, target_path, depth + 1));
            } else if metadata.is_file() {
                copy_project_file(&source_path, &target_path, &mut remaining)?;
            } else {
                return Err(format!(
                    "unsupported Ghidra project entry: {}",
                    source_path.display()
                ));
            }
        }
    }
    normalize_staged_project_owner(&staged_repository)?;
    Ok(name.to_owned())
}

#[derive(Clone, Debug, Serialize)]
pub struct GhidraRuntimeStatus {
    pub mode: &'static str,
    pub pinned_version: &'static str,
    pub runtime_ready: bool,
    pub worker_image_cached: Option<bool>,
    pub detail: String,
}

fn bounded_status(command: &mut Command, timeout: Duration) -> Result<bool, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| error.to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            return Ok(status.success());
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("runtime probe exceeded five seconds".to_owned());
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Read-only setup probe for the managed frontend. This never builds an image
/// or runs analysis; successful output still requires snapshot validation.
pub fn runtime_status() -> GhidraRuntimeStatus {
    if let Some(home) = env::var_os("HYDIR_GHIDRA_HOME") {
        let executable = PathBuf::from(&home).join("support").join(if cfg!(windows) {
            "analyzeHeadless.bat"
        } else {
            "analyzeHeadless"
        });
        let ready = executable.is_file();
        return GhidraRuntimeStatus {
            mode: "local",
            pinned_version: GHIDRA_VERSION,
            runtime_ready: ready,
            worker_image_cached: None,
            detail: if ready {
                "Ghidra executable found; version and output are checked during analysis".to_owned()
            } else {
                format!("HYDIR_GHIDRA_HOME lacks {}", executable.display())
            },
        };
    }
    let check = bounded_status(
        Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"]),
        Duration::from_secs(5),
    );
    let ready = check.as_ref().is_ok_and(|available| *available);
    let tag = image_tag();
    let image_cached = ready.then(|| {
        bounded_status(
            Command::new("docker").args(["image", "inspect", &tag]),
            Duration::from_secs(5),
        )
        .unwrap_or(false)
    });
    let offline = offline_requested();
    GhidraRuntimeStatus {
        mode: "docker",
        pinned_version: GHIDRA_VERSION,
        runtime_ready: ready && (!offline || image_cached == Some(true)),
        worker_image_cached: image_cached,
        detail: match check {
            Ok(true) if offline && image_cached != Some(true) => {
                "HYDIR_OFFLINE=1 requires the pinned Ghidra worker image in Docker's local image store"
                    .to_owned()
            }
            Ok(true) if offline => {
                "Docker engine and pinned Ghidra worker image are available offline".to_owned()
            }
            Ok(true) => {
                "Docker engine reachable; Hydir provisions the pinned image on first analysis"
                    .to_owned()
            }
            Ok(false) => {
                "Docker engine did not accept a probe; start Docker or set HYDIR_GHIDRA_HOME"
                    .to_owned()
            }
            Err(error) => {
                format!("Docker engine unavailable: {error}; start Docker or set HYDIR_GHIDRA_HOME")
            }
        },
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheRecord {
    schema_version: u32,
    key: String,
    snapshot_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRecord {
    schema_version: u32,
    key: String,
    generation: String,
}

fn project_key(binary_digest: &str, mode: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"hydir-ghidra-project-v1\0");
    hash.update(GHIDRA_VERSION.as_bytes());
    hash.update(binary_digest.as_bytes());
    hash.update(EXPORTER.as_bytes());
    hash.update(DOCKERFILE.as_bytes());
    hash.update(mode.as_bytes());
    format!("{:x}", hash.finalize())
}

fn project_root(key: &str) -> Result<PathBuf, String> {
    #[cfg(target_os = "windows")]
    let base = env::var_os("LOCALAPPDATA").or_else(|| env::var_os("APPDATA"));
    #[cfg(target_os = "macos")]
    let base =
        env::var_os("HOME").map(|home| PathBuf::from(home).join("Library/Caches").into_os_string());
    #[cfg(target_os = "linux")]
    let base = env::var_os("XDG_CACHE_HOME").or_else(|| {
        env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").into_os_string())
    });
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    let base: Option<std::ffi::OsString> = None;
    let base = base.ok_or("cannot determine user cache directory for Ghidra projects")?;
    Ok(PathBuf::from(base)
        .join("HydIR")
        .join("ghidra-projects")
        .join(key))
}

fn existing_project(root: &Path, key: &str) -> Option<PathBuf> {
    let record: ProjectRecord =
        serde_json::from_slice(&fs::read(root.join("project.json")).ok()?).ok()?;
    if record.schema_version != 1
        || record.key != key
        || !record.generation.starts_with("generation-")
        || record.generation.len() <= 11
        || !record.generation[11..]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric())
    {
        return None;
    }
    let directory = root.join(record.generation);
    directory
        .join("HydirAuto.gpr")
        .is_file()
        .then_some(directory)
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

/// Recheck a persisted worker snapshot before using it as analysis input.
/// This includes the pinned Ghidra version and requested function selector.
pub fn validate_cached_snapshot(
    bytes: &[u8],
    binary_digest: &str,
    selected_entry: Option<u64>,
) -> Result<GhidraSnapshot, String> {
    validate_output(bytes, binary_digest, selected_entry)
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

/// Identity of the managed analysis for one binary and function selector.
/// Shared callers use this before launching Ghidra to locate a previously
/// validated snapshot. Exporter, image, version, and execution mode are part
/// of the identity, so changing any of them misses the old cache entry.
pub fn analysis_cache_key(binary_digest: &str, selected_entry: Option<u64>) -> String {
    let mode = if env::var_os("HYDIR_GHIDRA_HOME").is_some() {
        "local-12.1.4"
    } else {
        "docker-12.1.4"
    };
    cache_key(binary_digest, selected_entry, mode)
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
    let cancel_file = env::var_os("HYDIR_GHIDRA_CANCEL_FILE").map(PathBuf::from);
    run_bounded_with_cancel_file(
        command,
        action,
        timeout,
        log_path,
        container_name,
        cancel_file.as_deref(),
    )
}

fn run_bounded_with_cancel_file(
    command: &mut Command,
    action: &str,
    timeout: Duration,
    log_path: &Path,
    container_name: Option<&str>,
    cancel_file: Option<&Path>,
) -> Result<(), String> {
    let log = File::create(log_path).map_err(|e| format!("cannot create Ghidra log: {e}"))?;
    let err = log
        .try_clone()
        .map_err(|e| format!("cannot clone Ghidra log: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
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
            Ok(None) if cancel_file.is_some_and(|path| path.exists()) => {
                stop_bounded_child(&mut child, container_name);
                return Err(format!("{action} cancelled: {}", log_tail(log_path)));
            }
            Ok(None) if Instant::now() >= deadline => {
                stop_bounded_child(&mut child, container_name);
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

fn stop_bounded_child(child: &mut std::process::Child, container_name: Option<&str>) {
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
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
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
    if offline_requested() {
        return Err(format!(
            "HYDIR_OFFLINE=1: pinned Ghidra worker image {tag} is not cached; provision it before going offline or set HYDIR_GHIDRA_HOME"
        ));
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
    project: &Path,
    reuse_project: bool,
    selected_entry: Option<u64>,
    run_as: Option<&str>,
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
        "--mount".into(),
        format!("type=bind,source={},target=/project", project.display()),
    ];
    if let Some(user) = run_as {
        args.extend(["--user".into(), user.into()]);
    }
    args.extend([tag.into(), "/project".into(), "HydirAuto".into()]);
    if reuse_project {
        args.extend(["-process".into(), "-noanalysis".into()]);
    } else {
        args.extend(["-import".into(), "/input/binary".into()]);
    }
    args.extend(["-scriptPath".into(), "/opt/hydir/scripts".into()]);
    args.extend(script_args(
        selected_entry,
        "/work/snapshot.json",
        "/input/binary",
    ));
    args
}

fn docker_project_args(
    mut args: Vec<String>,
    tag: &str,
    selector: &ProjectSelector,
) -> Vec<String> {
    let image_index = args
        .iter()
        .position(|arg| arg == tag)
        .expect("image tag argument");
    args[image_index + 2] = selector.headless_name.clone();
    args.insert(image_index + 4, selector.leaf.clone());
    args.insert(image_index + 6, "-readOnly".into());
    args.push(format!("domainPath={}", selector.domain_path));
    args.splice(
        image_index..image_index,
        [
            "--env".into(),
            format!("JAVA_TOOL_OPTIONS={EXPERT_JAVA_OPTIONS}"),
        ],
    );
    args
}

fn local_analyze(
    home: &Path,
    binary: &Path,
    work: &Path,
    project: &Path,
    reuse_project: bool,
    selected_entry: Option<u64>,
    project_import: Option<&ProjectSelector>,
) -> Result<(), String> {
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
    if project_import.is_some() {
        command.env("JAVA_TOOL_OPTIONS", EXPERT_JAVA_OPTIONS);
    }
    command
        .arg(project)
        .arg(project_import.map_or("HydirAuto", |s| s.headless_name.as_str()));
    if let Some(selector) = project_import {
        command
            .arg("-process")
            .arg(&selector.leaf)
            .args(["-noanalysis", "-readOnly"]);
    } else if reuse_project {
        command.args(["-process", "-noanalysis"]);
    } else {
        command.arg("-import").arg(binary);
    }
    command.arg("-scriptPath").arg(&script_dir);
    command.args(script_args(
        selected_entry,
        &snapshot.display().to_string(),
        &binary.display().to_string(),
    ));
    if let Some(selector) = project_import {
        command.arg(format!("domainPath={}", selector.domain_path));
    }
    run_bounded(
        &mut command,
        "Ghidra headless analysis",
        ANALYSIS_TIMEOUT,
        &work.join("analysis.log"),
        None,
    )
}

fn docker_analyze(
    binary: &Path,
    work: &Path,
    project: &Path,
    reuse_project: bool,
    selected_entry: Option<u64>,
    project_import: Option<&ProjectSelector>,
) -> Result<(), String> {
    let tag = provision_image(work)?;
    let staging = work.join("container-work");
    fs::create_dir(&staging).map_err(|e| format!("cannot stage Ghidra project: {e}"))?;
    // On Unix, use the host user's uid/gid for bind-mounted output and project
    // files. A fixed image uid can write them but may leave mode-0600 snapshots
    // unreadable to the Rust process on the host.
    #[cfg(unix)]
    let run_as = {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(&staging)
            .map_err(|e| format!("cannot inspect Ghidra scratch owner: {e}"))?;
        (metadata.uid() != 0).then(|| format!("{}:{}", metadata.uid(), metadata.gid()))
    };
    #[cfg(not(unix))]
    let run_as: Option<String> = None;
    // If the host runs as root (or uses a non-Unix bind mount), keep the
    // image's uid 10001 and grant access only to the mounted leaf directories.
    #[cfg(unix)]
    if run_as.is_none() {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o777))
            .map_err(|e| format!("cannot grant Ghidra scratch access: {e}"))?;
        fs::set_permissions(project, fs::Permissions::from_mode(0o777))
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
    let mut args = docker_run_args(
        &tag,
        &name,
        binary,
        &staging,
        project,
        reuse_project,
        selected_entry,
        run_as.as_deref(),
    );
    if let Some(selector) = project_import {
        args = docker_project_args(args, &tag, selector);
    }
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
    let key = analysis_cache_key(&binary_digest, selected_entry);
    let _output_lock = lock_output(&output_abs)?;
    if let Some(snapshot) = try_cached(&output_abs, &binary_digest, selected_entry, &key) {
        return Ok(snapshot);
    }
    let project_key = project_key(&binary_digest, mode);
    let project_root = project_root(&project_key)?;
    fs::create_dir_all(&project_root)
        .map_err(|e| format!("cannot create managed Ghidra project directory: {e}"))?;
    let _project_lock = lock_output(&project_root.join("project"))?;
    let old_project = existing_project(&project_root, &project_key);
    let fresh_project = if old_project.is_none() {
        Some(
            tempfile::Builder::new()
                .prefix("generation-")
                .tempdir_in(&project_root)
                .map_err(|e| format!("cannot stage managed Ghidra project: {e}"))?,
        )
    } else {
        None
    };
    let project = old_project
        .as_deref()
        .unwrap_or_else(|| fresh_project.as_ref().unwrap().path());
    let reuse_project = old_project.is_some();
    let scratch = tempfile::Builder::new()
        .prefix("hydir-ghidra-")
        .tempdir()
        .map_err(|e| format!("cannot create Ghidra scratch directory: {e}"))?;
    if let Some(home) = local_home {
        local_analyze(
            Path::new(&home),
            &binary,
            scratch.path(),
            project,
            reuse_project,
            selected_entry,
            None,
        )?;
    } else {
        docker_analyze(
            &binary,
            scratch.path(),
            project,
            reuse_project,
            selected_entry,
            None,
        )?;
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
    if let Some(fresh_project) = fresh_project {
        if !fresh_project.path().join("HydirAuto.gpr").is_file() {
            return Err("Ghidra exported a snapshot but did not save its managed project".into());
        }
        let generation = fresh_project
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let _ = fresh_project.keep();
        let record = ProjectRecord {
            schema_version: 1,
            key: project_key,
            generation,
        };
        atomic_write(
            &project_root.join("project.json"),
            &serde_json::to_vec(&record)
                .map_err(|e| format!("cannot encode managed Ghidra project: {e}"))?,
        )?;
    }
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

/// Export one program from an expert-supplied, closed Ghidra project. The
/// source project is copied into system scratch before headless opens it.
/// This route deliberately has no cache: every call checks current project
/// contents and the original binary binding afresh.
pub fn import_project(
    binary: &Path,
    project_file: &Path,
    program: &str,
    selected_entry: Option<u64>,
    output: &Path,
) -> Result<GhidraSnapshot, String> {
    check_project_ancestors(project_file)?;
    let project_file = fs::canonicalize(project_file)
        .map_err(|e| format!("cannot resolve Ghidra project: {e}"))?;
    let project_name = project_file
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("Ghidra project name must be valid UTF-8")?;
    let selector = project_selector(project_name, program)?;
    let repository = project_file.with_extension("rep");
    check_project_ancestors(&repository)?;
    let repository = fs::canonicalize(&repository)
        .map_err(|e| format!("cannot resolve matching Ghidra repository: {e}"))?;
    let binary = fs::canonicalize(binary)
        .map_err(|e| format!("cannot resolve binary {}: {e}", binary.display()))?;
    if !binary.is_file() {
        return Err("input is not a regular binary file".into());
    }
    let size = fs::metadata(&binary).map_err(|e| e.to_string())?.len();
    if size == 0 || size > MAX_BINARY_BYTES as u64 {
        return Err(format!(
            "binary size {size} exceeds Hydir's 64 MiB input limit"
        ));
    }
    let binary_digest = digest_file(&binary)?;
    let output_abs = if output.is_absolute() {
        output.to_path_buf()
    } else {
        env::current_dir().map_err(|e| e.to_string())?.join(output)
    };
    let parent = output_abs
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or("snapshot output needs a filename")?;
    fs::create_dir_all(parent).map_err(|e| format!("cannot create output directory: {e}"))?;
    let output_abs = fs::canonicalize(parent)
        .map_err(|e| format!("cannot resolve output directory: {e}"))?
        .join(
            output_abs
                .file_name()
                .ok_or("snapshot output needs a filename")?,
        );
    let resolved_output = if output_abs.exists() {
        fs::canonicalize(&output_abs).map_err(|e| e.to_string())?
    } else {
        output_abs.clone()
    };
    if resolved_output == binary
        || resolved_output == project_file
        || resolved_output.starts_with(&repository)
    {
        return Err("snapshot output must not replace the binary or source project".into());
    }
    let _output_lock = lock_output(&output_abs)?;
    let scratch = tempfile::Builder::new()
        .prefix("hydir-ghidra-project-")
        .tempdir()
        .map_err(|e| format!("cannot create system Ghidra scratch directory: {e}"))?;
    let staged_project = scratch.path().join("project");
    stage_closed_project(&project_file, &staged_project)?;
    if let Some(home) = env::var_os("HYDIR_GHIDRA_HOME") {
        local_analyze(
            Path::new(&home),
            &binary,
            scratch.path(),
            &staged_project,
            true,
            selected_entry,
            Some(&selector),
        )?;
    } else {
        docker_analyze(
            &binary,
            scratch.path(),
            &staged_project,
            true,
            selected_entry,
            Some(&selector),
        )?;
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
    if digest_file(&binary)? != binary_digest {
        return Err("original binary changed during Ghidra project import".into());
    }
    match fs::remove_file(cache_path(&output_abs)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot clear stale Ghidra output cache: {error}")),
    }
    atomic_write(&output_abs, &bytes)?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROJECT_PROPERTY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<FILE_INFO><BASIC_INFO><STATE NAME=\"OWNER\" TYPE=\"string\" VALUE=\"muffin\" /><STATE NAME=\"CUSTOM\" TYPE=\"int\" VALUE=\"42\" /></BASIC_INFO></FILE_INFO>";

    #[test]
    fn staged_project_owner_is_normalized_without_losing_other_properties() {
        let normalized = normalized_project_owner_xml(PROJECT_PROPERTY.as_bytes()).unwrap();
        let text = String::from_utf8(normalized).unwrap();
        assert!(text.contains("NAME=\"OWNER\" TYPE=\"string\" VALUE=\"hydir\""));
        assert!(text.contains("NAME=\"CUSTOM\" TYPE=\"int\" VALUE=\"42\""));
        assert!(PROJECT_PROPERTY.contains("VALUE=\"muffin\""));
    }

    #[test]
    fn malformed_project_owner_metadata_is_rejected() {
        for invalid in [
            PROJECT_PROPERTY.replace("NAME=\"OWNER\"", "NAME=\"OTHER\""),
            PROJECT_PROPERTY.replace(
                "</BASIC_INFO>",
                "<STATE NAME=\"OWNER\" TYPE=\"string\" VALUE=\"again\" /></BASIC_INFO>",
            ),
            PROJECT_PROPERTY.replace("TYPE=\"string\"", "TYPE=\"int\""),
            PROJECT_PROPERTY.replace(" VALUE=\"muffin\"", ""),
            PROJECT_PROPERTY.replace("<BASIC_INFO>", "<WRONG>"),
            PROJECT_PROPERTY.replace("</FILE_INFO>", ""),
            format!(
                "<!DOCTYPE FILE_INFO [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>{PROJECT_PROPERTY}"
            ),
        ] {
            assert!(
                normalized_project_owner_xml(invalid.as_bytes()).is_err(),
                "{invalid}"
            );
        }
        assert!(
            normalized_project_owner_xml(&vec![b' '; MAX_PROJECT_PROPERTY_BYTES as usize + 1])
                .unwrap_err()
                .contains("64 KiB")
        );
    }

    #[test]
    fn project_selector_is_exact_and_rejects_ambiguous_paths() {
        let selector = project_selector("Expert", "firmware/main.elf").unwrap();
        assert_eq!(selector.headless_name, "Expert/firmware");
        assert_eq!(selector.leaf, "main.elf");
        assert_eq!(selector.domain_path, "/firmware/main.elf");
        for invalid in [
            "",
            "/main.elf",
            "../main.elf",
            "foo/../main.elf",
            "foo//main.elf",
            "foo/./main.elf",
            "foo/*.elf",
            "foo/?.elf",
            "foo/[ab].elf",
            "foo\\main.elf",
            "C:main.elf",
            "foo/main.elf/",
        ] {
            assert!(project_selector("Expert", invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn closed_project_staging_copies_only_matching_pair_and_caps_size() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("Expert.gpr");
        let repository = root.path().join("Expert.rep");
        fs::write(&project, b"project").unwrap();
        fs::create_dir(&repository).unwrap();
        fs::write(repository.join("project.prp"), PROJECT_PROPERTY).unwrap();
        fs::create_dir(repository.join("folder")).unwrap();
        fs::write(repository.join("folder/main.elf.gbf"), b"program").unwrap();
        fs::write(root.path().join("unrelated.txt"), b"secret").unwrap();
        let staged = root.path().join("staged");
        assert_eq!(stage_closed_project(&project, &staged).unwrap(), "Expert");
        assert_eq!(fs::read(staged.join("Expert.gpr")).unwrap(), b"project");
        assert_eq!(
            fs::read(staged.join("Expert.rep/folder/main.elf.gbf")).unwrap(),
            b"program"
        );
        assert!(!staged.join("unrelated.txt").exists());
        assert_eq!(
            fs::read_to_string(repository.join("project.prp")).unwrap(),
            PROJECT_PROPERTY
        );
        assert!(
            fs::read_to_string(staged.join("Expert.rep/project.prp"))
                .unwrap()
                .contains("VALUE=\"hydir\"")
        );

        let large = repository.join("oversize");
        File::create(&large)
            .unwrap()
            .set_len(MAX_PROJECT_BYTES + 1)
            .unwrap();
        assert!(
            stage_closed_project(&project, &root.path().join("too-large"))
                .unwrap_err()
                .contains("2 GiB")
        );
    }

    #[cfg(unix)]
    #[test]
    fn closed_project_staging_rejects_links() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("Expert.gpr");
        let repository = root.path().join("Expert.rep");
        fs::write(&project, b"project").unwrap();
        fs::create_dir(&repository).unwrap();
        symlink(root.path().join("elsewhere"), repository.join("escape")).unwrap();
        assert!(
            stage_closed_project(&project, &root.path().join("staged"))
                .unwrap_err()
                .contains("link")
        );
    }

    #[cfg(windows)]
    #[test]
    fn closed_project_staging_rejects_reparse_links_when_supported() {
        use std::os::windows::fs::symlink_file;
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("Expert.gpr");
        let repository = root.path().join("Expert.rep");
        fs::write(&project, b"project").unwrap();
        fs::create_dir(&repository).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        if symlink_file(&outside, repository.join("escape")).is_err() {
            return; // Creating symlinks requires developer mode on some Windows hosts.
        }
        assert!(
            stage_closed_project(&project, &root.path().join("staged"))
                .unwrap_err()
                .contains("link")
        );
    }

    #[test]
    fn project_import_refuses_output_inside_source_repository() {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("Expert.gpr");
        let repository = root.path().join("Expert.rep");
        let binary = root.path().join("binary.elf");
        fs::write(&project, b"project").unwrap();
        fs::create_dir(&repository).unwrap();
        fs::write(&binary, b"binary").unwrap();
        let output = repository.join("snapshot.json");
        let error = import_project(&binary, &project, "program", None, &output).unwrap_err();
        assert!(error.contains("source project"));
        assert!(!output.exists());
    }

    #[test]
    fn project_container_args_process_one_leaf_read_only() {
        let selector = project_selector("Expert", "firmware/main.elf").unwrap();
        let args = docker_run_args(
            "image:tag",
            "hydir-test",
            Path::new("/tmp/binary"),
            Path::new("/tmp/work"),
            Path::new("/tmp/project"),
            true,
            Some(0x401000),
            None,
        );
        let args = docker_project_args(args, "image:tag", &selector);
        assert!(args.windows(5).any(|w| w
            == [
                "Expert/firmware",
                "-process",
                "main.elf",
                "-noanalysis",
                "-readOnly"
            ]));
        assert!(
            args.iter()
                .any(|arg| arg == "domainPath=/firmware/main.elf")
        );
        assert!(!args.iter().any(|arg| arg == "-import"));
        assert!(args.windows(2).any(|w| w == ["--network", "none"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["--env", "JAVA_TOOL_OPTIONS=-Duser.name=hydir"])
        );
    }

    #[test]
    fn cancellation_stops_a_running_worker_command() {
        let scratch = tempfile::tempdir().unwrap();
        let cancel = scratch.path().join("cancel");
        #[cfg(windows)]
        let mut command = {
            let mut command = Command::new("powershell.exe");
            command.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 10",
            ]);
            command
        };
        #[cfg(unix)]
        let mut command = {
            let mut command = Command::new("sh");
            command.args(["-c", "sleep 10"]);
            command
        };
        let marker = cancel.clone();
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            fs::write(marker, []).unwrap();
        });
        let started = Instant::now();
        let result = run_bounded_with_cancel_file(
            &mut command,
            "test command",
            Duration::from_secs(20),
            &scratch.path().join("worker.log"),
            None,
            Some(&cancel),
        );
        trigger.join().unwrap();
        assert!(result.unwrap_err().contains("cancelled"));
        assert!(started.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn run_args_isolate_worker_and_preserve_selected_address() {
        let args = docker_run_args(
            "hydir-ghidra:test",
            "hydir-test",
            Path::new("/tmp/input"),
            Path::new("/tmp/scratch"),
            Path::new("/tmp/project"),
            false,
            Some(0x401080),
            Some("1001:1001"),
        );
        assert!(args.windows(2).any(|w| w == ["--network", "none"]));
        assert!(args.iter().any(|a| a == "--read-only"));
        assert!(
            args.iter()
                .any(|a| a.contains("target=/input/binary,readonly"))
        );
        assert!(args.iter().any(|a| a == "no-new-privileges"));
        assert!(args.windows(2).any(|w| w == ["--user", "1001:1001"]));
        assert_eq!(args.last().unwrap(), "0x401080");
        assert!(args.iter().any(|arg| arg == "-import"));
        let reused = docker_run_args(
            "hydir-ghidra:test",
            "hydir-test",
            Path::new("/tmp/input"),
            Path::new("/tmp/scratch"),
            Path::new("/tmp/project"),
            true,
            None,
            None,
        );
        assert!(!reused.iter().any(|arg| arg == "--user"));
        assert!(reused.iter().any(|arg| arg == "-process"));
        assert!(reused.iter().any(|arg| arg == "-noanalysis"));
        assert!(!reused.iter().any(|arg| arg == "-import"));
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

    #[test]
    fn managed_project_record_requires_matching_identity_and_project_file() {
        let root = tempfile::tempdir().unwrap();
        let generation = root.path().join("generation-test123");
        fs::create_dir(&generation).unwrap();
        let record = ProjectRecord {
            schema_version: 1,
            key: "expected".to_owned(),
            generation: "generation-test123".to_owned(),
        };
        fs::write(
            root.path().join("project.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert!(existing_project(root.path(), "expected").is_none());
        fs::write(generation.join("HydirAuto.gpr"), b"project").unwrap();
        assert_eq!(existing_project(root.path(), "expected"), Some(generation));
        assert!(existing_project(root.path(), "other").is_none());
        let traversal = ProjectRecord {
            generation: "../other".to_owned(),
            ..record
        };
        fs::write(
            root.path().join("project.json"),
            serde_json::to_vec(&traversal).unwrap(),
        )
        .unwrap();
        assert!(existing_project(root.path(), "expected").is_none());
    }
}
