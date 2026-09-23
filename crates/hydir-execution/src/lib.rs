//! Versioned input and replay artifacts. Execution is kept separate from static analysis.

use object::{Architecture, BinaryFormat, Object, ObjectKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

mod gdb_mi;
mod origin_probe;
mod snapshot;
pub use gdb_mi::{MiListEntry, MiRecord, MiValue, parse_mi_line};
pub use origin_probe::{
    MAX_ORIGIN_PROBE_JSON_BYTES, ORIGIN_PROBE_VERSION, OriginProbe, ProbeEvidence, ProbeLocation,
    ProbeStatus, parse_origin_probe, probe_origin, validate_origin_probe,
};
pub use snapshot::{
    EXECUTION_SNAPSHOT_VERSION, ExecutionSnapshot, MAX_EXECUTION_SNAPSHOT_JSON_BYTES,
    MemoryMapping, MemoryPage, MemoryPageState, MemoryReadError, RegisterObservation,
    SnapshotStatus, StopPoint, parse_execution_snapshot, read_snapshot_memory,
    validate_execution_snapshot,
};

#[cfg(target_os = "linux")]
mod runner;
#[cfg(target_os = "linux")]
pub use runner::replay_local;
#[cfg(target_os = "linux")]
mod capture;
#[cfg(target_os = "linux")]
pub use capture::{capture_elf_address, capture_function_entry};

pub const INPUT_SPEC_VERSION: u32 = 1;
pub const NATIVE_REPLAY_REPORT_VERSION: u32 = 1;
pub const MAX_INPUT_SPEC_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_INPUT_FILES: usize = 16;
pub const MAX_ARGV: usize = 32;
pub const MAX_ORIGINS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSpec {
    pub schema_version: u32,
    pub binary_sha256: String,
    #[serde(default)]
    pub argv_hex: Vec<String>,
    #[serde(default)]
    pub stdin_hex: String,
    #[serde(default)]
    pub files: Vec<InputFile>,
    #[serde(default)]
    pub origins: Vec<InputOrigin>,
    pub goal: ReplayGoal,
    pub budget: ReplayBudget,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    /// A relative UTF-8 path below the runner's scratch directory.
    pub path: String,
    pub bytes_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum InputChannel {
    Stdin,
    Argv { index: usize },
    File { path: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputEncoding {
    Raw,
    Ascii,
    Utf8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputOrigin {
    pub id: String,
    pub channel: InputChannel,
    pub offset: usize,
    pub length: usize,
    pub encoding: InputEncoding,
    /// Optional set of allowed byte values, encoded as hex. Empty means unconstrained.
    #[serde(default)]
    pub alphabet_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayGoal {
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub stdout_contains_hex: Option<String>,
    #[serde(default)]
    pub stderr_contains_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayBudget {
    pub timeout_ms: u64,
    pub memory_bytes: u64,
    pub output_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayStatus {
    GoalMatched,
    GoalMismatched,
    TimedOut,
    OutputLimit,
    RunnerError,
    UnsupportedHost,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeReplayReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub input_sha256: String,
    pub status: ReplayStatus,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout_hex: String,
    pub stderr_hex: String,
    pub elapsed_ms: u64,
    pub runner: String,
    pub diagnostic: Option<String>,
}

pub fn parse_input_spec(json: &[u8]) -> Result<InputSpec, String> {
    if json.len() > MAX_INPUT_SPEC_BYTES {
        return Err("InputSpec exceeds 2 MiB JSON limit".into());
    }
    serde_json::from_slice(json).map_err(|error| format!("invalid InputSpec JSON: {error}"))
}

pub fn validate_input_spec(elf: &[u8], input: &InputSpec) -> Result<(), String> {
    if input.schema_version != INPUT_SPEC_VERSION {
        return Err("unsupported InputSpec version".into());
    }
    if elf.len() > 64 * 1024 * 1024 {
        return Err("binary exceeds 64 MiB import limit".into());
    }
    let object = object::File::parse(elf).map_err(|error| format!("ELF parse failed: {error}"))?;
    if object.format() != BinaryFormat::Elf
        || object.architecture() != Architecture::X86_64
        || !object.is_little_endian()
        || object.kind() != ObjectKind::Executable && object.kind() != ObjectKind::Dynamic
    {
        return Err("replay requires a linked little-endian x86-64 ELF".into());
    }
    let digest = format!("{:x}", Sha256::digest(elf));
    if input.binary_sha256 != digest {
        return Err("InputSpec binary SHA-256 does not match ELF".into());
    }
    if input.argv_hex.len() > MAX_ARGV
        || input.files.len() > MAX_INPUT_FILES
        || input.origins.len() > MAX_ORIGINS
    {
        return Err("InputSpec item count exceeds limit".into());
    }
    let mut total = 0usize;
    let stdin = decode_hex(&input.stdin_hex, MAX_INPUT_BYTES)?;
    total += stdin.len();
    let argv = input
        .argv_hex
        .iter()
        .map(|value| {
            let bytes = decode_hex(value, 4096)?;
            if bytes.contains(&0) {
                return Err("argv contains NUL".into());
            }
            Ok(bytes)
        })
        .collect::<Result<Vec<_>, String>>()?;
    total += argv.iter().map(Vec::len).sum::<usize>();
    let mut paths = BTreeSet::new();
    let files = input
        .files
        .iter()
        .map(|file| {
            validate_relative_path(&file.path)?;
            if !paths.insert(file.path.as_str()) {
                return Err("duplicate input file path".into());
            }
            let bytes = decode_hex(&file.bytes_hex, MAX_INPUT_BYTES)?;
            total += bytes.len();
            Ok((file.path.as_str(), bytes))
        })
        .collect::<Result<Vec<_>, String>>()?;
    for path in &paths {
        let mut ancestor = path.rsplit_once('/');
        while let Some((prefix, _)) = ancestor {
            if paths.contains(prefix) {
                return Err("input file path conflicts with a parent file".into());
            }
            ancestor = prefix.rsplit_once('/');
        }
    }
    if total > MAX_INPUT_BYTES {
        return Err("combined input exceeds 1 MiB".into());
    }
    let mut ids = BTreeSet::new();
    for origin in &input.origins {
        if origin.id.is_empty() || origin.id.len() > 128 || !ids.insert(origin.id.as_str()) {
            return Err("origin IDs must be unique and 1..128 bytes".into());
        }
        let channel_bytes: &[u8] = match &origin.channel {
            InputChannel::Stdin => &stdin,
            InputChannel::Argv { index } => argv
                .get(*index)
                .ok_or("origin argv index is out of range")?,
            InputChannel::File { path } => {
                &files
                    .iter()
                    .find(|(candidate, _)| candidate == path)
                    .ok_or("origin file is missing")?
                    .1
            }
        };
        let end = origin
            .offset
            .checked_add(origin.length)
            .ok_or("origin range overflow")?;
        if origin.length == 0 || end > channel_bytes.len() {
            return Err("origin range is outside input".into());
        }
        let value = &channel_bytes[origin.offset..end];
        match origin.encoding {
            InputEncoding::Raw => {}
            InputEncoding::Ascii if !value.is_ascii() => return Err("origin is not ASCII".into()),
            InputEncoding::Utf8 if std::str::from_utf8(value).is_err() => {
                return Err("origin is not UTF-8".into());
            }
            _ => {}
        }
        if !origin.alphabet_hex.is_empty() {
            let alphabet = decode_hex(&origin.alphabet_hex, 256)?;
            if alphabet.is_empty() || !value.iter().all(|byte| alphabet.contains(byte)) {
                return Err("origin bytes violate alphabet".into());
            }
        }
    }
    if input.goal.exit_code.is_none()
        && input.goal.stdout_contains_hex.is_none()
        && input.goal.stderr_contains_hex.is_none()
    {
        return Err("replay goal has no predicates".into());
    }
    for needle in [
        &input.goal.stdout_contains_hex,
        &input.goal.stderr_contains_hex,
    ]
    .into_iter()
    .flatten()
    {
        if decode_hex(needle, 4096)?.is_empty() {
            return Err("replay output predicate is empty".into());
        }
    }
    if !(1..=30_000).contains(&input.budget.timeout_ms)
        || !(16 * 1024 * 1024..=1024 * 1024 * 1024).contains(&input.budget.memory_bytes)
        || !(1..=1024 * 1024).contains(&input.budget.output_bytes)
    {
        return Err("replay budget is outside supported bounds".into());
    }
    Ok(())
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.len() > 256
        || path.is_empty()
        || path.contains('\\')
        || path.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || path.starts_with('/')
        || path
            .split('/')
            .next()
            .is_some_and(|part| part.starts_with(".hydir-"))
    {
        return Err("input file path must be a normalized relative path".into());
    }
    Ok(())
}

pub fn decode_hex(value: &str, max_bytes: usize) -> Result<Vec<u8>, String> {
    if value.len() > max_bytes * 2
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("hex bytes are malformed or exceed limit".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|part| {
            u8::from_str_radix(std::str::from_utf8(part).expect("ASCII hex"), 16)
                .map_err(|_| "invalid hex byte".into())
        })
        .collect()
}

pub fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn input_sha256(input: &InputSpec) -> Result<String, String> {
    let bytes = serde_json::to_vec(input).map_err(|error| error.to_string())?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn validate_replay_report(
    elf: &[u8],
    input: &InputSpec,
    report: &NativeReplayReport,
) -> Result<(), String> {
    validate_input_spec(elf, input)?;
    if report.schema_version != NATIVE_REPLAY_REPORT_VERSION
        || report.binary_sha256 != input.binary_sha256
        || report.input_sha256 != input_sha256(input)?
    {
        return Err("replay report version or input binding is invalid".into());
    }
    if report.runner.is_empty()
        || report.runner.len() > 128
        || report
            .diagnostic
            .as_ref()
            .is_some_and(|value| value.len() > 4096)
    {
        return Err("replay report metadata exceeds limit".into());
    }
    if matches!(
        report.status,
        ReplayStatus::TimedOut
            | ReplayStatus::OutputLimit
            | ReplayStatus::RunnerError
            | ReplayStatus::UnsupportedHost
    ) && !report
        .diagnostic
        .as_ref()
        .is_some_and(|value| !value.is_empty())
    {
        return Err("incomplete replay requires a diagnostic".into());
    }
    let stdout = decode_hex(&report.stdout_hex, input.budget.output_bytes as usize)?;
    let stderr = decode_hex(&report.stderr_hex, input.budget.output_bytes as usize)?;
    if stdout.len() + stderr.len() > input.budget.output_bytes as usize {
        return Err("replay output exceeds budget".into());
    }
    if report.signal.is_some() {
        return Err("ReplayReport v1 has no independent signal observation".into());
    }
    if matches!(report.status, ReplayStatus::UnsupportedHost)
        && (!stdout.is_empty() || !stderr.is_empty() || report.elapsed_ms != 0)
    {
        return Err("unsupported host cannot claim process observations".into());
    }
    if matches!(
        report.status,
        ReplayStatus::GoalMatched | ReplayStatus::GoalMismatched
    ) {
        let exit = report.exit_code.ok_or("observed replay has no exit code")?;
        if !(0..128).contains(&exit) {
            return Err("Bubblewrap cannot distinguish this exit value from a signal".into());
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
        let matched = input.goal.exit_code.is_none_or(|wanted| wanted == exit)
            && stdout_goal
                .as_ref()
                .is_none_or(|needle| stdout.windows(needle.len()).any(|window| window == needle))
            && stderr_goal
                .as_ref()
                .is_none_or(|needle| stderr.windows(needle.len()).any(|window| window == needle));
        if matched != matches!(report.status, ReplayStatus::GoalMatched) {
            return Err("replay status contradicts observed goal predicates".into());
        }
    } else if report.exit_code.is_some() {
        return Err("incomplete replay cannot claim an exit code".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header() -> Vec<u8> {
        let mut elf = vec![0; 64];
        elf[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf
    }

    fn sample_spec(elf: &[u8]) -> InputSpec {
        InputSpec {
            schema_version: INPUT_SPEC_VERSION,
            binary_sha256: format!("{:x}", Sha256::digest(elf)),
            argv_hex: vec!["616263".into()],
            stdin_hex: "313233".into(),
            files: vec![InputFile {
                path: "data/key".into(),
                bytes_hex: "4142".into(),
            }],
            origins: vec![InputOrigin {
                id: "user-argument".into(),
                channel: InputChannel::Argv { index: 0 },
                offset: 0,
                length: 3,
                encoding: InputEncoding::Ascii,
                alphabet_hex: "616263".into(),
            }],
            goal: ReplayGoal {
                exit_code: Some(0),
                stdout_contains_hex: Some("4f4b".into()),
                stderr_contains_hex: None,
            },
            budget: ReplayBudget {
                timeout_ms: 1000,
                memory_bytes: 128 * 1024 * 1024,
                output_bytes: 4096,
            },
        }
    }

    #[test]
    fn input_spec_round_trip_and_binding() {
        let elf = elf_header();
        let input = sample_spec(&elf);
        validate_input_spec(&elf, &input).unwrap();
        let json = serde_json::to_vec(&input).unwrap();
        assert_eq!(parse_input_spec(&json).unwrap(), input);
        assert_eq!(input_sha256(&input).unwrap().len(), 64);
        let mut other_elf = elf;
        other_elf[24] = 1;
        assert!(
            validate_input_spec(&other_elf, &input)
                .unwrap_err()
                .contains("SHA-256")
        );
    }

    #[test]
    fn rejects_invalid_origin_paths_goals_and_budgets() {
        let elf = elf_header();
        let mut input = sample_spec(&elf);
        input.files[0].path = "../escape".into();
        assert!(validate_input_spec(&elf, &input).is_err());
        input = sample_spec(&elf);
        input.files[0].path = ".hydir-stdin".into();
        assert!(validate_input_spec(&elf, &input).is_err());
        input = sample_spec(&elf);
        input.files.push(InputFile {
            path: "data".into(),
            bytes_hex: "41".into(),
        });
        assert!(validate_input_spec(&elf, &input).is_err());
        input = sample_spec(&elf);
        input.origins[0].length = 4;
        assert!(validate_input_spec(&elf, &input).is_err());
        input = sample_spec(&elf);
        input.origins[0].alphabet_hex = "41".into();
        assert!(validate_input_spec(&elf, &input).is_err());
        input = sample_spec(&elf);
        input.goal = ReplayGoal {
            exit_code: None,
            stdout_contains_hex: None,
            stderr_contains_hex: None,
        };
        assert!(validate_input_spec(&elf, &input).is_err());
        input = sample_spec(&elf);
        input.budget.timeout_ms = 0;
        assert!(validate_input_spec(&elf, &input).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_unbounded_json() {
        let elf = elf_header();
        let input = sample_spec(&elf);
        let mut value = serde_json::to_value(input).unwrap();
        value["unexpected"] = serde_json::json!(true);
        assert!(parse_input_spec(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(parse_input_spec(&vec![b' '; MAX_INPUT_SPEC_BYTES + 1]).is_err());
    }

    #[test]
    fn report_cannot_assert_a_mismatched_goal() {
        let elf = elf_header();
        let input = sample_spec(&elf);
        let mut report = NativeReplayReport {
            schema_version: NATIVE_REPLAY_REPORT_VERSION,
            binary_sha256: input.binary_sha256.clone(),
            input_sha256: input_sha256(&input).unwrap(),
            status: ReplayStatus::GoalMatched,
            exit_code: Some(0),
            signal: None,
            stdout_hex: "4f4b".into(),
            stderr_hex: String::new(),
            elapsed_ms: 1,
            runner: "test".into(),
            diagnostic: None,
        };
        validate_replay_report(&elf, &input, &report).unwrap();
        report.stdout_hex = "4e4f".into();
        assert!(validate_replay_report(&elf, &input, &report).is_err());
        report.status = ReplayStatus::GoalMismatched;
        validate_replay_report(&elf, &input, &report).unwrap();
        report.status = ReplayStatus::TimedOut;
        assert!(validate_replay_report(&elf, &input, &report).is_err());
        report.status = ReplayStatus::GoalMismatched;
        report.exit_code = Some(139);
        assert!(validate_replay_report(&elf, &input, &report).is_err());
        report.status = ReplayStatus::RunnerError;
        report.exit_code = None;
        report.diagnostic = Some("exit status ambiguous".into());
        validate_replay_report(&elf, &input, &report).unwrap();
        report.signal = Some(11);
        assert!(validate_replay_report(&elf, &input, &report).is_err());
    }
}
