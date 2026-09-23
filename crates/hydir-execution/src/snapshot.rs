//! Sparse process-state artifact. Unrecorded pages are always unknown.

use crate::{InputSpec, decode_hex, input_sha256, validate_input_spec};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const EXECUTION_SNAPSHOT_VERSION: u32 = 1;
pub const PAGE_BYTES: usize = 4096;
pub const MAX_EXECUTION_SNAPSHOT_JSON_BYTES: usize = 4 * 1024 * 1024;
const MAX_MAPPINGS: usize = 1024;
const MAX_PAGES: usize = 32;
const MAX_REGISTERS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Stopped,
    UnsupportedThreads,
    TimedOut,
    RunnerError,
    UnsupportedHost,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopPoint {
    pub runtime_pc: u64,
    /// ELF virtual address. For PIE this is relative to the load bias.
    pub elf_vaddr: Option<u64>,
    pub load_bias: Option<u64>,
    pub symbol: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum RegisterObservation {
    Present { value: u64 },
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryMapping {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", deny_unknown_fields)]
pub enum MemoryPageState {
    Present { bytes_hex: String },
    Unavailable { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPage {
    pub address: u64,
    pub value: MemoryPageState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSnapshot {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub input_sha256: String,
    pub status: SnapshotStatus,
    pub stop: Option<StopPoint>,
    pub thread_id: Option<u64>,
    pub thread_count: u32,
    pub registers: BTreeMap<String, RegisterObservation>,
    pub mappings: Vec<MemoryMapping>,
    /// Selected pages only. No page outside this list is assumed present.
    pub pages: Vec<MemoryPage>,
    pub runner: String,
    pub diagnostics: Vec<String>,
}

pub fn parse_execution_snapshot(json: &[u8]) -> Result<ExecutionSnapshot, String> {
    if json.len() > MAX_EXECUTION_SNAPSHOT_JSON_BYTES {
        return Err("ExecutionSnapshot exceeds 4 MiB JSON limit".into());
    }
    serde_json::from_slice(json).map_err(|error| format!("invalid ExecutionSnapshot JSON: {error}"))
}

pub fn validate_execution_snapshot(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &ExecutionSnapshot,
) -> Result<(), String> {
    validate_input_spec(elf, input)?;
    if snapshot.schema_version != EXECUTION_SNAPSHOT_VERSION
        || snapshot.binary_sha256 != input.binary_sha256
        || snapshot.input_sha256 != input_sha256(input)?
    {
        return Err("snapshot version or binary/input binding is invalid".into());
    }
    if snapshot.runner.is_empty()
        || snapshot.runner.len() > 128
        || snapshot.diagnostics.len() > 64
        || snapshot
            .diagnostics
            .iter()
            .any(|message| message.len() > 512)
        || snapshot.mappings.len() > MAX_MAPPINGS
        || snapshot.pages.len() > MAX_PAGES
        || snapshot.registers.len() > MAX_REGISTERS
    {
        return Err("snapshot inventory exceeds limit".into());
    }
    let mut previous_end = 0;
    for mapping in &snapshot.mappings {
        if mapping.start >= mapping.end
            || mapping.start < previous_end
            || mapping
                .path
                .as_ref()
                .is_some_and(|path| path.len() > 4096 || path.contains('\0'))
        {
            return Err("snapshot mappings are invalid or overlap".into());
        }
        previous_end = mapping.end;
    }
    let mut seen_pages = BTreeSet::new();
    for page in &snapshot.pages {
        let end = page
            .address
            .checked_add(PAGE_BYTES as u64)
            .ok_or("page address overflow")?;
        if page.address % PAGE_BYTES as u64 != 0 || !seen_pages.insert(page.address) {
            return Err("snapshot pages must be unique and aligned".into());
        }
        match &page.value {
            MemoryPageState::Present { bytes_hex } => {
                if bytes_hex.len() != PAGE_BYTES * 2
                    || decode_hex(bytes_hex, PAGE_BYTES)?.len() != PAGE_BYTES
                {
                    return Err("present page must contain exactly 4096 bytes".into());
                }
                if !snapshot.mappings.iter().any(|mapping| {
                    mapping.readable && mapping.start <= page.address && end <= mapping.end
                }) {
                    return Err("present page is outside a readable mapping".into());
                }
            }
            MemoryPageState::Unavailable { reason } if reason.is_empty() || reason.len() > 512 => {
                return Err("unavailable page requires a bounded reason".into());
            }
            MemoryPageState::Unavailable { .. } => {}
        }
    }
    for (name, observation) in &snapshot.registers {
        if name.is_empty()
            || name.len() > 16
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err("register name is invalid".into());
        }
        if let RegisterObservation::Unavailable { reason } = observation {
            if reason.is_empty() || reason.len() > 512 {
                return Err("unavailable register requires a bounded reason".into());
            }
        }
    }
    match snapshot.status {
        SnapshotStatus::Stopped => {
            if snapshot.thread_count != 1 || snapshot.thread_id.is_none() {
                return Err("stopped snapshot requires one identified thread".into());
            }
            let stop = snapshot
                .stop
                .as_ref()
                .ok_or("stopped snapshot has no stop point")?;
            if stop
                .symbol
                .as_ref()
                .is_some_and(|name| name.is_empty() || name.len() > 256)
            {
                return Err("stop symbol is invalid".into());
            }
            match (stop.elf_vaddr, stop.load_bias) {
                (Some(vaddr), Some(bias)) if vaddr.checked_add(bias) == Some(stop.runtime_pc) => {}
                (None, None) => {}
                _ => return Err("stop ELF address and load bias disagree".into()),
            }
            for register in ["rip", "rsp", "eflags"] {
                if !matches!(
                    snapshot.registers.get(register),
                    Some(RegisterObservation::Present { .. })
                ) {
                    return Err(format!("stopped snapshot lacks {register}"));
                }
            }
            if !matches!(snapshot.registers.get("rip"), Some(RegisterObservation::Present { value }) if *value == stop.runtime_pc)
            {
                return Err("stop PC and RIP disagree".into());
            }
            if !snapshot.mappings.iter().any(|mapping| {
                mapping.executable
                    && mapping.start <= stop.runtime_pc
                    && stop.runtime_pc < mapping.end
            }) {
                return Err("stop PC is outside executable mappings".into());
            }
        }
        SnapshotStatus::UnsupportedThreads => {
            if snapshot.thread_count <= 1 {
                return Err("unsupported_threads requires multiple threads".into());
            }
        }
        SnapshotStatus::TimedOut
        | SnapshotStatus::RunnerError
        | SnapshotStatus::UnsupportedHost => {
            if snapshot.stop.is_some()
                || !snapshot.registers.is_empty()
                || !snapshot.pages.is_empty()
            {
                return Err("failed capture cannot claim stopped state".into());
            }
        }
    }
    if matches!(snapshot.status, SnapshotStatus::UnsupportedHost)
        && (!snapshot.mappings.is_empty()
            || snapshot.thread_id.is_some()
            || snapshot.thread_count != 0)
    {
        return Err("unsupported host cannot claim process observations".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MemoryReadError {
    TooLarge,
    AddressOverflow,
    MissingPage { address: u64 },
    UnavailablePage { address: u64, reason: String },
    InvalidPage { address: u64 },
}

/// Reads only captured bytes. A missing or unavailable page is never zero-filled.
pub fn read_snapshot_memory(
    snapshot: &ExecutionSnapshot,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, MemoryReadError> {
    if length > 64 * 1024 {
        return Err(MemoryReadError::TooLarge);
    }
    let end = address
        .checked_add(length as u64)
        .ok_or(MemoryReadError::AddressOverflow)?;
    let mut result = Vec::with_capacity(length);
    let mut cursor = address;
    while cursor < end {
        let page_start = cursor & !(PAGE_BYTES as u64 - 1);
        let page = snapshot
            .pages
            .iter()
            .find(|page| page.address == page_start)
            .ok_or(MemoryReadError::MissingPage {
                address: page_start,
            })?;
        let bytes = match &page.value {
            MemoryPageState::Present { bytes_hex } => {
                decode_hex(bytes_hex, PAGE_BYTES).map_err(|_| MemoryReadError::InvalidPage {
                    address: page_start,
                })?
            }
            MemoryPageState::Unavailable { reason } => {
                return Err(MemoryReadError::UnavailablePage {
                    address: page_start,
                    reason: reason.clone(),
                });
            }
        };
        if bytes.len() != PAGE_BYTES {
            return Err(MemoryReadError::InvalidPage {
                address: page_start,
            });
        }
        let start = (cursor - page_start) as usize;
        let count = ((end - cursor) as usize).min(PAGE_BYTES - start);
        result.extend_from_slice(&bytes[start..start + count]);
        cursor += count as u64;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReplayBudget, ReplayGoal, encode_hex};
    use sha2::{Digest, Sha256};

    fn elf_header() -> Vec<u8> {
        let mut elf = vec![0; 64];
        elf[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf
    }

    fn input(elf: &[u8]) -> InputSpec {
        InputSpec {
            schema_version: 1,
            binary_sha256: format!("{:x}", Sha256::digest(elf)),
            argv_hex: Vec::new(),
            stdin_hex: String::new(),
            files: Vec::new(),
            origins: Vec::new(),
            goal: ReplayGoal {
                exit_code: Some(0),
                stdout_contains_hex: None,
                stderr_contains_hex: None,
            },
            budget: ReplayBudget {
                timeout_ms: 1000,
                memory_bytes: 128 * 1024 * 1024,
                output_bytes: 4096,
            },
        }
    }

    fn snapshot(input: &InputSpec) -> ExecutionSnapshot {
        let mut registers = BTreeMap::new();
        registers.insert("rip".into(), RegisterObservation::Present { value: 0x1000 });
        registers.insert("rsp".into(), RegisterObservation::Present { value: 0x2100 });
        registers.insert(
            "eflags".into(),
            RegisterObservation::Present { value: 0x202 },
        );
        ExecutionSnapshot {
            schema_version: EXECUTION_SNAPSHOT_VERSION,
            binary_sha256: input.binary_sha256.clone(),
            input_sha256: input_sha256(input).unwrap(),
            status: SnapshotStatus::Stopped,
            stop: Some(StopPoint {
                runtime_pc: 0x1000,
                elf_vaddr: Some(0x1000),
                load_bias: Some(0),
                symbol: Some("main".into()),
            }),
            thread_id: Some(1),
            thread_count: 1,
            registers,
            mappings: vec![MemoryMapping {
                start: 0x1000,
                end: 0x4000,
                file_offset: 0,
                readable: true,
                writable: false,
                executable: true,
                path: Some("/work/program".into()),
            }],
            pages: vec![
                MemoryPage {
                    address: 0x1000,
                    value: MemoryPageState::Present {
                        bytes_hex: encode_hex(&vec![0x90; PAGE_BYTES]),
                    },
                },
                MemoryPage {
                    address: 0x2000,
                    value: MemoryPageState::Unavailable {
                        reason: "read failed".into(),
                    },
                },
            ],
            runner: "test-gdb-mi".into(),
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn round_trip_and_sparse_memory() {
        let elf = elf_header();
        let input = input(&elf);
        let snapshot = snapshot(&input);
        validate_execution_snapshot(&elf, &input, &snapshot).unwrap();
        let json = serde_json::to_vec(&snapshot).unwrap();
        assert_eq!(parse_execution_snapshot(&json).unwrap(), snapshot);
        assert_eq!(
            read_snapshot_memory(&snapshot, 0x1000, 4).unwrap(),
            vec![0x90; 4]
        );
        assert!(matches!(
            read_snapshot_memory(&snapshot, 0x2000, 1),
            Err(MemoryReadError::UnavailablePage { .. })
        ));
        assert!(matches!(
            read_snapshot_memory(&snapshot, 0x3000, 1),
            Err(MemoryReadError::MissingPage { .. })
        ));
        assert!(matches!(
            read_snapshot_memory(&snapshot, 0x1fff, 2),
            Err(MemoryReadError::UnavailablePage { .. })
        ));
        let mut complete_pair = snapshot.clone();
        complete_pair.pages[1].value = MemoryPageState::Present {
            bytes_hex: encode_hex(&vec![0x41; PAGE_BYTES]),
        };
        validate_execution_snapshot(&elf, &input, &complete_pair).unwrap();
        assert_eq!(
            read_snapshot_memory(&complete_pair, 0x1fff, 2).unwrap(),
            vec![0x90, 0x41]
        );
    }

    #[test]
    fn rejects_false_process_and_memory_claims() {
        let elf = elf_header();
        let input = input(&elf);
        let mut value = snapshot(&input);
        value.stop.as_mut().unwrap().load_bias = Some(1);
        assert!(validate_execution_snapshot(&elf, &input, &value).is_err());
        value = snapshot(&input);
        value
            .registers
            .insert("rip".into(), RegisterObservation::Present { value: 0x3000 });
        assert!(validate_execution_snapshot(&elf, &input, &value).is_err());
        value = snapshot(&input);
        value.pages[0].value = MemoryPageState::Present {
            bytes_hex: "00".into(),
        };
        assert!(validate_execution_snapshot(&elf, &input, &value).is_err());
        value = snapshot(&input);
        value.pages.push(value.pages[0].clone());
        assert!(validate_execution_snapshot(&elf, &input, &value).is_err());
        value = snapshot(&input);
        value.status = SnapshotStatus::UnsupportedHost;
        assert!(validate_execution_snapshot(&elf, &input, &value).is_err());
    }
}
