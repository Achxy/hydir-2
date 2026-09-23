//! Analyst-selected input-byte probes against a sparse execution snapshot.
//! Equality at a chosen location is not proof of input provenance.

use crate::{
    ExecutionSnapshot, InputChannel, InputSpec, MemoryReadError, RegisterObservation,
    SnapshotStatus, decode_hex, encode_hex, read_snapshot_memory, validate_execution_snapshot,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ORIGIN_PROBE_VERSION: u32 = 1;
pub const MAX_ORIGIN_PROBE_JSON_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum ProbeLocation {
    Register { name: String, offset: i64 },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Matched,
    Different,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeEvidence {
    /// Only byte equality at an analyst-selected location was checked.
    ByteEqualityOnly,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginProbe {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub input_sha256: String,
    pub snapshot_sha256: String,
    pub origin_id: String,
    pub location: ProbeLocation,
    pub runtime_address: Option<u64>,
    pub length: usize,
    pub status: ProbeStatus,
    pub evidence: ProbeEvidence,
    pub observed_hex: Option<String>,
    pub diagnostic: Option<String>,
}

pub fn parse_origin_probe(json: &[u8]) -> Result<OriginProbe, String> {
    if json.len() > MAX_ORIGIN_PROBE_JSON_BYTES {
        return Err("OriginProbe exceeds 256 KiB JSON limit".into());
    }
    serde_json::from_slice(json).map_err(|error| format!("invalid OriginProbe JSON: {error}"))
}

pub fn probe_origin(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &ExecutionSnapshot,
    origin_id: &str,
    location: ProbeLocation,
) -> Result<OriginProbe, String> {
    validate_execution_snapshot(elf, input, snapshot)?;
    let expected = origin_bytes(input, origin_id)?;
    let snapshot_sha256 = format!(
        "{:x}",
        Sha256::digest(
            serde_json::to_vec(snapshot)
                .map_err(|error| format!("cannot serialize ExecutionSnapshot: {error}"))?
        )
    );
    let mut report = OriginProbe {
        schema_version: ORIGIN_PROBE_VERSION,
        binary_sha256: snapshot.binary_sha256.clone(),
        input_sha256: snapshot.input_sha256.clone(),
        snapshot_sha256,
        origin_id: origin_id.to_owned(),
        location: location.clone(),
        runtime_address: None,
        length: expected.len(),
        status: ProbeStatus::Unavailable,
        evidence: ProbeEvidence::ByteEqualityOnly,
        observed_hex: None,
        diagnostic: None,
    };
    let ProbeLocation::Register { name, offset } = location;
    if name.is_empty()
        || name.len() > 16
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || !(-4096..=4096).contains(&offset)
    {
        return Err("probe register or offset is outside supported bounds".into());
    }
    if snapshot.status != SnapshotStatus::Stopped {
        report.diagnostic = Some("snapshot has no stopped process state".into());
        return Ok(report);
    }
    let base = match snapshot.registers.get(&name) {
        Some(RegisterObservation::Present { value }) => *value,
        Some(RegisterObservation::Unavailable { .. }) => {
            report.diagnostic = Some("selected register is unavailable".into());
            return Ok(report);
        }
        None => {
            report.diagnostic = Some("selected register was not captured".into());
            return Ok(report);
        }
    };
    let address = if offset >= 0 {
        base.checked_add(offset as u64)
    } else {
        base.checked_sub(offset.unsigned_abs())
    };
    let Some(address) = address else {
        report.diagnostic = Some("register displacement overflows the address space".into());
        return Ok(report);
    };
    report.runtime_address = Some(address);
    if expected.len() > 64 * 1024 {
        report.diagnostic = Some("origin exceeds the 64 KiB snapshot read limit".into());
        return Ok(report);
    }
    let observed = match read_snapshot_memory(snapshot, address, expected.len()) {
        Ok(bytes) => bytes,
        Err(error) => {
            report.diagnostic = Some(memory_error(&error));
            return Ok(report);
        }
    };
    report.status = if observed == expected {
        ProbeStatus::Matched
    } else {
        ProbeStatus::Different
    };
    report.observed_hex = Some(encode_hex(&observed));
    Ok(report)
}

pub fn validate_origin_probe(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &ExecutionSnapshot,
    report: &OriginProbe,
) -> Result<(), String> {
    let expected = probe_origin(
        elf,
        input,
        snapshot,
        &report.origin_id,
        report.location.clone(),
    )?;
    if *report != expected {
        return Err("OriginProbe disagrees with its bound input and snapshot".into());
    }
    Ok(())
}

fn origin_bytes(input: &InputSpec, origin_id: &str) -> Result<Vec<u8>, String> {
    let origin = input
        .origins
        .iter()
        .find(|candidate| candidate.id == origin_id)
        .ok_or("InputSpec origin ID is missing")?;
    let channel = match &origin.channel {
        InputChannel::Stdin => decode_hex(&input.stdin_hex, crate::MAX_INPUT_BYTES)?,
        InputChannel::Argv { index } => decode_hex(
            input
                .argv_hex
                .get(*index)
                .ok_or("origin argv index is missing")?,
            4096,
        )?,
        InputChannel::File { path } => decode_hex(
            &input
                .files
                .iter()
                .find(|file| &file.path == path)
                .ok_or("origin file is missing")?
                .bytes_hex,
            crate::MAX_INPUT_BYTES,
        )?,
    };
    let end = origin
        .offset
        .checked_add(origin.length)
        .ok_or("origin range overflows")?;
    channel
        .get(origin.offset..end)
        .map(<[u8]>::to_vec)
        .ok_or("origin range is outside its input channel".into())
}

fn memory_error(error: &MemoryReadError) -> String {
    match error {
        MemoryReadError::TooLarge => "requested memory range exceeds limit".into(),
        MemoryReadError::AddressOverflow => "memory address range overflows".into(),
        MemoryReadError::MissingPage { address } => {
            format!("snapshot did not capture page 0x{address:x}")
        }
        MemoryReadError::UnavailablePage { address, .. } => {
            format!("snapshot page 0x{address:x} is unavailable")
        }
        MemoryReadError::InvalidPage { address } => {
            format!("snapshot page 0x{address:x} is invalid")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InputEncoding, InputOrigin, MemoryMapping, MemoryPage, MemoryPageState, ReplayBudget,
        ReplayGoal, StopPoint,
    };
    use std::collections::BTreeMap;

    fn fixture() -> (Vec<u8>, InputSpec, ExecutionSnapshot) {
        let elf = include_bytes!("../../../demo/hydir-prism.elf").to_vec();
        let input = InputSpec {
            schema_version: 1,
            binary_sha256: format!("{:x}", Sha256::digest(&elf)),
            argv_hex: Vec::new(),
            stdin_hex: "4142".into(),
            files: Vec::new(),
            origins: vec![InputOrigin {
                id: "phrase".into(),
                channel: InputChannel::Stdin,
                offset: 0,
                length: 2,
                encoding: InputEncoding::Ascii,
                alphabet_hex: String::new(),
            }],
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
        };
        let mut registers = BTreeMap::new();
        registers.insert("rip".into(), RegisterObservation::Present { value: 0x1000 });
        registers.insert("rsp".into(), RegisterObservation::Present { value: 0x2100 });
        registers.insert(
            "eflags".into(),
            RegisterObservation::Present { value: 0x202 },
        );
        registers.insert("rdi".into(), RegisterObservation::Present { value: 0x1100 });
        let mut page = vec![0u8; 4096];
        page[0x100..0x102].copy_from_slice(b"AB");
        let snapshot = ExecutionSnapshot {
            schema_version: 1,
            binary_sha256: input.binary_sha256.clone(),
            input_sha256: crate::input_sha256(&input).unwrap(),
            status: SnapshotStatus::Stopped,
            stop: Some(StopPoint {
                runtime_pc: 0x1000,
                elf_vaddr: Some(0x1000),
                load_bias: Some(0),
                symbol: None,
            }),
            thread_id: Some(1),
            thread_count: 1,
            registers,
            mappings: vec![MemoryMapping {
                start: 0x1000,
                end: 0x3000,
                file_offset: 0,
                readable: true,
                writable: true,
                executable: true,
                path: None,
            }],
            pages: vec![MemoryPage {
                address: 0x1000,
                value: MemoryPageState::Present {
                    bytes_hex: encode_hex(&page),
                },
            }],
            runner: "fixture".into(),
            diagnostics: Vec::new(),
        };
        (elf, input, snapshot)
    }

    #[test]
    fn probe_reports_equality_without_claiming_provenance() {
        let (elf, input, snapshot) = fixture();
        let location = ProbeLocation::Register {
            name: "rdi".into(),
            offset: 0,
        };
        let report = probe_origin(&elf, &input, &snapshot, "phrase", location).unwrap();
        assert_eq!(report.status, ProbeStatus::Matched);
        assert_eq!(report.evidence, ProbeEvidence::ByteEqualityOnly);
        assert_eq!(report.runtime_address, Some(0x1100));
        validate_origin_probe(&elf, &input, &snapshot, &report).unwrap();
        let round_trip = parse_origin_probe(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert_eq!(round_trip, report);
        let mut forged = report.clone();
        forged.observed_hex = Some("0000".into());
        assert!(validate_origin_probe(&elf, &input, &snapshot, &forged).is_err());
        let mut changed_snapshot = snapshot.clone();
        changed_snapshot.pages[0].value = MemoryPageState::Present {
            bytes_hex: encode_hex(&vec![0u8; 4096]),
        };
        assert!(validate_origin_probe(&elf, &input, &changed_snapshot, &report).is_err());
    }

    #[test]
    fn probe_distinguishes_different_and_missing_memory() {
        let (elf, input, mut snapshot) = fixture();
        let location = ProbeLocation::Register {
            name: "rdi".into(),
            offset: 0,
        };
        snapshot.pages[0].value = MemoryPageState::Present {
            bytes_hex: encode_hex(&vec![0u8; 4096]),
        };
        let different = probe_origin(&elf, &input, &snapshot, "phrase", location.clone()).unwrap();
        assert_eq!(different.status, ProbeStatus::Different);
        assert_eq!(different.observed_hex.as_deref(), Some("0000"));
        snapshot.pages[0].value = MemoryPageState::Unavailable {
            reason: "read failed".into(),
        };
        let missing = probe_origin(&elf, &input, &snapshot, "phrase", location).unwrap();
        assert_eq!(missing.status, ProbeStatus::Unavailable);
        assert!(missing.observed_hex.is_none());
        assert!(missing.diagnostic.is_some());
    }
}
