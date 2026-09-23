//! A bounded, digest-bound handoff from a captured process to symbolic analysis.
//! A matched origin probe asserts byte equality at a selected address, not provenance.

use crate::{
    ExecutionSnapshot, InputChannel, InputOrigin, InputSpec, MemoryPageState, OriginProbe,
    ProbeEvidence, ProbeStatus, RegisterObservation, SnapshotStatus, origin_probe::origin_bytes,
    read_snapshot_memory, validate_input_spec, validate_origin_probe,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SNAPSHOT_RESUME_VERSION: u32 = 1;
pub const MAX_SNAPSHOT_RESUME_JSON_BYTES: usize = 128 * 1024;
const MAX_CODE_BYTES: usize = 4096;
const MAX_SYMBOLIC_BYTES: usize = 32;
const MAX_PRESENT_PAGES: usize = 8;
const REQUIRED_REGISTERS: [&str; 18] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15", "rip", "eflags",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotResumePage {
    pub address: u64,
    pub bytes_hex: String,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotResumePlan {
    pub schema_version: u32,
    pub operation: String,
    pub binary_sha256: String,
    pub input_sha256: String,
    pub snapshot_sha256: String,
    pub probe_sha256: String,
    pub code_address: u64,
    pub code_hex: String,
    pub registers: BTreeMap<String, u64>,
    /// Only present captured pages. Every other memory byte remains unavailable.
    pub pages: Vec<SnapshotResumePage>,
    pub symbolic_origin: InputOrigin,
    pub origin_address: u64,
    pub seed_hex: String,
    pub origin_probe_evidence: ProbeEvidence,
    pub assumptions: Vec<String>,
    pub return_equals: u64,
    pub max_seeds: u32,
    pub max_instructions_per_seed: u32,
    pub max_solver_queries: u32,
    pub wall_timeout_ms: u32,
    pub solver_timeout_ms: u32,
}

pub fn parse_snapshot_resume_plan(json: &[u8]) -> Result<SnapshotResumePlan, String> {
    if json.len() > MAX_SNAPSHOT_RESUME_JSON_BYTES {
        return Err("SnapshotResumePlan exceeds 128 KiB JSON limit".into());
    }
    serde_json::from_slice(json)
        .map_err(|error| format!("invalid SnapshotResumePlan JSON: {error}"))
}

pub fn build_snapshot_resume_plan(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &ExecutionSnapshot,
    probe: &OriginProbe,
    code_bytes: usize,
    return_equals: u64,
) -> Result<SnapshotResumePlan, String> {
    validate_origin_probe(elf, input, snapshot, probe)?;
    if snapshot.status != SnapshotStatus::Stopped {
        return Err("resume requires a stopped snapshot".into());
    }
    if probe.status != ProbeStatus::Matched {
        return Err("resume requires a matched origin probe".into());
    }
    if code_bytes == 0 || code_bytes > MAX_CODE_BYTES {
        return Err("resume code must be 1..=4096 bytes".into());
    }
    let origin = input
        .origins
        .iter()
        .find(|candidate| candidate.id == probe.origin_id)
        .ok_or("resume origin is missing")?;
    if origin.length == 0 || origin.length > MAX_SYMBOLIC_BYTES {
        return Err("resume origin must be 1..=32 bytes".into());
    }
    let origin_address = probe
        .runtime_address
        .ok_or("matched probe has no runtime address")?;
    let stop = snapshot.stop.as_ref().ok_or("stopped snapshot has no PC")?;
    let code_end = stop
        .runtime_pc
        .checked_add(code_bytes as u64)
        .ok_or("resume code range overflows")?;
    let origin_end = origin_address
        .checked_add(origin.length as u64)
        .ok_or("resume origin range overflows")?;
    if origin_address < code_end && origin_end > stop.runtime_pc {
        return Err("resume origin overlaps executable code".into());
    }
    if !snapshot.mappings.iter().any(|mapping| {
        mapping.executable
            && mapping.readable
            && mapping.start <= stop.runtime_pc
            && code_end <= mapping.end
    }) {
        return Err("resume code range is outside one readable executable mapping".into());
    }
    let code = read_snapshot_memory(snapshot, stop.runtime_pc, code_bytes)
        .map_err(|error| format!("resume code is not fully captured: {error:?}"))?;
    let seed = origin_bytes(input, &origin.id)?;
    let observed = read_snapshot_memory(snapshot, origin_address, seed.len())
        .map_err(|error| format!("resume origin is not fully captured: {error:?}"))?;
    if seed != observed {
        return Err("resume origin differs from captured memory".into());
    }
    let mut registers = BTreeMap::new();
    for name in REQUIRED_REGISTERS {
        match snapshot.registers.get(name) {
            Some(RegisterObservation::Present { value }) => {
                registers.insert(name.to_owned(), *value);
            }
            _ => return Err(format!("resume requires captured register {name}")),
        }
    }
    let pages = snapshot
        .pages
        .iter()
        .filter_map(|page| match &page.value {
            MemoryPageState::Present { bytes_hex } => Some((page.address, bytes_hex)),
            MemoryPageState::Unavailable { .. } => None,
        })
        .map(|(address, bytes_hex)| {
            let end = address
                .checked_add(crate::snapshot::PAGE_BYTES as u64)
                .ok_or("resume page address overflows")?;
            let mapping = snapshot
                .mappings
                .iter()
                .find(|mapping| mapping.readable && mapping.start <= address && end <= mapping.end)
                .ok_or("resume page is outside readable mappings")?;
            Ok(SnapshotResumePage {
                address,
                bytes_hex: bytes_hex.clone(),
                writable: mapping.writable,
                executable: mapping.executable,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    if pages.len() > MAX_PRESENT_PAGES {
        return Err("resume contains more than eight present pages".into());
    }
    let plan = SnapshotResumePlan {
        schema_version: SNAPSHOT_RESUME_VERSION,
        operation: "snapshot_return".into(),
        binary_sha256: snapshot.binary_sha256.clone(),
        input_sha256: snapshot.input_sha256.clone(),
        snapshot_sha256: digest_json(snapshot)?,
        probe_sha256: digest_json(probe)?,
        code_address: stop.runtime_pc,
        code_hex: crate::encode_hex(&code),
        registers,
        pages,
        symbolic_origin: origin.clone(),
        origin_address,
        seed_hex: crate::encode_hex(&seed),
        origin_probe_evidence: probe.evidence.clone(),
        assumptions: vec![
            "analyst_selected_origin_address_has_input_channel_bytes".into(),
            "selected_code_extent_and_captured_pages_cover_this_function_path".into(),
        ],
        return_equals,
        max_seeds: 16,
        max_instructions_per_seed: 1024,
        max_solver_queries: 32,
        wall_timeout_ms: 20_000,
        solver_timeout_ms: 1000,
    };
    let encoded = serde_json::to_vec(&plan)
        .map_err(|error| format!("cannot serialize SnapshotResumePlan: {error}"))?;
    if encoded.len() > MAX_SNAPSHOT_RESUME_JSON_BYTES {
        return Err("SnapshotResumePlan exceeds 128 KiB bridge limit".into());
    }
    Ok(plan)
}

pub fn validate_snapshot_resume_plan(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &ExecutionSnapshot,
    probe: &OriginProbe,
    plan: &SnapshotResumePlan,
) -> Result<(), String> {
    if plan.code_hex.len() % 2 != 0 {
        return Err("resume code hex has an odd length".into());
    }
    let expected = build_snapshot_resume_plan(
        elf,
        input,
        snapshot,
        probe,
        plan.code_hex.len() / 2,
        plan.return_equals,
    )?;
    if *plan != expected {
        return Err("SnapshotResumePlan disagrees with bound artifacts".into());
    }
    Ok(())
}

/// Replace only the declared origin bytes; all other input bytes stay fixed.
pub fn input_with_origin_candidate(
    elf: &[u8],
    input: &InputSpec,
    origin_id: &str,
    candidate_hex: &str,
) -> Result<InputSpec, String> {
    validate_input_spec(elf, input)?;
    let origin = input
        .origins
        .iter()
        .find(|candidate| candidate.id == origin_id)
        .ok_or("candidate origin is missing")?;
    let candidate = crate::decode_hex(candidate_hex, MAX_SYMBOLIC_BYTES)?;
    if candidate.len() != origin.length {
        return Err("candidate length differs from origin length".into());
    }
    let mut revised = input.clone();
    let target = match &origin.channel {
        InputChannel::Stdin => &mut revised.stdin_hex,
        InputChannel::Argv { index } => revised
            .argv_hex
            .get_mut(*index)
            .ok_or("candidate argv index is missing")?,
        InputChannel::File { path } => {
            &mut revised
                .files
                .iter_mut()
                .find(|file| &file.path == path)
                .ok_or("candidate file is missing")?
                .bytes_hex
        }
    };
    let mut bytes = crate::decode_hex(target, crate::MAX_INPUT_BYTES)?;
    bytes[origin.offset..origin.offset + origin.length].copy_from_slice(&candidate);
    *target = crate::encode_hex(&bytes);
    validate_input_spec(elf, &revised)?;
    Ok(revised)
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("cannot serialize resume dependency: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        InputEncoding, MemoryMapping, MemoryPage, ProbeLocation, ReplayBudget, ReplayGoal,
        StopPoint, probe_origin,
    };

    fn fixture() -> (Vec<u8>, InputSpec, ExecutionSnapshot, OriginProbe) {
        let elf = include_bytes!("../../../demo/hydir-prism.elf").to_vec();
        let input = InputSpec {
            schema_version: 1,
            binary_sha256: format!("{:x}", Sha256::digest(&elf)),
            argv_hex: Vec::new(),
            stdin_hex: "42".into(),
            files: Vec::new(),
            origins: vec![InputOrigin {
                id: "byte0".into(),
                channel: InputChannel::Stdin,
                offset: 0,
                length: 1,
                encoding: InputEncoding::Raw,
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
        for name in REQUIRED_REGISTERS {
            registers.insert(name.into(), RegisterObservation::Present { value: 0 });
        }
        registers.insert("rip".into(), RegisterObservation::Present { value: 0x1000 });
        registers.insert("rsp".into(), RegisterObservation::Present { value: 0x3000 });
        registers.insert("rdi".into(), RegisterObservation::Present { value: 0x2000 });
        registers.insert(
            "eflags".into(),
            RegisterObservation::Present { value: 0x202 },
        );
        let code = [
            0x0f, 0xb6, 0x07, 0x83, 0xf8, 0x41, 0x0f, 0x94, 0xc0, 0x0f, 0xb6, 0xc0, 0xc3,
        ];
        let mut code_page = vec![0; 4096];
        code_page[..code.len()].copy_from_slice(&code);
        let mut input_page = vec![0; 4096];
        input_page[0] = b'B';
        let mut stack_page = vec![0; 4096];
        stack_page[..8].copy_from_slice(&0x4000u64.to_le_bytes());
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
                end: 0x4000,
                file_offset: 0,
                readable: true,
                writable: true,
                executable: true,
                path: Some("/work/program".into()),
            }],
            pages: [code_page, input_page, stack_page]
                .into_iter()
                .enumerate()
                .map(|(index, bytes)| MemoryPage {
                    address: 0x1000 + index as u64 * 4096,
                    value: MemoryPageState::Present {
                        bytes_hex: crate::encode_hex(&bytes),
                    },
                })
                .collect(),
            runner: "test".into(),
            diagnostics: Vec::new(),
        };
        let probe = probe_origin(
            &elf,
            &input,
            &snapshot,
            "byte0",
            ProbeLocation::Register {
                name: "rdi".into(),
                offset: 0,
            },
        )
        .unwrap();
        (elf, input, snapshot, probe)
    }

    #[test]
    fn plan_binds_captured_code_pages_registers_and_probe() {
        let (elf, input, snapshot, probe) = fixture();
        let plan = build_snapshot_resume_plan(&elf, &input, &snapshot, &probe, 13, 1).unwrap();
        assert_eq!(plan.code_hex, "0fb60783f8410f94c00fb6c0c3");
        assert_eq!(plan.origin_address, 0x2000);
        assert_eq!(plan.seed_hex, "42");
        assert_eq!(plan.pages.len(), 3);
        validate_snapshot_resume_plan(&elf, &input, &snapshot, &probe, &plan).unwrap();
        let parsed = parse_snapshot_resume_plan(&serde_json::to_vec(&plan).unwrap()).unwrap();
        assert_eq!(parsed, plan);

        let mut forged = plan.clone();
        forged.registers.insert("rdi".into(), 0x2100);
        assert!(validate_snapshot_resume_plan(&elf, &input, &snapshot, &probe, &forged).is_err());
        let mut forged = plan.clone();
        forged.pages[0].bytes_hex.replace_range(..2, "90");
        assert!(validate_snapshot_resume_plan(&elf, &input, &snapshot, &probe, &forged).is_err());
    }

    #[test]
    fn plan_refuses_missing_state_and_unmatched_probe() {
        let (elf, input, mut snapshot, probe) = fixture();
        snapshot.registers.remove("rbx");
        let missing = probe_origin(
            &elf,
            &input,
            &snapshot,
            "byte0",
            ProbeLocation::Register {
                name: "rdi".into(),
                offset: 0,
            },
        )
        .unwrap();
        assert!(
            build_snapshot_resume_plan(&elf, &input, &snapshot, &missing, 13, 1)
                .unwrap_err()
                .contains("captured register rbx")
        );

        let (elf, input, mut snapshot, _) = fixture();
        if let MemoryPageState::Present { bytes_hex } = &mut snapshot.pages[1].value {
            bytes_hex.replace_range(..2, "43");
        }
        let different = probe_origin(
            &elf,
            &input,
            &snapshot,
            "byte0",
            ProbeLocation::Register {
                name: "rdi".into(),
                offset: 0,
            },
        )
        .unwrap();
        assert_eq!(different.status, ProbeStatus::Different);
        assert!(
            build_snapshot_resume_plan(&elf, &input, &snapshot, &different, 13, 1)
                .unwrap_err()
                .contains("matched origin probe")
        );

        let (elf, input, mut snapshot, _) = fixture();
        snapshot.pages[0].value = MemoryPageState::Unavailable {
            reason: "read failed".into(),
        };
        let missing_code = probe_origin(
            &elf,
            &input,
            &snapshot,
            "byte0",
            ProbeLocation::Register {
                name: "rdi".into(),
                offset: 0,
            },
        )
        .unwrap();
        assert!(
            build_snapshot_resume_plan(&elf, &input, &snapshot, &missing_code, 13, 1)
                .unwrap_err()
                .contains("code is not fully captured")
        );
        let _ = probe;
    }

    #[test]
    fn candidate_replaces_only_declared_origin() {
        let (elf, input, _, _) = fixture();
        let revised = input_with_origin_candidate(&elf, &input, "byte0", "41").unwrap();
        assert_eq!(revised.stdin_hex, "41");
        assert_eq!(revised.goal, input.goal);
        assert_ne!(
            crate::input_sha256(&revised).unwrap(),
            crate::input_sha256(&input).unwrap()
        );
        assert!(input_with_origin_candidate(&elf, &input, "byte0", "4142").is_err());
    }
}
