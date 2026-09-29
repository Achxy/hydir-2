//! Input-bound runtime observations. These never assert static CFG completeness.

use crate::{InputSpec, decode_hex, input_sha256, validate_input_spec};
use object::{Object, ObjectSegment, SegmentFlags};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const DYNAMIC_TRACE_VERSION: u32 = 1;
pub const DYNAMIC_TRACE_V2_VERSION: u32 = 2;
pub const MAX_DYNAMIC_TRACE_JSON_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TRACE_EVENTS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceBudget {
    pub max_events: usize,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceStatus {
    Completed,
    Truncated,
    TimedOut,
    InjectionError,
    ProcessFault,
    Detached,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceEventKind {
    Entry,
    Block,
    Call,
    Exit,
}

/// `elf_vaddr` is present only if original runtime bytes match file-backed
/// executable bytes at that address. External call targets may remain unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceWitness {
    pub runtime_address: u64,
    pub elf_vaddr: Option<u64>,
    pub original_bytes_hex: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEvent {
    pub sequence: u64,
    pub thread_id: u32,
    pub kind: TraceEventKind,
    pub source: TraceWitness,
    pub target: Option<TraceWitness>,
    /// v2 entry-only CPU context, read before the selected function runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registers: Option<BTreeMap<String, u64>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicTrace {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub input_sha256: String,
    pub selected_elf_vaddr: u64,
    pub ghidra_snapshot_sha256: Option<String>,
    pub observer: String,
    pub frida_version: String,
    pub agent_sha256: String,
    pub runtime_module_base: Option<u64>,
    pub elf_load_bias: Option<u64>,
    pub budget: TraceBudget,
    pub status: TraceStatus,
    pub lost_events: u64,
    /// Output captured from the target. F0 does not observe its exit status.
    pub stdout_hex: String,
    pub stderr_hex: String,
    pub diagnostics: Vec<String>,
    pub events: Vec<TraceEvent>,
}

pub fn parse_dynamic_trace(json: &[u8]) -> Result<DynamicTrace, String> {
    if json.len() > MAX_DYNAMIC_TRACE_JSON_BYTES {
        return Err("DynamicTrace exceeds 16 MiB JSON limit".into());
    }
    serde_json::from_slice(json).map_err(|error| format!("invalid DynamicTrace JSON: {error}"))
}

pub fn validate_dynamic_trace(
    elf: &[u8],
    input: &InputSpec,
    trace: &DynamicTrace,
) -> Result<(), String> {
    validate_input_spec(elf, input)?;
    if !matches!(
        trace.schema_version,
        DYNAMIC_TRACE_VERSION | DYNAMIC_TRACE_V2_VERSION
    ) || trace.binary_sha256 != input.binary_sha256
        || trace.input_sha256 != input_sha256(input)?
    {
        return Err("DynamicTrace version or input binding is invalid".into());
    }
    let file = object::File::parse(elf).map_err(|error| error.to_string())?;
    if executable_file_bytes(&file, elf, trace.selected_elf_vaddr, 1).is_none() {
        return Err("selected address is outside file-backed executable ELF bytes".into());
    }
    if trace.budget.max_events == 0
        || trace.budget.max_events > MAX_TRACE_EVENTS
        || trace.budget.timeout_ms == 0
        || trace.budget.timeout_ms > input.budget.timeout_ms
        || trace.events.len() > trace.budget.max_events
        || trace.observer.is_empty()
        || trace.observer.len() > 128
        || trace.frida_version.is_empty()
        || trace.frida_version.len() > 64
        || !digest(&trace.agent_sha256)
        || trace
            .ghidra_snapshot_sha256
            .as_deref()
            .is_some_and(|value| !digest(value))
        || trace.diagnostics.len() > 16
        || trace.diagnostics.iter().any(|value| value.len() > 512)
    {
        return Err("DynamicTrace metadata or budget is invalid".into());
    }
    if trace.runtime_module_base.is_some() != trace.elf_load_bias.is_some() {
        return Err("runtime module base and ELF load bias must be paired".into());
    }
    if let (Some(base), Some(bias)) = (trace.runtime_module_base, trace.elf_load_bias) {
        let image_base = file
            .segments()
            .filter_map(|segment| {
                let (offset, size) = segment.file_range();
                (size > 0 && offset == 0).then_some(segment.address() & !4095)
            })
            .min()
            .or_else(|| {
                file.segments()
                    .map(|segment| segment.address() & !4095)
                    .min()
            })
            .ok_or("ELF has no load segments")?;
        if image_base.checked_add(bias) != Some(base) {
            return Err("runtime module base disagrees with ELF load bias".into());
        }
    }
    let stdout = decode_hex(&trace.stdout_hex, input.budget.output_bytes as usize)?;
    let stderr = decode_hex(&trace.stderr_hex, input.budget.output_bytes as usize)?;
    if stdout.len() + stderr.len() > input.budget.output_bytes as usize {
        return Err("observed output exceeds InputSpec budget".into());
    }
    let mut entries = 0;
    let mut exits = 0;
    for (index, event) in trace.events.iter().enumerate() {
        if event.sequence != index as u64 || event.thread_id == 0 {
            return Err("DynamicTrace sequence or thread ID is invalid".into());
        }
        validate_witness(&file, elf, trace.elf_load_bias, &event.source)?;
        if let Some(target) = &event.target {
            validate_witness(&file, elf, trace.elf_load_bias, target)?;
        }
        if matches!(event.kind, TraceEventKind::Entry) {
            entries += 1;
            if event.source.elf_vaddr != Some(trace.selected_elf_vaddr) {
                return Err("entry does not match selected ELF address".into());
            }
        }
        match (&event.kind, &event.registers, trace.schema_version) {
            (TraceEventKind::Entry, Some(registers), DYNAMIC_TRACE_V2_VERSION) => {
                validate_entry_registers(registers, event.source.runtime_address)?;
            }
            (TraceEventKind::Entry, None, DYNAMIC_TRACE_V2_VERSION) => {
                return Err("v2 entry lacks captured register context".into());
            }
            (_, Some(_), _) => {
                return Err("register context is only allowed on v2 entry events".into());
            }
            _ => {}
        }
        if matches!(event.kind, TraceEventKind::Exit) {
            exits += 1;
        }
        if matches!(event.kind, TraceEventKind::Call) != event.target.is_some() {
            return Err("call target presence is invalid".into());
        }
    }
    if matches!(trace.status, TraceStatus::Completed)
        && (entries == 0 || exits == 0 || trace.lost_events != 0)
    {
        return Err("completed trace lacks entry/exit or has lost events".into());
    }
    if matches!(trace.status, TraceStatus::Truncated)
        && trace.events.len() < trace.budget.max_events
        && trace.lost_events == 0
    {
        return Err("truncated trace has not reached its event cap".into());
    }
    Ok(())
}

fn validate_entry_registers(
    registers: &BTreeMap<String, u64>,
    runtime_entry: u64,
) -> Result<(), String> {
    const NAMES: &[&str] = &[
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12",
        "R13", "R14", "R15", "RIP",
    ];
    if registers.len() > NAMES.len()
        || registers.keys().any(|name| !NAMES.contains(&name.as_str()))
        || registers.get("RIP") != Some(&runtime_entry)
        || !registers.contains_key("RSP")
    {
        return Err("v2 entry register layout or runtime RIP is invalid".into());
    }
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_witness(
    file: &object::File<'_>,
    elf: &[u8],
    bias: Option<u64>,
    witness: &TraceWitness,
) -> Result<(), String> {
    match (witness.elf_vaddr, witness.original_bytes_hex.as_deref()) {
        (Some(address), Some(bytes)) => {
            let decoded = decode_hex(bytes, 16)?;
            if decoded.is_empty() {
                return Err("normalized witness has no runtime bytes".into());
            }
            if bias.and_then(|value| address.checked_add(value)) != Some(witness.runtime_address) {
                return Err("normalized witness does not match ELF load bias".into());
            }
            if executable_file_bytes(file, elf, address, decoded.len()) != Some(decoded.as_slice())
            {
                return Err("normalized witness differs from file-backed executable bytes".into());
            }
        }
        (None, None) => {}
        _ => return Err("witness address and original bytes must be paired".into()),
    }
    Ok(())
}

fn executable_file_bytes<'a>(
    file: &object::File<'_>,
    elf: &'a [u8],
    address: u64,
    length: usize,
) -> Option<&'a [u8]> {
    for segment in file.segments() {
        if !matches!(segment.flags(), SegmentFlags::Elf { p_flags } if p_flags & object::elf::PF_X != 0)
        {
            continue;
        }
        let (offset, size) = segment.file_range();
        let Some(relative) = address.checked_sub(segment.address()) else {
            continue;
        };
        if relative
            .checked_add(length as u64)
            .is_none_or(|end| end > size)
        {
            continue;
        }
        let start = usize::try_from(offset.checked_add(relative)?).ok()?;
        return elf.get(start..start.checked_add(length)?);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{INPUT_SPEC_VERSION, ReplayBudget, ReplayGoal};
    use object::Object;
    use sha2::{Digest, Sha256};

    #[test]
    fn trace_identity_and_runtime_bytes_are_checked() {
        let elf = include_bytes!("../../../tests/fixtures/ghidra_add_zero.elf");
        let file = object::File::parse(elf.as_slice()).unwrap();
        let address = file.entry();
        let image_base = file
            .segments()
            .filter_map(|segment| {
                let (offset, size) = segment.file_range();
                (size > 0 && offset == 0).then_some(segment.address() & !4095)
            })
            .min()
            .unwrap();
        let input = InputSpec {
            schema_version: INPUT_SPEC_VERSION,
            binary_sha256: format!("{:x}", Sha256::digest(elf)),
            argv_hex: vec![],
            stdin_hex: String::new(),
            files: vec![],
            origins: vec![],
            goal: ReplayGoal {
                exit_code: Some(0),
                stdout_contains_hex: None,
                stderr_contains_hex: None,
            },
            budget: ReplayBudget {
                timeout_ms: 2000,
                memory_bytes: 1024 * 1024 * 1024,
                output_bytes: 1024,
            },
        };
        let bytes = executable_file_bytes(&file, elf, address, 4).unwrap();
        let witness = TraceWitness {
            runtime_address: address,
            elf_vaddr: Some(address),
            original_bytes_hex: Some(crate::encode_hex(bytes)),
        };
        let mut trace = DynamicTrace {
            schema_version: DYNAMIC_TRACE_VERSION,
            binary_sha256: input.binary_sha256.clone(),
            input_sha256: input_sha256(&input).unwrap(),
            selected_elf_vaddr: address,
            ghidra_snapshot_sha256: None,
            observer: "test".into(),
            frida_version: "17.9.5".into(),
            agent_sha256: format!("{:x}", Sha256::digest(b"test")),
            runtime_module_base: Some(image_base),
            elf_load_bias: Some(0),
            budget: TraceBudget {
                max_events: 8,
                timeout_ms: 1000,
            },
            status: TraceStatus::Completed,
            lost_events: 0,
            stdout_hex: String::new(),
            stderr_hex: String::new(),
            diagnostics: vec![],
            events: vec![
                TraceEvent {
                    sequence: 0,
                    thread_id: 1,
                    kind: TraceEventKind::Entry,
                    source: witness.clone(),
                    target: None,
                    registers: None,
                },
                TraceEvent {
                    sequence: 1,
                    thread_id: 1,
                    kind: TraceEventKind::Exit,
                    source: witness,
                    target: None,
                    registers: None,
                },
            ],
        };
        validate_dynamic_trace(elf, &input, &trace).unwrap();
        trace.events[0].source.original_bytes_hex = Some("90909090".into());
        assert!(validate_dynamic_trace(elf, &input, &trace).is_err());
        trace.events[0].source.original_bytes_hex = Some(crate::encode_hex(bytes));
        trace.input_sha256 = "0".repeat(64);
        assert!(validate_dynamic_trace(elf, &input, &trace).is_err());
        trace.input_sha256 = input_sha256(&input).unwrap();
        trace.status = TraceStatus::Truncated;
        assert!(validate_dynamic_trace(elf, &input, &trace).is_err());
        trace.lost_events = 1;
        validate_dynamic_trace(elf, &input, &trace).unwrap();
        let legacy = serde_json::to_vec(&trace).unwrap();
        assert!(
            parse_dynamic_trace(&legacy).unwrap().events[0]
                .registers
                .is_none()
        );
        trace.schema_version = DYNAMIC_TRACE_V2_VERSION;
        assert!(validate_dynamic_trace(elf, &input, &trace).is_err());
        trace.events[0].registers = Some(BTreeMap::from([
            ("RIP".into(), address),
            ("RSP".into(), 0x700000),
            ("RDI".into(), 5),
        ]));
        validate_dynamic_trace(elf, &input, &trace).unwrap();
        trace.events[0]
            .registers
            .as_mut()
            .unwrap()
            .insert("RIP".into(), address + 1);
        assert!(validate_dynamic_trace(elf, &input, &trace).is_err());
    }
}
