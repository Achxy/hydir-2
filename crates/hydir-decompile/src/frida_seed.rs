//! Convert one validated entry capture into a partial raw-P-code seed.
//! Runtime memory and rebased PIE pointers are deliberately not guessed.

use hydir_execution::{
    DYNAMIC_TRACE_V2_VERSION, DYNAMIC_TRACE_V3_VERSION, DynamicTrace, InputSpec, TraceEventKind,
    validate_dynamic_trace,
};
use hydir_ir::pcode::{GhidraSnapshot, parse_pcode_seed, validate_ghidra_snapshot};
use hydir_loader::import_elf;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn address(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .ok_or("Ghidra address lacks 0x prefix")?;
    u64::from_str_radix(digits, 16).map_err(|_| "invalid Ghidra address".into())
}

/// Returns PcodeSeed v1 JSON. Its empty memory array is intentional: Frida's
/// entry register capture does not observe stack or global memory bytes.
pub fn frida_entry_pcode_seed(
    elf: &[u8],
    input: &InputSpec,
    snapshot: &GhidraSnapshot,
    trace: &DynamicTrace,
) -> Result<Vec<u8>, String> {
    validate_dynamic_trace(elf, input, trace)?;
    validate_ghidra_snapshot(snapshot, &input.binary_sha256)?;
    if !matches!(
        trace.schema_version,
        DYNAMIC_TRACE_V2_VERSION | DYNAMIC_TRACE_V3_VERSION
    ) {
        return Err("Frida entry seed needs DynamicTrace v2/v3 register capture".into());
    }
    let snapshot_digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(snapshot).map_err(|error| error.to_string())?)
    );
    if trace.ghidra_snapshot_sha256.as_deref() != Some(snapshot_digest.as_str()) {
        return Err("Frida trace is not bound to this Ghidra snapshot".into());
    }
    if trace.elf_load_bias != Some(0) {
        return Err("Frida entry seed cannot safely rebase runtime pointers from PIE yet".into());
    }
    let elf_base = import_elf(elf)
        .map_err(|error| error.to_string())?
        .mapped_segments
        .iter()
        .filter(|segment| segment.address_space == 0 && segment.memory_size > 0)
        .map(|segment| segment.virtual_address.0)
        .min()
        .ok_or("ELF has no mapped RAM segment")?;
    let snapshot_base = address(&snapshot.program.image_base.offset)?;
    let snapshot_entry = address(&snapshot.selected_function.entry.offset)?;
    if snapshot.program.image_base.space != "ram"
        || snapshot.selected_function.entry.space != "ram"
        || snapshot_base != elf_base
        || snapshot_entry != trace.selected_elf_vaddr
    {
        return Err("Ghidra and Frida function addresses do not share an unrebased image".into());
    }
    if snapshot.register_layout.is_empty() {
        return Err("Ghidra snapshot has no exported register layout".into());
    }
    let mut entries = trace
        .events
        .iter()
        .filter(|event| matches!(event.kind, TraceEventKind::Entry));
    let event = entries.next().ok_or("Frida trace has no entry capture")?;
    if entries.next().is_some() {
        return Err("Frida trace has multiple entry captures; select one invocation first".into());
    }
    let captured = event
        .registers
        .as_ref()
        .ok_or("Frida entry registers are unavailable")?;
    let mut ranges = BTreeSet::new();
    let mut registers = Vec::new();
    for (name, value) in captured {
        let layout = snapshot
            .register_layout
            .iter()
            .find(|layout| &layout.name == name)
            .ok_or_else(|| format!("captured {name} has no Ghidra base-register layout"))?;
        if layout.size_bytes != 8 || layout.storage.space != "register" {
            return Err(format!("captured {name} has incompatible Ghidra storage"));
        }
        let offset = address(&layout.storage.offset)?;
        for byte in 0..8 {
            if !ranges.insert(offset + byte) {
                return Err("captured Ghidra base-register storage overlaps".into());
            }
        }
        registers.push(json!({
            "offset": layout.storage.offset,
            "size": 8,
            "value": format!("0x{value:x}"),
        }));
    }
    let seed = serde_json::to_vec_pretty(&json!({
        "schema_version": 1,
        "binary_sha256": input.binary_sha256,
        "entry": snapshot.selected_function.entry,
        "registers": registers,
        "memory": [],
    }))
    .map_err(|error| error.to_string())?;
    parse_pcode_seed(&seed, snapshot)?;
    Ok(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_execution::{
        INPUT_SPEC_VERSION, ReplayBudget, ReplayGoal, TraceBudget, TraceEvent, TraceStatus,
        TraceWitness, input_sha256,
    };
    use hydir_ir::pcode::parse_ghidra_snapshot;
    use serde_json::Value;
    use std::collections::BTreeMap;

    #[test]
    fn unrebased_entry_yields_partial_seed_and_rebased_entry_stops() {
        let elf = include_bytes!("../../../tests/fixtures/ghidra_add_zero.elf");
        let digest = format!("{:x}", Sha256::digest(elf));
        let mut snapshot_json: Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/ghidra_add_zero_v2.json"
        ))
        .unwrap();
        snapshot_json["register_layout"] = json!([
            {"name":"RDI","storage":{"space":"register","offset":"0x38"},"size_bytes":8},
            {"name":"RIP","storage":{"space":"register","offset":"0x288"},"size_bytes":8},
            {"name":"RSP","storage":{"space":"register","offset":"0x20"},"size_bytes":8}
        ]);
        let snapshot =
            parse_ghidra_snapshot(&serde_json::to_vec(&snapshot_json).unwrap(), &digest).unwrap();
        let entry = address(&snapshot.selected_function.entry.offset).unwrap();
        let image_base = address(&snapshot.program.image_base.offset).unwrap();
        let input = InputSpec {
            schema_version: INPUT_SPEC_VERSION,
            binary_sha256: digest.clone(),
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
        let witness = TraceWitness {
            runtime_address: entry,
            elf_vaddr: Some(entry),
            original_bytes_hex: Some(snapshot.selected_function.instructions[0].bytes.clone()),
        };
        let mut trace = DynamicTrace {
            schema_version: DYNAMIC_TRACE_V2_VERSION,
            binary_sha256: digest,
            input_sha256: input_sha256(&input).unwrap(),
            selected_elf_vaddr: entry,
            ghidra_snapshot_sha256: Some(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&snapshot).unwrap())
            )),
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
                    registers: Some(BTreeMap::from([
                        ("RDI".into(), 7),
                        ("RIP".into(), entry),
                        ("RSP".into(), 0x700000),
                    ])),
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
            jump_evidence: vec![],
        };
        let seed = frida_entry_pcode_seed(elf, &input, &snapshot, &trace).unwrap();
        let json: Value = serde_json::from_slice(&seed).unwrap();
        assert_eq!(json["registers"].as_array().unwrap().len(), 3);
        assert!(json["memory"].as_array().unwrap().is_empty());
        trace.elf_load_bias = Some(0x1000);
        trace.runtime_module_base = Some(image_base + 0x1000);
        for event in &mut trace.events {
            event.source.runtime_address += 0x1000;
        }
        trace.events[0]
            .registers
            .as_mut()
            .unwrap()
            .insert("RIP".into(), entry + 0x1000);
        assert!(
            frida_entry_pcode_seed(elf, &input, &snapshot, &trace)
                .unwrap_err()
                .contains("PIE")
        );
    }
}
