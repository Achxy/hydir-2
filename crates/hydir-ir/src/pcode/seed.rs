//! Binary-bound concrete-state seeds for bounded Ghidra P-code traces.
//!
//! The v1 JSON shape is shared by the CLI, SDK, and desktop workbench. A seed
//! is accepted only for the selected function of the matching snapshot.

use super::{GhidraSnapshot, PcodeConcreteState, PcodeVarnode};
use serde::Deserialize;
use std::collections::BTreeSet;

pub const PCODE_SEED_VERSION: u32 = 1;
pub const MAX_PCODE_SEED_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedFile {
    schema_version: u32,
    binary_sha256: String,
    entry: super::PcodeAddress,
    #[serde(default)]
    registers: Vec<SeedRegister>,
    #[serde(default)]
    memory: Vec<SeedMemory>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedRegister {
    offset: String,
    size: u32,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedMemory {
    space: String,
    byte_offset: String,
    size: u32,
    value: String,
}

fn hex(value: &str) -> Result<u64, String> {
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("seed values and offsets must be 0x-prefixed hexadecimal")?;
    u64::from_str_radix(digits, 16).map_err(|_| "seed value exceeds u64".to_owned())
}

fn bounded_value(value: &str, size: u32) -> Result<u64, String> {
    if !(1..=8).contains(&size) {
        return Err("seed width must be 1..=8 bytes".to_owned());
    }
    let value = hex(value)?;
    if size < 8 && value >= (1u64 << (size * 8)) {
        return Err("seed value does not fit its declared width".to_owned());
    }
    Ok(value)
}

fn reserve_bytes(
    seen: &mut BTreeSet<(String, u64)>,
    space: &str,
    offset: u64,
    size: u32,
) -> Result<(), String> {
    if !(1..=8).contains(&size) || offset.checked_add(u64::from(size - 1)).is_none() {
        return Err("seed byte range is invalid".to_owned());
    }
    for index in 0..size {
        if !seen.insert((space.to_owned(), offset + u64::from(index))) {
            return Err("seed byte ranges overlap".to_owned());
        }
    }
    Ok(())
}

/// Parse a v1 seed file and validate its binding to a selected Ghidra
/// function. Register and memory bytes must be disjoint and exactly known.
pub fn parse_pcode_seed(
    bytes: &[u8],
    snapshot: &GhidraSnapshot,
) -> Result<PcodeConcreteState, String> {
    if bytes.is_empty() || bytes.len() > MAX_PCODE_SEED_BYTES {
        return Err("P-code seed file is empty or exceeds 1 MiB".to_owned());
    }
    let seed: SeedFile = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if seed.schema_version != PCODE_SEED_VERSION
        || seed.binary_sha256 != snapshot.binary_sha256
        || seed.entry != snapshot.selected_function.entry
    {
        return Err(
            "P-code seed version, binary digest, or function entry disagrees with snapshot"
                .to_owned(),
        );
    }
    if seed.registers.len() + seed.memory.len() > 65_536 {
        return Err("P-code seed has too many entries".to_owned());
    }
    let spaces = snapshot
        .address_spaces
        .iter()
        .filter(|space| space.space_type == 1)
        .map(|space| space.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut state = PcodeConcreteState::default();
    let mut seen = BTreeSet::new();
    for register in seed.registers {
        let offset = hex(&register.offset)?;
        let value = bounded_value(&register.value, register.size)?;
        reserve_bytes(&mut seen, "register", offset, register.size)?;
        state.write_varnode(
            &PcodeVarnode {
                space: "register".to_owned(),
                offset: register.offset,
                size: register.size,
            },
            value,
        )?;
    }
    for memory in seed.memory {
        if !spaces.contains(memory.space.as_str()) {
            return Err("P-code seed memory space is not a Ghidra RAM space".to_owned());
        }
        let offset = hex(&memory.byte_offset)?;
        let value = bounded_value(&memory.value, memory.size)?;
        reserve_bytes(&mut seen, &memory.space, offset, memory.size)?;
        state.write_memory(&memory.space, offset, memory.size, value)?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::parse_ghidra_snapshot;
    use serde_json::{Value, json};

    fn snapshot() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap()
    }

    fn seed(snapshot: &GhidraSnapshot) -> Value {
        json!({
            "schema_version": PCODE_SEED_VERSION,
            "binary_sha256": snapshot.binary_sha256,
            "entry": snapshot.selected_function.entry,
            "registers": [{"offset":"0x0","size":8,"value":"0x102030405060708"}],
            "memory": [{"space":"ram","byte_offset":"0x1000","size":8,"value":"0xdeadbeef"}]
        })
    }

    fn parse(value: &Value, snapshot: &GhidraSnapshot) -> Result<PcodeConcreteState, String> {
        parse_pcode_seed(&serde_json::to_vec(value).unwrap(), snapshot)
    }

    #[test]
    fn real_snapshot_seed_preserves_register_and_memory_bytes() {
        let snapshot = snapshot();
        let state = parse(&seed(&snapshot), &snapshot).unwrap();
        assert_eq!(
            state
                .read_varnode(&PcodeVarnode {
                    space: "register".to_owned(),
                    offset: "0x1".to_owned(),
                    size: 1,
                })
                .unwrap(),
            Some(0x07)
        );
        assert_eq!(
            state.read_memory("ram", 0x1000, 8).unwrap(),
            Some(0xdeadbeef)
        );
        assert_eq!(state.read_memory("ram", 0x1008, 1).unwrap(), None);

        let minimal = json!({
            "schema_version": PCODE_SEED_VERSION,
            "binary_sha256": snapshot.binary_sha256,
            "entry": snapshot.selected_function.entry
        });
        assert_eq!(
            parse(&minimal, &snapshot).unwrap(),
            PcodeConcreteState::default()
        );
    }

    #[test]
    fn rejects_wrong_binding_overlap_and_unknown_fields() {
        let snapshot = snapshot();
        let mut value = seed(&snapshot);
        value["binary_sha256"] = json!("0".repeat(64));
        assert!(
            parse(&value, &snapshot)
                .unwrap_err()
                .contains("disagrees with snapshot")
        );

        value = seed(&snapshot);
        value["entry"]["offset"] = json!("0x2013db");
        assert!(
            parse(&value, &snapshot)
                .unwrap_err()
                .contains("disagrees with snapshot")
        );

        value = seed(&snapshot);
        value["registers"].as_array_mut().unwrap().push(json!({
            "offset":"0x1","size":1,"value":"0x1"
        }));
        assert!(parse(&value, &snapshot).unwrap_err().contains("overlap"));

        value = seed(&snapshot);
        value["registers"][0]["extra"] = json!(true);
        assert!(parse(&value, &snapshot).is_err());
    }

    #[test]
    fn rejects_invalid_width_space_and_input_bounds() {
        let snapshot = snapshot();
        let mut value = seed(&snapshot);
        value["registers"][0]["size"] = json!(1);
        assert!(
            parse(&value, &snapshot)
                .unwrap_err()
                .contains("does not fit")
        );

        value = seed(&snapshot);
        value["memory"][0]["space"] = json!("stack");
        assert!(
            parse(&value, &snapshot)
                .unwrap_err()
                .contains("not a Ghidra RAM space")
        );

        value = seed(&snapshot);
        value["registers"][0]["offset"] = json!("0xffffffffffffffff");
        assert!(
            parse(&value, &snapshot)
                .unwrap_err()
                .contains("byte range is invalid")
        );

        assert!(parse_pcode_seed(&[], &snapshot).is_err());
        assert!(parse_pcode_seed(&vec![b' '; MAX_PCODE_SEED_BYTES + 1], &snapshot).is_err());
    }
}
