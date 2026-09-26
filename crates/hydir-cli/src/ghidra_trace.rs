//! Reproducible, binary-bound seed files for bounded concrete P-code traces.

use hydir_ir::pcode::{GhidraSnapshot, PcodeConcreteState, PcodeVarnode};
use serde::Deserialize;
use std::collections::BTreeSet;

pub const MAX_SEED_BYTES: usize = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedFile {
    schema_version: u32,
    binary_sha256: String,
    entry: hydir_ir::pcode::PcodeAddress,
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

pub fn parse_seed(bytes: &[u8], snapshot: &GhidraSnapshot) -> Result<PcodeConcreteState, String> {
    if bytes.is_empty() || bytes.len() > MAX_SEED_BYTES {
        return Err("P-code seed file is empty or exceeds 1 MiB".to_owned());
    }
    let seed: SeedFile = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if seed.schema_version != 1
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
