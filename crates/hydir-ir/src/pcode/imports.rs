//! Binary-bound ELF import and PLT-call evidence. A name here identifies a
//! relocation request; it does not assert the dynamic linker's final binding
//! or an external function's effects.

use super::{
    GhidraSnapshot, PcodeAddress, hex_u64, image::snapshot_layout_sha256,
    process_memory::checked_dynamic_table, validate_ghidra_snapshot,
};
use goblin::{elf::Elf, options::ParseOptions};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PCODE_ELF_IMPORT_INDEX_VERSION: u32 = 1;
const MAX_IMPORTS: usize = 65_536;
const MAX_IMPORT_NAME_BYTES: usize = 256;
const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeElfImport {
    pub name: String,
    /// Runtime address of the JUMP_SLOT relocation, after Ghidra's load bias.
    pub got: PcodeAddress,
    pub relocation_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeElfImportCall {
    pub call_site: PcodeAddress,
    pub plt_target: PcodeAddress,
    pub got: PcodeAddress,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeElfImportIndex {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub snapshot_layout_sha256: String,
    pub imports: Vec<PcodeElfImport>,
    /// Only direct, Ghidra-evidenced calls whose exact PLT jump bytes point
    /// at a named JUMP_SLOT are linked to an import.
    pub calls: Vec<PcodeElfImportCall>,
}

fn executable_bytes<'a>(
    elf: &Elf<'_>,
    binary: &'a [u8],
    address: u64,
    size: usize,
) -> Option<&'a [u8]> {
    let end = address.checked_add(size as u64)?;
    elf.program_headers.iter().find_map(|header| {
        if header.p_type != goblin::elf::program_header::PT_LOAD
            || header.p_flags & goblin::elf::program_header::PF_X == 0
            || address < header.p_vaddr
            || end > header.p_vaddr.checked_add(header.p_filesz)?
        {
            return None;
        }
        let offset =
            usize::try_from(header.p_offset.checked_add(address - header.p_vaddr)?).ok()?;
        binary.get(offset..offset.checked_add(size)?)
    })
}

fn plt_got_address(elf: &Elf<'_>, binary: &[u8], target: u64) -> Option<u64> {
    let first = executable_bytes(elf, binary, target, 10)?;
    let prefix = if first.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa]) {
        4
    } else {
        0
    };
    if first.get(prefix..prefix + 2)? != [0xff, 0x25] {
        return None;
    }
    let displacement = i32::from_le_bytes(first.get(prefix + 2..prefix + 6)?.try_into().ok()?);
    u64::try_from(i128::from(target) + i128::from(prefix as u64 + 6) + i128::from(displacement))
        .ok()
}

fn read_imports(binary: &[u8]) -> Result<(Vec<(u64, String)>, Elf<'_>), String> {
    if binary.is_empty() || binary.len() > MAX_BINARY_BYTES {
        return Err("ELF import binary is empty or exceeds 64 MiB".to_owned());
    }
    let elf = Elf::parse_with_opts(binary, &ParseOptions::strict())
        .map_err(|error| format!("invalid ELF import metadata: {error}"))?;
    if !elf.is_64 || !elf.little_endian || elf.header.e_machine != goblin::elf::header::EM_X86_64 {
        return Err("ELF imports require x86-64 little-endian ELF".to_owned());
    }
    let mut imports = Vec::new();
    if let Some(dynamic) = &elf.dynamic {
        let tag = |wanted| -> Result<Option<u64>, String> {
            let mut values = dynamic
                .dyns
                .iter()
                .filter(|entry| entry.d_tag == wanted)
                .map(|entry| entry.d_val);
            let value = values.next();
            if values.next().is_some() {
                return Err("duplicate ELF import table tag".to_owned());
            }
            Ok(value)
        };
        let size = tag(goblin::elf::dynamic::DT_PLTRELSZ)?;
        let entry_size = match tag(goblin::elf::dynamic::DT_PLTREL)? {
            Some(goblin::elf::dynamic::DT_RELA) => 24,
            Some(goblin::elf::dynamic::DT_REL) => 16,
            None if size.unwrap_or(0) == 0 => 24,
            _ => return Err("ELF PLT relocation format is unsupported".to_owned()),
        };
        checked_dynamic_table(
            binary,
            &elf.program_headers,
            tag(goblin::elf::dynamic::DT_JMPREL)?,
            size,
            entry_size,
            elf.pltrelocs.len(),
        )?;
        for relocation in &elf.pltrelocs {
            if relocation.r_type != goblin::elf::reloc::R_X86_64_JUMP_SLOT {
                continue;
            }
            if imports.len() >= MAX_IMPORTS || relocation.r_addend.is_some_and(|addend| addend != 0)
            {
                return Err("ELF JUMP_SLOT import count or addend is unsupported".to_owned());
            }
            let slot_end = relocation
                .r_offset
                .checked_add(8)
                .ok_or("ELF JUMP_SLOT address overflows")?;
            if !elf.program_headers.iter().any(|header| {
                header.p_type == goblin::elf::program_header::PT_LOAD
                    && header.p_flags & goblin::elf::program_header::PF_W != 0
                    && relocation.r_offset >= header.p_vaddr
                    && header
                        .p_vaddr
                        .checked_add(header.p_memsz)
                        .is_some_and(|end| slot_end <= end)
            }) {
                return Err("ELF JUMP_SLOT is outside writable PT_LOAD".to_owned());
            }
            let symbol = elf
                .dynsyms
                .get(relocation.r_sym)
                .ok_or("ELF JUMP_SLOT symbol index is invalid")?;
            if symbol.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize {
                return Err("ELF JUMP_SLOT is not an undefined import".to_owned());
            }
            let name = elf
                .dynstrtab
                .get_at(symbol.st_name)
                .ok_or("ELF JUMP_SLOT symbol name is invalid")?;
            if name.is_empty()
                || name.len() > MAX_IMPORT_NAME_BYTES
                || name.chars().any(char::is_control)
            {
                return Err("ELF JUMP_SLOT symbol name is unsupported".to_owned());
            }
            imports.push((relocation.r_offset, name.to_owned()));
        }
    }
    imports.sort_by_key(|(address, _)| *address);
    if imports.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("ELF JUMP_SLOT slots overlap".to_owned());
    }
    Ok((imports, elf))
}

impl PcodeElfImportIndex {
    pub fn from_elf(binary: &[u8], snapshot: &GhidraSnapshot) -> Result<Self, String> {
        let digest = format!("{:x}", Sha256::digest(binary));
        validate_ghidra_snapshot(snapshot, &digest)?;
        let (raw_imports, elf) = read_imports(binary)?;
        let lowest = elf
            .program_headers
            .iter()
            .filter(|header| header.p_type == goblin::elf::program_header::PT_LOAD)
            .map(|header| header.p_vaddr)
            .min()
            .ok_or("ELF has no PT_LOAD segments")?;
        let bias = i128::from(hex_u64(&snapshot.program.image_base.offset)?) - i128::from(lowest);
        let space = &snapshot.program.image_base.space;
        let imports = raw_imports
            .into_iter()
            .map(|(got, name)| {
                Ok(PcodeElfImport {
                    name,
                    got: PcodeAddress {
                        space: space.clone(),
                        offset: format!(
                            "0x{:x}",
                            u64::try_from(i128::from(got) + bias)
                                .map_err(|_| "ELF GOT cannot map to Ghidra RAM")?
                        ),
                    },
                    relocation_type: "R_X86_64_JUMP_SLOT".to_owned(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut calls = Vec::new();
        let mut seen = BTreeSet::new();
        for call in &snapshot.selected_function.call_targets {
            if call.computed || call.conditional {
                continue;
            }
            let Some(target) = &call.target else { continue };
            if target.space != *space || call.call_site.space != *space {
                continue;
            }
            let target_value = hex_u64(&target.offset)?;
            let Ok(target_elf) = u64::try_from(i128::from(target_value) - bias) else {
                continue;
            };
            let Some(got_elf) = plt_got_address(&elf, binary, target_elf) else {
                continue;
            };
            let Ok(got_runtime) = u64::try_from(i128::from(got_elf) + bias) else {
                continue;
            };
            let Some(import) = imports.iter().find(|import| {
                import.got.space == *space && hex_u64(&import.got.offset).ok() == Some(got_runtime)
            }) else {
                continue;
            };
            if seen.insert((
                call.call_site.space.clone(),
                hex_u64(&call.call_site.offset)?,
                target_value,
            )) {
                calls.push(PcodeElfImportCall {
                    call_site: call.call_site.clone(),
                    plt_target: target.clone(),
                    got: import.got.clone(),
                    name: import.name.clone(),
                });
            }
        }
        calls.sort_by_key(|call| {
            (
                call.call_site.space.clone(),
                hex_u64(&call.call_site.offset).unwrap_or(0),
            )
        });
        Ok(Self {
            schema_version: PCODE_ELF_IMPORT_INDEX_VERSION,
            binary_sha256: digest,
            snapshot_layout_sha256: snapshot_layout_sha256(snapshot)?,
            imports,
            calls,
        })
    }

    pub fn parse_bound(
        json: &[u8],
        binary: &[u8],
        snapshot: &GhidraSnapshot,
    ) -> Result<Self, String> {
        if json.len() > 4 * 1024 * 1024 {
            return Err("ELF import index JSON exceeds 4 MiB".to_owned());
        }
        let parsed: Self = serde_json::from_slice(json)
            .map_err(|error| format!("invalid ELF import index JSON: {error}"))?;
        let canonical = Self::from_elf(binary, snapshot)?;
        if parsed != canonical {
            return Err("ELF import index differs from binary and Ghidra analysis".to_owned());
        }
        Ok(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plt_slots_and_stub_bytes_resolve_with_or_without_sections() {
        for binary in [
            include_bytes!("../../../../tests/fixtures/ghidra_import_calls.elf").as_slice(),
            include_bytes!("../../../../tests/fixtures/ghidra_import_calls_sectionless.elf")
                .as_slice(),
        ] {
            let (imports, elf) = read_imports(binary).unwrap();
            assert_eq!(
                imports,
                vec![(0x3428, "strlen".to_owned()), (0x3430, "memcmp".to_owned())]
            );
            assert_eq!(plt_got_address(&elf, binary, 0x1350), Some(0x3428));
            assert_eq!(plt_got_address(&elf, binary, 0x1360), Some(0x3430));
            assert_eq!(plt_got_address(&elf, binary, 0x1340), None);
            assert!(!imports.iter().any(|(got, _)| *got == 0x3420));
        }
    }
}
