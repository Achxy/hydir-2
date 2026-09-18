//! ELF-aware x86-64 disassembly with explicit uncertainty boundaries.

use crate::{HydirError, Result, error, parse_elf};
use hydir_core::{
    Address, DISASSEMBLY_SCHEMA_VERSION, DisassemblyFlow, DisassemblyFunction, DisassemblyGap,
    DisassemblyInstruction, DisassemblyReport, DisassemblySection,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

const MAX_DISASSEMBLY_SECTIONS: usize = 4096;
const MAX_DISASSEMBLY_INSTRUCTIONS: usize = 1_000_000;

#[derive(Clone)]
struct SectionBytes {
    address: u64,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct Seed {
    name: String,
    address: u64,
    size: u64,
    section: usize,
    provenance: String,
}

fn direct_target(instruction: &Instruction) -> Option<u64> {
    match instruction.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(instruction.near_branch_target())
        }
        _ => None,
    }
}

fn classify_flow(instruction: &Instruction) -> (DisassemblyFlow, Option<u64>) {
    match instruction.flow_control() {
        FlowControl::Next => (DisassemblyFlow::Next, None),
        FlowControl::ConditionalBranch => (
            DisassemblyFlow::ConditionalBranch,
            direct_target(instruction),
        ),
        FlowControl::UnconditionalBranch => (
            DisassemblyFlow::UnconditionalBranch,
            direct_target(instruction),
        ),
        FlowControl::Call => (DisassemblyFlow::Call, direct_target(instruction)),
        FlowControl::IndirectBranch => (DisassemblyFlow::IndirectBranch, None),
        FlowControl::IndirectCall => (DisassemblyFlow::IndirectCall, None),
        FlowControl::Return => (DisassemblyFlow::Return, None),
        _ => (DisassemblyFlow::Unknown, None),
    }
}

fn instruction_text(instruction: &Instruction) -> (String, String) {
    let mnemonic = format!("{:?}", instruction.mnemonic()).to_lowercase();
    let rendered = instruction.to_string();
    let operands = rendered
        .strip_prefix(&mnemonic)
        .unwrap_or(&rendered)
        .trim()
        .to_owned();
    (mnemonic, operands)
}

fn decode_at(section: &SectionBytes, offset: usize) -> Option<(Instruction, usize)> {
    let ip = section.address.checked_add(offset as u64)?;
    let mut decoder = Decoder::with_ip(64, &section.bytes[offset..], ip, DecoderOptions::NONE);
    let instruction = decoder.decode();
    let length = decoder.position();
    if instruction.is_invalid() || length == 0 {
        None
    } else {
        Some((instruction, length))
    }
}

fn append_gap(
    gaps: &mut Vec<DisassemblyGap>,
    address: u64,
    size: u64,
    reason: &str,
    provenance: &str,
) {
    if size == 0 {
        return;
    }
    if let Some(previous) = gaps.last_mut()
        && previous.address.0.saturating_add(previous.size) == address
        && previous.reason == reason
        && previous.provenance == provenance
    {
        previous.size = previous.size.saturating_add(size);
        return;
    }
    gaps.push(DisassemblyGap {
        address: Address(address),
        size,
        reason: reason.to_owned(),
        provenance: provenance.to_owned(),
    });
}

fn recover_seed(
    section: &SectionBytes,
    seed: &Seed,
    occupied: &mut [bool],
    instructions: &mut BTreeMap<u64, DisassemblyInstruction>,
    function_addresses: &mut BTreeSet<u64>,
    gaps: &mut Vec<DisassemblyGap>,
    warnings: &mut Vec<String>,
) {
    let section_end = section.address.saturating_add(section.bytes.len() as u64);
    let extent_end = seed
        .address
        .saturating_add(seed.size.max(1))
        .min(section_end);
    let mut pending = VecDeque::from([seed.address]);
    let mut seen = BTreeSet::new();
    while let Some(address) = pending.pop_front() {
        if !seen.insert(address) || address < seed.address || address >= extent_end {
            continue;
        }
        let Ok(offset) = usize::try_from(address.saturating_sub(section.address)) else {
            continue;
        };
        let Some((instruction, length)) = decode_at(section, offset) else {
            append_gap(gaps, address, 1, "undecodable bytes", &seed.provenance);
            warnings.push(format!(
                "invalid instruction at 0x{address:x} in trusted seed {}",
                seed.name
            ));
            continue;
        };
        let end = offset.saturating_add(length);
        if end > section.bytes.len() || instruction.next_ip() > extent_end {
            warnings.push(format!(
                "instruction at 0x{address:x} crosses seed extent for {}",
                seed.name
            ));
            continue;
        }
        if occupied[offset..end].iter().any(|occupied| *occupied) {
            if instructions.contains_key(&address) {
                function_addresses.insert(address);
                continue;
            }
            warnings.push(format!(
                "overlapping instruction target at 0x{address:x} for {}",
                seed.name
            ));
            append_gap(
                gaps,
                address,
                1,
                "overlaps recovered code",
                &seed.provenance,
            );
            continue;
        }
        occupied[offset..end].fill(true);
        let (flow, target) = classify_flow(&instruction);
        let (mnemonic, operands) = instruction_text(&instruction);
        let record = DisassemblyInstruction {
            address: Address(address),
            bytes_hex: section.bytes[offset..end]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            mnemonic,
            operands,
            flow,
            branch_target: target.map(Address),
            function: Some(seed.name.clone()),
            provenance: seed.provenance.clone(),
        };
        instructions.insert(address, record);
        function_addresses.insert(address);

        let next = instruction.next_ip();
        match flow {
            DisassemblyFlow::Next | DisassemblyFlow::Call => pending.push_back(next),
            DisassemblyFlow::ConditionalBranch => {
                pending.push_back(next);
                if let Some(target) = target {
                    pending.push_back(target);
                }
            }
            DisassemblyFlow::UnconditionalBranch => {
                if let Some(target) = target {
                    pending.push_back(target);
                } else {
                    warnings.push(format!("direct branch target unavailable at 0x{address:x}"));
                }
            }
            DisassemblyFlow::IndirectBranch | DisassemblyFlow::IndirectCall => {
                warnings.push(format!(
                    "unresolved indirect control flow at 0x{address:x} in {}",
                    seed.name
                ));
            }
            DisassemblyFlow::Return | DisassemblyFlow::Unknown => {}
        }
    }
}

pub fn disassemble_elf(bytes: &[u8]) -> Result<DisassemblyReport> {
    let file = parse_elf(bytes)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let mut sections = Vec::new();
    let mut executable = Vec::new();
    for section in file.sections() {
        if section.kind() != SectionKind::Text {
            continue;
        }
        if sections.len() >= MAX_DISASSEMBLY_SECTIONS {
            return Err(HydirError(
                "ELF executable section limit exceeded".to_owned(),
            ));
        }
        let data = section
            .data()
            .map_err(|read_error| error(format!("executable section read failed: {read_error}")))?;
        let name = section.name().unwrap_or("<invalid-name>").to_owned();
        let section_index = executable.len();
        sections.push(DisassemblySection {
            name: name.clone(),
            address: Address(section.address()),
            size: section.size(),
            executable: true,
            provenance: "ELF section metadata; SectionKind::Text".to_owned(),
        });
        executable.push((
            section.index(),
            section_index,
            SectionBytes {
                address: section.address(),
                bytes: data.to_vec(),
            },
        ));
    }
    if executable.is_empty() {
        return Err(error("ELF contains no executable text sections"));
    }

    let mut seeds = Vec::new();
    for symbol in file.symbols() {
        if symbol.kind() != SymbolKind::Text
            || !symbol.is_definition()
            || symbol.size() == 0
            || symbol.section_index().is_none()
        {
            continue;
        }
        if let Some((_, section_index, _)) = executable
            .iter()
            .find(|(index, _, _)| Some(*index) == symbol.section_index())
        {
            seeds.push(Seed {
                name: symbol.name().unwrap_or("<invalid-symbol>").to_owned(),
                address: symbol.address(),
                size: symbol.size(),
                section: *section_index,
                provenance: "ELF text symbol; recursive CFG recovery".to_owned(),
            });
        }
    }
    let entry = file.entry();
    if entry != 0
        && !seeds.iter().any(|seed| seed.address == entry)
        && let Some((_, section_index, section)) = executable.iter().find(|(_, _, section)| {
            entry >= section.address
                && entry < section.address.saturating_add(section.bytes.len() as u64)
        })
    {
        seeds.push(Seed {
            name: "<elf-entry>".to_owned(),
            address: entry,
            size: section
                .address
                .saturating_add(section.bytes.len() as u64)
                .saturating_sub(entry),
            section: *section_index,
            provenance: "ELF entry point; recursive CFG recovery".to_owned(),
        });
    }
    seeds.sort_by_key(|seed| (seed.section, seed.address, seed.name.clone()));

    let mut instructions = BTreeMap::new();
    let mut function_addresses: HashMap<u64, BTreeSet<u64>> = HashMap::new();
    let mut warnings = Vec::new();
    let mut gaps = Vec::new();
    for (section_number, (_, _, section)) in executable.iter().enumerate() {
        let mut occupied = vec![false; section.bytes.len()];
        for seed in seeds.iter().filter(|seed| seed.section == section_number) {
            let addresses = function_addresses.entry(seed.address).or_default();
            recover_seed(
                section,
                seed,
                &mut occupied,
                &mut instructions,
                addresses,
                &mut gaps,
                &mut warnings,
            );
        }
        let mut offset = 0usize;
        while offset < section.bytes.len() {
            if occupied[offset] {
                offset += 1;
                continue;
            }
            let Some((instruction, length)) = decode_at(section, offset) else {
                let address = section.address.saturating_add(offset as u64);
                append_gap(
                    &mut gaps,
                    address,
                    1,
                    "undecodable bytes",
                    "linear sweep uncertainty",
                );
                warnings.push(format!(
                    "undecodable byte at 0x{address:x} during linear sweep"
                ));
                offset += 1;
                continue;
            };
            let end = offset.saturating_add(length);
            if end > section.bytes.len() || occupied[offset..end].iter().any(|occupied| *occupied) {
                let address = section.address.saturating_add(offset as u64);
                append_gap(
                    &mut gaps,
                    address,
                    1,
                    "overlaps recovered code",
                    "linear sweep uncertainty",
                );
                offset += 1;
                continue;
            }
            occupied[offset..end].fill(true);
            let address = instruction.ip();
            let (flow, target) = classify_flow(&instruction);
            let (mnemonic, operands) = instruction_text(&instruction);
            instructions.insert(
                address,
                DisassemblyInstruction {
                    address: Address(address),
                    bytes_hex: section.bytes[offset..end]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                    mnemonic,
                    operands,
                    flow,
                    branch_target: target.map(Address),
                    function: None,
                    provenance: "linear sweep uncertainty; not a recovered function".to_owned(),
                },
            );
            offset = end;
            if instructions.len() > MAX_DISASSEMBLY_INSTRUCTIONS {
                return Err(error("disassembly instruction limit exceeded"));
            }
        }
    }

    let mut functions = Vec::new();
    for seed in seeds {
        let addresses = function_addresses.remove(&seed.address).unwrap_or_default();
        functions.push(DisassemblyFunction {
            name: seed.name,
            entry: Address(seed.address),
            size: seed.size,
            instruction_addresses: addresses.into_iter().map(Address).collect(),
            provenance: seed.provenance,
        });
    }
    gaps.sort_by_key(|gap| gap.address.0);
    Ok(DisassemblyReport {
        schema_version: DISASSEMBLY_SCHEMA_VERSION,
        binary_sha256: digest,
        target_triple: super::elf_target_triple(file.flags()).to_owned(),
        sections,
        functions,
        instructions: instructions.into_values().collect(),
        gaps,
        warnings,
        provenance: "HydIR ELF text sections, iced-x86 recursive seeds plus marked linear sweep"
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_section(bytes: &[u8]) -> SectionBytes {
        SectionBytes {
            address: 0x1000,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn decodes_sequential_instruction_and_return() {
        let section = test_section(&[0x48, 0x89, 0xf8, 0xc3]);
        let mut occupied = vec![false; section.bytes.len()];
        let mut instructions = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        let mut gaps = Vec::new();
        let mut warnings = Vec::new();
        recover_seed(
            &section,
            &Seed {
                name: "f".to_owned(),
                address: 0x1000,
                size: 4,
                section: 0,
                provenance: "test".to_owned(),
            },
            &mut occupied,
            &mut instructions,
            &mut addresses,
            &mut gaps,
            &mut warnings,
        );
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions.get(&0x1000).unwrap().mnemonic, "mov");
        assert_eq!(
            instructions.get(&0x1003).unwrap().flow,
            DisassemblyFlow::Return
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn follows_conditional_branch_and_marks_indirect_flow() {
        let section = test_section(&[0x74, 0x02, 0xff, 0xe0, 0xc3, 0xc3]);
        let mut occupied = vec![false; section.bytes.len()];
        let mut instructions = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        let mut gaps = Vec::new();
        let mut warnings = Vec::new();
        recover_seed(
            &section,
            &Seed {
                name: "f".to_owned(),
                address: 0x1000,
                size: 6,
                section: 0,
                provenance: "test".to_owned(),
            },
            &mut occupied,
            &mut instructions,
            &mut addresses,
            &mut gaps,
            &mut warnings,
        );
        assert_eq!(
            instructions.get(&0x1000).unwrap().flow,
            DisassemblyFlow::ConditionalBranch
        );
        assert_eq!(
            instructions.get(&0x1002).unwrap().flow,
            DisassemblyFlow::IndirectBranch
        );
        assert!(!warnings.is_empty());
    }

    #[test]
    fn records_direct_call_and_fallthrough() {
        let section = test_section(&[0xe8, 0x00, 0x00, 0x00, 0x00, 0xc3]);
        let mut occupied = vec![false; section.bytes.len()];
        let mut instructions = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        let mut gaps = Vec::new();
        let mut warnings = Vec::new();
        recover_seed(
            &section,
            &Seed {
                name: "caller".to_owned(),
                address: 0x1000,
                size: 6,
                section: 0,
                provenance: "test".to_owned(),
            },
            &mut occupied,
            &mut instructions,
            &mut addresses,
            &mut gaps,
            &mut warnings,
        );
        assert_eq!(
            instructions.get(&0x1000).unwrap().flow,
            DisassemblyFlow::Call
        );
        assert_eq!(
            instructions.get(&0x1000).unwrap().branch_target,
            Some(Address(0x1005))
        );
        assert_eq!(
            instructions.get(&0x1005).unwrap().flow,
            DisassemblyFlow::Return
        );
    }

    #[test]
    fn branch_into_owned_instruction_is_reported() {
        let section = test_section(&[0xeb, 0xff, 0xc3]);
        let mut occupied = vec![false; section.bytes.len()];
        let mut instructions = BTreeMap::new();
        let mut addresses = BTreeSet::new();
        let mut gaps = Vec::new();
        let mut warnings = Vec::new();
        recover_seed(
            &section,
            &Seed {
                name: "overlap".to_owned(),
                address: 0x1000,
                size: 3,
                section: 0,
                provenance: "test".to_owned(),
            },
            &mut occupied,
            &mut instructions,
            &mut addresses,
            &mut gaps,
            &mut warnings,
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("overlapping"))
        );
    }

    #[test]
    fn invalid_bytes_become_linear_sweep_gaps() {
        let section = test_section(&[0x0f, 0x0f, 0xc3]);
        let mut occupied = vec![false; section.bytes.len()];
        let mut instructions = BTreeMap::new();
        let mut gaps = Vec::new();
        let mut offset = 0;
        while offset < section.bytes.len() {
            if let Some((instruction, length)) = decode_at(&section, offset) {
                let end = offset + length;
                occupied[offset..end].fill(true);
                let (flow, target) = classify_flow(&instruction);
                let (mnemonic, operands) = instruction_text(&instruction);
                instructions.insert(
                    instruction.ip(),
                    DisassemblyInstruction {
                        address: Address(instruction.ip()),
                        bytes_hex: section.bytes[offset..end]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect(),
                        mnemonic,
                        operands,
                        flow,
                        branch_target: target.map(Address),
                        function: None,
                        provenance: "linear sweep uncertainty".to_owned(),
                    },
                );
                offset = end;
            } else {
                append_gap(
                    &mut gaps,
                    section.address + offset as u64,
                    1,
                    "undecodable bytes",
                    "linear sweep uncertainty",
                );
                offset += 1;
            }
        }
        assert!(!gaps.is_empty());
        assert!(
            instructions
                .values()
                .any(|instruction| instruction.flow == DisassemblyFlow::Return)
        );
    }
}
