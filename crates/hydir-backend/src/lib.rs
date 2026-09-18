//! Narrow, native ELF/x86-64 frontend and machine-code-to-LLVM lift.
//!
//! The supported slice accepts symbol-bounded, two-u64-argument SysV
//! functions. It rejects memory operations, calls, partial registers and
//! unknown instructions rather than guessing their behavior.

mod cfg;
mod disasm;

pub use cfg::lift_cfg;
pub use disasm::disassemble_elf;

use hydir_core::{
    Address, AddressKind, AddressSpaceSpec, FactProvenance, FactSource, FunctionCfg, FunctionSpec,
    ImportSpec, MappedSegmentSpec, PROGRAM_SPEC_VERSION, ProgramSpec, RecoveryState,
    RelocationSpec, RelocationTargetSpec, SectionSpec,
};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    ObjectSymbolTable, RelocationTarget, SectionKind, SymbolKind,
};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, error::Error, fmt};

#[derive(Debug)]
pub struct HydirError(pub String);

impl fmt::Display for HydirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for HydirError {}

pub type Result<T> = std::result::Result<T, HydirError>;
pub const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SPEC_SECTIONS: usize = 4096;
const MAX_SPEC_SEGMENTS: usize = 128;
const MAX_SPEC_FUNCTIONS: usize = 8192;
const MAX_SPEC_IMPORTS: usize = 8192;
const MAX_SPEC_RELOCATIONS: usize = 32768;
const MAX_METADATA_NAME_BYTES: usize = 4096;

fn error(message: impl Into<String>) -> HydirError {
    HydirError(message.into())
}

fn parse_elf(bytes: &[u8]) -> Result<object::File<'_>> {
    if bytes.len() > MAX_BINARY_BYTES {
        return Err(error("binary exceeds 64 MiB import limit"));
    }
    let file =
        object::File::parse(bytes).map_err(|e| error(format!("binary parse failed: {e}")))?;
    if file.format() != BinaryFormat::Elf
        || file.architecture() != Architecture::X86_64
        || !file.is_little_endian()
    {
        return Err(error("only little-endian x86-64 ELF is supported"));
    }
    Ok(file)
}

pub fn import_elf(bytes: &[u8]) -> Result<ProgramSpec> {
    let file = parse_elf(bytes)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let address_kind = if file.kind() == object::ObjectKind::Relocatable {
        AddressKind::SectionRelative
    } else {
        AddressKind::Virtual
    };
    let sections = file
        .sections()
        .take(MAX_SPEC_SECTIONS + 1)
        .map(|section| {
            Ok(SectionSpec {
                name: bounded_name(section.name().unwrap_or("<invalid-name>"))?,
                address: Address(section.address()),
                address_kind,
                file_offset: section.file_range().map(|(offset, _)| Address(offset)),
                size: section.size(),
                kind: format!("{:?}", section.kind()),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure_inventory_limit("sections", sections.len(), MAX_SPEC_SECTIONS)?;
    let mapped_segments = file
        .segments()
        .enumerate()
        .take(MAX_SPEC_SEGMENTS + 1)
        .map(|(index, segment)| {
            let (offset, file_size) = segment.file_range();
            let permissions = segment.permissions();
            MappedSegmentSpec {
                id: format!("sha256:{digest}:load:{index}"),
                address_space: 0,
                virtual_address: Address(segment.address()),
                memory_size: segment.size(),
                file_offset: Address(offset),
                file_size,
                alignment: segment.align(),
                readable: permissions.readable(),
                writable: permissions.writable(),
                executable: permissions.executable(),
                provenance: elf_metadata("PT_LOAD program header"),
            }
        })
        .collect::<Vec<_>>();
    ensure_inventory_limit("load segments", mapped_segments.len(), MAX_SPEC_SEGMENTS)?;
    let raw_imports = file
        .imports()
        .map_err(|e| error(format!("ELF import inventory failed: {e}")))?;
    ensure_inventory_limit("imports", raw_imports.len(), MAX_SPEC_IMPORTS)?;
    let imports = raw_imports
        .into_iter()
        .map(|import| {
            Ok(ImportSpec {
                library: byte_label(import.library())?,
                name: byte_label(import.name())?,
                provenance: elf_metadata("ELF dynamic import table"),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut relocations = Vec::new();
    for section in file.sections() {
        let section_name = bounded_name(section.name().unwrap_or("<invalid-name>"))?;
        for (offset, relocation) in section.relocations() {
            ensure_inventory_slot("relocations", relocations.len(), MAX_SPEC_RELOCATIONS)?;
            let location = section
                .address()
                .checked_add(offset)
                .ok_or_else(|| error(format!("relocation address overflows in {section_name}")))?;
            relocations.push(RelocationSpec {
                location: Address(location),
                address_kind,
                source_section: Some(section_name.clone()),
                kind: format!("{:?}", relocation.kind()),
                encoding: format!("{:?}", relocation.encoding()),
                format_flags: format!("{:?}", relocation.flags()),
                size_bits: relocation.size(),
                addend: relocation.addend(),
                implicit_addend: relocation.has_implicit_addend(),
                target: relocation_target(&file, relocation.target(), &digest, false)?,
                provenance: elf_metadata("ELF section relocation"),
            });
        }
    }
    if let Some(dynamic_relocations) = file.dynamic_relocations() {
        for (location, relocation) in dynamic_relocations {
            ensure_inventory_slot("relocations", relocations.len(), MAX_SPEC_RELOCATIONS)?;
            relocations.push(RelocationSpec {
                location: Address(location),
                address_kind: AddressKind::Virtual,
                source_section: None,
                kind: format!("{:?}", relocation.kind()),
                encoding: format!("{:?}", relocation.encoding()),
                format_flags: format!("{:?}", relocation.flags()),
                size_bits: relocation.size(),
                addend: relocation.addend(),
                implicit_addend: relocation.has_implicit_addend(),
                target: relocation_target(&file, relocation.target(), &digest, true)?,
                provenance: elf_metadata("ELF dynamic relocation"),
            });
        }
    }
    let functions = file
        .symbols()
        .filter(|symbol| {
            symbol.kind() == SymbolKind::Text
                && symbol.is_definition()
                && symbol.size() > 0
                && symbol.section_index().is_some()
        })
        .take(MAX_SPEC_FUNCTIONS + 1)
        .map(|symbol| {
            Ok(FunctionSpec {
                id: format!("sha256:{digest}:symbol:{:?}", symbol.index()),
                name: bounded_name(symbol.name().unwrap_or("<invalid-name>"))?,
                address: Address(symbol.address()),
                address_kind,
                section_name: symbol
                    .section_index()
                    .and_then(|index| file.section_by_index(index).ok())
                    .and_then(|section| section.name().ok().map(str::to_owned))
                    .map(|name| bounded_name(&name))
                    .transpose()?
                    .unwrap_or_else(|| "<invalid-name>".to_owned()),
                size: symbol.size(),
                provenance: "ELF symbol table".to_owned(),
                control_flow_status: "not recovered".to_owned(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure_inventory_limit("functions", functions.len(), MAX_SPEC_FUNCTIONS)?;
    Ok(ProgramSpec {
        schema_version: PROGRAM_SPEC_VERSION,
        binary_sha256: digest,
        target_triple: elf_target_triple(file.flags()).to_owned(),
        abi: "System V AMD64 (target convention; individual prototypes unknown)".to_owned(),
        file_kind: format!("{:?}", file.kind()),
        image_base: None,
        entry_point: (file.kind() != object::ObjectKind::Relocatable && file.entry() != 0)
            .then(|| Address(file.entry())),
        data_layout: None,
        address_spaces: (address_kind == AddressKind::Virtual)
            .then(|| AddressSpaceSpec {
                id: 0,
                name: "ELF process virtual memory".to_owned(),
                address_kind: AddressKind::Virtual,
                provenance: elf_metadata("linked ELF virtual address space"),
            })
            .into_iter()
            .collect(),
        mapped_segments,
        sections,
        functions,
        imports,
        relocations,
        calls: Vec::new(),
        references: Vec::new(),
        call_recovery: RecoveryState::NotAttempted,
        reference_recovery: RecoveryState::NotAttempted,
        assumptions: Vec::new(),
        recovery_scope: "ELF metadata inventory only; calls, references, and stripped-code discovery not attempted".to_owned(),
        unresolved_control_flow: true,
    })
}

fn ensure_inventory_limit(label: &str, count: usize, limit: usize) -> Result<()> {
    if count > limit {
        return Err(error(format!(
            "ELF {label} exceed inspection limit of {limit}"
        )));
    }
    Ok(())
}

fn ensure_inventory_slot(label: &str, count: usize, limit: usize) -> Result<()> {
    if count >= limit {
        return Err(error(format!(
            "ELF {label} exceed inspection limit of {limit}"
        )));
    }
    Ok(())
}

fn bounded_name(name: &str) -> Result<String> {
    if name.len() > MAX_METADATA_NAME_BYTES {
        return Err(error(format!(
            "ELF metadata name exceeds {MAX_METADATA_NAME_BYTES}-byte inspection limit"
        )));
    }
    Ok(name.to_owned())
}

fn elf_target_triple(flags: object::FileFlags) -> &'static str {
    match flags {
        object::FileFlags::Elf { os_abi, .. } if os_abi == object::elf::ELFOSABI_LINUX => {
            "x86_64-unknown-linux-gnu"
        }
        object::FileFlags::Elf { os_abi, .. } if os_abi == object::elf::ELFOSABI_FREEBSD => {
            "x86_64-unknown-freebsd"
        }
        _ => "x86_64-unknown-elf",
    }
}

fn elf_metadata(scope: &str) -> FactProvenance {
    FactProvenance {
        source: FactSource::ElfMetadata,
        scope: scope.to_owned(),
    }
}

fn byte_label(bytes: &[u8]) -> Result<String> {
    if bytes.len() > MAX_METADATA_NAME_BYTES {
        return Err(error(format!(
            "ELF import name exceeds {MAX_METADATA_NAME_BYTES}-byte inspection limit"
        )));
    }
    match std::str::from_utf8(bytes) {
        Ok(name) => Ok(name.to_owned()),
        Err(_) => Ok(format!(
            "hex:{}",
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        )),
    }
}

fn relocation_target(
    file: &object::File<'_>,
    target: RelocationTarget,
    digest: &str,
    dynamic: bool,
) -> Result<RelocationTargetSpec> {
    Ok(match target {
        RelocationTarget::Symbol(index) => RelocationTargetSpec::Symbol {
            id: format!(
                "sha256:{digest}:{}:{index:?}",
                if dynamic { "dynamic-symbol" } else { "symbol" }
            ),
            name: if dynamic {
                file.dynamic_symbol_table()
                    .and_then(|table| table.symbol_by_index(index).ok())
                    .and_then(|symbol| symbol.name().ok().map(str::to_owned))
            } else {
                file.symbol_by_index(index)
                    .ok()
                    .and_then(|symbol| symbol.name().ok().map(str::to_owned))
            }
            .map(|name| bounded_name(&name))
            .transpose()?,
        },
        RelocationTarget::Section(index) => RelocationTargetSpec::Section {
            name: bounded_name(
                &file
                    .section_by_index(index)
                    .ok()
                    .and_then(|section| section.name().ok().map(str::to_owned))
                    .unwrap_or_else(|| format!("<invalid-section:{index:?}>")),
            )?,
        },
        RelocationTarget::Absolute => RelocationTargetSpec::Absolute,
        other => RelocationTargetSpec::Unresolved {
            description: format!("{other:?}"),
        },
    })
}

/// Lift a named ELF symbol. The symbol's bytes, not source or pseudocode, are
/// decoded. The caller asserts the function prototype `u64(u64, u64)`.
pub fn lift_symbol(bytes: &[u8], name: &str) -> Result<String> {
    let (code, address, _) = symbol_code(bytes, name)?;
    lift_cfg(&code, address)
}

/// Extract a validated, bounded named text symbol for an external semantics
/// backend. ELF parsing and symbol-boundary validation remain owned by HydIR.
pub fn extract_symbol_code(bytes: &[u8], name: &str) -> Result<(Vec<u8>, u64)> {
    let (code, address, _) = symbol_code(bytes, name)?;
    Ok((code, address))
}

/// Recover the reachable, direct CFG for a named function symbol. This is a
/// symbol-scoped analysis result, separate from the initial ELF inventory.
pub fn recover_symbol_cfg(bytes: &[u8], name: &str) -> Result<FunctionCfg> {
    let (code, address, address_kind) = symbol_code(bytes, name)?;
    cfg::recover_function_cfg(
        &code,
        address,
        address_kind,
        name,
        format!("{:x}", Sha256::digest(bytes)),
        "ELF symbol extent and native iced-x86 decoding",
    )
}

/// Lift a bounded function at an analyst-supplied virtual entry address.
/// This permits stripped executables without inventing code-discovery facts.
pub fn lift_at(bytes: &[u8], address: u64, size: u64) -> Result<String> {
    let code = code_at(bytes, address, size)?;
    lift_cfg(&code, address)
}

pub fn recover_at_cfg(bytes: &[u8], address: u64, size: u64) -> Result<FunctionCfg> {
    let code = code_at(bytes, address, size)?;
    cfg::recover_function_cfg(
        &code,
        address,
        AddressKind::Virtual,
        &format!("analyst_entry_0x{address:x}"),
        format!("{:x}", Sha256::digest(bytes)),
        "Analyst-supplied virtual entry and byte extent; native iced-x86 decoding",
    )
}

fn code_at(bytes: &[u8], address: u64, size: u64) -> Result<Vec<u8>> {
    if size == 0 || size > 4096 {
        return Err(error(
            "analyst-supplied function size must be 1..=4096 bytes",
        ));
    }
    let end = address
        .checked_add(size)
        .ok_or_else(|| error("analyst-supplied address range overflow"))?;
    let file = parse_elf(bytes)?;
    if file.kind() == object::ObjectKind::Relocatable {
        return Err(error(
            "address-based recovery requires a linked ELF with virtual addresses",
        ));
    }
    let mut match_bytes = None;
    for section in file.sections() {
        if section.kind() != SectionKind::Text || section.size() > 16 * 1024 * 1024 {
            continue;
        }
        let section_end = section
            .address()
            .checked_add(section.size())
            .ok_or_else(|| error("text section address range overflow"))?;
        if address < section.address() || end > section_end {
            continue;
        }
        let start = usize::try_from(address - section.address())
            .map_err(|_| error("analyst entry exceeds host size"))?;
        let finish = usize::try_from(end - section.address())
            .map_err(|_| error("analyst extent exceeds host size"))?;
        let data = section
            .data()
            .map_err(|e| error(format!("text section read failed: {e}")))?;
        let code = data
            .get(start..finish)
            .ok_or_else(|| error("analyst extent exceeds text section data"))?;
        if match_bytes.replace(code.to_vec()).is_some() {
            return Err(error(
                "analyst address range matches multiple text sections",
            ));
        }
    }
    match_bytes.ok_or_else(|| error("analyst address range is not inside one text section"))
}

fn symbol_code(bytes: &[u8], name: &str) -> Result<(Vec<u8>, u64, AddressKind)> {
    let file = parse_elf(bytes)?;
    let symbol = file
        .symbols()
        .find(|symbol| {
            symbol.name().ok() == Some(name)
                && symbol.kind() == SymbolKind::Text
                && symbol.is_definition()
                && symbol.size() > 0
        })
        .ok_or_else(|| {
            error(format!(
                "function symbol {name:?} not found (stripped recovery unsupported)"
            ))
        })?;
    let index = symbol
        .section_index()
        .ok_or_else(|| error("symbol has no section"))?;
    let section = file
        .section_by_index(index)
        .map_err(|e| error(format!("section lookup failed: {e}")))?;
    if section.kind() != SectionKind::Text {
        return Err(error("function symbol is not in a text section"));
    }
    if symbol.size() > 4096 || section.size() > 16 * 1024 * 1024 {
        return Err(error(
            "symbol or text section exceeds this slice's lift limit",
        ));
    }
    let section_bytes = section
        .data()
        .map_err(|e| error(format!("section read failed: {e}")))?;
    let start = symbol
        .address()
        .checked_sub(section.address())
        .ok_or_else(|| error("symbol address precedes section"))?;
    let end = start
        .checked_add(symbol.size())
        .ok_or_else(|| error("symbol range overflow"))?;
    let start = usize::try_from(start).map_err(|_| error("symbol offset exceeds host size"))?;
    let end = usize::try_from(end).map_err(|_| error("symbol end exceeds host size"))?;
    let code = section_bytes
        .get(start..end)
        .ok_or_else(|| error("symbol bytes exceed section data"))?;
    let address_kind = if file.kind() == object::ObjectKind::Relocatable {
        AddressKind::SectionRelative
    } else {
        AddressKind::Virtual
    };
    Ok((code.to_vec(), symbol.address(), address_kind))
}

/// Emits a raw LLVM module for the supported instruction subset.
pub fn lift_linear(code: &[u8], address: u64) -> Result<String> {
    if code.is_empty() || code.len() > 4096 {
        return Err(error("function must contain 1..=4096 bytes"));
    }
    let mut decoder = Decoder::with_ip(64, code, address, DecoderOptions::NONE);
    let mut state = HashMap::<Register, String>::new();
    state.insert(Register::RDI, "%arg0".to_owned());
    state.insert(Register::RSI, "%arg1".to_owned());
    let mut body = String::new();
    let mut sequence = 0u32;
    let mut returned = false;

    while decoder.can_decode() {
        let offset = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(error(format!(
                "invalid x86 instruction at 0x{:x}",
                instruction.ip()
            )));
        }
        if instruction.has_lock_prefix()
            || instruction.has_rep_prefix()
            || instruction.has_repne_prefix()
        {
            return Err(error(format!(
                "instruction prefix unsupported at 0x{:x}",
                instruction.ip()
            )));
        }
        let raw = &code[offset..decoder.position()];
        let encoded = raw
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        body.push_str(&format!("  ; 0x{:x}: {}\n", instruction.ip(), encoded));
        match instruction.mnemonic() {
            Mnemonic::Mov
                if instruction.op_count() == 2
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register =>
            {
                let source = read_register(&state, instruction.op1_register(), instruction.ip())?;
                let target = checked_register(instruction.op0_register(), instruction.ip())?;
                state.insert(target, source);
            }
            Mnemonic::Lea
                if instruction.op_count() == 2
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Memory =>
            {
                let target = checked_register(instruction.op0_register(), instruction.ip())?;
                let result = lift_lea(&instruction, &state, &mut body, &mut sequence)?;
                state.insert(target, result);
            }
            Mnemonic::Add | Mnemonic::Sub
                if instruction.op_count() == 2
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register =>
            {
                // Flags are not consumed by any accepted instruction and are
                // outside this scalar ABI result contract.
                let target = checked_register(instruction.op0_register(), instruction.ip())?;
                let lhs = read_register(&state, target, instruction.ip())?;
                let rhs = read_register(&state, instruction.op1_register(), instruction.ip())?;
                let op = if instruction.mnemonic() == Mnemonic::Add {
                    "add"
                } else {
                    "sub"
                };
                let result = emit_binary(&mut body, &mut sequence, op, &lhs, &rhs);
                state.insert(target, result);
            }
            Mnemonic::Nop if instruction.op_count() == 0 => {}
            Mnemonic::Ret if instruction.op_count() == 0 => {
                let value = read_register(&state, Register::RAX, instruction.ip())?;
                body.push_str(&format!("  ret i64 {value}\n"));
                returned = true;
                if decoder.can_decode() {
                    return Err(error(
                        "bytes after return are unsupported in a function symbol",
                    ));
                }
            }
            _ => {
                return Err(error(format!(
                    "unsupported {:?} at 0x{:x}",
                    instruction.mnemonic(),
                    instruction.ip()
                )));
            }
        }
    }
    if !returned {
        return Err(error("function has no supported return"));
    }
    Ok(format!(
        "; HydIR raw lift; explicit prototype: u64(u64, u64)\n\
         ; Unsupported memory/calls/branches are rejected, not approximated.\n\
         target triple = \"x86_64-unknown-linux-gnu\"\n\n\
         define i64 @hydir_lifted(i64 %arg0, i64 %arg1) {{\nentry:\n{body}}}\n"
    ))
}

fn checked_register(register: Register, ip: u64) -> Result<Register> {
    match register {
        Register::RAX | Register::RDI | Register::RSI | Register::RDX | Register::RCX => {
            Ok(register)
        }
        _ => Err(error(format!(
            "register {register:?} unsupported at 0x{ip:x}; only full 64-bit scalar registers are modeled"
        ))),
    }
}

fn read_register(state: &HashMap<Register, String>, register: Register, ip: u64) -> Result<String> {
    checked_register(register, ip)?;
    state
        .get(&register)
        .cloned()
        .ok_or_else(|| error(format!("read of uninitialized {register:?} at 0x{ip:x}")))
}

fn emit_binary(body: &mut String, sequence: &mut u32, op: &str, lhs: &str, rhs: &str) -> String {
    let value = format!("%v{}", *sequence);
    *sequence += 1;
    body.push_str(&format!("  {value} = {op} i64 {lhs}, {rhs}\n"));
    value
}

fn lift_lea(
    instruction: &Instruction,
    state: &HashMap<Register, String>,
    body: &mut String,
    sequence: &mut u32,
) -> Result<String> {
    if instruction.segment_prefix() != Register::None || instruction.memory_base() == Register::RIP
    {
        return Err(error(format!(
            "segment/RIP-relative LEA unsupported at 0x{:x}",
            instruction.ip()
        )));
    }
    let base = if instruction.memory_base() == Register::None {
        "0".to_owned()
    } else {
        read_register(state, instruction.memory_base(), instruction.ip())?
    };
    let index = if instruction.memory_index() == Register::None {
        "0".to_owned()
    } else {
        read_register(state, instruction.memory_index(), instruction.ip())?
    };
    let scaled = if instruction.memory_index_scale() == 1 {
        index
    } else {
        emit_binary(
            body,
            sequence,
            "mul",
            &index,
            &instruction.memory_index_scale().to_string(),
        )
    };
    let sum = emit_binary(body, sequence, "add", &base, &scaled);
    let displacement = instruction.memory_displacement64() as i64;
    Ok(if displacement == 0 {
        sum
    } else {
        emit_binary(body, sequence, "add", &sum, &displacement.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifts_machine_lea_not_source() {
        // lea rax,[rdi+rsi]; ret
        let ir = lift_linear(&[0x48, 0x8d, 0x04, 0x37, 0xc3], 0x401000).unwrap();
        assert!(ir.contains("0x401000: 488d0437"));
        assert!(ir.contains("add i64 %arg0, %arg1"));
        assert!(ir.contains("ret i64 %v0"));
        assert!(!ir.contains("nsw"));
    }

    #[test]
    fn rejects_unknown_semantics() {
        // xor rax,rax; ret
        let err = lift_linear(&[0x48, 0x31, 0xc0, 0xc3], 0).unwrap_err();
        assert!(err.0.contains("unsupported Xor"));
    }

    #[test]
    fn rejects_partial_registers() {
        // mov eax,edi; ret
        let err = lift_linear(&[0x89, 0xf8, 0xc3], 0).unwrap_err();
        assert!(err.0.contains("full 64-bit"));
    }

    #[test]
    fn rejects_missing_result() {
        let err = lift_linear(&[0xc3], 0).unwrap_err();
        assert!(err.0.contains("uninitialized RAX"));
    }

    #[test]
    fn lifts_wrapping_add_without_poison_flags() {
        // mov rax,rdi; add rax,rsi; ret
        let ir = lift_linear(&[0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3], 0).unwrap();
        assert!(ir.contains("add i64 %arg0, %arg1"));
        assert!(!ir.contains("add nsw"));
        assert!(!ir.contains("add nuw"));
    }

    #[test]
    fn rejects_memory_read() {
        // mov rax,[rdi]; ret
        let err = lift_linear(&[0x48, 0x8b, 0x07, 0xc3], 0).unwrap_err();
        assert!(err.0.contains("unsupported Mov"));
    }

    #[test]
    fn metadata_inventory_limits_are_explicit() {
        assert!(ensure_inventory_limit("sections", MAX_SPEC_SECTIONS, MAX_SPEC_SECTIONS).is_ok());
        assert!(
            ensure_inventory_limit("sections", MAX_SPEC_SECTIONS + 1, MAX_SPEC_SECTIONS)
                .unwrap_err()
                .0
                .contains("sections exceed")
        );
        assert!(bounded_name(&"x".repeat(MAX_METADATA_NAME_BYTES)).is_ok());
        assert!(bounded_name(&"x".repeat(MAX_METADATA_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn generic_elf_osabi_is_not_claimed_as_linux() {
        let flags = object::FileFlags::Elf {
            os_abi: object::elf::ELFOSABI_SYSV,
            abi_version: 0,
            e_flags: 0,
        };
        assert_eq!(elf_target_triple(flags), "x86_64-unknown-elf");
        let flags = object::FileFlags::Elf {
            os_abi: object::elf::ELFOSABI_LINUX,
            abi_version: 0,
            e_flags: 0,
        };
        assert_eq!(elf_target_triple(flags), "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn external_symbol_extraction_rejects_non_elf() {
        let error = extract_symbol_code(b"not an ELF", "main").unwrap_err();
        assert!(error.0.contains("binary parse failed"));
    }

    #[test]
    fn external_symbol_extraction_rejects_missing_symbol() {
        let error = extract_symbol_code(&[], "missing").unwrap_err();
        assert!(error.0.contains("binary parse failed"));
    }
}
