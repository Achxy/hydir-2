//! Bounded native loading of little-endian x86-64 ELF files.
//!
//! This crate owns immutable file-format facts. Discovery and semantic
//! conclusions belong to later pipeline stages and must not be fabricated by
//! the loader.

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian as GimliLittleEndian, UnwindSection};
use hydir_core::{
    Address, AddressKind, AddressSpaceSpec, DynamicSymbolSpec, FactProvenance, FactSource,
    FunctionSpec, ImportSpec, Location, MappedSegmentSpec, PROGRAM_SPEC_VERSION, ProgramHeaderSpec,
    ProgramSpec, RecoveryState, RelocationSpec, RelocationTargetSpec, RuntimePointerArrayKind,
    RuntimePointerArraySpec, RuntimePointerEntrySpec, RuntimeRangeKind, RuntimeRangeSpec,
    SectionSpec, UncertaintySpec, UnwindRangeSpec, validate_program_spec,
};
use object::endian::LittleEndian;
use object::read::elf::{ElfFile64, ProgramHeader as _, Sym as _};
use object::{
    Architecture, BinaryFormat, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    ObjectSymbolTable, RelocationKind, RelocationTarget, SectionKind, SymbolKind, elf,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    error::Error,
    fmt,
};

pub const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SPEC_SECTIONS: usize = 4096;
const MAX_SPEC_SEGMENTS: usize = 128;
const MAX_SPEC_FUNCTIONS: usize = 8192;
const MAX_SPEC_IMPORTS: usize = 8192;
const MAX_SPEC_RELOCATIONS: usize = 32768;
const MAX_PROGRAM_HEADERS: usize = 1024;
const MAX_DYNAMIC_SYMBOLS: usize = 65_536;
const MAX_RUNTIME_RANGES: usize = 4096;
const MAX_POINTER_ARRAYS: usize = 128;
const MAX_POINTER_ENTRIES: usize = 65_536;
const MAX_UNWIND_RANGES: usize = 65_536;
const MAX_METADATA_NAME_BYTES: usize = 4096;

#[derive(Debug)]
pub struct LoaderError(pub String);

impl fmt::Display for LoaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for LoaderError {}

pub type Result<T> = std::result::Result<T, LoaderError>;

fn error(message: impl Into<String>) -> LoaderError {
    LoaderError(message.into())
}

pub fn parse_elf(bytes: &[u8]) -> Result<object::File<'_>> {
    if bytes.len() > MAX_BINARY_BYTES {
        return Err(error("binary exceeds 64 MiB import limit"));
    }
    let file = object::File::parse(bytes)
        .map_err(|source| error(format!("binary parse failed: {source}")))?;
    if file.format() != BinaryFormat::Elf
        || file.architecture() != Architecture::X86_64
        || !file.is_little_endian()
    {
        return Err(error("only little-endian x86-64 ELF is supported"));
    }
    Ok(file)
}

pub fn target_triple(flags: object::FileFlags) -> &'static str {
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

pub fn import_elf(bytes: &[u8]) -> Result<ProgramSpec> {
    let file = parse_elf(bytes)?;
    let digest = format!("{:x}", Sha256::digest(bytes));
    let address_kind = if file.kind() == object::ObjectKind::Relocatable {
        AddressKind::SectionRelative
    } else {
        AddressKind::Virtual
    };
    let section_count = file.sections().take(MAX_SPEC_SECTIONS + 1).count();
    ensure_inventory_limit("sections", section_count, MAX_SPEC_SECTIONS)?;
    let section_spaces = file
        .sections()
        .take(MAX_SPEC_SECTIONS)
        .enumerate()
        .map(|(index, section)| {
            (
                section.index(),
                u32::try_from(index + 1).unwrap_or(u32::MAX),
            )
        })
        .collect::<HashMap<_, _>>();
    let sections = file
        .sections()
        .take(MAX_SPEC_SECTIONS + 1)
        .map(|section| {
            let address_space = if address_kind == AddressKind::Virtual {
                0
            } else {
                *section_spaces
                    .get(&section.index())
                    .ok_or_else(|| error("ELF section address space is missing"))?
            };
            Ok(SectionSpec {
                name: bounded_name(section.name().unwrap_or("<invalid-name>"))?,
                address: Address(section.address()),
                location: Some(Location {
                    address_space,
                    value: Address(section.address()),
                }),
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
    let raw_elf = ElfFile64::<LittleEndian>::parse(bytes)
        .map_err(|source| error(format!("ELF64 metadata parse failed: {source}")))?;
    let endian = raw_elf.endian();
    let program_headers = raw_elf
        .elf_program_headers()
        .iter()
        .enumerate()
        .take(MAX_PROGRAM_HEADERS + 1)
        .map(|(index, header)| ProgramHeaderSpec {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            type_value: header.p_type(endian),
            type_name: program_header_name(header.p_type(endian)),
            flags: header.p_flags(endian),
            file_offset: Address(header.p_offset(endian)),
            location: Location {
                address_space: 0,
                value: Address(header.p_vaddr(endian)),
            },
            physical_address: Address(header.p_paddr(endian)),
            file_size: header.p_filesz(endian),
            memory_size: header.p_memsz(endian),
            alignment: header.p_align(endian),
            provenance: elf_metadata("ELF64 program header"),
        })
        .collect::<Vec<_>>();
    ensure_inventory_limit(
        "program headers",
        program_headers.len(),
        MAX_PROGRAM_HEADERS,
    )?;
    let versions = raw_elf
        .elf_section_table()
        .versions(endian, bytes)
        .map_err(|source| error(format!("ELF symbol-version inventory failed: {source}")))?;
    let mut dynamic_symbols = Vec::new();
    for symbol in file.dynamic_symbols() {
        ensure_inventory_slot(
            "dynamic symbols",
            dynamic_symbols.len(),
            MAX_DYNAMIC_SYMBOLS,
        )?;
        let version_index = versions
            .as_ref()
            .map(|table| table.version_index(endian, symbol.index()));
        let version = match (versions.as_ref(), version_index) {
            (Some(table), Some(index)) => table
                .version(index)
                .map_err(|source| error(format!("ELF symbol version is invalid: {source}")))?,
            _ => None,
        };
        let raw_symbol = raw_elf
            .elf_dynamic_symbol_table()
            .symbol(symbol.index())
            .ok();
        let defined =
            raw_symbol.is_some_and(|value| !value.is_undefined(endian)) || symbol.is_definition();
        let location = if !defined || symbol.kind() == SymbolKind::Tls {
            None
        } else if address_kind == AddressKind::Virtual {
            Some(Location {
                address_space: 0,
                value: Address(symbol.address()),
            })
        } else {
            symbol
                .section_index()
                .and_then(|index| section_spaces.get(&index).copied())
                .map(|address_space| Location {
                    address_space,
                    value: Address(symbol.address()),
                })
        };
        dynamic_symbols.push(DynamicSymbolSpec {
            id: format!("sha256:{digest}:dynamic-symbol:{:?}", symbol.index()),
            name: bounded_name(symbol.name().unwrap_or("<invalid-name>"))?,
            version: version.map(|value| byte_label(value.name())).transpose()?,
            version_file: version
                .and_then(|value| value.file())
                .map(byte_label)
                .transpose()?,
            version_hidden: version_index.is_some_and(|index| index.is_hidden()),
            location,
            size: symbol.size(),
            kind: format!("{:?}", symbol.kind()),
            binding: raw_symbol
                .map(|value| symbol_binding_name(value.st_bind()))
                .unwrap_or_else(|| "unknown".to_owned()),
            visibility: raw_symbol
                .map(|value| symbol_visibility_name(value.st_visibility()))
                .unwrap_or_else(|| "unknown".to_owned()),
            defined,
            provenance: elf_metadata("ELF dynamic symbol table and GNU symbol versions"),
        });
    }
    let (runtime_ranges, pointer_arrays) = runtime_metadata(
        &file,
        address_kind,
        &section_spaces,
        &mapped_segments,
        &digest,
    )?;
    let (unwind_ranges, unwind_issues) = unwind_metadata(
        &file,
        address_kind,
        &section_spaces,
        &mapped_segments,
        &digest,
    )?;
    let raw_imports = file
        .imports()
        .map_err(|source| error(format!("ELF import inventory failed: {source}")))?;
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
                location_ref: Some(Location {
                    address_space: if address_kind == AddressKind::Virtual {
                        0
                    } else {
                        *section_spaces
                            .get(&section.index())
                            .ok_or_else(|| error("ELF relocation address space is missing"))?
                    },
                    value: Address(location),
                }),
                address_kind,
                source_section: Some(section_name.clone()),
                kind: format!("{:?}", relocation.kind()),
                encoding: format!("{:?}", relocation.encoding()),
                format_flags: format!("{:?}", relocation.flags()),
                size_bits: relocation.size(),
                addend: relocation.addend(),
                implicit_addend: relocation.has_implicit_addend(),
                target: relocation_target(
                    &file,
                    relocation.target(),
                    &digest,
                    false,
                    address_kind,
                    &section_spaces,
                )?,
                provenance: elf_metadata("ELF section relocation"),
            });
        }
    }
    if let Some(dynamic_relocations) = file.dynamic_relocations() {
        for (location, relocation) in dynamic_relocations {
            ensure_inventory_slot("relocations", relocations.len(), MAX_SPEC_RELOCATIONS)?;
            relocations.push(RelocationSpec {
                location: Address(location),
                location_ref: Some(Location {
                    address_space: 0,
                    value: Address(location),
                }),
                address_kind: AddressKind::Virtual,
                source_section: None,
                kind: format!("{:?}", relocation.kind()),
                encoding: format!("{:?}", relocation.encoding()),
                format_flags: format!("{:?}", relocation.flags()),
                size_bits: relocation.size(),
                addend: relocation.addend(),
                implicit_addend: relocation.has_implicit_addend(),
                target: relocation_target(
                    &file,
                    relocation.target(),
                    &digest,
                    true,
                    address_kind,
                    &section_spaces,
                )?,
                provenance: elf_metadata("ELF dynamic relocation"),
            });
        }
    }
    let mut functions = file
        .symbols()
        .filter(|symbol| {
            symbol.kind() == SymbolKind::Text
                && symbol.is_definition()
                && symbol.size() > 0
                && symbol.section_index().is_some()
        })
        .take(MAX_SPEC_FUNCTIONS + 1)
        .map(|symbol| {
            let section_index = symbol
                .section_index()
                .ok_or_else(|| error("ELF text symbol has no section"))?;
            Ok(FunctionSpec {
                id: format!("sha256:{digest}:symbol:{:?}", symbol.index()),
                name: bounded_name(symbol.name().unwrap_or("<invalid-name>"))?,
                address: Address(symbol.address()),
                location: Some(Location {
                    address_space: if address_kind == AddressKind::Virtual {
                        0
                    } else {
                        *section_spaces
                            .get(&section_index)
                            .ok_or_else(|| error("ELF symbol address space is missing"))?
                    },
                    value: Address(symbol.address()),
                }),
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
    for symbol in file.dynamic_symbols().filter(|symbol| {
        symbol.kind() == SymbolKind::Text
            && symbol.is_definition()
            && symbol.size() > 0
            && symbol.section_index().is_some()
    }) {
        let section_index = symbol
            .section_index()
            .ok_or_else(|| error("ELF dynamic text symbol has no section"))?;
        let name = bounded_name(symbol.name().unwrap_or("<invalid-name>"))?;
        if functions.iter().any(|function| {
            function.address.0 == symbol.address()
                && function.size == symbol.size()
                && function.name == name
        }) {
            continue;
        }
        ensure_inventory_slot("functions", functions.len(), MAX_SPEC_FUNCTIONS)?;
        functions.push(FunctionSpec {
            id: format!("sha256:{digest}:dynamic-symbol:{:?}", symbol.index()),
            name,
            address: Address(symbol.address()),
            location: Some(Location {
                address_space: if address_kind == AddressKind::Virtual {
                    0
                } else {
                    *section_spaces
                        .get(&section_index)
                        .ok_or_else(|| error("ELF dynamic symbol address space is missing"))?
                },
                value: Address(symbol.address()),
            }),
            address_kind,
            section_name: file
                .section_by_index(section_index)
                .ok()
                .and_then(|section| section.name().ok().map(str::to_owned))
                .map(|name| bounded_name(&name))
                .transpose()?
                .unwrap_or_else(|| "<invalid-name>".to_owned()),
            size: symbol.size(),
            provenance: "ELF dynamic symbol table".to_owned(),
            control_flow_status: "not recovered".to_owned(),
        });
    }
    ensure_inventory_limit("functions", functions.len(), MAX_SPEC_FUNCTIONS)?;
    let mut uncertainties = vec![UncertaintySpec {
        id: "elf-import-control-flow".to_owned(),
        category: "control_flow".to_owned(),
        description: "ELF import inventories metadata but does not recover complete control flow"
            .to_owned(),
        affected_addresses: Vec::new(),
        blocks_stable_operation: true,
        provenance: elf_metadata("ELF import recovery boundary"),
    }];
    if !unwind_issues.is_empty() {
        uncertainties.push(UncertaintySpec {
            id: "elf-unwind-fdes-partial".to_owned(),
            category: "function_discovery".to_owned(),
            description: unwind_issues.join("; "),
            affected_addresses: runtime_ranges
                .iter()
                .filter(|range| range.kind == RuntimeRangeKind::Unwind)
                .map(|range| range.location.value)
                .collect(),
            blocks_stable_operation: true,
            provenance: elf_metadata("bounded ELF unwind-section inventory"),
        });
    }
    let unresolved_pointer_slots = pointer_arrays
        .iter()
        .flat_map(|array| array.entries.iter())
        .filter(|entry| entry.target.is_none())
        .count();
    if unresolved_pointer_slots != 0 {
        uncertainties.push(UncertaintySpec {
            id: "elf-runtime-pointer-slots-unresolved".to_owned(),
            category: "function_discovery".to_owned(),
            description: format!(
                "{unresolved_pointer_slots} init/fini pointer slots remain unresolved after static relocation processing"
            ),
            affected_addresses: pointer_arrays
                .iter()
                .flat_map(|array| array.entries.iter())
                .filter(|entry| entry.target.is_none())
                .map(|entry| entry.slot.value)
                .collect(),
            blocks_stable_operation: true,
            provenance: elf_metadata("ELF runtime pointer-array recovery boundary"),
        });
    }
    let spec = ProgramSpec {
        schema_version: PROGRAM_SPEC_VERSION,
        binary_sha256: digest,
        target_triple: target_triple(file.flags()).to_owned(),
        abi: "System V AMD64 (target convention; individual prototypes unknown)".to_owned(),
        file_kind: format!("{:?}", file.kind()),
        image_base: None,
        entry_point: (file.kind() != object::ObjectKind::Relocatable && file.entry() != 0)
            .then(|| Address(file.entry())),
        entry_location: (file.kind() != object::ObjectKind::Relocatable && file.entry() != 0)
            .then(|| Location {
                address_space: 0,
                value: Address(file.entry()),
            }),
        data_layout: None,
        program_headers,
        dynamic_symbols,
        runtime_ranges,
        unwind_ranges,
        pointer_arrays,
        address_spaces: if address_kind == AddressKind::Virtual {
            vec![AddressSpaceSpec {
                id: 0,
                name: "ELF process virtual memory".to_owned(),
                address_kind: AddressKind::Virtual,
                provenance: elf_metadata("linked ELF virtual address space"),
            }]
        } else {
            file.sections()
                .take(MAX_SPEC_SECTIONS)
                .map(|section| AddressSpaceSpec {
                    id: *section_spaces
                        .get(&section.index())
                        .unwrap_or(&u32::MAX),
                    name: format!(
                        "ELF section {}",
                        section.name().unwrap_or("<invalid-name>")
                    ),
                    address_kind: AddressKind::SectionRelative,
                    provenance: elf_metadata("relocatable ELF section address space"),
                })
                .collect()
        },
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
        typed_model: Default::default(),
        memory_facts: Vec::new(),
        uncertainties,
        provenance: vec![elf_metadata(
            "native object parser over immutable input bytes",
        )],
        recovery_scope: "ELF metadata inventory including program headers, versioned dynamic symbols, runtime section ranges, linked-image unwind FDE ranges, relocations, and init/fini pointers; calls, references, and complete stripped-code discovery not attempted".to_owned(),
        unresolved_control_flow: true,
    };
    validate_program_spec(&spec)
        .map_err(|message| error(format!("imported ProgramSpec is invalid: {message}")))?;
    Ok(spec)
}

fn program_header_name(value: u32) -> String {
    let name = match value {
        elf::PT_NULL => "PT_NULL",
        elf::PT_LOAD => "PT_LOAD",
        elf::PT_DYNAMIC => "PT_DYNAMIC",
        elf::PT_INTERP => "PT_INTERP",
        elf::PT_NOTE => "PT_NOTE",
        elf::PT_SHLIB => "PT_SHLIB",
        elf::PT_PHDR => "PT_PHDR",
        elf::PT_TLS => "PT_TLS",
        elf::PT_GNU_EH_FRAME => "PT_GNU_EH_FRAME",
        elf::PT_GNU_STACK => "PT_GNU_STACK",
        elf::PT_GNU_RELRO => "PT_GNU_RELRO",
        elf::PT_GNU_PROPERTY => "PT_GNU_PROPERTY",
        _ => return format!("PT_0x{value:08x}"),
    };
    name.to_owned()
}

fn symbol_binding_name(value: u8) -> String {
    match value {
        elf::STB_LOCAL => "local".to_owned(),
        elf::STB_GLOBAL => "global".to_owned(),
        elf::STB_WEAK => "weak".to_owned(),
        elf::STB_GNU_UNIQUE => "gnu_unique".to_owned(),
        _ => format!("0x{value:02x}"),
    }
}

fn symbol_visibility_name(value: u8) -> String {
    match value {
        elf::STV_DEFAULT => "default".to_owned(),
        elf::STV_INTERNAL => "internal".to_owned(),
        elf::STV_HIDDEN => "hidden".to_owned(),
        elf::STV_PROTECTED => "protected".to_owned(),
        _ => format!("0x{value:02x}"),
    }
}

fn unwind_metadata(
    file: &object::File<'_>,
    address_kind: AddressKind,
    section_spaces: &HashMap<object::SectionIndex, u32>,
    mapped_segments: &[MappedSegmentSpec],
    digest: &str,
) -> Result<(Vec<UnwindRangeSpec>, Vec<String>)> {
    let Some(section) = file.section_by_name(".eh_frame") else {
        return Ok((Vec::new(), Vec::new()));
    };
    if section.size() == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let data = match section.uncompressed_data() {
        Ok(data) => data,
        Err(source) => {
            return Ok((
                Vec::new(),
                vec![format!(".eh_frame data is unavailable: {source}")],
            ));
        }
    };
    let (relocated_data, relocation_targets, mut issues) =
        if address_kind == AddressKind::SectionRelative {
            relocate_eh_frame(file, &section, data.as_ref(), section_spaces)
        } else {
            (data.as_ref().to_vec(), BTreeMap::new(), Vec::new())
        };
    let mut bases = BaseAddresses::default().set_eh_frame(section.address());
    if let Some(address) = file
        .section_by_name(".eh_frame_hdr")
        .map(|section| section.address())
    {
        bases = bases.set_eh_frame_hdr(address);
    }
    if let Some(address) = file
        .section_by_name(".text")
        .map(|section| section.address())
    {
        bases = bases.set_text(address);
    }
    if let Some(address) = file
        .section_by_name(".got")
        .or_else(|| file.section_by_name(".got.plt"))
        .map(|section| section.address())
    {
        bases = bases.set_got(address);
    }
    let mut frame = EhFrame::new(&relocated_data, GimliLittleEndian);
    frame.set_address_size(8);
    let mut entries = frame.entries(&bases);
    let mut ranges = Vec::new();
    loop {
        let entry = match entries.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(source) => {
                issues.push(format!(".eh_frame entry parsing stopped: {source}"));
                break;
            }
        };
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        ensure_inventory_slot("unwind FDE ranges", ranges.len(), MAX_UNWIND_RANGES)?;
        let record_offset = u64::try_from(partial.offset())
            .map_err(|_| error(".eh_frame record offset exceeds u64"))?;
        let record_end = record_offset
            .checked_add(u64::try_from(partial.entry_len()).unwrap_or(u64::MAX))
            .and_then(|end| end.checked_add(12));
        let relocation_target = record_end.and_then(|record_end| {
            relocation_targets
                .range(record_offset..record_end)
                .next()
                .map(|(_, target)| *target)
        });
        let fde =
            match partial.parse(|section, bases, offset| section.cie_from_offset(bases, offset)) {
                Ok(fde) => fde,
                Err(source) => {
                    issues.push(format!(
                        ".eh_frame FDE at offset 0x{record_offset:x} is invalid: {source}"
                    ));
                    continue;
                }
            };
        let initial_address = fde.initial_address();
        let address_range = fde.len();
        if address_range == 0 {
            issues.push(format!(
                ".eh_frame FDE at offset 0x{record_offset:x} has an empty range"
            ));
            continue;
        }
        let Some(end) = initial_address.checked_add(address_range) else {
            issues.push(format!(
                ".eh_frame FDE at offset 0x{record_offset:x} overflows its address range"
            ));
            continue;
        };
        let initial_location = if address_kind == AddressKind::Virtual {
            Location {
                address_space: 0,
                value: Address(initial_address),
            }
        } else if let Some(target) = relocation_target {
            if target.value.0 != initial_address {
                issues.push(format!(
                    ".eh_frame FDE at offset 0x{record_offset:x} decoded 0x{initial_address:x} but its relocation resolves to {}:0x{:x}",
                    target.address_space, target.value.0
                ));
                continue;
            }
            target
        } else {
            issues.push(format!(
                ".eh_frame FDE at offset 0x{record_offset:x} has no relocation-backed section identity"
            ));
            continue;
        };
        let executable = if address_kind == AddressKind::Virtual {
            mapped_segments.iter().any(|segment| {
                segment.address_space == initial_location.address_space
                    && segment.executable
                    && segment.virtual_address.0 <= initial_address
                    && segment
                        .virtual_address
                        .0
                        .checked_add(segment.memory_size)
                        .is_some_and(|segment_end| end <= segment_end)
            })
        } else {
            file.sections().any(|candidate| {
                candidate.kind() == SectionKind::Text
                    && section_spaces.get(&candidate.index()).copied()
                        == Some(initial_location.address_space)
                    && candidate.address() <= initial_address
                    && candidate
                        .address()
                        .checked_add(candidate.size())
                        .is_some_and(|section_end| end <= section_end)
            })
        };
        ranges.push(UnwindRangeSpec {
            id: format!("sha256:{digest}:eh-frame-fde:0x{record_offset:x}"),
            section_name: ".eh_frame".to_owned(),
            record_offset,
            initial_location,
            address_range,
            executable,
            provenance: elf_metadata("decoded ELF .eh_frame frame-description entry"),
        });
    }
    Ok((ranges, issues))
}

fn relocate_eh_frame(
    file: &object::File<'_>,
    section: &object::Section<'_, '_>,
    data: &[u8],
    section_spaces: &HashMap<object::SectionIndex, u32>,
) -> (Vec<u8>, BTreeMap<u64, Location>, Vec<String>) {
    let mut relocated = data.to_vec();
    let mut targets = BTreeMap::new();
    let mut issues = Vec::new();
    for (offset, relocation) in section.relocations() {
        if targets.len() >= MAX_SPEC_RELOCATIONS {
            issues.push(format!(
                ".eh_frame relocation count exceeds {MAX_SPEC_RELOCATIONS}"
            ));
            break;
        }
        if relocation.has_implicit_addend() {
            issues.push(format!(
                ".eh_frame relocation at 0x{offset:x} uses an unsupported implicit addend"
            ));
            continue;
        }
        let target = match relocation.target() {
            RelocationTarget::Symbol(index) => file
                .symbol_by_index(index)
                .ok()
                .filter(|symbol| symbol.section_index().is_some())
                .and_then(|symbol| {
                    let address_space = symbol
                        .section_index()
                        .and_then(|index| section_spaces.get(&index).copied())?;
                    let value = symbol.address().checked_add_signed(relocation.addend())?;
                    Some(Location {
                        address_space,
                        value: Address(value),
                    })
                }),
            RelocationTarget::Section(index) => {
                file.section_by_index(index)
                    .ok()
                    .and_then(|target_section| {
                        let address_space = section_spaces.get(&index).copied()?;
                        let value = target_section
                            .address()
                            .checked_add_signed(relocation.addend())?;
                        Some(Location {
                            address_space,
                            value: Address(value),
                        })
                    })
            }
            _ => None,
        };
        let Some(target) = target else {
            issues.push(format!(
                ".eh_frame relocation at 0x{offset:x} has no defined section target"
            ));
            continue;
        };
        let start = match usize::try_from(offset) {
            Ok(start) => start,
            Err(_) => {
                issues.push(format!(
                    ".eh_frame relocation offset 0x{offset:x} exceeds host size"
                ));
                continue;
            }
        };
        let applied = match (relocation.kind(), relocation.size()) {
            (RelocationKind::Relative, 32) => {
                let place = section.address().checked_add(offset);
                place
                    .and_then(|place| {
                        let value = i128::from(target.value.0) - i128::from(place);
                        i32::try_from(value).ok()
                    })
                    .and_then(|value| {
                        relocated
                            .get_mut(start..start.checked_add(4)?)?
                            .copy_from_slice(&value.to_le_bytes());
                        Some(())
                    })
            }
            (RelocationKind::Absolute, 64) => relocated
                .get_mut(start..start.saturating_add(8))
                .map(|bytes| bytes.copy_from_slice(&target.value.0.to_le_bytes())),
            (RelocationKind::Absolute, 32) => {
                u32::try_from(target.value.0).ok().and_then(|value| {
                    relocated
                        .get_mut(start..start.checked_add(4)?)?
                        .copy_from_slice(&value.to_le_bytes());
                    Some(())
                })
            }
            _ => None,
        };
        if applied.is_some() {
            targets.insert(offset, target);
        } else {
            issues.push(format!(
                ".eh_frame relocation at 0x{offset:x} has unsupported {:?}/{:?}/{} semantics",
                relocation.kind(),
                relocation.encoding(),
                relocation.size()
            ));
        }
    }
    (relocated, targets, issues)
}

fn runtime_metadata(
    file: &object::File<'_>,
    address_kind: AddressKind,
    section_spaces: &HashMap<object::SectionIndex, u32>,
    mapped_segments: &[MappedSegmentSpec],
    digest: &str,
) -> Result<(Vec<RuntimeRangeSpec>, Vec<RuntimePointerArraySpec>)> {
    let mut ranges = Vec::new();
    let mut arrays = Vec::new();
    let relocated_targets = runtime_pointer_targets(file, address_kind, section_spaces)?;
    for section in file.sections() {
        if section.size() == 0 {
            continue;
        }
        let section_name = bounded_name(section.name().unwrap_or("<invalid-name>"))?;
        let Some(kind) = runtime_range_kind(&section_name, section.kind()) else {
            continue;
        };
        ensure_inventory_slot("runtime metadata ranges", ranges.len(), MAX_RUNTIME_RANGES)?;
        let address_space = if address_kind == AddressKind::Virtual {
            0
        } else {
            *section_spaces
                .get(&section.index())
                .ok_or_else(|| error("runtime metadata section address space is missing"))?
        };
        let location = Location {
            address_space,
            value: Address(section.address()),
        };
        ranges.push(RuntimeRangeSpec {
            id: format!("sha256:{digest}:runtime-range:{:?}", section.index()),
            kind,
            section_name: section_name.clone(),
            location,
            file_offset: section.file_range().map(|(offset, _)| Address(offset)),
            size: section.size(),
            provenance: elf_metadata(runtime_range_scope(kind)),
        });
        let pointer_kind = match kind {
            RuntimeRangeKind::InitArray => Some(RuntimePointerArrayKind::Init),
            RuntimeRangeKind::FiniArray => Some(RuntimePointerArrayKind::Fini),
            RuntimeRangeKind::PreinitArray => Some(RuntimePointerArrayKind::Preinit),
            _ => None,
        };
        let Some(pointer_kind) = pointer_kind else {
            continue;
        };
        ensure_inventory_slot("runtime pointer arrays", arrays.len(), MAX_POINTER_ARRAYS)?;
        let data = section
            .data()
            .map_err(|source| error(format!("ELF {section_name} data is invalid: {source}")))?;
        let entry_count = data.len() / 8;
        ensure_inventory_limit("runtime pointer entries", entry_count, MAX_POINTER_ENTRIES)?;
        let mut entries = Vec::with_capacity(entry_count);
        for (index, chunk) in data.chunks_exact(8).enumerate() {
            let byte_offset = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_mul(8))
                .ok_or_else(|| error("runtime pointer slot offset overflows"))?;
            let slot_value = section
                .address()
                .checked_add(byte_offset)
                .ok_or_else(|| error("runtime pointer slot address overflows"))?;
            let raw_value = u64::from_le_bytes(
                chunk
                    .try_into()
                    .map_err(|_| error("runtime pointer entry width is invalid"))?,
            );
            let slot = Location {
                address_space,
                value: Address(slot_value),
            };
            let relocated_target = relocated_targets.get(&slot);
            let raw_target =
                (address_kind == AddressKind::Virtual && raw_value != 0).then_some(Location {
                    address_space: 0,
                    value: Address(raw_value),
                });
            let target = relocated_target
                .map(|(target, _)| *target)
                .or(raw_target)
                .filter(|target| {
                    is_executable_location(
                        file,
                        *target,
                        address_kind,
                        section_spaces,
                        mapped_segments,
                    )
                });
            entries.push(RuntimePointerEntrySpec {
                slot,
                raw_value: Address(raw_value),
                target,
                target_provenance: target.map(|_| {
                    elf_metadata(relocated_target.map_or(
                        "linked ELF pointer value targets an executable mapping",
                        |(_, scope)| *scope,
                    ))
                }),
            });
        }
        arrays.push(RuntimePointerArraySpec {
            id: format!("sha256:{digest}:pointer-array:{:?}", section.index()),
            kind: pointer_kind,
            section_name,
            location,
            entry_width_bits: 64,
            entries,
            trailing_bytes: u8::try_from(data.len() % 8).unwrap_or(7),
            provenance: elf_metadata("ELF runtime constructor/destructor pointer array"),
        });
    }
    let mut itanium_ranges = BTreeSet::new();
    for (table, symbol) in file.symbols().map(|symbol| ("symbol", symbol)).chain(
        file.dynamic_symbols()
            .map(|symbol| ("dynamic-symbol", symbol)),
    ) {
        let name = symbol.name().unwrap_or("<invalid-name>");
        if symbol.size() == 0 || !is_itanium_runtime_metadata_symbol(name) {
            continue;
        }
        let Some(section_index) = symbol.section_index() else {
            continue;
        };
        let Ok(section) = file.section_by_index(section_index) else {
            continue;
        };
        let Some(section_offset) = symbol.address().checked_sub(section.address()) else {
            continue;
        };
        if section_offset
            .checked_add(symbol.size())
            .is_none_or(|end| end > section.size())
        {
            continue;
        }
        let address_space = if address_kind == AddressKind::Virtual {
            0
        } else {
            *section_spaces
                .get(&section_index)
                .ok_or_else(|| error("Itanium metadata symbol address space is missing"))?
        };
        let location = Location {
            address_space,
            value: Address(symbol.address()),
        };
        let name = bounded_name(name)?;
        if !itanium_ranges.insert((name.clone(), location, symbol.size())) {
            continue;
        }
        ensure_inventory_slot("runtime metadata ranges", ranges.len(), MAX_RUNTIME_RANGES)?;
        let section_name = bounded_name(section.name().unwrap_or("<invalid-name>"))?;
        ranges.push(RuntimeRangeSpec {
            id: format!("sha256:{digest}:itanium-{table}-range:{:?}", symbol.index()),
            kind: RuntimeRangeKind::LanguageMetadata,
            section_name,
            location,
            file_offset: section
                .file_range()
                .and_then(|(offset, _)| offset.checked_add(section_offset))
                .map(Address),
            size: symbol.size(),
            provenance: elf_metadata(&format!("Itanium C++ ABI runtime metadata symbol {name}")),
        });
    }
    Ok((ranges, arrays))
}

fn is_itanium_runtime_metadata_symbol(name: &str) -> bool {
    ["_ZTI", "_ZTS", "_ZTV", "_ZTT", "_ZTC"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

fn runtime_pointer_targets(
    file: &object::File<'_>,
    address_kind: AddressKind,
    section_spaces: &HashMap<object::SectionIndex, u32>,
) -> Result<BTreeMap<Location, (Location, &'static str)>> {
    let mut targets = BTreeMap::new();
    let mut relocation_count = 0usize;
    if let Some(relocations) = file.dynamic_relocations() {
        for (location, relocation) in relocations {
            ensure_inventory_slot(
                "runtime pointer relocations",
                relocation_count,
                MAX_SPEC_RELOCATIONS,
            )?;
            relocation_count += 1;
            let target = match relocation.target() {
                RelocationTarget::Absolute => u64::try_from(relocation.addend()).ok(),
                RelocationTarget::Symbol(index) => file
                    .dynamic_symbol_table()
                    .and_then(|table| table.symbol_by_index(index).ok())
                    .filter(|symbol| {
                        symbol.section_index().is_some() && symbol.kind() != SymbolKind::Tls
                    })
                    .and_then(|symbol| symbol.address().checked_add_signed(relocation.addend())),
                _ => None,
            };
            if let Some(target) = target {
                targets.insert(
                    Location {
                        address_space: 0,
                        value: Address(location),
                    },
                    (
                        Location {
                            address_space: 0,
                            value: Address(target),
                        },
                        "ELF dynamic relocation resolves runtime pointer slot",
                    ),
                );
            }
        }
    }
    if address_kind != AddressKind::SectionRelative {
        return Ok(targets);
    }
    for source in file.sections() {
        let Some(source_space) = section_spaces.get(&source.index()).copied() else {
            continue;
        };
        for (offset, relocation) in source.relocations() {
            ensure_inventory_slot(
                "runtime pointer relocations",
                relocation_count,
                MAX_SPEC_RELOCATIONS,
            )?;
            relocation_count += 1;
            let target = match relocation.target() {
                RelocationTarget::Symbol(index) => file
                    .symbol_by_index(index)
                    .ok()
                    .filter(|symbol| {
                        symbol.section_index().is_some() && symbol.kind() != SymbolKind::Tls
                    })
                    .and_then(|symbol| {
                        let target_space = symbol
                            .section_index()
                            .and_then(|section| section_spaces.get(&section).copied())?;
                        let value = symbol.address().checked_add_signed(relocation.addend())?;
                        Some(Location {
                            address_space: target_space,
                            value: Address(value),
                        })
                    }),
                RelocationTarget::Section(index) => {
                    file.section_by_index(index).ok().and_then(|section| {
                        let target_space = section_spaces.get(&index).copied()?;
                        let value = section.address().checked_add_signed(relocation.addend())?;
                        Some(Location {
                            address_space: target_space,
                            value: Address(value),
                        })
                    })
                }
                _ => None,
            };
            if let Some(target) = target {
                let slot_value = source
                    .address()
                    .checked_add(offset)
                    .ok_or_else(|| error("ELF section relocation location overflows"))?;
                targets.insert(
                    Location {
                        address_space: source_space,
                        value: Address(slot_value),
                    },
                    (
                        target,
                        "ELF section relocation resolves runtime pointer slot",
                    ),
                );
            }
        }
    }
    Ok(targets)
}

fn is_executable_location(
    file: &object::File<'_>,
    target: Location,
    address_kind: AddressKind,
    section_spaces: &HashMap<object::SectionIndex, u32>,
    mapped_segments: &[MappedSegmentSpec],
) -> bool {
    if address_kind == AddressKind::Virtual {
        return target.address_space == 0
            && mapped_segments.iter().any(|segment| {
                segment.executable
                    && segment.virtual_address.0 <= target.value.0
                    && segment
                        .virtual_address
                        .0
                        .checked_add(segment.memory_size)
                        .is_some_and(|end| target.value.0 < end)
            });
    }
    file.sections().any(|section| {
        section.kind() == SectionKind::Text
            && section_spaces.get(&section.index()).copied() == Some(target.address_space)
            && section.address() <= target.value.0
            && section
                .address()
                .checked_add(section.size())
                .is_some_and(|end| target.value.0 < end)
    })
}

fn runtime_range_kind(name: &str, kind: SectionKind) -> Option<RuntimeRangeKind> {
    if name == ".init_array" {
        Some(RuntimeRangeKind::InitArray)
    } else if name == ".fini_array" {
        Some(RuntimeRangeKind::FiniArray)
    } else if name == ".preinit_array" {
        Some(RuntimeRangeKind::PreinitArray)
    } else if matches!(
        kind,
        SectionKind::Tls | SectionKind::UninitializedTls | SectionKind::TlsVariables
    ) {
        Some(RuntimeRangeKind::Tls)
    } else if name == ".eh_frame" || name == ".eh_frame_hdr" || name == ".gcc_except_table" {
        Some(RuntimeRangeKind::Unwind)
    } else if name == ".plt" || name.starts_with(".plt.") {
        Some(RuntimeRangeKind::Plt)
    } else if name == ".got" || name.starts_with(".got.") {
        Some(RuntimeRangeKind::Got)
    } else if matches!(
        name,
        ".gopclntab" | ".go.buildinfo" | ".rustc" | ".note.rustc"
    ) {
        Some(RuntimeRangeKind::LanguageMetadata)
    } else {
        None
    }
}

fn runtime_range_scope(kind: RuntimeRangeKind) -> &'static str {
    match kind {
        RuntimeRangeKind::Plt => "ELF PLT section range",
        RuntimeRangeKind::Got => "ELF GOT section range",
        RuntimeRangeKind::Tls => "ELF TLS section range",
        RuntimeRangeKind::Unwind => "ELF unwind-related section range; FDEs not parsed",
        RuntimeRangeKind::InitArray => "ELF init-array section range",
        RuntimeRangeKind::FiniArray => "ELF fini-array section range",
        RuntimeRangeKind::PreinitArray => "ELF preinit-array section range",
        RuntimeRangeKind::LanguageMetadata => "compiler language-runtime metadata section range",
    }
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
    address_kind: AddressKind,
    section_spaces: &HashMap<object::SectionIndex, u32>,
) -> Result<RelocationTargetSpec> {
    Ok(match target {
        RelocationTarget::Symbol(index) => {
            let symbol = if dynamic {
                file.dynamic_symbol_table()
                    .and_then(|table| table.symbol_by_index(index).ok())
            } else {
                file.symbol_by_index(index).ok()
            };
            let defined = symbol
                .as_ref()
                .is_some_and(|symbol| symbol.section_index().is_some());
            let location = symbol
                .as_ref()
                .filter(|symbol| {
                    symbol.section_index().is_some() && symbol.kind() != SymbolKind::Tls
                })
                .and_then(|symbol| {
                    let address_space = if address_kind == AddressKind::Virtual {
                        Some(0)
                    } else {
                        symbol
                            .section_index()
                            .and_then(|section| section_spaces.get(&section).copied())
                    }?;
                    Some(Location {
                        address_space,
                        value: Address(symbol.address()),
                    })
                });
            RelocationTargetSpec::Symbol {
                id: format!(
                    "sha256:{digest}:{}:{index:?}",
                    if dynamic { "dynamic-symbol" } else { "symbol" }
                ),
                name: symbol
                    .as_ref()
                    .and_then(|symbol| symbol.name().ok().map(str::to_owned))
                    .map(|name| bounded_name(&name))
                    .transpose()?,
                location,
                defined,
            }
        }
        RelocationTarget::Section(index) => RelocationTargetSpec::Section {
            name: bounded_name(
                &file
                    .section_by_index(index)
                    .ok()
                    .and_then(|section| section.name().ok().map(str::to_owned))
                    .unwrap_or_else(|| format!("<invalid-section:{index:?}>")),
            )?,
            location: file.section_by_index(index).ok().and_then(|section| {
                let address_space = if address_kind == AddressKind::Virtual {
                    Some(0)
                } else {
                    section_spaces.get(&index).copied()
                }?;
                Some(Location {
                    address_space,
                    value: Address(section.address()),
                })
            }),
        },
        RelocationTarget::Absolute => RelocationTargetSpec::Absolute,
        other => RelocationTargetSpec::Unresolved {
            description: format!("{other:?}"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_elf_imports_with_canonical_locations() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let spec = import_elf(bytes).unwrap();
        assert_eq!(spec.schema_version, PROGRAM_SPEC_VERSION);
        assert!(
            spec.functions
                .iter()
                .all(|function| function.location.is_some())
        );
        assert!(
            spec.sections
                .iter()
                .all(|section| section.location.is_some())
        );
    }

    #[test]
    fn inventory_and_name_limits_are_inclusive() {
        assert!(ensure_inventory_limit("sections", MAX_SPEC_SECTIONS, MAX_SPEC_SECTIONS).is_ok());
        assert!(
            ensure_inventory_limit("sections", MAX_SPEC_SECTIONS + 1, MAX_SPEC_SECTIONS).is_err()
        );
        assert!(bounded_name(&"x".repeat(MAX_METADATA_NAME_BYTES)).is_ok());
        assert!(bounded_name(&"x".repeat(MAX_METADATA_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn stripped_shared_elf_preserves_runtime_linker_metadata() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/dynamic_metadata_stripped.elf");
        let spec = import_elf(bytes).unwrap();
        assert_eq!(spec.program_headers.len(), 10);
        assert!(
            spec.program_headers
                .iter()
                .any(|header| header.type_name == "PT_TLS")
        );
        assert!(
            spec.program_headers
                .iter()
                .any(|header| header.type_name == "PT_GNU_EH_FRAME")
        );
        let exported = spec
            .dynamic_symbols
            .iter()
            .find(|symbol| symbol.name == "exported_fn")
            .unwrap();
        assert_eq!(exported.version.as_deref(), Some("HYDIR_1.0"));
        assert!(exported.defined);
        assert_eq!(exported.location.unwrap().value.0, 0x1434);
        let tls = spec
            .dynamic_symbols
            .iter()
            .find(|symbol| symbol.name == "hydir_tls_value")
            .unwrap();
        assert!(tls.defined);
        assert!(tls.location.is_none());
        let pointer_targets = spec
            .pointer_arrays
            .iter()
            .flat_map(|array| array.entries.iter())
            .filter_map(|entry| entry.target.map(|target| target.value.0))
            .collect::<Vec<_>>();
        assert_eq!(pointer_targets, vec![0x1443, 0x1444]);
        assert!(spec.runtime_ranges.iter().any(|range| {
            range.kind == RuntimeRangeKind::Unwind && range.section_name == ".eh_frame"
        }));
        assert!(
            spec.runtime_ranges.iter().any(|range| {
                range.kind == RuntimeRangeKind::Plt && range.section_name == ".plt"
            })
        );
        assert!(spec.runtime_ranges.iter().any(|range| {
            range.kind == RuntimeRangeKind::Got && range.section_name == ".got.plt"
        }));
        assert_eq!(spec.unwind_ranges.len(), 1);
        assert_eq!(spec.unwind_ranges[0].initial_location.value.0, 0x1434);
        assert_eq!(spec.unwind_ranges[0].address_range, 15);
        assert!(spec.unwind_ranges[0].executable);
    }

    #[test]
    fn relocatable_elf_preserves_section_identity_and_resolves_pointer_arrays() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/relocatable_metadata.o");
        let spec = import_elf(bytes).unwrap();
        assert_eq!(spec.file_kind, "Relocatable");
        assert!(spec.program_headers.is_empty());
        let text_space = spec
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .and_then(|section| section.location)
            .unwrap()
            .address_space;
        let external_call = spec
            .relocations
            .iter()
            .find(|relocation| relocation.source_section.as_deref() == Some(".text"))
            .unwrap();
        assert_eq!(
            external_call.location_ref.unwrap().address_space,
            text_space
        );
        assert!(matches!(
            &external_call.target,
            RelocationTargetSpec::Symbol {
                name: Some(name),
                location: None,
                defined: false,
                ..
            } if name == "external_hook"
        ));
        let pointer_targets = spec
            .pointer_arrays
            .iter()
            .flat_map(|array| array.entries.iter())
            .map(|entry| entry.target.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            pointer_targets,
            vec![
                Location {
                    address_space: text_space,
                    value: Address(0xf),
                },
                Location {
                    address_space: text_space,
                    value: Address(0x10),
                },
            ]
        );
        assert_eq!(spec.unwind_ranges.len(), 1);
        assert_eq!(
            spec.unwind_ranges[0].initial_location,
            Location {
                address_space: text_space,
                value: Address(0),
            }
        );
        assert_eq!(spec.unwind_ranges[0].address_range, 15);
        assert!(spec.unwind_ranges[0].executable);
        assert!(
            spec.uncertainties
                .iter()
                .all(|uncertainty| uncertainty.id != "elf-unwind-fdes-partial")
        );
    }

    #[test]
    fn relocatable_cpp_preserves_itanium_runtime_metadata_symbols() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/cpp_rtti.o");
        let spec = import_elf(bytes).unwrap();
        let metadata = spec
            .runtime_ranges
            .iter()
            .filter(|range| {
                range.kind == RuntimeRangeKind::LanguageMetadata
                    && range.provenance.scope.contains("Itanium C++ ABI")
            })
            .collect::<Vec<_>>();
        assert_eq!(metadata.len(), 3);
        for (symbol, section, size) in [
            ("_ZTV9HydirBase", ".data.rel.ro", 40),
            ("_ZTI9HydirBase", ".data.rel.ro", 16),
            ("_ZTS9HydirBase", ".rodata", 11),
        ] {
            let range = metadata
                .iter()
                .find(|range| range.provenance.scope.ends_with(symbol))
                .expect("Itanium metadata symbol should have its own bounded range");
            assert_eq!(range.section_name, section);
            assert_eq!(range.size, size);
            assert!(range.file_offset.is_some());
        }
    }

    #[test]
    fn stripped_unwind_only_elf_recovers_bounded_executable_fdes() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/unwind_discovery_stripped.elf");
        let spec = import_elf(bytes).unwrap();
        assert!(spec.functions.is_empty());
        assert_eq!(
            spec.unwind_ranges
                .iter()
                .map(|range| (range.initial_location.value.0, range.address_range))
                .collect::<Vec<_>>(),
            vec![(0x129c, 5), (0x12a1, 3)]
        );
        assert!(spec.unwind_ranges.iter().all(|range| range.executable));
        assert!(
            spec.uncertainties
                .iter()
                .all(|uncertainty| uncertainty.id != "elf-unwind-fdes-partial")
        );
    }
}
