//! Narrow, native ELF/x86-64 frontend and machine-code-to-LLVM lift.
//!
//! The supported slice accepts symbol-bounded, two-u64-argument SysV
//! functions. It rejects unresolved calls, unmodeled partial registers and
//! unknown instructions rather than guessing their behavior.

mod cfg;
mod disasm;
mod stack;

pub use cfg::lift_cfg;
pub use disasm::disassemble_elf;
pub use hydir_loader::MAX_BINARY_BYTES;

use hydir_core::{
    Address, AddressKind, DisassemblyFlow, ExitStackRelation, FactProvenance, FactSource,
    FunctionCfg, InteriorEntryEvidence, PhysicalRegionIr, ProgramSpec, REGION_SPEC_VERSION,
    RegionContract, RegionDecisionIr, region_bytes,
};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
};

#[derive(Debug)]
pub struct HydirError(pub String);

impl fmt::Display for HydirError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for HydirError {}

pub type Result<T> = std::result::Result<T, HydirError>;
fn error(message: impl Into<String>) -> HydirError {
    HydirError(message.into())
}

/// Recover exact direct control flow for a RegionSpec while preserving its
/// declared external exits. This is a structural artifact only: imported
/// live-state and stack facts are not promoted to native semantic proof.
pub fn recover_region_cfg(region: &RegionContract) -> Result<FunctionCfg> {
    let code = region_bytes(region).map_err(error)?;
    let terminal_call_sites = region
        .calls
        .iter()
        .filter(|call| call.noreturn || call.stops_flow)
        .map(|call| call.source.0)
        .collect::<std::collections::BTreeSet<_>>();
    cfg::recover_declared_region_cfg(
        &code,
        region.entry.0,
        &region.exits,
        &terminal_call_sites,
        cfg::RegionCfgMetadata {
            address_kind: region.address_kind,
            symbol_name: &region.symbol_name,
            binary_sha256: region.binary_sha256.clone(),
            provenance: &format!(
                "{}; HydIR declared-exit RegionSpec CFG recovery",
                region.provenance.scope
            ),
        },
    )
}

/// Lift the first conservative RegionIR form: a side-effect-free conditional
/// region with explicit physical inputs, pass-through outputs, and two exact
/// continuation addresses.
pub fn lift_region_decision(region: &RegionContract) -> Result<RegionDecisionIr> {
    cfg::lift_region_decision(region)
}

/// Decode a RegionSpec into typed physical-state RegionIR. This proves the
/// instruction semantics and declared control flow while retaining unresolved
/// boundary facts that still block SSA/C and patch lowering.
pub fn lift_physical_region(region: &RegionContract) -> Result<PhysicalRegionIr> {
    cfg::lift_physical_region(region)
}

fn parse_elf(bytes: &[u8]) -> Result<object::File<'_>> {
    hydir_loader::parse_elf(bytes).map_err(|source| error(source.to_string()))
}

/// Compatibility facade for callers that have not migrated to `hydir-loader`.
pub fn import_elf(bytes: &[u8]) -> Result<ProgramSpec> {
    hydir_loader::import_elf(bytes).map_err(|source| error(source.to_string()))
}

fn elf_target_triple(flags: object::FileFlags) -> &'static str {
    hydir_loader::target_triple(flags)
}

/// Lift a named ELF symbol. The symbol's bytes, not source or pseudocode, are
/// decoded. The caller asserts the function prototype `u64(u64, u64)`.
/// Direct calls are limited to unique bounded scalar leaf symbols in a linked
/// ELF; stack alignment and caller-saved state are checked before emission.
pub fn lift_symbol(bytes: &[u8], name: &str) -> Result<String> {
    let (code, address, _) = symbol_code(bytes, name)?;
    let plain = lift_cfg(&code, address);
    if plain.is_ok() {
        return plain;
    }
    let targets = cfg::discover_direct_calls(&code, address)?;
    if targets.is_empty() {
        return plain;
    }
    if targets.len() > 8 {
        return Err(error(
            "more than eight direct-call targets exceed the scalar C subset",
        ));
    }
    let file = parse_elf(bytes)?;
    if file.kind() == object::ObjectKind::Relocatable {
        return Err(error("direct-call lift requires a linked ELF"));
    }
    let spec = import_elf(bytes)?;
    let caller_end = address
        .checked_add(code.len() as u64)
        .ok_or_else(|| error("caller address range overflow"))?;
    if spec.relocations.iter().any(|relocation| {
        relocation.address_kind == AddressKind::Virtual
            && (address..caller_end).contains(&relocation.location.0)
    }) {
        return Err(error("direct-call caller contains a relocation"));
    }
    let mut helpers = String::new();
    for target in &targets {
        let mut symbols = file.symbols().filter(|symbol| {
            symbol.kind() == SymbolKind::Text
                && symbol.is_definition()
                && symbol.size() > 0
                && symbol.address() == *target
        });
        let symbol = symbols.next().ok_or_else(|| {
            error(format!(
                "direct-call target 0x{target:x} has no bounded symbol"
            ))
        })?;
        if symbols.next().is_some() {
            return Err(error(format!(
                "direct-call target 0x{target:x} is ambiguous"
            )));
        }
        let callee_name = symbol
            .name()
            .map_err(|_| error("direct-call callee symbol has no valid name"))?;
        let (callee_code, callee_address, _) = symbol_code(bytes, callee_name)?;
        let callee_end = callee_address
            .checked_add(callee_code.len() as u64)
            .ok_or_else(|| error("callee address range overflow"))?;
        if callee_address != *target || (address < callee_end && callee_address < caller_end) {
            return Err(error(
                "direct-call callee overlaps caller or has unstable address",
            ));
        }
        let callee_ir = lift_cfg(&callee_code, callee_address).map_err(|reason| {
            error(format!(
                "direct-call callee {callee_name:?} is not a scalar leaf: {reason}"
            ))
        })?;
        let definition = callee_ir
            .split_once("define i64 @hydir_lifted")
            .ok_or_else(|| error("internal callee LLVM definition missing"))?
            .1;
        helpers.push_str(&format!(
            "define i64 @hydir_callee_{target:x}{definition}\n"
        ));
    }
    let caller_ir = cfg::lift_cfg_with_calls(&code, address, &targets)?;
    let (header, main) = caller_ir
        .split_once("define i64 @hydir_lifted")
        .ok_or_else(|| error("internal caller LLVM definition missing"))?;
    Ok(format!("{header}{helpers}define i64 @hydir_lifted{main}"))
}

/// Proven eight-byte local offsets, relative to function-entry RSP. This is
/// only a stack-address analysis result; callers must also require a
/// successful scalar lift before treating a local value as defined.
pub fn proven_stack_local_offsets(bytes: &[u8], name: &str) -> Result<Vec<i64>> {
    let (code, address, _) = symbol_code(bytes, name)?;
    Ok(stack::analyze_stack(&code, address)?
        .slots
        .into_iter()
        .filter(|slot| slot.width_bytes == 8)
        .map(|slot| slot.offset)
        .collect())
}

/// Extract a validated, bounded named text symbol for an external semantics
/// backend. ELF parsing and symbol-boundary validation remain owned by HydIR.
pub fn extract_symbol_code(bytes: &[u8], name: &str) -> Result<(Vec<u8>, u64)> {
    let (code, address, _) = symbol_code(bytes, name)?;
    Ok((code, address))
}

/// Extract a bounded executable window beginning at a linked virtual address.
/// The window stops at the containing text section, the requested bound, or
/// the next known text symbol. It is evidence for recursive discovery, not a
/// claim that the whole window belongs to one function.
pub fn extract_executable_window(bytes: &[u8], address: u64, max_size: usize) -> Result<Vec<u8>> {
    if max_size == 0 || max_size > 64 * 1024 {
        return Err(error(
            "executable discovery window must contain 1..=65536 bytes",
        ));
    }
    let file = parse_elf(bytes)?;
    if file.kind() == object::ObjectKind::Relocatable {
        return Err(error(
            "virtual-address discovery requires a linked ELF; use a section location for ET_REL",
        ));
    }
    let section = file
        .sections()
        .find(|section| {
            section.kind() == SectionKind::Text
                && section.address() <= address
                && section
                    .address()
                    .checked_add(section.size())
                    .is_some_and(|end| address < end)
        })
        .ok_or_else(|| {
            error(format!(
                "0x{address:x} is not in an executable text section"
            ))
        })?;
    let data = section
        .data()
        .map_err(|read_error| error(format!("executable section read failed: {read_error}")))?;
    let start = usize::try_from(address - section.address())
        .map_err(|_| error("executable discovery offset exceeds host size"))?;
    let section_remaining = data.len().saturating_sub(start);
    let next_symbol_distance = file
        .symbols()
        .filter(|symbol| {
            symbol.kind() == SymbolKind::Text
                && symbol.is_definition()
                && symbol.section_index() == Some(section.index())
                && symbol.address() > address
        })
        .map(|symbol| symbol.address() - address)
        .min()
        .and_then(|distance| usize::try_from(distance).ok())
        .unwrap_or(section_remaining);
    let length = max_size.min(section_remaining).min(next_symbol_distance);
    if length == 0 {
        return Err(error("executable discovery window is empty"));
    }
    Ok(data[start..start + length].to_vec())
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

/// Export immutable bytes and currently established region facts. This is a
/// read-only evidence artifact; unknown live state and stack alignment keep it
/// ineligible for replacement even when direct CFG recovery succeeds.
pub fn region_contract(bytes: &[u8], name: &str) -> Result<RegionContract> {
    let (code, address, address_kind) = symbol_code(bytes, name)?;
    let end = address
        .checked_add(code.len() as u64)
        .ok_or_else(|| error("region address range overflow"))?;
    let spec = import_elf(bytes)?;
    let selected_location = spec
        .functions
        .iter()
        .find(|function| {
            function.name == name
                && function.address == Address(address)
                && function.size == code.len() as u64
        })
        .and_then(|function| function.location)
        .ok_or_else(|| error("selected symbol has no canonical ProgramSpec location"))?;
    let mut observed_entries = BTreeMap::<u64, InteriorEntryEvidence>::new();
    if let Some(entry) = spec.entry_point
        && (address + 1..end).contains(&entry.0)
    {
        observed_entries.insert(
            entry.0,
            InteriorEntryEvidence {
                entry,
                source: None,
                reason: "ELF entry point lies inside selected symbol".to_owned(),
                provenance: FactProvenance {
                    source: FactSource::ElfMetadata,
                    scope: "ELF entry address".to_owned(),
                },
            },
        );
    }
    for function in &spec.functions {
        if function.location.is_some_and(|location| {
            location.address_space == selected_location.address_space
                && (address + 1..end).contains(&location.value.0)
        }) {
            observed_entries
                .entry(function.address.0)
                .or_insert_with(|| InteriorEntryEvidence {
                    entry: function.address,
                    source: None,
                    reason: format!(
                        "ELF text symbol {} begins inside selected symbol",
                        function.name
                    ),
                    provenance: FactProvenance {
                        source: FactSource::ElfMetadata,
                        scope: "symbol entry only; executable reachability not proven".to_owned(),
                    },
                });
        }
    }
    let mut unresolved_facts = Vec::new();
    match disassemble_elf(bytes) {
        Ok(report) => {
            for instruction in report.instructions {
                if instruction.function.is_none()
                    || (address..end).contains(&instruction.address.0)
                    || !matches!(
                        instruction.flow,
                        DisassemblyFlow::Call
                            | DisassemblyFlow::ConditionalBranch
                            | DisassemblyFlow::UnconditionalBranch
                    )
                {
                    continue;
                }
                if let Some(target) = instruction.branch_target
                    && (address + 1..end).contains(&target.0)
                {
                    observed_entries.entry(target.0).or_insert_with(|| InteriorEntryEvidence {
                        entry: target,
                        source: Some(instruction.address),
                        reason: format!("recovered direct {:?} enters selected symbol interior", instruction.flow),
                        provenance: FactProvenance {
                            source: FactSource::NativeAnalysis,
                            scope: "direct edge from recursively decoded symbol code; other code remains uncertain".to_owned(),
                        },
                    });
                }
            }
        }
        Err(reason) => unresolved_facts.push(format!("outside_edge_scan: {reason}")),
    }
    let relocations = spec
        .relocations
        .into_iter()
        .filter(|relocation| {
            relocation.location_ref.is_some_and(|location| {
                location.address_space == selected_location.address_space
                    && (address..end).contains(&location.value.0)
            })
        })
        .collect();
    if !observed_entries.is_empty() {
        unresolved_facts
            .push("one or more observed entries reach the selected symbol interior".to_owned());
    }
    if let Err(reason) = cfg::recover_function_cfg(
        &code,
        address,
        address_kind,
        name,
        spec.binary_sha256.clone(),
        "ELF symbol extent and native iced-x86 decoding",
    ) {
        unresolved_facts.push(format!("scalar_cfg: {reason}"));
    }
    if let Err(reason) = cfg::lift_cfg(&code, address) {
        unresolved_facts.push(format!("scalar_lift: {reason}"));
    }
    let (exits, stack_delta) = match stack::analyze_stack(&code, address) {
        Ok(evidence) => (evidence.return_sites, Some(evidence.exit_rsp_delta)),
        Err(reason) => {
            unresolved_facts.push(format!("stack_and_exits: {reason}"));
            (Vec::new(), None)
        }
    };
    unresolved_facts.extend([
        "alternate entries and unreachable bytes: not analyzed".to_owned(),
        "live_in machine locations: not analyzed".to_owned(),
        "live_out machine locations: not analyzed".to_owned(),
        "stack alignment at entry and exits: not established".to_owned(),
        "relocation applicability after placement: not analyzed".to_owned(),
    ]);
    let exit_stack_relations = stack_delta.map_or_else(Vec::new, |rsp_delta| {
        exits
            .iter()
            .copied()
            .map(|exit| ExitStackRelation {
                exit,
                rsp_delta,
                alignment_mod_16: None,
                provenance: FactProvenance {
                    source: FactSource::NativeAnalysis,
                    scope: "bounded native stack analysis over reachable region instructions"
                        .to_owned(),
                },
            })
            .collect()
    });
    Ok(RegionContract {
        schema_version: REGION_SPEC_VERSION,
        binary_sha256: spec.binary_sha256,
        symbol_name: name.to_owned(),
        address_kind,
        entry: Address(address),
        byte_length: code.len() as u64,
        bytes_sha256: format!("{:x}", Sha256::digest(&code)),
        bytes_hex: code.iter().map(|byte| format!("{byte:02x}")).collect(),
        exits,
        calls: Vec::new(),
        relocations,
        observed_interior_entries: observed_entries.into_values().collect(),
        live_in: None,
        live_out: None,
        physical_live_in: Vec::new(),
        physical_live_out: Vec::new(),
        stack_delta,
        stack_entry_alignment: None,
        exit_stack_relations,
        global_references: Vec::new(),
        variable_locations: Vec::new(),
        assumptions: Vec::new(),
        unresolved_facts,
        replacement_ready: false,
        provenance: FactProvenance {
            source: FactSource::NativeAnalysis,
            scope: "Linked ELF symbol bytes, conservative CFG and stack-state recovery".to_owned(),
        },
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

    #[test]
    fn region_contract_never_promotes_unknown_machine_state() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let region = region_contract(binary, "hydir_max2").unwrap();
        assert_eq!(region.bytes_hex, "4889f84839f773034889f0c3");
        assert_eq!(region.exits.len(), 1);
        assert_eq!(region.live_in, None);
        assert_eq!(region.stack_delta, Some(8));
        assert!(!region.replacement_ready);
    }

    #[test]
    fn region_records_text_symbol_inside_selected_extent() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/interior_entry.elf");
        let region = region_contract(binary, "hydir_outer").unwrap();
        assert_eq!(region.observed_interior_entries.len(), 1);
        assert_eq!(
            region.observed_interior_entries[0].entry.0,
            region.entry.0 + 3
        );
        assert!(!region.replacement_ready);
    }

    #[test]
    fn region_records_external_direct_call_to_interior() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/interior_call.elf");
        let region = region_contract(binary, "hydir_outer").unwrap();
        assert_eq!(region.observed_interior_entries.len(), 1);
        let entry = &region.observed_interior_entries[0];
        assert_eq!(entry.entry.0, region.entry.0 + 3);
        assert!(entry.source.is_some());
        assert!(!region.replacement_ready);
    }

    #[test]
    fn region_reports_balanced_frame_without_claiming_replacement_safety() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/frame.elf");
        let region = region_contract(binary, "hydir_frame_balance").unwrap();
        assert_eq!(region.stack_delta, Some(8));
        assert_eq!(region.exits.len(), 1);
        assert!(
            !region
                .unresolved_facts
                .iter()
                .any(|fact| fact.starts_with("scalar_cfg:"))
        );
        assert!(!region.replacement_ready);
    }

    #[test]
    fn reports_proven_stack_local_offsets_for_typed_assertions() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/stack.elf");
        assert_eq!(
            proven_stack_local_offsets(binary, "hydir_stack_slot_add").unwrap(),
            vec![-16]
        );
        assert_eq!(
            proven_stack_local_offsets(binary, "hydir_stack_branch").unwrap(),
            vec![-16]
        );
    }

    #[test]
    fn checked_in_elf_fixtures_match_the_pinned_manifest() {
        for (name, bytes, length, digest) in [
            (
                "max2.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/max2.elf").as_slice(),
                1048,
                "48b09f9d8580403f4aa51435dfc5955f10715609c1487a123d07c9c6bff38d7d",
            ),
            (
                "frame.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/frame.elf").as_slice(),
                3312,
                "86e289c9ac20fd7031021877b617863b4c6087f05aa5f4a402f0b8c598ff0532",
            ),
            (
                "stack.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/stack.elf").as_slice(),
                3312,
                "5e2f4266a51b4c010f266d8e005e6c11783d6d58a82a09a2baa884a828dd12b9",
            ),
            (
                "interior_entry.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/interior_entry.elf").as_slice(),
                1128,
                "d808c757125322467338a877f8df32ad8415b8fdca74ad594fdde104c3c3455f",
            ),
            (
                "interior_call.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/interior_call.elf").as_slice(),
                1104,
                "321806c9a4e730b1c2f62c2883947c5abd5cc2f844c27db3f75e8457c50b0057",
            ),
            (
                "dynamic_metadata.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/dynamic_metadata.elf").as_slice(),
                3488,
                "8e32e846c8789463bcec4fff3161b8f244a04135260b78bb5288c3826b7cb8a8",
            ),
            (
                "dynamic_metadata_stripped.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/dynamic_metadata_stripped.elf")
                    .as_slice(),
                2928,
                "073e4180d15e09f84e4c0a974e034cfee3e0075723bd03e3e87a9e674add968e",
            ),
            (
                "relocatable_metadata.o",
                include_bytes!("../../../fuzz/corpus/elf_import/relocatable_metadata.o").as_slice(),
                1424,
                "6f915d491d0e49f0e072dd9ad86a3cc5b4bfd44cd8af12855015384ae4b34799",
            ),
            (
                "unwind_discovery.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/unwind_discovery.elf").as_slice(),
                1968,
                "ca29b9544d1d3065489a2981ffc7c0624aaeaccdb0ea415cb5d5d0e4db91f7c8",
            ),
            (
                "unwind_discovery_stripped.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/unwind_discovery_stripped.elf")
                    .as_slice(),
                1512,
                "288418fe9691928033f3f6fe52bb5227e288705f2c326f28a36b95c3cf70d720",
            ),
            (
                "jump_table.elf",
                include_bytes!("../../../fuzz/corpus/elf_import/jump_table.elf").as_slice(),
                1488,
                "e6cdb19e5cecba852b9d377c8d50bff4cb677f903e8174f5c0736817f1850067",
            ),
        ] {
            assert_eq!(&bytes[..4], b"\x7fELF", "{name} ELF magic");
            assert_eq!(bytes.len(), length, "{name} length");
            assert_eq!(format!("{:x}", Sha256::digest(bytes)), digest, "{name}");
        }
    }
}
