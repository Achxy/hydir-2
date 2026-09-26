//! Native ELF-to-C orchestration.
//!
//! The first vertical slice accepts symbol-backed functions and bounded
//! discovered entries. Unlike the legacy scalar LLVM path it preserves
//! unsupported instructions as explicit opaque effects and still returns a
//! compilable low-level C artifact.

mod expression;
pub use expression::lower_expression_ir;
mod pcode_cfg_llvm;
mod pcode_llvm;
mod pcode_standalone;
pub use pcode_cfg_llvm::{
    PCODE_CFG_GUEST_RAM_MAX_BYTES, PCODE_CFG_LLVM_VERSION, PcodeCfgLlvmArtifact,
    PcodeCfgLlvmSourceOperation, PcodeCfgLlvmStatus, PcodeCfgLlvmStopSite, emit_pcode_cfg_llvm,
};
pub use pcode_llvm::{
    PcodeLlvmPrefixArtifact, PcodeLlvmSourceOperation, emit_pcode_exact_operation_llvm,
    emit_pcode_linear_prefix_llvm,
};
pub use pcode_standalone::{
    PcodeStandalonePrefixArtifact, PcodeStateByte, emit_pcode_standalone_prefix_llvm,
};

use hydir_analysis::recover_pointer_table_targets;
use hydir_backend::{
    disassemble_elf, extract_executable_window, extract_symbol_code, region_contract,
};
use hydir_core::{
    Address, AddressKind, DECOMPILATION_UNIT_VERSION, DecompilationArtifactDigests,
    DecompilationDiagnostic, DecompilationSemanticFidelity, DecompilationStructuralCompleteness,
    DecompilationUnit, DecompilationVerificationStatus, DiagnosticSeverity, FactProvenance,
    FactSource, Location, ProgramSpec, REGION_SPEC_VERSION, RegionSpec, RelocationSpec,
    RelocationTargetSpec, RuntimeRangeKind, StatementAddressProvenance,
    validate_decompilation_unit,
};
use hydir_ir::{
    AbiValue, AliasSet, CIR_VERSION, Cir, CirBlock, CirStatement, CirTerminator,
    FUNCTION_INDEX_VERSION, FUNCTION_IR_VERSION, FunctionCall, FunctionEvidence,
    FunctionEvidenceState, FunctionExtent, FunctionIndex, FunctionIr, GlobalObject,
    IndexedFunction, InstructionDecorators, IrDiagnostic, MACHINE_FUNCTION_IR_VERSION,
    MachineBlock, MachineControlEffect, MachineEdge, MachineEdgeKind, MachineEffects,
    MachineFunctionIr, MachineInstruction, MachineMemoryEffect, MachineOperand, MachineOperation,
    PointerOriginKind, PointerProvenance, RecoveredAccessKind, STATE_FUNCTION_IR_VERSION,
    SemanticFidelity, StackObject, StateBlock, StateBlockFlow, StateComponentIncoming,
    StateComponentPhi, StateComponentVersion, StateFunctionIr, StateIncoming, StateOperation,
    StructuralCompleteness, VerificationStatus, validate_cir, validate_function_index,
    validate_function_ir, validate_machine_function_ir, validate_state_function_ir,
};
use hydir_loader::import_elf;
use hydir_semantics::{
    AF, CF, ControlEffect, Effects, MemoryEffect, OF, PF, R8, R9, R10, R11, R12, R13, R14, R15,
    RAX, RBP, RBX, RCX, RDI, RDX, RSI, RSP, SF, ZF, classify,
};
use iced_x86::{
    Decoder, DecoderOptions, EncodingKind, FlowControl, Instruction, OpKind, Register,
    RoundingControl,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ALL_REGISTERS: [&str; 16] = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13",
    "r14", "r15",
];
const ALL_FLAGS: [&str; 6] = ["zf", "sf", "of", "cf", "pf", "af"];
const MACHINE_FLAGS: [&str; 7] = ["zf", "sf", "of", "cf", "pf", "af", "df"];
const MAX_FUNCTION_BYTES: usize = 64 * 1024;
const MAX_DECODED_INSTRUCTIONS: usize = 16 * 1024;
const MAX_DISCOVERY_DECODE_BYTES: usize = 8 * 1024 * 1024;
const MAX_DISCOVERY_MEMBERSHIP_FUNCTIONS: usize = 256;
const MAX_DISCOVERED_FUNCTIONS: usize = 16 * 1024;
const MAX_NATIVE_C_BYTES: usize = 8 * 1024 * 1024;
const MAX_INDIRECT_RECOVERY_PASSES: usize = 32;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeDecompilation {
    pub machine_ir: MachineFunctionIr,
    pub state_ir: StateFunctionIr,
    pub function_ir: FunctionIr,
    pub cir: Cir,
    pub low_level_c: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_c: Option<String>,
    pub diagnostics: Vec<DecompilationDiagnostic>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeCoverageReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub discovered_functions: usize,
    pub attempted_functions: usize,
    pub lifted_functions: usize,
    pub exact_functions: usize,
    pub conservative_functions: usize,
    pub partial_functions: usize,
    pub exact_instructions: usize,
    pub opaque_instructions: usize,
    #[serde(default)]
    pub exact_families: BTreeMap<String, usize>,
    #[serde(default)]
    pub opaque_families: BTreeMap<String, usize>,
    /// Bounded representative locations for each opaque instruction family.
    /// Counts remain authoritative; samples are diagnostic evidence only.
    #[serde(default)]
    pub opaque_samples: BTreeMap<String, Vec<Location>>,
    #[serde(default)]
    pub diagnostics: Vec<String>,
}

pub fn discover_functions(bytes: &[u8]) -> Result<FunctionIndex, String> {
    discover_functions_impl(bytes, true)
}

/// Builds the complete evidence-backed candidate inventory while deferring
/// recursive block-membership enrichment. Interactive selection and batch
/// scheduling use this bounded form; the `discover` artifact uses the eager
/// form above.
pub fn discover_function_candidates(bytes: &[u8]) -> Result<FunctionIndex, String> {
    discover_functions_impl(bytes, false)
}

fn discover_functions_impl(
    bytes: &[u8],
    recover_block_membership: bool,
) -> Result<FunctionIndex, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let mut supplemental_diagnostics = Vec::new();
    let mut entry_counts = BTreeMap::<Location, usize>::new();
    for function in &spec.functions {
        if let Some(location) = function.location {
            *entry_counts.entry(location).or_default() += 1;
        }
    }
    let mut functions = spec
        .functions
        .iter()
        .filter_map(|function| {
            let entry = function.location?;
            let ambiguous = entry_counts.get(&entry).copied().unwrap_or(0) > 1;
            let mut evidence = vec![FunctionEvidence {
                kind: if function.provenance.contains("dynamic") {
                    "elf_dynamic_symbol".to_owned()
                } else {
                    "elf_symbol".to_owned()
                },
                description: function.provenance.clone(),
                site: Some(entry),
            }];
            if let Some(runtime_evidence) = language_symbol_evidence(&function.name, entry) {
                evidence.push(runtime_evidence);
            }
            Some(IndexedFunction {
                id: function.id.clone(),
                entry,
                name: Some(function.name.clone()),
                state: if ambiguous {
                    FunctionEvidenceState::Ambiguous
                } else {
                    FunctionEvidenceState::Confirmed
                },
                block_entries: vec![entry],
                extents: vec![FunctionExtent {
                    start: entry,
                    size: function.size,
                    evidence_kind: if function.provenance.contains("dynamic") {
                        "elf_dynamic_symbol".to_owned()
                    } else {
                        "elf_symbol".to_owned()
                    },
                }],
                evidence,
                candidate_targets: Vec::new(),
                tail_call_evidence: Vec::new(),
                unresolved_conflicts: if ambiguous {
                    vec!["multiple ELF text symbols share this entry".to_owned()]
                } else {
                    Vec::new()
                },
            })
        })
        .collect::<Vec<_>>();
    for unwind in spec.unwind_ranges.iter().filter(|range| range.executable) {
        let entry = unwind.initial_location;
        let extent = FunctionExtent {
            start: entry,
            size: unwind.address_range,
            evidence_kind: "elf_unwind_fde".to_owned(),
        };
        let evidence = FunctionEvidence {
            kind: "elf_unwind_fde".to_owned(),
            description: format!(
                "{} FDE at section offset 0x{:x} covers {} bytes",
                unwind.section_name, unwind.record_offset, unwind.address_range
            ),
            site: Some(entry),
        };
        if let Some(function) = functions
            .iter_mut()
            .find(|function| function.entry == entry)
        {
            if function
                .extents
                .iter()
                .any(|candidate| candidate.start == extent.start && candidate.size != extent.size)
            {
                function.unresolved_conflicts.push(format!(
                    "unwind range size {} disagrees with another extent at this entry",
                    extent.size
                ));
            }
            if !function.extents.contains(&extent) {
                function.extents.push(extent);
            }
            function.evidence.push(evidence);
            continue;
        }
        let overlapping = functions
            .iter()
            .enumerate()
            .filter_map(|(index, function)| {
                function
                    .extents
                    .iter()
                    .any(|candidate| function_extents_overlap(candidate, &extent))
                    .then_some(index)
            })
            .collect::<Vec<_>>();
        for index in &overlapping {
            let function = &mut functions[*index];
            if function.state != FunctionEvidenceState::Confirmed {
                function.state = FunctionEvidenceState::Ambiguous;
            }
            function.unresolved_conflicts.push(format!(
                "extent overlaps unwind-derived candidate at {}:0x{:x}",
                entry.address_space, entry.value.0
            ));
        }
        functions.push(IndexedFunction {
            id: format!(
                "sha256:{}:unwind:{}:0x{:x}",
                spec.binary_sha256, entry.address_space, entry.value.0
            ),
            entry,
            name: None,
            state: if overlapping.is_empty() {
                FunctionEvidenceState::Probable
            } else {
                FunctionEvidenceState::Ambiguous
            },
            block_entries: vec![entry],
            extents: vec![extent],
            evidence: vec![evidence],
            candidate_targets: Vec::new(),
            tail_call_evidence: Vec::new(),
            unresolved_conflicts: if overlapping.is_empty() {
                Vec::new()
            } else {
                vec!["unwind range overlaps an existing function extent".to_owned()]
            },
        });
    }
    if let Some(entry) = spec.entry_location
        && !functions.iter().any(|function| function.entry == entry)
    {
        functions.push(IndexedFunction {
            id: format!(
                "sha256:{}:entry:{}:0x{:x}",
                spec.binary_sha256, entry.address_space, entry.value.0
            ),
            entry,
            name: Some("_start".to_owned()),
            state: FunctionEvidenceState::Probable,
            block_entries: vec![entry],
            extents: Vec::new(),
            evidence: vec![FunctionEvidence {
                kind: "elf_entry".to_owned(),
                description: "ELF header entry point".to_owned(),
                site: Some(entry),
            }],
            candidate_targets: Vec::new(),
            tail_call_evidence: Vec::new(),
            unresolved_conflicts: vec![
                "function extent is not established by the ELF entry point alone".to_owned(),
            ],
        });
    }
    for array in &spec.pointer_arrays {
        for pointer in &array.entries {
            let Some(entry) = pointer.target else {
                continue;
            };
            let evidence = FunctionEvidence {
                kind: format!("elf_{:?}_array", array.kind).to_ascii_lowercase(),
                description: format!(
                    "{} entry from {}",
                    match array.kind {
                        hydir_core::RuntimePointerArrayKind::Init => "constructor",
                        hydir_core::RuntimePointerArrayKind::Fini => "destructor",
                        hydir_core::RuntimePointerArrayKind::Preinit => "pre-constructor",
                    },
                    array.section_name
                ),
                site: Some(pointer.slot),
            };
            if let Some(function) = functions
                .iter_mut()
                .find(|function| function.entry == entry)
            {
                function.evidence.push(evidence);
                continue;
            }
            functions.push(IndexedFunction {
                id: format!(
                    "sha256:{}:candidate:{}:0x{:x}",
                    spec.binary_sha256, entry.address_space, entry.value.0
                ),
                entry,
                name: None,
                state: FunctionEvidenceState::Probable,
                block_entries: vec![entry],
                extents: Vec::new(),
                evidence: vec![evidence],
                candidate_targets: Vec::new(),
                tail_call_evidence: Vec::new(),
                unresolved_conflicts: vec![
                    "runtime pointer establishes an entry but not a complete function extent"
                        .to_owned(),
                ],
            });
        }
    }
    match discover_go_pclntab(bytes, &spec) {
        Ok(discovery) => {
            for candidate in discovery.candidates {
                let evidence = FunctionEvidence {
                    kind: "go_pclntab".to_owned(),
                    description: "Go 1.18+ pclntab function entry, extent, and name".to_owned(),
                    site: Some(candidate.entry),
                };
                let extent = FunctionExtent {
                    start: candidate.entry,
                    size: candidate.size,
                    evidence_kind: "go_pclntab".to_owned(),
                };
                if let Some(function) = functions
                    .iter_mut()
                    .find(|function| function.entry == candidate.entry)
                {
                    if function.name.as_deref() == Some("_start")
                        && function
                            .evidence
                            .iter()
                            .all(|evidence| evidence.kind == "elf_entry")
                    {
                        function.name = Some(candidate.name.clone());
                    }
                    if !function.extents.contains(&extent) {
                        function.extents.push(extent);
                    }
                    function.evidence.push(evidence);
                    function.unresolved_conflicts.retain(|conflict| {
                        conflict
                            != "function extent is not established by the ELF entry point alone"
                    });
                    if function.unresolved_conflicts.is_empty() {
                        function.state = FunctionEvidenceState::Confirmed;
                    }
                    continue;
                }
                functions.push(IndexedFunction {
                    id: format!(
                        "sha256:{}:go-pclntab:0x{:x}",
                        spec.binary_sha256, candidate.entry.value.0
                    ),
                    entry: candidate.entry,
                    name: Some(candidate.name),
                    state: FunctionEvidenceState::Confirmed,
                    block_entries: vec![candidate.entry],
                    extents: vec![extent],
                    evidence: vec![evidence],
                    candidate_targets: Vec::new(),
                    tail_call_evidence: Vec::new(),
                    unresolved_conflicts: Vec::new(),
                });
            }
            if discovery.skipped != 0 || discovery.omitted != 0 {
                supplemental_diagnostics.push(IrDiagnostic {
                    code: "go_pclntab_partial".to_owned(),
                    message: format!(
                        "Go pclntab recovery skipped {} malformed row(s) and omitted {} row(s) beyond the {}-candidate bound",
                        discovery.skipped, discovery.omitted, MAX_DISCOVERED_FUNCTIONS
                    ),
                    address: None,
                    blocks_stable_operation: true,
                });
            }
        }
        Err(message) => supplemental_diagnostics.push(IrDiagnostic {
            code: "go_pclntab_invalid".to_owned(),
            message,
            address: None,
            blocks_stable_operation: true,
        }),
    }
    for (entry, size, import_name, section_name) in discover_plt_stubs(bytes, &spec) {
        let evidence = FunctionEvidence {
            kind: "elf_plt_stub".to_owned(),
            description: import_name.as_ref().map_or_else(
                || format!("decoded indirect linkage stub in {section_name}"),
                |name| format!("decoded {name} linkage stub in {section_name}"),
            ),
            site: Some(entry),
        };
        let extent = FunctionExtent {
            start: entry,
            size,
            evidence_kind: "elf_plt_stub".to_owned(),
        };
        if let Some(function) = functions
            .iter_mut()
            .find(|function| function.entry == entry)
        {
            if function.name.is_none() {
                function.name = import_name.as_ref().map(|name| format!("{name}@plt"));
            }
            if !function.extents.contains(&extent) {
                function.extents.push(extent);
            }
            function.evidence.push(evidence);
            continue;
        }
        functions.push(IndexedFunction {
            id: format!(
                "sha256:{}:plt:{}:0x{:x}",
                spec.binary_sha256, entry.address_space, entry.value.0
            ),
            entry,
            name: import_name.map(|name| format!("{name}@plt")),
            state: FunctionEvidenceState::Probable,
            block_entries: vec![entry],
            extents: vec![extent],
            evidence: vec![evidence],
            candidate_targets: Vec::new(),
            tail_call_evidence: Vec::new(),
            unresolved_conflicts: Vec::new(),
        });
    }
    if spec.file_kind != "Relocatable"
        && let Ok(report) = disassemble_elf(bytes)
    {
        for candidate in report.candidates {
            let entry = location(0, candidate.entry.0);
            if functions.iter().any(|function| function.entry == entry) {
                continue;
            }
            functions.push(IndexedFunction {
                id: format!(
                    "sha256:{}:candidate:0:0x{:x}",
                    spec.binary_sha256, candidate.entry.0
                ),
                entry,
                name: None,
                state: FunctionEvidenceState::Probable,
                block_entries: vec![entry],
                extents: Vec::new(),
                evidence: vec![FunctionEvidence {
                    kind: "native_candidate".to_owned(),
                    description: candidate.reason,
                    site: Some(location(0, candidate.evidence_site.0)),
                }],
                candidate_targets: Vec::new(),
                tail_call_evidence: Vec::new(),
                unresolved_conflicts: vec![
                    "function extent must be established by bounded recursive recovery".to_owned(),
                ],
            });
        }
    }
    let truncated = functions.len().saturating_sub(MAX_DISCOVERED_FUNCTIONS);
    if truncated != 0 {
        functions.sort_by_key(|function| {
            let evidence_rank = match function.state {
                FunctionEvidenceState::Confirmed => 0,
                FunctionEvidenceState::Probable => 1,
                FunctionEvidenceState::Ambiguous => 2,
            };
            (evidence_rank, function.entry, function.id.clone())
        });
        functions.truncate(MAX_DISCOVERED_FUNCTIONS);
    }
    let membership_diagnostic = if recover_block_membership {
        populate_direct_block_membership(bytes, &spec, &mut functions)
    } else {
        Some(IrDiagnostic {
            code: "block_membership_deferred".to_owned(),
            message: "recursive block-membership enrichment was deferred for bounded interactive selection; every candidate retains its entry, extent, and evidence and is decoded when selected"
                .to_owned(),
            address: None,
            blocks_stable_operation: false,
        })
    };
    functions.sort_by_key(|function| (function.entry, function.id.clone()));
    let mut diagnostics = vec![IrDiagnostic {
        code: "initial_discovery_incomplete".to_owned(),
        message: "FunctionIndex v1 contains ELF symbols and extents, decoded unwind FDE ranges, runtime init/fini targets, decoded PLT linkage stubs, the ELF entry point, and direct-call candidates found by bounded recursive probes; unresolved indirect targets remain explicit"
            .to_owned(),
        address: None,
        blocks_stable_operation: false,
    }];
    diagnostics.extend(supplemental_diagnostics);
    if let Some(diagnostic) = membership_diagnostic {
        diagnostics.push(diagnostic);
    }
    if truncated != 0 {
        diagnostics.push(IrDiagnostic {
            code: "function_candidate_limit".to_owned(),
            message: format!(
                "retained the {MAX_DISCOVERED_FUNCTIONS} strongest function candidates and omitted {truncated} lower-evidence candidates"
            ),
            address: None,
            blocks_stable_operation: true,
        });
    }
    let index = FunctionIndex {
        schema_version: FUNCTION_INDEX_VERSION,
        binary_sha256: spec.binary_sha256,
        functions,
        diagnostics,
    };
    validate_function_index(&index)?;
    Ok(index)
}

#[derive(Clone, Debug)]
struct GoPclnCandidate {
    entry: Location,
    size: u64,
    name: String,
}

#[derive(Clone, Debug, Default)]
struct GoPclnDiscovery {
    candidates: Vec<GoPclnCandidate>,
    skipped: usize,
    omitted: usize,
}

fn discover_go_pclntab(bytes: &[u8], spec: &ProgramSpec) -> Result<GoPclnDiscovery, String> {
    let Some(range) = spec.runtime_ranges.iter().find(|range| {
        range.kind == RuntimeRangeKind::LanguageMetadata && range.section_name == ".gopclntab"
    }) else {
        return Ok(GoPclnDiscovery::default());
    };
    if spec.file_kind == "Relocatable" || range.location.address_space != 0 {
        return Err(
            "Go pclntab discovery currently requires a linked virtual-address ELF".to_owned(),
        );
    }
    let file_offset = range
        .file_offset
        .and_then(|offset| usize::try_from(offset.0).ok())
        .ok_or_else(|| "Go pclntab has no bounded file offset".to_owned())?;
    let size = usize::try_from(range.size)
        .map_err(|_| "Go pclntab size exceeds host limits".to_owned())?;
    let end = file_offset
        .checked_add(size)
        .ok_or_else(|| "Go pclntab file range overflows".to_owned())?;
    let data = bytes
        .get(file_offset..end)
        .ok_or_else(|| "Go pclntab file range is truncated".to_owned())?;
    if data.len() < 72 {
        return Err("Go pclntab is shorter than its 64-bit header".to_owned());
    }
    let magic = read_u32(data, 0).ok_or_else(|| "Go pclntab magic is truncated".to_owned())?;
    if !matches!(magic, 0xffff_fff0 | 0xffff_fff1)
        || data[4] != 0
        || data[5] != 0
        || !matches!(data[6], 1 | 2 | 4)
        || data[7] != 8
    {
        return Err(
            "Go pclntab header is not a supported little-endian Go 1.18+ 64-bit layout".to_owned(),
        );
    }
    let function_count = read_u64(data, 8)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| "Go pclntab function count exceeds host limits".to_owned())?;
    if function_count > 1_000_000 {
        return Err(
            "Go pclntab function count exceeds the one-million-row safety bound".to_owned(),
        );
    }
    let funcname_offset = read_u64(data, 32)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| "Go pclntab function-name offset exceeds host limits".to_owned())?;
    let functab_offset = read_u64(data, 64)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| "Go pclntab function-table offset exceeds host limits".to_owned())?;
    let functab_size = function_count
        .checked_mul(2)
        .and_then(|fields| fields.checked_add(1))
        .and_then(|fields| fields.checked_mul(4))
        .ok_or_else(|| "Go pclntab function-table size overflows".to_owned())?;
    if funcname_offset >= data.len()
        || functab_offset
            .checked_add(functab_size)
            .is_none_or(|end| end > data.len())
    {
        return Err(
            "Go pclntab name or function table lies outside the metadata section".to_owned(),
        );
    }
    let text_start = spec
        .sections
        .iter()
        .filter(|section| section.kind == "Text" && section.name == ".text")
        .filter_map(|section| section.location)
        .find(|location| location.address_space == 0)
        .ok_or_else(|| "Go pclntab has no linked .text base for entry offsets".to_owned())?;
    let retained = function_count.min(MAX_DISCOVERED_FUNCTIONS);
    let mut discovery = GoPclnDiscovery {
        candidates: Vec::with_capacity(retained),
        skipped: 0,
        omitted: function_count.saturating_sub(retained),
    };
    for index in 0..retained {
        let row = functab_offset + index * 8;
        let Some(entry_offset) = read_u32(data, row).map(u64::from) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(function_offset) = read_u32(data, row + 4).map(|offset| offset as usize) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(next_offset) = read_u32(data, row + 8).map(u64::from) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(size) = next_offset
            .checked_sub(entry_offset)
            .filter(|size| *size != 0)
        else {
            discovery.skipped += 1;
            continue;
        };
        let Some(function_record) = functab_offset.checked_add(function_offset) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(name_offset) = read_u32(data, function_record + 4).map(|offset| offset as usize)
        else {
            discovery.skipped += 1;
            continue;
        };
        let Some(name_start) = funcname_offset.checked_add(name_offset) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(name_data) = data.get(name_start..) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(name_length) = name_data.iter().take(4097).position(|byte| *byte == 0) else {
            discovery.skipped += 1;
            continue;
        };
        if name_length == 0 || name_length > 4096 {
            discovery.skipped += 1;
            continue;
        }
        let Ok(name) = std::str::from_utf8(&name_data[..name_length]) else {
            discovery.skipped += 1;
            continue;
        };
        let Some(entry_value) = text_start.value.0.checked_add(entry_offset) else {
            discovery.skipped += 1;
            continue;
        };
        let entry = location(0, entry_value);
        if !spec.mapped_segments.iter().any(|segment| {
            segment.executable
                && segment.virtual_address.0 <= entry_value
                && segment
                    .virtual_address
                    .0
                    .checked_add(segment.memory_size)
                    .is_some_and(|end| entry_value < end)
        }) {
            discovery.skipped += 1;
            continue;
        }
        discovery.candidates.push(GoPclnCandidate {
            entry,
            size,
            name: name.to_owned(),
        });
    }
    Ok(discovery)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset.checked_add(8)?)?
        .try_into()
        .ok()
        .map(u64::from_le_bytes)
}

fn language_symbol_evidence(name: &str, entry: Location) -> Option<FunctionEvidence> {
    let (kind, description) = if is_rust_symbol(name) {
        (
            "rust_symbol",
            "symbol spelling matches Rust v0 or legacy hash-bearing mangling",
        )
    } else if name.starts_with("_Z") {
        (
            "itanium_cxx_symbol",
            "symbol spelling matches the Itanium C++ ABI mangling prefix",
        )
    } else if is_go_symbol(name) {
        (
            "go_symbol",
            "symbol spelling matches a Go package/runtime function convention",
        )
    } else {
        return None;
    };
    Some(FunctionEvidence {
        kind: kind.to_owned(),
        description: description.to_owned(),
        site: Some(entry),
    })
}

fn is_rust_symbol(name: &str) -> bool {
    if name.starts_with("_R") {
        return true;
    }
    let Some(hash) = name
        .strip_suffix('E')
        .and_then(|name| name.rsplit_once("17h"))
    else {
        return false;
    };
    name.starts_with("_ZN")
        && hash.1.len() == 16
        && hash.1.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_go_symbol(name: &str) -> bool {
    let Some((package, function)) = name.rsplit_once('.') else {
        return false;
    };
    !package.is_empty()
        && !function.is_empty()
        && package
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'/' | b'-' | b'.'))
        && function.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'$' | b'-' | b'(' | b')' | b'*' | b'[' | b']')
        })
}

fn populate_direct_block_membership(
    bytes: &[u8],
    spec: &ProgramSpec,
    functions: &mut [IndexedFunction],
) -> Option<IrDiagnostic> {
    let entries = functions
        .iter()
        .map(|function| function.entry)
        .collect::<Vec<_>>();
    let mut decoded_bytes = 0usize;
    let mut decoded_functions = 0usize;
    let mut skipped = 0usize;
    for function in functions {
        if decoded_functions >= MAX_DISCOVERY_MEMBERSHIP_FUNCTIONS {
            skipped += 1;
            continue;
        }
        let extent_bound = function
            .extents
            .iter()
            .filter(|extent| extent.start == function.entry && extent.size != 0)
            .filter_map(|extent| usize::try_from(extent.size).ok())
            .min()
            .map(|bound| bound.min(MAX_FUNCTION_BYTES));
        let next_entry_bound = entries
            .iter()
            .filter(|entry| {
                entry.address_space == function.entry.address_space
                    && entry.value.0 > function.entry.value.0
            })
            .filter_map(|entry| {
                entry
                    .value
                    .0
                    .checked_sub(function.entry.value.0)
                    .and_then(|distance| usize::try_from(distance).ok())
            })
            .min();
        let bound = extent_bound
            .or(next_entry_bound)
            .unwrap_or(MAX_FUNCTION_BYTES)
            .min(MAX_FUNCTION_BYTES);
        if bound == 0 {
            skipped += 1;
            continue;
        }
        if decoded_bytes
            .checked_add(bound)
            .is_none_or(|total| total > MAX_DISCOVERY_DECODE_BYTES)
        {
            skipped += 1;
            continue;
        }
        let Ok(code) = extract_location_window(bytes, spec, function.entry, bound) else {
            skipped += 1;
            continue;
        };
        decoded_bytes += code.len();
        decoded_functions += 1;
        let stop_entries = entries
            .iter()
            .filter(|entry| {
                entry.address_space == function.entry.address_space && **entry != function.entry
            })
            .map(|entry| entry.value.0)
            .collect::<BTreeSet<_>>();
        let Ok(mut machine) = decode_program_function(
            &code,
            function.entry.value.0,
            function.entry.address_space,
            spec.binary_sha256.clone(),
            function.id.clone(),
            function
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", function.entry.value.0)),
            &stop_entries,
            bytes,
            spec,
        ) else {
            skipped += 1;
            continue;
        };
        if spec.file_kind == "Relocatable" && apply_control_relocations(&mut machine, spec).is_err()
        {
            skipped += 1;
            continue;
        }
        function.block_entries = machine.blocks.iter().map(|block| block.address).collect();
        if !function.block_entries.contains(&function.entry) {
            function.block_entries.insert(0, function.entry);
        }
        function.candidate_targets = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .flat_map(|instruction| {
                instruction.edges.iter().filter_map(move |edge| {
                    (edge.kind == MachineEdgeKind::Call
                        || edge.kind == MachineEdgeKind::IndirectTarget
                        || (instruction.effects.control == MachineControlEffect::DirectBranch
                            && edge.kind == MachineEdgeKind::External))
                        .then_some(edge.target)
                        .flatten()
                })
            })
            .collect();
        function.candidate_targets.sort();
        function.candidate_targets.dedup();
        function.tail_call_evidence = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| {
                instruction.effects.control == MachineControlEffect::DirectBranch
                    && instruction
                        .edges
                        .iter()
                        .any(|edge| edge.kind == MachineEdgeKind::External && edge.target.is_some())
            })
            .map(|instruction| FunctionEvidence {
                kind: "direct_terminal_branch".to_owned(),
                description:
                    "direct branch leaves the bounded function extent and may be a tail call"
                        .to_owned(),
                site: Some(instruction.address),
            })
            .collect();
    }
    (skipped != 0).then(|| IrDiagnostic {
        code: "block_membership_budget".to_owned(),
        message: format!(
            "direct block-membership recovery skipped {skipped} candidates after extraction/decoding failures, the {MAX_DISCOVERY_DECODE_BYTES}-byte analysis budget, or the {MAX_DISCOVERY_MEMBERSHIP_FUNCTIONS}-function eager-membership budget; every retained candidate still keeps its entry and evidence for lazy lifting"
        ),
        address: None,
        blocks_stable_operation: false,
    })
}

fn function_extents_overlap(left: &FunctionExtent, right: &FunctionExtent) -> bool {
    if left.start.address_space != right.start.address_space {
        return false;
    }
    let Some(left_end) = left.start.value.0.checked_add(left.size) else {
        return true;
    };
    let Some(right_end) = right.start.value.0.checked_add(right.size) else {
        return true;
    };
    left.start.value.0 < right_end && right.start.value.0 < left_end
}

fn discover_plt_stubs(
    bytes: &[u8],
    spec: &ProgramSpec,
) -> Vec<(Location, u64, Option<String>, String)> {
    let mut import_names = spec
        .relocations
        .iter()
        .filter(|relocation| relocation.format_flags.contains("r_type: 7"))
        .filter_map(|relocation| match &relocation.target {
            RelocationTargetSpec::Symbol {
                name: Some(name),
                defined: false,
                ..
            } => Some((
                relocation
                    .location_ref
                    .unwrap_or_else(|| location(0, relocation.location.0)),
                name.clone(),
            )),
            _ => None,
        })
        .collect::<Vec<_>>();
    import_names.sort_by_key(|(location, _)| *location);
    let import_names = import_names
        .into_iter()
        .map(|(_, name)| name)
        .collect::<Vec<_>>();
    let mut stubs = Vec::new();
    'ranges: for range in spec
        .runtime_ranges
        .iter()
        .filter(|range| range.kind == RuntimeRangeKind::Plt)
    {
        let stride = if range.section_name == ".plt.got" {
            8usize
        } else {
            16usize
        };
        let Ok(size) = usize::try_from(range.size) else {
            continue;
        };
        if size < stride || size > MAX_DISCOVERY_DECODE_BYTES {
            continue;
        }
        let Ok(data) = extract_location_window(bytes, spec, range.location, size) else {
            continue;
        };
        let first_slot = usize::from(range.section_name == ".plt");
        for slot_index in first_slot..(data.len() / stride) {
            if stubs.len() >= MAX_DISCOVERED_FUNCTIONS {
                break 'ranges;
            }
            let offset = slot_index * stride;
            let Some(entry_value) = range.location.value.0.checked_add(offset as u64) else {
                continue;
            };
            let mut decoder = Decoder::with_ip(
                64,
                &data[offset..offset + stride],
                entry_value,
                DecoderOptions::NONE,
            );
            let mut has_indirect_jump = false;
            while decoder.can_decode() {
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    break;
                }
                if instruction.flow_control() == FlowControl::IndirectBranch {
                    has_indirect_jump = true;
                    break;
                }
            }
            if !has_indirect_jump {
                continue;
            }
            let import_index = if range.section_name == ".plt" {
                slot_index.checked_sub(1)
            } else if range.section_name == ".plt.sec" {
                Some(slot_index)
            } else {
                None
            };
            stubs.push((
                location(range.location.address_space, entry_value),
                stride as u64,
                import_index.and_then(|index| import_names.get(index).cloned()),
                range.section_name.clone(),
            ));
        }
    }
    stubs.sort_by_key(|(entry, _, _, _)| *entry);
    stubs.dedup_by_key(|(entry, _, _, _)| *entry);
    stubs
}

pub fn lift_machine_function(bytes: &[u8], symbol: &str) -> Result<MachineFunctionIr, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let function = spec
        .functions
        .iter()
        .find(|function| function.name == symbol)
        .ok_or_else(|| format!("function symbol {symbol:?} is not present in ProgramSpec"))?;
    let entry = function
        .location
        .ok_or_else(|| format!("function symbol {symbol:?} has no canonical location"))?;
    let (code, address) = extract_symbol_code(bytes, symbol).map_err(|error| error.to_string())?;
    let mut ir = decode_program_function(
        &code,
        address,
        entry.address_space,
        spec.binary_sha256.clone(),
        function.id.clone(),
        symbol.to_owned(),
        &BTreeSet::new(),
        bytes,
        &spec,
    )?;
    if spec.file_kind == "Relocatable" {
        apply_control_relocations(&mut ir, &spec)?;
    }
    validate_machine_function_ir(&ir)?;
    ir.verification = VerificationStatus::StaticallyValidated;
    Ok(ir)
}

pub fn lift_machine_function_at(
    bytes: &[u8],
    entry: Location,
) -> Result<MachineFunctionIr, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let index = discover_function_candidates(bytes)?;
    let selected = index
        .functions
        .iter()
        .find(|function| function.entry == entry)
        .ok_or_else(|| {
            format!(
                "{}:0x{:x} is not a FunctionIndex entry; add an analyst entry fact first",
                entry.address_space, entry.value.0
            )
        })?;
    lift_indexed_function(
        bytes,
        &spec,
        &index,
        selected,
        selected.state != FunctionEvidenceState::Confirmed,
    )
}

fn lift_indexed_function(
    bytes: &[u8],
    spec: &ProgramSpec,
    index: &FunctionIndex,
    selected: &IndexedFunction,
    candidate_mode: bool,
) -> Result<MachineFunctionIr, String> {
    if spec.binary_sha256 != index.binary_sha256 {
        return Err("ProgramSpec and FunctionIndex binary digests differ".to_owned());
    }
    let entry = selected.entry;
    let stop_entries = index
        .functions
        .iter()
        .filter(|function| function.entry.address_space == entry.address_space)
        .map(|function| function.entry.value.0)
        .filter(|address| *address != entry.value.0)
        .collect::<BTreeSet<_>>();
    let extent_bound = selected
        .extents
        .iter()
        .filter(|extent| extent.start == entry && extent.size != 0)
        .filter_map(|extent| usize::try_from(extent.size).ok())
        .min();
    let window_bound = extent_bound
        .unwrap_or(MAX_FUNCTION_BYTES)
        .min(MAX_FUNCTION_BYTES);
    let code = extract_location_window(bytes, spec, entry, window_bound)?;
    let mut machine = decode_program_function(
        &code,
        entry.value.0,
        entry.address_space,
        spec.binary_sha256.clone(),
        selected.id.clone(),
        selected
            .name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", entry.value.0)),
        &stop_entries,
        bytes,
        spec,
    )?;
    if spec.file_kind == "Relocatable" {
        apply_control_relocations(&mut machine, spec)?;
    }
    if !candidate_mode {
        validate_machine_function_ir(&machine)?;
        machine.verification = VerificationStatus::StaticallyValidated;
        return Ok(machine);
    }
    machine.structural_completeness = StructuralCompleteness::Partial;
    machine.diagnostics.push(IrDiagnostic {
        code: if extent_bound.is_some() {
            "evidence_bounded_extent".to_owned()
        } else {
            "candidate_extent".to_owned()
        },
        message: if let Some(extent) = extent_bound {
            format!(
                "Function body was recovered recursively inside a {extent}-byte evidence extent; block ownership and indirect targets remain unproven"
            )
        } else {
            "Function body was recovered recursively from a candidate entry inside a bounded executable window; indirect targets and the complete extent remain unproven"
                .to_owned()
        },
        address: Some(entry),
        blocks_stable_operation: true,
    });
    validate_machine_function_ir(&machine)?;
    Ok(machine)
}

fn extract_location_window(
    bytes: &[u8],
    spec: &ProgramSpec,
    entry: Location,
    max_size: usize,
) -> Result<Vec<u8>, String> {
    if max_size == 0 || max_size > MAX_FUNCTION_BYTES {
        return Err(format!(
            "executable discovery window must contain 1..={MAX_FUNCTION_BYTES} bytes"
        ));
    }
    if entry.address_space == 0 && spec.file_kind != "Relocatable" {
        return extract_executable_window(bytes, entry.value.0, max_size)
            .map_err(|error| error.to_string());
    }
    let section = spec
        .sections
        .iter()
        .find(|section| {
            section.kind == "Text"
                && section.location.is_some_and(|location| {
                    location.address_space == entry.address_space
                        && location.value.0 <= entry.value.0
                        && location
                            .value
                            .0
                            .checked_add(section.size)
                            .is_some_and(|end| entry.value.0 < end)
                })
        })
        .ok_or_else(|| {
            format!(
                "{}:0x{:x} is not in an executable text section",
                entry.address_space, entry.value.0
            )
        })?;
    let section_location = section
        .location
        .ok_or_else(|| "validated text section has no canonical location".to_owned())?;
    let file_offset = section
        .file_offset
        .ok_or_else(|| "executable text section has no file-backed bytes".to_owned())?
        .0;
    let relative = entry
        .value
        .0
        .checked_sub(section_location.value.0)
        .ok_or_else(|| "entry precedes its containing section".to_owned())?;
    let available = section
        .size
        .checked_sub(relative)
        .ok_or_else(|| "entry exceeds its containing section".to_owned())?;
    let start = file_offset
        .checked_add(relative)
        .and_then(|offset| usize::try_from(offset).ok())
        .ok_or_else(|| "executable section file offset exceeds host size".to_owned())?;
    let available = usize::try_from(available).unwrap_or(usize::MAX);
    let length = max_size
        .min(available)
        .min(bytes.len().saturating_sub(start));
    let end = start
        .checked_add(length)
        .ok_or_else(|| "executable discovery window overflows host size".to_owned())?;
    if length == 0 || end > bytes.len() {
        return Err("executable discovery window is empty or outside the file".to_owned());
    }
    Ok(bytes[start..end].to_vec())
}

#[allow(clippy::too_many_arguments)]
fn decode_program_function(
    code: &[u8],
    address: u64,
    address_space: u32,
    binary_sha256: String,
    function_id: String,
    name: String,
    stop_entries: &BTreeSet<u64>,
    bytes: &[u8],
    spec: &ProgramSpec,
) -> Result<MachineFunctionIr, String> {
    let initial = decode_function(
        code,
        address,
        address_space,
        binary_sha256.clone(),
        function_id.clone(),
        name.clone(),
        stop_entries,
    )?;
    let mut recovered = initial;
    let mut targets = BTreeMap::<u64, Vec<u64>>::new();
    for _ in 0..MAX_INDIRECT_RECOVERY_PASSES {
        let pass_targets = recover_indirect_target_map(bytes, spec, &recovered);
        let mut changed = false;
        for (site, mut site_targets) in pass_targets {
            site_targets.sort_unstable();
            site_targets.dedup();
            let stored = targets.entry(site).or_default();
            let old_len = stored.len();
            stored.extend(site_targets);
            stored.sort_unstable();
            stored.dedup();
            changed |= stored.len() != old_len;
        }
        if !changed {
            break;
        }
        recovered = decode_function_with_targets(
            code,
            address,
            address_space,
            binary_sha256.clone(),
            function_id.clone(),
            name.clone(),
            stop_entries,
            &targets,
        )?;
    }
    if targets.is_empty() {
        return Ok(recovered);
    }
    let target_count = targets.values().map(Vec::len).sum::<usize>();
    let site_count = targets.len();
    recovered.diagnostics.push(IrDiagnostic {
        code: "bounded_indirect_targets".to_owned(),
        message: format!(
            "recovered {target_count} in-function targets across {site_count} indirect control site(s) from bounded pointer-table, relocation-backed relative-table, or register-constant evidence"
        ),
        address: targets
            .keys()
            .next()
            .map(|address| location(address_space, *address)),
        blocks_stable_operation: false,
    });
    Ok(recovered)
}

fn recover_indirect_target_map(
    bytes: &[u8],
    spec: &ProgramSpec,
    machine: &MachineFunctionIr,
) -> BTreeMap<u64, Vec<u64>> {
    let mut recovered = BTreeMap::new();
    let mut instructions = machine
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .collect::<Vec<_>>();
    instructions.sort_by_key(|instruction| instruction.address);
    for (position, instruction) in instructions.iter().enumerate() {
        if !matches!(
            instruction.effects.control,
            MachineControlEffect::IndirectBranch | MachineControlEffect::IndirectCall
        ) {
            continue;
        }
        let targets = match instruction.operands.first() {
            Some(MachineOperand::Memory {
                base,
                index,
                scale,
                displacement,
                absolute,
                width_bits,
                ..
            }) if *width_bits == 64 && (index.is_none() || *scale == 8) => {
                let table_value = if let Some(base_register) = base {
                    recover_register_constant_value(&instructions, position, base_register)
                        .and_then(|value| {
                            value
                                .checked_add(absolute.unwrap_or(0))
                                .and_then(|value| value.checked_add_signed(*displacement))
                        })
                } else {
                    absolute.or_else(|| u64::try_from(*displacement).ok())
                };
                let Some(table_value) = table_value else {
                    continue;
                };
                let indexed = index.is_some();
                let targets = recover_pointer_table_targets(
                    bytes,
                    spec,
                    location(machine.entry.address_space, table_value),
                    machine.entry,
                    machine.byte_length,
                    if indexed { 256 } else { 1 },
                );
                if (indexed && targets.len() < 2) || targets.is_empty() {
                    continue;
                }
                targets
            }
            Some(MachineOperand::Register { name, .. }) => {
                let table_targets =
                    if instruction.effects.control == MachineControlEffect::IndirectBranch {
                        recover_relative_jump_table_targets(
                            spec,
                            machine,
                            &instructions,
                            position,
                            name,
                        )
                    } else {
                        Vec::new()
                    };
                if table_targets.len() >= 2 {
                    table_targets
                } else {
                    let targets =
                        recover_register_constant_targets(machine, &instructions, position, name);
                    if targets.is_empty() {
                        continue;
                    }
                    targets
                }
            }
            _ => continue,
        };
        recovered.insert(
            instruction.address.value.0,
            targets.into_iter().map(|target| target.value.0).collect(),
        );
    }
    recovered
}

fn recover_register_constant_targets(
    machine: &MachineFunctionIr,
    instructions: &[&MachineInstruction],
    control_position: usize,
    control_register: &str,
) -> Vec<Location> {
    let Some(value) =
        recover_register_constant_value(instructions, control_position, control_register)
    else {
        return Vec::new();
    };
    // A constant indirect target is proven even when it leaves the current
    // function extent. The decoder will not recursively claim an external
    // block, while CIR lowers it to an explicit external exit/tail target.
    vec![location(machine.entry.address_space, value)]
}

fn recover_register_constant_value(
    instructions: &[&MachineInstruction],
    use_position: usize,
    register: &str,
) -> Option<u64> {
    if use_position > instructions.len() {
        return None;
    }
    let mut tracked = register.to_owned();
    for instruction in instructions[..use_position].iter().rev().take(16) {
        if instruction.effects.control != MachineControlEffect::Next {
            break;
        }
        if !instruction.effects.written_registers.contains(&tracked) {
            continue;
        }
        let MachineOperation::Exact { family } = &instruction.operation else {
            return None;
        };
        let [
            MachineOperand::Register {
                name: destination,
                width_bits: 64,
            },
            source,
        ] = instruction.operands.as_slice()
        else {
            return None;
        };
        if destination != &tracked {
            return None;
        }
        let value = match (family.as_str(), source) {
            (
                "lea",
                MachineOperand::Memory {
                    base: None,
                    index: None,
                    absolute: Some(value),
                    ..
                },
            ) => Some(*value),
            ("mov", MachineOperand::Immediate { value, .. }) => Some(*value),
            (
                "mov",
                MachineOperand::Register {
                    name,
                    width_bits: 64,
                },
            ) => {
                tracked.clone_from(name);
                continue;
            }
            _ => None,
        };
        return value;
    }
    None
}

fn recover_relative_jump_table_targets(
    spec: &ProgramSpec,
    machine: &MachineFunctionIr,
    instructions: &[&MachineInstruction],
    jump_position: usize,
    jump_register: &str,
) -> Vec<Location> {
    if jump_position < 3 {
        return Vec::new();
    }
    let [lea, load, add] = [
        instructions[jump_position - 3],
        instructions[jump_position - 2],
        instructions[jump_position - 1],
    ];
    if !instructions_are_contiguous(&[lea, load, add, instructions[jump_position]]) {
        return Vec::new();
    }
    let (
        [
            MachineOperand::Register {
                name: table_register,
                ..
            },
            MachineOperand::Memory { .. },
        ],
        [
            MachineOperand::Register {
                name: load_destination,
                width_bits: 64,
            },
            MachineOperand::Memory {
                base: Some(load_base),
                index: Some(_),
                scale: 4,
                width_bits: 32,
                ..
            },
        ],
        [
            MachineOperand::Register {
                name: add_destination,
                width_bits: 64,
            },
            MachineOperand::Register {
                name: add_source,
                width_bits: 64,
            },
        ],
    ) = (
        lea.operands.as_slice(),
        load.operands.as_slice(),
        add.operands.as_slice(),
    )
    else {
        return Vec::new();
    };
    if !matches!(&lea.operation, MachineOperation::Exact { family } if family == "lea")
        || !matches!(&load.operation, MachineOperation::Exact { family } if family == "movsxd")
        || !matches!(&add.operation, MachineOperation::Exact { family } if family == "add")
        || load_destination != jump_register
        || add_destination != jump_register
        || load_base != table_register
        || add_source != table_register
    {
        return Vec::new();
    }
    let lea_length = u64::try_from(lea.bytes_hex.len() / 2).unwrap_or(0);
    let Some(lea_end) = lea.address.value.0.checked_add(lea_length) else {
        return Vec::new();
    };
    let Some(table_relocation) = spec.relocations.iter().find(|relocation| {
        relocation.kind == "Relative"
            && relocation.size_bits == 32
            && relocation.location_ref.is_some_and(|site| {
                site.address_space == lea.address.address_space
                    && (lea.address.value.0..lea_end).contains(&site.value.0)
            })
    }) else {
        return Vec::new();
    };
    let Some(relocation_site) = table_relocation.location_ref else {
        return Vec::new();
    };
    let Some(target_base) = relocation_target_location(&table_relocation.target) else {
        return Vec::new();
    };
    let Some(next_ip_adjustment) = lea_end.checked_sub(relocation_site.value.0) else {
        return Vec::new();
    };
    let Some(table_adjustment) = i64::try_from(next_ip_adjustment)
        .ok()
        .and_then(|adjustment| table_relocation.addend.checked_add(adjustment))
    else {
        return Vec::new();
    };
    let Some(table_value) = target_base.value.0.checked_add_signed(table_adjustment) else {
        return Vec::new();
    };
    let table = location(target_base.address_space, table_value);
    let Some(function_end) = machine.entry.value.0.checked_add(machine.byte_length) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for index in 0..256_u64 {
        let Some(slot_value) = index
            .checked_mul(4)
            .and_then(|offset| table.value.0.checked_add(offset))
        else {
            break;
        };
        let slot = location(table.address_space, slot_value);
        let Some(relocation) = spec.relocations.iter().find(|relocation| {
            relocation.location_ref == Some(slot)
                && relocation.kind == "Relative"
                && relocation.size_bits == 32
        }) else {
            break;
        };
        let Some(base) = relocation_target_location(&relocation.target) else {
            break;
        };
        if base.address_space != machine.entry.address_space {
            break;
        }
        let Some(slot_offset) = slot.value.0.checked_sub(table.value.0) else {
            break;
        };
        let Some(target_value) = base
            .value
            .0
            .checked_add_signed(relocation.addend)
            .and_then(|value| value.checked_sub(slot_offset))
        else {
            break;
        };
        let target = location(base.address_space, target_value);
        if !(machine.entry.value.0..function_end).contains(&target_value)
            || !spec.sections.iter().any(|section| {
                section.kind == "Text"
                    && section.location.is_some_and(|start| {
                        start.address_space == target.address_space
                            && start.value.0 <= target.value.0
                            && start
                                .value
                                .0
                                .checked_add(section.size)
                                .is_some_and(|end| target.value.0 < end)
                    })
            })
        {
            break;
        }
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    targets
}

fn relocation_target_location(target: &RelocationTargetSpec) -> Option<Location> {
    match target {
        RelocationTargetSpec::Symbol {
            location,
            defined: true,
            ..
        }
        | RelocationTargetSpec::Section { location, .. } => *location,
        _ => None,
    }
}

fn instructions_are_contiguous(instructions: &[&MachineInstruction]) -> bool {
    instructions.windows(2).all(|pair| {
        let length = u64::try_from(pair[0].bytes_hex.len() / 2).unwrap_or(0);
        pair[0]
            .address
            .value
            .0
            .checked_add(length)
            .is_some_and(|end| end == pair[1].address.value.0)
    })
}

fn decode_function(
    code: &[u8],
    address: u64,
    address_space: u32,
    binary_sha256: String,
    function_id: String,
    name: String,
    stop_entries: &BTreeSet<u64>,
) -> Result<MachineFunctionIr, String> {
    decode_function_with_targets(
        code,
        address,
        address_space,
        binary_sha256,
        function_id,
        name,
        stop_entries,
        &BTreeMap::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_function_with_targets(
    code: &[u8],
    address: u64,
    address_space: u32,
    binary_sha256: String,
    function_id: String,
    name: String,
    stop_entries: &BTreeSet<u64>,
    indirect_targets: &BTreeMap<u64, Vec<u64>>,
) -> Result<MachineFunctionIr, String> {
    if code.is_empty() || code.len() > MAX_FUNCTION_BYTES {
        return Err(format!(
            "native function extent must contain 1..={MAX_FUNCTION_BYTES} bytes"
        ));
    }
    let end = address
        .checked_add(code.len() as u64)
        .ok_or_else(|| "function address range overflows".to_owned())?;
    let mut pending = VecDeque::from([address]);
    let mut instructions = BTreeMap::<u64, MachineInstruction>::new();
    let mut byte_owners = vec![None::<u64>; code.len()];
    let mut diagnostics = Vec::new();
    let mut structural = StructuralCompleteness::Complete;
    let mut semantic = SemanticFidelity::ExactUnderModel;

    while let Some(ip) = pending.pop_front() {
        if instructions.len() >= MAX_DECODED_INSTRUCTIONS {
            structural = StructuralCompleteness::Partial;
            diagnostics.push(IrDiagnostic {
                code: "instruction_limit".to_owned(),
                message: format!(
                    "recursive decoding stopped at the {MAX_DECODED_INSTRUCTIONS}-instruction limit"
                ),
                address: Some(location(address_space, ip)),
                blocks_stable_operation: true,
            });
            break;
        }
        if instructions.contains_key(&ip) {
            continue;
        }
        if !(address..end).contains(&ip) {
            continue;
        }
        let offset = usize::try_from(ip - address)
            .map_err(|_| "instruction offset exceeds host size".to_owned())?;
        if let Some(owner) = byte_owners[offset] {
            structural = StructuralCompleteness::Partial;
            diagnostics.push(IrDiagnostic {
                code: "overlapping_instruction".to_owned(),
                message: format!("control target 0x{ip:x} enters instruction owned by 0x{owner:x}"),
                address: Some(location(address_space, ip)),
                blocks_stable_operation: true,
            });
            continue;
        }
        let mut decoder = Decoder::with_ip(64, &code[offset..], ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let length = decoder.position().max(1).min(code.len() - offset);
        for owner in &mut byte_owners[offset..offset + length] {
            *owner = Some(ip);
        }
        let raw = &code[offset..offset + length];
        let invalid = instruction.is_invalid();
        let control = control_effect(&instruction, invalid);
        let indirect_resolved = indirect_targets
            .get(&ip)
            .is_some_and(|targets| !targets.is_empty());
        let classification = if invalid {
            Err(format!("invalid x86 instruction at 0x{ip:x}"))
        } else {
            generic_exact_effects(&instruction).map_or_else(
                || classify(&instruction).map(|operation| exact_effects(operation.effects())),
                Ok,
            )
        };
        let classification = if classification.is_err()
            && matches!(
                control,
                MachineControlEffect::IndirectCall | MachineControlEffect::IndirectBranch
            ) {
            indirect_control_effects(&instruction, control)
                .ok_or_else(|| format!("unsupported indirect control at 0x{ip:x}"))
        } else {
            classification
        };
        let (operation, effects) = match classification {
            Ok(effects) => {
                if matches!(
                    control,
                    MachineControlEffect::DirectCall
                        | MachineControlEffect::IndirectCall
                        | MachineControlEffect::IndirectBranch
                ) {
                    semantic = SemanticFidelity::Conservative;
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Div | iced_x86::Mnemonic::Idiv
                ) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_divide_exception".to_owned(),
                        message: "division has exact normal-path arithmetic and an explicit unresolved exception edge in machine/state/function IR; CIR and C retain the exception as a non-returning divide-error helper"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if instruction.mnemonic() == iced_x86::Mnemonic::Ud2 {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_invalid_opcode_exception".to_owned(),
                        message: "UD2 has an exact non-returning invalid-opcode operation and an explicit unresolved exception edge in machine/state/function IR; generated C retains it as a non-returning helper"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if instruction.mnemonic() == iced_x86::Mnemonic::Int3 {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_breakpoint_exception".to_owned(),
                        message: "INT3 has an exact non-returning breakpoint operation and an explicit unresolved exception edge in machine/state/function IR; generated C retains it as a non-returning helper"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if instruction.mnemonic() == iced_x86::Mnemonic::Int {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_software_interrupt".to_owned(),
                        message: "INT has an exact non-returning software-interrupt operation and explicit unresolved exception edge; generated C retains the vector and fault site through a non-returning helper"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Pushfq | iced_x86::Mnemonic::Popfq
                ) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_flags_stack_environment".to_owned(),
                        message: "PUSHFQ/POPFQ has an explicit native helper contract over modeled flags, preserved unmodeled RFLAGS bits, stack memory, and privilege-dependent writability; the environment dependence prevents an exact-under-model function claim"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Bsf | iced_x86::Mnemonic::Bsr
                ) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "conditional_undefined_bit_scan_destination".to_owned(),
                        message: "BSF/BSR data and flag behavior is explicit, including an undefined-value helper for the zero-source destination, but conditional undefinedness is not yet a first-class StateIR output"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if scalar_float_binary_width(instruction.mnemonic()).is_some()
                    || packed_float_binary_lane_width(instruction.mnemonic()).is_some()
                    || scalar_float_compare_width(instruction.mnemonic()).is_some()
                    || scalar_float_sqrt_width(instruction.mnemonic()).is_some()
                    || packed_float_sqrt_lane_width(instruction.mnemonic()).is_some()
                    || scalar_float_precision_conversion(instruction.mnemonic()).is_some()
                    || scalar_integer_float_conversion(instruction.mnemonic()).is_some()
                    || packed_integer_float_conversion(instruction.mnemonic()).is_some()
                    || packed_float_precision_conversion(instruction.mnemonic()).is_some()
                {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_simd_float_exception".to_owned(),
                        message: "SSE/AVX floating operations have exact operand, destination-lane, and MXCSR-helper semantics on the normal path plus an explicit unresolved SIMD floating-point exception edge; unmasked exception delivery is not yet lowered into CIR"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if x87_may_deliver_exception(instruction.mnemonic()) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_x87_exception".to_owned(),
                        message: "the x87 operation has exact stack, 80-bit value, status/tag/control, memory, and integer-flag semantics on the normal path through the native x87 helper contract plus an explicit unresolved x87 exception edge"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if extended_state_may_deliver_exception(instruction.mnemonic()) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_extended_state_exception".to_owned(),
                        message: "the FXSAVE/FXRSTOR or MXCSR transfer has exact bounded state-image semantics on the normal path plus an explicit unresolved alignment, reserved-bit, or memory exception edge"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if supported_environment_instruction(instruction.mnemonic()) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_environment_input".to_owned(),
                        message: "the system instruction has exact bounded register and flag effects through a native environment helper; its host/privilege-dependent value or unsupported-feature exception remains explicit and prevents an exact-under-model function claim"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if aligned_vector_memory_operation(&instruction) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_vector_alignment_exception".to_owned(),
                        message: "the aligned SSE/AVX memory move has exact normal-path register and memory semantics through an alignment-checking helper plus an explicit unresolved alignment or memory exception edge"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if instruction.mnemonic() == iced_x86::Mnemonic::Vmovntdq {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "explicit_non_temporal_store_ordering".to_owned(),
                        message: "VMOVNTDQ has exact byte-store semantics through the native non-temporal helper and threads ordered memory state, but cacheability and weak-ordering details are not yet first-class FunctionIR properties"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Shl | iced_x86::Mnemonic::Shr | iced_x86::Mnemonic::Sar
                ) && instruction.op_count() == 2
                    && instruction.op_kind(1) == OpKind::Register
                {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "summarized_variable_shift_flags".to_owned(),
                        message: "variable shift data and carry are exact for 32/64-bit operands and generated C makes count-dependent overflow undefinedness visible, but conditional undefinedness is not yet a first-class StateIR output"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Shld | iced_x86::Mnemonic::Shrd
                ) && instruction.op_count() == 3
                    && instruction.op_kind(2) == OpKind::Register
                {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "summarized_variable_double_shift_flags".to_owned(),
                        message: "variable double-width shift data and carry are exact for 32/64-bit operands and generated C makes count-dependent overflow undefinedness visible, but conditional undefinedness is not yet a first-class StateIR output"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Rol | iced_x86::Mnemonic::Ror
                ) && instruction.op_count() == 2
                    && instruction.op_kind(1) == OpKind::Register
                {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "summarized_variable_rotate_flags".to_owned(),
                        message: "variable rotate data and carry are exact and generated C makes count-dependent overflow undefinedness visible, but conditional undefinedness is not yet a first-class StateIR output"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if matches!(
                    instruction.mnemonic(),
                    iced_x86::Mnemonic::Rcl | iced_x86::Mnemonic::Rcr
                ) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "conditional_undefined_rotate_through_carry_overflow".to_owned(),
                        message: "rotate-through-carry data and carry are exact for width-generic immediate and CL counts; generated C makes count-dependent overflow undefinedness visible, but conditional undefinedness is not yet a first-class StateIR output"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                if supported_string_operation(&instruction) {
                    semantic = SemanticFidelity::Conservative;
                    diagnostics.push(IrDiagnostic {
                        code: "summarized_string_fault_progress".to_owned(),
                        message: "string transfer register and memory behavior is modeled, including REP and the direction flag, but interruption and fault-time partial progress are not first-class CFG outcomes"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                }
                (
                    MachineOperation::Exact {
                        family: exact_operation_family(&instruction),
                    },
                    effects,
                )
            }
            Err(reason) => {
                semantic = SemanticFidelity::Conservative;
                diagnostics.push(IrDiagnostic {
                    code: "opaque_instruction".to_owned(),
                    message: reason.clone(),
                    address: Some(location(address_space, ip)),
                    blocks_stable_operation: true,
                });
                let effects = if let Some(effects) =
                    bounded_system_opaque_effects(&instruction, control)
                {
                    diagnostics.push(IrDiagnostic {
                        code: "bounded_opaque_system_call".to_owned(),
                        message: "the Linux x86-64 system-call instruction remains an explicit opaque environment transition, but its ABI register, flag, and unknown-memory footprint is bounded instead of consuming every machine register"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                    effects
                } else if let Some(effects) = bounded_atomic_opaque_effects(&instruction, control) {
                    diagnostics.push(IrDiagnostic {
                        code: "bounded_opaque_atomic".to_owned(),
                        message: "the atomic instruction remains an explicit opaque operation, but its register, flag, and read-modify-write memory footprint is bounded instead of consuming the full machine state"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                    effects
                } else if let Some(effects) = bounded_xsave_opaque_effects(&instruction, control) {
                    diagnostics.push(IrDiagnostic {
                        code: "bounded_opaque_extended_state_image".to_owned(),
                        message: "the XSAVE-family instruction remains opaque because its image size and component layout depend on XCR0/XSS, but its request-mask, address, extended-state, directional-memory, and exception effects are bounded without consuming unrelated general registers"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                    effects
                } else if let Some(effects) =
                    bounded_extended_data_opaque_effects(&instruction, control)
                {
                    diagnostics.push(IrDiagnostic {
                        code: "bounded_opaque_extended_data".to_owned(),
                        message: "the extended-register instruction remains opaque because floating-point environment or lane semantics are not fully modeled, but its explicit registers, memory access, and architectural environment footprint are bounded"
                            .to_owned(),
                        address: Some(location(address_space, ip)),
                        blocks_stable_operation: true,
                    });
                    effects
                } else {
                    opaque_effects(control)
                };
                (MachineOperation::OpaqueEffect { reason }, effects)
            }
        };
        if control == MachineControlEffect::IndirectCall && !indirect_resolved {
            diagnostics.push(IrDiagnostic {
                code: "unresolved_indirect_call_target".to_owned(),
                message: "the indirect CALL instruction and its fallthrough are modeled exactly, but the runtime target and callee summary remain unresolved"
                    .to_owned(),
                address: Some(location(address_space, ip)),
                blocks_stable_operation: true,
            });
        }
        if invalid
            || matches!(control, MachineControlEffect::Unknown)
            || (control == MachineControlEffect::IndirectBranch && !indirect_resolved)
        {
            structural = StructuralCompleteness::Partial;
        }
        let mut edges = instruction_edges(
            &instruction,
            invalid,
            address_space,
            address,
            end,
            stop_entries,
            indirect_targets.get(&ip).map(Vec::as_slice),
        );
        if matches!(
            instruction.mnemonic(),
            iced_x86::Mnemonic::Div | iced_x86::Mnemonic::Idiv
        ) || matches!(
            instruction.mnemonic(),
            iced_x86::Mnemonic::Ud2 | iced_x86::Mnemonic::Int3 | iced_x86::Mnemonic::Int
        ) || scalar_float_binary_width(instruction.mnemonic()).is_some()
            || packed_float_binary_lane_width(instruction.mnemonic()).is_some()
            || scalar_float_compare_width(instruction.mnemonic()).is_some()
            || scalar_float_sqrt_width(instruction.mnemonic()).is_some()
            || packed_float_sqrt_lane_width(instruction.mnemonic()).is_some()
            || scalar_float_precision_conversion(instruction.mnemonic()).is_some()
            || scalar_integer_float_conversion(instruction.mnemonic()).is_some()
            || packed_integer_float_conversion(instruction.mnemonic()).is_some()
            || packed_float_precision_conversion(instruction.mnemonic()).is_some()
            || x87_may_deliver_exception(instruction.mnemonic())
            || extended_state_may_deliver_exception(instruction.mnemonic())
            || environment_instruction_may_deliver_exception(instruction.mnemonic())
            || aligned_vector_memory_operation(&instruction)
        {
            edges.push(MachineEdge {
                kind: MachineEdgeKind::Exception,
                target: None,
            });
        }
        for edge in &edges {
            if let Some(target) = edge.target
                && target.address_space == address_space
                && (address..end).contains(&target.value.0)
                && !matches!(edge.kind, MachineEdgeKind::Call)
                && !stop_entries.contains(&target.value.0)
            {
                pending.push_back(target.value.0);
            }
        }
        instructions.insert(
            ip,
            MachineInstruction {
                address: location(address_space, ip),
                bytes_hex: raw.iter().map(|byte| format!("{byte:02x}")).collect(),
                mnemonic: if invalid {
                    "invalid".to_owned()
                } else {
                    format!("{:?}", instruction.mnemonic()).to_ascii_lowercase()
                },
                operands: machine_operands(&instruction, address_space),
                decorators: instruction_decorators(&instruction),
                operation,
                effects,
                edges,
            },
        );
    }

    let blocks = instructions
        .into_iter()
        .map(|(ip, instruction)| MachineBlock {
            label: label(ip),
            address: location(address_space, ip),
            instructions: vec![instruction],
        })
        .collect::<Vec<_>>();
    Ok(MachineFunctionIr {
        schema_version: MACHINE_FUNCTION_IR_VERSION,
        binary_sha256,
        function_id,
        name,
        entry: location(address_space, address),
        byte_length: code.len() as u64,
        blocks,
        structural_completeness: structural,
        semantic_fidelity: semantic,
        verification: VerificationStatus::NotRun,
        diagnostics,
    })
}

fn indirect_control_effects(
    instruction: &Instruction,
    control: MachineControlEffect,
) -> Option<MachineEffects> {
    let operands = machine_operands(instruction, 0);
    if operands.len() != 1
        || !matches!(
            operands[0],
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(&operands[0]);
    if control == MachineControlEffect::IndirectCall {
        read_registers.push("rsp".to_owned());
    }
    read_registers.sort();
    read_registers.dedup();
    let target_is_memory = matches!(operands[0], MachineOperand::Memory { .. });
    Some(MachineEffects {
        read_registers,
        written_registers: if control == MachineControlEffect::IndirectCall {
            vec!["rsp".to_owned()]
        } else {
            Vec::new()
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: match (control, target_is_memory) {
            (MachineControlEffect::IndirectCall, true) => MachineMemoryEffect::ReadWrite,
            (MachineControlEffect::IndirectCall, false) => MachineMemoryEffect::Write,
            (_, true) => MachineMemoryEffect::Read,
            (_, false) => MachineMemoryEffect::None,
        },
        control,
        conservative: false,
    })
}

fn supported_string_operation(instruction: &Instruction) -> bool {
    if instruction.segment_prefix() != Register::None
        || !matches!(instruction.memory_size().size(), 1 | 2 | 4 | 8)
        || !matches!(
            instruction.mnemonic(),
            iced_x86::Mnemonic::Movsb
                | iced_x86::Mnemonic::Movsw
                | iced_x86::Mnemonic::Movsd
                | iced_x86::Mnemonic::Movsq
                | iced_x86::Mnemonic::Stosb
                | iced_x86::Mnemonic::Stosw
                | iced_x86::Mnemonic::Stosd
                | iced_x86::Mnemonic::Stosq
                | iced_x86::Mnemonic::Cmpsb
                | iced_x86::Mnemonic::Cmpsw
                | iced_x86::Mnemonic::Cmpsd
                | iced_x86::Mnemonic::Cmpsq
                | iced_x86::Mnemonic::Scasb
                | iced_x86::Mnemonic::Scasw
                | iced_x86::Mnemonic::Scasd
                | iced_x86::Mnemonic::Scasq
        )
    {
        return false;
    }
    if instruction.has_repne_prefix()
        && !matches!(
            instruction.mnemonic(),
            iced_x86::Mnemonic::Cmpsb
                | iced_x86::Mnemonic::Cmpsw
                | iced_x86::Mnemonic::Cmpsd
                | iced_x86::Mnemonic::Cmpsq
                | iced_x86::Mnemonic::Scasb
                | iced_x86::Mnemonic::Scasw
                | iced_x86::Mnemonic::Scasd
                | iced_x86::Mnemonic::Scasq
        )
    {
        return false;
    }
    let source =
        (0..instruction.op_count()).any(|index| instruction.op_kind(index) == OpKind::MemorySegRSI);
    let destination =
        (0..instruction.op_count()).any(|index| instruction.op_kind(index) == OpKind::MemoryESRDI);
    match instruction.mnemonic() {
        iced_x86::Mnemonic::Movsb
        | iced_x86::Mnemonic::Movsw
        | iced_x86::Mnemonic::Movsd
        | iced_x86::Mnemonic::Movsq
        | iced_x86::Mnemonic::Cmpsb
        | iced_x86::Mnemonic::Cmpsw
        | iced_x86::Mnemonic::Cmpsd
        | iced_x86::Mnemonic::Cmpsq => source && destination,
        _ => destination,
    }
}

fn exact_operation_family(instruction: &Instruction) -> String {
    let family = format!("{:?}", instruction.mnemonic()).to_ascii_lowercase();
    if instruction.has_lock_prefix() {
        format!("lock_{family}")
    } else if instruction.mnemonic() == iced_x86::Mnemonic::Xchg
        && instruction.op0_kind() == OpKind::Memory
    {
        "atomic_xchg".to_owned()
    } else if supported_string_operation(instruction) && instruction.has_repne_prefix() {
        format!("repne_{family}")
    } else if supported_string_operation(instruction) && instruction.has_rep_prefix() {
        if matches!(
            instruction.mnemonic(),
            iced_x86::Mnemonic::Cmpsb
                | iced_x86::Mnemonic::Cmpsw
                | iced_x86::Mnemonic::Cmpsd
                | iced_x86::Mnemonic::Cmpsq
                | iced_x86::Mnemonic::Scasb
                | iced_x86::Mnemonic::Scasw
                | iced_x86::Mnemonic::Scasd
                | iced_x86::Mnemonic::Scasq
        ) {
            format!("repe_{family}")
        } else {
            format!("rep_{family}")
        }
    } else {
        family
    }
}

fn generic_string_effects(instruction: &Instruction) -> Option<MachineEffects> {
    if !supported_string_operation(instruction) {
        return None;
    }
    let repeated = instruction.has_rep_prefix() || instruction.has_repne_prefix();
    let move_string = matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Movsb
            | iced_x86::Mnemonic::Movsw
            | iced_x86::Mnemonic::Movsd
            | iced_x86::Mnemonic::Movsq
    );
    let compare_string = matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Cmpsb
            | iced_x86::Mnemonic::Cmpsw
            | iced_x86::Mnemonic::Cmpsd
            | iced_x86::Mnemonic::Cmpsq
            | iced_x86::Mnemonic::Scasb
            | iced_x86::Mnemonic::Scasw
            | iced_x86::Mnemonic::Scasd
            | iced_x86::Mnemonic::Scasq
    );
    let scan_string = matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Scasb
            | iced_x86::Mnemonic::Scasw
            | iced_x86::Mnemonic::Scasd
            | iced_x86::Mnemonic::Scasq
    );
    let mut read_registers = if move_string || (compare_string && !scan_string) {
        vec!["rsi".to_owned(), "rdi".to_owned()]
    } else {
        vec!["rax".to_owned(), "rdi".to_owned()]
    };
    let mut written_registers = if move_string || (compare_string && !scan_string) {
        vec!["rsi".to_owned(), "rdi".to_owned()]
    } else {
        vec!["rdi".to_owned()]
    };
    if repeated {
        read_registers.push("rcx".to_owned());
        written_registers.push("rcx".to_owned());
    }
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: vec!["df".to_owned()],
        written_flags: if compare_string {
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        } else {
            Vec::new()
        },
        undefined_flags: Vec::new(),
        memory: if move_string {
            MachineMemoryEffect::ReadWrite
        } else if compare_string {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::Write
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_exact_effects(instruction: &Instruction) -> Option<MachineEffects> {
    let mnemonic = instruction.mnemonic();
    if instruction.rounding_control() != RoundingControl::None
        || instruction.suppress_all_exceptions()
    {
        return None;
    }
    if mnemonic == iced_x86::Mnemonic::Vpcompressq
        && instruction.op_mask() != Register::None
        && !instruction.is_broadcast()
    {
        let operands = machine_operands(instruction, 0);
        let mask = format!("{:?}", instruction.op_mask()).to_ascii_lowercase();
        return generic_vector_compress_effects(&operands, &mask, instruction.zeroing_masking());
    }
    if matches!(
        mnemonic,
        iced_x86::Mnemonic::Vpxord | iced_x86::Mnemonic::Vpandq | iced_x86::Mnemonic::Vporq
    ) && instruction.op_mask() != Register::None
        && !instruction.is_broadcast()
    {
        let operands = machine_operands(instruction, 0);
        let mask = format!("{:?}", instruction.op_mask()).to_ascii_lowercase();
        return generic_masked_vector_write_effects(
            &operands,
            &mask,
            instruction.zeroing_masking(),
        );
    }
    if matches!(
        mnemonic,
        iced_x86::Mnemonic::Vmovdqu32
            | iced_x86::Mnemonic::Vmovdqu64
            | iced_x86::Mnemonic::Vmovdqa32
            | iced_x86::Mnemonic::Vmovdqa64
            | iced_x86::Mnemonic::Vmovups
            | iced_x86::Mnemonic::Vmovupd
            | iced_x86::Mnemonic::Vmovaps
            | iced_x86::Mnemonic::Vmovapd
    ) && instruction.op_mask() != Register::None
        && !instruction.is_broadcast()
    {
        let operands = machine_operands(instruction, 0);
        let mask = format!("{:?}", instruction.op_mask()).to_ascii_lowercase();
        return generic_masked_vector_move_effects(&operands, &mask, instruction.zeroing_masking());
    }
    if instruction.encoding() == EncodingKind::EVEX
        && (instruction.op_mask() != Register::None || instruction.is_broadcast())
        && let Some(lane_width) = packed_float_binary_lane_width(mnemonic)
    {
        let operands = machine_operands(instruction, 0);
        let mask = (instruction.op_mask() != Register::None)
            .then(|| format!("{:?}", instruction.op_mask()).to_ascii_lowercase());
        return generic_evex_packed_float_binary_effects(
            &operands,
            lane_width,
            mask.as_deref(),
            instruction.zeroing_masking(),
            instruction.is_broadcast(),
        );
    }
    if mnemonic == iced_x86::Mnemonic::Vpopcntb
        && instruction.op_mask() != Register::None
        && !instruction.is_broadcast()
    {
        let operands = machine_operands(instruction, 0);
        let mask = format!("{:?}", instruction.op_mask()).to_ascii_lowercase();
        return generic_masked_vector_unary_effects(
            &operands,
            &mask,
            instruction.zeroing_masking(),
        );
    }
    if mnemonic == iced_x86::Mnemonic::Vgf2p8affineqb
        && (instruction.op_mask() != Register::None || instruction.is_broadcast())
    {
        let operands = machine_operands(instruction, 0);
        let mask = (instruction.op_mask() != Register::None)
            .then(|| format!("{:?}", instruction.op_mask()).to_ascii_lowercase());
        return generic_evex_vector_affine_effects(
            &operands,
            mask.as_deref(),
            instruction.zeroing_masking(),
            instruction.is_broadcast(),
        );
    }
    if mnemonic == iced_x86::Mnemonic::Vpcmpuq
        && (instruction.op_mask() != Register::None || instruction.is_broadcast())
    {
        let operands = machine_operands(instruction, 0);
        let mask = (instruction.op_mask() != Register::None)
            .then(|| format!("{:?}", instruction.op_mask()).to_ascii_lowercase());
        return generic_evex_vector_mask_compare_effects(
            &operands,
            mask.as_deref(),
            instruction.zeroing_masking(),
            instruction.is_broadcast(),
        );
    }
    if matches!(
        mnemonic,
        iced_x86::Mnemonic::Vpermb | iced_x86::Mnemonic::Vpermi2b
    ) && instruction.op_mask() != Register::None
        && !instruction.is_broadcast()
    {
        let operands = machine_operands(instruction, 0);
        let mask = format!("{:?}", instruction.op_mask()).to_ascii_lowercase();
        return match mnemonic {
            iced_x86::Mnemonic::Vpermb => {
                generic_masked_vector_write_effects(&operands, &mask, instruction.zeroing_masking())
            }
            iced_x86::Mnemonic::Vpermi2b => {
                let mut effects = generic_vector_permute2_effects(&operands)?;
                effects.read_registers.push(mask);
                effects.read_registers.sort();
                effects.read_registers.dedup();
                Some(effects)
            }
            _ => None,
        };
    }
    // Masked/broadcast EVEX operations require opmask and merge/zero semantics
    // that remain explicit opaque effects. A narrow unmasked ZMM subset has a
    // complete low-YMM/high-ZMM state representation and may proceed below.
    if instruction.op_mask() != Register::None || instruction.is_broadcast() {
        return None;
    }
    if instruction.encoding() == EncodingKind::EVEX {
        let operands = machine_operands(instruction, 0);
        return match mnemonic {
            iced_x86::Mnemonic::Vpxord | iced_x86::Mnemonic::Vpandq | iced_x86::Mnemonic::Vporq => {
                generic_vector_bitwise_effects(&operands)
            }
            iced_x86::Mnemonic::Vpermb => generic_vector_bitwise_effects(&operands),
            iced_x86::Mnemonic::Vpermi2b => generic_vector_permute2_effects(&operands),
            iced_x86::Mnemonic::Vgf2p8affineqb => generic_vector_affine_effects(&operands),
            iced_x86::Mnemonic::Vpcmpuq => generic_vector_mask_compare_effects(&operands),
            iced_x86::Mnemonic::Vmovdqu32 | iced_x86::Mnemonic::Vmovdqu64 => {
                generic_vector_move_effects(&operands)
            }
            iced_x86::Mnemonic::Vmovdqa32 | iced_x86::Mnemonic::Vmovdqa64 => {
                generic_vector_move_effects(&operands)
            }
            iced_x86::Mnemonic::Vpopcntb => generic_vector_unary_effects(&operands),
            iced_x86::Mnemonic::Vaddps
            | iced_x86::Mnemonic::Vsubps
            | iced_x86::Mnemonic::Vmulps
            | iced_x86::Mnemonic::Vdivps
            | iced_x86::Mnemonic::Vaddpd
            | iced_x86::Mnemonic::Vsubpd
            | iced_x86::Mnemonic::Vmulpd
            | iced_x86::Mnemonic::Vdivpd => generic_packed_float_binary_effects(&operands, true),
            _ => None,
        };
    }
    if matches!(
        mnemonic,
        iced_x86::Mnemonic::Nop | iced_x86::Mnemonic::Pause | iced_x86::Mnemonic::Endbr64
    ) {
        return Some(MachineEffects {
            read_registers: Vec::new(),
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::None,
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    if matches!(mnemonic, iced_x86::Mnemonic::Ud2 | iced_x86::Mnemonic::Int3)
        && instruction.op_count() == 0
    {
        return Some(MachineEffects {
            read_registers: Vec::new(),
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::None,
            control: MachineControlEffect::Stop,
            conservative: false,
        });
    }
    if mnemonic == iced_x86::Mnemonic::Int
        && instruction.op_count() == 1
        && matches!(instruction.op_kind(0), OpKind::Immediate8)
    {
        return Some(MachineEffects {
            read_registers: Vec::new(),
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::None,
            control: MachineControlEffect::Stop,
            conservative: false,
        });
    }
    if matches!(
        mnemonic,
        iced_x86::Mnemonic::Lfence | iced_x86::Mnemonic::Sfence | iced_x86::Mnemonic::Mfence
    ) && instruction.op_count() == 0
    {
        return Some(MachineEffects {
            read_registers: Vec::new(),
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::Fence,
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    if matches!(
        mnemonic,
        iced_x86::Mnemonic::Pushfq | iced_x86::Mnemonic::Popfq
    ) && instruction.op_count() == 0
    {
        let push = mnemonic == iced_x86::Mnemonic::Pushfq;
        return Some(MachineEffects {
            read_registers: if push {
                vec!["rsp".to_owned(), "rflags_unmodeled".to_owned()]
            } else {
                vec!["rsp".to_owned()]
            },
            written_registers: if push {
                vec!["rsp".to_owned()]
            } else {
                vec!["rsp".to_owned(), "rflags_unmodeled".to_owned()]
            },
            read_flags: if push {
                MACHINE_FLAGS.into_iter().map(str::to_owned).collect()
            } else {
                Vec::new()
            },
            written_flags: if push {
                Vec::new()
            } else {
                MACHINE_FLAGS.into_iter().map(str::to_owned).collect()
            },
            undefined_flags: Vec::new(),
            memory: if push {
                MachineMemoryEffect::Write
            } else {
                MachineMemoryEffect::Read
            },
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    if matches!(mnemonic, iced_x86::Mnemonic::Jp | iced_x86::Mnemonic::Jnp)
        && instruction.flow_control() == FlowControl::ConditionalBranch
    {
        return Some(MachineEffects {
            read_registers: Vec::new(),
            written_registers: Vec::new(),
            read_flags: vec!["pf".to_owned()],
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::None,
            control: MachineControlEffect::ConditionalBranch,
            conservative: false,
        });
    }
    let operands = machine_operands(instruction, 0);
    if let Some(effects) = generic_atomic_effects(instruction, &operands) {
        return Some(effects);
    }
    if let Some(effects) = generic_extended_state_effects(instruction, &operands) {
        return Some(effects);
    }
    if let Some(effects) = generic_environment_instruction_effects(instruction, &operands) {
        return Some(effects);
    }
    if mnemonic == iced_x86::Mnemonic::Wait && operands.is_empty() {
        return Some(MachineEffects {
            read_registers: vec!["x87_control".to_owned(), "x87_status".to_owned()],
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::None,
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    if let Some(effects) = generic_x87_effects(instruction, &operands) {
        return Some(effects);
    }
    let string_transfer = supported_string_operation(instruction);
    if instruction.has_lock_prefix()
        || (instruction.has_rep_prefix()
            && !matches!(
                mnemonic,
                iced_x86::Mnemonic::Popcnt | iced_x86::Mnemonic::Lzcnt | iced_x86::Mnemonic::Tzcnt
            )
            && !string_transfer)
        || (instruction.has_repne_prefix() && !string_transfer)
        || instruction.flow_control() != FlowControl::Next
    {
        return None;
    }
    let family = format!("{:?}", instruction.mnemonic()).to_ascii_lowercase();
    if let Some(read_flags) = condition_read_flags(&family) {
        return conditional_data_effects(instruction, &family, read_flags);
    }
    match mnemonic {
        iced_x86::Mnemonic::Cld | iced_x86::Mnemonic::Std if operands.is_empty() => {
            return Some(MachineEffects {
                read_registers: Vec::new(),
                written_registers: Vec::new(),
                read_flags: Vec::new(),
                written_flags: vec!["df".to_owned()],
                undefined_flags: Vec::new(),
                memory: MachineMemoryEffect::None,
                control: MachineControlEffect::Next,
                conservative: false,
            });
        }
        _ if string_transfer => return generic_string_effects(instruction),
        iced_x86::Mnemonic::Vzeroupper | iced_x86::Mnemonic::Vzeroall if operands.is_empty() => {
            return Some(MachineEffects {
                read_registers: Vec::new(),
                written_registers: (0..16).map(|index| format!("ymm{index}")).collect(),
                read_flags: Vec::new(),
                written_flags: Vec::new(),
                undefined_flags: Vec::new(),
                memory: MachineMemoryEffect::None,
                control: MachineControlEffect::Next,
                conservative: false,
            });
        }
        iced_x86::Mnemonic::Movd | iced_x86::Mnemonic::Vmovd => {
            return generic_vector_scalar_move_effects(
                &operands,
                32,
                mnemonic == iced_x86::Mnemonic::Vmovd,
            );
        }
        iced_x86::Mnemonic::Movq | iced_x86::Mnemonic::Vmovq => {
            return generic_vector_scalar_move_effects(
                &operands,
                64,
                mnemonic == iced_x86::Mnemonic::Vmovq,
            );
        }
        iced_x86::Mnemonic::Movss | iced_x86::Mnemonic::Vmovss => {
            return generic_scalar_float_move_effects(
                &operands,
                32,
                mnemonic == iced_x86::Mnemonic::Vmovss,
            );
        }
        iced_x86::Mnemonic::Movsd | iced_x86::Mnemonic::Vmovsd if !string_transfer => {
            return generic_scalar_float_move_effects(
                &operands,
                64,
                mnemonic == iced_x86::Mnemonic::Vmovsd,
            );
        }
        _ if scalar_float_binary_width(mnemonic).is_some() => {
            return generic_scalar_float_binary_effects(
                &operands,
                scalar_float_binary_width(mnemonic).expect("matched scalar floating operation"),
                matches!(
                    mnemonic,
                    iced_x86::Mnemonic::Vaddss
                        | iced_x86::Mnemonic::Vaddsd
                        | iced_x86::Mnemonic::Vsubss
                        | iced_x86::Mnemonic::Vsubsd
                        | iced_x86::Mnemonic::Vmulss
                        | iced_x86::Mnemonic::Vmulsd
                        | iced_x86::Mnemonic::Vdivss
                        | iced_x86::Mnemonic::Vdivsd
                ),
            );
        }
        _ if packed_float_binary_lane_width(mnemonic).is_some() => {
            return generic_packed_float_binary_effects(
                &operands,
                matches!(
                    mnemonic,
                    iced_x86::Mnemonic::Vaddps
                        | iced_x86::Mnemonic::Vaddpd
                        | iced_x86::Mnemonic::Vsubps
                        | iced_x86::Mnemonic::Vsubpd
                        | iced_x86::Mnemonic::Vmulps
                        | iced_x86::Mnemonic::Vmulpd
                        | iced_x86::Mnemonic::Vdivps
                        | iced_x86::Mnemonic::Vdivpd
                ),
            );
        }
        _ if scalar_float_compare_width(mnemonic).is_some() => {
            return generic_scalar_float_compare_effects(
                &operands,
                scalar_float_compare_width(mnemonic).expect("matched scalar floating comparison"),
            );
        }
        _ if scalar_float_sqrt_width(mnemonic).is_some() => {
            return generic_scalar_float_sqrt_effects(
                &operands,
                scalar_float_sqrt_width(mnemonic).expect("matched scalar floating square root"),
                matches!(
                    mnemonic,
                    iced_x86::Mnemonic::Vsqrtss | iced_x86::Mnemonic::Vsqrtsd
                ),
            );
        }
        _ if packed_float_sqrt_lane_width(mnemonic).is_some() => {
            return generic_packed_float_sqrt_effects(
                &operands,
                matches!(
                    mnemonic,
                    iced_x86::Mnemonic::Vsqrtps | iced_x86::Mnemonic::Vsqrtpd
                ),
            );
        }
        _ if scalar_float_precision_conversion(mnemonic).is_some() => {
            let (source_width, destination_width, vex_encoded) =
                scalar_float_precision_conversion(mnemonic)
                    .expect("matched scalar floating precision conversion");
            return generic_scalar_float_conversion_effects(
                &operands,
                source_width,
                destination_width,
                vex_encoded,
            );
        }
        _ if scalar_integer_float_conversion(mnemonic).is_some() => {
            return generic_scalar_integer_float_conversion_effects(
                &operands,
                scalar_integer_float_conversion(mnemonic)
                    .expect("matched scalar integer/floating conversion"),
            );
        }
        _ if packed_integer_float_conversion(mnemonic).is_some() => {
            return generic_packed_integer_float_conversion_effects(&operands);
        }
        _ if packed_float_precision_conversion(mnemonic).is_some() => {
            return generic_packed_float_precision_conversion_effects(
                &operands,
                packed_float_precision_conversion(mnemonic)
                    .expect("matched packed floating precision conversion"),
            );
        }
        iced_x86::Mnemonic::Movups
        | iced_x86::Mnemonic::Movupd
        | iced_x86::Mnemonic::Movdqu
        | iced_x86::Mnemonic::Vmovups
        | iced_x86::Mnemonic::Vmovupd
        | iced_x86::Mnemonic::Vmovdqu => return generic_vector_move_effects(&operands),
        iced_x86::Mnemonic::Movaps
        | iced_x86::Mnemonic::Movapd
        | iced_x86::Mnemonic::Movdqa
        | iced_x86::Mnemonic::Vmovaps
        | iced_x86::Mnemonic::Vmovapd
        | iced_x86::Mnemonic::Vmovdqa => return generic_vector_move_effects(&operands),
        iced_x86::Mnemonic::Pxor
        | iced_x86::Mnemonic::Xorps
        | iced_x86::Mnemonic::Xorpd
        | iced_x86::Mnemonic::Pand
        | iced_x86::Mnemonic::Pandn
        | iced_x86::Mnemonic::Por
        | iced_x86::Mnemonic::Andps
        | iced_x86::Mnemonic::Andpd
        | iced_x86::Mnemonic::Andnps
        | iced_x86::Mnemonic::Andnpd
        | iced_x86::Mnemonic::Orps
        | iced_x86::Mnemonic::Orpd
        | iced_x86::Mnemonic::Vpxor
        | iced_x86::Mnemonic::Vxorps
        | iced_x86::Mnemonic::Vxorpd
        | iced_x86::Mnemonic::Vpand
        | iced_x86::Mnemonic::Vpandn
        | iced_x86::Mnemonic::Vpor
        | iced_x86::Mnemonic::Vandps
        | iced_x86::Mnemonic::Vandpd
        | iced_x86::Mnemonic::Vandnps
        | iced_x86::Mnemonic::Vandnpd
        | iced_x86::Mnemonic::Vorps
        | iced_x86::Mnemonic::Vorpd => return generic_vector_bitwise_effects(&operands),
        iced_x86::Mnemonic::Paddb
        | iced_x86::Mnemonic::Paddw
        | iced_x86::Mnemonic::Paddd
        | iced_x86::Mnemonic::Paddq
        | iced_x86::Mnemonic::Psubb
        | iced_x86::Mnemonic::Psubw
        | iced_x86::Mnemonic::Psubd
        | iced_x86::Mnemonic::Psubq
        | iced_x86::Mnemonic::Paddsb
        | iced_x86::Mnemonic::Paddsw
        | iced_x86::Mnemonic::Paddusb
        | iced_x86::Mnemonic::Paddusw
        | iced_x86::Mnemonic::Psubsb
        | iced_x86::Mnemonic::Psubsw
        | iced_x86::Mnemonic::Psubusb
        | iced_x86::Mnemonic::Psubusw
        | iced_x86::Mnemonic::Pmullw
        | iced_x86::Mnemonic::Pmulld
        | iced_x86::Mnemonic::Pmuludq
        | iced_x86::Mnemonic::Pcmpeqb
        | iced_x86::Mnemonic::Pcmpeqw
        | iced_x86::Mnemonic::Pcmpeqd
        | iced_x86::Mnemonic::Pcmpeqq
        | iced_x86::Mnemonic::Pcmpgtb
        | iced_x86::Mnemonic::Pcmpgtw
        | iced_x86::Mnemonic::Pcmpgtd
        | iced_x86::Mnemonic::Pcmpgtq
        | iced_x86::Mnemonic::Pminub
        | iced_x86::Mnemonic::Pminuw
        | iced_x86::Mnemonic::Pminud
        | iced_x86::Mnemonic::Pminsw
        | iced_x86::Mnemonic::Pminsd
        | iced_x86::Mnemonic::Pmaxub
        | iced_x86::Mnemonic::Pmaxuw
        | iced_x86::Mnemonic::Pmaxud
        | iced_x86::Mnemonic::Pmaxsw
        | iced_x86::Mnemonic::Pmaxsd
        | iced_x86::Mnemonic::Vpaddb
        | iced_x86::Mnemonic::Vpaddw
        | iced_x86::Mnemonic::Vpaddd
        | iced_x86::Mnemonic::Vpaddq
        | iced_x86::Mnemonic::Vpsubb
        | iced_x86::Mnemonic::Vpsubw
        | iced_x86::Mnemonic::Vpsubd
        | iced_x86::Mnemonic::Vpsubq
        | iced_x86::Mnemonic::Vpaddsb
        | iced_x86::Mnemonic::Vpaddsw
        | iced_x86::Mnemonic::Vpaddusb
        | iced_x86::Mnemonic::Vpaddusw
        | iced_x86::Mnemonic::Vpsubsb
        | iced_x86::Mnemonic::Vpsubsw
        | iced_x86::Mnemonic::Vpsubusb
        | iced_x86::Mnemonic::Vpsubusw
        | iced_x86::Mnemonic::Vpmullw
        | iced_x86::Mnemonic::Vpmulld
        | iced_x86::Mnemonic::Vpmuludq
        | iced_x86::Mnemonic::Vpcmpeqb
        | iced_x86::Mnemonic::Vpcmpeqw
        | iced_x86::Mnemonic::Vpcmpeqd
        | iced_x86::Mnemonic::Vpcmpeqq
        | iced_x86::Mnemonic::Vpcmpgtb
        | iced_x86::Mnemonic::Vpcmpgtw
        | iced_x86::Mnemonic::Vpcmpgtd
        | iced_x86::Mnemonic::Vpcmpgtq
        | iced_x86::Mnemonic::Vpminub
        | iced_x86::Mnemonic::Vpminuw
        | iced_x86::Mnemonic::Vpminud
        | iced_x86::Mnemonic::Vpminsw
        | iced_x86::Mnemonic::Vpminsd
        | iced_x86::Mnemonic::Vpmaxub
        | iced_x86::Mnemonic::Vpmaxuw
        | iced_x86::Mnemonic::Vpmaxud
        | iced_x86::Mnemonic::Vpmaxsw
        | iced_x86::Mnemonic::Vpmaxsd
        | iced_x86::Mnemonic::Punpcklbw
        | iced_x86::Mnemonic::Punpcklwd
        | iced_x86::Mnemonic::Punpckldq
        | iced_x86::Mnemonic::Punpcklqdq
        | iced_x86::Mnemonic::Punpckhbw
        | iced_x86::Mnemonic::Punpckhwd
        | iced_x86::Mnemonic::Punpckhdq
        | iced_x86::Mnemonic::Punpckhqdq
        | iced_x86::Mnemonic::Vpunpcklbw
        | iced_x86::Mnemonic::Vpunpcklwd
        | iced_x86::Mnemonic::Vpunpckldq
        | iced_x86::Mnemonic::Vpunpcklqdq
        | iced_x86::Mnemonic::Vpunpckhbw
        | iced_x86::Mnemonic::Vpunpckhwd
        | iced_x86::Mnemonic::Vpunpckhdq
        | iced_x86::Mnemonic::Vpunpckhqdq
        | iced_x86::Mnemonic::Pshufb
        | iced_x86::Mnemonic::Vpshufb => return generic_vector_bitwise_effects(&operands),
        iced_x86::Mnemonic::Packsswb
        | iced_x86::Mnemonic::Packssdw
        | iced_x86::Mnemonic::Packuswb
        | iced_x86::Mnemonic::Packusdw
        | iced_x86::Mnemonic::Vpacksswb
        | iced_x86::Mnemonic::Vpackssdw
        | iced_x86::Mnemonic::Vpackuswb
        | iced_x86::Mnemonic::Vpackusdw => return generic_vector_bitwise_effects(&operands),
        iced_x86::Mnemonic::Psllw
        | iced_x86::Mnemonic::Pslld
        | iced_x86::Mnemonic::Psllq
        | iced_x86::Mnemonic::Psrlw
        | iced_x86::Mnemonic::Psrld
        | iced_x86::Mnemonic::Psrlq
        | iced_x86::Mnemonic::Psraw
        | iced_x86::Mnemonic::Psrad
        | iced_x86::Mnemonic::Vpsllw
        | iced_x86::Mnemonic::Vpslld
        | iced_x86::Mnemonic::Vpsllq
        | iced_x86::Mnemonic::Vpsrlw
        | iced_x86::Mnemonic::Vpsrld
        | iced_x86::Mnemonic::Vpsrlq
        | iced_x86::Mnemonic::Vpsraw
        | iced_x86::Mnemonic::Vpsrad
        | iced_x86::Mnemonic::Pshufd
        | iced_x86::Mnemonic::Vpshufd
        | iced_x86::Mnemonic::Pshuflw
        | iced_x86::Mnemonic::Pshufhw
        | iced_x86::Mnemonic::Vpshuflw
        | iced_x86::Mnemonic::Vpshufhw => {
            return generic_vector_immediate_effects(&operands);
        }
        iced_x86::Mnemonic::Vpbroadcastb
        | iced_x86::Mnemonic::Vpbroadcastq
        | iced_x86::Mnemonic::Vbroadcastss => {
            return generic_vector_broadcast_effects(&operands);
        }
        iced_x86::Mnemonic::Vextracti128 => {
            return generic_vector_extract_effects(&operands);
        }
        iced_x86::Mnemonic::Vinserti128 => {
            return generic_vector_insert_effects(&operands);
        }
        iced_x86::Mnemonic::Aesenc => return generic_aesenc_effects(&operands),
        iced_x86::Mnemonic::Pinsrw | iced_x86::Mnemonic::Pinsrd | iced_x86::Mnemonic::Pinsrq => {
            return generic_vector_insert_scalar_effects(&operands);
        }
        iced_x86::Mnemonic::Vmovntdq => {
            return generic_vector_non_temporal_store_effects(&operands);
        }
        iced_x86::Mnemonic::Ptest | iced_x86::Mnemonic::Vptest => {
            return generic_vector_test_effects(&operands);
        }
        iced_x86::Mnemonic::Pmovmskb | iced_x86::Mnemonic::Vpmovmskb => {
            return generic_vector_byte_mask_effects(&operands);
        }
        iced_x86::Mnemonic::Kmovb
        | iced_x86::Mnemonic::Kmovw
        | iced_x86::Mnemonic::Kmovd
        | iced_x86::Mnemonic::Kmovq => return generic_opmask_move_effects(&operands, mnemonic),
        iced_x86::Mnemonic::Prefetchnta
        | iced_x86::Mnemonic::Prefetcht0
        | iced_x86::Mnemonic::Prefetcht1
        | iced_x86::Mnemonic::Prefetcht2
        | iced_x86::Mnemonic::Prefetchw
        | iced_x86::Mnemonic::Prefetchwt1 => return generic_prefetch_effects(&operands),
        _ => {}
    }
    for index in 0..instruction.op_count() {
        if instruction.op_kind(index) == OpKind::Register
            && !supported_gpr(instruction.op_register(index))
        {
            return None;
        }
    }
    match mnemonic {
        iced_x86::Mnemonic::Add
        | iced_x86::Mnemonic::Sub
        | iced_x86::Mnemonic::And
        | iced_x86::Mnemonic::Or
        | iced_x86::Mnemonic::Xor => return generic_binary_effects(&operands, mnemonic),
        iced_x86::Mnemonic::Adc | iced_x86::Mnemonic::Sbb => {
            return generic_binary_with_carry_effects(&operands, mnemonic);
        }
        iced_x86::Mnemonic::Andn => return generic_andn_effects(&operands),
        iced_x86::Mnemonic::Cmp | iced_x86::Mnemonic::Test => {
            return generic_compare_effects(&operands, mnemonic);
        }
        iced_x86::Mnemonic::Inc | iced_x86::Mnemonic::Dec => {
            return generic_unary_effects(&operands, &["zf", "sf", "of", "pf", "af"]);
        }
        iced_x86::Mnemonic::Neg => {
            return generic_unary_effects(&operands, &ALL_FLAGS);
        }
        iced_x86::Mnemonic::Not => return generic_unary_effects(&operands, &[]),
        iced_x86::Mnemonic::Shl | iced_x86::Mnemonic::Shr | iced_x86::Mnemonic::Sar => {
            return generic_shift_effects(&operands);
        }
        iced_x86::Mnemonic::Shld | iced_x86::Mnemonic::Shrd => {
            return generic_double_shift_effects(&operands);
        }
        iced_x86::Mnemonic::Shlx | iced_x86::Mnemonic::Shrx | iced_x86::Mnemonic::Sarx => {
            return generic_flagless_shift_effects(&operands, false);
        }
        iced_x86::Mnemonic::Rorx => {
            return generic_flagless_shift_effects(&operands, true);
        }
        iced_x86::Mnemonic::Pdep | iced_x86::Mnemonic::Pext => {
            return generic_bmi2_permutation_effects(&operands);
        }
        iced_x86::Mnemonic::Rol | iced_x86::Mnemonic::Ror => {
            return generic_rotate_effects(&operands);
        }
        iced_x86::Mnemonic::Rcl | iced_x86::Mnemonic::Rcr => {
            return generic_rotate_through_carry_effects(&operands);
        }
        iced_x86::Mnemonic::Xchg => return generic_register_exchange_effects(&operands),
        iced_x86::Mnemonic::Bswap => return generic_bswap_effects(&operands),
        iced_x86::Mnemonic::Bsf | iced_x86::Mnemonic::Bsr => {
            return generic_bit_scan_effects(&operands);
        }
        iced_x86::Mnemonic::Bt
        | iced_x86::Mnemonic::Btc
        | iced_x86::Mnemonic::Btr
        | iced_x86::Mnemonic::Bts => {
            return generic_register_bit_test_effects(&operands, mnemonic);
        }
        iced_x86::Mnemonic::Popcnt => return generic_bit_count_effects(&operands, false),
        iced_x86::Mnemonic::Lzcnt | iced_x86::Mnemonic::Tzcnt => {
            return generic_bit_count_effects(&operands, true);
        }
        iced_x86::Mnemonic::Imul if operands.len() == 1 => {
            return generic_full_multiply_effects(&operands);
        }
        iced_x86::Mnemonic::Imul => return generic_imul_effects(&operands),
        iced_x86::Mnemonic::Mul => return generic_full_multiply_effects(&operands),
        iced_x86::Mnemonic::Div | iced_x86::Mnemonic::Idiv => {
            return generic_divide_effects(&operands);
        }
        iced_x86::Mnemonic::Cbw
        | iced_x86::Mnemonic::Cwde
        | iced_x86::Mnemonic::Cdqe
        | iced_x86::Mnemonic::Cwd
        | iced_x86::Mnemonic::Cdq
        | iced_x86::Mnemonic::Cqo => return accumulator_sign_extension_effects(mnemonic),
        iced_x86::Mnemonic::Push => return generic_push_effects(&operands),
        iced_x86::Mnemonic::Pop => return generic_pop_effects(&operands),
        iced_x86::Mnemonic::Lea => return generic_lea_effects(&operands),
        iced_x86::Mnemonic::Mov
        | iced_x86::Mnemonic::Movzx
        | iced_x86::Mnemonic::Movsx
        | iced_x86::Mnemonic::Movsxd => {}
        _ => return None,
    }
    if instruction.op_count() != 2 {
        return None;
    }
    let [destination, source] = operands.as_slice() else {
        return None;
    };
    let destination_width = operand_scalar_width(destination)?;
    let source_width = operand_scalar_width(source)?;
    if !matches!(destination_width, 8 | 16 | 32 | 64)
        || !matches!(source_width, 8 | 16 | 32 | 64)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(
            source,
            MachineOperand::Branch { .. } | MachineOperand::RelocatedBranch { .. }
        )
        || (mnemonic == iced_x86::Mnemonic::Mov && destination_width != source_width)
        || (matches!(
            mnemonic,
            iced_x86::Mnemonic::Movzx | iced_x86::Mnemonic::Movsx | iced_x86::Mnemonic::Movsxd
        ) && (destination_width <= source_width
            || !matches!(destination, MachineOperand::Register { .. })))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    if let MachineOperand::Register { name, width_bits } = destination
        && matches!(width_bits, 8 | 16)
    {
        read_registers.push(name.clone());
    }
    read_registers.sort();
    read_registers.dedup();
    let written_registers = match destination {
        MachineOperand::Register { name, .. } => vec![name.clone()],
        _ => Vec::new(),
    };
    let memory = match (destination, source) {
        (MachineOperand::Memory { .. }, _) => MachineMemoryEffect::Write,
        (_, MachineOperand::Memory { .. }) => MachineMemoryEffect::Read,
        _ => MachineMemoryEffect::None,
    };
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_atomic_effects(
    instruction: &Instruction,
    operands: &[MachineOperand],
) -> Option<MachineEffects> {
    let mnemonic = instruction.mnemonic();
    let implicit_exchange_lock = mnemonic == iced_x86::Mnemonic::Xchg
        && matches!(operands.first(), Some(MachineOperand::Memory { .. }));
    let wide_compare_exchange = matches!(
        mnemonic,
        iced_x86::Mnemonic::Cmpxchg8b | iced_x86::Mnemonic::Cmpxchg16b
    );
    if !instruction.has_lock_prefix() && !implicit_exchange_lock && !wide_compare_exchange {
        return None;
    }
    if wide_compare_exchange {
        let [destination @ MachineOperand::Memory { .. }] = operands else {
            return None;
        };
        let width = operand_scalar_width(destination)?;
        if !matches!(
            (mnemonic, width),
            (iced_x86::Mnemonic::Cmpxchg8b, 64) | (iced_x86::Mnemonic::Cmpxchg16b, 128)
        ) {
            return None;
        }
        let mut read_registers = operand_address_registers(destination);
        read_registers.extend(["rax", "rdx", "rbx", "rcx"].into_iter().map(str::to_owned));
        read_registers.sort();
        read_registers.dedup();
        return Some(MachineEffects {
            read_registers,
            written_registers: vec!["rax".to_owned(), "rdx".to_owned()],
            read_flags: Vec::new(),
            written_flags: vec!["zf".to_owned()],
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::ReadWrite,
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    if let [destination @ MachineOperand::Memory { .. }] = operands {
        let width = operand_scalar_width(destination)?;
        if !instruction.has_lock_prefix() || !matches!(width, 8 | 16 | 32 | 64) {
            return None;
        }
        let (written_flags, undefined_flags) = match mnemonic {
            iced_x86::Mnemonic::Inc | iced_x86::Mnemonic::Dec => (
                ["zf", "sf", "of", "pf", "af"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                Vec::new(),
            ),
            iced_x86::Mnemonic::Neg => (
                ALL_FLAGS.into_iter().map(str::to_owned).collect(),
                Vec::new(),
            ),
            iced_x86::Mnemonic::Not => (Vec::new(), Vec::new()),
            _ => return None,
        };
        return Some(MachineEffects {
            read_registers: operand_address_registers(destination),
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags,
            undefined_flags,
            memory: MachineMemoryEffect::ReadWrite,
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    let (destination, source) = match operands {
        [destination @ MachineOperand::Memory { .. }, source] => (destination, source),
        _ => return None,
    };
    let width = operand_scalar_width(destination)?;
    let bit_modify = matches!(
        mnemonic,
        iced_x86::Mnemonic::Btc | iced_x86::Mnemonic::Btr | iced_x86::Mnemonic::Bts
    );
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Immediate { .. }
        )
        || (!bit_modify && operand_scalar_width(source) != Some(width))
        || (bit_modify && !matches!(width, 16 | 32 | 64))
        || (bit_modify
            && matches!(source, MachineOperand::Register { .. })
            && operand_scalar_width(source) != Some(width))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    let mut written_registers = Vec::new();
    let (written_flags, undefined_flags) = match mnemonic {
        iced_x86::Mnemonic::Xadd if matches!(source, MachineOperand::Register { .. }) => {
            let MachineOperand::Register { name, .. } = source else {
                unreachable!("atomic XADD source was checked as a register")
            };
            written_registers.push(name.clone());
            (
                ALL_FLAGS.into_iter().map(str::to_owned).collect(),
                Vec::new(),
            )
        }
        iced_x86::Mnemonic::Cmpxchg if matches!(source, MachineOperand::Register { .. }) => {
            read_registers.push("rax".to_owned());
            written_registers.push("rax".to_owned());
            (
                ALL_FLAGS.into_iter().map(str::to_owned).collect(),
                Vec::new(),
            )
        }
        iced_x86::Mnemonic::Xchg if implicit_exchange_lock => {
            let MachineOperand::Register { name, .. } = source else {
                return None;
            };
            written_registers.push(name.clone());
            (Vec::new(), Vec::new())
        }
        iced_x86::Mnemonic::Add | iced_x86::Mnemonic::Sub => (
            ALL_FLAGS.into_iter().map(str::to_owned).collect(),
            Vec::new(),
        ),
        iced_x86::Mnemonic::Adc | iced_x86::Mnemonic::Sbb => (
            ALL_FLAGS.into_iter().map(str::to_owned).collect(),
            Vec::new(),
        ),
        iced_x86::Mnemonic::And | iced_x86::Mnemonic::Or | iced_x86::Mnemonic::Xor => (
            ["zf", "sf", "of", "cf", "pf"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            vec!["af".to_owned()],
        ),
        iced_x86::Mnemonic::Btc | iced_x86::Mnemonic::Btr | iced_x86::Mnemonic::Bts => {
            (vec!["cf".to_owned()], Vec::new())
        }
        _ => return None,
    };
    read_registers.sort();
    read_registers.dedup();
    written_registers.sort();
    written_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: if matches!(mnemonic, iced_x86::Mnemonic::Adc | iced_x86::Mnemonic::Sbb) {
            vec!["cf".to_owned()]
        } else {
            Vec::new()
        },
        written_flags,
        undefined_flags,
        memory: MachineMemoryEffect::ReadWrite,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn supported_x87_operation(mnemonic: iced_x86::Mnemonic) -> bool {
    use iced_x86::Mnemonic;
    matches!(
        mnemonic,
        Mnemonic::Fabs
            | Mnemonic::Fadd
            | Mnemonic::Faddp
            | Mnemonic::Fbld
            | Mnemonic::Fbstp
            | Mnemonic::Fchs
            | Mnemonic::Fclex
            | Mnemonic::Fcmovb
            | Mnemonic::Fcmovbe
            | Mnemonic::Fcmove
            | Mnemonic::Fcmovnb
            | Mnemonic::Fcmovnbe
            | Mnemonic::Fcmovne
            | Mnemonic::Fcmovnu
            | Mnemonic::Fcmovu
            | Mnemonic::Fcom
            | Mnemonic::Fcomi
            | Mnemonic::Fcomip
            | Mnemonic::Fcomp
            | Mnemonic::Fcompp
            | Mnemonic::Fcos
            | Mnemonic::Fdecstp
            | Mnemonic::Fdiv
            | Mnemonic::Fdivp
            | Mnemonic::Fdivr
            | Mnemonic::Fdivrp
            | Mnemonic::Ffree
            | Mnemonic::Ffreep
            | Mnemonic::Fiadd
            | Mnemonic::Ficom
            | Mnemonic::Ficomp
            | Mnemonic::Fidiv
            | Mnemonic::Fidivr
            | Mnemonic::Fild
            | Mnemonic::Fimul
            | Mnemonic::Fincstp
            | Mnemonic::Finit
            | Mnemonic::Fist
            | Mnemonic::Fistp
            | Mnemonic::Fisttp
            | Mnemonic::Fisub
            | Mnemonic::Fisubr
            | Mnemonic::Fld
            | Mnemonic::Fld1
            | Mnemonic::Fldcw
            | Mnemonic::Fldenv
            | Mnemonic::Fldl2e
            | Mnemonic::Fldl2t
            | Mnemonic::Fldlg2
            | Mnemonic::Fldln2
            | Mnemonic::Fldpi
            | Mnemonic::Fldz
            | Mnemonic::Fmul
            | Mnemonic::Fmulp
            | Mnemonic::Fnsave
            | Mnemonic::Fnclex
            | Mnemonic::Fninit
            | Mnemonic::Fnop
            | Mnemonic::Fnstcw
            | Mnemonic::Fnstenv
            | Mnemonic::Fnstsw
            | Mnemonic::Fpatan
            | Mnemonic::Fprem
            | Mnemonic::Fprem1
            | Mnemonic::Fptan
            | Mnemonic::Frndint
            | Mnemonic::Frstor
            | Mnemonic::Fsave
            | Mnemonic::Fscale
            | Mnemonic::Fsin
            | Mnemonic::Fsincos
            | Mnemonic::Fsqrt
            | Mnemonic::Fst
            | Mnemonic::Fstcw
            | Mnemonic::Fstenv
            | Mnemonic::Fstp
            | Mnemonic::Fstsw
            | Mnemonic::Fsub
            | Mnemonic::Fsubp
            | Mnemonic::Fsubr
            | Mnemonic::Fsubrp
            | Mnemonic::Ftst
            | Mnemonic::Fucom
            | Mnemonic::Fucomi
            | Mnemonic::Fucomip
            | Mnemonic::Fucomp
            | Mnemonic::Fucompp
            | Mnemonic::Fxam
            | Mnemonic::Fxch
            | Mnemonic::Fxtract
            | Mnemonic::Fyl2x
            | Mnemonic::Fyl2xp1
    )
}

fn extended_state_may_deliver_exception(mnemonic: iced_x86::Mnemonic) -> bool {
    matches!(
        mnemonic,
        iced_x86::Mnemonic::Fxsave
            | iced_x86::Mnemonic::Fxsave64
            | iced_x86::Mnemonic::Fxrstor
            | iced_x86::Mnemonic::Fxrstor64
            | iced_x86::Mnemonic::Ldmxcsr
            | iced_x86::Mnemonic::Stmxcsr
    ) || is_xsave_instruction(mnemonic)
}

fn supported_environment_instruction(mnemonic: iced_x86::Mnemonic) -> bool {
    matches!(
        mnemonic,
        iced_x86::Mnemonic::Cpuid
            | iced_x86::Mnemonic::Rdtsc
            | iced_x86::Mnemonic::Rdtscp
            | iced_x86::Mnemonic::Xgetbv
            | iced_x86::Mnemonic::Rdrand
            | iced_x86::Mnemonic::Rdseed
    )
}

fn environment_instruction_may_deliver_exception(mnemonic: iced_x86::Mnemonic) -> bool {
    supported_environment_instruction(mnemonic) && mnemonic != iced_x86::Mnemonic::Cpuid
}

fn generic_environment_instruction_effects(
    instruction: &Instruction,
    operands: &[MachineOperand],
) -> Option<MachineEffects> {
    use iced_x86::Mnemonic;
    let mnemonic = instruction.mnemonic();
    let (read_registers, written_registers, written_flags) = match mnemonic {
        Mnemonic::Cpuid if operands.is_empty() => (
            vec!["rax".to_owned(), "rcx".to_owned()],
            vec![
                "rax".to_owned(),
                "rbx".to_owned(),
                "rcx".to_owned(),
                "rdx".to_owned(),
            ],
            Vec::new(),
        ),
        Mnemonic::Rdtsc if operands.is_empty() => (
            Vec::new(),
            vec!["rax".to_owned(), "rdx".to_owned()],
            Vec::new(),
        ),
        Mnemonic::Rdtscp if operands.is_empty() => (
            Vec::new(),
            vec!["rax".to_owned(), "rcx".to_owned(), "rdx".to_owned()],
            Vec::new(),
        ),
        Mnemonic::Xgetbv if operands.is_empty() => (
            vec!["rcx".to_owned()],
            vec!["rax".to_owned(), "rdx".to_owned()],
            Vec::new(),
        ),
        Mnemonic::Rdrand | Mnemonic::Rdseed => {
            let [MachineOperand::Register { name, width_bits }] = operands else {
                return None;
            };
            if !matches!(width_bits, 16 | 32 | 64) {
                return None;
            }
            (
                Vec::new(),
                vec![name.clone()],
                ALL_FLAGS.into_iter().map(str::to_owned).collect(),
            )
        }
        _ => return None,
    };
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags,
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_extended_state_effects(
    instruction: &Instruction,
    operands: &[MachineOperand],
) -> Option<MachineEffects> {
    use iced_x86::Mnemonic;
    let [memory @ MachineOperand::Memory { width_bits, .. }] = operands else {
        return None;
    };
    let mnemonic = instruction.mnemonic();
    let save = matches!(mnemonic, Mnemonic::Fxsave | Mnemonic::Fxsave64);
    let restore = matches!(mnemonic, Mnemonic::Fxrstor | Mnemonic::Fxrstor64);
    let store_mxcsr = mnemonic == Mnemonic::Stmxcsr;
    let load_mxcsr = mnemonic == Mnemonic::Ldmxcsr;
    if !((save || restore) && *width_bits == 4096
        || (store_mxcsr || load_mxcsr) && *width_bits == 32)
    {
        return None;
    }
    let x87_state = || {
        (0..8)
            .map(|index| format!("st{index}"))
            .chain(
                [
                    "x87_control",
                    "x87_status",
                    "x87_tag",
                    "x87_instruction_pointer",
                    "x87_data_pointer",
                    "x87_opcode",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .collect::<Vec<_>>()
    };
    let vector_state = || {
        (0..16)
            .map(|index| format!("ymm{index}"))
            .collect::<Vec<_>>()
    };
    let mut read_registers = operand_address_registers(memory);
    let mut written_registers = Vec::new();
    if save {
        read_registers.extend(x87_state());
        read_registers.extend(vector_state());
        read_registers.extend(["mxcsr".to_owned(), "mxcsr_mask".to_owned()]);
    } else if restore {
        written_registers.extend(x87_state());
        written_registers.extend(vector_state());
        written_registers.push("mxcsr".to_owned());
    } else if store_mxcsr {
        read_registers.push("mxcsr".to_owned());
    } else {
        written_registers.push("mxcsr".to_owned());
    }
    read_registers.sort();
    read_registers.dedup();
    written_registers.sort();
    written_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if save || store_mxcsr {
            MachineMemoryEffect::Write
        } else {
            MachineMemoryEffect::Read
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn x87_may_deliver_exception(mnemonic: iced_x86::Mnemonic) -> bool {
    mnemonic == iced_x86::Mnemonic::Wait
        || (supported_x87_operation(mnemonic)
            && !matches!(
                mnemonic,
                iced_x86::Mnemonic::Fnclex
                    | iced_x86::Mnemonic::Fninit
                    | iced_x86::Mnemonic::Fnop
                    | iced_x86::Mnemonic::Fnsave
                    | iced_x86::Mnemonic::Fnstcw
                    | iced_x86::Mnemonic::Fnstenv
                    | iced_x86::Mnemonic::Fnstsw
            ))
}

fn generic_x87_effects(
    instruction: &Instruction,
    operands: &[MachineOperand],
) -> Option<MachineEffects> {
    use iced_x86::Mnemonic;
    let mnemonic = instruction.mnemonic();
    if !supported_x87_operation(mnemonic)
        || operands.len() > 2
        || operands.iter().any(|operand| {
            !matches!(
                operand,
                MachineOperand::Register { name, width_bits: 80 }
                    if name.strip_prefix("st").and_then(|index| index.parse::<u8>().ok()).is_some_and(|index| index < 8)
            ) && !matches!(operand, MachineOperand::Register { name, width_bits: 16 } if name == "rax" && matches!(mnemonic, Mnemonic::Fnstsw | Mnemonic::Fstsw))
                && !matches!(operand, MachineOperand::Memory { width_bits, .. } if matches!(width_bits, 16 | 32 | 64 | 80 | 112 | 224 | 752 | 864))
        })
        || operands
            .iter()
            .filter(|operand| matches!(operand, MachineOperand::Memory { .. }))
            .count()
            > 1
    {
        return None;
    }
    let has_memory = operands
        .iter()
        .any(|operand| matches!(operand, MachineOperand::Memory { .. }));
    let memory = if matches!(
        mnemonic,
        Mnemonic::Fst
            | Mnemonic::Fstp
            | Mnemonic::Fist
            | Mnemonic::Fistp
            | Mnemonic::Fisttp
            | Mnemonic::Fbstp
            | Mnemonic::Fnsave
            | Mnemonic::Fnstcw
            | Mnemonic::Fnstenv
            | Mnemonic::Fstcw
            | Mnemonic::Fsave
            | Mnemonic::Fstenv
            | Mnemonic::Fnstsw
            | Mnemonic::Fstsw
    ) && has_memory
    {
        MachineMemoryEffect::Write
    } else if has_memory {
        MachineMemoryEffect::Read
    } else {
        MachineMemoryEffect::None
    };
    let mut read_registers = operands
        .iter()
        .flat_map(operand_address_registers)
        .collect::<Vec<_>>();
    read_registers.extend((0..8).map(|index| format!("st{index}")));
    read_registers.extend(
        [
            "x87_control",
            "x87_status",
            "x87_tag",
            "x87_instruction_pointer",
            "x87_data_pointer",
            "x87_opcode",
        ]
        .into_iter()
        .map(str::to_owned),
    );
    read_registers.sort();
    read_registers.dedup();
    let mut written_registers = (0..8).map(|index| format!("st{index}")).collect::<Vec<_>>();
    written_registers.extend([
        "x87_status".to_owned(),
        "x87_tag".to_owned(),
        "x87_instruction_pointer".to_owned(),
        "x87_data_pointer".to_owned(),
        "x87_opcode".to_owned(),
    ]);
    if matches!(
        mnemonic,
        Mnemonic::Fldcw
            | Mnemonic::Fldenv
            | Mnemonic::Finit
            | Mnemonic::Fninit
            | Mnemonic::Fnsave
            | Mnemonic::Fnstenv
            | Mnemonic::Frstor
            | Mnemonic::Fsave
            | Mnemonic::Fstenv
    ) {
        written_registers.push("x87_control".to_owned());
    }
    if operands.iter().any(
        |operand| matches!(operand, MachineOperand::Register { name, width_bits: 16 } if name == "rax"),
    ) {
        written_registers.push("rax".to_owned());
    }
    let writes_integer_flags = matches!(
        mnemonic,
        Mnemonic::Fcomi | Mnemonic::Fcomip | Mnemonic::Fucomi | Mnemonic::Fucomip
    );
    let read_flags = match mnemonic {
        Mnemonic::Fcmovb => vec!["cf".to_owned()],
        Mnemonic::Fcmove => vec!["zf".to_owned()],
        Mnemonic::Fcmovbe => vec!["cf".to_owned(), "zf".to_owned()],
        Mnemonic::Fcmovu => vec!["pf".to_owned()],
        Mnemonic::Fcmovnb => vec!["cf".to_owned()],
        Mnemonic::Fcmovne => vec!["zf".to_owned()],
        Mnemonic::Fcmovnbe => vec!["cf".to_owned(), "zf".to_owned()],
        Mnemonic::Fcmovnu => vec!["pf".to_owned()],
        _ => Vec::new(),
    };
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags,
        written_flags: if writes_integer_flags {
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        } else {
            Vec::new()
        },
        undefined_flags: Vec::new(),
        memory,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_binary_effects(
    operands: &[MachineOperand],
    mnemonic: iced_x86::Mnemonic,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || operand_scalar_width(source) != Some(width)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || !matches!(
            source,
            MachineOperand::Register { .. }
                | MachineOperand::Immediate { .. }
                | MachineOperand::Memory { .. }
        )
        || (matches!(destination, MachineOperand::Memory { .. })
            && matches!(source, MachineOperand::Memory { .. }))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(source));
    read_registers.sort();
    read_registers.dedup();
    let logic = matches!(
        mnemonic,
        iced_x86::Mnemonic::And | iced_x86::Mnemonic::Or | iced_x86::Mnemonic::Xor
    );
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: if logic {
            ["zf", "sf", "of", "cf", "pf"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        },
        undefined_flags: logic.then(|| "af".to_owned()).into_iter().collect(),
        memory: match (destination, source) {
            (MachineOperand::Memory { .. }, _) => MachineMemoryEffect::ReadWrite,
            (_, MachineOperand::Memory { .. }) => MachineMemoryEffect::Read,
            _ => MachineMemoryEffect::None,
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_move_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 128 | 256 | 512)
        || operand_scalar_width(source) != Some(width)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || (matches!(destination, MachineOperand::Memory { .. })
            && matches!(source, MachineOperand::Memory { .. }))
        || [destination, source]
            .iter()
            .filter_map(|operand| match operand {
                MachineOperand::Register { name, width_bits } => Some((name, width_bits)),
                _ => None,
            })
            .any(|(name, width_bits)| !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    if let MachineOperand::Register { name, width_bits } = destination
        && *width_bits == 128
    {
        read_registers.push(name.clone());
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: match (destination, source) {
            (MachineOperand::Memory { .. }, _) => MachineMemoryEffect::Write,
            (_, MachineOperand::Memory { .. }) => MachineMemoryEffect::Read,
            _ => MachineMemoryEffect::None,
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_masked_vector_move_effects(
    operands: &[MachineOperand],
    mask: &str,
    zeroing: bool,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    if !is_opmask_register(mask)
        || operand_scalar_width(destination) != Some(512)
        || operand_scalar_width(source) != Some(512)
        || (zeroing && matches!(destination, MachineOperand::Memory { .. }))
    {
        return None;
    }
    let mut effects = generic_vector_move_effects(operands)?;
    effects.read_registers.push(mask.to_owned());
    if !zeroing && matches!(destination, MachineOperand::Register { .. }) {
        effects
            .read_registers
            .extend(operand_read_registers(destination));
    }
    effects.read_registers.sort();
    effects.read_registers.dedup();
    Some(effects)
}

fn generic_vector_unary_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if width != 512
        || operand_scalar_width(source) != Some(width)
        || !matches!(destination, MachineOperand::Register { .. })
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || [destination, source]
            .iter()
            .filter_map(|operand| match operand {
                MachineOperand::Register { name, width_bits } => Some((name, width_bits)),
                _ => None,
            })
            .any(|(name, width_bits)| !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_masked_vector_unary_effects(
    operands: &[MachineOperand],
    mask: &str,
    zeroing: bool,
) -> Option<MachineEffects> {
    let destination = operands.first()?;
    if !is_opmask_register(mask) {
        return None;
    }
    let mut effects = generic_vector_unary_effects(operands)?;
    effects.read_registers.push(mask.to_owned());
    if !zeroing {
        effects
            .read_registers
            .extend(operand_read_registers(destination));
    }
    effects.read_registers.sort();
    effects.read_registers.dedup();
    Some(effects)
}

fn generic_vector_permute2_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, first_table, second_table] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 512,
    } = destination
    else {
        return None;
    };
    if !supported_vector_register(destination_name, 512)
        || !matches!(
            first_table,
            MachineOperand::Register {
                name,
                width_bits: 512
            } if supported_vector_register(name, 512)
        )
        || operand_scalar_width(second_table) != Some(512)
        || !matches!(
            second_table,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(
            second_table,
            MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits)
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(first_table));
    read_registers.extend(operand_read_registers(second_table));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(second_table, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_masked_vector_write_effects(
    operands: &[MachineOperand],
    mask: &str,
    zeroing: bool,
) -> Option<MachineEffects> {
    if !is_opmask_register(mask) {
        return None;
    }
    let destination = operands.first()?;
    let mut effects = generic_vector_bitwise_effects(operands)?;
    effects.read_registers.push(mask.to_owned());
    if !zeroing {
        effects
            .read_registers
            .extend(operand_read_registers(destination));
    }
    effects.read_registers.sort();
    effects.read_registers.dedup();
    Some(effects)
}

fn generic_vector_compress_effects(
    operands: &[MachineOperand],
    mask: &str,
    zeroing: bool,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let destination_register = match destination {
        MachineOperand::Register {
            name,
            width_bits: 512,
        } if supported_vector_register(name, 512) => Some(name),
        MachineOperand::Memory {
            width_bits: 512, ..
        } => None,
        _ => return None,
    };
    if !is_opmask_register(mask)
        || operand_scalar_width(source) != Some(512)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(
            source,
            MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits)
        )
        || (matches!(destination, MachineOperand::Memory { .. })
            && !matches!(source, MachineOperand::Register { .. }))
        || (zeroing && matches!(destination, MachineOperand::Memory { .. }))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    if !zeroing && destination_register.is_some() {
        read_registers.extend(operand_read_registers(destination));
    }
    read_registers.push(mask.to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: destination_register.into_iter().cloned().collect(),
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: match (destination, source) {
            (MachineOperand::Memory { .. }, _) => MachineMemoryEffect::Write,
            (_, MachineOperand::Memory { .. }) => MachineMemoryEffect::Read,
            _ => MachineMemoryEffect::None,
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_affine_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [
        destination,
        input,
        matrix,
        MachineOperand::Immediate { width_bits: 8, .. },
    ] = operands
    else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 512,
    } = destination
    else {
        return None;
    };
    if !supported_vector_register(destination_name, 512)
        || !matches!(
            input,
            MachineOperand::Register {
                name,
                width_bits: 512
            } if supported_vector_register(name, 512)
        )
        || operand_scalar_width(matrix) != Some(512)
        || !matches!(
            matrix,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(
            matrix,
            MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits)
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(input);
    read_registers.extend(operand_read_registers(matrix));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(matrix, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_evex_vector_affine_effects(
    operands: &[MachineOperand],
    mask: Option<&str>,
    zeroing: bool,
    broadcast: bool,
) -> Option<MachineEffects> {
    let [
        destination,
        input,
        matrix,
        MachineOperand::Immediate { width_bits: 8, .. },
    ] = operands
    else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 512,
    } = destination
    else {
        return None;
    };
    let invalid_matrix = if broadcast {
        !matches!(matrix, MachineOperand::Memory { width_bits: 64, .. })
    } else {
        operand_scalar_width(matrix) != Some(512)
            || !matches!(
                matrix,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
            || matches!(matrix, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    };
    if !supported_vector_register(destination_name, 512)
        || !matches!(
            input,
            MachineOperand::Register {
                name,
                width_bits: 512
            } if supported_vector_register(name, 512)
        )
        || invalid_matrix
        || (zeroing && mask.is_none())
        || mask.is_some_and(|name| !is_opmask_register(name))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(input);
    read_registers.extend(operand_read_registers(matrix));
    if let Some(mask) = mask {
        read_registers.push(mask.to_owned());
        if !zeroing {
            read_registers.push(destination_name.clone());
        }
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(matrix, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_mask_compare_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [
        destination,
        left,
        right,
        MachineOperand::Immediate {
            value,
            width_bits: 8,
        },
    ] = operands
    else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 64,
    } = destination
    else {
        return None;
    };
    if *value > 7
        || !is_opmask_register(destination_name)
        || !matches!(
            left,
            MachineOperand::Register {
                name,
                width_bits: 512
            } if supported_vector_register(name, 512)
        )
        || operand_scalar_width(right) != Some(512)
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(
            right,
            MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits)
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_evex_vector_mask_compare_effects(
    operands: &[MachineOperand],
    mask: Option<&str>,
    zeroing: bool,
    broadcast: bool,
) -> Option<MachineEffects> {
    let [
        destination,
        left,
        right,
        MachineOperand::Immediate {
            value,
            width_bits: 8,
        },
    ] = operands
    else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 64,
    } = destination
    else {
        return None;
    };
    let invalid_right = if broadcast {
        !matches!(right, MachineOperand::Memory { width_bits: 64, .. })
    } else {
        operand_scalar_width(right) != Some(512)
            || !matches!(
                right,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
            || matches!(right, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    };
    if *value > 7
        || zeroing
        || !is_opmask_register(destination_name)
        || !matches!(
            left,
            MachineOperand::Register {
                name,
                width_bits: 512
            } if supported_vector_register(name, 512)
        )
        || invalid_right
        || mask.is_some_and(|name| !is_opmask_register(name))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    if let Some(mask) = mask {
        read_registers.push(mask.to_owned());
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_opmask_move_effects(
    operands: &[MachineOperand],
    mnemonic: iced_x86::Mnemonic,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let width = match mnemonic {
        iced_x86::Mnemonic::Kmovb => 8,
        iced_x86::Mnemonic::Kmovw => 16,
        iced_x86::Mnemonic::Kmovd => 32,
        iced_x86::Mnemonic::Kmovq => 64,
        _ => return None,
    };
    let valid = |operand: &MachineOperand| match operand {
        MachineOperand::Register {
            name,
            width_bits: 64,
        } if is_opmask_register(name) => true,
        MachineOperand::Register { name, width_bits } => {
            ALL_REGISTERS.contains(&name.as_str())
                && *width_bits == if width == 64 { 64 } else { 32 }
        }
        MachineOperand::Memory { width_bits, .. } => *width_bits == width,
        _ => false,
    };
    if !valid(destination)
        || !valid(source)
        || ![destination, source].iter().any(|operand| {
            matches!(operand, MachineOperand::Register { name, .. } if is_opmask_register(name))
        })
        || (matches!(destination, MachineOperand::Memory { .. })
            && matches!(source, MachineOperand::Memory { .. }))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: match (destination, source) {
            (MachineOperand::Memory { .. }, _) => MachineMemoryEffect::Write,
            (_, MachineOperand::Memory { .. }) => MachineMemoryEffect::Read,
            _ => MachineMemoryEffect::None,
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn is_opmask_register(name: &str) -> bool {
    name.strip_prefix('k')
        .and_then(|index| index.parse::<u8>().ok())
        .is_some_and(|index| index < 8)
}

fn generic_vector_byte_mask_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: destination_width,
    } = destination
    else {
        return None;
    };
    let MachineOperand::Register {
        name: source_name,
        width_bits: source_width,
    } = source
    else {
        return None;
    };
    if !matches!(destination_width, 32 | 64)
        || !matches!(source_width, 128 | 256)
        || !supported_vector_register(source_name, *source_width)
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: vec![source_name.clone()],
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_aesenc_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, round_key] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 128,
    } = destination
    else {
        return None;
    };
    if !supported_vector_register(destination_name, 128)
        || operand_scalar_width(round_key) != Some(128)
        || !matches!(
            round_key,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(round_key, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(round_key));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(round_key, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_insert_scalar_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source, MachineOperand::Immediate { .. }] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 128,
    } = destination
    else {
        return None;
    };
    let source_width = operand_scalar_width(source)?;
    if !supported_vector_register(destination_name, 128)
        || !matches!(source_width, 16 | 32 | 64)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(source));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_non_temporal_store_effects(
    operands: &[MachineOperand],
) -> Option<MachineEffects> {
    let [destination @ MachineOperand::Memory { .. }, source] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 128 | 256)
        || operand_scalar_width(source) != Some(width)
        || !matches!(source, MachineOperand::Register { .. })
        || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: Vec::new(),
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::Write,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_test_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [left, right] = operands else {
        return None;
    };
    let width = operand_scalar_width(left)?;
    if !matches!(width, 128 | 256)
        || operand_scalar_width(right) != Some(width)
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || [left, right]
            .iter()
            .filter_map(|operand| match operand {
                MachineOperand::Register { name, width_bits } => Some((name, width_bits)),
                _ => None,
            })
            .any(|(name, width_bits)| !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: Vec::new(),
        read_flags: Vec::new(),
        written_flags: ALL_FLAGS.into_iter().map(str::to_owned).collect(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_prefetch_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [source @ MachineOperand::Memory { .. }] = operands else {
        return None;
    };
    Some(MachineEffects {
        read_registers: operand_address_registers(source),
        written_registers: Vec::new(),
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        // Architecturally this is only a cache hint: it does not read a value
        // into machine state and ignored hints have no observable result.
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn aligned_vector_memory_operation(instruction: &Instruction) -> bool {
    matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Movaps
            | iced_x86::Mnemonic::Movapd
            | iced_x86::Mnemonic::Movdqa
            | iced_x86::Mnemonic::Vmovaps
            | iced_x86::Mnemonic::Vmovapd
            | iced_x86::Mnemonic::Vmovdqa
            | iced_x86::Mnemonic::Vmovdqa32
            | iced_x86::Mnemonic::Vmovdqa64
    ) && (0..instruction.op_count()).any(|index| {
        matches!(
            instruction.op_kind(index),
            OpKind::Memory
                | OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI
        )
    })
}

fn generic_vector_scalar_move_effects(
    operands: &[MachineOperand],
    scalar_width: u16,
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    let destination_is_vector = vector_register(destination);
    let source_is_vector = vector_register(source);
    let scalar_operand = |operand: &MachineOperand| {
        operand_scalar_width(operand) == Some(scalar_width)
            && matches!(
                operand,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
    };
    let valid_direction = if destination_is_vector {
        scalar_operand(source) || (scalar_width == 64 && source_is_vector)
    } else {
        scalar_operand(destination) && source_is_vector
    };
    if !valid_direction
        || (matches!(destination, MachineOperand::Memory { .. })
            && matches!(source, MachineOperand::Memory { .. }))
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(operand_read_registers(source));
    if destination_is_vector
        && !vex_encoded
        && let MachineOperand::Register { name, .. } = destination
    {
        read_registers.push(name.clone());
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: match (destination, source) {
            (MachineOperand::Memory { .. }, _) => MachineMemoryEffect::Write,
            (_, MachineOperand::Memory { .. }) => MachineMemoryEffect::Read,
            _ => MachineMemoryEffect::None,
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_scalar_float_move_effects(
    operands: &[MachineOperand],
    scalar_width: u16,
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    let scalar_memory = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width
        )
    };
    let (destination, sources): (&MachineOperand, Vec<&MachineOperand>) = match operands {
        [destination, source] if !vex_encoded => (destination, vec![source]),
        [destination, source] if vex_encoded && scalar_memory(destination) => {
            (destination, vec![source])
        }
        [destination, merge, scalar] if vex_encoded => (destination, vec![merge, scalar]),
        _ => return None,
    };
    let valid = if scalar_memory(destination) {
        sources.len() == 1 && vector_register(sources[0])
    } else if vector_register(destination) && !vex_encoded {
        sources.len() == 1 && (vector_register(sources[0]) || scalar_memory(sources[0]))
    } else if vector_register(destination) && vex_encoded {
        sources.len() == 2
            && vector_register(sources[0])
            && (vector_register(sources[1]) || scalar_memory(sources[1]))
    } else {
        false
    };
    if !valid {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.extend(
        sources
            .iter()
            .flat_map(|source| operand_read_registers(source)),
    );
    if vector_register(destination) && !vex_encoded {
        read_registers.extend(operand_read_registers(destination));
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if scalar_memory(destination) {
            MachineMemoryEffect::Write
        } else if sources.iter().any(|source| scalar_memory(source)) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn scalar_float_binary_width(mnemonic: iced_x86::Mnemonic) -> Option<u16> {
    match mnemonic {
        iced_x86::Mnemonic::Addss
        | iced_x86::Mnemonic::Subss
        | iced_x86::Mnemonic::Mulss
        | iced_x86::Mnemonic::Divss
        | iced_x86::Mnemonic::Minss
        | iced_x86::Mnemonic::Maxss
        | iced_x86::Mnemonic::Vaddss
        | iced_x86::Mnemonic::Vsubss
        | iced_x86::Mnemonic::Vmulss
        | iced_x86::Mnemonic::Vdivss
        | iced_x86::Mnemonic::Vminss
        | iced_x86::Mnemonic::Vmaxss => Some(32),
        iced_x86::Mnemonic::Addsd
        | iced_x86::Mnemonic::Subsd
        | iced_x86::Mnemonic::Mulsd
        | iced_x86::Mnemonic::Divsd
        | iced_x86::Mnemonic::Minsd
        | iced_x86::Mnemonic::Maxsd
        | iced_x86::Mnemonic::Vaddsd
        | iced_x86::Mnemonic::Vsubsd
        | iced_x86::Mnemonic::Vmulsd
        | iced_x86::Mnemonic::Vdivsd
        | iced_x86::Mnemonic::Vminsd
        | iced_x86::Mnemonic::Vmaxsd => Some(64),
        _ => None,
    }
}

fn generic_scalar_float_binary_effects(
    operands: &[MachineOperand],
    scalar_width: u16,
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    let scalar_source = |operand: &MachineOperand| {
        vector_register(operand)
            || matches!(
                operand,
                MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width
            )
    };
    let (destination, left, right) = match operands {
        [destination, right] if !vex_encoded => (destination, destination, right),
        [destination, left, right] if vex_encoded => (destination, left, right),
        _ => return None,
    };
    if !vector_register(destination) || !vector_register(left) || !scalar_source(right) {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    let MachineOperand::Register { name, .. } = destination else {
        unreachable!("scalar floating destination was checked as a register")
    };
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn packed_float_binary_lane_width(mnemonic: iced_x86::Mnemonic) -> Option<u16> {
    match mnemonic {
        iced_x86::Mnemonic::Addps
        | iced_x86::Mnemonic::Subps
        | iced_x86::Mnemonic::Mulps
        | iced_x86::Mnemonic::Divps
        | iced_x86::Mnemonic::Vaddps
        | iced_x86::Mnemonic::Vsubps
        | iced_x86::Mnemonic::Vmulps
        | iced_x86::Mnemonic::Vdivps => Some(32),
        iced_x86::Mnemonic::Addpd
        | iced_x86::Mnemonic::Subpd
        | iced_x86::Mnemonic::Mulpd
        | iced_x86::Mnemonic::Divpd
        | iced_x86::Mnemonic::Vaddpd
        | iced_x86::Mnemonic::Vsubpd
        | iced_x86::Mnemonic::Vmulpd
        | iced_x86::Mnemonic::Vdivpd => Some(64),
        _ => None,
    }
}

fn generic_packed_float_binary_effects(
    operands: &[MachineOperand],
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let (destination, left, right) = match operands {
        [destination, right] if !vex_encoded => (destination, destination, right),
        [destination, left, right] if vex_encoded => (destination, left, right),
        _ => return None,
    };
    let MachineOperand::Register {
        name,
        width_bits: destination_width,
    } = destination
    else {
        return None;
    };
    if !matches!(destination_width, 128 | 256 | 512)
        || (!vex_encoded && *destination_width != 128)
        || !supported_vector_register(name, *destination_width)
        || operand_scalar_width(left) != Some(*destination_width)
        || operand_scalar_width(right) != Some(*destination_width)
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(left, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
        || matches!(right, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_evex_packed_float_binary_effects(
    operands: &[MachineOperand],
    lane_width: u16,
    mask: Option<&str>,
    zeroing: bool,
    broadcast: bool,
) -> Option<MachineEffects> {
    let [destination, left, right] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name: destination_name,
        width_bits: 512,
    } = destination
    else {
        return None;
    };
    let invalid_right = if broadcast {
        !matches!(right, MachineOperand::Memory { width_bits, .. } if *width_bits == lane_width)
    } else {
        operand_scalar_width(right) != Some(512)
            || !matches!(
                right,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
            || matches!(right, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    };
    if !matches!(lane_width, 32 | 64)
        || !supported_vector_register(destination_name, 512)
        || !matches!(
            left,
            MachineOperand::Register {
                name,
                width_bits: 512
            } if supported_vector_register(name, 512)
        )
        || invalid_right
        || (zeroing && mask.is_none())
        || mask.is_some_and(|name| !is_opmask_register(name))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.push("mxcsr".to_owned());
    if let Some(mask) = mask {
        read_registers.push(mask.to_owned());
        if !zeroing {
            read_registers.push(destination_name.clone());
        }
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination_name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn scalar_float_compare_width(mnemonic: iced_x86::Mnemonic) -> Option<u16> {
    match mnemonic {
        iced_x86::Mnemonic::Comiss
        | iced_x86::Mnemonic::Ucomiss
        | iced_x86::Mnemonic::Vcomiss
        | iced_x86::Mnemonic::Vucomiss => Some(32),
        iced_x86::Mnemonic::Comisd
        | iced_x86::Mnemonic::Ucomisd
        | iced_x86::Mnemonic::Vcomisd
        | iced_x86::Mnemonic::Vucomisd => Some(64),
        _ => None,
    }
}

fn generic_scalar_float_compare_effects(
    operands: &[MachineOperand],
    scalar_width: u16,
) -> Option<MachineEffects> {
    let [left, right] = operands else {
        return None;
    };
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    if !vector_register(left)
        || !(vector_register(right)
            || matches!(right, MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec!["mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: ALL_FLAGS.into_iter().map(str::to_owned).collect(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn scalar_float_sqrt_width(mnemonic: iced_x86::Mnemonic) -> Option<u16> {
    match mnemonic {
        iced_x86::Mnemonic::Sqrtss | iced_x86::Mnemonic::Vsqrtss => Some(32),
        iced_x86::Mnemonic::Sqrtsd | iced_x86::Mnemonic::Vsqrtsd => Some(64),
        _ => None,
    }
}

fn packed_float_sqrt_lane_width(mnemonic: iced_x86::Mnemonic) -> Option<u16> {
    match mnemonic {
        iced_x86::Mnemonic::Sqrtps | iced_x86::Mnemonic::Vsqrtps => Some(32),
        iced_x86::Mnemonic::Sqrtpd | iced_x86::Mnemonic::Vsqrtpd => Some(64),
        _ => None,
    }
}

fn generic_scalar_float_sqrt_effects(
    operands: &[MachineOperand],
    scalar_width: u16,
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    let scalar_source = |operand: &MachineOperand| {
        vector_register(operand)
            || matches!(operand, MachineOperand::Memory { width_bits, .. } if *width_bits == scalar_width)
    };
    let (destination, merge, source) = match operands {
        [destination, source] if !vex_encoded => (destination, destination, source),
        [destination, merge, source] if vex_encoded => (destination, merge, source),
        _ => return None,
    };
    if !vector_register(destination) || !vector_register(merge) || !scalar_source(source) {
        return None;
    }
    let mut read_registers = operand_read_registers(merge);
    read_registers.extend(operand_read_registers(source));
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    let MachineOperand::Register { name, .. } = destination else {
        unreachable!("scalar square-root destination was checked as a register")
    };
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_packed_float_sqrt_effects(
    operands: &[MachineOperand],
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 128 | 256 | 512)
        || (!vex_encoded && *width_bits != 128)
        || !supported_vector_register(name, *width_bits)
        || operand_scalar_width(source) != Some(*width_bits)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn scalar_float_precision_conversion(mnemonic: iced_x86::Mnemonic) -> Option<(u16, u16, bool)> {
    match mnemonic {
        iced_x86::Mnemonic::Cvtss2sd => Some((32, 64, false)),
        iced_x86::Mnemonic::Cvtsd2ss => Some((64, 32, false)),
        iced_x86::Mnemonic::Vcvtss2sd => Some((32, 64, true)),
        iced_x86::Mnemonic::Vcvtsd2ss => Some((64, 32, true)),
        _ => None,
    }
}

fn generic_scalar_float_conversion_effects(
    operands: &[MachineOperand],
    source_width: u16,
    _destination_width: u16,
    vex_encoded: bool,
) -> Option<MachineEffects> {
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    let scalar_source = |operand: &MachineOperand| {
        vector_register(operand)
            || matches!(operand, MachineOperand::Memory { width_bits, .. } if *width_bits == source_width)
    };
    let (destination, merge, source) = match operands {
        [destination, source] if !vex_encoded => (destination, destination, source),
        [destination, merge, source] if vex_encoded => (destination, merge, source),
        _ => return None,
    };
    if !vector_register(destination) || !vector_register(merge) || !scalar_source(source) {
        return None;
    }
    let mut read_registers = operand_read_registers(merge);
    read_registers.extend(operand_read_registers(source));
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    let MachineOperand::Register { name, .. } = destination else {
        unreachable!("scalar conversion destination was checked as a register")
    };
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScalarIntegerFloatConversion {
    IntegerToFloat { float_width: u16, vex: bool },
    FloatToInteger { float_width: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackedIntegerFloatConversion {
    IntegerToFloat,
    FloatToInteger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackedFloatPrecisionConversion {
    WidenFloat,
    NarrowFloat,
    WidenInteger,
    NarrowInteger,
}

fn packed_float_precision_conversion(
    mnemonic: iced_x86::Mnemonic,
) -> Option<PackedFloatPrecisionConversion> {
    use iced_x86::Mnemonic;
    match mnemonic {
        Mnemonic::Cvtps2pd | Mnemonic::Vcvtps2pd => {
            Some(PackedFloatPrecisionConversion::WidenFloat)
        }
        Mnemonic::Cvtpd2ps | Mnemonic::Vcvtpd2ps => {
            Some(PackedFloatPrecisionConversion::NarrowFloat)
        }
        Mnemonic::Cvtdq2pd | Mnemonic::Vcvtdq2pd => {
            Some(PackedFloatPrecisionConversion::WidenInteger)
        }
        Mnemonic::Cvtpd2dq | Mnemonic::Cvttpd2dq | Mnemonic::Vcvtpd2dq | Mnemonic::Vcvttpd2dq => {
            Some(PackedFloatPrecisionConversion::NarrowInteger)
        }
        _ => None,
    }
}

fn generic_packed_float_precision_conversion_effects(
    operands: &[MachineOperand],
    conversion: PackedFloatPrecisionConversion,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name,
        width_bits: destination_width,
    } = destination
    else {
        return None;
    };
    let source_width = operand_scalar_width(source)?;
    let widths_valid = match conversion {
        PackedFloatPrecisionConversion::WidenFloat
        | PackedFloatPrecisionConversion::WidenInteger => matches!(
            (*destination_width, source_width),
            (128, 64 | 128) | (256, 128)
        ),
        PackedFloatPrecisionConversion::NarrowFloat
        | PackedFloatPrecisionConversion::NarrowInteger => {
            matches!((*destination_width, source_width), (128, 128 | 256))
        }
    };
    if !widths_valid
        || !supported_vector_register(name, *destination_width)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn packed_integer_float_conversion(
    mnemonic: iced_x86::Mnemonic,
) -> Option<PackedIntegerFloatConversion> {
    use iced_x86::Mnemonic;
    match mnemonic {
        Mnemonic::Cvtdq2ps | Mnemonic::Vcvtdq2ps => {
            Some(PackedIntegerFloatConversion::IntegerToFloat)
        }
        Mnemonic::Cvtps2dq | Mnemonic::Cvttps2dq | Mnemonic::Vcvtps2dq | Mnemonic::Vcvttps2dq => {
            Some(PackedIntegerFloatConversion::FloatToInteger)
        }
        _ => None,
    }
}

fn generic_packed_integer_float_conversion_effects(
    operands: &[MachineOperand],
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 128 | 256)
        || !supported_vector_register(name, *width_bits)
        || operand_scalar_width(source) != Some(*width_bits)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.push("mxcsr".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone(), "mxcsr".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn scalar_integer_float_conversion(
    mnemonic: iced_x86::Mnemonic,
) -> Option<ScalarIntegerFloatConversion> {
    use iced_x86::Mnemonic;
    match mnemonic {
        Mnemonic::Cvtsi2ss => Some(ScalarIntegerFloatConversion::IntegerToFloat {
            float_width: 32,
            vex: false,
        }),
        Mnemonic::Cvtsi2sd => Some(ScalarIntegerFloatConversion::IntegerToFloat {
            float_width: 64,
            vex: false,
        }),
        Mnemonic::Vcvtsi2ss => Some(ScalarIntegerFloatConversion::IntegerToFloat {
            float_width: 32,
            vex: true,
        }),
        Mnemonic::Vcvtsi2sd => Some(ScalarIntegerFloatConversion::IntegerToFloat {
            float_width: 64,
            vex: true,
        }),
        Mnemonic::Cvtss2si | Mnemonic::Cvttss2si | Mnemonic::Vcvtss2si | Mnemonic::Vcvttss2si => {
            Some(ScalarIntegerFloatConversion::FloatToInteger { float_width: 32 })
        }
        Mnemonic::Cvtsd2si | Mnemonic::Cvttsd2si | Mnemonic::Vcvtsd2si | Mnemonic::Vcvttsd2si => {
            Some(ScalarIntegerFloatConversion::FloatToInteger { float_width: 64 })
        }
        _ => None,
    }
}

fn generic_scalar_integer_float_conversion_effects(
    operands: &[MachineOperand],
    conversion: ScalarIntegerFloatConversion,
) -> Option<MachineEffects> {
    let vector_register = |operand: &MachineOperand| {
        matches!(
            operand,
            MachineOperand::Register { name, width_bits: 128 }
                if supported_vector_register(name, 128)
        )
    };
    match conversion {
        ScalarIntegerFloatConversion::IntegerToFloat { vex, .. } => {
            let (destination, merge, source) = match operands {
                [destination, source] if !vex => (destination, destination, source),
                [destination, merge, source] if vex => (destination, merge, source),
                _ => return None,
            };
            let source_width = operand_scalar_width(source)?;
            if !vector_register(destination)
                || !vector_register(merge)
                || !matches!(source_width, 32 | 64)
                || !matches!(
                    source,
                    MachineOperand::Register { .. } | MachineOperand::Memory { .. }
                )
            {
                return None;
            }
            let mut read_registers = operand_read_registers(merge);
            read_registers.extend(operand_read_registers(source));
            read_registers.push("mxcsr".to_owned());
            read_registers.sort();
            read_registers.dedup();
            let MachineOperand::Register { name, .. } = destination else {
                unreachable!("integer-to-floating destination was checked as a vector register")
            };
            Some(MachineEffects {
                read_registers,
                written_registers: vec![name.clone(), "mxcsr".to_owned()],
                read_flags: Vec::new(),
                written_flags: Vec::new(),
                undefined_flags: Vec::new(),
                memory: if matches!(source, MachineOperand::Memory { .. }) {
                    MachineMemoryEffect::Read
                } else {
                    MachineMemoryEffect::None
                },
                control: MachineControlEffect::Next,
                conservative: false,
            })
        }
        ScalarIntegerFloatConversion::FloatToInteger { float_width } => {
            let [destination, source] = operands else {
                return None;
            };
            if !matches!(
                destination,
                MachineOperand::Register {
                    width_bits: 32 | 64,
                    ..
                }
            ) || !(vector_register(source)
                || matches!(source, MachineOperand::Memory { width_bits, .. } if *width_bits == float_width))
            {
                return None;
            }
            let mut read_registers = operand_read_registers(source);
            read_registers.push("mxcsr".to_owned());
            read_registers.sort();
            read_registers.dedup();
            let MachineOperand::Register { name, .. } = destination else {
                unreachable!("floating-to-integer destination was checked as a register")
            };
            Some(MachineEffects {
                read_registers,
                written_registers: vec![name.clone(), "mxcsr".to_owned()],
                read_flags: Vec::new(),
                written_flags: Vec::new(),
                undefined_flags: Vec::new(),
                memory: if matches!(source, MachineOperand::Memory { .. }) {
                    MachineMemoryEffect::Read
                } else {
                    MachineMemoryEffect::None
                },
                control: MachineControlEffect::Next,
                conservative: false,
            })
        }
    }
}

fn generic_divide_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [divisor] = operands else {
        return None;
    };
    let width = operand_scalar_width(divisor)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            divisor,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(divisor);
    read_registers.push("rax".to_owned());
    if width != 8 {
        read_registers.push("rdx".to_owned());
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: if width == 8 {
            vec!["rax".to_owned()]
        } else {
            vec!["rax".to_owned(), "rdx".to_owned()]
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: ALL_FLAGS.into_iter().map(str::to_owned).collect(),
        memory: if matches!(divisor, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_bitwise_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let (destination, sources) = match operands {
        [destination, source] => (destination, [destination, source]),
        [destination, left, right] => (destination, [left, right]),
        _ => return None,
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 128 | 256 | 512)
        || !supported_vector_register(name, *width_bits)
        || sources.iter().any(|source| {
            operand_scalar_width(source) != Some(*width_bits)
                || !matches!(
                    source,
                    MachineOperand::Register { .. } | MachineOperand::Memory { .. }
                )
                || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
        })
        || sources
            .iter()
            .filter(|source| matches!(source, MachineOperand::Memory { .. }))
            .count()
            > 1
    {
        return None;
    }
    let mut read_registers = sources
        .iter()
        .flat_map(|source| operand_read_registers(source))
        .collect::<Vec<_>>();
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if sources
            .iter()
            .any(|source| matches!(source, MachineOperand::Memory { .. }))
        {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_immediate_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let (destination, source, immediate) = match operands {
        [destination, immediate] => (destination, destination, immediate),
        [destination, source, immediate] => (destination, source, immediate),
        _ => return None,
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 128 | 256)
        || !supported_vector_register(name, *width_bits)
        || operand_scalar_width(source) != Some(*width_bits)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
        || !matches!(immediate, MachineOperand::Immediate { width_bits: 8, .. })
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(source),
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_broadcast_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    let source_valid = matches!(
        source,
        MachineOperand::Memory {
            width_bits: 8 | 32 | 64,
            ..
        } | MachineOperand::Register {
            name: _,
            width_bits: 128
        }
    );
    if !matches!(width_bits, 128 | 256)
        || !supported_vector_register(name, *width_bits)
        || !source_valid
        || matches!(source, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(source),
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_extract_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source, immediate] = operands else {
        return None;
    };
    let MachineOperand::Register {
        name: source_name,
        width_bits: 256,
    } = source
    else {
        return None;
    };
    if !supported_vector_register(source_name, 256)
        || operand_scalar_width(destination) != Some(128)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(destination, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
        || !matches!(immediate, MachineOperand::Immediate { width_bits: 8, .. })
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.push(source_name.clone());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Write
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_vector_insert_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [
        MachineOperand::Register {
            name: destination,
            width_bits: 256,
        },
        left @ MachineOperand::Register {
            name: left_name,
            width_bits: 256,
        },
        right,
        MachineOperand::Immediate { .. },
    ] = operands
    else {
        return None;
    };
    if !supported_vector_register(destination, 256)
        || !supported_vector_register(left_name, 256)
        || operand_scalar_width(right) != Some(128)
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || matches!(right, MachineOperand::Register { name, width_bits } if !supported_vector_register(name, *width_bits))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![destination.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_andn_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, left, right] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 32 | 64)
        || operand_scalar_width(left) != Some(*width_bits)
        || operand_scalar_width(right) != Some(*width_bits)
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(
            right,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: ["zf", "sf", "of", "cf"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        undefined_flags: ["pf", "af"].into_iter().map(str::to_owned).collect(),
        memory: if matches!(right, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn supported_vector_register(name: &str, width_bits: u16) -> bool {
    let prefix = if width_bits == 128 {
        "xmm"
    } else if width_bits == 256 {
        "ymm"
    } else if width_bits == 512 {
        "zmm"
    } else {
        return false;
    };
    name.strip_prefix(prefix)
        .and_then(|index| index.parse::<u8>().ok())
        .is_some_and(|index| index < 32)
}

fn generic_binary_with_carry_effects(
    operands: &[MachineOperand],
    mnemonic: iced_x86::Mnemonic,
) -> Option<MachineEffects> {
    let mut effects = generic_binary_effects(operands, mnemonic)?;
    effects.read_flags.push("cf".to_owned());
    Some(effects)
}

fn generic_compare_effects(
    operands: &[MachineOperand],
    mnemonic: iced_x86::Mnemonic,
) -> Option<MachineEffects> {
    let [left, right] = operands else {
        return None;
    };
    let width = operand_scalar_width(left)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || operand_scalar_width(right) != Some(width)
        || !matches!(
            left,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || !matches!(
            right,
            MachineOperand::Register { .. }
                | MachineOperand::Immediate { .. }
                | MachineOperand::Memory { .. }
        )
        || (matches!(left, MachineOperand::Memory { .. })
            && matches!(right, MachineOperand::Memory { .. }))
    {
        return None;
    }
    let mut read_registers = operand_read_registers(left);
    read_registers.extend(operand_read_registers(right));
    read_registers.sort();
    read_registers.dedup();
    let logic = mnemonic == iced_x86::Mnemonic::Test;
    Some(MachineEffects {
        read_registers,
        written_registers: Vec::new(),
        read_flags: Vec::new(),
        written_flags: if logic {
            ["zf", "sf", "of", "cf", "pf"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else {
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        },
        undefined_flags: logic.then(|| "af".to_owned()).into_iter().collect(),
        memory: if matches!(left, MachineOperand::Memory { .. })
            || matches!(right, MachineOperand::Memory { .. })
        {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_unary_effects(
    operands: &[MachineOperand],
    written_flags: &[&str],
) -> Option<MachineEffects> {
    let [destination] = operands else {
        return None;
    };
    if !matches!(operand_scalar_width(destination)?, 8 | 16 | 32 | 64)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(destination),
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: written_flags
            .iter()
            .map(|flag| (*flag).to_owned())
            .collect(),
        undefined_flags: Vec::new(),
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_shift_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    if matches!(operands, [_, MachineOperand::Immediate { .. }]) {
        return generic_immediate_shift_effects(operands);
    }
    let [
        destination,
        count @ MachineOperand::Register { width_bits: 8, .. },
    ] = operands
    else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(count));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: ALL_FLAGS.into_iter().map(str::to_owned).collect(),
        undefined_flags: Vec::new(),
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_immediate_shift_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, MachineOperand::Immediate { value: count, .. }] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || *count == 0
        || *count >= u64::from(width)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(destination),
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: if *count == 1 {
            vec!["zf", "sf", "of", "cf", "pf"]
        } else {
            vec!["zf", "sf", "cf", "pf"]
        }
        .into_iter()
        .map(str::to_owned)
        .collect(),
        undefined_flags: if *count > 1 {
            vec!["of".to_owned(), "af".to_owned()]
        } else {
            vec!["af".to_owned()]
        },
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_double_shift_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source @ MachineOperand::Register { .. }, count] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 32 | 64)
        || operand_scalar_width(source) != Some(width)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let effective_immediate = match count {
        MachineOperand::Immediate { value, .. } => {
            let effective = *value & u64::from(width - 1);
            (effective != 0).then_some(effective)
        }
        MachineOperand::Register { width_bits: 8, .. } => None,
        _ => return None,
    };
    if matches!(count, MachineOperand::Immediate { .. }) && effective_immediate.is_none() {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(source));
    read_registers.extend(operand_read_registers(count));
    read_registers.sort();
    read_registers.dedup();
    let (written_flags, undefined_flags) = match effective_immediate {
        Some(1) => (
            ["zf", "sf", "of", "cf", "pf"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            vec!["af".to_owned()],
        ),
        Some(_) => (
            ["zf", "sf", "cf", "pf"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            vec!["of".to_owned(), "af".to_owned()],
        ),
        None => (
            ALL_FLAGS.into_iter().map(str::to_owned).collect(),
            Vec::new(),
        ),
    };
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags,
        undefined_flags,
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_flagless_shift_effects(
    operands: &[MachineOperand],
    immediate_count: bool,
) -> Option<MachineEffects> {
    let [destination, source, count] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    let count_valid = if immediate_count {
        matches!(count, MachineOperand::Immediate { width_bits: 8, .. })
    } else {
        matches!(count, MachineOperand::Register { width_bits: count_width, .. } if count_width == width_bits)
    };
    if !matches!(width_bits, 32 | 64)
        || operand_scalar_width(source) != Some(*width_bits)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || !count_valid
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.extend(operand_read_registers(count));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_bmi2_permutation_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source, mask] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 32 | 64)
        || operand_scalar_width(source) != Some(*width_bits)
        || operand_scalar_width(mask) != Some(*width_bits)
        || !matches!(source, MachineOperand::Register { .. })
        || !matches!(
            mask,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.extend(operand_read_registers(mask));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(mask, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_rotate_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    if matches!(operands, [_, MachineOperand::Immediate { .. }]) {
        return generic_immediate_rotate_effects(operands);
    }
    let [
        destination,
        count @ MachineOperand::Register { width_bits: 8, .. },
    ] = operands
    else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(count));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: vec!["of".to_owned(), "cf".to_owned()],
        undefined_flags: Vec::new(),
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_immediate_rotate_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [
        destination,
        MachineOperand::Immediate {
            value: raw_count, ..
        },
    ] = operands
    else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || raw_count % u64::from(width) == 0
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let count = raw_count % u64::from(width);
    Some(MachineEffects {
        read_registers: operand_read_registers(destination),
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: Vec::new(),
        written_flags: if count == 1 {
            vec!["of", "cf"]
        } else {
            vec!["cf"]
        }
        .into_iter()
        .map(str::to_owned)
        .collect(),
        undefined_flags: if count > 1 {
            vec!["of".to_owned()]
        } else {
            Vec::new()
        },
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_rotate_through_carry_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, count] = operands else {
        return None;
    };
    let width = operand_scalar_width(destination)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
        || !matches!(
            count,
            MachineOperand::Immediate { .. } | MachineOperand::Register { width_bits: 8, .. }
        )
    {
        return None;
    }
    let effective_immediate = match count {
        MachineOperand::Immediate { value, .. } => {
            let masked = value & if width == 64 { 63 } else { 31 };
            Some(if width < 32 {
                masked % (u64::from(width) + 1)
            } else {
                masked
            })
        }
        _ => None,
    };
    if effective_immediate == Some(0) {
        return Some(MachineEffects {
            read_registers: Vec::new(),
            written_registers: Vec::new(),
            read_flags: Vec::new(),
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: MachineMemoryEffect::None,
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(count));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: match destination {
            MachineOperand::Register { name, .. } => vec![name.clone()],
            _ => Vec::new(),
        },
        read_flags: vec!["cf".to_owned()],
        written_flags: vec!["cf".to_owned(), "of".to_owned()],
        undefined_flags: Vec::new(),
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_register_exchange_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [left, right] = operands else {
        return None;
    };
    let width = operand_scalar_width(left)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || operand_scalar_width(right) != Some(width)
        || !matches!(left, MachineOperand::Register { .. })
        || !matches!(right, MachineOperand::Register { .. })
    {
        return None;
    }
    let mut registers = operand_read_registers(left);
    registers.extend(operand_read_registers(right));
    registers.sort();
    registers.dedup();
    Some(MachineEffects {
        read_registers: registers.clone(),
        written_registers: registers,
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_bswap_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination @ MachineOperand::Register { name, width_bits }] = operands else {
        return None;
    };
    if !matches!(width_bits, 32 | 64) {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(destination),
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_bit_scan_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 16 | 32 | 64)
        || operand_scalar_width(source) != Some(*width_bits)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(source),
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: vec!["zf".to_owned()],
        undefined_flags: ["sf", "of", "cf", "pf", "af"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_register_bit_test_effects(
    operands: &[MachineOperand],
    mnemonic: iced_x86::Mnemonic,
) -> Option<MachineEffects> {
    let [destination, bit_index] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        // Memory bit strings need signed register-index address adjustment.
        // Keep them opaque until that addressing rule is represented in CIR.
        return None;
    };
    if !matches!(width_bits, 16 | 32 | 64)
        || !matches!(
            bit_index,
            MachineOperand::Immediate { .. } | MachineOperand::Register { .. }
        )
        || (matches!(bit_index, MachineOperand::Register { .. })
            && operand_scalar_width(bit_index) != Some(*width_bits))
    {
        return None;
    }
    let modifies_destination = matches!(
        mnemonic,
        iced_x86::Mnemonic::Btc | iced_x86::Mnemonic::Btr | iced_x86::Mnemonic::Bts
    );
    let mut read_registers = operand_read_registers(destination);
    read_registers.extend(operand_read_registers(bit_index));
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: if modifies_destination {
            vec![name.clone()]
        } else {
            Vec::new()
        },
        read_flags: Vec::new(),
        written_flags: vec!["cf".to_owned()],
        undefined_flags: ["zf", "sf", "of", "pf", "af"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_bit_count_effects(
    operands: &[MachineOperand],
    undefined_nonzero_flags: bool,
) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 16 | 32 | 64)
        || operand_scalar_width(source) != Some(*width_bits)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: operand_read_registers(source),
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: if undefined_nonzero_flags {
            vec!["zf".to_owned(), "cf".to_owned()]
        } else {
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        },
        undefined_flags: if undefined_nonzero_flags {
            vec![
                "sf".to_owned(),
                "of".to_owned(),
                "pf".to_owned(),
                "af".to_owned(),
            ]
        } else {
            Vec::new()
        },
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_imul_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let (destination, multiplicands) = match operands {
        [destination, source] => (destination, [destination, source]),
        [destination, source, immediate] => (destination, [source, immediate]),
        _ => return None,
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 16 | 32 | 64)
        || multiplicands
            .iter()
            .any(|operand| operand_scalar_width(operand) != Some(*width_bits))
        || multiplicands.iter().any(|operand| {
            !matches!(
                operand,
                MachineOperand::Register { .. }
                    | MachineOperand::Immediate { .. }
                    | MachineOperand::Memory { .. }
            )
        })
        || multiplicands
            .iter()
            .filter(|operand| matches!(operand, MachineOperand::Memory { .. }))
            .count()
            > 1
    {
        return None;
    }
    let mut read_registers = multiplicands
        .iter()
        .flat_map(|operand| operand_read_registers(operand))
        .collect::<Vec<_>>();
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: ["of", "cf"].into_iter().map(str::to_owned).collect(),
        undefined_flags: ["zf", "sf", "pf", "af"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        memory: if multiplicands
            .iter()
            .any(|operand| matches!(operand, MachineOperand::Memory { .. }))
        {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_full_multiply_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [source] = operands else {
        return None;
    };
    let width = operand_scalar_width(source)?;
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            source,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.push("rax".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: if width == 8 {
            vec!["rax".to_owned()]
        } else {
            vec!["rax".to_owned(), "rdx".to_owned()]
        },
        read_flags: Vec::new(),
        written_flags: ["of", "cf"].into_iter().map(str::to_owned).collect(),
        undefined_flags: ["zf", "sf", "pf", "af"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn accumulator_sign_extension_effects(mnemonic: iced_x86::Mnemonic) -> Option<MachineEffects> {
    let (read_registers, written_registers) = match mnemonic {
        iced_x86::Mnemonic::Cbw | iced_x86::Mnemonic::Cwde | iced_x86::Mnemonic::Cdqe => {
            (vec!["rax".to_owned()], vec!["rax".to_owned()])
        }
        iced_x86::Mnemonic::Cwd => (
            vec!["rax".to_owned(), "rdx".to_owned()],
            vec!["rdx".to_owned()],
        ),
        iced_x86::Mnemonic::Cdq | iced_x86::Mnemonic::Cqo => {
            (vec!["rax".to_owned()], vec!["rdx".to_owned()])
        }
        _ => return None,
    };
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_push_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [source] = operands else {
        return None;
    };
    if operand_scalar_width(source) != Some(64)
        || !matches!(
            source,
            MachineOperand::Register { .. }
                | MachineOperand::Immediate { .. }
                | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_read_registers(source);
    read_registers.push("rsp".to_owned());
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec!["rsp".to_owned()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(source, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::Write
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_pop_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination] = operands else {
        return None;
    };
    if operand_scalar_width(destination) != Some(64)
        || !matches!(
            destination,
            MachineOperand::Register { .. } | MachineOperand::Memory { .. }
        )
    {
        return None;
    }
    let mut read_registers = operand_address_registers(destination);
    read_registers.push("rsp".to_owned());
    read_registers.sort();
    read_registers.dedup();
    let mut written_registers = vec!["rsp".to_owned()];
    if let MachineOperand::Register { name, .. } = destination {
        written_registers.push(name.clone());
        written_registers.sort();
        written_registers.dedup();
    }
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if matches!(destination, MachineOperand::Memory { .. }) {
            MachineMemoryEffect::ReadWrite
        } else {
            MachineMemoryEffect::Read
        },
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn generic_lea_effects(operands: &[MachineOperand]) -> Option<MachineEffects> {
    let [destination, source] = operands else {
        return None;
    };
    let MachineOperand::Register { name, width_bits } = destination else {
        return None;
    };
    if !matches!(width_bits, 16 | 32 | 64) || !matches!(source, MachineOperand::Memory { .. }) {
        return None;
    }
    let mut read_registers = operand_address_registers(source);
    if *width_bits == 16 {
        read_registers.push(name.clone());
    }
    read_registers.sort();
    read_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers: vec![name.clone()],
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::None,
        control: MachineControlEffect::Next,
        conservative: false,
    })
}

fn conditional_data_effects(
    instruction: &Instruction,
    family: &str,
    read_flags: Vec<String>,
) -> Option<MachineEffects> {
    for index in 0..instruction.op_count() {
        if instruction.op_kind(index) == OpKind::Register
            && !supported_gpr(instruction.op_register(index))
        {
            return None;
        }
    }
    let operands = machine_operands(instruction, 0);
    if family.starts_with("set") {
        let [destination] = operands.as_slice() else {
            return None;
        };
        if operand_scalar_width(destination) != Some(8)
            || !matches!(
                destination,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
        {
            return None;
        }
        let mut destination_reads = operand_address_registers(destination);
        if let MachineOperand::Register { name, .. } = destination {
            destination_reads.push(name.clone());
        }
        return Some(MachineEffects {
            read_registers: destination_reads,
            written_registers: match destination {
                MachineOperand::Register { name, .. } => vec![name.clone()],
                _ => Vec::new(),
            },
            read_flags,
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: if matches!(destination, MachineOperand::Memory { .. }) {
                MachineMemoryEffect::Write
            } else {
                MachineMemoryEffect::None
            },
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    if family.starts_with("cmov") {
        let [destination, source] = operands.as_slice() else {
            return None;
        };
        let width = operand_scalar_width(destination)?;
        if !matches!(width, 16 | 32 | 64)
            || operand_scalar_width(source) != Some(width)
            || !matches!(destination, MachineOperand::Register { .. })
            || !matches!(
                source,
                MachineOperand::Register { .. } | MachineOperand::Memory { .. }
            )
        {
            return None;
        }
        let mut read_registers = operand_read_registers(destination);
        read_registers.extend(operand_read_registers(source));
        read_registers.sort();
        read_registers.dedup();
        return Some(MachineEffects {
            read_registers,
            written_registers: match destination {
                MachineOperand::Register { name, .. } => vec![name.clone()],
                _ => Vec::new(),
            },
            read_flags,
            written_flags: Vec::new(),
            undefined_flags: Vec::new(),
            memory: if matches!(source, MachineOperand::Memory { .. }) {
                MachineMemoryEffect::Read
            } else {
                MachineMemoryEffect::None
            },
            control: MachineControlEffect::Next,
            conservative: false,
        });
    }
    None
}

fn condition_read_flags(family: &str) -> Option<Vec<String>> {
    let suffix = family
        .strip_prefix("set")
        .or_else(|| family.strip_prefix("cmov"))?;
    let names = match suffix {
        "e" | "z" | "ne" | "nz" => &["zf"][..],
        "s" | "ns" => &["sf"][..],
        "o" | "no" => &["of"][..],
        "p" | "pe" | "np" | "po" => &["pf"][..],
        "b" | "c" | "nae" | "ae" | "nb" | "nc" => &["cf"][..],
        "be" | "na" | "a" | "nbe" => &["cf", "zf"][..],
        "l" | "nge" | "ge" | "nl" => &["sf", "of"][..],
        "le" | "ng" | "g" | "nle" => &["zf", "sf", "of"][..],
        _ => return None,
    };
    Some(names.iter().map(|name| (*name).to_owned()).collect())
}

fn operand_scalar_width(operand: &MachineOperand) -> Option<u16> {
    match operand {
        MachineOperand::Register { width_bits, .. }
        | MachineOperand::Immediate { width_bits, .. }
        | MachineOperand::Memory { width_bits, .. } => Some(*width_bits),
        MachineOperand::Branch { .. } | MachineOperand::RelocatedBranch { .. } => None,
    }
}

fn operand_address_registers(operand: &MachineOperand) -> Vec<String> {
    match operand {
        MachineOperand::Memory { base, index, .. } => base.iter().chain(index).cloned().collect(),
        _ => Vec::new(),
    }
}

fn operand_read_registers(operand: &MachineOperand) -> Vec<String> {
    match operand {
        MachineOperand::Register { name, .. } => vec![name.clone()],
        MachineOperand::Memory { .. } => operand_address_registers(operand),
        _ => Vec::new(),
    }
}

fn supported_gpr(register: Register) -> bool {
    let raw = format!("{register:?}").to_ascii_lowercase();
    !matches!(raw.as_str(), "ah" | "bh" | "ch" | "dh")
        && matches!(register.size(), 1 | 2 | 4 | 8)
        && (ALL_REGISTERS.contains(&canonical_register(register).as_str()))
}

fn apply_control_relocations(
    machine: &mut MachineFunctionIr,
    spec: &ProgramSpec,
) -> Result<(), String> {
    let function_end = machine
        .entry
        .value
        .0
        .checked_add(machine.byte_length)
        .ok_or_else(|| {
            "MachineFunctionIR extent overflows while applying relocations".to_owned()
        })?;
    for relocation in spec.relocations.iter().filter(|relocation| {
        relocation.location_ref.is_some_and(|location| {
            location.address_space == machine.entry.address_space
                && (machine.entry.value.0..function_end).contains(&location.value.0)
        })
    }) {
        let relocation_site = relocation
            .location_ref
            .ok_or_else(|| "validated relocation has no canonical location".to_owned())?;
        let Some(instruction) = machine
            .blocks
            .iter_mut()
            .flat_map(|block| block.instructions.iter_mut())
            .find(|instruction| {
                let byte_length = u64::try_from(instruction.bytes_hex.len() / 2).unwrap_or(0);
                instruction.address.address_space == relocation_site.address_space
                    && instruction.address.value.0 <= relocation_site.value.0
                    && instruction
                        .address
                        .value
                        .0
                        .checked_add(byte_length)
                        .is_some_and(|end| relocation_site.value.0 < end)
            })
        else {
            continue;
        };
        if !matches!(
            instruction.effects.control,
            MachineControlEffect::DirectCall
                | MachineControlEffect::DirectBranch
                | MachineControlEffect::ConditionalBranch
        ) {
            continue;
        }
        let target = relocated_control_target(relocation);
        let symbol = relocation_target_name(&relocation.target);
        let mut replaced_operand = false;
        for operand in &mut instruction.operands {
            if matches!(
                operand,
                MachineOperand::Branch { .. } | MachineOperand::RelocatedBranch { .. }
            ) {
                *operand = MachineOperand::RelocatedBranch {
                    relocation: relocation_site,
                    target,
                    symbol: symbol.clone(),
                    relocation_kind: relocation.kind.clone(),
                };
                replaced_operand = true;
            }
        }
        if !replaced_operand {
            continue;
        }
        let edge = match instruction.effects.control {
            MachineControlEffect::DirectCall => instruction
                .edges
                .iter_mut()
                .find(|edge| edge.kind == MachineEdgeKind::Call),
            MachineControlEffect::DirectBranch => instruction.edges.iter_mut().find(|edge| {
                matches!(
                    edge.kind,
                    MachineEdgeKind::Direct
                        | MachineEdgeKind::External
                        | MachineEdgeKind::Unresolved
                )
            }),
            MachineControlEffect::ConditionalBranch => instruction
                .edges
                .iter_mut()
                .find(|edge| edge.kind == MachineEdgeKind::Taken),
            _ => None,
        };
        if let Some(edge) = edge {
            edge.target = target;
            if instruction.effects.control == MachineControlEffect::DirectBranch {
                edge.kind = target.map_or(MachineEdgeKind::Unresolved, |target| {
                    if target.address_space == machine.entry.address_space
                        && (machine.entry.value.0..function_end).contains(&target.value.0)
                    {
                        MachineEdgeKind::Direct
                    } else {
                        MachineEdgeKind::External
                    }
                });
            }
        }
        if let Some(target) = target {
            machine.diagnostics.push(IrDiagnostic {
                code: "relocation_control_target_resolved".to_owned(),
                message: format!(
                    "ELF {} relocation at {}:0x{:x} resolves {}control target to {}:0x{:x}",
                    relocation.kind,
                    relocation_site.address_space,
                    relocation_site.value.0,
                    symbol
                        .as_deref()
                        .map_or_else(String::new, |name| format!("{name:?} ")),
                    target.address_space,
                    target.value.0
                ),
                address: Some(instruction.address),
                blocks_stable_operation: false,
            });
        } else {
            machine.structural_completeness = StructuralCompleteness::Partial;
            machine.semantic_fidelity = SemanticFidelity::Conservative;
            machine.diagnostics.push(IrDiagnostic {
                code: "unresolved_relocation_control_target".to_owned(),
                message: format!(
                    "ELF {} relocation at {}:0x{:x} references {}without a defined canonical target",
                    relocation.kind,
                    relocation_site.address_space,
                    relocation_site.value.0,
                    symbol.as_deref().map_or_else(
                        || "an unresolved target ".to_owned(),
                        |name| format!("symbol {name:?} ")
                    )
                ),
                address: Some(instruction.address),
                blocks_stable_operation: true,
            });
        }
    }
    Ok(())
}

fn relocated_control_target(relocation: &RelocationSpec) -> Option<Location> {
    let base = match &relocation.target {
        RelocationTargetSpec::Symbol {
            location, defined, ..
        } if *defined => *location,
        RelocationTargetSpec::Section { location, .. } => *location,
        RelocationTargetSpec::Symbol { .. }
        | RelocationTargetSpec::Absolute
        | RelocationTargetSpec::Unresolved { .. } => None,
    }?;
    let encoded_next_ip_adjustment = if relocation.encoding == "X86Branch" {
        i64::from(relocation.size_bits / 8)
    } else {
        0
    };
    let adjustment = relocation.addend.checked_add(encoded_next_ip_adjustment)?;
    Some(Location {
        address_space: base.address_space,
        value: Address(base.value.0.checked_add_signed(adjustment)?),
    })
}

fn relocation_target_name(target: &RelocationTargetSpec) -> Option<String> {
    match target {
        RelocationTargetSpec::Symbol { name, .. } => name.clone().filter(|name| !name.is_empty()),
        RelocationTargetSpec::Section { name, .. } => Some(name.clone()),
        RelocationTargetSpec::Absolute | RelocationTargetSpec::Unresolved { .. } => None,
    }
}

fn location(address_space: u32, value: u64) -> Location {
    Location {
        address_space,
        value: Address(value),
    }
}

fn label(address: u64) -> String {
    format!("b_{address:016x}")
}

fn control_effect(instruction: &Instruction, invalid: bool) -> MachineControlEffect {
    if invalid {
        return MachineControlEffect::Unknown;
    }
    if instruction.mnemonic() == iced_x86::Mnemonic::Syscall {
        return MachineControlEffect::IndirectCall;
    }
    match instruction.flow_control() {
        FlowControl::Next => MachineControlEffect::Next,
        FlowControl::UnconditionalBranch => MachineControlEffect::DirectBranch,
        FlowControl::IndirectBranch => MachineControlEffect::IndirectBranch,
        FlowControl::ConditionalBranch => MachineControlEffect::ConditionalBranch,
        FlowControl::Return => MachineControlEffect::Return,
        FlowControl::Call => MachineControlEffect::DirectCall,
        FlowControl::IndirectCall => MachineControlEffect::IndirectCall,
        FlowControl::Interrupt | FlowControl::XbeginXabortXend | FlowControl::Exception => {
            MachineControlEffect::Stop
        }
    }
}

fn instruction_edges(
    instruction: &Instruction,
    invalid: bool,
    address_space: u32,
    start: u64,
    end: u64,
    stop_entries: &BTreeSet<u64>,
    indirect_targets: Option<&[u64]>,
) -> Vec<MachineEdge> {
    if invalid {
        return vec![MachineEdge {
            kind: MachineEdgeKind::Unresolved,
            target: None,
        }];
    }
    let at = |value| Some(location(address_space, value));
    if instruction.mnemonic() == iced_x86::Mnemonic::Syscall {
        return vec![
            MachineEdge {
                kind: MachineEdgeKind::Call,
                target: None,
            },
            MachineEdge {
                kind: if instruction.next_ip() < end
                    && !stop_entries.contains(&instruction.next_ip())
                {
                    MachineEdgeKind::Fallthrough
                } else {
                    MachineEdgeKind::External
                },
                target: at(instruction.next_ip()),
            },
        ];
    }
    let classify_target = |value| {
        if (start..end).contains(&value) && !stop_entries.contains(&value) {
            MachineEdgeKind::Direct
        } else {
            MachineEdgeKind::External
        }
    };
    match instruction.flow_control() {
        FlowControl::Next => vec![MachineEdge {
            kind: if instruction.next_ip() < end && !stop_entries.contains(&instruction.next_ip()) {
                MachineEdgeKind::Fallthrough
            } else {
                MachineEdgeKind::External
            },
            target: at(instruction.next_ip()),
        }],
        FlowControl::UnconditionalBranch => {
            let target = instruction.near_branch_target();
            vec![MachineEdge {
                kind: classify_target(target),
                target: at(target),
            }]
        }
        FlowControl::ConditionalBranch => {
            let target = instruction.near_branch_target();
            vec![
                MachineEdge {
                    kind: MachineEdgeKind::Taken,
                    target: at(target),
                },
                MachineEdge {
                    kind: if instruction.next_ip() < end
                        && !stop_entries.contains(&instruction.next_ip())
                    {
                        MachineEdgeKind::Fallthrough
                    } else {
                        MachineEdgeKind::External
                    },
                    target: at(instruction.next_ip()),
                },
            ]
        }
        FlowControl::Call => vec![
            MachineEdge {
                kind: MachineEdgeKind::Call,
                target: at(instruction.near_branch_target()),
            },
            MachineEdge {
                kind: if instruction.next_ip() < end
                    && !stop_entries.contains(&instruction.next_ip())
                {
                    MachineEdgeKind::Fallthrough
                } else {
                    MachineEdgeKind::External
                },
                target: at(instruction.next_ip()),
            },
        ],
        FlowControl::IndirectCall => {
            let mut edges = indirect_targets.map_or_else(
                || {
                    vec![MachineEdge {
                        kind: MachineEdgeKind::Call,
                        target: None,
                    }]
                },
                |targets| {
                    targets
                        .iter()
                        .map(|target| MachineEdge {
                            kind: MachineEdgeKind::Call,
                            target: at(*target),
                        })
                        .collect()
                },
            );
            edges.push(MachineEdge {
                kind: if instruction.next_ip() < end
                    && !stop_entries.contains(&instruction.next_ip())
                {
                    MachineEdgeKind::Fallthrough
                } else {
                    MachineEdgeKind::External
                },
                target: at(instruction.next_ip()),
            });
            edges
        }
        FlowControl::IndirectBranch => indirect_targets.map_or_else(
            || {
                vec![MachineEdge {
                    kind: MachineEdgeKind::Unresolved,
                    target: None,
                }]
            },
            |targets| {
                targets
                    .iter()
                    .map(|target| MachineEdge {
                        kind: MachineEdgeKind::IndirectTarget,
                        target: at(*target),
                    })
                    .collect()
            },
        ),
        FlowControl::Return
        | FlowControl::Interrupt
        | FlowControl::XbeginXabortXend
        | FlowControl::Exception => Vec::new(),
    }
}

fn machine_operands(instruction: &Instruction, address_space: u32) -> Vec<MachineOperand> {
    (0..instruction.op_count())
        .filter_map(|index| {
            let kind = instruction.op_kind(index);
            match kind {
                OpKind::Register => {
                    let register = instruction.op_register(index);
                    Some(MachineOperand::Register {
                        name: canonical_register(register),
                        width_bits: u16::try_from(register.size() * 8).unwrap_or(0),
                    })
                }
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    Some(MachineOperand::Branch {
                        target: location(address_space, instruction.near_branch_target()),
                    })
                }
                OpKind::Immediate8
                | OpKind::Immediate8_2nd
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64 => Some(MachineOperand::Immediate {
                    value: instruction.immediate(index),
                    width_bits: immediate_width(kind),
                }),
                OpKind::Memory
                | OpKind::MemorySegSI
                | OpKind::MemorySegESI
                | OpKind::MemorySegRSI
                | OpKind::MemorySegDI
                | OpKind::MemorySegEDI
                | OpKind::MemorySegRDI
                | OpKind::MemoryESDI
                | OpKind::MemoryESEDI
                | OpKind::MemoryESRDI => Some(MachineOperand::Memory {
                    segment: optional_register(instruction.segment_prefix()),
                    base: if instruction.is_ip_rel_memory_operand() {
                        None
                    } else {
                        optional_register(instruction.memory_base())
                    },
                    index: optional_register(instruction.memory_index()),
                    scale: instruction.memory_index_scale(),
                    displacement: if instruction.is_ip_rel_memory_operand() {
                        0
                    } else {
                        instruction.memory_displacement64() as i64
                    },
                    absolute: instruction
                        .is_ip_rel_memory_operand()
                        .then(|| instruction.ip_rel_memory_address()),
                    width_bits: machine_memory_width(instruction),
                }),
                _ => None,
            }
        })
        .collect()
}

fn instruction_decorators(instruction: &Instruction) -> InstructionDecorators {
    InstructionDecorators {
        op_mask: (instruction.op_mask() != Register::None)
            .then(|| format!("{:?}", instruction.op_mask()).to_ascii_lowercase()),
        zeroing: instruction.zeroing_masking(),
        broadcast: instruction.is_broadcast(),
        rounding: match instruction.rounding_control() {
            RoundingControl::None => None,
            RoundingControl::RoundToNearest => Some("nearest".to_owned()),
            RoundingControl::RoundDown => Some("down".to_owned()),
            RoundingControl::RoundUp => Some("up".to_owned()),
            RoundingControl::RoundTowardZero => Some("toward_zero".to_owned()),
        },
        suppress_all_exceptions: instruction.suppress_all_exceptions(),
    }
}

fn machine_memory_width(instruction: &Instruction) -> u16 {
    let decoded = u16::try_from(instruction.memory_size().size() * 8).unwrap_or(0);
    if decoded != 0 {
        return decoded;
    }
    if instruction.mnemonic() == iced_x86::Mnemonic::Lea {
        return u16::try_from(instruction.op0_register().size() * 8).unwrap_or(0);
    }
    0
}

fn immediate_width(kind: OpKind) -> u16 {
    match kind {
        OpKind::Immediate8 | OpKind::Immediate8_2nd => 8,
        OpKind::Immediate16 | OpKind::Immediate8to16 => 16,
        OpKind::Immediate32 | OpKind::Immediate8to32 => 32,
        OpKind::Immediate64 | OpKind::Immediate8to64 | OpKind::Immediate32to64 => 64,
        _ => 0,
    }
}

fn optional_register(register: Register) -> Option<String> {
    (register != Register::None).then(|| canonical_register(register))
}

fn canonical_register(register: Register) -> String {
    let raw = format!("{register:?}").to_ascii_lowercase();
    match raw.as_str() {
        "al" | "ah" | "ax" | "eax" => "rax".to_owned(),
        "bl" | "bh" | "bx" | "ebx" => "rbx".to_owned(),
        "cl" | "ch" | "cx" | "ecx" => "rcx".to_owned(),
        "dl" | "dh" | "dx" | "edx" => "rdx".to_owned(),
        "sil" | "si" | "esi" => "rsi".to_owned(),
        "dil" | "di" | "edi" => "rdi".to_owned(),
        "bpl" | "bp" | "ebp" => "rbp".to_owned(),
        "spl" | "sp" | "esp" => "rsp".to_owned(),
        _ if raw.starts_with('e') && raw.len() == 3 => format!("r{}", &raw[1..]),
        _ if raw.starts_with('r') && raw.ends_with('d') => raw.trim_end_matches('d').to_owned(),
        _ if raw.starts_with('r') && raw.ends_with('w') => raw.trim_end_matches('w').to_owned(),
        _ if raw.starts_with('r') && raw.ends_with('b') => raw.trim_end_matches('b').to_owned(),
        _ if raw.starts_with('r') && raw.ends_with('l') => raw.trim_end_matches('l').to_owned(),
        _ => raw,
    }
}

fn register_names(mask: u16) -> Vec<String> {
    [
        (RAX, "rax"),
        (RBX, "rbx"),
        (RCX, "rcx"),
        (RDX, "rdx"),
        (RSI, "rsi"),
        (RDI, "rdi"),
        (RBP, "rbp"),
        (RSP, "rsp"),
        (R8, "r8"),
        (R9, "r9"),
        (R10, "r10"),
        (R11, "r11"),
        (R12, "r12"),
        (R13, "r13"),
        (R14, "r14"),
        (R15, "r15"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, name)| name.to_owned())
    .collect()
}

fn flag_names(mask: u8) -> Vec<String> {
    [
        (ZF, "zf"),
        (SF, "sf"),
        (OF, "of"),
        (CF, "cf"),
        (PF, "pf"),
        (AF, "af"),
    ]
    .into_iter()
    .filter(|(bit, _)| mask & bit != 0)
    .map(|(_, name)| name.to_owned())
    .collect()
}

fn exact_effects(effects: Effects) -> MachineEffects {
    MachineEffects {
        read_registers: register_names(effects.read_registers),
        written_registers: register_names(effects.write_registers),
        read_flags: flag_names(effects.read_flags),
        written_flags: flag_names(effects.write_flags),
        undefined_flags: Vec::new(),
        memory: match effects.memory {
            MemoryEffect::None => MachineMemoryEffect::None,
            MemoryEffect::ReadReturnAddress
            | MemoryEffect::ReadSavedFramePointer
            | MemoryEffect::ReadSavedRegister
            | MemoryEffect::ReadStackLocal
            | MemoryEffect::ReadMappedMemory => MachineMemoryEffect::Read,
            MemoryEffect::WriteSavedFramePointer
            | MemoryEffect::WriteSavedRegister
            | MemoryEffect::WriteStackLocal
            | MemoryEffect::WriteMappedMemory
            | MemoryEffect::WriteReturnAddress => MachineMemoryEffect::Write,
            MemoryEffect::ReadWriteStackLocal => MachineMemoryEffect::ReadWrite,
        },
        control: match effects.control {
            ControlEffect::Next => MachineControlEffect::Next,
            ControlEffect::DirectBranch => MachineControlEffect::DirectBranch,
            ControlEffect::ConditionalBranch => MachineControlEffect::ConditionalBranch,
            ControlEffect::DirectCall => MachineControlEffect::DirectCall,
            ControlEffect::Return => MachineControlEffect::Return,
        },
        conservative: false,
    }
}

fn opaque_effects(control: MachineControlEffect) -> MachineEffects {
    MachineEffects {
        read_registers: ALL_REGISTERS.into_iter().map(str::to_owned).collect(),
        written_registers: ALL_REGISTERS.into_iter().map(str::to_owned).collect(),
        read_flags: MACHINE_FLAGS.into_iter().map(str::to_owned).collect(),
        written_flags: MACHINE_FLAGS.into_iter().map(str::to_owned).collect(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::Unknown,
        control,
        conservative: true,
    }
}

fn bounded_atomic_opaque_effects(
    instruction: &Instruction,
    control: MachineControlEffect,
) -> Option<MachineEffects> {
    let operands = machine_operands(instruction, 0);
    let has_memory_destination = matches!(operands.first(), Some(MachineOperand::Memory { .. }));
    if !(instruction.has_lock_prefix()
        || (instruction.mnemonic() == iced_x86::Mnemonic::Xchg && has_memory_destination))
    {
        return None;
    }
    let mut read_registers = operands
        .iter()
        .flat_map(operand_read_registers)
        .collect::<Vec<_>>();
    let mut written_registers = Vec::new();
    let written_flags = match instruction.mnemonic() {
        iced_x86::Mnemonic::Xadd => {
            let [destination, source @ MachineOperand::Register { name, .. }] = operands.as_slice()
            else {
                return None;
            };
            if !matches!(destination, MachineOperand::Memory { .. })
                || operand_scalar_width(destination) != operand_scalar_width(source)
            {
                return None;
            }
            written_registers.push(name.clone());
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        }
        iced_x86::Mnemonic::Cmpxchg => {
            let [destination, source @ MachineOperand::Register { .. }] = operands.as_slice()
            else {
                return None;
            };
            if !matches!(destination, MachineOperand::Memory { .. })
                || operand_scalar_width(destination) != operand_scalar_width(source)
            {
                return None;
            }
            read_registers.push("rax".to_owned());
            written_registers.push("rax".to_owned());
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        }
        iced_x86::Mnemonic::Xchg => {
            let [
                destination @ MachineOperand::Memory { .. },
                source @ MachineOperand::Register { name, .. },
            ] = operands.as_slice()
            else {
                return None;
            };
            if operand_scalar_width(destination) != operand_scalar_width(source) {
                return None;
            }
            written_registers.push(name.clone());
            Vec::new()
        }
        iced_x86::Mnemonic::Inc | iced_x86::Mnemonic::Dec => {
            ["zf", "sf", "of"].into_iter().map(str::to_owned).collect()
        }
        iced_x86::Mnemonic::Not => Vec::new(),
        iced_x86::Mnemonic::Add
        | iced_x86::Mnemonic::Adc
        | iced_x86::Mnemonic::Sub
        | iced_x86::Mnemonic::Sbb
        | iced_x86::Mnemonic::And
        | iced_x86::Mnemonic::Or
        | iced_x86::Mnemonic::Xor
        | iced_x86::Mnemonic::Neg => ALL_FLAGS.into_iter().map(str::to_owned).collect(),
        _ => return None,
    };
    read_registers.sort();
    read_registers.dedup();
    written_registers.sort();
    written_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: if matches!(
            instruction.mnemonic(),
            iced_x86::Mnemonic::Adc | iced_x86::Mnemonic::Sbb
        ) {
            vec!["cf".to_owned()]
        } else {
            Vec::new()
        },
        written_flags,
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::ReadWrite,
        control,
        conservative: true,
    })
}

fn bounded_extended_data_opaque_effects(
    instruction: &Instruction,
    control: MachineControlEffect,
) -> Option<MachineEffects> {
    if control != MachineControlEffect::Next || instruction.op_count() == 0 {
        return None;
    }
    let operands = machine_operands(instruction, 0);
    let extended_registers = operands
        .iter()
        .filter_map(|operand| match operand {
            MachineOperand::Register { name, .. } if is_extended_state_register(name) => {
                Some(name.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if extended_registers.is_empty() {
        return None;
    }
    let x87 = extended_registers
        .iter()
        .any(|name| name.starts_with("st") || name.starts_with("mm"));
    let mut read_registers = operands
        .iter()
        .flat_map(operand_read_registers)
        .collect::<Vec<_>>();
    if instruction.op_mask() != Register::None {
        read_registers.push(format!("{:?}", instruction.op_mask()).to_ascii_lowercase());
    }
    let mut written_registers = match operands.first() {
        Some(MachineOperand::Register { name, .. }) => vec![name.clone()],
        _ => Vec::new(),
    };
    if x87 {
        for index in 0..8 {
            read_registers.push(format!("st{index}"));
            written_registers.push(format!("st{index}"));
        }
        read_registers.push("x87_status".to_owned());
        written_registers.push("x87_status".to_owned());
    } else {
        read_registers.push("mxcsr".to_owned());
        written_registers.push("mxcsr".to_owned());
    }
    read_registers.sort();
    read_registers.dedup();
    written_registers.sort();
    written_registers.dedup();
    let writes_integer_flags = matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Comiss
            | iced_x86::Mnemonic::Ucomiss
            | iced_x86::Mnemonic::Comisd
            | iced_x86::Mnemonic::Ucomisd
    );
    let has_memory = operands
        .iter()
        .any(|operand| matches!(operand, MachineOperand::Memory { .. }));
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags: if writes_integer_flags {
            ALL_FLAGS.into_iter().map(str::to_owned).collect()
        } else {
            Vec::new()
        },
        undefined_flags: Vec::new(),
        memory: if matches!(operands.first(), Some(MachineOperand::Memory { .. })) {
            MachineMemoryEffect::ReadWrite
        } else if has_memory {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::None
        },
        control,
        conservative: true,
    })
}

fn is_xsave_instruction(mnemonic: iced_x86::Mnemonic) -> bool {
    matches!(
        mnemonic,
        iced_x86::Mnemonic::Xsave
            | iced_x86::Mnemonic::Xsave64
            | iced_x86::Mnemonic::Xsaveopt
            | iced_x86::Mnemonic::Xsaveopt64
            | iced_x86::Mnemonic::Xsavec
            | iced_x86::Mnemonic::Xsavec64
            | iced_x86::Mnemonic::Xsaves
            | iced_x86::Mnemonic::Xsaves64
            | iced_x86::Mnemonic::Xrstor
            | iced_x86::Mnemonic::Xrstor64
            | iced_x86::Mnemonic::Xrstors
            | iced_x86::Mnemonic::Xrstors64
    )
}

fn bounded_xsave_opaque_effects(
    instruction: &Instruction,
    control: MachineControlEffect,
) -> Option<MachineEffects> {
    if control != MachineControlEffect::Next || !is_xsave_instruction(instruction.mnemonic()) {
        return None;
    }
    let operands = machine_operands(instruction, 0);
    let [memory @ MachineOperand::Memory { .. }] = operands.as_slice() else {
        return None;
    };
    let restore = matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Xrstor
            | iced_x86::Mnemonic::Xrstor64
            | iced_x86::Mnemonic::Xrstors
            | iced_x86::Mnemonic::Xrstors64
    );
    let supervisor = matches!(
        instruction.mnemonic(),
        iced_x86::Mnemonic::Xsaves
            | iced_x86::Mnemonic::Xsaves64
            | iced_x86::Mnemonic::Xrstors
            | iced_x86::Mnemonic::Xrstors64
    );
    let extended_state = || {
        (0..8)
            .map(|index| format!("st{index}"))
            .chain((0..32).map(|index| format!("zmm{index}")))
            .chain((0..8).map(|index| format!("k{index}")))
            .chain(
                [
                    "mxcsr",
                    "x87_control",
                    "x87_status",
                    "x87_tag",
                    "x87_instruction_pointer",
                    "x87_data_pointer",
                    "x87_opcode",
                    "pkru",
                    "extended_state_unknown",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .collect::<Vec<_>>()
    };
    let mut read_registers = operand_address_registers(memory);
    read_registers.extend(["rax", "rdx", "xcr0"].into_iter().map(str::to_owned));
    if supervisor {
        read_registers.push("ia32_xss".to_owned());
    }
    let mut written_registers = Vec::new();
    if restore {
        written_registers.extend(extended_state());
    } else {
        read_registers.extend(extended_state());
    }
    read_registers.sort();
    read_registers.dedup();
    written_registers.sort();
    written_registers.dedup();
    Some(MachineEffects {
        read_registers,
        written_registers,
        read_flags: Vec::new(),
        written_flags: Vec::new(),
        undefined_flags: Vec::new(),
        memory: if restore {
            MachineMemoryEffect::Read
        } else {
            MachineMemoryEffect::Write
        },
        control,
        conservative: true,
    })
}

fn bounded_system_opaque_effects(
    instruction: &Instruction,
    control: MachineControlEffect,
) -> Option<MachineEffects> {
    if instruction.mnemonic() != iced_x86::Mnemonic::Syscall
        || instruction.op_count() != 0
        || control != MachineControlEffect::IndirectCall
    {
        return None;
    }
    Some(MachineEffects {
        read_registers: ["r10", "r8", "r9", "rax", "rdi", "rdx", "rsi"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        written_registers: ["r11", "rax", "rcx"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        read_flags: MACHINE_FLAGS.into_iter().map(str::to_owned).collect(),
        written_flags: MACHINE_FLAGS.into_iter().map(str::to_owned).collect(),
        undefined_flags: Vec::new(),
        memory: MachineMemoryEffect::Unknown,
        control,
        conservative: true,
    })
}

fn is_extended_state_register(name: &str) -> bool {
    ["xmm", "ymm", "zmm", "st", "mm", "k"]
        .into_iter()
        .any(|prefix| {
            name.strip_prefix(prefix)
                .is_some_and(|index| index.parse::<u8>().is_ok())
        })
}

pub fn lower_state_ir(machine: &MachineFunctionIr) -> Result<StateFunctionIr, String> {
    validate_machine_function_ir(machine)?;
    let mut next_state = 1u32;
    let mut input_states = BTreeMap::from([(machine.entry, 0u32)]);
    for block in &machine.blocks {
        if block.address != machine.entry {
            input_states.insert(block.address, next_state);
            next_state = next_state
                .checked_add(1)
                .ok_or_else(|| "StateFunctionIR state version overflows".to_owned())?;
        }
    }
    let mut output_states = BTreeMap::new();
    let mut blocks = Vec::with_capacity(machine.blocks.len());
    for block in &machine.blocks {
        let input_state = *input_states
            .get(&block.address)
            .ok_or_else(|| "StateFunctionIR block input state is missing".to_owned())?;
        let mut operation_input = input_state;
        let mut operations = Vec::with_capacity(block.instructions.len());
        for instruction in &block.instructions {
            let output_state = next_state;
            next_state = next_state
                .checked_add(1)
                .ok_or_else(|| "StateFunctionIR state version overflows".to_owned())?;
            operations.push(match &instruction.operation {
                MachineOperation::Exact { family } => StateOperation::Exact {
                    address: instruction.address,
                    family: family.clone(),
                    operands: instruction.operands.clone(),
                    decorators: instruction.decorators.clone(),
                    input_components: Vec::new(),
                    output_components: Vec::new(),
                    undefined_outputs: instruction
                        .effects
                        .undefined_flags
                        .iter()
                        .map(|flag| format!("flag:{flag}"))
                        .collect(),
                    input_state: operation_input,
                    output_state,
                },
                MachineOperation::OpaqueEffect { reason } => StateOperation::Unknown {
                    address: instruction.address,
                    reason: reason.clone(),
                    input_components: Vec::new(),
                    output_components: Vec::new(),
                    input_state: operation_input,
                    output_state,
                },
            });
            operation_input = output_state;
        }
        output_states.insert(block.address, operation_input);
        blocks.push(StateBlock {
            label: block.label.clone(),
            address: block.address,
            operations,
            edges: block
                .instructions
                .last()
                .map(|instruction| instruction.edges.clone())
                .unwrap_or_default(),
            state_flow: Some(StateBlockFlow {
                input_state,
                output_state: operation_input,
                incoming: Vec::new(),
                component_phis: Vec::new(),
                component_outputs: Vec::new(),
            }),
        });
    }
    let block_addresses = blocks
        .iter()
        .map(|block| block.address)
        .collect::<BTreeSet<_>>();
    let mut incoming = BTreeMap::<Location, BTreeMap<Location, u32>>::new();
    for block in &blocks {
        let output_state = *output_states
            .get(&block.address)
            .ok_or_else(|| "StateFunctionIR block output state is missing".to_owned())?;
        for target in block
            .edges
            .iter()
            .filter(|edge| edge.kind != MachineEdgeKind::Call)
            .filter_map(|edge| edge.target)
            .filter(|target| block_addresses.contains(target))
        {
            incoming
                .entry(target)
                .or_default()
                .insert(block.address, output_state);
        }
    }
    for block in &mut blocks {
        if let Some(flow) = &mut block.state_flow {
            flow.incoming = incoming
                .remove(&block.address)
                .unwrap_or_default()
                .into_iter()
                .map(|(predecessor, state)| StateIncoming { predecessor, state })
                .collect();
        }
    }
    populate_component_ssa(machine, &mut blocks)?;
    let ir = StateFunctionIr {
        schema_version: STATE_FUNCTION_IR_VERSION,
        binary_sha256: machine.binary_sha256.clone(),
        function_id: machine.function_id.clone(),
        entry: machine.entry,
        blocks,
        structural_completeness: machine.structural_completeness,
        semantic_fidelity: machine.semantic_fidelity,
        verification: VerificationStatus::StaticallyValidated,
        diagnostics: machine.diagnostics.clone(),
    };
    validate_state_function_ir(&ir)?;
    Ok(ir)
}

fn populate_component_ssa(
    machine: &MachineFunctionIr,
    blocks: &mut [StateBlock],
) -> Result<(), String> {
    let components = machine_state_components(machine);
    let mut next_versions = components
        .iter()
        .cloned()
        .map(|component| (component, 1u32))
        .collect::<BTreeMap<_, _>>();
    let entry_versions = components
        .iter()
        .cloned()
        .map(|component| (component, 0u32))
        .collect::<BTreeMap<_, _>>();
    let mut block_inputs = BTreeMap::<Location, BTreeMap<String, u32>>::new();
    for block in &machine.blocks {
        let versions = if block.address == machine.entry {
            entry_versions.clone()
        } else {
            let mut versions = BTreeMap::new();
            for component in &components {
                versions.insert(
                    component.clone(),
                    allocate_component_version(&mut next_versions, component)?,
                );
            }
            versions
        };
        block_inputs.insert(block.address, versions);
    }

    let mut block_outputs = BTreeMap::<Location, BTreeMap<String, u32>>::new();
    for (machine_block, state_block) in machine.blocks.iter().zip(blocks.iter_mut()) {
        let mut current = block_inputs
            .get(&machine_block.address)
            .cloned()
            .ok_or_else(|| "component SSA block input is missing".to_owned())?;
        if machine_block.instructions.len() != state_block.operations.len() {
            return Err("component SSA operation count differs from MachineIR".to_owned());
        }
        for (instruction, operation) in machine_block
            .instructions
            .iter()
            .zip(state_block.operations.iter_mut())
        {
            let (inputs, outputs) = instruction_components(instruction);
            let input_components = inputs
                .iter()
                .map(|component| {
                    Ok(StateComponentVersion {
                        component: component.clone(),
                        version: *current.get(component).ok_or_else(|| {
                            format!("component SSA input {component} is unversioned")
                        })?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            let mut output_components = Vec::with_capacity(outputs.len());
            for component in outputs {
                let version = allocate_component_version(&mut next_versions, &component)?;
                current.insert(component.clone(), version);
                output_components.push(StateComponentVersion { component, version });
            }
            match operation {
                StateOperation::Exact {
                    input_components: operation_inputs,
                    output_components: operation_outputs,
                    ..
                }
                | StateOperation::Unknown {
                    input_components: operation_inputs,
                    output_components: operation_outputs,
                    ..
                } => {
                    *operation_inputs = input_components;
                    *operation_outputs = output_components;
                }
            }
        }
        block_outputs.insert(machine_block.address, current);
    }

    for block in blocks {
        let input_versions = block_inputs
            .get(&block.address)
            .ok_or_else(|| "component SSA flow input is missing".to_owned())?;
        let output_versions = block_outputs
            .get(&block.address)
            .ok_or_else(|| "component SSA flow output is missing".to_owned())?;
        let flow = block
            .state_flow
            .as_mut()
            .ok_or_else(|| "component SSA requires block flow metadata".to_owned())?;
        flow.component_phis = components
            .iter()
            .map(|component| {
                let incoming = flow
                    .incoming
                    .iter()
                    .map(|incoming| {
                        Ok(StateComponentIncoming {
                            predecessor: incoming.predecessor,
                            version: *block_outputs
                                .get(&incoming.predecessor)
                                .and_then(|versions| versions.get(component))
                                .ok_or_else(|| {
                                    format!(
                                        "component SSA predecessor {:?} output is missing",
                                        incoming.predecessor
                                    )
                                })?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                Ok(StateComponentPhi {
                    component: component.clone(),
                    output_version: *input_versions
                        .get(component)
                        .ok_or_else(|| format!("component SSA phi {component} is unversioned"))?,
                    incoming,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        flow.component_outputs = output_versions
            .iter()
            .map(|(component, version)| StateComponentVersion {
                component: component.clone(),
                version: *version,
            })
            .collect();
    }
    Ok(())
}

fn machine_state_components(machine: &MachineFunctionIr) -> Vec<String> {
    let mut components = ALL_REGISTERS
        .iter()
        .map(|name| format!("register:{name}"))
        .chain(MACHINE_FLAGS.iter().map(|name| format!("flag:{name}")))
        .chain(
            [
                "memory:stack",
                "memory:image",
                "memory:tls",
                "memory:heap",
                "memory:volatile",
                "memory:unknown",
                "control",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .collect::<BTreeSet<_>>();
    components.extend(
        machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .flat_map(|instruction| {
                instruction
                    .effects
                    .read_registers
                    .iter()
                    .chain(&instruction.effects.written_registers)
            })
            .map(|name| format!("register:{}", register_component_name(name))),
    );
    components.into_iter().collect()
}

fn register_component_name(name: &str) -> String {
    ["xmm", "ymm", "zmm"]
        .into_iter()
        .find_map(|prefix| name.strip_prefix(prefix))
        .filter(|index| index.parse::<u8>().is_ok_and(|index| index < 32))
        .map_or_else(|| name.to_owned(), |index| format!("ymm{index}"))
}

fn allocate_component_version(
    next_versions: &mut BTreeMap<String, u32>,
    component: &str,
) -> Result<u32, String> {
    let next = next_versions
        .get_mut(component)
        .ok_or_else(|| format!("component SSA does not recognize {component}"))?;
    let version = *next;
    *next = next
        .checked_add(1)
        .ok_or_else(|| format!("component SSA version for {component} overflows"))?;
    Ok(version)
}

fn instruction_components(
    instruction: &MachineInstruction,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut inputs = instruction
        .effects
        .read_registers
        .iter()
        .map(|name| format!("register:{}", register_component_name(name)))
        .chain(
            instruction
                .effects
                .read_flags
                .iter()
                .map(|name| format!("flag:{name}")),
        )
        .collect::<BTreeSet<_>>();
    let mut outputs = instruction
        .effects
        .written_registers
        .iter()
        .map(|name| format!("register:{}", register_component_name(name)))
        .chain(
            instruction
                .effects
                .written_flags
                .iter()
                .chain(&instruction.effects.undefined_flags)
                .map(|name| format!("flag:{name}")),
        )
        .collect::<BTreeSet<_>>();
    let memory_regions = instruction_memory_regions(instruction);
    if matches!(
        instruction.effects.memory,
        MachineMemoryEffect::Read
            | MachineMemoryEffect::ReadWrite
            | MachineMemoryEffect::Fence
            | MachineMemoryEffect::Unknown
    ) {
        inputs.extend(memory_regions.iter().cloned());
    }
    if matches!(
        instruction.effects.memory,
        MachineMemoryEffect::Write
            | MachineMemoryEffect::ReadWrite
            | MachineMemoryEffect::Fence
            | MachineMemoryEffect::Unknown
    ) {
        // A memory definition also consumes its previous version so stores
        // cannot be reordered across other effects in the same region.
        inputs.extend(memory_regions.iter().cloned());
        outputs.extend(memory_regions);
    }
    if instruction.effects.control != MachineControlEffect::Next {
        inputs.insert("control".to_owned());
        outputs.insert("control".to_owned());
    }
    (inputs, outputs)
}

fn instruction_memory_regions(instruction: &MachineInstruction) -> BTreeSet<String> {
    if matches!(
        instruction.effects.memory,
        MachineMemoryEffect::Fence | MachineMemoryEffect::Unknown
    ) {
        return [
            "memory:stack",
            "memory:image",
            "memory:tls",
            "memory:heap",
            "memory:volatile",
            "memory:unknown",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
    }
    let mut regions = instruction
        .operands
        .iter()
        .filter_map(|operand| {
            let MachineOperand::Memory {
                segment,
                base,
                absolute,
                ..
            } = operand
            else {
                return None;
            };
            Some(
                if segment
                    .as_deref()
                    .is_some_and(|name| matches!(name, "fs" | "gs"))
                {
                    "memory:tls"
                } else if base
                    .as_deref()
                    .is_some_and(|name| matches!(name, "rsp" | "rbp"))
                {
                    "memory:stack"
                } else if absolute.is_some() {
                    "memory:image"
                } else {
                    "memory:unknown"
                },
            )
        })
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if instruction.effects.memory != MachineMemoryEffect::None
        && matches!(
            instruction.mnemonic.as_str(),
            "push" | "pop" | "leave" | "call" | "ret"
        )
    {
        regions.insert("memory:stack".to_owned());
    } else if regions.is_empty() && instruction.effects.memory != MachineMemoryEffect::None {
        regions.insert("memory:unknown".to_owned());
    }
    if regions.contains("memory:unknown") {
        // A non-stack, non-image, non-TLS pointer may designate a recovered
        // heap allocation, but without provenance it must continue to alias
        // the unknown region as well.
        regions.insert("memory:heap".to_owned());
    }
    let ordered_memory = instruction.effects.memory == MachineMemoryEffect::Fence
        || matches!(
            &instruction.operation,
            MachineOperation::Exact { family }
                if family.starts_with("lock_")
                    || matches!(family.as_str(), "atomic_xchg" | "cmpxchg8b" | "cmpxchg16b" | "lock_cmpxchg8b" | "lock_cmpxchg16b" | "vmovntdq")
        );
    if ordered_memory {
        regions.insert("memory:volatile".to_owned());
    }
    regions
}

pub fn lower_function_ir(
    machine: &MachineFunctionIr,
    state: &StateFunctionIr,
) -> Result<FunctionIr, String> {
    validate_machine_function_ir(machine)?;
    validate_state_function_ir(state)?;
    if machine.binary_sha256 != state.binary_sha256
        || machine.function_id != state.function_id
        || machine.entry != state.entry
    {
        return Err("MachineFunctionIR and StateFunctionIR identities differ".to_owned());
    }
    let (stack_objects, global_objects, calls, mut alias_sets) = recover_function_facts(machine);
    let (parameters, returns, abi_diagnostics) = infer_sysv_abi(machine, &stack_objects);
    let pointer_provenance = recover_pointer_provenance(machine, &parameters, &calls);
    let uncertain_pointer_ids = pointer_provenance
        .iter()
        .filter(|pointer| {
            pointer
                .target_regions
                .iter()
                .any(|region| region == "unknown")
        })
        .map(|pointer| pointer.id.clone())
        .collect::<Vec<_>>();
    if uncertain_pointer_ids.len() > 1 {
        alias_sets.push(AliasSet {
            id: "pointer_unknown_alias".to_owned(),
            members: uncertain_pointer_ids,
            evidence: "pointer values targeting the unknown region may alias until allocation- or type-specific evidence separates them"
                .to_owned(),
        });
    }
    let mut diagnostics = state.diagnostics.clone();
    diagnostics.extend(abi_diagnostics);
    let ir = FunctionIr {
        schema_version: FUNCTION_IR_VERSION,
        binary_sha256: state.binary_sha256.clone(),
        function_id: state.function_id.clone(),
        name: machine.name.clone(),
        entry: state.entry,
        calling_convention: "sysv_amd64_partial".to_owned(),
        parameters,
        returns,
        stack_objects,
        global_objects,
        calls,
        alias_sets,
        pointer_provenance,
        blocks: state.blocks.clone(),
        structural_completeness: state.structural_completeness,
        semantic_fidelity: state.semantic_fidelity,
        verification: VerificationStatus::StaticallyValidated,
        rewrite_ready: false,
        diagnostics,
    };
    validate_function_ir(&ir)?;
    Ok(ir)
}

fn recover_pointer_provenance(
    machine: &MachineFunctionIr,
    parameters: &[AbiValue],
    calls: &[FunctionCall],
) -> Vec<PointerProvenance> {
    let mut pointers = parameters
        .iter()
        .filter(|parameter| parameter.type_name.contains('*'))
        .map(|parameter| PointerProvenance {
            id: format!("pointer_parameter_{}", parameter.location),
            value_location: parameter.location.clone(),
            origin: PointerOriginKind::Parameter,
            target_regions: vec!["heap".to_owned(), "unknown".to_owned()],
            sites: vec![machine.entry],
            evidence: parameter.evidence.clone(),
        })
        .collect::<Vec<_>>();

    for instruction in machine.blocks.iter().flat_map(|block| &block.instructions) {
        let MachineOperation::Exact { family } = &instruction.operation else {
            continue;
        };
        let [
            MachineOperand::Register { name, .. },
            MachineOperand::Memory {
                segment,
                base,
                absolute,
                ..
            },
        ] = instruction.operands.as_slice()
        else {
            continue;
        };
        if family != "lea" {
            continue;
        }
        let recovered = if segment
            .as_deref()
            .is_some_and(|segment| matches!(segment, "fs" | "gs"))
        {
            Some((
                PointerOriginKind::TlsAddress,
                "tls",
                "segment-relative TLS address",
            ))
        } else if base
            .as_deref()
            .is_some_and(|base| matches!(base, "rsp" | "rbp"))
        {
            Some((
                PointerOriginKind::StackAddress,
                "stack",
                "stack-frame address",
            ))
        } else if absolute.is_some() {
            Some((
                PointerOriginKind::ImageAddress,
                "image",
                "mapped-image address",
            ))
        } else {
            None
        };
        let Some((origin, region, description)) = recovered else {
            continue;
        };
        pointers.push(PointerProvenance {
            id: format!(
                "pointer_{region}_{}_{}_{:x}",
                instruction.address.address_space, name, instruction.address.value.0
            ),
            value_location: name.clone(),
            origin,
            target_regions: vec![region.to_owned()],
            sites: vec![instruction.address],
            evidence: vec![format!(
                "exact LEA forms a {description} at {}:0x{:x}",
                instruction.address.address_space, instruction.address.value.0
            )],
        });
    }

    for call in calls {
        let Some(symbol) = call
            .symbol
            .as_deref()
            .and_then(|symbol| symbol.split('@').next())
        else {
            continue;
        };
        let origin = if matches!(
            symbol,
            "malloc" | "calloc" | "realloc" | "aligned_alloc" | "_Znwm" | "_Znam"
        ) {
            Some(PointerOriginKind::AllocatorReturn)
        } else if symbol == "mmap" {
            Some(PointerOriginKind::MappedReturn)
        } else {
            None
        };
        let Some(origin) = origin else {
            continue;
        };
        pointers.push(PointerProvenance {
            id: format!(
                "pointer_call_result_{}_{:x}",
                call.site.address_space, call.site.value.0
            ),
            value_location: "rax".to_owned(),
            origin,
            target_regions: vec!["heap".to_owned()],
            sites: vec![call.site],
            evidence: vec![format!(
                "audited {symbol} return contract produces a pointer in RAX"
            )],
        });
    }
    pointers.sort_by(|left, right| left.id.cmp(&right.id));
    pointers
}

fn infer_sysv_abi(
    machine: &MachineFunctionIr,
    stack_objects: &[StackObject],
) -> (Vec<AbiValue>, Vec<AbiValue>, Vec<IrDiagnostic>) {
    const ARGUMENT_REGISTERS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    const VECTOR_ARGUMENT_REGISTERS: [&str; 8] = [
        "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
    ];
    const CALL_DEFINED_REGISTERS: [&str; 25] = [
        "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "ymm0", "ymm1", "ymm2",
        "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13",
        "ymm14", "ymm15",
    ];
    let blocks = machine
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let mut inputs = blocks
        .keys()
        .map(|address| (*address, None::<BTreeSet<String>>))
        .collect::<BTreeMap<_, _>>();
    inputs.insert(machine.entry, Some(BTreeSet::new()));
    let mut outputs = BTreeMap::<Location, BTreeSet<String>>::new();
    let mut parameter_evidence = BTreeMap::<String, BTreeSet<String>>::new();
    let mut pointer_parameters = BTreeSet::<String>::new();
    let mut vector_parameter_widths = BTreeMap::<String, u16>::new();
    let mut vector_return_widths = BTreeMap::<String, u16>::new();
    let mut vector_parameter_types = BTreeMap::<String, BTreeSet<String>>::new();
    let mut vector_return_types = BTreeMap::<String, BTreeSet<String>>::new();
    let mut omitted_parameter_evidence = 0usize;
    let mut pending = VecDeque::from([machine.entry]);
    let mut saw_opaque = false;
    while let Some(address) = pending.pop_front() {
        let Some(block) = blocks.get(&address) else {
            continue;
        };
        let Some(mut defined) = inputs.get(&address).cloned().flatten() else {
            continue;
        };
        for instruction in &block.instructions {
            match &instruction.operation {
                MachineOperation::Exact { family } => {
                    let semantic_inputs = abi_semantic_input_registers(instruction);
                    for base in instruction
                        .operands
                        .iter()
                        .filter_map(|operand| match operand {
                            MachineOperand::Memory { base, .. } => base.as_deref(),
                            _ => None,
                        })
                    {
                        if ARGUMENT_REGISTERS.contains(&base) && !defined.contains(base) {
                            pointer_parameters.insert(base.to_owned());
                            record_abi_parameter_evidence(
                                &mut parameter_evidence,
                                base,
                                format!(
                                    "used as a memory base before a must-definition at {}:0x{:x}",
                                    instruction.address.address_space, instruction.address.value.0
                                ),
                                &mut omitted_parameter_evidence,
                            );
                        }
                    }
                    for register in ARGUMENT_REGISTERS {
                        if semantic_inputs.contains(register) && !defined.contains(register) {
                            record_abi_parameter_evidence(
                                &mut parameter_evidence,
                                register,
                                format!(
                                    "read before a must-definition at {}:0x{:x}",
                                    instruction.address.address_space, instruction.address.value.0
                                ),
                                &mut omitted_parameter_evidence,
                            );
                        }
                    }
                    for (register, width) in instruction
                        .effects
                        .read_registers
                        .iter()
                        .filter_map(|register| abi_vector_register(register))
                    {
                        if semantic_inputs.contains(&register) && !defined.contains(&register) {
                            record_abi_parameter_evidence(
                                &mut parameter_evidence,
                                &register,
                                format!(
                                    "read before a must-definition at {}:0x{:x}",
                                    instruction.address.address_space, instruction.address.value.0
                                ),
                                &mut omitted_parameter_evidence,
                            );
                            vector_parameter_widths
                                .entry(register.clone())
                                .and_modify(|known| *known = (*known).max(width))
                                .or_insert(width);
                            if let Some(type_name) = recovered_vector_type(family, width, false) {
                                vector_parameter_types
                                    .entry(register)
                                    .or_default()
                                    .insert(type_name);
                            }
                        }
                    }
                    for (register, width) in instruction
                        .effects
                        .written_registers
                        .iter()
                        .filter_map(|register| abi_vector_register(register))
                    {
                        vector_return_widths
                            .entry(register.clone())
                            .and_modify(|known| *known = (*known).max(width))
                            .or_insert(width);
                        if let Some(type_name) = recovered_vector_type(family, width, true) {
                            vector_return_types
                                .entry(register)
                                .or_default()
                                .insert(type_name);
                        }
                    }
                    defined.extend(
                        instruction
                            .effects
                            .written_registers
                            .iter()
                            .map(|register| register_component_name(register)),
                    );
                    if matches!(
                        instruction.effects.control,
                        MachineControlEffect::DirectCall | MachineControlEffect::IndirectCall
                    ) {
                        defined.extend(CALL_DEFINED_REGISTERS.into_iter().map(str::to_owned));
                    }
                }
                MachineOperation::OpaqueEffect { .. } => {
                    saw_opaque = true;
                    defined.extend(
                        instruction
                            .effects
                            .written_registers
                            .iter()
                            .map(|register| register_component_name(register)),
                    );
                }
            }
        }
        outputs.insert(address, defined.clone());
        for target in block
            .instructions
            .last()
            .into_iter()
            .flat_map(|instruction| &instruction.edges)
            .filter(|edge| edge.kind != MachineEdgeKind::Call)
            .filter_map(|edge| edge.target)
            .filter(|target| blocks.contains_key(target))
        {
            let changed = match inputs.get(&target).cloned().flatten() {
                None => {
                    inputs.insert(target, Some(defined.clone()));
                    true
                }
                Some(previous) => {
                    let intersection = previous
                        .intersection(&defined)
                        .cloned()
                        .collect::<BTreeSet<_>>();
                    if intersection != previous {
                        inputs.insert(target, Some(intersection));
                        true
                    } else {
                        false
                    }
                }
            };
            if changed {
                pending.push_back(target);
            }
        }
    }
    let mut parameters = ARGUMENT_REGISTERS
        .into_iter()
        .enumerate()
        .filter_map(|(index, register)| {
            let evidence = parameter_evidence.remove(register)?;
            Some(AbiValue {
                name: format!("arg{index}"),
                location: register.to_owned(),
                type_name: if pointer_parameters.contains(register) {
                    "void *".to_owned()
                } else {
                    "u64_machine_word".to_owned()
                },
                inferred: true,
                evidence: evidence.into_iter().collect(),
            })
        })
        .collect::<Vec<_>>();
    parameters.extend(
        VECTOR_ARGUMENT_REGISTERS
            .into_iter()
            .enumerate()
            .filter_map(|(index, register)| {
                let evidence = parameter_evidence.remove(register)?;
                let width = vector_parameter_widths
                    .get(register)
                    .copied()
                    .unwrap_or(128);
                let recovered_type = unique_recovered_type(&vector_parameter_types, register);
                let mut evidence = evidence.into_iter().collect::<Vec<_>>();
                if let Some(type_name) = &recovered_type {
                    evidence.push(format!(
                        "{type_name} follows from exact SSE/AVX arithmetic use"
                    ));
                }
                Some(AbiValue {
                    name: format!("vector_arg{index}"),
                    location: match width {
                        128 => register.replacen("ymm", "xmm", 1),
                        256 => register.to_owned(),
                        512 => register.replacen("ymm", "zmm", 1),
                        _ => register.to_owned(),
                    },
                    type_name: recovered_type.unwrap_or_else(|| format!("u{width}_vector")),
                    inferred: true,
                    evidence,
                })
            }),
    );
    parameters.extend(
        stack_objects
            .iter()
            .filter(|object| {
                object.base_register == "entry_rsp"
                    && object.displacement >= 8
                    && object.access == RecoveredAccessKind::Read
            })
            .enumerate()
            .map(|(index, object)| AbiValue {
                name: format!("stack_arg{index}"),
                location: format!("entry_rsp+{}", object.displacement),
                type_name: format!("u{}_machine_value", object.width_bits),
                inferred: true,
                evidence: vec![format!(
                    "read-only normalized stack object {} is above the entry return address",
                    object.id
                )],
            }),
    );
    let return_blocks = machine
        .blocks
        .iter()
        .filter(|block| {
            block.instructions.last().is_some_and(|instruction| {
                instruction.effects.control == MachineControlEffect::Return
            })
        })
        .collect::<Vec<_>>();
    let is_return_defined = |register: &str| {
        !return_blocks.is_empty()
            && return_blocks.iter().all(|block| {
                outputs
                    .get(&block.address)
                    .is_some_and(|defined| defined.contains(register))
            })
    };
    let mut returns = Vec::new();
    if is_return_defined("rax") {
        returns.push(AbiValue {
            name: "return_value".to_owned(),
            location: "rax".to_owned(),
            type_name: "u64_machine_word".to_owned(),
            inferred: true,
            evidence: vec![format!(
                "rax has a must-definition at all {} recovered return site(s)",
                return_blocks.len()
            )],
        });
        if is_return_defined("rdx") {
            returns.push(AbiValue {
                name: "return_value_high".to_owned(),
                location: "rdx".to_owned(),
                type_name: "u64_machine_word".to_owned(),
                inferred: true,
                evidence: vec![format!(
                    "rdx accompanies a must-defined rax at all {} recovered return site(s)",
                    return_blocks.len()
                )],
            });
        }
    }
    if is_return_defined("ymm0") {
        for (index, register) in ["ymm0", "ymm1"].into_iter().enumerate() {
            if index != 0 && !is_return_defined(register) {
                continue;
            }
            let width = vector_return_widths.get(register).copied().unwrap_or(128);
            let recovered_type = unique_recovered_type(&vector_return_types, register);
            let mut evidence = vec![format!(
                "{} has a must-definition at all {} recovered return site(s)",
                register,
                return_blocks.len()
            )];
            if let Some(type_name) = &recovered_type {
                evidence.push(format!(
                    "{type_name} follows from exact SSE/AVX arithmetic definition"
                ));
            }
            returns.push(AbiValue {
                name: if index == 0 {
                    "vector_return_value".to_owned()
                } else {
                    "vector_return_value_high".to_owned()
                },
                location: match width {
                    128 => register.replacen("ymm", "xmm", 1),
                    256 => register.to_owned(),
                    512 => register.replacen("ymm", "zmm", 1),
                    _ => register.to_owned(),
                },
                type_name: recovered_type.unwrap_or_else(|| format!("u{width}_vector")),
                inferred: true,
                evidence,
            });
        }
    }
    let mut diagnostics = vec![IrDiagnostic {
        code: "sysv_abi_partial".to_owned(),
        message: format!(
            "inferred {} parameter location(s) and {} return location(s), including integer/vector register classes and uniquely evidenced scalar/packed floating types, from register must-definition and normalized stack-access dataflow; aggregate classification and variadics remain unresolved",
            parameters.len(),
            returns.len()
        ),
        address: Some(machine.entry),
        blocks_stable_operation: true,
    }];
    if omitted_parameter_evidence != 0 {
        diagnostics.push(IrDiagnostic {
            code: "abi_evidence_truncated".to_owned(),
            message: format!(
                "omitted {omitted_parameter_evidence} redundant ABI input-evidence site(s) after retaining the first 64 distinct sites per parameter"
            ),
            address: Some(machine.entry),
            blocks_stable_operation: true,
        });
    }
    if saw_opaque {
        diagnostics.push(IrDiagnostic {
            code: "abi_opaque_effect".to_owned(),
            message: "opaque effects consume and produce machine state, so ABI inference does not interpret their all-state dependencies as source parameters"
                .to_owned(),
            address: Some(machine.entry),
            blocks_stable_operation: true,
        });
    }
    (parameters, returns, diagnostics)
}

fn record_abi_parameter_evidence(
    evidence_by_register: &mut BTreeMap<String, BTreeSet<String>>,
    register: &str,
    evidence: String,
    omitted: &mut usize,
) {
    const MAX_EVIDENCE_PER_VALUE: usize = 64;
    let entries = evidence_by_register.entry(register.to_owned()).or_default();
    if entries.contains(&evidence) {
        return;
    }
    if entries.len() < MAX_EVIDENCE_PER_VALUE {
        entries.insert(evidence);
    } else {
        *omitted += 1;
    }
}

fn unique_recovered_type(
    types: &BTreeMap<String, BTreeSet<String>>,
    register: &str,
) -> Option<String> {
    let candidates = types.get(register)?;
    (candidates.len() == 1)
        .then(|| candidates.iter().next().cloned())
        .flatten()
}

fn recovered_vector_type(family: &str, register_width: u16, output: bool) -> Option<String> {
    if matches!(family, "cvtss2sd" | "vcvtss2sd") {
        return Some(if output { "double" } else { "float" }.to_owned());
    }
    if matches!(family, "cvtsd2ss" | "vcvtsd2ss") {
        return Some(if output { "float" } else { "double" }.to_owned());
    }
    if matches!(family, "cvtdq2ps" | "vcvtdq2ps") {
        return Some(
            match (output, register_width) {
                (false, 128) => "i32x4",
                (false, 256) => "i32x8",
                (false, 512) => "i32x16",
                (true, 128) => "float32x4",
                (true, 256) => "float32x8",
                (true, 512) => "float32x16",
                _ => return None,
            }
            .to_owned(),
        );
    }
    if matches!(
        family,
        "cvtps2dq" | "cvttps2dq" | "vcvtps2dq" | "vcvttps2dq"
    ) {
        return Some(
            match (output, register_width) {
                (false, 128) => "float32x4",
                (false, 256) => "float32x8",
                (false, 512) => "float32x16",
                (true, 128) => "i32x4",
                (true, 256) => "i32x8",
                (true, 512) => "i32x16",
                _ => return None,
            }
            .to_owned(),
        );
    }
    let scalar_single = matches!(
        family,
        "addss"
            | "subss"
            | "mulss"
            | "divss"
            | "vaddss"
            | "vsubss"
            | "vmulss"
            | "vdivss"
            | "sqrtss"
            | "vsqrtss"
            | "cvtsi2ss"
            | "vcvtsi2ss"
            | "cvtss2si"
            | "cvttss2si"
            | "vcvtss2si"
            | "vcvttss2si"
            | "comiss"
            | "ucomiss"
            | "vcomiss"
            | "vucomiss"
    );
    let scalar_double = matches!(
        family,
        "addsd"
            | "subsd"
            | "mulsd"
            | "divsd"
            | "vaddsd"
            | "vsubsd"
            | "vmulsd"
            | "vdivsd"
            | "sqrtsd"
            | "vsqrtsd"
            | "cvtsi2sd"
            | "vcvtsi2sd"
            | "cvtsd2si"
            | "cvttsd2si"
            | "vcvtsd2si"
            | "vcvttsd2si"
            | "comisd"
            | "ucomisd"
            | "vcomisd"
            | "vucomisd"
    );
    if scalar_single {
        return Some("float".to_owned());
    }
    if scalar_double {
        return Some("double".to_owned());
    }
    let packed_single = matches!(
        family,
        "addps"
            | "subps"
            | "mulps"
            | "divps"
            | "vaddps"
            | "vsubps"
            | "vmulps"
            | "vdivps"
            | "sqrtps"
            | "vsqrtps"
    );
    let packed_double = matches!(
        family,
        "addpd"
            | "subpd"
            | "mulpd"
            | "divpd"
            | "vaddpd"
            | "vsubpd"
            | "vmulpd"
            | "vdivpd"
            | "sqrtpd"
            | "vsqrtpd"
    );
    match (packed_single, packed_double, register_width) {
        (true, false, 128) => Some("float32x4".to_owned()),
        (true, false, 256) => Some("float32x8".to_owned()),
        (true, false, 512) => Some("float32x16".to_owned()),
        (false, true, 128) => Some("float64x2".to_owned()),
        (false, true, 256) => Some("float64x4".to_owned()),
        (false, true, 512) => Some("float64x8".to_owned()),
        _ => None,
    }
}

fn abi_vector_register(register: &str) -> Option<(String, u16)> {
    let (prefix, width) = if register.starts_with("xmm") {
        ("xmm", 128)
    } else if register.starts_with("ymm") {
        ("ymm", 256)
    } else if register.starts_with("zmm") {
        ("zmm", 512)
    } else {
        return None;
    };
    let index = register.strip_prefix(prefix)?.parse::<u8>().ok()?;
    (index < 16).then(|| (format!("ymm{index}"), width))
}

fn abi_semantic_input_registers(instruction: &MachineInstruction) -> BTreeSet<String> {
    let mut inputs = instruction
        .effects
        .read_registers
        .iter()
        .map(|register| register_component_name(register))
        .collect::<BTreeSet<_>>();
    let destination_is_write_only = matches!(
        instruction.mnemonic.as_str(),
        "mov"
            | "movzx"
            | "movsx"
            | "movsxd"
            | "movups"
            | "movupd"
            | "movdqu"
            | "vmovups"
            | "vmovupd"
            | "vmovdqu"
            | "movaps"
            | "movapd"
            | "movdqa"
            | "vmovaps"
            | "vmovapd"
            | "vmovdqa"
            | "movd"
            | "movq"
            | "vmovd"
            | "vmovq"
            | "movss"
            | "movsd"
            | "vmovss"
            | "vmovsd"
    ) || instruction.mnemonic.starts_with("set");
    if destination_is_write_only
        && let Some(MachineOperand::Register { name, .. }) = instruction.operands.first()
    {
        inputs.remove(&register_component_name(name));
    }
    if matches!(instruction.mnemonic.as_str(), "sqrtss" | "sqrtsd")
        && let [
            MachineOperand::Register {
                name: destination, ..
            },
            source,
        ] = instruction.operands.as_slice()
    {
        let source_is_same = matches!(
            source,
            MachineOperand::Register { name, .. }
                if register_component_name(name) == register_component_name(destination)
        );
        if !source_is_same {
            inputs.remove(&register_component_name(destination));
        }
    }
    if matches!(
        instruction.mnemonic.as_str(),
        "cvtsi2ss" | "cvtsi2sd" | "vcvtsi2ss" | "vcvtsi2sd"
    ) {
        let merge_index = usize::from(instruction.operands.len() == 3);
        if let Some(MachineOperand::Register { name: merge, .. }) =
            instruction.operands.get(merge_index)
        {
            inputs.remove(&register_component_name(merge));
        }
    }
    if matches!(
        instruction.mnemonic.as_str(),
        "cvtss2sd" | "cvtsd2ss" | "vcvtss2sd" | "vcvtsd2ss"
    ) {
        let merge_index = usize::from(instruction.operands.len() == 3);
        if let (Some(MachineOperand::Register { name: merge, .. }), Some(source)) = (
            instruction.operands.get(merge_index),
            instruction.operands.last(),
        ) {
            let source_is_same = matches!(
                source,
                MachineOperand::Register { name, .. }
                    if register_component_name(name) == register_component_name(merge)
            );
            if !source_is_same {
                inputs.remove(&register_component_name(merge));
            }
        }
    }
    if matches!(
        instruction.mnemonic.as_str(),
        "xor" | "pxor" | "xorps" | "xorpd" | "vpxor" | "vxorps" | "vxorpd"
    ) && instruction.operands.len() >= 2
    {
        let sources = if instruction.operands.len() == 2 {
            &instruction.operands[..]
        } else {
            &instruction.operands[1..]
        };
        if let [
            MachineOperand::Register { name: left, .. },
            MachineOperand::Register { name: right, .. },
        ] = sources
            && register_component_name(left) == register_component_name(right)
        {
            inputs.remove(&register_component_name(left));
        }
    }
    inputs
}

fn recover_function_facts(
    machine: &MachineFunctionIr,
) -> (
    Vec<StackObject>,
    Vec<GlobalObject>,
    Vec<FunctionCall>,
    Vec<AliasSet>,
) {
    let stack_states = recover_stack_states(machine);
    let mut stack =
        BTreeMap::<(String, i64, u16), (RecoveredAccessKind, BTreeSet<Location>, bool)>::new();
    let mut globals = BTreeMap::<(Location, u16), (RecoveredAccessKind, BTreeSet<Location>)>::new();
    let mut calls = Vec::new();
    for instruction in machine.blocks.iter().flat_map(|block| &block.instructions) {
        let memory_access = match instruction.effects.memory {
            MachineMemoryEffect::Read => Some(RecoveredAccessKind::Read),
            MachineMemoryEffect::Write => Some(RecoveredAccessKind::Write),
            MachineMemoryEffect::ReadWrite => Some(RecoveredAccessKind::ReadWrite),
            MachineMemoryEffect::Unknown
                if matches!(
                    instruction.effects.control,
                    MachineControlEffect::IndirectBranch | MachineControlEffect::IndirectCall
                ) =>
            {
                Some(RecoveredAccessKind::Read)
            }
            MachineMemoryEffect::None
            | MachineMemoryEffect::Fence
            | MachineMemoryEffect::Unknown => None,
        };
        if let Some(access) = memory_access {
            for operand in &instruction.operands {
                let MachineOperand::Memory {
                    segment,
                    base,
                    index,
                    displacement,
                    absolute,
                    width_bits,
                    ..
                } = operand
                else {
                    continue;
                };
                if segment.is_none()
                    && index.is_none()
                    && matches!(base.as_deref(), Some("rsp" | "rbp"))
                {
                    let raw_base = base.clone().unwrap_or_default();
                    let normalized = stack_states
                        .get(&instruction.address)
                        .and_then(|state| match raw_base.as_str() {
                            "rsp" => state.rsp_delta,
                            "rbp" => state.rbp_delta,
                            _ => None,
                        })
                        .and_then(|delta| delta.checked_add(*displacement));
                    let (base_register, displacement, proven) = normalized.map_or_else(
                        || (raw_base, *displacement, false),
                        |displacement| ("entry_rsp".to_owned(), displacement, true),
                    );
                    let key = (base_register, displacement, *width_bits);
                    let entry = stack
                        .entry(key)
                        .or_insert((access, BTreeSet::new(), proven));
                    entry.0 = merge_access(entry.0, access);
                    entry.1.insert(instruction.address);
                    entry.2 &= proven;
                } else if segment.is_none()
                    && let Some(absolute) = (*absolute).or_else(|| {
                        base.is_none()
                            .then(|| u64::try_from(*displacement).ok())
                            .flatten()
                    })
                    && *width_bits != 0
                {
                    let key = (location(machine.entry.address_space, absolute), *width_bits);
                    let entry = globals.entry(key).or_insert((access, BTreeSet::new()));
                    entry.0 = merge_access(entry.0, access);
                    entry.1.insert(instruction.address);
                }
            }
        }
        if matches!(
            instruction.effects.control,
            MachineControlEffect::DirectCall | MachineControlEffect::IndirectCall
        ) {
            let symbol = instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    MachineOperand::RelocatedBranch { symbol, .. } => symbol.clone(),
                    _ => None,
                });
            let targets = instruction
                .edges
                .iter()
                .filter(|edge| edge.kind == MachineEdgeKind::Call)
                .map(|edge| edge.target)
                .collect::<Vec<_>>();
            for target in if targets.is_empty() {
                vec![None]
            } else {
                targets
            } {
                let call_abi = known_external_call_abi(symbol.as_deref());
                calls.push(FunctionCall {
                    site: instruction.address,
                    target,
                    symbol: symbol.clone(),
                    indirect: instruction.effects.control == MachineControlEffect::IndirectCall,
                    tail_call: false,
                    noreturn: known_external_noreturn(symbol.as_deref()),
                    prototype: known_external_prototype(symbol.as_deref()).map(str::to_owned),
                    arguments: call_abi
                        .as_ref()
                        .map(|abi| abi.arguments.clone())
                        .unwrap_or_default(),
                    returns: call_abi
                        .as_ref()
                        .map(|abi| abi.returns.clone())
                        .unwrap_or_default(),
                    variadic: call_abi.as_ref().is_some_and(|abi| abi.variadic),
                    evidence: if symbol.is_some() {
                        "ELF relocation-backed call operand".to_owned()
                    } else if target.is_some() {
                        "decoded native call edge".to_owned()
                    } else {
                        "unresolved native call effect".to_owned()
                    },
                });
            }
        }
        if instruction.effects.control == MachineControlEffect::DirectBranch
            && let Some(edge) = instruction
                .edges
                .iter()
                .find(|edge| edge.kind == MachineEdgeKind::External)
        {
            let symbol = instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    MachineOperand::RelocatedBranch { symbol, .. } => symbol.clone(),
                    _ => None,
                });
            let call_abi = known_external_call_abi(symbol.as_deref());
            calls.push(FunctionCall {
                site: instruction.address,
                target: edge.target,
                symbol: symbol.clone(),
                indirect: false,
                tail_call: true,
                noreturn: known_external_noreturn(symbol.as_deref()),
                prototype: known_external_prototype(symbol.as_deref()).map(str::to_owned),
                arguments: call_abi
                    .as_ref()
                    .map(|abi| abi.arguments.clone())
                    .unwrap_or_default(),
                returns: call_abi
                    .as_ref()
                    .map(|abi| abi.returns.clone())
                    .unwrap_or_default(),
                variadic: call_abi.as_ref().is_some_and(|abi| abi.variadic),
                evidence: if symbol.is_some() {
                    "terminal relocation-backed direct branch to another function".to_owned()
                } else {
                    "terminal direct branch leaves the recovered function extent".to_owned()
                },
            });
        }
    }
    let stack_objects = stack
        .into_iter()
        .map(
            |((base_register, displacement, width_bits), (access, sites, normalized))| {
                StackObject {
                    id: format!("stack:{base_register}:{displacement}:{width_bits}"),
                    base_register,
                    displacement,
                    width_bits,
                    access,
                    sites: sites.into_iter().collect(),
                    evidence: if normalized {
                        "abstract stack dataflow normalized every access to the function-entry RSP"
                            .to_owned()
                    } else {
                        "raw base-relative access retained because stack/frame state was unresolved"
                            .to_owned()
                    },
                }
            },
        )
        .collect::<Vec<_>>();
    let global_objects = globals
        .into_iter()
        .map(|((location, width_bits), (access, sites))| GlobalObject {
            id: format!(
                "global:{}:0x{:x}:{width_bits}",
                location.address_space, location.value.0
            ),
            location,
            width_bits,
            access,
            sites: sites.into_iter().collect(),
            evidence: "absolute or RIP-relative decoded memory operand".to_owned(),
        })
        .collect::<Vec<_>>();
    let alias_sets = overlapping_stack_alias_sets(&stack_objects);
    (stack_objects, global_objects, calls, alias_sets)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StackFrameState {
    rsp_delta: Option<i64>,
    rbp_delta: Option<i64>,
}

fn recover_stack_states(machine: &MachineFunctionIr) -> BTreeMap<Location, StackFrameState> {
    let blocks = machine
        .blocks
        .iter()
        .map(|block| (block.address, block))
        .collect::<BTreeMap<_, _>>();
    let mut block_inputs = BTreeMap::from([(
        machine.entry,
        StackFrameState {
            rsp_delta: Some(0),
            rbp_delta: None,
        },
    )]);
    let mut instruction_inputs = BTreeMap::new();
    let mut pending = VecDeque::from([machine.entry]);
    while let Some(address) = pending.pop_front() {
        let Some(block) = blocks.get(&address) else {
            continue;
        };
        let Some(mut state) = block_inputs.get(&address).copied() else {
            continue;
        };
        for instruction in &block.instructions {
            instruction_inputs.insert(instruction.address, state);
            state = transfer_stack_state(state, instruction);
        }
        for target in block
            .instructions
            .last()
            .into_iter()
            .flat_map(|instruction| &instruction.edges)
            .filter(|edge| edge.kind != MachineEdgeKind::Call)
            .filter_map(|edge| edge.target)
            .filter(|target| blocks.contains_key(target))
        {
            let merged = block_inputs
                .get(&target)
                .copied()
                .map_or(state, |previous| merge_stack_state(previous, state));
            if block_inputs.get(&target) != Some(&merged) {
                block_inputs.insert(target, merged);
                pending.push_back(target);
            }
        }
    }
    instruction_inputs
}

fn merge_stack_state(left: StackFrameState, right: StackFrameState) -> StackFrameState {
    StackFrameState {
        rsp_delta: (left.rsp_delta == right.rsp_delta)
            .then_some(left.rsp_delta)
            .flatten(),
        rbp_delta: (left.rbp_delta == right.rbp_delta)
            .then_some(left.rbp_delta)
            .flatten(),
    }
}

fn transfer_stack_state(
    mut state: StackFrameState,
    instruction: &MachineInstruction,
) -> StackFrameState {
    let MachineOperation::Exact { family } = &instruction.operation else {
        if instruction
            .effects
            .written_registers
            .iter()
            .any(|name| name == "rsp")
        {
            state.rsp_delta = None;
        }
        if instruction
            .effects
            .written_registers
            .iter()
            .any(|name| name == "rbp")
        {
            state.rbp_delta = None;
        }
        return state;
    };
    let before = state;
    let mut handled_rsp = false;
    let mut handled_rbp = false;
    match (family.as_str(), instruction.operands.as_slice()) {
        ("push", _) => {
            state.rsp_delta = state.rsp_delta.and_then(|delta| delta.checked_sub(8));
            handled_rsp = true;
        }
        ("pop", [MachineOperand::Register { name, .. }]) => {
            state.rsp_delta = state.rsp_delta.and_then(|delta| delta.checked_add(8));
            handled_rsp = true;
            handled_rbp = name == "rbp";
            if handled_rbp {
                state.rbp_delta = None;
            }
        }
        (
            "add" | "sub",
            [
                MachineOperand::Register {
                    name,
                    width_bits: 64,
                },
                MachineOperand::Immediate { value, .. },
            ],
        ) if name == "rsp" => {
            let amount = *value as i64;
            state.rsp_delta = state.rsp_delta.and_then(|delta| {
                if family == "add" {
                    delta.checked_add(amount)
                } else {
                    delta.checked_sub(amount)
                }
            });
            handled_rsp = true;
        }
        (
            "mov",
            [
                MachineOperand::Register {
                    name: destination,
                    width_bits: 64,
                },
                MachineOperand::Register {
                    name: source,
                    width_bits: 64,
                },
            ],
        ) if destination == "rbp" && source == "rsp" => {
            state.rbp_delta = state.rsp_delta;
            handled_rbp = true;
        }
        (
            "mov",
            [
                MachineOperand::Register {
                    name: destination,
                    width_bits: 64,
                },
                MachineOperand::Register {
                    name: source,
                    width_bits: 64,
                },
            ],
        ) if destination == "rsp" && source == "rbp" => {
            state.rsp_delta = state.rbp_delta;
            handled_rsp = true;
        }
        (
            "lea",
            [
                MachineOperand::Register {
                    name: destination,
                    width_bits: 64,
                },
                MachineOperand::Memory {
                    base: Some(base),
                    index: None,
                    displacement,
                    absolute: None,
                    ..
                },
            ],
        ) if destination == "rsp" || destination == "rbp" => {
            let base_delta = match base.as_str() {
                "rsp" => before.rsp_delta,
                "rbp" => before.rbp_delta,
                _ => None,
            };
            let value = base_delta.and_then(|delta| delta.checked_add(*displacement));
            if destination == "rsp" {
                state.rsp_delta = value;
                handled_rsp = true;
            } else {
                state.rbp_delta = value;
                handled_rbp = true;
            }
        }
        ("leave", []) => {
            state.rsp_delta = state.rbp_delta.and_then(|delta| delta.checked_add(8));
            state.rbp_delta = None;
            handled_rsp = true;
            handled_rbp = true;
        }
        _ => {}
    }
    if !handled_rsp
        && instruction
            .effects
            .written_registers
            .iter()
            .any(|name| name == "rsp")
    {
        state.rsp_delta = None;
    }
    if !handled_rbp
        && instruction
            .effects
            .written_registers
            .iter()
            .any(|name| name == "rbp")
    {
        state.rbp_delta = None;
    }
    state
}

fn merge_access(left: RecoveredAccessKind, right: RecoveredAccessKind) -> RecoveredAccessKind {
    if left == right {
        left
    } else {
        RecoveredAccessKind::ReadWrite
    }
}

fn overlapping_stack_alias_sets(objects: &[StackObject]) -> Vec<AliasSet> {
    let mut result = Vec::new();
    let mut consumed = BTreeSet::new();
    for (index, object) in objects.iter().enumerate() {
        if consumed.contains(&index) {
            continue;
        }
        let mut members = vec![object.id.clone()];
        for (other_index, other) in objects.iter().enumerate().skip(index + 1) {
            if object.base_register != other.base_register {
                continue;
            }
            let left_end = object
                .displacement
                .checked_add(i64::from(object.width_bits / 8));
            let right_end = other
                .displacement
                .checked_add(i64::from(other.width_bits / 8));
            if left_end.is_some_and(|left_end| {
                right_end.is_some_and(|right_end| {
                    object.displacement < right_end && other.displacement < left_end
                })
            }) {
                consumed.insert(other_index);
                members.push(other.id.clone());
            }
        }
        if members.len() > 1 {
            result.push(AliasSet {
                id: format!("stack_alias_{}", result.len()),
                members,
                evidence: "overlapping raw base-relative byte ranges".to_owned(),
            });
        }
    }
    result
}

fn known_external_prototype(symbol: Option<&str>) -> Option<&'static str> {
    match symbol?.split('@').next().unwrap_or_default() {
        "malloc" => Some("void *malloc(size_t size)"),
        "calloc" => Some("void *calloc(size_t count, size_t size)"),
        "realloc" => Some("void *realloc(void *pointer, size_t size)"),
        "aligned_alloc" => Some("void *aligned_alloc(size_t alignment, size_t size)"),
        "posix_memalign" => {
            Some("int posix_memalign(void **pointer, size_t alignment, size_t size)")
        }
        "free" => Some("void free(void *pointer)"),
        "memcpy" => Some("void *memcpy(void *destination, const void *source, size_t size)"),
        "memmove" => Some("void *memmove(void *destination, const void *source, size_t size)"),
        "memset" => Some("void *memset(void *destination, int value, size_t size)"),
        "memcmp" => Some("int memcmp(const void *left, const void *right, size_t size)"),
        "memchr" => Some("void *memchr(const void *memory, int value, size_t size)"),
        "strlen" => Some("size_t strlen(const char *string)"),
        "strnlen" => Some("size_t strnlen(const char *string, size_t maximum)"),
        "strcmp" => Some("int strcmp(const char *left, const char *right)"),
        "strncmp" => Some("int strncmp(const char *left, const char *right, size_t size)"),
        "strcpy" => Some("char *strcpy(char *destination, const char *source)"),
        "strncpy" => Some("char *strncpy(char *destination, const char *source, size_t size)"),
        "puts" => Some("int puts(const char *string)"),
        "printf" => Some("int printf(const char *format, ...)"),
        "fprintf" => Some("int fprintf(void *stream, const char *format, ...)"),
        "snprintf" => Some("int snprintf(char *buffer, size_t size, const char *format, ...)"),
        "read" => Some("ssize_t read(int descriptor, void *buffer, size_t count)"),
        "write" => Some("ssize_t write(int descriptor, const void *buffer, size_t count)"),
        "pread" => Some("ssize_t pread(int descriptor, void *buffer, size_t count, off_t offset)"),
        "pwrite" => {
            Some("ssize_t pwrite(int descriptor, const void *buffer, size_t count, off_t offset)")
        }
        "open" => Some("int open(const char *path, int flags, ...)"),
        "openat" => Some("int openat(int directory, const char *path, int flags, ...)"),
        "close" => Some("int close(int descriptor)"),
        "lseek" => Some("off_t lseek(int descriptor, off_t offset, int origin)"),
        "mmap" => Some(
            "void *mmap(void *address, size_t length, int protection, int flags, int descriptor, off_t offset)",
        ),
        "munmap" => Some("int munmap(void *address, size_t length)"),
        "mprotect" => Some("int mprotect(void *address, size_t length, int protection)"),
        "getenv" => Some("char *getenv(const char *name)"),
        "strtol" => Some("long strtol(const char *string, char **end, int base)"),
        "strtoul" => Some("unsigned long strtoul(const char *string, char **end, int base)"),
        "dlopen" => Some("void *dlopen(const char *path, int mode)"),
        "dlsym" => Some("void *dlsym(void *handle, const char *name)"),
        "dlclose" => Some("int dlclose(void *handle)"),
        "pthread_create" => Some(
            "int pthread_create(unsigned long *thread, const void *attributes, void *(*start)(void *), void *argument)",
        ),
        "pthread_join" => Some("int pthread_join(unsigned long thread, void **result)"),
        "exit" | "_exit" | "_Exit" | "quick_exit" => Some("void exit(int status) /* noreturn */"),
        "abort" => Some("void abort(void) /* noreturn */"),
        "__stack_chk_fail" => Some("void __stack_chk_fail(void) /* noreturn */"),
        "__assert_fail" => Some(
            "void __assert_fail(const char *assertion, const char *file, unsigned line, const char *function) /* noreturn */",
        ),
        _ => None,
    }
}

fn known_external_noreturn(symbol: Option<&str>) -> bool {
    matches!(
        symbol
            .and_then(|symbol| symbol.split('@').next())
            .unwrap_or_default(),
        "exit" | "_exit" | "_Exit" | "quick_exit" | "abort" | "__stack_chk_fail" | "__assert_fail"
    )
}

#[derive(Clone, Debug)]
struct KnownCallAbi {
    arguments: Vec<AbiValue>,
    returns: Vec<AbiValue>,
    variadic: bool,
}

fn known_external_call_abi(symbol: Option<&str>) -> Option<KnownCallAbi> {
    const INTEGER_ARGUMENTS: [&str; 6] = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"];
    let symbol = symbol?.split('@').next().unwrap_or_default();
    let prototype = known_external_prototype(Some(symbol))?;
    let open = prototype.find('(')?;
    let close = prototype.rfind(')')?;
    let declaration = prototype[..open].trim();
    let return_type = declaration.strip_suffix(symbol)?.trim();
    let mut parameters = Vec::<String>::new();
    let mut start = 0usize;
    let mut depth = 0usize;
    let body = &prototype[open + 1..close];
    for (index, character) in body.char_indices() {
        match character {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parameters.push(body[start..index].trim().to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    parameters.push(body[start..].trim().to_owned());
    let variadic = parameters.iter().any(|parameter| parameter == "...");
    parameters
        .retain(|parameter| !parameter.is_empty() && parameter != "void" && parameter != "...");
    let arguments = parameters
        .into_iter()
        .enumerate()
        .map(|(index, type_name)| AbiValue {
            name: format!("argument_{index}"),
            location: INTEGER_ARGUMENTS.get(index).map_or_else(
                || format!("stack:+{}", (index - INTEGER_ARGUMENTS.len()) * 8),
                |register| (*register).to_owned(),
            ),
            type_name,
            inferred: false,
            evidence: vec!["audited external signature and SysV AMD64 ABI".to_owned()],
        })
        .collect();
    let returns = (return_type != "void")
        .then(|| AbiValue {
            name: "return_value".to_owned(),
            location: "rax".to_owned(),
            type_name: return_type.to_owned(),
            inferred: false,
            evidence: vec!["audited external signature and SysV AMD64 ABI".to_owned()],
        })
        .into_iter()
        .collect();
    Some(KnownCallAbi {
        arguments,
        returns,
        variadic,
    })
}

/// Export native FunctionIR as verifier-friendly LLVM IR without making LLVM
/// canonical. Every state operation is retained as a JSON descriptor consumed
/// by an explicit runtime-effect hook; opaque operations use a distinct hook.
/// The export is intentionally not a rewrite-ready behavioral claim.
pub fn export_function_ir_llvm(function: &FunctionIr) -> Result<String, String> {
    validate_function_ir(function)?;
    let labels = function
        .blocks
        .iter()
        .map(|block| (block.address, llvm_block_label(block.address)))
        .collect::<BTreeMap<_, _>>();
    let entry = labels
        .get(&function.entry)
        .ok_or_else(|| "FunctionIR entry does not identify a block".to_owned())?;

    let mut descriptors = Vec::<Vec<u8>>::new();
    let mut descriptor_ids = BTreeMap::<(Location, usize), usize>::new();
    for block in &function.blocks {
        for (operation_index, operation) in block.operations.iter().enumerate() {
            let descriptor = serde_json::to_vec(operation)
                .map_err(|error| format!("cannot serialize FunctionIR operation: {error}"))?;
            let descriptor_id = descriptors.len();
            descriptors.push(descriptor);
            descriptor_ids.insert((block.address, operation_index), descriptor_id);
        }
    }

    let mut llvm = String::new();
    llvm.push_str("; Hydir native FunctionIR export; LLVM is not canonical.\n");
    llvm.push_str(&format!("; binary_sha256 = {}\n", function.binary_sha256));
    llvm.push_str(&format!(
        "; structural = {:?}, semantic = {:?}, verification = {:?}, rewrite_ready = {}\n",
        function.structural_completeness,
        function.semantic_fidelity,
        function.verification,
        function.rewrite_ready
    ));
    llvm.push_str("target triple = \"x86_64-unknown-linux-gnu\"\n\n");
    llvm.push_str("%HydirMachineState = type { [16 x i64], [4 x i8], i8* }\n\n");
    for (descriptor_id, descriptor) in descriptors.iter().enumerate() {
        llvm.push_str(&format!(
            "@hydir_op_{descriptor_id} = private unnamed_addr constant [{} x i8] c\"{}\\00\"\n",
            descriptor.len() + 1,
            llvm_byte_string(descriptor)
        ));
    }
    if !descriptors.is_empty() {
        llvm.push('\n');
    }
    llvm.push_str(
        "declare void @hydir_exact_effect(%HydirMachineState*, i8*, i64)\n\
         declare void @hydir_opaque_effect(%HydirMachineState*, i8*, i64)\n\
         declare void @hydir_call_effect(%HydirMachineState*, i32, i64, i1, i32, i64)\n\
         declare void @hydir_external_exit(%HydirMachineState*, i32, i64)\n\
         declare i1 @hydir_branch_condition(%HydirMachineState*, i32, i64)\n\n",
    );
    llvm.push_str(&format!(
        "define void @{}(%HydirMachineState* %state) {{\nentry:\n  br label %{}\n",
        llvm_function_name(&function.name),
        entry
    ));

    for block in &function.blocks {
        let label = labels
            .get(&block.address)
            .ok_or_else(|| "FunctionIR block has no LLVM label".to_owned())?;
        llvm.push_str(&format!("\n{label}:\n"));
        for (operation_index, operation) in block.operations.iter().enumerate() {
            let descriptor_id = descriptor_ids
                .get(&(block.address, operation_index))
                .ok_or_else(|| "FunctionIR operation descriptor is missing".to_owned())?;
            let descriptor_len = descriptors[*descriptor_id].len();
            let hook = match operation {
                StateOperation::Exact { .. } => "hydir_exact_effect",
                StateOperation::Unknown { .. } => "hydir_opaque_effect",
            };
            llvm.push_str(&format!(
                "  call void @{hook}(%HydirMachineState* %state, i8* getelementptr inbounds ([{} x i8], [{} x i8]* @hydir_op_{descriptor_id}, i64 0, i64 0), i64 {descriptor_len})\n",
                descriptor_len + 1,
                descriptor_len + 1,
            ));
        }

        for edge in block
            .edges
            .iter()
            .filter(|edge| edge.kind == MachineEdgeKind::Call)
        {
            let (has_target, target_space, target_value) =
                edge.target.map_or(("false", 0, 0), |target| {
                    ("true", target.address_space, target.value.0)
                });
            llvm.push_str(&format!(
                "  call void @hydir_call_effect(%HydirMachineState* %state, i32 {}, i64 {}, i1 {has_target}, i32 {target_space}, i64 {})\n",
                block.address.address_space,
                llvm_i64(block.address.value.0),
                llvm_i64(target_value),
            ));
        }

        let mut internal = Vec::<String>::new();
        let mut has_external = false;
        for edge in block
            .edges
            .iter()
            .filter(|edge| edge.kind != MachineEdgeKind::Call)
        {
            if let Some(target) = edge.target
                && let Some(target_label) = labels.get(&target)
            {
                if !internal.contains(target_label) {
                    internal.push(target_label.clone());
                }
            } else {
                has_external = true;
            }
        }
        match (internal.as_slice(), has_external) {
            ([], false) => llvm.push_str("  ret void\n"),
            ([], true) => {
                llvm_external_exit(&mut llvm, block.address);
                llvm.push_str("  ret void\n");
            }
            ([target], false) => llvm.push_str(&format!("  br label %{target}\n")),
            ([target], true) => {
                llvm.push_str(&format!(
                    "  %cond_{} = call i1 @hydir_branch_condition(%HydirMachineState* %state, i32 {}, i64 {})\n  br i1 %cond_{}, label %{target}, label %exit_{}\n",
                    label,
                    block.address.address_space,
                    llvm_i64(block.address.value.0),
                    label,
                    label,
                ));
                llvm.push_str(&format!("\nexit_{label}:\n"));
                llvm_external_exit(&mut llvm, block.address);
                llvm.push_str("  ret void\n");
            }
            ([first, second], false) => llvm.push_str(&format!(
                "  %cond_{} = call i1 @hydir_branch_condition(%HydirMachineState* %state, i32 {}, i64 {})\n  br i1 %cond_{}, label %{first}, label %{second}\n",
                label,
                block.address.address_space,
                llvm_i64(block.address.value.0),
                label,
            )),
            _ => {
                llvm_external_exit(&mut llvm, block.address);
                llvm.push_str("  ret void\n");
            }
        }
    }
    llvm.push_str("}\n");
    Ok(llvm)
}

fn llvm_block_label(location: Location) -> String {
    format!("b_{}_{:x}", location.address_space, location.value.0)
}

fn llvm_function_name(name: &str) -> String {
    let mut result = String::from("hydir_native_");
    for character in name.chars() {
        if character.is_ascii_alphanumeric() || character == '_' {
            result.push(character);
        } else {
            result.push('_');
        }
    }
    if result == "hydir_native_" {
        result.push_str("function");
    }
    result
}

fn llvm_byte_string(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("\\{byte:02X}"))
        .collect::<String>()
}

fn llvm_i64(value: u64) -> i64 {
    value as i64
}

fn llvm_external_exit(llvm: &mut String, location: Location) {
    llvm.push_str(&format!(
        "  call void @hydir_external_exit(%HydirMachineState* %state, i32 {}, i64 {})\n",
        location.address_space,
        llvm_i64(location.value.0),
    ));
}

pub fn lower_cir(machine: &MachineFunctionIr, function: &FunctionIr) -> Result<Cir, String> {
    validate_machine_function_ir(machine)?;
    validate_function_ir(function)?;
    if machine.binary_sha256 != function.binary_sha256
        || machine.function_id != function.function_id
        || machine.entry != function.entry
    {
        return Err("MachineFunctionIR and FunctionIR identities differ".to_owned());
    }
    let blocks = machine
        .blocks
        .iter()
        .map(|block| {
            let instruction = block
                .instructions
                .last()
                .ok_or_else(|| "machine block has no instruction".to_owned())?;
            let is_control = instruction.effects.control != MachineControlEffect::Next;
            let statements = if !is_control
                || matches!(instruction.operation, MachineOperation::OpaqueEffect { .. })
                || instruction.effects.control == MachineControlEffect::Stop
            {
                vec![cir_statement(instruction)]
            } else {
                Vec::new()
            };
            Ok(CirBlock {
                label: block.label.clone(),
                address: block.address,
                statements,
                terminator: cir_terminator(instruction),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let cir = Cir {
        schema_version: CIR_VERSION,
        binary_sha256: function.binary_sha256.clone(),
        function_id: function.function_id.clone(),
        name: function.name.clone(),
        entry: function.entry,
        blocks,
        structural_completeness: function.structural_completeness,
        semantic_fidelity: function.semantic_fidelity,
        verification: VerificationStatus::StaticallyValidated,
        rewrite_ready: false,
        diagnostics: function.diagnostics.clone(),
    };
    validate_cir(&cir)?;
    Ok(cir)
}

fn cir_statement(instruction: &MachineInstruction) -> CirStatement {
    match &instruction.operation {
        MachineOperation::Exact { family } => CirStatement::Operation {
            address: instruction.address,
            family: family.clone(),
            operands: instruction.operands.clone(),
            decorators: instruction.decorators.clone(),
            effects: instruction.effects.clone(),
        },
        MachineOperation::OpaqueEffect { reason } => CirStatement::OpaqueEffect {
            address: instruction.address,
            bytes_hex: instruction.bytes_hex.clone(),
            reason: reason.clone(),
            effects: instruction.effects.clone(),
        },
    }
}

fn cir_terminator(instruction: &MachineInstruction) -> CirTerminator {
    let edge = |kind| {
        instruction
            .edges
            .iter()
            .find(|edge| edge.kind == kind)
            .and_then(|edge| edge.target)
    };
    let recovered_indirect = || {
        let targets = instruction
            .edges
            .iter()
            .filter(|edge| edge.kind == MachineEdgeKind::IndirectTarget)
            .filter_map(|edge| edge.target)
            .collect::<Vec<_>>();
        (!targets.is_empty()).then_some(CirTerminator::Switch {
            dispatch: instruction.address,
            targets,
            unresolved_default: true,
        })
    };
    if matches!(instruction.operation, MachineOperation::OpaqueEffect { .. }) {
        return match instruction.effects.control {
            MachineControlEffect::Next
            | MachineControlEffect::DirectCall
            | MachineControlEffect::IndirectCall => edge(MachineEdgeKind::Fallthrough)
                .or_else(|| edge(MachineEdgeKind::External))
                .map_or(CirTerminator::Exit { target: None }, |target| {
                    CirTerminator::Fallthrough { target }
                }),
            MachineControlEffect::DirectBranch => edge(MachineEdgeKind::Direct)
                .or_else(|| edge(MachineEdgeKind::External))
                .map_or_else(
                    || CirTerminator::Unresolved {
                        reason: "opaque direct branch target is unavailable".to_owned(),
                        target_operand: None,
                    },
                    |target| CirTerminator::Goto { target },
                ),
            MachineControlEffect::Return => CirTerminator::Return,
            MachineControlEffect::Stop => CirTerminator::Exit { target: None },
            MachineControlEffect::IndirectBranch => {
                recovered_indirect().unwrap_or_else(|| CirTerminator::Unresolved {
                    reason: "opaque instruction has unresolved indirect control outcome".to_owned(),
                    target_operand: instruction.operands.first().cloned(),
                })
            }
            MachineControlEffect::ConditionalBranch | MachineControlEffect::Unknown => {
                CirTerminator::Unresolved {
                    reason: "opaque instruction has unresolved control outcome".to_owned(),
                    target_operand: None,
                }
            }
        };
    }
    match instruction.effects.control {
        MachineControlEffect::Next => edge(MachineEdgeKind::Fallthrough)
            .or_else(|| edge(MachineEdgeKind::External))
            .map_or(CirTerminator::Exit { target: None }, |target| {
                CirTerminator::Fallthrough { target }
            }),
        MachineControlEffect::DirectBranch => edge(MachineEdgeKind::Direct)
            .or_else(|| edge(MachineEdgeKind::External))
            .map_or_else(
                || CirTerminator::Unresolved {
                    reason: "direct branch target is unavailable".to_owned(),
                    target_operand: None,
                },
                |target| CirTerminator::Goto { target },
            ),
        MachineControlEffect::ConditionalBranch => {
            let taken = edge(MachineEdgeKind::Taken);
            let fallthrough =
                edge(MachineEdgeKind::Fallthrough).or_else(|| edge(MachineEdgeKind::External));
            match (taken, fallthrough) {
                (Some(taken), Some(fallthrough)) => CirTerminator::Branch {
                    condition: instruction.mnemonic.clone(),
                    taken,
                    fallthrough,
                },
                _ => CirTerminator::Unresolved {
                    reason: "conditional branch target is unavailable".to_owned(),
                    target_operand: None,
                },
            }
        }
        MachineControlEffect::DirectCall | MachineControlEffect::IndirectCall => {
            let call_targets = instruction
                .edges
                .iter()
                .filter(|edge| edge.kind == MachineEdgeKind::Call)
                .filter_map(|edge| edge.target)
                .collect::<Vec<_>>();
            CirTerminator::Call {
                target: (call_targets.len() == 1).then(|| call_targets[0]),
                target_operand: if instruction.effects.control == MachineControlEffect::IndirectCall
                {
                    instruction.operands.first().cloned()
                } else {
                    None
                },
                next: edge(MachineEdgeKind::Fallthrough)
                    .or_else(|| edge(MachineEdgeKind::External)),
            }
        }
        MachineControlEffect::Return => CirTerminator::Return,
        MachineControlEffect::IndirectBranch => {
            recovered_indirect().unwrap_or_else(|| CirTerminator::Unresolved {
                reason: "indirect control target".to_owned(),
                target_operand: instruction.operands.first().cloned(),
            })
        }
        MachineControlEffect::Unknown => CirTerminator::Unresolved {
            reason: "unknown control target".to_owned(),
            target_operand: None,
        },
        MachineControlEffect::Stop => CirTerminator::Exit { target: None },
    }
}

pub fn decompile_symbol(bytes: &[u8], symbol: &str) -> Result<NativeDecompilation, String> {
    let machine_ir = lift_machine_function(bytes, symbol)?;
    decompile_machine(machine_ir)
}

pub fn decompile_function_at(bytes: &[u8], entry: Location) -> Result<NativeDecompilation, String> {
    let machine_ir = lift_machine_function_at(bytes, entry)?;
    decompile_machine(machine_ir)
}

pub fn decompile_indexed_function(
    bytes: &[u8],
    index: &FunctionIndex,
    function_id: &str,
) -> Result<NativeDecompilation, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let selected = index
        .functions
        .iter()
        .find(|function| function.id == function_id)
        .ok_or_else(|| format!("FunctionIndex has no function id {function_id:?}"))?;
    let machine = lift_indexed_function(
        bytes,
        &spec,
        index,
        selected,
        selected.state != FunctionEvidenceState::Confirmed,
    )?;
    decompile_machine(machine)
}

fn decompile_machine(machine_ir: MachineFunctionIr) -> Result<NativeDecompilation, String> {
    let state_ir = lower_state_ir(&machine_ir)?;
    let function_ir = lower_function_ir(&machine_ir, &state_ir)?;
    let cir = lower_cir(&machine_ir, &function_ir)?;
    let low_level_c = hydir_c::emit_native_low_level_c(&cir)?;
    let structured_c = hydir_c::emit_native_structured_c(&cir)?;
    if low_level_c.len() > MAX_NATIVE_C_BYTES
        || structured_c
            .as_ref()
            .is_some_and(|source| source.len() > MAX_NATIVE_C_BYTES)
    {
        return Err(format!(
            "native C output exceeds the {MAX_NATIVE_C_BYTES}-byte per-view limit"
        ));
    }
    let diagnostics = cir
        .diagnostics
        .iter()
        .map(|diagnostic| DecompilationDiagnostic {
            code: diagnostic.code.clone(),
            severity: DiagnosticSeverity::Warning,
            message: diagnostic.message.clone(),
            blocks_stable_operation: diagnostic.blocks_stable_operation,
        })
        .collect();
    Ok(NativeDecompilation {
        machine_ir,
        state_ir,
        function_ir,
        cir,
        low_level_c,
        structured_c,
        diagnostics,
    })
}

pub fn decompile_symbol_unit(bytes: &[u8], symbol: &str) -> Result<DecompilationUnit, String> {
    let native = decompile_symbol(bytes, symbol)?;
    let region = region_contract(bytes, symbol).map_err(|error| error.to_string())?;
    package_native_unit(native, region)
}

pub fn decompile_function_unit_at(
    bytes: &[u8],
    entry: Location,
) -> Result<DecompilationUnit, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let native = decompile_function_at(bytes, entry)?;
    let region = native_region_spec(bytes, &spec, &native)?;
    package_native_unit(native, region)
}

pub fn decompile_indexed_function_unit(
    bytes: &[u8],
    index: &FunctionIndex,
    function_id: &str,
) -> Result<DecompilationUnit, String> {
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let selected = index
        .functions
        .iter()
        .find(|function| function.id == function_id)
        .ok_or_else(|| format!("FunctionIndex has no function id {function_id:?}"))?;
    let machine = lift_indexed_function(
        bytes,
        &spec,
        index,
        selected,
        selected.state != FunctionEvidenceState::Confirmed,
    )?;
    let native = decompile_machine(machine)?;
    let region = native_region_spec(bytes, &spec, &native)?;
    package_native_unit(native, region)
}

fn package_native_unit(
    native: NativeDecompilation,
    region: RegionSpec,
) -> Result<DecompilationUnit, String> {
    let artifacts = DecompilationArtifactDigests {
        machine_ir_sha256: Some(artifact_sha256(&native.machine_ir)?),
        state_ir_sha256: Some(artifact_sha256(&native.state_ir)?),
        function_ir_sha256: Some(artifact_sha256(&native.function_ir)?),
        cir_sha256: Some(artifact_sha256(&native.cir)?),
    };
    let c_source = native.low_level_c.clone();
    let statement_provenance = native_statement_provenance(&native.cir, &c_source);
    let unit = DecompilationUnit {
        schema_version: DECOMPILATION_UNIT_VERSION,
        binary_sha256: native.machine_ir.binary_sha256.clone(),
        region,
        function_id: Some(native.machine_ir.function_id.clone()),
        model_revision: None,
        artifacts,
        region_ir_llvm: String::new(),
        cir: Some(
            serde_json::to_string_pretty(&native.cir)
                .map_err(|error| format!("cannot serialize native CIR: {error}"))?,
        ),
        c_source,
        low_level_c: Some(native.low_level_c),
        structured_c: native.structured_c,
        structural_completeness: match native.cir.structural_completeness {
            StructuralCompleteness::Partial => DecompilationStructuralCompleteness::Partial,
            StructuralCompleteness::Complete => DecompilationStructuralCompleteness::Complete,
        },
        semantic_fidelity: match native.cir.semantic_fidelity {
            SemanticFidelity::Unknown => DecompilationSemanticFidelity::Unknown,
            SemanticFidelity::Conservative => DecompilationSemanticFidelity::Conservative,
            SemanticFidelity::ExactUnderModel => DecompilationSemanticFidelity::ExactUnderModel,
        },
        verification: DecompilationVerificationStatus::StaticallyValidated,
        rewrite_ready: false,
        statement_provenance,
        diagnostics: native.diagnostics,
        engine_version: concat!("hydir-native/", env!("CARGO_PKG_VERSION")).to_owned(),
    };
    validate_decompilation_unit(&unit)?;
    Ok(unit)
}

fn native_region_spec(
    bytes: &[u8],
    spec: &ProgramSpec,
    native: &NativeDecompilation,
) -> Result<RegionSpec, String> {
    let machine = &native.machine_ir;
    let byte_length = usize::try_from(machine.byte_length)
        .map_err(|_| "native machine extent exceeds host size".to_owned())?;
    let region_bytes = extract_location_window(bytes, spec, machine.entry, byte_length)?;
    if region_bytes.len() != byte_length {
        return Err("native region extraction did not preserve the machine extent".to_owned());
    }
    let region_end = machine
        .entry
        .value
        .0
        .checked_add(machine.byte_length)
        .ok_or_else(|| "native region range overflows".to_owned())?;
    let internal = machine
        .blocks
        .iter()
        .map(|block| block.address)
        .collect::<BTreeSet<_>>();
    let exits = machine
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .flat_map(|instruction| &instruction.edges)
        .filter(|edge| edge.kind != MachineEdgeKind::Call)
        .filter_map(|edge| edge.target)
        .filter(|target| !internal.contains(target))
        .map(|target| target.value)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let relocations = spec
        .relocations
        .iter()
        .filter(|relocation| {
            relocation.location_ref.is_some_and(|location| {
                location.address_space == machine.entry.address_space
                    && (machine.entry.value.0..region_end).contains(&location.value.0)
            })
        })
        .cloned()
        .collect();
    let address_kind = spec
        .address_spaces
        .iter()
        .find(|space| space.id == machine.entry.address_space)
        .map(|space| space.address_kind)
        .unwrap_or(AddressKind::Virtual);
    let mut unresolved_facts = native
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.blocks_stable_operation)
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect::<Vec<_>>();
    if machine.entry.address_space != 0 {
        unresolved_facts.push(format!(
            "RegionSpec v3 entry omits canonical address-space {}; FunctionIndex and native IR artifacts preserve it",
            machine.entry.address_space
        ));
    }
    if unresolved_facts.is_empty() {
        unresolved_facts.push(
            "native discovered-function packaging is decompilation-only until rewrite proof is implemented"
                .to_owned(),
        );
    }
    Ok(RegionSpec {
        schema_version: REGION_SPEC_VERSION,
        binary_sha256: machine.binary_sha256.clone(),
        symbol_name: machine.name.clone(),
        address_kind,
        entry: machine.entry.value,
        byte_length: machine.byte_length,
        bytes_sha256: format!("{:x}", Sha256::digest(&region_bytes)),
        bytes_hex: region_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        exits,
        calls: Vec::new(),
        relocations,
        observed_interior_entries: Vec::new(),
        live_in: None,
        live_out: None,
        physical_live_in: Vec::new(),
        physical_live_out: Vec::new(),
        stack_delta: None,
        stack_entry_alignment: None,
        exit_stack_relations: Vec::new(),
        global_references: Vec::new(),
        variable_locations: Vec::new(),
        assumptions: Vec::new(),
        unresolved_facts,
        replacement_ready: false,
        provenance: FactProvenance {
            source: FactSource::NativeAnalysis,
            scope: "bounded native FunctionIndex entry and recursively recovered machine blocks"
                .to_owned(),
        },
    })
}

fn native_statement_provenance(cir: &Cir, source: &str) -> Vec<StatementAddressProvenance> {
    let lines = source.lines().collect::<Vec<_>>();
    let starts = cir
        .blocks
        .iter()
        .filter_map(|block| {
            let label = format!(
                "hydir_b_{}_{}:",
                block.address.address_space, block.address.value.0
            );
            lines
                .iter()
                .position(|line| line.trim() == label)
                .map(|line| (line, block.address))
        })
        .collect::<Vec<_>>();
    starts
        .iter()
        .enumerate()
        .map(|(index, (line, address))| {
            let end = starts
                .get(index + 1)
                .map_or(lines.len().saturating_sub(1), |(next, _)| {
                    next.saturating_sub(1)
                });
            StatementAddressProvenance {
                c_start_line: u32::try_from(line + 1).unwrap_or(u32::MAX),
                c_end_line: u32::try_from(end + 1).unwrap_or(u32::MAX),
                addresses: vec![address.value],
                provenance: FactProvenance {
                    source: FactSource::NativeAnalysis,
                    scope: format!(
                        "native CIR block {}:0x{:x}",
                        address.address_space, address.value.0
                    ),
                },
            }
        })
        .collect()
}

pub fn measure_native_coverage(bytes: &[u8]) -> Result<NativeCoverageReport, String> {
    let index = discover_functions(bytes)?;
    let spec = import_elf(bytes).map_err(|error| error.to_string())?;
    let mut report = NativeCoverageReport {
        schema_version: 1,
        binary_sha256: index.binary_sha256.clone(),
        discovered_functions: index.functions.len(),
        attempted_functions: 0,
        lifted_functions: 0,
        exact_functions: 0,
        conservative_functions: 0,
        partial_functions: 0,
        exact_instructions: 0,
        opaque_instructions: 0,
        exact_families: BTreeMap::new(),
        opaque_families: BTreeMap::new(),
        opaque_samples: BTreeMap::new(),
        diagnostics: Vec::new(),
    };
    let mut attempted_ids = BTreeSet::new();
    for function in &index.functions {
        if !attempted_ids.insert(function.id.clone()) {
            continue;
        }
        report.attempted_functions += 1;
        let lifted = if function
            .evidence
            .iter()
            .any(|evidence| evidence.kind == "elf_symbol")
        {
            function
                .name
                .as_deref()
                .ok_or_else(|| "ELF symbol evidence has no name".to_owned())
                .and_then(|name| lift_machine_function(bytes, name))
        } else {
            lift_indexed_function(
                bytes,
                &spec,
                &index,
                function,
                function.state != FunctionEvidenceState::Confirmed,
            )
        };
        match lifted {
            Ok(machine) => {
                report.lifted_functions += 1;
                if machine.structural_completeness == StructuralCompleteness::Partial {
                    report.partial_functions += 1;
                }
                match machine.semantic_fidelity {
                    SemanticFidelity::ExactUnderModel => report.exact_functions += 1,
                    SemanticFidelity::Conservative | SemanticFidelity::Unknown => {
                        report.conservative_functions += 1
                    }
                }
                for instruction in machine
                    .blocks
                    .iter()
                    .flat_map(|block| block.instructions.iter())
                {
                    match &instruction.operation {
                        MachineOperation::Exact { family } => {
                            report.exact_instructions += 1;
                            *report.exact_families.entry(family.clone()).or_default() += 1;
                        }
                        MachineOperation::OpaqueEffect { .. } => {
                            report.opaque_instructions += 1;
                            *report
                                .opaque_families
                                .entry(instruction.mnemonic.clone())
                                .or_default() += 1;
                            let samples = report
                                .opaque_samples
                                .entry(instruction.mnemonic.clone())
                                .or_default();
                            if samples.len() < 8 && !samples.contains(&instruction.address) {
                                samples.push(instruction.address);
                            }
                        }
                    }
                }
            }
            Err(error) => {
                if report.diagnostics.len() < 128 {
                    report.diagnostics.push(format!("{}: {error}", function.id));
                }
            }
        }
    }
    Ok(report)
}

pub fn artifact_sha256<T: Serialize>(artifact: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(artifact)
        .map_err(|error| format!("cannot serialize native artifact: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn machine(operation: MachineOperation) -> MachineFunctionIr {
        let effects = match operation {
            MachineOperation::Exact { .. } => MachineEffects {
                read_registers: vec!["rax".to_owned()],
                written_registers: vec!["rax".to_owned()],
                read_flags: Vec::new(),
                written_flags: Vec::new(),
                undefined_flags: Vec::new(),
                memory: MachineMemoryEffect::None,
                control: MachineControlEffect::Next,
                conservative: false,
            },
            MachineOperation::OpaqueEffect { .. } => opaque_effects(MachineControlEffect::Next),
        };
        MachineFunctionIr {
            schema_version: MACHINE_FUNCTION_IR_VERSION,
            binary_sha256: "a".repeat(64),
            function_id: "f".to_owned(),
            name: "f".to_owned(),
            entry: location(0, 0x1000),
            byte_length: 1,
            blocks: vec![MachineBlock {
                label: label(0x1000),
                address: location(0, 0x1000),
                instructions: vec![MachineInstruction {
                    address: location(0, 0x1000),
                    bytes_hex: "90".to_owned(),
                    mnemonic: "nop".to_owned(),
                    operands: Vec::new(),
                    decorators: InstructionDecorators::default(),
                    operation,
                    effects,
                    edges: vec![MachineEdge {
                        kind: MachineEdgeKind::External,
                        target: Some(location(0, 0x1001)),
                    }],
                }],
            }],
            structural_completeness: StructuralCompleteness::Complete,
            semantic_fidelity: SemanticFidelity::Conservative,
            verification: VerificationStatus::StaticallyValidated,
            diagnostics: Vec::new(),
        }
    }

    #[test]
    fn opaque_effect_survives_every_native_layer() {
        let machine = machine(MachineOperation::OpaqueEffect {
            reason: "unsupported".to_owned(),
        });
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        assert!(matches!(
            cir.blocks[0].statements[0],
            CirStatement::OpaqueEffect { .. }
        ));
        assert!(!cir.rewrite_ready);
    }

    #[test]
    fn native_scalar_cfg_reaches_c_without_llvm() {
        let code = [
            0x48, 0x89, 0xf8, // mov rax, rdi
            0x48, 0x39, 0xf7, // cmp rdi, rsi
            0x73, 0x03, // jae return
            0x48, 0x89, 0xf0, // mov rax, rsi
            0xc3, // ret
        ];
        let machine = decode_function(
            &code,
            0x1000,
            0,
            "d".repeat(64),
            "max".to_owned(),
            "max".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let state = lower_state_ir(&machine).unwrap();
        let join = state
            .blocks
            .iter()
            .find(|block| block.address.value.0 == 0x100b)
            .unwrap();
        let flow = join.state_flow.as_ref().unwrap();
        assert_eq!(flow.incoming.len(), 2);
        assert_ne!(flow.incoming[0].state, flow.incoming[1].state);
        let rax_phi = flow
            .component_phis
            .iter()
            .find(|phi| phi.component == "register:rax")
            .unwrap();
        assert_eq!(rax_phi.incoming.len(), 2);
        assert_ne!(rax_phi.incoming[0].version, rax_phi.incoming[1].version);
        let function = lower_function_ir(&machine, &state).unwrap();
        assert_eq!(
            function
                .parameters
                .iter()
                .map(|parameter| parameter.location.as_str())
                .collect::<Vec<_>>(),
            vec!["rdi", "rsi"]
        );
        assert_eq!(function.returns[0].location, "rax");
        assert!(
            function
                .parameters
                .iter()
                .all(|parameter| !parameter.evidence.is_empty())
        );
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("if (!state->cf)"));
        assert!(c.contains("state->rax = (uint64_t)(state->rsi)"));
        assert!(!c.contains("LLVM"));
        let structured = hydir_c::emit_native_structured_c(&cir)
            .unwrap()
            .expect("single reducible diamond should structure");
        assert!(structured.contains("if (!state->cf)"));
        assert!(structured.contains("} else {"));
        assert!(!structured.contains("goto "));
    }

    #[test]
    fn nested_acyclic_decisions_structure_without_gotos() {
        let code = [
            0x48, 0x83, 0xff, 0x00, // cmp rdi,0
            0x74, 0x12, // je outer_else
            0x48, 0x83, 0xfe, 0x00, // cmp rsi,0
            0x74, 0x06, // je inner_else
            0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax,1
            0xc3, // ret
            0xb8, 0x02, 0x00, 0x00, 0x00, // inner_else: mov eax,2
            0xc3, // ret
            0xb8, 0x03, 0x00, 0x00, 0x00, // outer_else: mov eax,3
            0xc3, // ret
        ];
        let machine = decode_function(
            &code,
            0x1800,
            0,
            "a".repeat(64),
            "nested".to_owned(),
            "nested".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let structured = hydir_c::emit_native_structured_c(&cir)
            .unwrap()
            .expect("nested acyclic branches should structure");
        assert_eq!(structured.matches("if (state->zf)").count(), 2);
        assert_eq!(structured.matches("} else {").count(), 2);
        assert!(!structured.contains("goto "));
    }

    #[test]
    fn syscall_is_a_compilable_visible_opaque_effect() {
        let machine = decode_function(
            &[0x0f, 0x05, 0xc3],
            0x2000,
            0,
            "e".repeat(64),
            "syscall".to_owned(),
            "syscall".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let syscall = &machine.blocks[0].instructions[0];
        assert_eq!(
            syscall.effects.read_registers,
            ["r10", "r8", "r9", "rax", "rdi", "rdx", "rsi"]
        );
        assert_eq!(syscall.effects.written_registers, ["r11", "rax", "rcx"]);
        assert_eq!(syscall.effects.memory, MachineMemoryEffect::Unknown);
        assert!(
            machine
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "bounded_opaque_system_call")
        );
        let state = lower_state_ir(&machine).unwrap();
        let first = &state.blocks[0].operations[0];
        assert!(matches!(
            first,
            StateOperation::Unknown {
                output_components,
                ..
            } if output_components
                .iter()
                .any(|output| output.component == "memory:unknown")
        ));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_opaque_effect(state, UINT64_C(0x2000), \"0f05\")"));
        assert!(c.contains("goto hydir_b_0_8194"));
        assert!(!function.rewrite_ready);
        assert!(!cir.rewrite_ready);
    }

    #[test]
    fn partial_register_moves_and_extensions_are_exact_native_operations() {
        let machine = decode_function(
            &[
                0x40, 0x88, 0xf8, // mov al,dil
                0x66, 0x89, 0xf0, // mov ax,si
                0x88, 0x44, 0x24, 0x01, // mov [rsp+1],al
                0x0f, 0xb6, 0x54, 0x24, 0x01, // movzx edx,byte [rsp+1]
                0x48, 0x0f, 0xbe, 0xc8, // movsx rcx,al
                0xc3, // ret
            ],
            0x2400,
            0,
            "f".repeat(64),
            "partial-registers".to_owned(),
            "partial_registers".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert!(machine.blocks.iter().all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        let state = lower_state_ir(&machine).unwrap();
        assert!(matches!(
            &state.blocks[0].operations[0],
            StateOperation::Exact {
                input_components,
                ..
            } if input_components
                .iter()
                .any(|input| input.component == "register:rax")
        ));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("void hydir_partial_registers"));
        assert!(c.contains("state->rax & ~UINT64_C(0xff)"));
        assert!(c.contains("state->rax & ~UINT64_C(0xffff)"));
        assert!(c.contains("hydir_store8"));
        assert!(c.contains("hydir_load8"));
        assert!(c.contains("hydir_sign_extend"));
    }

    #[test]
    fn extended_byte_registers_and_multibyte_nops_are_exact() {
        let machine = decode_function(
            &[
                0x0f, 0x1f, 0x04, 0x00, // nop dword ptr [rax+rax]
                0x41, 0x80, 0xf0, 0x5a, // xor r8b,0x5a
                0xc3, // ret
            ],
            0x2420,
            0,
            "1".repeat(64),
            "extended-byte".to_owned(),
            "extended_byte".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert_eq!(
            machine.blocks[1].instructions[0].effects.written_registers,
            ["r8"]
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("state->r8 & ~UINT64_C(0xff)"));
    }

    #[test]
    fn width_generic_alu_compare_and_unary_operations_are_exact() {
        let machine = decode_function(
            &[
                0x40, 0x00, 0xf0, // add al,sil
                0x66, 0x29, 0xf0, // sub ax,si
                0x20, 0x44, 0x24, 0x01, // and byte [rsp+1],al
                0x80, 0x7c, 0x24, 0x01, 0x7f, // cmp byte [rsp+1],0x7f
                0x66, 0x85, 0xf0, // test ax,si
                0xfe, 0xc0, // inc al
                0x66, 0xff, 0xc8, // dec ax
                0xf7, 0xd8, // neg eax
                0x48, 0xf7, 0xd0, // not rax
                0xc3, // ret
            ],
            0x2500,
            0,
            "2".repeat(64),
            "generic-widths".to_owned(),
            "generic_widths".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert!(machine.blocks.iter().all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        let inc = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "inc")
            .unwrap();
        assert_eq!(
            inc.effects.written_flags,
            vec!["zf", "sf", "of", "pf", "af"]
        );
        let neg = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "neg")
            .unwrap();
        assert!(neg.effects.written_flags.contains(&"cf".to_owned()));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint8_t hydir_lhs_2500"));
        assert!(c.contains("uint16_t hydir_lhs_2503"));
        assert!(c.contains("state->of"));
        assert!(c.contains("state->cf = (uint8_t)(hydir_lhs_2517 != 0)"));
    }

    #[test]
    fn shifts_rotates_exchange_and_byte_swap_are_exact() {
        let machine = decode_function(
            &[
                0xd0, 0xe0, // shl al,1
                0x66, 0xc1, 0xe8, 0x04, // shr ax,4
                0xc1, 0xf8, 0x03, // sar eax,3
                0xd0, 0xc3, // rol bl,1
                0x48, 0xc1, 0xcb, 0x04, // ror rbx,4
                0x48, 0x93, // xchg rax,rbx
                0x0f, 0xc8, // bswap eax
                0x48, 0x0f, 0xc9, // bswap rcx
                0xc3, // ret
            ],
            0x2600,
            0,
            "6".repeat(64),
            "bit-operations".to_owned(),
            "bit_operations".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert!(machine.blocks.iter().all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint8_t hydir_lhs_2600"));
        assert!(c.contains("uint16_t hydir_lhs_2602"));
        assert!(c.contains("hydir_lhs_2602 >> 4U"));
        assert!(c.contains("state->of = hydir_undefined_flag"));
        assert!(c.contains("uint64_t hydir_left_260f"));
        assert!(c.contains("UINT32_C(0xff000000)"));
        assert!(c.contains("UINT64_C(0xff00000000000000)"));
    }

    #[test]
    fn population_and_zero_counts_have_explicit_flag_semantics() {
        let machine = decode_function(
            &[
                0xf3, 0x48, 0x0f, 0xb8, 0xc7, // popcnt rax,rdi
                0xf3, 0x48, 0x0f, 0xbd, 0xc9, // lzcnt rcx,rcx
                0xf3, 0x48, 0x0f, 0xbc, 0xd6, // tzcnt rdx,rsi
                0xc3, // ret
            ],
            0x2630,
            0,
            "6".repeat(64),
            "bit-counts".to_owned(),
            "bit_counts".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let counts = machine
            .blocks
            .iter()
            .take(3)
            .map(|block| &block.instructions[0])
            .collect::<Vec<_>>();
        assert!(counts[0].effects.undefined_flags.is_empty());
        assert_eq!(counts[1].effects.undefined_flags, ["sf", "of", "pf", "af"]);
        assert_eq!(counts[2].effects.undefined_flags, ["sf", "of", "pf", "af"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_popcount64"));
        assert!(c.contains("hydir_lzcnt64"));
        assert!(c.contains("hydir_tzcnt64"));
        assert!(c.contains("state->sf = hydir_undefined_flag"));
    }

    #[test]
    fn bit_scans_and_register_bit_tests_have_explicit_undefinedness() {
        let machine = decode_function(
            &[
                0x48, 0x0f, 0xbc, 0xc7, // bsf rax,rdi
                0x48, 0x0f, 0xbd, 0xce, // bsr rcx,rsi
                0x48, 0x0f, 0xba, 0xe7, 0x03, // bt rdi,3
                0x48, 0x0f, 0xba, 0xef, 0x04, // bts rdi,4
                0x48, 0x0f, 0xba, 0xf7, 0x05, // btr rdi,5
                0x48, 0x0f, 0xba, 0xff, 0x06, // btc rdi,6
                0xc3, // ret
            ],
            0x2638,
            0,
            "6".repeat(64),
            "bit-scans-tests".to_owned(),
            "bit_scans_tests".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        let bsf = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "bsf")
            .unwrap();
        assert_eq!(bsf.effects.written_flags, ["zf"]);
        assert_eq!(bsf.effects.undefined_flags, ["sf", "of", "cf", "pf", "af"]);
        let bt = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "bt")
            .unwrap();
        assert!(bt.effects.written_registers.is_empty());
        assert_eq!(bt.effects.written_flags, ["cf"]);
        let bts = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "bts")
            .unwrap();
        assert_eq!(bts.effects.written_registers, ["rdi"]);
        assert!(
            machine.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == "conditional_undefined_bit_scan_destination"
            })
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_undefined_value"));
        assert!(c.contains("hydir_tzcnt64(hydir_scan_source_2638"));
        assert!(c.contains("hydir_lzcnt64(hydir_scan_source_263c"));
        assert!(!c.contains("hydir_bit_mask_2640"));
        assert!(c.contains("hydir_bit_mask_2645"));
        assert!(c.contains("state->cf = (uint8_t)"));
        assert!(c.contains("state->zf = hydir_undefined_flag"));
    }

    #[test]
    fn int3_is_an_explicit_nonreturning_breakpoint_exception() {
        let machine = decode_function(
            &[0xcc],
            0x2660,
            0,
            "6".repeat(64),
            "breakpoint".to_owned(),
            "breakpoint".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let instruction = &machine.blocks[0].instructions[0];
        assert!(matches!(
            instruction.operation,
            MachineOperation::Exact { ref family } if family == "int3"
        ));
        assert_eq!(instruction.effects.control, MachineControlEffect::Stop);
        assert!(
            instruction
                .edges
                .iter()
                .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none())
        );
        assert!(
            machine
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "explicit_breakpoint_exception")
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_breakpoint(state, UINT64_C(0x2660))"));

        let software = decode_function(
            &[0xcd, 0x03],
            0x2668,
            0,
            "6".repeat(64),
            "software-interrupt".to_owned(),
            "software_interrupt".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert!(matches!(
            software.blocks[0].instructions[0].operation,
            MachineOperation::Exact { ref family } if family == "int"
        ));
        assert!(
            software
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "explicit_software_interrupt")
        );
        let state = lower_state_ir(&software).unwrap();
        let function = lower_function_ir(&software, &state).unwrap();
        let cir = lower_cir(&software, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_software_interrupt"));
    }

    #[test]
    fn vector_byte_masks_and_prefetch_hints_are_exact() {
        let machine = decode_function(
            &[
                0x66, 0x0f, 0xd7, 0xc0, // pmovmskb eax,xmm0
                0xc5, 0xfd, 0xd7, 0xc1, // vpmovmskb eax,ymm1
                0x0f, 0x18, 0x08, // prefetcht0 [rax]
                0xc3, // ret
            ],
            0x2670,
            0,
            "6".repeat(64),
            "vector-byte-mask".to_owned(),
            "vector_byte_mask".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].mnemonic, "pmovmskb");
        assert_eq!(instructions[0].effects.read_registers, ["xmm0"]);
        assert_eq!(instructions[0].effects.written_registers, ["rax"]);
        assert_eq!(instructions[1].effects.read_registers, ["ymm1"]);
        assert_eq!(instructions[2].mnemonic, "prefetcht0");
        assert_eq!(instructions[2].effects.memory, MachineMemoryEffect::None);
        assert_eq!(instructions[2].effects.read_registers, ["rax"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_byte_mask_2670"));
        assert!(c.contains("hydir_byte_2674 < 32U"));
        assert!(c.contains("architectural cache hint"));
    }

    #[test]
    fn opmask_moves_and_unmasked_zmm_byte_popcount_are_exact() {
        let machine = decode_function(
            &[
                0xc4, 0xe1, 0xfb, 0x92, 0xc8, // kmovq k1,rax
                0xc5, 0x78, 0x93, 0xf9, // kmovw r15d,k1
                0xc5, 0xf9, 0x92, 0xc9, // kmovb k1,ecx
                0x62, 0xf2, 0x7d, 0x48, 0x54, 0xd9, // vpopcntb zmm3,zmm1
                0xc3, // ret
            ],
            0x2690,
            0,
            "6".repeat(64),
            "opmask-popcount".to_owned(),
            "opmask_popcount".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].effects.read_registers, ["rax"]);
        assert_eq!(instructions[0].effects.written_registers, ["k1"]);
        assert_eq!(instructions[1].effects.read_registers, ["k1"]);
        assert_eq!(instructions[1].effects.written_registers, ["r15"]);
        assert_eq!(instructions[3].effects.read_registers, ["zmm1"]);
        assert_eq!(instructions[3].effects.written_registers, ["zmm3"]);
        let state = lower_state_ir(&machine).unwrap();
        assert!(state.blocks.iter().flat_map(|block| &block.operations).any(
            |operation| matches!(
                operation,
                StateOperation::Exact {
                    output_components,
                    ..
                } if output_components.iter().any(|component| component.component == "register:k1")
            )
        ));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint64_t k[8]"));
        assert!(c.contains("state->k[1] = (uint64_t)(state->rax)"));
        assert!(c.contains("state->r15 = (uint32_t)((uint16_t)(state->k[1]))"));
        assert!(c.contains("hydir_popcount_source_269d"));
        assert!(c.contains("hydir_popcount64"));
        assert!(c.contains("state->zmm_hi256[3]"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn unmasked_zmm_byte_permute_gf_affine_and_mask_compare_are_exact() {
        let machine = decode_function(
            &[
                0x62, 0xf2, 0x7d, 0x48, 0x8d, 0xc4, // vpermb zmm0,zmm0,zmm4
                0x62, 0xf3, 0xfd, 0x48, 0xce, 0xc1, 0x00, // vgf2p8affineqb zmm0,zmm0,zmm1,0
                0x62, 0xf2, 0x7d, 0x48, 0x75, 0xcc, // vpermi2b zmm1,zmm0,zmm4
                0x62, 0xf3, 0x85, 0x48, 0x1e, 0xc9, 0x04, // vpcmpuq k1,zmm15,zmm1,4
                0x62, 0xf2, 0xfd, 0x49, 0x8b, 0xc9, // vpcompressq zmm1{k1},zmm1
                0xc3, // ret
            ],
            0x26c0,
            0,
            "6".repeat(64),
            "zmm-byte-ops".to_owned(),
            "zmm_byte_ops".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].effects.read_registers, ["zmm0", "zmm4"]);
        assert_eq!(instructions[1].effects.read_registers, ["zmm0", "zmm1"]);
        assert_eq!(
            instructions[2].effects.read_registers,
            ["zmm0", "zmm1", "zmm4"]
        );
        assert_eq!(instructions[3].effects.read_registers, ["zmm1", "zmm15"]);
        assert_eq!(instructions[3].effects.written_registers, ["k1"]);
        assert_eq!(instructions[4].decorators.op_mask.as_deref(), Some("k1"));
        assert!(!instructions[4].decorators.zeroing);
        assert_eq!(instructions[4].effects.read_registers, ["k1", "zmm1"]);
        assert_eq!(instructions[4].effects.written_registers, ["zmm1"]);
        assert!(!instructions.iter().any(|instruction| {
            instruction
                .effects
                .read_registers
                .contains(&"mxcsr".to_owned())
                || instruction
                    .effects
                    .written_registers
                    .contains(&"mxcsr".to_owned())
        }));
        let state = lower_state_ir(&machine).unwrap();
        assert!(
            state
                .blocks
                .iter()
                .flat_map(|block| &block.operations)
                .any(|operation| matches!(
                    operation,
                    StateOperation::Exact {
                        family,
                        decorators,
                        ..
                    } if family == "vpcompressq" && decorators.op_mask.as_deref() == Some("k1")
                ))
        );
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("& UINT8_C(63)"));
        assert!(c.contains("& UINT8_C(127)"));
        assert!(c.contains("hydir_parity8"));
        assert!(c.contains("hydir_left != hydir_right"));
        assert!(c.contains("state->k[1] = hydir_compare_mask_26d3"));
        assert!(c.contains("hydir_compress_result_26da"));
        assert!(c.contains("state->k[1] >> hydir_lane_26da"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn masked_zmm_byte_permutations_preserve_merge_and_zero_semantics() {
        let machine = decode_function(
            &[
                0x62, 0xf2, 0x7d, 0x49, 0x8d, 0xc4, // vpermb zmm0{k1},zmm0,zmm4
                0x62, 0xf2, 0x7d, 0xc9, 0x8d, 0xc4, // vpermb zmm0{k1}{z},zmm0,zmm4
                0x62, 0xf2, 0x7d, 0x49, 0x75, 0xcc, // vpermi2b zmm1{k1},zmm0,zmm4
                0x62, 0xf2, 0x7d, 0xc9, 0x75, 0xcc, // vpermi2b zmm1{k1}{z},zmm0,zmm4
                0xc3, // ret
            ],
            0x26f0,
            0,
            "7".repeat(64),
            "masked-zmm-byte-ops".to_owned(),
            "masked_zmm_byte_ops".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        for instruction in &instructions[..4] {
            assert_eq!(instruction.decorators.op_mask.as_deref(), Some("k1"));
            assert!(
                instruction
                    .effects
                    .read_registers
                    .contains(&"k1".to_owned())
            );
            assert!(matches!(
                instruction.operation,
                MachineOperation::Exact { .. }
            ));
        }
        assert!(!instructions[0].decorators.zeroing);
        assert!(instructions[1].decorators.zeroing);
        assert!(!instructions[2].decorators.zeroing);
        assert!(instructions[3].decorators.zeroing);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("memcpy(hydir_permute_result_26f0"));
        assert!(c.contains("state->k[1] >> hydir_lane_26f0"));
        assert!(c.contains("memset(hydir_permute_result_26f6"));
        assert!(c.contains("hydir_permute2_indices_26fc[hydir_lane_26fc]"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn aesenc_has_byte_exact_native_round_semantics() {
        let machine = decode_function(
            &[
                0x66, 0x0f, 0x38, 0xdc, 0xc1, // aesenc xmm0,xmm1
                0xc3, // ret
            ],
            0x2680,
            0,
            "6".repeat(64),
            "aes-round".to_owned(),
            "aes_round".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let aes = &machine.blocks[0].instructions[0];
        assert!(matches!(
            aes.operation,
            MachineOperation::Exact { ref family } if family == "aesenc"
        ));
        assert_eq!(aes.effects.read_registers, ["xmm0", "xmm1"]);
        assert_eq!(aes.effects.written_registers, ["xmm0"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("static inline uint8_t hydir_aes_sbox"));
        assert!(c.contains("hydir_aesenc_round(hydir_aes_state_2680"));
    }

    #[test]
    fn packed_word_half_shuffles_are_lane_exact() {
        let machine = decode_function(
            &[
                0xf2, 0x0f, 0x70, 0xc1, 0x1b, // pshuflw xmm0,xmm1,0x1b
                0xf3, 0x0f, 0x70, 0xd3, 0x1b, // pshufhw xmm2,xmm3,0x1b
                0xc3, // ret
            ],
            0x2690,
            0,
            "6".repeat(64),
            "word-half-shuffles".to_owned(),
            "word_half_shuffles".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].mnemonic, "pshuflw");
        assert_eq!(instructions[1].mnemonic, "pshufhw");
        assert!(
            instructions[..2]
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("2U * (0U + hydir_word_2690)"));
        assert!(c.contains("2U * (4U + hydir_word_2695)"));
    }

    #[test]
    fn scalar_vector_inserts_minimum_and_non_temporal_store_are_native() {
        let machine = decode_function(
            &[
                0x66, 0x0f, 0xc4, 0xc0, 0x03, // pinsrw xmm0,eax,3
                0x66, 0x0f, 0x3a, 0x22, 0xc9, 0x02, // pinsrd xmm1,ecx,2
                0x66, 0x48, 0x0f, 0x3a, 0x22, 0xd2, 0x01, // pinsrq xmm2,rdx,1
                0xf2, 0x0f, 0x5d, 0xc1, // minsd xmm0,xmm1
                0xc5, 0xfd, 0xe7, 0x07, // vmovntdq ymmword ptr [rdi],ymm0
                0xc3, // ret
            ],
            0x26a0,
            0,
            "6".repeat(64),
            "scalar-vector-inserts".to_owned(),
            "scalar_vector_inserts".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].mnemonic, "pinsrw");
        assert_eq!(instructions[1].mnemonic, "pinsrd");
        assert_eq!(instructions[2].mnemonic, "pinsrq");
        assert_eq!(instructions[3].mnemonic, "minsd");
        assert_eq!(instructions[4].mnemonic, "vmovntdq");
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        let state = lower_state_ir(&machine).unwrap();
        let non_temporal = state
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .find(|operation| matches!(operation, StateOperation::Exact { family, .. } if family == "vmovntdq"))
            .unwrap();
        assert!(matches!(
            non_temporal,
            StateOperation::Exact { input_components, output_components, .. }
                if input_components.iter().any(|component| component.component == "memory:volatile")
                    && output_components.iter().any(|component| component.component == "memory:volatile")
        ));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_insert_scalar_26a0"));
        assert!(c.contains("hydir_insert_scalar_26ab"));
        assert!(c.contains("\"min\""));
        assert!(c.contains("hydir_non_temporal_vector_store"));
    }

    #[test]
    fn byte_broadcast_and_vector_test_are_exact() {
        let machine = decode_function(
            &[
                0xc4, 0xe2, 0x7d, 0x78, 0xc8, // vpbroadcastb ymm1,xmm0
                0xc4, 0xe2, 0x7d, 0x17, 0xdb, // vptest ymm3,ymm3
                0xc3, // ret
            ],
            0x26d0,
            0,
            "6".repeat(64),
            "broadcast-test".to_owned(),
            "broadcast_test".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].mnemonic, "vpbroadcastb");
        assert_eq!(instructions[1].mnemonic, "vptest");
        assert_eq!(instructions[1].effects.written_flags.len(), 6);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint8_t hydir_broadcast_26d0"));
        assert!(c.contains("hydir_test_andn_26d5"));
        assert!(c.contains("state->cf = (uint8_t)(hydir_test_andn_26d5 == 0U)"));
    }

    #[test]
    fn narrow_variable_shifts_and_rotate_through_carry_are_explicit() {
        let machine = decode_function(
            &[
                0xd2, 0xea, // shr dl,cl
                0x48, 0xd1, 0xda, // rcr rdx,1
                0xd2, 0xd0, // rcl al,cl
                0xc3, // ret
            ],
            0x26e0,
            0,
            "6".repeat(64),
            "carry-rotates".to_owned(),
            "carry_rotates".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].mnemonic, "shr");
        assert_eq!(instructions[1].mnemonic, "rcr");
        assert_eq!(instructions[2].mnemonic, "rcl");
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(instructions[1].effects.read_flags, ["cf"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("shr_overshift_result"));
        assert!(c.contains("hydir_rotate_count_26e2"));
        assert!(c.contains("hydir_rotate_carry_26e5"));
    }

    #[test]
    fn pushfq_and_popfq_preserve_explicit_flags_environment_state() {
        let machine = decode_function(
            &[0x9c, 0x9d, 0xc3], // pushfq; popfq; ret
            0x26f0,
            0,
            "6".repeat(64),
            "flags-stack".to_owned(),
            "flags_stack".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions[0].effects.memory, MachineMemoryEffect::Write);
        assert_eq!(instructions[1].effects.memory, MachineMemoryEffect::Read);
        assert!(
            instructions[0]
                .effects
                .read_registers
                .contains(&"rflags_unmodeled".to_owned())
        );
        assert!(
            instructions[1]
                .effects
                .written_registers
                .contains(&"rflags_unmodeled".to_owned())
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint64_t rflags_unmodeled"));
        assert!(c.contains("hydir_pushfq(state, UINT64_C(0x26f0))"));
        assert!(c.contains("hydir_popfq(state, UINT64_C(0x26f1))"));
    }

    #[test]
    fn parity_and_auxiliary_carry_are_first_class_native_flags() {
        let machine = decode_function(
            &[
                0x04, 0x01, // add al,1
                0x84, 0xc0, // test al,al
                0x0f, 0x4a, 0xc2, // cmovp eax,edx
                0x0f, 0x9b, 0xc1, // setnp cl
                0x7a, 0x01, // jp +1
                0x90, // fallthrough nop
                0xc3, // ret
            ],
            0x2640,
            0,
            "9".repeat(64),
            "parity-flags".to_owned(),
            "parity_flags".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        let add = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "add")
            .unwrap();
        assert_eq!(add.effects.written_flags.len(), 6);
        assert!(add.effects.written_flags.contains(&"pf".to_owned()));
        assert!(add.effects.written_flags.contains(&"af".to_owned()));
        let test = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "test")
            .unwrap();
        assert!(test.effects.written_flags.contains(&"pf".to_owned()));
        assert_eq!(test.effects.undefined_flags, ["af"]);
        assert!(
            instructions
                .iter()
                .filter(|instruction| matches!(
                    instruction.mnemonic.as_str(),
                    "cmovp" | "setnp" | "jp"
                ))
                .all(|instruction| instruction.effects.read_flags == ["pf"])
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("state->pf = hydir_parity8"));
        assert!(c.contains("state->af = hydir_undefined_flag"));
        assert!(c.contains("if (state->pf)"));
        assert!(c.contains("(!state->pf)"));
    }

    #[test]
    fn variable_rotates_preserve_zero_count_and_expose_conditional_undefined_overflow() {
        let machine = decode_function(
            &[
                0x48, 0xd3, 0xc2, // rol rdx,cl
                0x48, 0xd3, 0xca, // ror rdx,cl
                0xc3, // ret
            ],
            0x2650,
            0,
            "7".repeat(64),
            "variable-rotates".to_owned(),
            "variable_rotates".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        assert!(machine.blocks.iter().take(2).all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "summarized_variable_rotate_flags")
                .count(),
            2
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("if (hydir_count_2650 != 0U)"));
        assert!(c.contains("if (hydir_count_2650 == 1U)"));
        assert!(c.contains("state->of = hydir_undefined_flag"));
    }

    #[test]
    fn variable_shifts_preserve_zero_count_and_expose_conditional_undefined_overflow() {
        let machine = decode_function(
            &[
                0xd3, 0xe0, // shl eax,cl
                0x48, 0xd3, 0xe8, // shr rax,cl
                0x48, 0xd3, 0xf8, // sar rax,cl
                0xc3, // ret
            ],
            0x2660,
            0,
            "5".repeat(64),
            "variable-shifts".to_owned(),
            "variable_shifts".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        assert!(machine.blocks.iter().take(3).all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "summarized_variable_shift_flags")
                .count(),
            3
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("if (hydir_count_2660 != 0U)"));
        assert!(c.contains("if (hydir_count_2660 == 1U)"));
        assert!(c.contains("hydir_lhs_2662 >> (hydir_count_2662 - 1U)"));
        assert!(c.contains("state->of = hydir_undefined_flag"));
    }

    #[test]
    fn double_shifts_cover_immediate_and_variable_multiword_arithmetic() {
        let machine = decode_function(
            &[
                0x0f, 0xa4, 0xd0, 0x04, // shld eax,edx,4
                0x48, 0x0f, 0xac, 0xd0, 0x01, // shrd rax,rdx,1
                0x0f, 0xa5, 0xd0, // shld eax,edx,cl
                0x48, 0x0f, 0xad, 0xd0, // shrd rax,rdx,cl
                0xc3, // ret
            ],
            0x2680,
            0,
            "4".repeat(64),
            "double-shifts".to_owned(),
            "double_shifts".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        assert!(machine.blocks.iter().take(4).all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| {
                    diagnostic.code == "summarized_variable_double_shift_flags"
                })
                .count(),
            2
        );
        let first = &machine.blocks[0].instructions[0];
        assert_eq!(first.effects.undefined_flags, ["of", "af"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_lhs_2680 << hydir_count_2680"));
        assert!(c.contains("hydir_rhs_2684 << (64U - hydir_count_2684)"));
        assert!(c.contains("if (hydir_count_2689 != 0U)"));
        assert!(c.contains("state->of = hydir_undefined_flag"));
    }

    #[test]
    fn common_locked_atomics_have_exact_helper_backed_semantics() {
        let machine = decode_function(
            &[
                0xf0, 0x48, 0x0f, 0xc1, 0x07, // lock xadd [rdi],rax
                0xf0, 0x48, 0x0f, 0xb1, 0x17, // lock cmpxchg [rdi],rdx
                0xf0, 0x83, 0x4c, 0x24, 0xc0, 0x00, // lock or dword [rsp-0x40],0
                0x48, 0x87, 0x0f, // xchg [rdi],rcx (implicitly locked)
                0xc3, // ret
            ],
            0x2700,
            0,
            "3".repeat(64),
            "bounded-atomics".to_owned(),
            "bounded_atomics".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let atomics = machine
            .blocks
            .iter()
            .take(4)
            .map(|block| &block.instructions[0])
            .collect::<Vec<_>>();
        assert_eq!(
            atomics
                .iter()
                .filter_map(|instruction| match &instruction.operation {
                    MachineOperation::Exact { family } => Some(family.as_str()),
                    MachineOperation::OpaqueEffect { .. } => None,
                })
                .collect::<Vec<_>>(),
            ["lock_xadd", "lock_cmpxchg", "lock_or", "atomic_xchg"]
        );
        assert!(atomics.iter().all(|instruction| {
            instruction.effects.memory == MachineMemoryEffect::ReadWrite
                && instruction.effects.read_registers.len() < ALL_REGISTERS.len()
                && !instruction.effects.conservative
        }));
        assert_eq!(atomics[0].effects.written_registers, ["rax"]);
        assert!(
            atomics[1]
                .effects
                .read_registers
                .contains(&"rax".to_owned())
        );
        assert_eq!(atomics[1].effects.written_registers, ["rax"]);
        assert_eq!(atomics[3].effects.written_registers, ["rcx"]);
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "bounded_opaque_atomic")
                .count(),
            0
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert_eq!(c.matches("hydir_opaque_effect").count(), 1);
        assert!(c.contains("hydir_atomic_rmw(state"));
        assert!(c.contains("hydir_atomic_cmpxchg(state"));
        assert!(c.contains("hydir_atomic_exchange(state"));
        assert!(c.contains("\"or\""));
    }

    #[test]
    fn common_floating_and_x87_operations_have_explicit_state_and_exception_edges() {
        let machine = decode_function(
            &[
                0xf3, 0x0f, 0x58, 0xc1, // addss xmm0,xmm1
                0xc5, 0xf4, 0x58, 0xc2, // vaddps ymm0,ymm1,ymm2
                0xd8, 0xc1, // fadd st0,st1
                0xc3, // ret
            ],
            0x2740,
            0,
            "b".repeat(64),
            "bounded-float".to_owned(),
            "bounded_float".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let scalar = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "addss")
            .expect("scalar SSE addition should be represented exactly");
        assert!(matches!(
            scalar.operation,
            MachineOperation::Exact { ref family } if family == "addss"
        ));
        assert!(scalar.effects.read_registers.contains(&"mxcsr".to_owned()));
        assert!(
            scalar
                .effects
                .written_registers
                .contains(&"mxcsr".to_owned())
        );
        assert!(
            scalar
                .edges
                .iter()
                .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none())
        );
        let packed = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "vaddps")
            .expect("packed AVX addition should be represented exactly");
        assert!(matches!(
            packed.operation,
            MachineOperation::Exact { ref family } if family == "vaddps"
        ));
        assert!(packed.effects.read_registers.contains(&"mxcsr".to_owned()));
        assert!(
            packed
                .effects
                .written_registers
                .contains(&"ymm0".to_owned())
        );
        let x87 = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "fadd")
            .expect("common x87 addition should be represented exactly");
        assert!(matches!(
            x87.operation,
            MachineOperation::Exact { ref family } if family == "fadd"
        ));
        assert!(
            x87.effects
                .read_registers
                .contains(&"x87_status".to_owned())
        );
        assert!(
            x87.effects
                .read_registers
                .contains(&"x87_control".to_owned())
        );
        assert!(
            x87.effects
                .written_registers
                .contains(&"x87_tag".to_owned())
        );
        assert!(
            x87.edges
                .iter()
                .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none())
        );
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_x87_exception")
                .count(),
            1
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert_eq!(c.matches("hydir_opaque_effect").count(), 1);
        assert!(c.contains("hydir_fp_binary32(state"));
        assert!(c.contains("hydir_x87_operation(state"));
        assert!(c.contains("uint8_t x87_st[8][10]"));
        assert!(c.contains("uint32_t mxcsr"));
    }

    #[test]
    fn carry_arithmetic_and_accumulator_sign_extension_are_exact() {
        let machine = decode_function(
            &[
                0x40, 0x10, 0xf0, // adc al,sil
                0x66, 0x19, 0xf0, // sbb ax,si
                0x11, 0xf0, // adc eax,esi
                0x48, 0x19, 0xf0, // sbb rax,rsi
                0x66, 0x98, // cbw
                0x98, // cwde
                0x48, 0x98, // cdqe
                0x66, 0x99, // cwd
                0x99, // cdq
                0x48, 0x99, // cqo
                0xc3, // ret
            ],
            0x2640,
            0,
            "8".repeat(64),
            "carry-and-sign".to_owned(),
            "carry_and_sign".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let carry_operations = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.mnemonic.as_str(), "adc" | "sbb"))
            .collect::<Vec<_>>();
        assert_eq!(carry_operations.len(), 4);
        assert!(
            carry_operations
                .iter()
                .all(|instruction| instruction.effects.read_flags == ["cf"])
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_carry_out_2640"));
        assert!(c.contains("hydir_carry_out_2643"));
        assert!(c.contains("hydir_sign_extend((uint8_t)state->rax, 8U)"));
        assert!(c.contains("state->rdx = ((state->rax >> 63U)"));
    }

    #[test]
    fn generic_stack_operands_preserve_x86_rsp_evaluation_order() {
        let machine = decode_function(
            &[
                0x6a, 0xff, // push -1
                0xff, 0x74, 0x24, 0x08, // push qword [rsp+8]
                0x8f, 0x04, 0x24, // pop qword [rsp]
                0x5c, // pop rsp
                0xc3, // ret
            ],
            0x2660,
            0,
            "9".repeat(64),
            "generic-stack".to_owned(),
            "generic_stack".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let state = lower_state_ir(&machine).unwrap();
        assert!(state.blocks.iter().all(|block| {
            block.state_flow.as_ref().is_some_and(|flow| {
                flow.component_outputs
                    .iter()
                    .any(|output| output.component == "memory:stack")
            })
        }));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        let pop_value = c.find("uint64_t hydir_pop_2666").unwrap();
        let increment = c[pop_value..].find("state->rsp += UINT64_C(8)").unwrap() + pop_value;
        let store = c[increment..].find("hydir_store64").unwrap() + increment;
        assert!(pop_value < increment && increment < store);
        let pop_rsp = c.find("uint64_t hydir_pop_2669").unwrap();
        let rsp_write = c[pop_rsp..]
            .find("state->rsp = (uint64_t)(hydir_pop_2669)")
            .unwrap()
            + pop_rsp;
        let rsp_increment = c[pop_rsp..].find("state->rsp += UINT64_C(8)").unwrap() + pop_rsp;
        assert!(rsp_increment < rsp_write);
    }

    #[test]
    fn signed_multiply_preserves_architectural_undefined_flags() {
        let machine = decode_function(
            &[
                0x66, 0x0f, 0xaf, 0xc3, // imul ax,bx
                0x0f, 0xaf, 0xc6, // imul eax,esi
                0x48, 0x0f, 0xaf, 0xc3, // imul rax,rbx
                0x6b, 0xca, 0xfd, // imul ecx,edx,-3
                0xc3, // ret
            ],
            0x2680,
            0,
            "7".repeat(64),
            "signed-multiply".to_owned(),
            "signed_multiply".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let multiplies = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| instruction.mnemonic == "imul")
            .collect::<Vec<_>>();
        assert_eq!(multiplies.len(), 4);
        assert!(multiplies.iter().all(|instruction| {
            instruction.effects.written_flags == ["of", "cf"]
                && instruction.effects.undefined_flags == ["zf", "sf", "pf", "af"]
        }));
        let state = lower_state_ir(&machine).unwrap();
        assert!(state.blocks.iter().any(|block| block.operations.iter().any(
            |operation| matches!(
                operation,
                StateOperation::Exact {
                    undefined_outputs,
                    ..
                } if undefined_outputs == &["flag:zf", "flag:sf", "flag:pf", "flag:af"]
            )
        )));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_imul_overflow"));
        assert!(c.contains("state->of = state->cf"));
        assert!(c.contains("state->zf = hydir_undefined_flag"));
        assert!(c.contains("state->sf = hydir_undefined_flag"));
    }

    #[test]
    fn implicit_accumulator_multiply_produces_full_width_results() {
        let machine = decode_function(
            &[
                0xf6, 0xe1, // mul cl
                0x66, 0xf7, 0xe1, // mul cx
                0xf7, 0xe1, // mul ecx
                0x48, 0xf7, 0xe1, // mul rcx
                0xf6, 0xe9, // imul cl
                0x66, 0xf7, 0xe9, // imul cx
                0xf7, 0xe9, // imul ecx
                0x48, 0xf7, 0xe9, // imul rcx
                0xc3, // ret
            ],
            0x2690,
            0,
            "4".repeat(64),
            "full-multiply".to_owned(),
            "full_multiply".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert!(machine.blocks.iter().take(8).all(|block| {
            let effects = &block.instructions[0].effects;
            effects.written_flags == ["of", "cf"]
                && effects.undefined_flags == ["zf", "sf", "pf", "af"]
        }));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_umul64wide(state->rax"));
        assert!(c.contains("hydir_mul_left_magnitude_26a1"));
        assert!(c.contains("hydir_product_high_26a1"));
        assert!(c.contains("state->of = state->cf"));
    }

    #[test]
    fn unsigned_division_has_exact_normal_path_and_explicit_divide_error() {
        let machine = decode_function(
            &[
                0xf6, 0xf1, // div cl
                0x66, 0xf7, 0xf1, // div cx
                0xf7, 0xf1, // div ecx
                0x48, 0xf7, 0xf1, // div rcx
                0xc3, // ret
            ],
            0x26a0,
            0,
            "2".repeat(64),
            "unsigned-divide".to_owned(),
            "unsigned_divide".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let divides = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| instruction.mnemonic == "div")
            .collect::<Vec<_>>();
        assert_eq!(divides.len(), 4);
        assert!(divides.iter().all(|instruction| {
            matches!(instruction.operation, MachineOperation::Exact { .. })
                && instruction.effects.undefined_flags.len() == 6
        }));
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_divide_exception")
                .count(),
            4
        );
        assert!(divides.iter().all(|instruction| {
            instruction
                .edges
                .iter()
                .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none())
        }));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint16_t hydir_dividend_26a0"));
        assert!(c.contains("UINT16_MAX) hydir_divide_error"));
        assert!(c.contains("UINT32_MAX) hydir_divide_error"));
        assert!(c.contains("hydir_udiv128by64(state->rdx, state->rax"));
        assert!(c.contains("state->cf = hydir_undefined_flag"));
    }

    #[test]
    fn signed_division_has_width_generic_normal_path_semantics() {
        let machine = decode_function(
            &[
                0xf6, 0xf9, // idiv cl
                0x66, 0xf7, 0xf9, // idiv cx
                0xf7, 0xf9, // idiv ecx
                0x48, 0xf7, 0xf9, // idiv rcx
                0xc3, // ret
            ],
            0x26b0,
            0,
            "3".repeat(64),
            "signed-divide".to_owned(),
            "signed_divide".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        assert!(machine.blocks.iter().take(4).all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("INT8_MIN"));
        assert!(c.contains("INT16_MIN"));
        assert!(c.contains("INT32_MIN"));
        assert!(c.contains("hydir_divisor_magnitude_26b7"));
        assert!(c.contains("hydir_quotient_negative_26b7"));
    }

    #[test]
    fn common_sse_and_avx_bitwise_dataflow_is_exact_and_alias_aware() {
        let machine = decode_function(
            &[
                0xf3, 0x0f, 0x6f, 0xc1, // movdqu xmm0,xmm1
                0xf3, 0x0f, 0x7f, 0x04, 0x24, // movdqu [rsp],xmm0
                0xf3, 0x0f, 0x6f, 0x14, 0x24, // movdqu xmm2,[rsp]
                0x66, 0x0f, 0xef, 0xc2, // pxor xmm0,xmm2
                0x0f, 0x57, 0xc8, // xorps xmm1,xmm0
                0xc5, 0xfe, 0x6f, 0xc1, // vmovdqu ymm0,ymm1
                0xc5, 0xfd, 0xef, 0xd1, // vpxor ymm2,ymm0,ymm1
                0xc5, 0xf8, 0x57, 0xd1, // vxorps xmm2,xmm0,xmm1
                0xc3, // ret
            ],
            0x26c0,
            0,
            "b".repeat(64),
            "vector-bitwise".to_owned(),
            "vector_bitwise".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let state = lower_state_ir(&machine).unwrap();
        let vector_components = state.blocks[0]
            .state_flow
            .as_ref()
            .unwrap()
            .component_phis
            .iter()
            .filter(|phi| phi.component.starts_with("register:ymm"))
            .map(|phi| phi.component.as_str())
            .collect::<BTreeSet<_>>();
        assert!(vector_components.contains("register:ymm0"));
        assert!(vector_components.contains("register:ymm1"));
        assert!(vector_components.contains("register:ymm2"));
        assert!(!vector_components.contains("register:xmm0"));
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint8_t ymm[32][32]"));
        assert!(c.contains("memmove(state->ymm[0], state->ymm[1], 16U)"));
        assert!(c.contains("hydir_vec_lhs_26d2[16]"));
        assert!(c.contains("hydir_vec_lhs_26d9[32]"));
        assert!(c.contains("memset(state->ymm[2] + 16U, 0, 16U)"));
    }

    #[test]
    fn optimized_avx2_integer_lane_operations_are_exact() {
        let machine = decode_function(
            &[
                0xc4, 0xe2, 0x7d, 0x59, 0x0d, 0x00, 0x00, 0x00,
                0x00, // vpbroadcastq ymm1,[rip]
                0xc5, 0x35, 0xf4, 0xd1, // vpmuludq ymm10,ymm9,ymm1
                0xc4, 0xc1, 0x25, 0x73, 0xd1, 0x20, // vpsrlq ymm11,ymm9,32
                0xc4, 0x41, 0x2d, 0xd4, 0xd3, // vpaddq ymm10,ymm10,ymm11
                0xc4, 0xc1, 0x2d, 0x73, 0xf2, 0x20, // vpsllq ymm10,ymm10,32
                0xc4, 0xe3, 0x7d, 0x39, 0xc1, 0x01, // vextracti128 xmm1,ymm0,1
                0xc5, 0xf9, 0x70, 0xc8, 0xee, // vpshufd xmm1,xmm0,0xee
                0xc4, 0xe2, 0x7d, 0x18, 0x05, 0x00, 0x00, 0x00,
                0x00, // vbroadcastss ymm0,[rip]
                0xc4, 0xe2, 0xc8, 0xf2, 0xc0, // andn rax,rsi,rax
                0xc3, // ret
            ],
            0x26d0,
            0,
            "5".repeat(64),
            "optimized-avx2".to_owned(),
            "optimized_avx2".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert!(machine.blocks.iter().all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_broadcast_"));
        assert!(c.contains("hydir_lane_result_"));
        assert!(c.contains("hydir_source_lane_"));
        assert!(c.contains("hydir_vec_source_"));
        assert!(c.contains("state->sf = (uint8_t)"));
        assert!(c.contains("state->cf = 0U"));
    }

    #[test]
    fn relocatable_avx2_fixture_reaches_both_native_c_views_without_opacity() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/avx2_integer.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.exact_instructions, 66);
        assert_eq!(coverage.opaque_instructions, 0);
        let native = decompile_symbol(bytes, "avx2_integer_kernel").unwrap();
        assert_eq!(
            native.machine_ir.semantic_fidelity,
            SemanticFidelity::ExactUnderModel
        );
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert!(native.machine_ir.blocks.iter().all(|block| matches!(
            block.instructions[0].operation,
            MachineOperation::Exact { .. }
        )));
        assert!(native.low_level_c.contains("hydir_lane_result_"));
        assert!(native.low_level_c.contains("hydir_sat_wide_"));
        assert!(native.low_level_c.contains("UINT32_C(255)"));
        assert!(native.low_level_c.contains("INT16_MAX"));
        assert!(native.low_level_c.contains("hydir_pack_result_"));
        for family in [
            "vpaddb",
            "vpsubq",
            "vpmulld",
            "vpcmpeqq",
            "vpcmpgtq",
            "vpminsw",
            "vpmaxud",
            "vpunpcklbw",
            "vpunpckhqdq",
            "vpsllw",
            "vpsrad",
            "vpshufb",
            "vinserti128",
            "vpaddusb",
            "vpsubsw",
            "vpacksswb",
            "vpackusdw",
        ] {
            assert!(native.machine_ir.blocks.iter().any(|block| {
                block.instructions.iter().any(
                    |instruction| matches!(&instruction.operation, MachineOperation::Exact { family: exact } if exact == family),
                )
            }));
        }
        assert!(
            native
                .structured_c
                .as_deref()
                .is_some_and(|c| c.contains("hydir_broadcast_"))
        );
    }

    #[test]
    fn masked_and_unmasked_avx512_bitwise_float_and_moves_preserve_full_zmm_state() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/avx512_opaque.o");
        let native = decompile_symbol(bytes, "hydir_avx512_opaque").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 41);
        for instruction in &instructions[..40] {
            assert!(matches!(
                instruction.operation,
                MachineOperation::Exact { .. }
            ));
            assert!(!instruction.effects.conservative);
            assert!(
                instruction
                    .effects
                    .read_registers
                    .iter()
                    .chain(&instruction.effects.written_registers)
                    .any(|register| register.starts_with("zmm"))
            );
            assert!(
                !instruction
                    .effects
                    .read_registers
                    .contains(&"rax".to_owned())
            );
        }
        assert_eq!(instructions[2].mnemonic, "vmovdqu64");
        assert_eq!(instructions[3].effects.memory, MachineMemoryEffect::Write);
        assert_eq!(instructions[4].effects.memory, MachineMemoryEffect::Read);
        assert_eq!(instructions[5].mnemonic, "vmovdqa64");
        let masked = instructions[6];
        assert!(matches!(
            masked.operation,
            MachineOperation::Exact { ref family } if family == "vpxord"
        ));
        assert!(!masked.effects.conservative);
        assert_eq!(masked.decorators.op_mask.as_deref(), Some("k1"));
        assert_eq!(
            masked.effects.read_registers,
            ["k1", "zmm1", "zmm2", "zmm3"]
        );
        assert!(
            native
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "explicit_simd_float_exception" })
        );
        assert!(
            !native
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "bounded_opaque_extended_data")
        );
        assert!(
            native
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "explicit_vector_alignment_exception")
        );
        assert!(native.low_level_c.contains("uint8_t zmm_hi256[32][32]"));
        assert!(native.low_level_c.contains("hydir_vec_result_0[64]"));
        assert!(native.low_level_c.contains("state->zmm_hi256[1]"));
        assert!(native.low_level_c.contains("hydir_vector_move_c[64]"));
        assert!(native.low_level_c.contains("state->zmm_hi256[6]"));
        assert!(native.low_level_c.contains("hydir_aligned_vector_move"));
        assert!(native.low_level_c.contains("memcpy(hydir_vec_result_24"));
        assert!(
            native
                .low_level_c
                .contains("state->k[1] >> (hydir_vec_i_24 / 4U)")
        );
        assert!(!native.low_level_c.contains("hydir_vec_right_e5"));
        assert!(native.low_level_c.contains("hydir_load8("));
        assert!(!native.low_level_c.contains("hydir_permute_source_eb"));
        assert!(!native.low_level_c.contains("hydir_permute2_second_f1"));
        assert!(native.low_level_c.contains("hydir_permute_index_eb"));
        assert!(native.low_level_c.contains("hydir_index_f1"));
        assert_eq!(native.low_level_c.matches("/* opaque ").count(), 0);
        let zmm_components = native.state_ir.blocks[0]
            .state_flow
            .as_ref()
            .unwrap()
            .component_phis
            .iter()
            .map(|phi| phi.component.as_str())
            .collect::<BTreeSet<_>>();
        assert!(zmm_components.contains("register:ymm0"));
        assert!(zmm_components.contains("register:ymm1"));
        assert!(
            !zmm_components
                .iter()
                .any(|component| component.starts_with("register:zmm"))
        );
        assert!(native.function_ir.parameters.iter().any(|parameter| {
            parameter.location == "zmm2" && parameter.type_name == "float32x16"
        }));
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(
            native.machine_ir.semantic_fidelity,
            SemanticFidelity::Conservative
        );
        assert!(!native.function_ir.rewrite_ready);
    }

    #[test]
    fn avx512_bitwise_masks_use_element_lanes_and_merge_or_zero() {
        let machine = decode_function(
            &[
                0x62, 0xf1, 0x75, 0x49, 0xef, 0xda, // vpxord zmm3{k1},zmm1,zmm2
                0x62, 0xf1, 0x75, 0xc9, 0xef, 0xda, // vpxord zmm3{k1}{z},zmm1,zmm2
                0x62, 0xf1, 0xd5, 0x4a, 0xdb, 0xe6, // vpandq zmm4{k2},zmm5,zmm6
                0x62, 0xf1, 0xd5, 0xca, 0xdb, 0xe6, // vpandq zmm4{k2}{z},zmm5,zmm6
                0x62, 0xd1, 0xbd, 0x4b, 0xeb, 0xf9, // vporq zmm7{k3},zmm8,zmm9
                0x62, 0xd1, 0xbd, 0xcb, 0xeb, 0xf9, // vporq zmm7{k3}{z},zmm8,zmm9
                0xc3,
            ],
            0x2720,
            0,
            "8".repeat(64),
            "masked-zmm-bitwise".to_owned(),
            "masked_zmm_bitwise".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k1", "zmm1", "zmm2", "zmm3"]
        );
        assert_eq!(
            instructions[1].effects.read_registers,
            ["k1", "zmm1", "zmm2"]
        );
        assert_eq!(
            instructions[2].effects.read_registers,
            ["k2", "zmm4", "zmm5", "zmm6"]
        );
        assert_eq!(
            instructions[3].effects.read_registers,
            ["k2", "zmm5", "zmm6"]
        );
        assert_eq!(
            instructions[4].effects.read_registers,
            ["k3", "zmm7", "zmm8", "zmm9"]
        );
        assert_eq!(
            instructions[5].effects.read_registers,
            ["k3", "zmm8", "zmm9"]
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("memcpy(hydir_vec_result_2720"));
        assert!(c.contains("state->k[1] >> (hydir_vec_i_2720 / 4U)"));
        assert!(c.contains("state->k[2] >> (hydir_vec_i_272c / 8U)"));
        assert!(c.contains("state->k[3] >> (hydir_vec_i_2738 / 8U)"));
        assert!(c.contains("memset(hydir_vec_result_273e"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn avx512_masked_moves_preserve_fault_suppression_and_merge_modes() {
        let machine = decode_function(
            &[
                0x62, 0xf1, 0x7e, 0x49, 0x6f, 0xc1, // vmovdqu32 zmm0{k1},zmm1
                0x62, 0xf1, 0x7e, 0xc9, 0x6f, 0xc1, // vmovdqu32 zmm0{k1}{z},zmm1
                0x62, 0xf1, 0xfe, 0x4a, 0x6f, 0x17, // vmovdqu64 zmm2{k2},[rdi]
                0x62, 0xf1, 0xfe, 0xca, 0x6f, 0x17, // vmovdqu64 zmm2{k2}{z},[rdi]
                0x62, 0xf1, 0xfe, 0x4b, 0x7f, 0x26, // vmovdqu64 [rsi]{k3},zmm4
                0x62, 0xf1, 0x7d, 0x4c, 0x6f, 0x2a, // vmovdqa32 zmm5{k4},[rdx]
                0xc3,
            ],
            0x2760,
            0,
            "9".repeat(64),
            "masked-zmm-moves".to_owned(),
            "masked_zmm_moves".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions[..6]
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k1", "zmm0", "zmm1"]
        );
        assert_eq!(instructions[1].effects.read_registers, ["k1", "zmm1"]);
        assert_eq!(
            instructions[2].effects.read_registers,
            ["k2", "rdi", "zmm2"]
        );
        assert_eq!(instructions[3].effects.read_registers, ["k2", "rdi"]);
        assert_eq!(
            instructions[4].effects.read_registers,
            ["k3", "rsi", "zmm4"]
        );
        assert_eq!(
            instructions[5].effects.read_registers,
            ["k4", "rdx", "zmm5"]
        );
        assert_eq!(instructions[2].effects.memory, MachineMemoryEffect::Read);
        assert_eq!(instructions[4].effects.memory, MachineMemoryEffect::Write);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_masked_move_result_2760"));
        assert!(c.contains("hydir_lane_2760 * 4U"));
        assert!(c.contains("hydir_masked_vector_move(state, UINT64_C(0x276c)"));
        assert!(c.contains("state->k[2], 0U, 0U"));
        assert!(c.contains("state->k[3], 1U, 0U"));
        assert!(c.contains("state->k[4], 0U, 1U"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn avx512_masked_and_broadcast_float_lanes_are_exception_aware() {
        let machine = decode_function(
            &[
                0x62, 0xf1, 0x74, 0x49, 0x58, 0xc2, // vaddps zmm0{k1},zmm1,zmm2
                0x62, 0xf1, 0x74, 0xc9, 0x58, 0xc2, // vaddps zmm0{k1}{z},zmm1,zmm2
                0x62, 0xf1, 0x5c, 0x5a, 0x58, 0x1f, // vaddps zmm3{k2},zmm4,[rdi]{1to16}
                0x62, 0xf1, 0xcd, 0xdb, 0x58, 0x2e, // vaddpd zmm5{k3}{z},zmm6,[rsi]{1to8}
                0x62, 0xf1, 0xbd, 0x58, 0x5c, 0x3e, // vsubpd zmm7,zmm8,[rsi]{1to8}
                0xc3,
            ],
            0x27a0,
            0,
            "a".repeat(64),
            "masked-zmm-float".to_owned(),
            "masked_zmm_float".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions[..5]
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k1", "mxcsr", "zmm0", "zmm1", "zmm2"]
        );
        assert_eq!(
            instructions[1].effects.read_registers,
            ["k1", "mxcsr", "zmm1", "zmm2"]
        );
        assert_eq!(
            instructions[2].effects.read_registers,
            ["k2", "mxcsr", "rdi", "zmm3", "zmm4"]
        );
        assert_eq!(
            instructions[3].effects.read_registers,
            ["k3", "mxcsr", "rsi", "zmm6"]
        );
        assert_eq!(
            instructions[4].effects.read_registers,
            ["mxcsr", "rsi", "zmm8"]
        );
        assert!(instructions[2].decorators.broadcast);
        assert!(instructions[3].decorators.zeroing);
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        assert!(
            machine
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "explicit_simd_float_exception")
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("memcpy(hydir_fp_result_27a0"));
        assert!(c.contains("memset(hydir_fp_result_27a6"));
        assert!(c.contains("state->k[2] & UINT64_C(0xffff)"));
        assert!(c.contains("hydir_fp_broadcast_27ac"));
        assert!(c.contains("state->k[3] & UINT64_C(0xff)"));
        assert!(c.contains("if (((state->k[1] >> 0U)"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn avx512_embedded_rounding_is_preserved_and_not_falsely_exact() {
        let machine = decode_function(
            &[
                0x62, 0xf1, 0x74, 0x18, 0x58, 0xc2, // vaddps zmm0,zmm1,zmm2,{rn-sae}
                0xc3,
            ],
            0x27c0,
            0,
            "f".repeat(64),
            "rounded-zmm-float".to_owned(),
            "rounded_zmm_float".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let instruction = &machine.blocks[0].instructions[0];
        assert_eq!(instruction.decorators.rounding.as_deref(), Some("nearest"));
        assert!(!instruction.decorators.suppress_all_exceptions);
        assert!(matches!(
            instruction.operation,
            MachineOperation::OpaqueEffect { .. }
        ));
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_opaque_effect(state, UINT64_C(0x27c0)"));
    }

    #[test]
    fn avx512_masked_byte_popcount_suppresses_inactive_memory_reads() {
        let machine = decode_function(
            &[
                0x62, 0xf2, 0x7d, 0x49, 0x54, 0xc1, // vpopcntb zmm0{k1},zmm1
                0x62, 0xf2, 0x7d, 0xc9, 0x54, 0xc1, // vpopcntb zmm0{k1}{z},zmm1
                0x62, 0xf2, 0x7d, 0x4a, 0x54, 0x17, // vpopcntb zmm2{k2},[rdi]
                0x62, 0xf2, 0x7d, 0xca, 0x54, 0x17, // vpopcntb zmm2{k2}{z},[rdi]
                0xc3,
            ],
            0x27d0,
            0,
            "b".repeat(64),
            "masked-zmm-popcount".to_owned(),
            "masked_zmm_popcount".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k1", "zmm0", "zmm1"]
        );
        assert_eq!(instructions[1].effects.read_registers, ["k1", "zmm1"]);
        assert_eq!(
            instructions[2].effects.read_registers,
            ["k2", "rdi", "zmm2"]
        );
        assert_eq!(instructions[3].effects.read_registers, ["k2", "rdi"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_popcount_result_27d0"));
        assert!(c.contains("state->k[1] >> hydir_lane_27d0"));
        assert!(c.contains("hydir_popcount64(hydir_load8("));
        assert!(c.contains("+ hydir_lane_27dc"));
        assert!(!c.contains("hydir_popcount_source_27dc"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn avx512_masked_gf_affine_supports_qword_broadcast() {
        let machine = decode_function(
            &[
                0x62, 0xf3, 0xf5, 0x49, 0xce, 0xc2,
                0x63, // vgf2p8affineqb zmm0{k1},zmm1,zmm2,0x63
                0x62, 0xf3, 0xf5, 0xc9, 0xce, 0xc2, 0x63, // same with {z}
                0x62, 0xf3, 0xdd, 0x5a, 0xce, 0x1f, 0x00, // zmm3{k2},zmm4,[rdi]{1to8},0
                0x62, 0xf3, 0xdd, 0xda, 0xce, 0x1f, 0x00, // same with {z}
                0xc3,
            ],
            0x2800,
            0,
            "c".repeat(64),
            "masked-zmm-gf".to_owned(),
            "masked_zmm_gf".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k1", "zmm0", "zmm1", "zmm2"]
        );
        assert_eq!(
            instructions[1].effects.read_registers,
            ["k1", "zmm1", "zmm2"]
        );
        assert_eq!(
            instructions[2].effects.read_registers,
            ["k2", "rdi", "zmm3", "zmm4"]
        );
        assert_eq!(
            instructions[3].effects.read_registers,
            ["k2", "rdi", "zmm4"]
        );
        assert!(instructions[2].decorators.broadcast);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_affine_matrix_280e[8]"));
        assert!(c.contains("if (state->k[2] != UINT64_C(0))"));
        assert!(c.contains("hydir_affine_result_2800"));
        assert!(c.contains("hydir_affine_matrix_280e[7U - hydir_bit_280e]"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn avx512_qword_compare_writemask_zeroes_inactive_results() {
        let machine = decode_function(
            &[
                0x62, 0xf3, 0xe5, 0x4a, 0x1e, 0xcc, 0x04, // vpcmpnequq k1{k2},zmm3,zmm4
                0x62, 0xf3, 0xe5, 0x5a, 0x1e, 0x0f, 0x01, // vpcmpltuq k1{k2},zmm3,[rdi]{1to8}
                0x62, 0xf3, 0xe5, 0x58, 0x1e, 0x0f, 0x01, // vpcmpltuq k1,zmm3,[rdi]{1to8}
                0xc3,
            ],
            0x2840,
            0,
            "d".repeat(64),
            "masked-zmm-compare".to_owned(),
            "masked_zmm_compare".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k2", "zmm3", "zmm4"]
        );
        assert_eq!(
            instructions[1].effects.read_registers,
            ["k2", "rdi", "zmm3"]
        );
        assert_eq!(instructions[2].effects.read_registers, ["rdi", "zmm3"]);
        assert_eq!(instructions[0].effects.written_registers, ["k1"]);
        assert_eq!(instructions[0].decorators.op_mask.as_deref(), Some("k2"));
        assert!(instructions[1].decorators.broadcast);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_compare_mask_2840 = UINT64_C(0)"));
        assert!(c.contains("state->k[2] >> hydir_lane_2840"));
        assert!(c.contains("state->k[2] & UINT64_C(0xff)"));
        assert!(c.contains("hydir_compare_broadcast_2847"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn avx512_qword_compress_store_writes_only_selected_values() {
        let machine = decode_function(
            &[
                0x62, 0xf2, 0xfd, 0x49, 0x8b, 0x17, // vpcompressq [rdi]{k1},zmm2
                0x62, 0xf2, 0xfd, 0x4a, 0x8b, 0xe3, // vpcompressq zmm3{k2},zmm4
                0x62, 0xf2, 0xfd, 0xca, 0x8b, 0xe3, // vpcompressq zmm3{k2}{z},zmm4
                0xc3,
            ],
            0x2860,
            0,
            "e".repeat(64),
            "zmm-compress-store".to_owned(),
            "zmm_compress_store".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions[0].effects.read_registers,
            ["k1", "rdi", "zmm2"]
        );
        assert_eq!(
            instructions[0].effects.written_registers,
            Vec::<String>::new()
        );
        assert_eq!(instructions[0].effects.memory, MachineMemoryEffect::Write);
        assert_eq!(
            instructions[1].effects.read_registers,
            ["k2", "zmm3", "zmm4"]
        );
        assert_eq!(instructions[2].effects.read_registers, ["k2", "zmm4"]);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_output_lane_2860 * 8U"));
        assert!(c.contains("hydir_compress_source_2860 + hydir_lane_2860 * 8U"));
        assert!(c.contains("hydir_compress_result_2866"));
        assert!(!c.contains("/* opaque "));
    }

    #[test]
    fn relocatable_bmi2_flagless_shifts_are_width_generic_and_exact() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/bmi2_shifts.o");
        let native = decompile_symbol(bytes, "hydir_bmi2_shifts").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 7);
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        for family in ["shlx", "shrx", "sarx", "rorx", "pdep", "pext"] {
            let instruction = instructions
                .iter()
                .find(|instruction| instruction.mnemonic == family)
                .unwrap();
            assert!(instruction.effects.read_flags.is_empty());
            assert!(instruction.effects.written_flags.is_empty());
            assert!(instruction.effects.undefined_flags.is_empty());
        }
        assert_eq!(
            native.machine_ir.semantic_fidelity,
            SemanticFidelity::ExactUnderModel
        );
        assert!(native.low_level_c.contains("hydir_count_0"));
        assert!(native.low_level_c.contains("hydir_count_f"));
        assert!(native.low_level_c.contains("64U - hydir_count_"));
        assert!(native.low_level_c.contains("hydir_lowest_15"));
        assert!(native.low_level_c.contains("hydir_lowest_1a"));
        assert!(!native.low_level_c.contains("/* opaque "));
        assert!(native.structured_c.is_some());
    }

    #[test]
    fn relocatable_atomic_fixture_decompiles_with_exact_locked_operations() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/atomics.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 4);
        assert_eq!(coverage.lifted_functions, 4);
        assert_eq!(coverage.exact_instructions, 24);
        assert_eq!(coverage.opaque_instructions, 0);

        let native = decompile_symbol(bytes, "hydir_atomic_fetch_add").unwrap();
        let atomic = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "xadd")
            .unwrap();
        assert!(matches!(
            atomic.operation,
            MachineOperation::Exact { ref family } if family == "lock_xadd"
        ));
        assert_eq!(atomic.effects.memory, MachineMemoryEffect::ReadWrite);
        assert_eq!(atomic.effects.written_registers, ["rax"]);
        let atomic_state = native
            .state_ir
            .blocks
            .iter()
            .flat_map(|block| &block.operations)
            .find(|operation| {
                matches!(operation, StateOperation::Exact { family, .. } if family == "lock_xadd")
            })
            .unwrap();
        let StateOperation::Exact {
            input_components,
            output_components,
            ..
        } = atomic_state
        else {
            unreachable!("locked XADD is exact")
        };
        assert!(
            input_components
                .iter()
                .any(|component| component.component == "memory:volatile")
        );
        assert!(
            output_components
                .iter()
                .any(|component| component.component == "memory:volatile")
        );
        assert!(
            !native
                .machine_ir
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "bounded_opaque_atomic")
        );
        assert!(native.low_level_c.contains("hydir_atomic_rmw(state"));
        assert!(!native.low_level_c.contains("/* opaque "));

        let compare = decompile_symbol(bytes, "hydir_atomic_compare_exchange").unwrap();
        let compare_families = compare
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| match &instruction.operation {
                MachineOperation::Exact { family } => Some(family.as_str()),
                MachineOperation::OpaqueEffect { .. } => None,
            })
            .collect::<BTreeSet<_>>();
        assert!(compare_families.contains("lock_cmpxchg8b"));
        assert!(compare_families.contains("lock_cmpxchg16b"));
        assert!(
            compare
                .low_level_c
                .contains("hydir_atomic_cmpxchg_wide(state")
        );

        let rmw = decompile_symbol(bytes, "hydir_atomic_fence").unwrap();
        for family in [
            "lock_inc", "lock_dec", "lock_neg", "lock_not", "lock_adc", "lock_sbb", "lock_bts",
            "lock_btr", "lock_btc",
        ] {
            assert!(rmw.low_level_c.contains(&format!("\"{}\"", &family[5..])));
        }
        assert!(!rmw.low_level_c.contains("/* opaque "));

        let fences = decompile_symbol(bytes, "hydir_explicit_fences").unwrap();
        let fence_instructions = fences
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| instruction.effects.memory == MachineMemoryEffect::Fence)
            .collect::<Vec<_>>();
        assert_eq!(fence_instructions.len(), 3);
        assert_eq!(
            fence_instructions
                .iter()
                .map(|instruction| instruction.mnemonic.as_str())
                .collect::<Vec<_>>(),
            ["lfence", "sfence", "mfence"]
        );
        let first_fence_components = match &fences.state_ir.blocks[0].operations[0] {
            StateOperation::Exact {
                input_components,
                output_components,
                ..
            } => (input_components, output_components),
            StateOperation::Unknown { .. } => panic!("fence should be exact"),
        };
        for region in [
            "memory:stack",
            "memory:image",
            "memory:tls",
            "memory:heap",
            "memory:volatile",
            "memory:unknown",
        ] {
            assert!(
                first_fence_components
                    .0
                    .iter()
                    .any(|component| component.component == region)
            );
            assert!(
                first_fence_components
                    .1
                    .iter()
                    .any(|component| component.component == region)
            );
        }
        assert!(
            fences
                .low_level_c
                .contains("hydir_memory_fence(state, \"lfence\")")
        );
    }

    #[test]
    fn relocatable_string_fixture_decompiles_without_opaque_instructions() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/string_ops.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 4);
        assert_eq!(coverage.lifted_functions, 4);
        assert_eq!(coverage.exact_instructions, 20);
        assert_eq!(coverage.opaque_instructions, 0);

        let native = decompile_symbol(bytes, "hydir_copy_bytes").unwrap();
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(
            native.machine_ir.semantic_fidelity,
            SemanticFidelity::Conservative
        );
        assert!(native.low_level_c.contains("while (state->rcx"));
        assert!(
            native
                .structured_c
                .as_deref()
                .is_some_and(|c| c.contains("hydir_load8(state->rsi)"))
        );
    }

    #[test]
    fn compiler_hints_and_avx_state_clears_are_exact() {
        let machine = decode_function(
            &[
                0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                0xf3, 0x90, // pause
                0xc5, 0xf8, 0x77, // vzeroupper
                0xc5, 0xfc, 0x77, // vzeroall
                0xc3, // ret
            ],
            0x26e0,
            0,
            "f".repeat(64),
            "compiler-hints".to_owned(),
            "compiler_hints".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert_eq!(
            machine
                .blocks
                .iter()
                .map(|block| block.instructions[0].mnemonic.as_str())
                .collect::<Vec<_>>(),
            ["endbr64", "pause", "vzeroupper", "vzeroall", "ret"]
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("memset(state->ymm[hydir_vec_i] + 16U, 0, 16U)"));
        assert!(c.contains("memset(state->ymm, 0, 16U * 32U)"));
    }

    #[test]
    fn string_transfers_model_rep_direction_and_bounded_fault_uncertainty() {
        let machine = decode_function(
            &[
                0xfc, // cld
                0xf3, 0xa4, // rep movsb
                0xf3, 0x48, 0xab, // rep stosq
                0xfd, // std
                0xa5, // movsd
                0xf3, 0xa6, // repe cmpsb
                0xf2, 0x48, 0xaf, // repne scasq
                0xc3, // ret
            ],
            0x2720,
            0,
            "a".repeat(64),
            "string-transfers".to_owned(),
            "string_transfers".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            instructions
                .iter()
                .filter_map(|instruction| match &instruction.operation {
                    MachineOperation::Exact { family } => Some(family.as_str()),
                    MachineOperation::OpaqueEffect { .. } => None,
                })
                .collect::<Vec<_>>(),
            [
                "cld",
                "rep_movsb",
                "rep_stosq",
                "std",
                "movsd",
                "repe_cmpsb",
                "repne_scasq",
                "ret"
            ]
        );
        let repeated_move = instructions
            .iter()
            .find(|instruction| {
                matches!(&instruction.operation, MachineOperation::Exact { family } if family == "rep_movsb")
            })
            .unwrap();
        assert!(
            repeated_move
                .effects
                .read_registers
                .contains(&"rcx".to_owned())
        );
        assert!(repeated_move.effects.read_flags.contains(&"df".to_owned()));
        assert_eq!(repeated_move.effects.memory, MachineMemoryEffect::ReadWrite);
        assert_eq!(
            machine
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "summarized_string_fault_progress")
                .count(),
            5
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("state->df = 0U"));
        assert!(c.contains("while (state->rcx != UINT64_C(0))"));
        assert!(c.contains("hydir_load8(state->rsi)"));
        assert!(c.contains("hydir_store64(state->rdi, (uint64_t)state->rax)"));
        assert!(c.contains("if (state->df != 0U)"));
        assert!(c.contains("if (!state->zf) break"));
        assert!(c.contains("if (state->zf) break"));
        assert!(c.contains("state->af = (uint8_t)"));
    }

    #[test]
    fn scalar_vector_transfers_are_exact_and_preserve_encoding_alias_rules() {
        let machine = decode_function(
            &[
                0x66, 0x0f, 0x6e, 0xc7, // movd xmm0,edi
                0x66, 0x0f, 0x7e, 0xc0, // movd eax,xmm0
                0x66, 0x48, 0x0f, 0x6e, 0xce, // movq xmm1,rsi
                0x66, 0x48, 0x0f, 0x7e, 0xc8, // movq rax,xmm1
                0xc5, 0xf9, 0x6e, 0xd1, // vmovd xmm2,ecx
                0xc4, 0xe1, 0xf9, 0x6e, 0xda, // vmovq xmm3,rdx
                0xc3, // ret
            ],
            0x26f0,
            0,
            "0".repeat(64),
            "scalar-vector".to_owned(),
            "scalar_vector".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("uint32_t hydir_vec_scalar_26f0"));
        assert!(c.contains("uint64_t hydir_vec_scalar_26f8"));
        assert!(c.contains("memset(state->ymm[2] + 16U, 0, 16U)"));
        assert!(c.contains("memset(state->ymm[3] + 16U, 0, 16U)"));
    }

    #[test]
    fn scalar_float_moves_are_exact_bit_transfers_without_fp_claims() {
        let machine = decode_function(
            &[
                0xf3, 0x0f, 0x10, 0xc1, // movss xmm0,xmm1
                0xf3, 0x0f, 0x10, 0x17, // movss xmm2,[rdi]
                0xf3, 0x0f, 0x11, 0x16, // movss [rsi],xmm2
                0xf2, 0x0f, 0x10, 0xdc, // movsd xmm3,xmm4
                0xf2, 0x0f, 0x10, 0x2f, // movsd xmm5,[rdi]
                0xf2, 0x0f, 0x11, 0x2e, // movsd [rsi],xmm5
                0xc5, 0xf2, 0x10, 0xc2, // vmovss xmm0,xmm1,xmm2
                0xc5, 0xdb, 0x10, 0xdd, // vmovsd xmm3,xmm4,xmm5
                0xc5, 0xfa, 0x11, 0x06, // vmovss [rsi],xmm0
                0xc5, 0xfb, 0x11, 0x1f, // vmovsd [rdi],xmm3
                0xc3,
            ],
            0x2c00,
            0,
            "a".repeat(64),
            "scalar-float-moves".to_owned(),
            "scalar_float_moves".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let instructions = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 11);
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        let families = instructions
            .iter()
            .filter_map(|instruction| match &instruction.operation {
                MachineOperation::Exact { family } => Some(family.as_str()),
                MachineOperation::OpaqueEffect { .. } => None,
            })
            .collect::<Vec<_>>();
        assert!(families.contains(&"movss"));
        assert!(families.contains(&"movsd"));
        assert!(families.contains(&"vmovss"));
        assert!(families.contains(&"vmovsd"));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_vec_merge_"));
        assert!(c.contains("hydir_vec_scalar_"));
        assert!(c.contains("memset(state->ymm[2] + 4U, 0, 12U)"));
        assert!(c.contains("memset(state->ymm[5] + 8U, 0, 8U)"));
        assert!(c.contains("memset(state->ymm[0] + 16U, 0, 16U)"));
        assert!(!c.contains("/* opaque "));

        let string_move = decode_function(
            &[0xa5, 0xc3], // movsd; ret
            0x2d00,
            0,
            "b".repeat(64),
            "string-movsd".to_owned(),
            "string_movsd".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&string_move).unwrap();
        let function = lower_function_ir(&string_move, &state).unwrap();
        let cir = lower_cir(&string_move, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_load32(state->rsi)"));
        assert!(c.contains("hydir_store32(state->rdi"));
    }

    #[test]
    fn scalar_sse_arithmetic_has_exact_mxcsr_aware_normal_paths() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/scalar_float_arithmetic.o");
        let native = decompile_symbol(bytes, "hydir_scalar_float_arithmetic").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 25);
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| instruction.mnemonic != "ret")
                .filter(|instruction| instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none()))
                .count(),
            24
        );
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_simd_float_exception")
                .count(),
            24
        );
        assert_eq!(
            native.machine_ir.semantic_fidelity,
            SemanticFidelity::Conservative
        );
        assert!(native.low_level_c.contains("hydir_fp_binary32(state"));
        assert!(native.low_level_c.contains("hydir_fp_binary64(state"));
        assert!(native.low_level_c.contains("hydir_fp_unary32(state"));
        assert!(native.low_level_c.contains("hydir_fp_unary64(state"));
        assert!(native.low_level_c.contains("hydir_fp_convert32_to64(state"));
        assert!(native.low_level_c.contains("hydir_fp_convert64_to32(state"));
        assert!(native.low_level_c.contains("hydir_i64_to_fp32(state"));
        assert!(native.low_level_c.contains("hydir_i64_to_fp64(state"));
        assert!(native.low_level_c.contains("hydir_fp32_to_i64(state"));
        assert!(native.low_level_c.contains("hydir_fp64_to_i64(state"));
        assert!(native.low_level_c.contains("\"add\""));
        assert!(native.low_level_c.contains("\"sub\""));
        assert!(native.low_level_c.contains("\"mul\""));
        assert!(native.low_level_c.contains("\"div\""));
        assert!(
            native
                .low_level_c
                .contains("memset(state->ymm[9] + 16U, 0, 16U)")
        );
        assert!(!native.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn scalar_sse_comparisons_define_integer_flags_and_mxcsr() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/scalar_float_arithmetic.o");
        let native = decompile_symbol(bytes, "hydir_scalar_float_compare").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 9);
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        let comparisons = instructions
            .iter()
            .filter(|instruction| instruction.mnemonic.contains("comis"))
            .collect::<Vec<_>>();
        assert_eq!(comparisons.len(), 4);
        assert!(comparisons.iter().all(|instruction| {
            instruction.effects.written_flags.len() == ALL_FLAGS.len()
                && instruction
                    .effects
                    .read_registers
                    .contains(&"mxcsr".to_owned())
                && instruction
                    .effects
                    .written_registers
                    .contains(&"mxcsr".to_owned())
                && instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none())
        }));
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_simd_float_exception")
                .count(),
            4
        );
        assert!(native.low_level_c.contains("hydir_fp_compare32(state"));
        assert!(native.low_level_c.contains("hydir_fp_compare64(state"));
        assert!(native.low_level_c.contains("state->rax"));
        assert!(native.low_level_c.contains("state->rcx"));
        assert!(!native.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn common_x87_fixture_has_exact_stack_state_normal_paths() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/x87_common.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 5);
        assert_eq!(coverage.lifted_functions, 5);
        assert_eq!(coverage.exact_instructions, 38);
        assert_eq!(coverage.opaque_instructions, 0);

        let native = decompile_symbol(bytes, "hydir_x87_compare_transcendental").unwrap();
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(
            native.machine_ir.semantic_fidelity,
            SemanticFidelity::Conservative
        );
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        let comparison = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "fucomip")
            .unwrap();
        assert_eq!(comparison.effects.written_flags.len(), ALL_FLAGS.len());
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_x87_exception")
                .count(),
            9
        );
        assert!(native.low_level_c.contains("hydir_x87_operation(state"));
        assert!(native.low_level_c.contains("\"fucomip\""));
        assert!(native.low_level_c.contains("\"fyl2x\""));
        assert!(!native.low_level_c.contains("/* opaque "));

        let environment = decompile_symbol(bytes, "hydir_x87_environment").unwrap();
        let status_store = environment
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| {
                instruction.mnemonic == "fnstsw"
                    && instruction
                        .effects
                        .written_registers
                        .contains(&"rax".to_owned())
            })
            .expect("FNSTSW AX should define the accumulator");
        assert!(
            status_store
                .edges
                .iter()
                .all(|edge| edge.kind != MachineEdgeKind::Exception)
        );
        assert!(environment.low_level_c.contains("\"fldcw\""));
        assert!(environment.low_level_c.contains("\"fnstsw\""));
        assert!(!environment.low_level_c.contains("/* opaque "));

        let images = decompile_symbol(bytes, "hydir_x87_environment_images").unwrap();
        assert_eq!(
            images
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_x87_exception")
                .count(),
            4
        );
        let image_instructions = images
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            image_instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            image_instructions
                .iter()
                .filter(|instruction| instruction.mnemonic == "wait")
                .count(),
            2
        );
        let load_environment = image_instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "fldenv")
            .unwrap();
        assert!(
            load_environment
                .effects
                .written_registers
                .contains(&"x87_instruction_pointer".to_owned())
        );
        assert!(
            load_environment
                .effects
                .written_registers
                .contains(&"x87_data_pointer".to_owned())
        );
        assert!(
            load_environment
                .effects
                .written_registers
                .contains(&"x87_opcode".to_owned())
        );
        for family in ["fldenv", "fnstenv", "frstor", "fnsave", "wait"] {
            assert!(images.low_level_c.contains(&format!("\"{family}\"")));
        }
        assert!(images.low_level_c.contains("x87_instruction_pointer"));
        assert!(!images.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn legacy_extended_state_images_have_bounded_exact_normal_paths() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/extended_state.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 1);
        assert_eq!(coverage.lifted_functions, 1);
        assert_eq!(coverage.exact_instructions, 5);
        assert_eq!(coverage.opaque_instructions, 0);

        let native = decompile_symbol(bytes, "hydir_fx_state").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_extended_state_exception")
                .count(),
            4
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none()))
                .count(),
            4
        );
        let save = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "fxsave64")
            .unwrap();
        assert_eq!(save.effects.memory, MachineMemoryEffect::Write);
        assert!(save.effects.read_registers.contains(&"st0".to_owned()));
        assert!(save.effects.read_registers.contains(&"ymm15".to_owned()));
        assert!(
            save.effects
                .read_registers
                .contains(&"mxcsr_mask".to_owned())
        );
        let restore = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "fxrstor64")
            .unwrap();
        assert_eq!(restore.effects.memory, MachineMemoryEffect::Read);
        assert!(
            restore
                .effects
                .written_registers
                .contains(&"x87_instruction_pointer".to_owned())
        );
        assert!(
            restore
                .effects
                .written_registers
                .contains(&"ymm15".to_owned())
        );
        assert!(
            native
                .low_level_c
                .contains("hydir_extended_state_operation(state")
        );
        assert!(native.low_level_c.contains("uint32_t mxcsr, mxcsr_mask"));
        assert!(!native.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn dynamic_xsave_images_are_bounded_directional_opaque_effects() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/xsave_state.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 1);
        assert_eq!(coverage.lifted_functions, 1);
        assert_eq!(coverage.exact_instructions, 1);
        assert_eq!(coverage.opaque_instructions, 6);

        let native = decompile_symbol(bytes, "hydir_xsave_state").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| { diagnostic.code == "bounded_opaque_extended_state_image" })
                .count(),
            6
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none()))
                .count(),
            6
        );
        let save = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "xsave64")
            .unwrap();
        assert_eq!(save.effects.memory, MachineMemoryEffect::Write);
        assert!(save.effects.read_registers.contains(&"rax".to_owned()));
        assert!(save.effects.read_registers.contains(&"xcr0".to_owned()));
        assert!(save.effects.read_registers.contains(&"zmm31".to_owned()));
        assert!(
            save.effects
                .read_registers
                .contains(&"extended_state_unknown".to_owned())
        );
        assert!(!save.effects.read_registers.contains(&"rbx".to_owned()));
        let restore = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "xrstors64")
            .unwrap();
        assert_eq!(restore.effects.memory, MachineMemoryEffect::Read);
        assert!(
            restore
                .effects
                .read_registers
                .contains(&"ia32_xss".to_owned())
        );
        assert!(
            restore
                .effects
                .written_registers
                .contains(&"extended_state_unknown".to_owned())
        );
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(native.low_level_c.matches("/* opaque ").count(), 6);
        assert!(!native.function_ir.rewrite_ready);
    }

    #[test]
    fn environment_dependent_system_instructions_have_bounded_helpers() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/system_state.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 1);
        assert_eq!(coverage.lifted_functions, 1);
        assert_eq!(coverage.exact_instructions, 7);
        assert_eq!(coverage.opaque_instructions, 0);

        let native = decompile_symbol(bytes, "hydir_system_state").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_environment_input")
                .count(),
            6
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none()))
                .count(),
            5
        );
        let cpuid = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "cpuid")
            .unwrap();
        assert_eq!(cpuid.effects.read_registers, ["rax", "rcx"]);
        assert_eq!(
            cpuid.effects.written_registers,
            ["rax", "rbx", "rcx", "rdx"]
        );
        let random = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "rdrand")
            .unwrap();
        assert_eq!(random.effects.written_registers, ["rax"]);
        assert_eq!(random.effects.written_flags.len(), ALL_FLAGS.len());
        for family in ["cpuid", "rdtsc", "rdtscp", "xgetbv", "rdrand", "rdseed"] {
            assert!(native.low_level_c.contains(&format!("\"{family}\"")));
        }
        assert!(
            native
                .low_level_c
                .contains("hydir_environment_operation(state")
        );
        assert!(!native.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn aligned_vector_memory_moves_keep_normal_path_and_fault_edges() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/aligned_vectors.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 1);
        assert_eq!(coverage.lifted_functions, 1);
        assert_eq!(coverage.exact_instructions, 5);
        assert_eq!(coverage.opaque_instructions, 0);

        let native = decompile_symbol(bytes, "hydir_aligned_vectors").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_vector_alignment_exception")
                .count(),
            4
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none()))
                .count(),
            4
        );
        let load = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "movaps")
            .unwrap();
        assert_eq!(load.effects.memory, MachineMemoryEffect::Read);
        let store = instructions
            .iter()
            .find(|instruction| instruction.mnemonic == "vmovdqa")
            .unwrap();
        assert_eq!(store.effects.memory, MachineMemoryEffect::Write);
        assert!(
            native
                .low_level_c
                .contains("hydir_aligned_vector_move(state")
        );
        assert!(native.low_level_c.contains("\"movaps\""));
        assert!(native.low_level_c.contains("\"vmovdqa\""));
        assert!(!native.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn packed_sse_avx_arithmetic_has_exact_lane_and_mxcsr_normal_paths() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/packed_float_arithmetic.o");
        let native = decompile_symbol(bytes, "hydir_packed_float_arithmetic").unwrap();
        let instructions = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        assert_eq!(instructions.len(), 27);
        assert!(
            instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        );
        assert_eq!(
            instructions
                .iter()
                .filter(|instruction| instruction.mnemonic != "ret")
                .filter(|instruction| instruction
                    .edges
                    .iter()
                    .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none()))
                .count(),
            26
        );
        assert_eq!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.code == "explicit_simd_float_exception")
                .count(),
            26
        );
        assert!(
            native
                .low_level_c
                .contains("hydir_fp_lane_result_0_0 = hydir_fp_binary32")
        );
        assert!(native.low_level_c.contains("= hydir_fp_binary64(state"));
        assert!(native.low_level_c.contains("= hydir_fp_unary32(state"));
        assert!(native.low_level_c.contains("= hydir_fp_unary64(state"));
        assert!(
            native
                .low_level_c
                .contains("hydir_packed_convert_result_lane_")
        );
        assert!(native.low_level_c.contains("hydir_i64_to_fp32(state"));
        assert!(native.low_level_c.contains("hydir_fp32_to_i64(state"));
        assert!(native.low_level_c.contains("hydir_precision_result_"));
        assert!(native.low_level_c.contains("hydir_fp_convert32_to64(state"));
        assert!(native.low_level_c.contains("hydir_fp_convert64_to32(state"));
        assert!(
            native
                .low_level_c
                .contains("memset(state->ymm[9] + 16U, 0, 16U)")
        );
        assert!(!native.low_level_c.contains("/* opaque "));

        let int_to_float = decompile_symbol(bytes, "hydir_packed_i32_to_float").unwrap();
        assert_eq!(int_to_float.function_ir.parameters[0].type_name, "i32x4");
        assert!(
            int_to_float
                .function_ir
                .returns
                .iter()
                .any(|value| value.location == "xmm0" && value.type_name == "float32x4")
        );
        let float_to_int = decompile_symbol(bytes, "hydir_packed_float_to_i32").unwrap();
        assert_eq!(
            float_to_int.function_ir.parameters[0].type_name,
            "float32x8"
        );
        assert!(
            float_to_int
                .function_ir
                .returns
                .iter()
                .any(|value| value.location == "ymm0" && value.type_name == "i32x8")
        );
    }

    #[test]
    fn stack_objects_are_normalized_to_entry_rsp_across_prologues() {
        let rsp_machine = decode_function(
            &[
                0x48, 0x83, 0xec, 0x20, // sub rsp,32
                0x48, 0x89, 0x7c, 0x24, 0x08, // mov [rsp+8],rdi
                0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax,[rsp+8]
                0x48, 0x83, 0xc4, 0x20, // add rsp,32
                0xc3, // ret
            ],
            0x2700,
            0,
            "3".repeat(64),
            "rsp-frame".to_owned(),
            "rsp_frame".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&rsp_machine).unwrap();
        assert!(state.blocks.iter().any(|block| block.operations.iter().any(
            |operation| matches!(
                operation,
                StateOperation::Exact {
                    output_components,
                    ..
                } if output_components
                    .iter()
                    .any(|output| output.component == "memory:stack")
            )
        )));
        let function = lower_function_ir(&rsp_machine, &state).unwrap();
        let slot = function
            .stack_objects
            .iter()
            .find(|slot| slot.displacement == -24)
            .expect("rsp-relative spill should normalize to entry RSP - 24");
        assert_eq!(slot.base_register, "entry_rsp");
        assert_eq!(slot.access, RecoveredAccessKind::ReadWrite);
        assert_eq!(slot.sites.len(), 2);
        assert!(slot.evidence.contains("normalized"));

        let rbp_machine = decode_function(
            &[
                0x55, // push rbp
                0x48, 0x89, 0xe5, // mov rbp,rsp
                0x48, 0x83, 0xec, 0x10, // sub rsp,16
                0x48, 0x89, 0x7d, 0xf8, // mov [rbp-8],rdi
                0xc9, // leave
                0xc3, // ret
            ],
            0x2800,
            0,
            "4".repeat(64),
            "rbp-frame".to_owned(),
            "rbp_frame".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&rbp_machine).unwrap();
        let function = lower_function_ir(&rbp_machine, &state).unwrap();
        let slot = function
            .stack_objects
            .iter()
            .find(|slot| slot.displacement == -16)
            .expect("rbp-relative spill should normalize through the saved-frame prologue");
        assert_eq!(slot.base_register, "entry_rsp");
        assert!(slot.evidence.contains("normalized"));
    }

    #[test]
    fn external_terminal_branch_is_recorded_as_a_tail_call() {
        let machine = decode_function(
            &[0xe9, 0xfb, 0x0f, 0x00, 0x00], // jmp 0x3900 from 0x2900
            0x2900,
            0,
            "5".repeat(64),
            "tail-call".to_owned(),
            "tail_call".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        assert_eq!(function.calls.len(), 1);
        assert!(function.calls[0].tail_call);
        assert!(!function.calls[0].indirect);
        assert_eq!(function.calls[0].target, Some(location(0, 0x3900)));
    }

    #[test]
    fn audited_external_knowledge_handles_versions_posix_and_noreturn_symbols() {
        assert_eq!(
            known_external_prototype(Some("memcpy@@GLIBC_2.14")),
            Some("void *memcpy(void *destination, const void *source, size_t size)")
        );
        assert!(
            known_external_prototype(Some("mmap@GLIBC_2.2.5"))
                .is_some_and(|prototype| prototype.starts_with("void *mmap("))
        );
        assert!(
            known_external_prototype(Some("pthread_create"))
                .is_some_and(|prototype| prototype.contains("(*start)(void *)"))
        );
        assert!(known_external_noreturn(Some("__assert_fail@GLIBC_2.2.5")));
        assert!(known_external_noreturn(Some("quick_exit")));
        assert!(!known_external_noreturn(Some("read")));

        let printf = known_external_call_abi(Some("printf@@GLIBC_2.2.5")).unwrap();
        assert!(printf.variadic);
        assert_eq!(printf.arguments.len(), 1);
        assert_eq!(printf.arguments[0].location, "rdi");
        assert_eq!(printf.returns[0].location, "rax");
        assert_eq!(printf.returns[0].type_name, "int");

        let pthread = known_external_call_abi(Some("pthread_create")).unwrap();
        assert!(!pthread.variadic);
        assert_eq!(pthread.arguments.len(), 4);
        assert_eq!(pthread.arguments[3].location, "rcx");
        assert!(pthread.arguments[2].type_name.contains("(*start)(void *)"));

        let abort = known_external_call_abi(Some("abort")).unwrap();
        assert!(abort.arguments.is_empty());
        assert!(abort.returns.is_empty());
    }

    #[test]
    fn language_symbol_evidence_is_conservative_and_family_specific() {
        let entry = location(0, 0x4000);
        for (name, expected) in [
            ("_RNvCs4fqI2P2rA04_4demo3run", "rust_symbol"),
            ("_ZN4demo3run17h0123456789abcdefE", "rust_symbol"),
            ("_ZN4demo3runEv", "itanium_cxx_symbol"),
            ("runtime.main", "go_symbol"),
            ("example.org/pkg.worker", "go_symbol"),
        ] {
            let evidence = language_symbol_evidence(name, entry).unwrap();
            assert_eq!(evidence.kind, expected);
            assert_eq!(evidence.site, Some(entry));
        }
        for name in ["plain_c_function", "ZNnot_mangled", ".bad"] {
            assert!(language_symbol_evidence(name, entry).is_none());
        }
    }

    #[test]
    fn optimized_cpp_fixture_lifts_lea_virtual_dispatch_and_ud2_conservatively() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/cpp_rtti.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 5);
        assert_eq!(coverage.lifted_functions, 5);
        assert_eq!(coverage.exact_functions, 3);
        assert_eq!(coverage.conservative_functions, 2);
        assert_eq!(coverage.partial_functions, 1);
        assert_eq!(coverage.exact_instructions, 9);
        assert_eq!(coverage.opaque_instructions, 0);
        assert!(coverage.diagnostics.is_empty());

        let index = discover_functions(bytes).unwrap();
        assert_eq!(
            index
                .functions
                .iter()
                .filter(|function| function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "itanium_cxx_symbol"))
                .count(),
            3
        );

        let local = decompile_symbol(bytes, "hydir_cpp_local").unwrap();
        assert_eq!(
            local.machine_ir.semantic_fidelity,
            SemanticFidelity::ExactUnderModel
        );
        let lea = local
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.mnemonic == "lea")
            .expect("optimized arithmetic should retain LEA");
        assert_eq!(lea.effects.read_registers, ["rdi"]);
        assert!(!local.low_level_c.contains("/* opaque "));

        let dispatch = decompile_symbol(bytes, "hydir_cpp_dispatch").unwrap();
        assert_eq!(
            dispatch.machine_ir.structural_completeness,
            StructuralCompleteness::Partial
        );
        assert_eq!(
            dispatch
                .machine_ir
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .filter(|instruction| matches!(
                    instruction.operation,
                    MachineOperation::OpaqueEffect { .. }
                ))
                .count(),
            0
        );
        assert!(
            dispatch
                .machine_ir
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| {
                    instruction.effects.control == MachineControlEffect::IndirectBranch
                        && matches!(instruction.operation, MachineOperation::Exact { .. })
                })
        );

        let deleting_destructor = decompile_symbol(bytes, "_ZN9HydirBaseD0Ev").unwrap();
        let ud2 = &deleting_destructor.machine_ir.blocks[0].instructions[0];
        assert!(matches!(
            ud2.operation,
            MachineOperation::Exact { ref family } if family == "ud2"
        ));
        assert!(
            ud2.edges
                .iter()
                .any(|edge| edge.kind == MachineEdgeKind::Exception && edge.target.is_none())
        );
        assert!(
            deleting_destructor
                .machine_ir
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "explicit_invalid_opcode_exception")
        );
        assert!(
            deleting_destructor
                .low_level_c
                .contains("hydir_invalid_opcode(state")
        );
        assert!(!deleting_destructor.low_level_c.contains("/* opaque "));
    }

    #[test]
    fn read_only_entry_stack_slot_is_an_evidenced_stack_parameter() {
        let machine = decode_function(
            &[
                0x48, 0x8b, 0x44, 0x24, 0x08, // mov rax,[rsp+8]
                0xc3, // ret
            ],
            0x2a00,
            0,
            "6".repeat(64),
            "stack-parameter".to_owned(),
            "stack_parameter".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let parameter = function
            .parameters
            .iter()
            .find(|parameter| parameter.location == "entry_rsp+8")
            .expect("read-only entry stack slot should be retained as a stack parameter");
        assert_eq!(parameter.type_name, "u64_machine_value");
        assert!(!parameter.evidence.is_empty());
    }

    #[test]
    fn abi_inference_distinguishes_partial_write_preservation_from_input_use() {
        let machine = decode_function(
            &[
                0xb0, 0x01, // mov al,1 -- preserves the high bytes but consumes no argument
                0xc3, // ret
            ],
            0x2a40,
            0,
            "c".repeat(64),
            "partial-write-abi".to_owned(),
            "partial_write_abi".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        assert!(function.parameters.is_empty());
        assert_eq!(function.returns.len(), 1);
        assert_eq!(function.returns[0].location, "rax");
    }

    #[test]
    fn abi_inference_marks_direct_memory_base_arguments_as_pointers() {
        let machine = decode_function(
            &[
                0x8b, 0x07, // mov eax,[rdi]
                0xc3, // ret
            ],
            0x2a50,
            0,
            "a".repeat(64),
            "pointer-abi".to_owned(),
            "pointer_abi".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&machine).unwrap();
        let memory_inputs = match &state.blocks[0].operations[0] {
            StateOperation::Exact {
                input_components, ..
            } => input_components
                .iter()
                .map(|component| component.component.as_str())
                .collect::<BTreeSet<_>>(),
            StateOperation::Unknown { .. } => panic!("pointer load should be exact"),
        };
        assert!(memory_inputs.contains("memory:heap"));
        assert!(memory_inputs.contains("memory:unknown"));
        let function = lower_function_ir(&machine, &state).unwrap();
        assert_eq!(function.parameters.len(), 1);
        assert_eq!(function.parameters[0].location, "rdi");
        assert_eq!(function.parameters[0].type_name, "void *");
        assert_eq!(function.pointer_provenance.len(), 1);
        assert_eq!(
            function.pointer_provenance[0].origin,
            PointerOriginKind::Parameter
        );
        assert_eq!(
            function.pointer_provenance[0].target_regions,
            ["heap", "unknown"]
        );
        assert!(
            function.parameters[0]
                .evidence
                .iter()
                .any(|evidence| evidence.contains("memory base"))
        );
    }

    #[test]
    fn function_ir_records_stack_image_and_allocator_pointer_origins() {
        let machine = decode_function(
            &[
                0x48, 0x8d, 0x44, 0x24, 0x08, // lea rax,[rsp+8]
                0x48, 0x8d, 0x0d, 0x00, 0x00, 0x00, 0x00, // lea rcx,[rip]
                0xc3, // ret
            ],
            0x2a80,
            0,
            "e".repeat(64),
            "pointer-provenance".to_owned(),
            "pointer_provenance".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let calls = vec![FunctionCall {
            site: location(0, 0x2a90),
            target: None,
            symbol: Some("malloc@GLIBC_2.2.5".to_owned()),
            indirect: false,
            tail_call: false,
            noreturn: false,
            prototype: Some("void *malloc(size_t size)".to_owned()),
            arguments: Vec::new(),
            returns: Vec::new(),
            variadic: false,
            evidence: "test audited external call".to_owned(),
        }];
        let pointers = recover_pointer_provenance(&machine, &[], &calls);
        assert!(
            pointers
                .iter()
                .any(|pointer| pointer.origin == PointerOriginKind::StackAddress)
        );
        assert!(
            pointers
                .iter()
                .any(|pointer| pointer.origin == PointerOriginKind::ImageAddress)
        );
        let allocation = pointers
            .iter()
            .find(|pointer| pointer.origin == PointerOriginKind::AllocatorReturn)
            .unwrap();
        assert_eq!(allocation.value_location, "rax");
        assert_eq!(allocation.target_regions, ["heap"]);
    }

    #[test]
    fn abi_inference_recovers_vector_arguments_and_multi_register_returns() {
        let vector_machine = decode_function(
            &[
                0xf3, 0x0f, 0x6f, 0xc1, // movdqu xmm0,xmm1
                0xc3, // ret
            ],
            0x2a60,
            0,
            "d".repeat(64),
            "vector-abi".to_owned(),
            "vector_abi".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&vector_machine).unwrap();
        let function = lower_function_ir(&vector_machine, &state).unwrap();
        assert_eq!(function.parameters.len(), 1);
        assert_eq!(function.parameters[0].location, "xmm1");
        assert_eq!(function.parameters[0].type_name, "u128_vector");
        assert!(
            function
                .returns
                .iter()
                .any(|value| value.location == "xmm0" && value.type_name == "u128_vector")
        );

        let pair_machine = decode_function(
            &[
                0x48, 0x89, 0xf8, // mov rax,rdi
                0x48, 0x89, 0xf2, // mov rdx,rsi
                0xc3, // ret
            ],
            0x2a80,
            0,
            "e".repeat(64),
            "pair-return".to_owned(),
            "pair_return".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&pair_machine).unwrap();
        let function = lower_function_ir(&pair_machine, &state).unwrap();
        assert_eq!(
            function
                .parameters
                .iter()
                .map(|value| value.location.as_str())
                .collect::<Vec<_>>(),
            ["rdi", "rsi"]
        );
        assert_eq!(
            function
                .returns
                .iter()
                .map(|value| value.location.as_str())
                .collect::<Vec<_>>(),
            ["rax", "rdx"]
        );
    }

    #[test]
    fn abi_inference_recovers_uniquely_evidenced_floating_types() {
        let scalar = decode_function(
            &[
                0xf3, 0x0f, 0x58, 0xc1, // addss xmm0,xmm1
                0xc3,
            ],
            0x2aa0,
            0,
            "f".repeat(64),
            "float-abi".to_owned(),
            "float_abi".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&scalar).unwrap();
        let function = lower_function_ir(&scalar, &state).unwrap();
        assert_eq!(
            function
                .parameters
                .iter()
                .map(|value| (value.location.as_str(), value.type_name.as_str()))
                .collect::<Vec<_>>(),
            [("xmm0", "float"), ("xmm1", "float")]
        );
        assert!(
            function
                .returns
                .iter()
                .any(|value| value.location == "xmm0" && value.type_name == "float")
        );

        let packed = decode_function(
            &[
                0xc5, 0xf4, 0x58, 0xc2, // vaddps ymm0,ymm1,ymm2
                0xc3,
            ],
            0x2ab0,
            0,
            "1".repeat(64),
            "packed-float-abi".to_owned(),
            "packed_float_abi".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&packed).unwrap();
        let function = lower_function_ir(&packed, &state).unwrap();
        assert_eq!(
            function
                .parameters
                .iter()
                .map(|value| (value.location.as_str(), value.type_name.as_str()))
                .collect::<Vec<_>>(),
            [("ymm1", "float32x8"), ("ymm2", "float32x8")]
        );
        assert!(
            function
                .returns
                .iter()
                .any(|value| value.location == "ymm0" && value.type_name == "float32x8")
        );

        let square_root = decode_function(
            &[
                0xf3, 0x0f, 0x51, 0xc1, // sqrtss xmm0,xmm1
                0xc3,
            ],
            0x2ac0,
            0,
            "2".repeat(64),
            "sqrt-float-abi".to_owned(),
            "sqrt_float_abi".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&square_root).unwrap();
        let function = lower_function_ir(&square_root, &state).unwrap();
        assert_eq!(function.parameters.len(), 1);
        assert_eq!(function.parameters[0].location, "xmm1");
        assert_eq!(function.parameters[0].type_name, "float");
        assert!(
            function
                .returns
                .iter()
                .any(|value| value.location == "xmm0" && value.type_name == "float")
        );
    }

    #[test]
    fn setcc_and_cmovcc_retain_flag_dependencies() {
        let machine = decode_function(
            &[
                0x48, 0x39, 0xf7, // cmp rdi,rsi
                0x0f, 0x94, 0xc0, // sete al
                0x48, 0x0f, 0x45, 0xc7, // cmovne rax,rdi
                0xc3, // ret
            ],
            0x2600,
            0,
            "1".repeat(64),
            "conditional-data".to_owned(),
            "conditional_data".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        let set = &machine.blocks[1].instructions[0];
        let cmov = &machine.blocks[2].instructions[0];
        assert_eq!(set.effects.read_flags, vec!["zf"]);
        assert_eq!(cmov.effects.read_flags, vec!["zf"]);
        assert!(cmov.effects.read_registers.contains(&"rax".to_owned()));
        assert!(cmov.effects.read_registers.contains(&"rdi".to_owned()));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("state->rax & ~UINT64_C(0xff)"));
        assert!(c.contains("if (!state->zf)"));
    }

    #[test]
    fn bounded_indirect_targets_become_explicit_cir_switch_cases() {
        let targets = BTreeMap::from([(0x2800, vec![0x2807, 0x2808])]);
        let machine = decode_function_with_targets(
            &[
                0xff, 0x24, 0xc5, 0x20, 0x20, 0x00, 0x00, // jmp [rax*8+0x2020]
                0xc3, // case 0
                0xc3, // case 1
            ],
            0x2800,
            0,
            "2".repeat(64),
            "jump-table".to_owned(),
            "jump_table".to_owned(),
            &BTreeSet::new(),
            &targets,
        )
        .unwrap();
        assert!(
            machine.blocks[0].instructions[0]
                .edges
                .iter()
                .all(|edge| edge.kind == MachineEdgeKind::IndirectTarget)
        );
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        assert!(matches!(
            &cir.blocks[0].terminator,
            CirTerminator::Switch { targets, .. } if targets.len() == 2
        ));
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_indirect_target"));
        assert!(c.contains("case UINT64_C(0x2807)"));
        assert!(c.contains("case UINT64_C(0x2808)"));
        assert!(c.contains("default:"));
    }

    #[test]
    fn rip_relative_register_constant_resolves_indirect_branch() {
        let bytes = [
            0x48, 0x8d, 0x05, 0x02, 0x00, 0x00, 0x00, // lea rax,[rip+2] -> ret
            0xff, 0xe0, // jmp rax
            0xc3, // ret
        ];
        let initial = decode_function(
            &bytes,
            0x3000,
            0,
            "d".repeat(64),
            "register-constant".to_owned(),
            "register_constant".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            initial.structural_completeness,
            StructuralCompleteness::Partial
        );
        let mut instructions = initial
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        instructions.sort_by_key(|instruction| instruction.address);
        let targets = recover_register_constant_targets(&initial, &instructions, 1, "rax");
        assert_eq!(targets, [location(0, 0x3009)]);
        let recovered = decode_function_with_targets(
            &bytes,
            0x3000,
            0,
            "d".repeat(64),
            "register-constant".to_owned(),
            "register_constant".to_owned(),
            &BTreeSet::new(),
            &BTreeMap::from([(0x3007, vec![0x3009])]),
        )
        .unwrap();
        assert_eq!(
            recovered.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(recovered.blocks.len(), 3);
        assert!(
            recovered.blocks[1].instructions[0]
                .edges
                .iter()
                .any(|edge| {
                    edge.kind == MachineEdgeKind::IndirectTarget
                        && edge.target == Some(location(0, 0x3009))
                })
        );
    }

    #[test]
    fn linked_absolute_jump_table_recovers_all_fixture_targets() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/jump_table.elf");
        let native = decompile_symbol(bytes, "table_dispatch").unwrap();
        let targets = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .flat_map(|instruction| &instruction.edges)
            .filter(|edge| edge.kind == MachineEdgeKind::IndirectTarget)
            .filter_map(|edge| edge.target.map(|target| target.value.0))
            .collect::<Vec<_>>();
        assert_eq!(targets, vec![0x201220, 0x201226, 0x20122c]);
        assert!(
            native
                .machine_ir
                .diagnostics
                .iter()
                .any(|diagnostic| { diagnostic.code == "bounded_indirect_targets" })
        );
        assert!(native.low_level_c.contains("case UINT64_C(0x201220)"));
        assert!(native.low_level_c.contains("case UINT64_C(0x201226)"));
        assert!(native.low_level_c.contains("case UINT64_C(0x20122c)"));
        let structured = native
            .structured_c
            .as_deref()
            .expect("guarded jump table should structure as if/switch");
        assert!(structured.contains("switch (hydir_indirect_target"));
        assert!(structured.contains("if (!state->cf && !state->zf)"));
        assert!(!structured.contains("goto "));
        assert!(native.function_ir.global_objects.iter().any(|object| {
            object.location.value.0 == 0x2001b0 && object.access == RecoveredAccessKind::Read
        }));
    }

    #[test]
    fn unresolved_indirect_call_preserves_target_and_complete_caller_cfg() {
        let machine = decode_function(
            &[
                0xff, 0xd0, // call rax
                0xc3, // ret
            ],
            0x2d80,
            0,
            "d".repeat(64),
            "indirect-call".to_owned(),
            "indirect_call".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let call = machine
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.effects.control == MachineControlEffect::IndirectCall)
            .unwrap();
        assert!(matches!(
            call.operation,
            MachineOperation::Exact { ref family } if family == "call"
        ));
        assert_eq!(call.effects.read_registers, ["rax", "rsp"]);
        assert_eq!(call.effects.written_registers, ["rsp"]);
        assert_eq!(call.effects.memory, MachineMemoryEffect::Write);
        assert!(
            call.edges
                .iter()
                .any(|edge| { edge.kind == MachineEdgeKind::Call && edge.target.is_none() })
        );
        assert!(call.edges.iter().any(|edge| {
            edge.kind == MachineEdgeKind::Fallthrough && edge.target == Some(location(0, 0x2d82))
        }));
        assert!(
            machine
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "unresolved_indirect_call_target")
        );

        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        assert_eq!(function.calls.len(), 1);
        assert!(function.calls[0].indirect);
        assert!(function.calls[0].target.is_none());
        let cir = lower_cir(&machine, &function).unwrap();
        assert!(matches!(
            cir.blocks[0].terminator,
            CirTerminator::Call {
                target: None,
                target_operand: Some(MachineOperand::Register {
                    ref name,
                    width_bits: 64
                }),
                next: Some(next)
            } if name == "rax" && next == location(0, 0x2d82)
        ));
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("unresolved indirect call target"));
        assert!(c.contains("hydir_unknown_call(state, (uint64_t)(state->rax))"));
        assert!(!c.contains("/* opaque call"));
    }

    #[test]
    fn unresolved_indirect_jump_is_exact_but_structurally_partial() {
        let machine = decode_function(
            &[0xff, 0xe0], // jmp rax
            0x2d90,
            0,
            "d".repeat(64),
            "indirect-jump".to_owned(),
            "indirect_jump".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(
            machine.structural_completeness,
            StructuralCompleteness::Partial
        );
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::Conservative);
        let jump = &machine.blocks[0].instructions[0];
        assert!(matches!(
            jump.operation,
            MachineOperation::Exact { ref family } if family == "jmp"
        ));
        assert_eq!(jump.effects.read_registers, ["rax"]);
        assert_eq!(jump.effects.written_registers, Vec::<String>::new());
        assert_eq!(jump.effects.memory, MachineMemoryEffect::None);
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        assert!(matches!(
            cir.blocks[0].terminator,
            CirTerminator::Unresolved {
                target_operand: Some(MachineOperand::Register {
                    ref name,
                    width_bits: 64
                }),
                ..
            } if name == "rax"
        ));
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("hydir_unknown_control(state, (uint64_t)(state->rax))"));
        assert!(!c.contains("/* opaque jmp"));
    }

    #[test]
    fn relocatable_relative_jump_table_recovers_relocation_backed_targets() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/relative_jump_table.o");
        let native = decompile_symbol(bytes, "relative_table_dispatch").unwrap();
        let jump = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .find(|instruction| instruction.effects.control == MachineControlEffect::IndirectBranch)
            .expect("relative table fixture should retain its indirect dispatch");
        assert!(matches!(jump.operation, MachineOperation::Exact { .. }));
        assert_eq!(
            jump.edges
                .iter()
                .filter(|edge| edge.kind == MachineEdgeKind::IndirectTarget)
                .filter_map(|edge| edge.target.map(|target| target.value.0))
                .collect::<Vec<_>>(),
            [0x15, 0x1b, 0x21, 0x27]
        );
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Complete
        );
        assert!(native.low_level_c.contains("case UINT64_C(0x15)"));
        assert!(native.low_level_c.contains("case UINT64_C(0x27)"));
    }

    #[test]
    fn latch_controlled_loop_structures_and_has_state_phi_inputs() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/stack.elf");
        let native = decompile_symbol(bytes, "hydir_repeat3").unwrap();
        let structured = native
            .structured_c
            .as_deref()
            .expect("simple latch loop should structure");
        assert!(structured.contains("do {"));
        assert!(structured.contains("} while (!state->zf);"));
        assert!(!structured.contains("goto "));
        let loop_header = native
            .state_ir
            .blocks
            .iter()
            .find(|block| block.address.value.0 == 0x2013f7)
            .unwrap();
        assert_eq!(loop_header.state_flow.as_ref().unwrap().incoming.len(), 2);
    }

    #[test]
    fn pretested_natural_loop_structures_with_an_explicit_break_guard() {
        let machine = decode_function(
            &[
                0x48, 0x85, 0xff, // test rdi,rdi
                0x74, 0x06, // je exit
                0x48, 0x83, 0xef, 0x01, // sub rdi,1
                0xeb, 0xf5, // jmp test
                0x48, 0x89, 0xf8, // mov rax,rdi
                0xc3, // ret
            ],
            0x2e00,
            0,
            "c".repeat(64),
            "pretest-loop".to_owned(),
            "pretest_loop".to_owned(),
            &BTreeSet::new(),
        )
        .unwrap();
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let structured = hydir_c::emit_native_structured_c(&cir)
            .unwrap()
            .expect("single natural pre-test loop should structure");
        assert!(structured.contains("for (;;) {"));
        assert!(structured.contains("if (state->zf) break;"));
        assert!(!structured.contains("goto "));
        let header = state
            .blocks
            .iter()
            .find(|block| block.address.value.0 == 0x2e00)
            .unwrap();
        assert!(
            header
                .state_flow
                .as_ref()
                .unwrap()
                .incoming
                .iter()
                .any(|incoming| incoming.predecessor.value.0 == 0x2e09)
        );
    }

    #[test]
    fn native_llvm_export_embeds_exact_and_opaque_descriptors() {
        for operation in [
            MachineOperation::Exact {
                family: "nop".to_owned(),
            },
            MachineOperation::OpaqueEffect {
                reason: "unsupported".to_owned(),
            },
        ] {
            let machine = machine(operation);
            let state = lower_state_ir(&machine).unwrap();
            let function = lower_function_ir(&machine, &state).unwrap();
            let llvm = export_function_ir_llvm(&function).unwrap();
            assert!(llvm.contains("%HydirMachineState = type"));
            assert!(llvm.contains("@hydir_op_0"));
            assert!(llvm.contains("rewrite_ready = false"));
            if matches!(
                state.blocks[0].operations[0],
                StateOperation::Unknown { .. }
            ) {
                assert!(llvm.contains("call void @hydir_opaque_effect"));
            } else {
                assert!(llvm.contains("call void @hydir_exact_effect"));
            }
        }
    }

    #[test]
    fn stripped_runtime_arrays_seed_probable_functions() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/dynamic_metadata_stripped.elf");
        let index = discover_functions(bytes).unwrap();
        for (entry, evidence) in [(0x1443, "elf_init_array"), (0x1444, "elf_fini_array")] {
            let function = index
                .functions
                .iter()
                .find(|function| function.entry.value.0 == entry)
                .unwrap();
            assert_eq!(function.state, FunctionEvidenceState::Probable);
            assert!(function.evidence.iter().any(|fact| fact.kind == evidence));
        }
        let exported = index
            .functions
            .iter()
            .find(|function| function.entry.value.0 == 0x1434)
            .unwrap();
        assert_eq!(exported.state, FunctionEvidenceState::Confirmed);
        assert!(
            exported
                .evidence
                .iter()
                .any(|fact| fact.kind == "elf_dynamic_symbol")
        );
    }

    #[test]
    fn decoded_plt_slots_seed_named_bounded_function_entries() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/dynamic_metadata.elf");
        let index = discover_functions(bytes).unwrap();
        let exported = index
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("exported_fn"))
            .expect("exported function should be indexed");
        assert!(exported.candidate_targets.contains(&location(0, 0x1460)));
        let stub = index
            .functions
            .iter()
            .find(|function| function.entry.value.0 == 0x1460)
            .expect("external_hook PLT slot should be indexed");
        assert_eq!(stub.name.as_deref(), Some("external_hook@plt"));
        assert_eq!(stub.state, FunctionEvidenceState::Probable);
        assert_eq!(stub.extents.len(), 1);
        assert_eq!(stub.extents[0].size, 16);
        assert!(
            stub.evidence
                .iter()
                .any(|evidence| evidence.kind == "elf_plt_stub")
        );

        let native = decompile_function_at(bytes, stub.entry).unwrap();
        assert_eq!(native.machine_ir.byte_length, 16);
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Partial
        );
        assert!(native.low_level_c.contains("hydir_unknown_control"));
    }

    #[test]
    fn stripped_unwind_fdes_seed_functions_with_extents() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/unwind_discovery_stripped.elf");
        let index = discover_functions(bytes).unwrap();
        assert_eq!(index.functions.len(), 2);
        for (entry, size) in [(0x129c, 5), (0x12a1, 3)] {
            let function = index
                .functions
                .iter()
                .find(|function| function.entry.value.0 == entry)
                .unwrap();
            assert_eq!(function.state, FunctionEvidenceState::Probable);
            assert_eq!(function.extents.len(), 1);
            assert_eq!(function.extents[0].size, size);
            assert!(!function.block_entries.is_empty());
            assert!(
                function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "elf_unwind_fde")
            );
            let machine = lift_machine_function_at(bytes, function.entry).unwrap();
            assert_eq!(machine.byte_length, size);
            let unit = decompile_function_unit_at(bytes, function.entry).unwrap();
            assert_eq!(unit.function_id.as_deref(), Some(function.id.as_str()));
            assert!(!unit.statement_provenance.is_empty());
            assert!(!unit.rewrite_ready);
        }
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 2);
        assert_eq!(coverage.lifted_functions, 2);
        assert_eq!(coverage.exact_functions, 2);
        assert_eq!(coverage.partial_functions, 2);
    }

    #[test]
    fn stripped_go_pclntab_recovers_named_bounded_functions() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/go_pclntab_stripped.elf");
        let index = discover_functions(bytes).unwrap();
        for (name, entry) in [("main.first", 0x2011fc), ("main.second", 0x201201)] {
            let function = index
                .functions
                .iter()
                .find(|function| function.name.as_deref() == Some(name))
                .expect("Go pclntab function should be indexed by its runtime name");
            assert_eq!(function.entry, location(0, entry));
            assert_eq!(function.state, FunctionEvidenceState::Confirmed);
            assert_eq!(function.extents.len(), 1);
            assert_eq!(function.extents[0].size, 5);
            assert!(
                function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.kind == "go_pclntab")
            );
            assert!(!function.block_entries.is_empty());

            let native = decompile_function_at(bytes, function.entry).unwrap();
            assert_eq!(native.machine_ir.byte_length, 5);
            assert_eq!(
                native.machine_ir.structural_completeness,
                StructuralCompleteness::Complete
            );
            assert!(native.machine_ir.blocks.iter().all(|block| {
                block.instructions.iter().all(|instruction| {
                    matches!(instruction.operation, MachineOperation::Exact { .. })
                })
            }));
            assert!(!native.low_level_c.contains("/* opaque "));
        }
        assert!(
            !index
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "go_pclntab_invalid")
        );
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 2);
        assert_eq!(coverage.lifted_functions, 2);
        assert_eq!(coverage.exact_instructions, 4);
        assert_eq!(coverage.opaque_instructions, 0);
        assert_eq!(coverage.partial_functions, 0);
    }

    #[test]
    fn real_stripped_go_compiler_output_recovers_and_lifts_selected_function() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/go_real_stripped.elf");
        let spec = import_elf(bytes).unwrap();
        let discovery = discover_go_pclntab(bytes, &spec).unwrap();
        assert!(discovery.candidates.len() >= 1_400);
        assert_eq!(discovery.skipped, 0);
        assert_eq!(discovery.omitted, 0);
        let candidate = discovery
            .candidates
            .iter()
            .find(|candidate| candidate.name == "main.hydirMix")
            .expect("real Go pclntab should retain the selected source function");
        assert_eq!(candidate.size, 64);
        let code = extract_location_window(
            bytes,
            &spec,
            candidate.entry,
            usize::try_from(candidate.size).unwrap(),
        )
        .unwrap();
        let stop_entries = discovery
            .candidates
            .iter()
            .map(|candidate| candidate.entry.value.0)
            .filter(|entry| *entry != candidate.entry.value.0)
            .collect::<BTreeSet<_>>();
        let machine = decode_program_function(
            &code,
            candidate.entry.value.0,
            candidate.entry.address_space,
            spec.binary_sha256.clone(),
            format!("sha256:{}:go-selected", spec.binary_sha256),
            candidate.name.clone(),
            &stop_entries,
            bytes,
            &spec,
        )
        .unwrap();
        assert_eq!(machine.semantic_fidelity, SemanticFidelity::ExactUnderModel);
        assert_eq!(
            machine
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .count(),
            11
        );
        assert!(machine.blocks.iter().all(|block| {
            block
                .instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        }));
        let state = lower_state_ir(&machine).unwrap();
        let function = lower_function_ir(&machine, &state).unwrap();
        let cir = lower_cir(&machine, &function).unwrap();
        let c = hydir_c::emit_native_low_level_c(&cir).unwrap();
        assert!(c.contains("state->rax"));
        assert!(c.contains("state->rbx"));
        assert!(!c.contains("/* opaque "));

        let index = discover_functions(bytes).unwrap();
        let large_id = index
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("runtime.(*semaRoot).queue"))
            .map(|function| function.id.clone())
            .expect("real Go pclntab should retain the large semaphore queue function");
        let large = decompile_indexed_function(bytes, &index, &large_id).unwrap();
        assert!(
            large
                .function_ir
                .parameters
                .iter()
                .all(|parameter| parameter.evidence.len() <= 64)
        );
        assert!(
            large
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "abi_evidence_truncated")
        );
    }

    #[test]
    fn real_rust_linux_object_preserves_v0_evidence_and_slice_abi() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/rust_real.o");
        let coverage = measure_native_coverage(bytes).unwrap();
        assert_eq!(coverage.discovered_functions, 2);
        assert_eq!(coverage.lifted_functions, 2);
        assert_eq!(coverage.exact_functions, 2);
        assert_eq!(coverage.exact_instructions, 80);
        assert_eq!(coverage.opaque_instructions, 0);

        let index = discover_functions(bytes).unwrap();
        let rust = index
            .functions
            .iter()
            .find(|function| {
                function
                    .name
                    .as_deref()
                    .is_some_and(|name| name.starts_with("_R"))
            })
            .expect("rustc v0 symbol should be indexed");
        assert!(
            rust.evidence
                .iter()
                .any(|evidence| evidence.kind == "rust_symbol")
        );
        let name = rust.name.as_deref().unwrap();
        let native = decompile_symbol(bytes, name).unwrap();
        assert_eq!(native.function_ir.parameters.len(), 2);
        assert_eq!(native.function_ir.parameters[0].location, "rdi");
        assert_eq!(native.function_ir.parameters[0].type_name, "void *");
        assert_eq!(native.function_ir.parameters[1].location, "rsi");
        assert_eq!(native.function_ir.returns[0].location, "rax");
        assert!(native.machine_ir.blocks.iter().all(|block| {
            block
                .instructions
                .iter()
                .all(|instruction| matches!(instruction.operation, MachineOperation::Exact { .. }))
        }));
        assert!(!native.low_level_c.contains("/* opaque "));
        let structured = native
            .structured_c
            .as_deref()
            .expect("rustc slice loop should have a conservative structured view");
        assert!(structured.contains("for (;;) {"));
        assert!(structured.contains("continue;"));
        assert!(structured.contains("break;"));

        let mix = decompile_symbol(bytes, "hydir_rust_mix").unwrap();
        let mix_structured = mix
            .structured_c
            .as_deref()
            .expect("multi-loop rustc function should have a hybrid structured view");
        assert_eq!(mix_structured.matches("for (;;) {").count(), 2);
        assert!(mix_structured.contains("continue;"));
        assert!(mix_structured.contains("break;"));
    }

    #[test]
    fn malformed_go_pclntab_is_a_bounded_diagnostic_not_a_file_failure() {
        let original = include_bytes!("../../../fuzz/corpus/elf_import/go_pclntab_stripped.elf");
        let spec = import_elf(original).unwrap();
        let metadata_offset = usize::try_from(
            spec.runtime_ranges
                .iter()
                .find(|range| range.section_name == ".gopclntab")
                .and_then(|range| range.file_offset)
                .expect("fixture Go metadata has a file offset")
                .0,
        )
        .unwrap();

        for (field_offset, value) in [(8usize, 1_000_001u64), (64usize, u64::MAX)] {
            let mut bytes = original.to_vec();
            bytes[metadata_offset + field_offset..metadata_offset + field_offset + 8]
                .copy_from_slice(&value.to_le_bytes());
            let index = discover_functions(&bytes).unwrap();
            let diagnostic = index
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "go_pclntab_invalid")
                .expect("malformed pclntab should remain an explicit diagnostic");
            assert!(diagnostic.blocks_stable_operation);
            assert!(index.functions.len() <= MAX_DISCOVERED_FUNCTIONS);
        }
    }

    #[test]
    fn relocatable_call_uses_relocation_instead_of_placeholder_bytes() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/relocatable_metadata.o");
        let native = decompile_symbol(bytes, "exported_fn").unwrap();
        let call = native
            .machine_ir
            .blocks
            .iter()
            .flat_map(|block| block.instructions.iter())
            .find(|instruction| instruction.effects.control == MachineControlEffect::DirectCall)
            .unwrap();
        assert!(matches!(
            &call.operands[0],
            MachineOperand::RelocatedBranch {
                target: None,
                symbol: Some(symbol),
                relocation_kind,
                ..
            } if symbol == "external_hook" && relocation_kind == "PltRelative"
        ));
        assert!(
            call.edges
                .iter()
                .any(|edge| edge.kind == MachineEdgeKind::Call && edge.target.is_none())
        );
        assert_eq!(
            native.machine_ir.structural_completeness,
            StructuralCompleteness::Partial
        );
        assert!(native.low_level_c.contains("hydir_unknown_call"));
        assert_eq!(native.function_ir.calls.len(), 1);
        assert_eq!(
            native.function_ir.calls[0].symbol.as_deref(),
            Some("external_hook")
        );
        assert!(native.function_ir.calls[0].target.is_none());
        assert!(
            !native
                .low_level_c
                .contains("hydir_call(state, UINT64_C(0x0))")
        );

        let unit = decompile_symbol_unit(bytes, "exported_fn").unwrap();
        assert_eq!(
            unit.region.address_kind,
            hydir_core::AddressKind::SectionRelative
        );
        assert_eq!(unit.region.relocations.len(), 1);
        assert!(!unit.statement_provenance.is_empty());
        assert!(!unit.rewrite_ready);
    }

    #[test]
    fn relocatable_function_index_entry_lifts_from_section_location() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/relocatable_metadata.o");
        let index = discover_functions(bytes).unwrap();
        let function = index
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("exported_fn"))
            .unwrap();
        assert_ne!(function.entry.address_space, 0);
        assert!(function.block_entries.len() > 1);
        let machine = lift_machine_function_at(bytes, function.entry).unwrap();
        assert_eq!(machine.entry, function.entry);
        assert_eq!(function.state, FunctionEvidenceState::Confirmed);
        assert!(
            !machine
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "evidence_bounded_extent")
        );
        assert!(
            machine
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| matches!(
                    instruction.operands.first(),
                    Some(MachineOperand::RelocatedBranch {
                        symbol: Some(symbol),
                        ..
                    }) if symbol == "external_hook"
                ))
        );
        let unit = decompile_function_unit_at(bytes, function.entry).unwrap();
        assert_eq!(unit.region.address_kind, AddressKind::SectionRelative);
        assert_eq!(unit.region.byte_length, machine.byte_length);
        assert!(!unit.statement_provenance.is_empty());
    }

    #[test]
    fn function_index_preserves_candidate_targets_and_tail_call_evidence() {
        let bytes = include_bytes!("../../../fuzz/corpus/elf_import/tail_calls.o");
        let index = discover_functions(bytes).unwrap();
        let source = index
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("hydir_tail_source"))
            .expect("tail source should be indexed");
        let target = index
            .functions
            .iter()
            .find(|function| function.name.as_deref() == Some("hydir_tail_target"))
            .expect("tail target should be indexed");
        assert!(source.candidate_targets.contains(&target.entry));
        assert_eq!(source.tail_call_evidence.len(), 1);
        assert_eq!(source.tail_call_evidence[0].kind, "direct_terminal_branch");
        assert_eq!(source.tail_call_evidence[0].site, Some(source.entry));

        let native = decompile_function_at(bytes, source.entry).unwrap();
        assert_eq!(native.function_ir.calls.len(), 1);
        assert!(native.function_ir.calls[0].tail_call);
        assert_eq!(native.function_ir.calls[0].target, Some(target.entry));
    }

    #[test]
    fn x86_branch_relocation_accounts_for_next_ip_bias() {
        let relocation = RelocationSpec {
            location: Address(5),
            location_ref: Some(location(2, 5)),
            address_kind: hydir_core::AddressKind::SectionRelative,
            source_section: Some(".text.caller".to_owned()),
            kind: "PltRelative".to_owned(),
            encoding: "X86Branch".to_owned(),
            format_flags: "Elf { r_type: 4 }".to_owned(),
            size_bits: 32,
            addend: -4,
            implicit_addend: false,
            target: RelocationTargetSpec::Symbol {
                id: "target".to_owned(),
                name: Some("target".to_owned()),
                location: Some(location(7, 0x20)),
                defined: true,
            },
            provenance: hydir_core::FactProvenance {
                source: hydir_core::FactSource::ElfMetadata,
                scope: "test".to_owned(),
            },
        };
        assert_eq!(
            relocated_control_target(&relocation),
            Some(location(7, 0x20))
        );
    }
}
