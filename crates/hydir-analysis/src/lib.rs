//! Conservative, symbol-bounded x86-64 ELF global-effect analysis.
//!
//! This is not a complete whole-program recovery. Direct calls to bounded
//! symbols are resolved; unrecognized targets and non-RIP memory are tainted
//! as possible global effects rather than treated as pure.

use hydir_backend::{HydirError, MAX_BINARY_BYTES, import_elf};
use hydir_core::{
    Address, AssumptionSpec, CallSpec, FactProvenance, FactSource, ProgramSpec, RecoveryState,
    ReferenceSpec,
};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind,
    Register,
};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const MAX_FUNCTIONS: usize = 512;
const MAX_FUNCTION_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GlobalReference {
    pub address: Address,
    pub section: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FunctionSummary {
    pub name: String,
    pub entry: Address,
    pub reachable_instructions: usize,
    pub direct_callees: Vec<String>,
    /// Recovered instruction sites, including direct targets outside the
    /// bounded symbol set and unknown indirect targets.
    pub call_sites: Vec<CallSpec>,
    /// Mapped-global targets where known; `None` means unresolved memory.
    pub reference_sites: Vec<ReferenceSpec>,
    pub unresolved_targets: Vec<Address>,
    pub direct_global_reads: Vec<GlobalReference>,
    pub direct_global_writes: Vec<GlobalReference>,
    pub possible_global_reads: Vec<GlobalReference>,
    pub possible_global_writes: Vec<GlobalReference>,
    /// True means the above enumerated addresses are NOT an exhaustive list.
    pub unknown_global_effects: bool,
    pub recovery_complete_within_symbol: bool,
    pub scc_id: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub scope: String,
    pub assumption: String,
    pub skipped_functions: Vec<String>,
    pub functions: Vec<FunctionSummary>,
}

#[derive(Clone)]
struct FunctionInput {
    name: String,
    entry: u64,
    code: Vec<u8>,
}

#[derive(Clone)]
struct GlobalRegion {
    start: u64,
    end: u64,
    section: String,
}

#[derive(Default)]
struct DirectFacts {
    name: String,
    entry: u64,
    instruction_count: usize,
    callees: BTreeSet<usize>,
    call_sites: BTreeSet<(Address, Option<Address>)>,
    reference_sites: BTreeSet<(Address, Option<Address>)>,
    unresolved: BTreeSet<Address>,
    reads: BTreeSet<GlobalReference>,
    writes: BTreeSet<GlobalReference>,
    unknown: bool,
    complete: bool,
}

pub fn analyze_elf(bytes: &[u8]) -> Result<AnalysisReport, HydirError> {
    if bytes.len() > MAX_BINARY_BYTES {
        return Err(HydirError("binary exceeds 64 MiB import limit".to_owned()));
    }
    let spec = import_elf(bytes)?;
    let file = object::File::parse(bytes)
        .map_err(|error| HydirError(format!("ELF parse failed: {error}")))?;
    if file.kind() == object::ObjectKind::Relocatable {
        return Err(HydirError(
            "global analysis currently requires a linked ELF; relocatable call targets need relocation resolution"
                .to_owned(),
        ));
    }
    let mut regions = Vec::new();
    for section in file.sections() {
        if !matches!(
            section.kind(),
            SectionKind::Data
                | SectionKind::ReadOnlyData
                | SectionKind::ReadOnlyDataWithRel
                | SectionKind::ReadOnlyString
                | SectionKind::UninitializedData
        ) {
            continue;
        }
        if let Some(end) = section.address().checked_add(section.size())
            && section.size() != 0
        {
            regions.push(GlobalRegion {
                start: section.address(),
                end,
                section: section.name().unwrap_or("<invalid-name>").to_owned(),
            });
        }
    }
    let mut selected = BTreeMap::<u64, FunctionInput>::new();
    let mut skipped = Vec::new();
    for symbol in file.symbols().filter(|symbol| {
        symbol.kind() == SymbolKind::Text && symbol.is_definition() && symbol.size() > 0
    }) {
        let name = symbol.name().unwrap_or("<invalid-name>").to_owned();
        if symbol.size() > MAX_FUNCTION_BYTES {
            skipped.push(format!("{name}: exceeds 4096-byte symbol limit"));
            continue;
        }
        let Some(index) = symbol.section_index() else {
            skipped.push(format!("{name}: no section"));
            continue;
        };
        let Ok(section) = file.section_by_index(index) else {
            skipped.push(format!("{name}: section lookup failed"));
            continue;
        };
        if section.kind() != SectionKind::Text || section.size() > 16 * 1024 * 1024 {
            skipped.push(format!("{name}: unsupported text section"));
            continue;
        }
        let Some(offset) = symbol.address().checked_sub(section.address()) else {
            skipped.push(format!("{name}: address precedes section"));
            continue;
        };
        let Some(end) = offset.checked_add(symbol.size()) else {
            skipped.push(format!("{name}: symbol range overflow"));
            continue;
        };
        let Ok(section_bytes) = section.data() else {
            skipped.push(format!("{name}: section bytes unavailable"));
            continue;
        };
        let Some(code) = usize::try_from(offset)
            .ok()
            .zip(usize::try_from(end).ok())
            .and_then(|(start, end)| section_bytes.get(start..end))
        else {
            skipped.push(format!("{name}: symbol bytes outside section"));
            continue;
        };
        selected.entry(symbol.address()).or_insert(FunctionInput {
            name,
            entry: symbol.address(),
            code: code.to_vec(),
        });
    }
    if selected.len() > MAX_FUNCTIONS {
        return Err(HydirError(format!(
            "analysis supports at most {MAX_FUNCTIONS} bounded function symbols"
        )));
    }
    let inputs: Vec<_> = selected.into_values().collect();
    let mut report = analyze_inputs(&inputs, &regions);
    report.binary_sha256 = spec.binary_sha256;
    report.skipped_functions = skipped;
    Ok(report)
}

/// Join the bounded analysis facts to an ELF metadata inventory. This is a
/// derived view, not a claim of whole-program recovery or persisted analyst
/// assumptions. Omitted symbols and unresolved edges keep recovery partial.
pub fn analyze_spec_elf(bytes: &[u8]) -> Result<ProgramSpec, HydirError> {
    let report = analyze_elf(bytes)?;
    let mut spec = import_elf(bytes)?;
    for summary in &report.functions {
        spec.calls.extend(summary.call_sites.iter().cloned());
        spec.references
            .extend(summary.reference_sites.iter().cloned());
        if let Some(function) = spec
            .functions
            .iter_mut()
            .find(|function| function.name == summary.name && function.address == summary.entry)
        {
            function.control_flow_status = if summary.recovery_complete_within_symbol {
                "reachable instructions recovered within bounded symbol; not whole-program complete"
            } else {
                "partial reachable recovery within bounded symbol"
            }
            .to_owned();
        }
    }
    spec.call_recovery = RecoveryState::Partial;
    spec.reference_recovery = RecoveryState::Partial;
    spec.assumptions.push(AssumptionSpec {
        id: format!("sha256:{}:analysis-contract:1", spec.binary_sha256),
        statement: report.assumption,
        scope: report.scope,
        provenance: FactProvenance {
            source: FactSource::NativeAnalysis,
            scope: "HydIR bounded global-effects analysis contract".to_owned(),
        },
    });
    spec.recovery_scope = format!(
        "ELF metadata plus bounded analysis of {} symbolized functions; {} skipped; calls/references remain partial",
        report.functions.len(),
        report.skipped_functions.len()
    );
    Ok(spec)
}

fn analyze_inputs(inputs: &[FunctionInput], regions: &[GlobalRegion]) -> AnalysisReport {
    let by_address: BTreeMap<u64, usize> = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| (input.entry, index))
        .collect();
    let direct: Vec<_> = inputs
        .iter()
        .map(|input| analyze_function(input, regions, &by_address))
        .collect();
    let scc = component_ids(&direct);
    let mut reads: Vec<_> = direct.iter().map(|facts| facts.reads.clone()).collect();
    let mut writes: Vec<_> = direct.iter().map(|facts| facts.writes.clone()).collect();
    let mut unknown: Vec<_> = direct.iter().map(|facts| facts.unknown).collect();
    // Finite monotone lattice; this converges for recursive SCCs too.
    loop {
        let mut changed = false;
        for (index, facts) in direct.iter().enumerate() {
            let mut next_reads = reads[index].clone();
            let mut next_writes = writes[index].clone();
            let mut next_unknown = unknown[index];
            for callee in &facts.callees {
                next_reads.extend(reads[*callee].iter().cloned());
                next_writes.extend(writes[*callee].iter().cloned());
                next_unknown |= unknown[*callee];
            }
            if next_reads != reads[index]
                || next_writes != writes[index]
                || next_unknown != unknown[index]
            {
                reads[index] = next_reads;
                writes[index] = next_writes;
                unknown[index] = next_unknown;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    AnalysisReport {
        schema_version: 2,
        binary_sha256: String::new(),
        scope: "Reachable instructions inside bounded ELF text symbols; only direct calls to selected symbol entries are resolved. Listed global addresses are may-accesses, not exhaustive when unknown_global_effects is true.".to_owned(),
        assumption: "Linked x86-64 ELF virtual addresses; call/return stack bookkeeping is treated as stack-local under the System V AMD64 stack contract. No other register-based memory access is assumed stack-local.".to_owned(),
        skipped_functions: Vec::new(),
        functions: direct
            .iter()
            .enumerate()
            .map(|(index, facts)| FunctionSummary {
                name: facts.name.clone(),
                entry: Address(facts.entry),
                reachable_instructions: facts.instruction_count,
                direct_callees: facts
                    .callees
                    .iter()
                    .map(|callee| direct[*callee].name.clone())
                    .collect(),
                call_sites: facts
                    .call_sites
                    .iter()
                    .map(|(source, target)| CallSpec {
                        source: *source,
                        target: *target,
                        provenance: analysis_site_provenance(),
                    })
                    .collect(),
                reference_sites: facts
                    .reference_sites
                    .iter()
                    .map(|(source, target)| ReferenceSpec {
                        source: *source,
                        target: *target,
                        provenance: analysis_site_provenance(),
                    })
                    .collect(),
                unresolved_targets: facts.unresolved.iter().copied().collect(),
                direct_global_reads: facts.reads.iter().cloned().collect(),
                direct_global_writes: facts.writes.iter().cloned().collect(),
                possible_global_reads: reads[index].iter().cloned().collect(),
                possible_global_writes: writes[index].iter().cloned().collect(),
                unknown_global_effects: unknown[index],
                recovery_complete_within_symbol: facts.complete,
                scc_id: scc[index],
            })
            .collect(),
    }
}

fn analysis_site_provenance() -> FactProvenance {
    FactProvenance {
        source: FactSource::NativeAnalysis,
        scope: "reachable instruction within a bounded ELF text symbol".to_owned(),
    }
}

fn analyze_function(
    input: &FunctionInput,
    regions: &[GlobalRegion],
    by_address: &BTreeMap<u64, usize>,
) -> DirectFacts {
    let mut facts = DirectFacts {
        name: input.name.clone(),
        entry: input.entry,
        complete: true,
        ..DirectFacts::default()
    };
    let Some(end) = input.entry.checked_add(input.code.len() as u64) else {
        facts.complete = false;
        facts.unknown = true;
        return facts;
    };
    let mut pending = VecDeque::from([input.entry]);
    let mut decoded = BTreeMap::<u64, u64>::new();
    let mut info_factory = InstructionInfoFactory::new();
    while let Some(address) = pending.pop_front() {
        if decoded.contains_key(&address) {
            continue;
        }
        if address < input.entry || address >= end {
            facts.unresolved.insert(Address(address));
            facts.complete = false;
            facts.unknown = true;
            continue;
        }
        let offset = (address - input.entry) as usize;
        let mut decoder =
            Decoder::with_ip(64, &input.code[offset..], address, DecoderOptions::NONE);
        let instruction = decoder.decode();
        let next = instruction.next_ip();
        if instruction.is_invalid()
            || next <= address
            || next > end
            || decoded
                .range(..=address)
                .next_back()
                .is_some_and(|(_, previous_end)| *previous_end > address)
            || decoded.range(address..next).next().is_some()
        {
            facts.unresolved.insert(Address(address));
            facts.complete = false;
            facts.unknown = true;
            continue;
        }
        decoded.insert(address, next);
        facts.instruction_count += 1;
        if instruction.is_privileged() {
            facts.unknown = true;
        }
        for memory in info_factory.info(&instruction).used_memory() {
            if memory.access() == OpAccess::NoMemAccess {
                continue;
            }
            if matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall | FlowControl::Return
            ) && memory.base() == Register::RSP
                && memory.index() == Register::None
            {
                continue;
            }
            let address = if instruction.is_ip_rel_memory_operand()
                && memory.index() == Register::None
                && memory.displacement() == instruction.ip_rel_memory_address()
            {
                Some(instruction.ip_rel_memory_address())
            } else {
                None
            };
            let Some((reference, region_end)) = address.and_then(|address| {
                regions.iter().find_map(|region| {
                    (region.start <= address && address < region.end).then(|| {
                        (
                            GlobalReference {
                                address: Address(address),
                                section: region.section.clone(),
                            },
                            region.end,
                        )
                    })
                })
            }) else {
                facts
                    .reference_sites
                    .insert((Address(instruction.ip()), address.map(Address)));
                facts.unknown = true;
                continue;
            };
            facts
                .reference_sites
                .insert((Address(instruction.ip()), Some(reference.address)));
            let size = memory.memory_size().size() as u64;
            if size == 0
                || reference
                    .address
                    .0
                    .checked_add(size)
                    .is_none_or(|end| end > region_end)
            {
                facts.unknown = true;
            }
            if matches!(
                memory.access(),
                OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
            ) {
                facts.reads.insert(reference.clone());
            }
            if matches!(
                memory.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                facts.writes.insert(reference);
            }
        }
        let direct_target = matches!(
            instruction.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        .then(|| instruction.near_branch_target());
        match instruction.flow_control() {
            FlowControl::Next => pending.push_back(next),
            FlowControl::ConditionalBranch => {
                if let Some(target) = direct_target {
                    pending.push_back(target);
                } else {
                    facts.unknown = true;
                    facts.complete = false;
                }
                pending.push_back(next);
            }
            FlowControl::UnconditionalBranch => {
                if let Some(target) = direct_target {
                    if let Some(callee) = by_address.get(&target)
                        && (target < input.entry || target >= end)
                    {
                        facts
                            .call_sites
                            .insert((Address(instruction.ip()), Some(Address(target))));
                        facts.callees.insert(*callee); // direct tail call
                    } else {
                        pending.push_back(target);
                    }
                } else {
                    facts.unknown = true;
                    facts.complete = false;
                }
            }
            FlowControl::Call => {
                if instruction.mnemonic() == Mnemonic::Call {
                    facts
                        .call_sites
                        .insert((Address(instruction.ip()), direct_target.map(Address)));
                    if let Some(target) = direct_target.and_then(|target| by_address.get(&target)) {
                        facts.callees.insert(*target);
                    } else {
                        facts.unknown = true;
                        facts
                            .unresolved
                            .insert(Address(direct_target.unwrap_or(instruction.ip())));
                    }
                } else {
                    // SYSCALL and similar control transfers are external
                    // effects, not function-call graph edges.
                    facts.unknown = true;
                    facts.unresolved.insert(Address(instruction.ip()));
                }
                pending.push_back(next);
            }
            FlowControl::IndirectCall => {
                facts.call_sites.insert((Address(instruction.ip()), None));
                facts.unknown = true;
                facts.unresolved.insert(Address(instruction.ip()));
                pending.push_back(next);
            }
            FlowControl::Return => {}
            _ => {
                facts.unknown = true;
                facts.complete = false;
                facts.unresolved.insert(Address(instruction.ip()));
            }
        }
    }
    facts
}

fn component_ids(facts: &[DirectFacts]) -> Vec<usize> {
    fn visit(index: usize, facts: &[DirectFacts], seen: &mut [bool], order: &mut Vec<usize>) {
        if seen[index] {
            return;
        }
        seen[index] = true;
        for callee in &facts[index].callees {
            visit(*callee, facts, seen, order);
        }
        order.push(index);
    }
    fn assign(index: usize, reverse: &[Vec<usize>], ids: &mut [usize], id: usize) {
        if ids[index] != usize::MAX {
            return;
        }
        ids[index] = id;
        for caller in &reverse[index] {
            assign(*caller, reverse, ids, id);
        }
    }
    let mut order = Vec::new();
    let mut seen = vec![false; facts.len()];
    for index in 0..facts.len() {
        visit(index, facts, &mut seen, &mut order);
    }
    let mut reverse = vec![Vec::new(); facts.len()];
    for (index, fact) in facts.iter().enumerate() {
        for callee in &fact.callees {
            reverse[*callee].push(index);
        }
    }
    let mut ids = vec![usize::MAX; facts.len()];
    let mut next_id = 0;
    for index in order.into_iter().rev() {
        if ids[index] == usize::MAX {
            assign(index, &reverse, &mut ids, next_id);
            next_id += 1;
        }
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(callee_code: &[u8]) -> AnalysisReport {
        // caller: call 0x2000; ret. callee: fixture bytes at 0x2000.
        analyze_inputs(
            &[
                FunctionInput {
                    name: "caller".to_owned(),
                    entry: 0x1000,
                    code: vec![0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3],
                },
                FunctionInput {
                    name: "callee".to_owned(),
                    entry: 0x2000,
                    code: callee_code.to_vec(),
                },
            ],
            &[GlobalRegion {
                start: 0x3000,
                end: 0x3010,
                section: ".data".to_owned(),
            }],
        )
    }

    #[test]
    fn changing_callee_global_write_changes_caller_summary() {
        let pure = fixture(&[0xc3]);
        let writing = fixture(&[
            0xc7, 0x05, 0xf6, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xc3,
        ]);
        assert_eq!(pure.functions[0].direct_callees, ["callee"]);
        assert!(pure.functions[0].possible_global_writes.is_empty());
        assert!(writing.functions[0].direct_global_writes.is_empty());
        assert_eq!(
            writing.functions[0].possible_global_writes[0].address,
            Address(0x3000)
        );
        assert_eq!(writing.functions[0].call_sites[0].source, Address(0x1000));
        assert_eq!(
            writing.functions[0].call_sites[0].target,
            Some(Address(0x2000))
        );
        assert_eq!(
            writing.functions[1].reference_sites[0].source,
            Address(0x2000)
        );
        assert_eq!(
            writing.functions[1].reference_sites[0].target,
            Some(Address(0x3000))
        );
    }

    #[test]
    fn unresolved_call_never_becomes_no_side_effects() {
        let report = analyze_inputs(
            &[FunctionInput {
                name: "caller".to_owned(),
                entry: 0x1000,
                code: vec![0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3],
            }],
            &[],
        );
        assert!(report.functions[0].unknown_global_effects);
        assert_eq!(report.functions[0].unresolved_targets, [Address(0x2000)]);
        assert_eq!(
            report.functions[0].call_sites[0].target,
            Some(Address(0x2000))
        );
    }

    #[test]
    fn indirect_call_keeps_unknown_target_and_effects() {
        let report = analyze_inputs(
            &[FunctionInput {
                name: "caller".to_owned(),
                entry: 0x1000,
                code: vec![0xff, 0xd0, 0xc3], // call rax; ret
            }],
            &[],
        );
        assert_eq!(report.functions[0].call_sites.len(), 1);
        assert_eq!(report.functions[0].call_sites[0].source, Address(0x1000));
        assert_eq!(report.functions[0].call_sites[0].target, None);
        assert!(report.functions[0].reference_sites.is_empty());
        assert!(report.functions[0].unknown_global_effects);
    }

    #[test]
    fn syscall_is_not_invented_as_a_function_call() {
        let report = analyze_inputs(
            &[FunctionInput {
                name: "entry".to_owned(),
                entry: 0x1000,
                code: vec![0x0f, 0x05], // syscall
            }],
            &[],
        );
        assert!(report.functions[0].call_sites.is_empty());
        assert!(report.functions[0].unknown_global_effects);
    }

    #[test]
    fn recursive_component_reaches_fixed_point() {
        let report = analyze_inputs(
            &[
                FunctionInput {
                    name: "a".to_owned(),
                    entry: 0x1000,
                    code: vec![0xe8, 0xfb, 0x0f, 0x00, 0x00, 0xc3],
                },
                FunctionInput {
                    name: "b".to_owned(),
                    entry: 0x2000,
                    code: vec![
                        0xe8, 0xfb, 0xef, 0xff, 0xff, // call a
                        0xc7, 0x05, 0xf1, 0x0f, 0x00, 0x00, 0x01, 0x00, 0x00,
                        0x00, // write 0x3000
                        0xc3,
                    ],
                },
            ],
            &[GlobalRegion {
                start: 0x3000,
                end: 0x3010,
                section: ".data".to_owned(),
            }],
        );
        assert_eq!(report.functions[0].scc_id, report.functions[1].scc_id);
        assert_eq!(
            report.functions[0].possible_global_writes,
            report.functions[1].possible_global_writes
        );
        assert_eq!(
            report.functions[0].possible_global_writes[0].address,
            Address(0x3000)
        );
    }
}
