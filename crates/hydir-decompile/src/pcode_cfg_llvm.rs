//! Bounded CFG-aware LLVM execution for a selected Ghidra raw P-code function.
//! Each operation keeps its source address. Stops are explicit and fidelity is
//! Unknown: this is a concrete path engine, not an equivalence proof.

use crate::pcode_llvm::{emit_pcode_exact_operation_llvm, pcode_offset, pcode_space_id};
use crate::pcode_standalone::{MAX_STATE_BYTES, PcodeStateByte, helper_definitions, node_bytes};
use hydir_ir::pcode::{
    GhidraAddressSpace, GhidraFlowKind, GhidraSnapshot, PcodeAddress, PcodeEffect,
    PcodeElfProcessMemory, PcodeExactOp, PcodeOpaqueClass, PcodeOperation,
    PcodeProcessAllocationKind, PcodeProcessAllocations, PcodeReadOnlyElfWindow,
    PcodeSemanticFunctionIr, PcodeSimplificationArtifact, PcodeVarnode, validate_ghidra_snapshot,
};
use hydir_ir::{SemanticFidelity, VerificationStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const PCODE_CFG_LLVM_VERSION: u32 = 2;
pub const PCODE_CFG_IMAGE_LLVM_VERSION: u32 = 3;
pub const PCODE_CFG_PROCESS_LLVM_VERSION: u32 = 4;
pub const PCODE_CFG_ALLOCATED_PROCESS_LLVM_VERSION: u32 = 5;
pub const PCODE_CFG_ELF_IMAGE_MAX_BYTES: usize = 65_536;
pub const PCODE_SIMPLIFIED_CFG_LLVM_VERSION: u32 = 1;
pub const PCODE_INTERPROCEDURAL_CFG_LLVM_VERSION: u32 = 1;
pub const PCODE_INTERPROCEDURAL_ALLOCATED_PROCESS_CFG_LLVM_VERSION: u32 = 2;
pub const PCODE_CFG_GUEST_RAM_MAX_BYTES: u64 = 1_048_576;
const MAX_CFG_INSTRUCTIONS: usize = 4096;
const MAX_CFG_OPERATIONS: usize = 4096;
const MAX_RUNTIME_STEPS: u32 = 262_144;
const MAX_LLVM_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROCESS_LLVM_BYTES: usize = 16 * 1024 * 1024;

#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeCfgLlvmStatus {
    Return = 1,
    Call = 2,
    OpaqueEffect = 3,
    UnsupportedMemory = 4,
    IndirectFlow = 5,
    UnresolvedFlow = 6,
    AmbiguousFlow = 7,
    OutOfFunction = 8,
    MalformedTarget = 9,
    UnknownInput = 10,
    StepBudget = 11,
    InvalidArguments = 12,
    VisitBudget = 13,
    InvalidOperation = 14,
    MemoryUnknownAlias = 15,
    MemoryUnknownBytes = 16,
    MemoryOutOfBounds = 17,
    MemoryAddressOverflow = 18,
    MemorySpaceMismatch = 19,
    MemoryUnsupportedLayout = 20,
    MemoryNonRamSpace = 21,
    MemoryUnknownSpace = 22,
    CallDepth = 23,
    ReturnMismatch = 24,
    RecursiveCall = 25,
    MemoryReadOnly = 26,
    MemoryUnmappedWrite = 27,
}

impl PcodeCfgLlvmStatus {
    pub const fn code(self) -> i32 {
        self as i32
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCfgLlvmSourceOperation {
    /// Ghidra P-code operation source address, which may differ from its
    /// containing instruction for delay-slot or override cases.
    pub address: PcodeAddress,
    pub instruction_address: PcodeAddress,
    pub instruction_index: usize,
    pub operation_index: usize,
    pub mnemonic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub userop_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCfgLlvmStopSite {
    pub address: PcodeAddress,
    pub operation_index: Option<usize>,
    pub status: PcodeCfgLlvmStatus,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCfgLlvmImageBinding {
    pub space: String,
    pub base: u64,
    pub byte_len: usize,
    pub known_byte_count: usize,
    /// Hash of the embedded bytes followed by their known-byte mask.
    pub contents_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeCfgLlvmProcessBinding {
    pub space: String,
    pub base: u64,
    pub byte_len: usize,
    pub known_byte_count: usize,
    pub mapped_byte_count: usize,
    pub writable_byte_count: usize,
    pub unresolved_relocation_bytes: usize,
    /// SHA-256 of initial bytes followed by known, mapped and writable masks.
    pub contents_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PcodeCfgLlvmArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub start: PcodeAddress,
    pub source_operations: Vec<PcodeCfgLlvmSourceOperation>,
    pub stop_sites: Vec<PcodeCfgLlvmStopSite>,
    pub state_bytes: usize,
    pub guest_ram_limit_bytes: u64,
    pub byte_map: Vec<PcodeStateByte>,
    pub state_abi: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only_image: Option<PcodeCfgLlvmImageBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_memory: Option<PcodeCfgLlvmProcessBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allocations: Option<PcodeProcessAllocations>,
    pub llvm_ir: String,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

/// The transformed IR and its LLVM path module are emitted together so the
/// source operation, local proof, and unverified machine claim stay visible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeSimplifiedCfgLlvmArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub simplification: PcodeSimplificationArtifact,
    pub llvm: PcodeCfgLlvmArtifact,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeInterproceduralCfgLlvmArtifact {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_entries: Vec<PcodeAddress>,
    pub snapshot_sha256: Vec<String>,
    /// Export failures from demand-driven collection; a missing callee stays
    /// an explicit stop in the LLVM module.
    pub snapshot_diagnostics: Vec<String>,
    pub max_call_depth: usize,
    pub llvm: PcodeCfgLlvmArtifact,
    pub semantic_fidelity: SemanticFidelity,
    pub verification: VerificationStatus,
}

struct CallLlvmContext<'a> {
    snapshots: &'a [GhidraSnapshot],
    owners: Vec<usize>,
    max_call_depth: usize,
    process: Option<&'a PcodeElfProcessMemory>,
}

fn internal_process_call_target(
    snapshot: &GhidraSnapshot,
    process: &PcodeElfProcessMemory,
    space: &str,
    address: u64,
) -> bool {
    process.is_mapped(space, address)
        && process.initial_byte(space, address).is_some()
        && snapshot.memory_blocks.iter().any(|block| {
            block.start.space == space
                && block.loaded
                && block.execute
                && !block.overlay
                && (block.name == ".text" || block.name.starts_with(".text."))
                && offset(&block.start.offset).is_ok_and(|start| start <= address)
                && offset(&block.end.offset).is_ok_and(|end| address <= end)
        })
}

fn offset(value: &str) -> Result<u64, String> {
    u64::from_str_radix(value.strip_prefix("0x").ok_or("missing 0x offset")?, 16)
        .map_err(|_| "invalid hexadecimal offset".to_owned())
}

fn relative_target(node: &PcodeVarnode, current: usize, count: usize) -> Result<usize, String> {
    if node.space != "const" || !(1..=8).contains(&node.size) {
        return Err("relative branch requires a 1..=8 byte constant".into());
    }
    let raw = offset(&node.offset)?;
    let shift = 64 - node.size * 8;
    if raw > (u64::MAX >> shift) {
        return Err("relative branch offset exceeds declared width".into());
    }
    let delta = ((raw << shift) as i64) >> shift;
    let target = (current as i64)
        .checked_add(delta)
        .ok_or("relative branch operation index overflows")?;
    if target < 0 || target as usize >= count {
        return Err("relative branch leaves its instruction".into());
    }
    Ok(target as usize)
}

fn target_label(
    target: &PcodeVarnode,
    instruction: usize,
    operation: usize,
    operation_count: usize,
    index: &BTreeMap<(String, u64), usize>,
) -> Result<String, (PcodeCfgLlvmStatus, String)> {
    if target.space == "const" {
        return relative_target(target, operation, operation_count)
            .map(|next| format!("op_{instruction}_{next}"))
            .map_err(|reason| (PcodeCfgLlvmStatus::MalformedTarget, reason));
    }
    let address =
        offset(&target.offset).map_err(|reason| (PcodeCfgLlvmStatus::MalformedTarget, reason))?;
    index
        .get(&(target.space.clone(), address))
        .map(|next| format!("ins_{next}"))
        .ok_or((
            PcodeCfgLlvmStatus::OutOfFunction,
            "direct branch target is outside selected instructions".into(),
        ))
}

fn stop_site(
    sites: &mut Vec<PcodeCfgLlvmStopSite>,
    address: &PcodeAddress,
    operation_index: Option<usize>,
    status: PcodeCfgLlvmStatus,
    reason: impl Into<String>,
) {
    sites.push(PcodeCfgLlvmStopSite {
        address: address.clone(),
        operation_index,
        status,
        reason: reason.into(),
    });
}

fn log_event(id: usize, count: &str, suffix: &str, destination: &str) -> String {
    format!(
        "  %slot_{id}_{suffix} = getelementptr i32, ptr %events, i32 {count}\n\
           store i32 {id}, ptr %slot_{id}_{suffix}\n\
           %next_{id}_{suffix} = add i32 {count}, 1\n\
           store i32 %next_{id}_{suffix}, ptr %event_count\n\
           br label %{destination}\n"
    )
}

fn stop_label(status: PcodeCfgLlvmStatus) -> &'static str {
    match status {
        PcodeCfgLlvmStatus::Return => "stop_return",
        PcodeCfgLlvmStatus::Call => "stop_call",
        PcodeCfgLlvmStatus::OpaqueEffect => "stop_opaque",
        PcodeCfgLlvmStatus::UnsupportedMemory => "stop_memory",
        PcodeCfgLlvmStatus::IndirectFlow => "stop_indirect",
        PcodeCfgLlvmStatus::UnresolvedFlow => "stop_unresolved",
        PcodeCfgLlvmStatus::AmbiguousFlow => "stop_ambiguous",
        PcodeCfgLlvmStatus::OutOfFunction => "stop_outside",
        PcodeCfgLlvmStatus::MalformedTarget => "stop_malformed",
        PcodeCfgLlvmStatus::UnknownInput => "stop_unknown",
        PcodeCfgLlvmStatus::StepBudget => "stop_budget",
        PcodeCfgLlvmStatus::InvalidArguments => "stop_invalid_args",
        PcodeCfgLlvmStatus::VisitBudget => "stop_visit_budget",
        PcodeCfgLlvmStatus::InvalidOperation => "stop_invalid_op",
        PcodeCfgLlvmStatus::MemoryUnknownAlias => "stop_memory_alias",
        PcodeCfgLlvmStatus::MemoryUnknownBytes => "stop_memory_bytes",
        PcodeCfgLlvmStatus::MemoryOutOfBounds => "stop_memory_bounds",
        PcodeCfgLlvmStatus::MemoryAddressOverflow => "stop_memory_overflow",
        PcodeCfgLlvmStatus::MemorySpaceMismatch => "stop_memory_space",
        PcodeCfgLlvmStatus::MemoryUnsupportedLayout => "stop_memory_layout",
        PcodeCfgLlvmStatus::MemoryNonRamSpace => "stop_memory_nonram",
        PcodeCfgLlvmStatus::MemoryUnknownSpace => "stop_memory_unknown_space",
        PcodeCfgLlvmStatus::CallDepth => "stop_call_depth",
        PcodeCfgLlvmStatus::ReturnMismatch => "stop_return_mismatch",
        PcodeCfgLlvmStatus::RecursiveCall => "stop_recursive_call",
        PcodeCfgLlvmStatus::MemoryReadOnly => "stop_memory_read_only",
        PcodeCfgLlvmStatus::MemoryUnmappedWrite => "stop_memory_unmapped_write",
    }
}

fn branch_to_stop(status: PcodeCfgLlvmStatus) -> String {
    format!("  br label %{}\n", stop_label(status))
}

fn known_check(
    node: &PcodeVarnode,
    stem: &str,
    body: &mut String,
) -> Result<Option<String>, String> {
    if node.space == "const" {
        return Ok(None);
    }
    let id = pcode_space_id(&node.space)?;
    let byte_offset = pcode_offset(node)?;
    let (bits, helper, mask) = if node.size > 8 {
        let mask = if node.size == 16 {
            u128::MAX
        } else {
            (1u128 << (node.size * 8)) - 1
        };
        (128, "hydir_read_varnode_wide", mask)
    } else if node.size == 8 {
        (64, "hydir_read_varnode", u128::from(u64::MAX))
    } else {
        (64, "hydir_read_varnode", (1u128 << (node.size * 8)) - 1)
    };
    body.push_str(&format!(
        "  %{stem}_mask = call i{bits} @{helper}(ptr %known, i32 {id}, i64 {byte_offset}, i32 {})\n\
           %{stem}_ok = icmp eq i{bits} %{stem}_mask, {mask}\n",
        node.size
    ));
    Ok(Some(format!("%{stem}_ok")))
}

fn emit_known_guard(
    checks: &[String],
    stem: &str,
    body: &mut String,
    next: &str,
    missing_status: PcodeCfgLlvmStatus,
) {
    if checks.is_empty() {
        body.push_str(&format!("  br label %{next}\n"));
        return;
    }
    let mut combined = checks[0].clone();
    for (index, check) in checks.iter().enumerate().skip(1) {
        let name = format!("%{stem}_all_{index}");
        body.push_str(&format!("  {name} = and i1 {combined}, {check}\n"));
        combined = name;
    }
    body.push_str(&format!(
        "  br i1 {combined}, label %{next}, label %{}\n",
        stop_label(missing_status)
    ));
}

#[allow(clippy::too_many_arguments)]
fn emit_interprocedural_call(
    context: &CallLlvmContext<'_>,
    source: &PcodeOperation,
    site: &PcodeAddress,
    instruction_index: usize,
    operation_index: usize,
    id: usize,
    index: &BTreeMap<(String, u64), usize>,
    caller_index: &BTreeMap<(String, u64), usize>,
    body: &mut String,
    sites: &mut Vec<PcodeCfgLlvmStopSite>,
) -> Result<(), String> {
    let owner = context.owners[instruction_index];
    let snapshot = &context.snapshots[owner];
    let indirect = source.opcode == 8;
    let pointer = source.inputs.first();
    let target_space = if indirect {
        site.space.as_str()
    } else {
        pointer.map(|node| node.space.as_str()).unwrap_or("")
    };
    let pointer_size = snapshot
        .address_spaces
        .iter()
        .find(|space| space.name == target_space)
        .map(|space| space.pointer_size);
    if source.mnemonic != if indirect { "CALLIND" } else { "CALL" }
        || source.output.is_some()
        || source.inputs.len() != 1
        || pointer_size.is_none_or(|size| size == 0 || size > 8)
        || pointer.is_none_or(|node| Some(node.size) != pointer_size)
        || indirect
            && !matches!(
                pointer.map(|node| node.space.as_str()),
                Some("register" | "unique" | "const")
            )
    {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::MalformedTarget,
            "invalid CALL target shape, space, or width",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
        return Ok(());
    }
    let pointer = pointer.expect("checked above");
    let site_key = (site.space.clone(), offset(&site.offset)?);
    let evidence = snapshot
        .selected_function
        .call_targets
        .iter()
        .filter(|call| {
            (
                call.call_site.space.clone(),
                offset(&call.call_site.offset).ok(),
            ) == (site_key.0.clone(), Some(site_key.1))
        })
        .collect::<Vec<_>>();
    let continuation = snapshot
        .selected_function
        .flow_edges
        .iter()
        .filter(|edge| {
            edge.kind == GhidraFlowKind::Fallthrough
                && (edge.source.space.clone(), offset(&edge.source.offset).ok())
                    == (site_key.0.clone(), Some(site_key.1))
        })
        .collect::<Vec<_>>();
    let Some(continuation) = (continuation.len() == 1)
        .then(|| continuation[0].target.as_ref())
        .flatten()
    else {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            "CALL has no unique analyzed fallthrough",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::Call));
        return Ok(());
    };
    let continuation_key = (continuation.space.clone(), offset(&continuation.offset)?);
    let continuation_width = snapshot
        .address_spaces
        .iter()
        .find(|space| space.name == continuation.space)
        .map(|space| space.pointer_size)
        .ok_or("CALL continuation has an unknown address space")?;
    let Some(&return_index) = caller_index.get(&continuation_key) else {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            "CALL fallthrough is outside caller",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::Call));
        return Ok(());
    };
    let valid_evidence =
        evidence.len() == 1 && !evidence[0].conditional && evidence[0].computed == indirect;
    if !valid_evidence {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            "CALL target disagrees with Ghidra call evidence",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::Call));
        return Ok(());
    }
    let evidence_target = evidence[0].target.as_ref().map(|target| {
        (
            target.space.clone(),
            offset(&target.offset).unwrap_or(u64::MAX),
        )
    });
    let target_key = if indirect {
        None
    } else {
        Some((pointer.space.clone(), offset(&pointer.offset)?))
    };
    if !indirect && evidence_target != target_key {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            "CALL target disagrees with Ghidra call evidence",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::Call));
        return Ok(());
    }
    if let (Some(process), Some((space, address))) = (context.process, target_key.as_ref())
        && !internal_process_call_target(snapshot, process, space, *address)
    {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            "CALL target is not a loaded internal executable ELF function",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::Call));
        return Ok(());
    }
    let routes = context
        .snapshots
        .iter()
        .filter_map(|callee| {
            let entry = &callee.selected_function.entry;
            let key = (entry.space.clone(), offset(&entry.offset).ok()?);
            if key.0 != target_space
                || target_key.as_ref().is_some_and(|target| target != &key)
                || evidence_target
                    .as_ref()
                    .is_some_and(|target| target != &key)
                || context.process.is_some_and(|process| {
                    !internal_process_call_target(snapshot, process, &key.0, key.1)
                })
            {
                return None;
            }
            index.get(&key).map(|instruction| (key.1, *instruction))
        })
        .collect::<Vec<_>>();
    stop_site(
        sites,
        &source.source_address,
        Some(operation_index),
        PcodeCfgLlvmStatus::CallDepth,
        "call depth budget exhausted",
    );
    stop_site(
        sites,
        &source.source_address,
        Some(operation_index),
        PcodeCfgLlvmStatus::RecursiveCall,
        "recursive call requires a separate bounded model",
    );
    let target_value =
        if indirect {
            stop_site(
                sites,
                &source.source_address,
                Some(operation_index),
                PcodeCfgLlvmStatus::UnknownInput,
                "CALLIND target bytes are unknown",
            );
            let check = known_check(pointer, &format!("call_{id}"), body)?;
            emit_known_guard(
                &check.into_iter().collect::<Vec<_>>(),
                &format!("call_{id}"),
                body,
                &format!("call_known_{id}"),
                PcodeCfgLlvmStatus::UnknownInput,
            );
            body.push_str(&format!("call_known_{id}:\n"));
            let value =
                if pointer.space == "const" {
                    format!("{}", offset(&pointer.offset)?)
                } else {
                    let name = format!("%call_value_{id}");
                    body.push_str(&format!(
                "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
                pcode_space_id(&pointer.space)?, pcode_offset(pointer)?, pointer.size));
                    name
                };
            Some(value)
        } else {
            None
        };
    body.push_str(&format!(
        "  %depth_{id} = load i32, ptr %call_depth\n  %depth_full_{id} = icmp uge i32 %depth_{id}, {}\n  br i1 %depth_full_{id}, label %{}, label %call_target_{id}\ncall_target_{id}:\n",
        context.max_call_depth, stop_label(PcodeCfgLlvmStatus::CallDepth)
    ));
    if let Some(value) = target_value {
        body.push_str(&format!(
            "  switch i64 {value}, label %{} [\n",
            stop_label(PcodeCfgLlvmStatus::Call)
        ));
        for (target, callee_index) in &routes {
            body.push_str(&format!(
                "    i64 {target}, label %call_route_{id}_{callee_index}\n"
            ));
        }
        body.push_str("  ]\n");
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            if context.process.is_some() {
                "CALLIND target is not a loaded, evidenced internal ELF callee"
            } else {
                "CALLIND target is not a loaded, evidenced callee"
            },
        );
    } else if let Some((_, callee)) = routes.first() {
        body.push_str(&format!("  br label %call_route_{id}_{callee}\n"));
    } else {
        stop_site(
            sites,
            &source.source_address,
            Some(operation_index),
            PcodeCfgLlvmStatus::Call,
            if context.process.is_some() {
                "CALL target is not a loaded internal executable ELF function"
            } else {
                "CALL callee snapshot is unavailable"
            },
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::Call));
    }
    for (_, callee_index) in routes {
        let callee_owner = context.owners[callee_index];
        body.push_str(&format!(
            "call_route_{id}_{callee_index}:\n  %active_ptr_{id}_{callee_index} = getelementptr [128 x i8], ptr %active_functions, i32 0, i32 {callee_owner}\n  %active_value_{id}_{callee_index} = load i8, ptr %active_ptr_{id}_{callee_index}\n  %recursive_{id}_{callee_index} = icmp ne i8 %active_value_{id}_{callee_index}, 0\n  br i1 %recursive_{id}_{callee_index}, label %{}, label %call_enter_{id}_{callee_index}\ncall_enter_{id}_{callee_index}:\n  store i8 1, ptr %active_ptr_{id}_{callee_index}\n  %return_slot_{id}_{callee_index} = getelementptr [16 x i32], ptr %return_sites, i32 0, i32 %depth_{id}\n  store i32 {return_index}, ptr %return_slot_{id}_{callee_index}\n  %address_slot_{id}_{callee_index} = getelementptr [16 x i64], ptr %return_addresses, i32 0, i32 %depth_{id}\n  store i64 {}, ptr %address_slot_{id}_{callee_index}\n  %width_slot_{id}_{callee_index} = getelementptr [16 x i32], ptr %return_widths, i32 0, i32 %depth_{id}\n  store i32 {continuation_width}, ptr %width_slot_{id}_{callee_index}\n  %depth_next_{id}_{callee_index} = add i32 %depth_{id}, 1\n  store i32 %depth_next_{id}_{callee_index}, ptr %call_depth\n",
            stop_label(PcodeCfgLlvmStatus::RecursiveCall), continuation_key.1
        ));
        body.push_str(&log_event(
            id,
            &format!("%count_{id}"),
            &format!("call_{callee_index}"),
            &format!("ins_{callee_index}"),
        ));
    }
    Ok(())
}

fn emit_interprocedural_return(
    source: &PcodeOperation,
    id: usize,
    owner: usize,
    return_sites: &BTreeSet<usize>,
    body: &mut String,
    sites: &mut Vec<PcodeCfgLlvmStopSite>,
) -> Result<(), String> {
    let pointer = source.inputs.first();
    if source.mnemonic != "RETURN"
        || source.output.is_some()
        || source.inputs.len() != 1
        || pointer.is_none_or(|node| {
            !(1..=8).contains(&node.size)
                || !matches!(node.space.as_str(), "register" | "unique" | "const")
        })
    {
        stop_site(
            sites,
            &source.source_address,
            Some(source.sequence_index as usize),
            PcodeCfgLlvmStatus::MalformedTarget,
            "invalid RETURN target shape",
        );
        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
        return Ok(());
    }
    let pointer = pointer.expect("checked above");
    stop_site(
        sites,
        &source.source_address,
        Some(source.sequence_index as usize),
        PcodeCfgLlvmStatus::UnknownInput,
        "RETURN target bytes are unknown",
    );
    stop_site(
        sites,
        &source.source_address,
        Some(source.sequence_index as usize),
        PcodeCfgLlvmStatus::ReturnMismatch,
        "callee RETURN target differs from caller continuation",
    );
    body.push_str(&format!(
        "  %return_depth_{id} = load i32, ptr %call_depth\n  %return_root_{id} = icmp eq i32 %return_depth_{id}, 0\n  br i1 %return_root_{id}, label %{}, label %return_nested_{id}\nreturn_nested_{id}:\n  %return_prev_{id} = sub i32 %return_depth_{id}, 1\n",
        stop_label(PcodeCfgLlvmStatus::Return)
    ));
    let check = known_check(pointer, &format!("return_{id}"), body)?;
    emit_known_guard(
        &check.into_iter().collect::<Vec<_>>(),
        &format!("return_{id}"),
        body,
        &format!("return_known_{id}"),
        PcodeCfgLlvmStatus::UnknownInput,
    );
    body.push_str(&format!("return_known_{id}:\n  %return_width_slot_{id} = getelementptr [16 x i32], ptr %return_widths, i32 0, i32 %return_prev_{id}\n  %return_width_{id} = load i32, ptr %return_width_slot_{id}\n  %return_width_ok_{id} = icmp eq i32 %return_width_{id}, {}\n  br i1 %return_width_ok_{id}, label %return_value_ready_{id}, label %{}\nreturn_value_ready_{id}:\n", pointer.size, stop_label(PcodeCfgLlvmStatus::ReturnMismatch)));
    let value = if pointer.space == "const" {
        format!("{}", offset(&pointer.offset)?)
    } else {
        let name = format!("%return_value_{id}");
        body.push_str(&format!(
            "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
            pcode_space_id(&pointer.space)?,
            pcode_offset(pointer)?,
            pointer.size
        ));
        name
    };
    body.push_str(&format!(
        "  %return_address_slot_{id} = getelementptr [16 x i64], ptr %return_addresses, i32 0, i32 %return_prev_{id}\n  %return_expected_{id} = load i64, ptr %return_address_slot_{id}\n  %return_matches_{id} = icmp eq i64 {value}, %return_expected_{id}\n  br i1 %return_matches_{id}, label %return_dispatch_{id}, label %{}\nreturn_dispatch_{id}:\n  store i32 %return_prev_{id}, ptr %call_depth\n  %returned_active_{id} = getelementptr [128 x i8], ptr %active_functions, i32 0, i32 {owner}\n  store i8 0, ptr %returned_active_{id}\n  %return_site_slot_{id} = getelementptr [16 x i32], ptr %return_sites, i32 0, i32 %return_prev_{id}\n  %return_site_{id} = load i32, ptr %return_site_slot_{id}\n  switch i32 %return_site_{id}, label %{} [\n",
        stop_label(PcodeCfgLlvmStatus::ReturnMismatch),
        stop_label(PcodeCfgLlvmStatus::ReturnMismatch)
    ));
    for instruction in return_sites {
        body.push_str(&format!(
            "    i32 {instruction}, label %return_route_{id}_{instruction}\n"
        ));
    }
    body.push_str("  ]\n");
    for instruction in return_sites {
        body.push_str(&format!("return_route_{id}_{instruction}:\n"));
        body.push_str(&log_event(
            id,
            &format!("%count_{id}"),
            &format!("return_{instruction}"),
            &format!("ins_{instruction}"),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemoryKind {
    Load,
    Store,
}

struct MemoryLayout<'a> {
    kind: MemoryKind,
    space: &'a GhidraAddressSpace,
    pointer: Cow<'a, PcodeVarnode>,
    value: &'a PcodeVarnode,
    width: u32,
}

fn memory_layout<'a>(
    source: &'a PcodeOperation,
    spaces: &'a [GhidraAddressSpace],
) -> Result<MemoryLayout<'a>, (PcodeCfgLlvmStatus, String)> {
    let invalid = |reason: &str| {
        (
            PcodeCfgLlvmStatus::MemoryUnsupportedLayout,
            reason.to_owned(),
        )
    };
    let kind = match (source.opcode, source.mnemonic.as_str()) {
        (2, "LOAD") if source.inputs.len() == 2 && source.output.is_some() => MemoryKind::Load,
        (3, "STORE") if source.inputs.len() == 3 && source.output.is_none() => MemoryKind::Store,
        _ => {
            return Err(invalid(
                "LOAD/STORE opcode, mnemonic, arity or output is invalid",
            ));
        }
    };
    let id_node = &source.inputs[0];
    if id_node.space != "const" || !(1..=8).contains(&id_node.size) {
        return Err(invalid("memory space ID must be a 1..=8 byte constant"));
    }
    let id = offset(&id_node.offset).map_err(|reason| invalid(&reason))?;
    let mask = if id_node.size == 8 {
        u64::MAX
    } else {
        (1u64 << (id_node.size * 8)) - 1
    };
    if id > mask {
        return Err(invalid("memory space ID exceeds its varnode width"));
    }
    let space = spaces
        .iter()
        .find(|space| u64::try_from(space.id).ok() == Some(id))
        .ok_or((
            PcodeCfgLlvmStatus::MemoryUnknownSpace,
            format!("no Ghidra address space has ID {id}"),
        ))?;
    if space.space_type != 1 || matches!(space.name.as_str(), "const" | "register" | "unique") {
        return Err((
            PcodeCfgLlvmStatus::MemoryNonRamSpace,
            format!("{} is not a Ghidra RAM space", space.name),
        ));
    }
    let pointer = &source.inputs[1];
    if !(1..=8).contains(&space.pointer_size)
        || pointer.size != space.pointer_size
        || !matches!(pointer.space.as_str(), "register" | "unique" | "const")
    {
        return Err(invalid(
            "pointer varnode differs from RAM space pointer width",
        ));
    }
    let value = match kind {
        MemoryKind::Load => source.output.as_ref().expect("LOAD output checked above"),
        MemoryKind::Store => &source.inputs[2],
    };
    if !matches!(value.space.as_str(), "register" | "unique" | "const")
        || kind == MemoryKind::Load && value.space == "const"
        || !(1..=8).contains(&value.size)
        || space.addressable_unit_size == 0
    {
        return Err(invalid("memory value width or state space is unsupported"));
    }
    Ok(MemoryLayout {
        kind,
        space,
        pointer: Cow::Borrowed(pointer),
        value,
        width: value.size,
    })
}

fn direct_ram_copy_layout<'a>(
    source: &'a PcodeOperation,
    spaces: &'a [GhidraAddressSpace],
) -> Result<MemoryLayout<'a>, (PcodeCfgLlvmStatus, String)> {
    let invalid = |reason: &str| {
        (
            PcodeCfgLlvmStatus::MemoryUnsupportedLayout,
            reason.to_owned(),
        )
    };
    let (Some(input), Some(output)) = (source.inputs.first(), source.output.as_ref()) else {
        return Err(invalid("direct RAM COPY requires one input and an output"));
    };
    if source.opcode != 1
        || source.mnemonic != "COPY"
        || source.inputs.len() != 1
        || input.size != output.size
        || !(1..=16).contains(&input.size)
        || !matches!(output.space.as_str(), "register" | "unique")
    {
        return Err(invalid(
            "direct RAM COPY width, arity or output storage is unsupported",
        ));
    }
    let space = spaces
        .iter()
        .find(|space| space.name == input.space)
        .ok_or((
            PcodeCfgLlvmStatus::MemoryUnknownSpace,
            "direct COPY source address space is absent".to_owned(),
        ))?;
    if space.space_type != 1 || space.pointer_size != 8 || space.addressable_unit_size == 0 {
        return Err((
            PcodeCfgLlvmStatus::MemoryNonRamSpace,
            "direct COPY requires a 64-bit RAM address space with a known addressable unit"
                .to_owned(),
        ));
    }
    offset(&input.offset).map_err(|reason| invalid(&reason))?;
    Ok(MemoryLayout {
        kind: MemoryKind::Load,
        space,
        pointer: Cow::Owned(PcodeVarnode {
            space: "const".to_owned(),
            offset: input.offset.clone(),
            size: space.pointer_size,
        }),
        value: output,
        width: input.size,
    })
}

fn validate_image_window(
    snapshot: &GhidraSnapshot,
    image: &PcodeReadOnlyElfWindow,
) -> Result<PcodeCfgLlvmImageBinding, String> {
    image.validate_for_snapshot(snapshot)?;
    let space = snapshot
        .address_spaces
        .iter()
        .find(|space| space.name == image.space() && space.space_type == 1)
        .ok_or("read-only ELF image space is not a Ghidra RAM space")?;
    if space.id < 0 {
        return Err("read-only ELF image space ID is negative".into());
    }
    let len = image.bytes().len();
    if len == 0 || len > PCODE_CFG_ELF_IMAGE_MAX_BYTES || image.known().len() != len {
        return Err(format!(
            "read-only ELF image requires equally sized, nonempty bytes and known mask within {} bytes",
            PCODE_CFG_ELF_IMAGE_MAX_BYTES
        ));
    }
    image
        .base()
        .checked_add(len as u64 - 1)
        .ok_or("read-only ELF image address range overflows u64")?;
    if image.known().iter().any(|byte| *byte != 0 && *byte != 0xff) {
        return Err("read-only ELF image known mask contains a partial byte".into());
    }
    let known_byte_count = image.known().iter().filter(|byte| **byte == 0xff).count();
    if known_byte_count == 0 {
        return Err("read-only ELF image has no known bytes".into());
    }
    let mut digest = Sha256::new();
    digest.update(image.bytes());
    digest.update(image.known());
    Ok(PcodeCfgLlvmImageBinding {
        space: image.space().to_owned(),
        base: image.base(),
        byte_len: len,
        known_byte_count,
        contents_sha256: format!("{:x}", digest.finalize()),
    })
}

fn validate_process_memory(
    snapshot: &GhidraSnapshot,
    process: &PcodeElfProcessMemory,
) -> Result<PcodeCfgLlvmProcessBinding, String> {
    process.validate_for_snapshot(snapshot)?;
    let space = snapshot
        .address_spaces
        .iter()
        .find(|space| space.name == process.space() && space.space_type == 1)
        .ok_or("ELF process memory space is not a Ghidra RAM space")?;
    if space.id < 0 {
        return Err("ELF process memory space ID is negative".into());
    }
    let len = process.bytes().len();
    process
        .base()
        .checked_add(len as u64 - 1)
        .ok_or("ELF process memory address range overflows u64")?;
    let mut digest = Sha256::new();
    digest.update(process.bytes());
    digest.update(process.known());
    digest.update(process.mapped());
    digest.update(process.writable());
    Ok(PcodeCfgLlvmProcessBinding {
        space: process.space().to_owned(),
        base: process.base(),
        byte_len: len,
        known_byte_count: process.known().iter().filter(|byte| **byte == 0xff).count(),
        mapped_byte_count: process
            .mapped()
            .iter()
            .filter(|byte| **byte == 0xff)
            .count(),
        writable_byte_count: process
            .writable()
            .iter()
            .filter(|byte| **byte == 0xff)
            .count(),
        unresolved_relocation_bytes: process.unresolved_relocation_bytes(),
        contents_sha256: format!("{:x}", digest.finalize()),
    })
}

fn encode_llvm_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut literal = String::with_capacity(bytes.len() * 3);
    for byte in bytes {
        write!(&mut literal, "\\{byte:02X}").expect("writing to String does not fail");
    }
    literal
}

fn image_globals(image: &PcodeReadOnlyElfWindow) -> String {
    format!(
        "@hydir_elf_image_bytes = private constant [{} x i8] c\"{}\"\n@hydir_elf_image_known = private constant [{} x i8] c\"{}\"\n\n",
        image.bytes().len(),
        encode_llvm_bytes(image.bytes()),
        image.known().len(),
        encode_llvm_bytes(image.known()),
    )
}

fn process_globals(process: &PcodeElfProcessMemory) -> String {
    let len = process.bytes().len();
    format!(
        "@hydir_process_initial_bytes = private constant [{len} x i8] c\"{}\"\n\
         @hydir_process_initial_known = private constant [{len} x i8] c\"{}\"\n\
         @hydir_process_mapped = private constant [{len} x i8] c\"{}\"\n\
         @hydir_process_writable = private constant [{len} x i8] c\"{}\"\n\n",
        encode_llvm_bytes(process.bytes()),
        encode_llvm_bytes(process.known()),
        encode_llvm_bytes(process.mapped()),
        encode_llvm_bytes(process.writable()),
    )
}

fn emit_process_memory_value(
    layout: &MemoryLayout<'_>,
    id: usize,
    body: &mut String,
    next_label: &str,
    process: &PcodeElfProcessMemory,
    strict_allocations: bool,
) -> Result<(), String> {
    let len = process.bytes().len();
    let load_bits = if layout.width > 8 { 128 } else { 64 };
    let load_writer = if layout.width > 8 {
        "hydir_write_varnode_wide"
    } else {
        "hydir_write_varnode"
    };
    body.push_str(&format!("process_memory_value_{id}:\n"));
    let mut mapped_checks = Vec::new();
    let mut read_only_checks = Vec::new();
    let mut known_checks = Vec::new();
    for byte in 0..layout.width {
        body.push_str(&format!(
            "  %process_index_{id}_{byte} = add i64 %process_relative_{id}, {byte}\n\
             %process_map_ptr_{id}_{byte} = getelementptr [{len} x i8], ptr @hydir_process_mapped, i64 0, i64 %process_index_{id}_{byte}\n\
             %process_map_byte_{id}_{byte} = load i8, ptr %process_map_ptr_{id}_{byte}\n\
             %process_map_ok_{id}_{byte} = icmp eq i8 %process_map_byte_{id}_{byte}, -1\n\
             %process_known_ptr_{id}_{byte} = getelementptr i8, ptr %process_known, i64 %process_index_{id}_{byte}\n"
        ));
        mapped_checks.push(format!("%process_map_ok_{id}_{byte}"));
        if layout.kind == MemoryKind::Store {
            body.push_str(&format!(
                "  %process_write_ptr_{id}_{byte} = getelementptr [{len} x i8], ptr @hydir_process_writable, i64 0, i64 %process_index_{id}_{byte}\n\
                 %process_write_byte_{id}_{byte} = load i8, ptr %process_write_ptr_{id}_{byte}\n\
                 %process_write_denied_{id}_{byte} = icmp eq i8 %process_write_byte_{id}_{byte}, 0\n\
                 %process_read_only_{id}_{byte} = and i1 %process_map_ok_{id}_{byte}, %process_write_denied_{id}_{byte}\n"
            ));
            read_only_checks.push(format!("%process_read_only_{id}_{byte}"));
        } else {
            body.push_str(&format!(
                "  %process_known_byte_{id}_{byte} = load i8, ptr %process_known_ptr_{id}_{byte}\n\
                 %process_known_ok_{id}_{byte} = icmp eq i8 %process_known_byte_{id}_{byte}, -1\n"
            ));
            known_checks.push(format!("%process_known_ok_{id}_{byte}"));
        }
    }
    if layout.kind == MemoryKind::Store {
        let mut any_read_only = read_only_checks[0].clone();
        for (byte, check) in read_only_checks.iter().enumerate().skip(1) {
            let name = format!("%process_any_read_only_{id}_{byte}");
            body.push_str(&format!("  {name} = or i1 {any_read_only}, {check}\n"));
            any_read_only = name;
        }
        body.push_str(&format!(
            "  br i1 {any_read_only}, label %stop_memory_read_only, label %process_read_only_clear_{id}\n\
             process_read_only_clear_{id}:\n"
        ));
    }
    emit_known_guard(
        &mapped_checks,
        &format!("process_mapped_{id}"),
        body,
        &format!("process_mapped_ready_{id}"),
        if strict_allocations && layout.kind == MemoryKind::Store {
            PcodeCfgLlvmStatus::MemoryUnmappedWrite
        } else {
            PcodeCfgLlvmStatus::MemoryUnknownBytes
        },
    );
    body.push_str(&format!("process_mapped_ready_{id}:\n"));
    if layout.kind == MemoryKind::Store {
        let data = layout.value;
        if let Some(check) = known_check(data, &format!("process_store_data_{id}"), body)? {
            body.push_str(&format!(
                "  br i1 {check}, label %process_store_{id}, label %stop_unknown\n"
            ));
        } else {
            body.push_str(&format!("  br label %process_store_{id}\n"));
        }
        body.push_str(&format!("process_store_{id}:\n"));
        let value = if data.space == "const" {
            let bits = data.size * 8;
            let mask = if bits == 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            format!("{}", offset(&data.offset)? & mask)
        } else {
            body.push_str(&format!(
                "  %process_store_value_{id} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
                pcode_space_id(&data.space)?, pcode_offset(data)?, data.size
            ));
            format!("%process_store_value_{id}")
        };
        for byte in 0..layout.width {
            body.push_str(&format!(
                "  %process_shifted_{id}_{byte} = lshr i64 {value}, {}\n\
                 %process_store_byte_{id}_{byte} = trunc i64 %process_shifted_{id}_{byte} to i8\n\
                 %process_byte_ptr_{id}_{byte} = getelementptr i8, ptr %process_bytes, i64 %process_index_{id}_{byte}\n\
                 store i8 %process_store_byte_{id}_{byte}, ptr %process_byte_ptr_{id}_{byte}\n\
                 store i8 -1, ptr %process_known_ptr_{id}_{byte}\n",
                byte * 8
            ));
        }
    } else {
        emit_known_guard(
            &known_checks,
            &format!("process_known_{id}"),
            body,
            &format!("process_load_{id}"),
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
        );
        body.push_str(&format!("process_load_{id}:\n"));
        let mut previous = None::<String>;
        for byte in 0..layout.width {
            body.push_str(&format!(
                "  %process_byte_ptr_{id}_{byte} = getelementptr i8, ptr %process_bytes, i64 %process_index_{id}_{byte}\n\
                 %process_byte_{id}_{byte} = load i8, ptr %process_byte_ptr_{id}_{byte}\n\
                 %process_wide_{id}_{byte} = zext i8 %process_byte_{id}_{byte} to i{load_bits}\n\
                 %process_part_{id}_{byte} = shl i{load_bits} %process_wide_{id}_{byte}, {}\n",
                byte * 8
            ));
            let part = format!("%process_part_{id}_{byte}");
            previous = Some(if let Some(previous) = previous {
                let name = format!("%process_acc_{id}_{byte}");
                body.push_str(&format!("  {name} = or i{load_bits} {previous}, {part}\n"));
                name
            } else {
                part
            });
        }
        let result = previous.expect("memory width checked nonzero");
        let output_space = pcode_space_id(&layout.value.space)?;
        let output_offset = pcode_offset(layout.value)?;
        body.push_str(&format!(
            "  call void @{load_writer}(ptr %state, i32 {output_space}, i64 {output_offset}, i32 {}, i{load_bits} {result})\n\
             call void @{load_writer}(ptr %known, i32 {output_space}, i64 {output_offset}, i32 {}, i{load_bits} -1)\n",
            layout.width, layout.width
        ));
    }
    body.push_str(&log_event(
        id,
        &format!("%count_{id}"),
        "process_memory",
        next_label,
    ));
    Ok(())
}

fn emit_memory_operation(
    layout: &MemoryLayout<'_>,
    id: usize,
    body: &mut String,
    next_label: &str,
    image: Option<&PcodeReadOnlyElfWindow>,
    process: Option<&PcodeElfProcessMemory>,
    allocations: Option<&PcodeProcessAllocations>,
) -> Result<(), String> {
    let space_id = layout.space.id;
    let load_bits = if layout.width > 8 { 128 } else { 64 };
    let load_writer = if layout.width > 8 {
        "hydir_write_varnode_wide"
    } else {
        "hydir_write_varnode"
    };
    body.push_str(&format!(
        "  %space_match_{id} = icmp eq i32 %guest_space_id, {space_id}\n  br i1 %space_match_{id}, label %memory_pointer_{id}, label %stop_memory_space\nmemory_pointer_{id}:\n"
    ));
    if let Some(check) = known_check(layout.pointer.as_ref(), &format!("pointer_{id}"), body)? {
        body.push_str(&format!(
            "  br i1 {check}, label %memory_address_{id}, label %stop_memory_alias\n"
        ));
    } else {
        body.push_str(&format!("  br label %memory_address_{id}\n"));
    }
    body.push_str(&format!("memory_address_{id}:\n"));
    let pointer = if layout.pointer.space == "const" {
        let bits = layout.pointer.size * 8;
        let mask = if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        format!("{}", offset(&layout.pointer.offset)? & mask)
    } else {
        let name = format!("%pointer_value_{id}");
        body.push_str(&format!(
            "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
            pcode_space_id(&layout.pointer.space)?,
            pcode_offset(layout.pointer.as_ref())?,
            layout.pointer.size
        ));
        name
    };
    let unit = layout.space.addressable_unit_size;
    let last = layout.width - 1;
    body.push_str(&format!(
        "  %scaled_{id} = call {{ i64, i1 }} @llvm.umul.with.overflow.i64(i64 {pointer}, i64 {unit})\n  %byte_address_{id} = extractvalue {{ i64, i1 }} %scaled_{id}, 0\n  %scale_overflow_{id} = extractvalue {{ i64, i1 }} %scaled_{id}, 1\n  %last_{id} = call {{ i64, i1 }} @llvm.uadd.with.overflow.i64(i64 %byte_address_{id}, i64 {last})\n  %end_overflow_{id} = extractvalue {{ i64, i1 }} %last_{id}, 1\n  %address_overflow_{id} = or i1 %scale_overflow_{id}, %end_overflow_{id}\n  br i1 %address_overflow_{id}, label %stop_memory_overflow, label %memory_bounds_{id}\nmemory_bounds_{id}:\n  %below_base_{id} = icmp ult i64 %byte_address_{id}, %guest_base\n  %relative_{id} = sub i64 %byte_address_{id}, %guest_base\n  %enough_{id} = icmp uge i64 %guest_len, {}\n  %last_start_{id} = sub i64 %guest_len, {}\n  %inside_{id} = icmp ule i64 %relative_{id}, %last_start_{id}\n  %room_{id} = and i1 %enough_{id}, %inside_{id}\n  %not_below_{id} = xor i1 %below_base_{id}, true\n  %in_bounds_{id} = and i1 %room_{id}, %not_below_{id}\n",
        layout.width, layout.width
    ));
    // Rust checks every read-only byte before checking whether the complete
    // STORE is mapped. Do the same even when a write straddles the process
    // span boundary, without ever indexing the embedded masks out of range.
    if let Some(process) =
        process.filter(|_| allocations.is_some() && layout.kind == MemoryKind::Store)
    {
        let len = process.bytes().len();
        let mut any_read_only = String::new();
        for byte in 0..layout.width {
            body.push_str(&format!(
                "  %pre_addr_{id}_{byte} = add i64 %byte_address_{id}, {byte}\n\
                   %pre_ge_{id}_{byte} = icmp uge i64 %pre_addr_{id}_{byte}, {}\n\
                   %pre_relative_{id}_{byte} = sub i64 %pre_addr_{id}_{byte}, {}\n\
                   %pre_lt_{id}_{byte} = icmp ult i64 %pre_relative_{id}_{byte}, {len}\n\
                   %pre_in_{id}_{byte} = and i1 %pre_ge_{id}_{byte}, %pre_lt_{id}_{byte}\n\
                   %pre_safe_{id}_{byte} = select i1 %pre_in_{id}_{byte}, i64 %pre_relative_{id}_{byte}, i64 0\n\
                   %pre_map_ptr_{id}_{byte} = getelementptr [{len} x i8], ptr @hydir_process_mapped, i64 0, i64 %pre_safe_{id}_{byte}\n\
                   %pre_map_{id}_{byte} = load i8, ptr %pre_map_ptr_{id}_{byte}\n\
                   %pre_write_ptr_{id}_{byte} = getelementptr [{len} x i8], ptr @hydir_process_writable, i64 0, i64 %pre_safe_{id}_{byte}\n\
                   %pre_write_{id}_{byte} = load i8, ptr %pre_write_ptr_{id}_{byte}\n\
                   %pre_mapped_{id}_{byte} = icmp eq i8 %pre_map_{id}_{byte}, -1\n\
                   %pre_denied_{id}_{byte} = icmp eq i8 %pre_write_{id}_{byte}, 0\n\
                   %pre_readonly_map_{id}_{byte} = and i1 %pre_mapped_{id}_{byte}, %pre_denied_{id}_{byte}\n\
                   %pre_readonly_{id}_{byte} = and i1 %pre_in_{id}_{byte}, %pre_readonly_map_{id}_{byte}\n",
                process.base(), process.base()
            ));
            let check = format!("%pre_readonly_{id}_{byte}");
            if any_read_only.is_empty() {
                any_read_only = check;
            } else {
                let next = format!("%pre_any_readonly_{id}_{byte}");
                body.push_str(&format!("  {next} = or i1 {any_read_only}, {check}\n"));
                any_read_only = next;
            }
        }
        body.push_str(&format!(
            "  br i1 {any_read_only}, label %stop_memory_read_only, label %memory_route_{id}\nmemory_route_{id}:\n"
        ));
    }
    if let Some(process) =
        process.filter(|process| allocations.is_some() && process.space() == layout.space.name)
    {
        let len = process.bytes().len();
        let enough = len >= layout.width as usize;
        let last_start = len.saturating_sub(layout.width as usize);
        let outside = if layout.kind == MemoryKind::Store {
            stop_label(PcodeCfgLlvmStatus::MemoryUnmappedWrite)
        } else {
            stop_label(PcodeCfgLlvmStatus::MemoryUnknownBytes)
        };
        body.push_str(&format!(
            "  br i1 %in_bounds_{id}, label %memory_stack_value_{id}, label %memory_heap_bounds_{id}\n\
             memory_heap_bounds_{id}:\n  %heap_below_{id} = icmp ult i64 %byte_address_{id}, %heap_base\n\
               %heap_relative_{id} = sub i64 %byte_address_{id}, %heap_base\n\
               %heap_enough_{id} = icmp uge i64 %heap_len, {}\n\
               %heap_last_start_{id} = sub i64 %heap_len, {}\n\
               %heap_inside_{id} = icmp ule i64 %heap_relative_{id}, %heap_last_start_{id}\n\
               %heap_not_below_{id} = xor i1 %heap_below_{id}, true\n\
               %heap_candidate_{id} = and i1 %heap_inside_{id}, %heap_not_below_{id}\n\
               %heap_room_{id} = and i1 %heap_candidate_{id}, %heap_enough_{id}\n\
               br i1 %heap_room_{id}, label %memory_heap_value_{id}, label %memory_process_bounds_{id}\n\
             memory_process_bounds_{id}:\n  %process_below_{id} = icmp ult i64 %byte_address_{id}, {}\n\
               %process_relative_{id} = sub i64 %byte_address_{id}, {}\n\
               %process_inside_{id} = icmp ule i64 %process_relative_{id}, {last_start}\n\
               %process_not_below_{id} = xor i1 %process_below_{id}, true\n\
               %process_candidate_{id} = and i1 %process_inside_{id}, %process_not_below_{id}\n\
               %process_in_bounds_{id} = and i1 %process_candidate_{id}, {enough}\n\
               br i1 %process_in_bounds_{id}, label %process_memory_value_{id}, label %{outside}\n\
             memory_stack_value_{id}:\n  br label %memory_value_{id}\n\
             memory_heap_value_{id}:\n  br label %memory_value_{id}\n\
             memory_value_{id}:\n  %active_relative_{id} = phi i64 [ %relative_{id}, %memory_stack_value_{id} ], [ %heap_relative_{id}, %memory_heap_value_{id} ]\n\
               %active_ram_{id} = phi ptr [ %guest_ram, %memory_stack_value_{id} ], [ %heap_ram, %memory_heap_value_{id} ]\n\
               %active_known_{id} = phi ptr [ %guest_known, %memory_stack_value_{id} ], [ %heap_known, %memory_heap_value_{id} ]\n",
            layout.width, layout.width, process.base(), process.base()
        ));
    } else if let Some(image) = image.filter(|image| image.space() == layout.space.name) {
        let image_len = image.bytes().len();
        let enough = image_len >= layout.width as usize;
        let last_start = image_len.saturating_sub(layout.width as usize);
        body.push_str(&format!(
            "  br i1 %in_bounds_{id}, label %memory_value_{id}, label %memory_image_bounds_{id}\nmemory_image_bounds_{id}:\n  %image_below_{id} = icmp ult i64 %byte_address_{id}, {}\n  %image_relative_{id} = sub i64 %byte_address_{id}, {}\n  %image_inside_{id} = icmp ule i64 %image_relative_{id}, {last_start}\n  %image_not_below_{id} = xor i1 %image_below_{id}, true\n  %image_candidate_{id} = and i1 %image_inside_{id}, %image_not_below_{id}\n  %image_in_bounds_{id} = and i1 %image_candidate_{id}, {}\n  br i1 %image_in_bounds_{id}, label %memory_image_value_{id}, label %stop_memory_bounds\nmemory_value_{id}:\n",
            image.base(), image.base(), enough
        ));
    } else if let Some(process) = process.filter(|process| process.space() == layout.space.name) {
        let len = process.bytes().len();
        let enough = len >= layout.width as usize;
        let last_start = len.saturating_sub(layout.width as usize);
        body.push_str(&format!(
            "  br i1 %in_bounds_{id}, label %memory_value_{id}, label %memory_process_bounds_{id}\n\
             memory_process_bounds_{id}:\n  %process_below_{id} = icmp ult i64 %byte_address_{id}, {}\n\
               %process_relative_{id} = sub i64 %byte_address_{id}, {}\n\
               %process_inside_{id} = icmp ule i64 %process_relative_{id}, {last_start}\n\
               %process_not_below_{id} = xor i1 %process_below_{id}, true\n\
               %process_candidate_{id} = and i1 %process_inside_{id}, %process_not_below_{id}\n\
               %process_in_bounds_{id} = and i1 %process_candidate_{id}, {}\n\
               br i1 %process_in_bounds_{id}, label %process_memory_value_{id}, label %stop_memory_bounds\n\
             memory_value_{id}:\n",
            process.base(), process.base(), enough
        ));
    } else {
        body.push_str(&format!(
            "  br i1 %in_bounds_{id}, label %memory_value_{id}, label %stop_memory_bounds\nmemory_value_{id}:\n"
        ));
    }
    let guest_relative = if allocations.is_some() {
        format!("%active_relative_{id}")
    } else {
        format!("%relative_{id}")
    };
    let guest_ram = if allocations.is_some() {
        format!("%active_ram_{id}")
    } else {
        "%guest_ram".into()
    };
    let guest_known = if allocations.is_some() {
        format!("%active_known_{id}")
    } else {
        "%guest_known".into()
    };
    match layout.kind {
        MemoryKind::Load => {
            let mut known_checks = Vec::new();
            for byte in 0..layout.width {
                body.push_str(&format!(
                    "  %relative_{id}_{byte} = add i64 {guest_relative}, {byte}\n  %guest_known_ptr_{id}_{byte} = getelementptr i8, ptr {guest_known}, i64 %relative_{id}_{byte}\n  %guest_known_byte_{id}_{byte} = load i8, ptr %guest_known_ptr_{id}_{byte}\n  %guest_byte_ok_{id}_{byte} = icmp eq i8 %guest_known_byte_{id}_{byte}, -1\n"
                ));
                known_checks.push(format!("%guest_byte_ok_{id}_{byte}"));
            }
            emit_known_guard(
                &known_checks,
                &format!("guest_{id}"),
                body,
                &format!("memory_load_{id}"),
                PcodeCfgLlvmStatus::MemoryUnknownBytes,
            );
            body.push_str(&format!("memory_load_{id}:\n"));
            let mut previous = None::<String>;
            for byte in 0..layout.width {
                body.push_str(&format!(
                    "  %guest_ptr_{id}_{byte} = getelementptr i8, ptr {guest_ram}, i64 %relative_{id}_{byte}\n  %guest_byte_{id}_{byte} = load i8, ptr %guest_ptr_{id}_{byte}\n  %guest_wide_{id}_{byte} = zext i8 %guest_byte_{id}_{byte} to i{load_bits}\n  %guest_part_{id}_{byte} = shl i{load_bits} %guest_wide_{id}_{byte}, {}\n",
                    byte * 8
                ));
                let part = format!("%guest_part_{id}_{byte}");
                if let Some(previous_value) = previous {
                    let name = format!("%guest_acc_{id}_{byte}");
                    body.push_str(&format!(
                        "  {name} = or i{load_bits} {previous_value}, {part}\n"
                    ));
                    previous = Some(name);
                } else {
                    previous = Some(part);
                }
            }
            let result = previous.expect("memory width checked nonzero");
            let output_space = pcode_space_id(&layout.value.space)?;
            let output_offset = pcode_offset(layout.value)?;
            body.push_str(&format!(
                "  call void @{load_writer}(ptr %state, i32 {output_space}, i64 {output_offset}, i32 {}, i{load_bits} {result})\n  call void @{load_writer}(ptr %known, i32 {output_space}, i64 {output_offset}, i32 {}, i{load_bits} -1)\n",
                layout.width, layout.width
            ));
        }
        MemoryKind::Store => {
            let data = layout.value;
            if let Some(check) = known_check(data, &format!("store_data_{id}"), body)? {
                body.push_str(&format!(
                    "  br i1 {check}, label %memory_store_{id}, label %stop_unknown\n"
                ));
            } else {
                body.push_str(&format!("  br label %memory_store_{id}\n"));
            }
            body.push_str(&format!("memory_store_{id}:\n"));
            let value =
                if data.space == "const" {
                    let bits = data.size * 8;
                    let mask = if bits == 64 {
                        u64::MAX
                    } else {
                        (1u64 << bits) - 1
                    };
                    format!("{}", offset(&data.offset)? & mask)
                } else {
                    let name = format!("%store_value_{id}");
                    body.push_str(&format!(
                    "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
                    pcode_space_id(&data.space)?, pcode_offset(data)?, data.size
                ));
                    name
                };
            for byte in 0..layout.width {
                body.push_str(&format!(
                    "  %store_shifted_{id}_{byte} = lshr i64 {value}, {}\n  %store_byte_{id}_{byte} = trunc i64 %store_shifted_{id}_{byte} to i8\n  %store_relative_{id}_{byte} = add i64 {guest_relative}, {byte}\n  %store_guest_ptr_{id}_{byte} = getelementptr i8, ptr {guest_ram}, i64 %store_relative_{id}_{byte}\n  store i8 %store_byte_{id}_{byte}, ptr %store_guest_ptr_{id}_{byte}\n  %store_known_ptr_{id}_{byte} = getelementptr i8, ptr {guest_known}, i64 %store_relative_{id}_{byte}\n  store i8 -1, ptr %store_known_ptr_{id}_{byte}\n",
                    byte * 8
                ));
            }
        }
    }
    body.push_str(&log_event(
        id,
        &format!("%count_{id}"),
        "memory",
        next_label,
    ));
    if let Some(image) = image.filter(|image| image.space() == layout.space.name) {
        body.push_str(&format!("memory_image_value_{id}:\n"));
        let image_len = image.bytes().len();
        let mut known_checks = Vec::new();
        for byte in 0..layout.width {
            body.push_str(&format!(
                "  %image_index_{id}_{byte} = add i64 %image_relative_{id}, {byte}\n  %image_known_ptr_{id}_{byte} = getelementptr [{image_len} x i8], ptr @hydir_elf_image_known, i64 0, i64 %image_index_{id}_{byte}\n  %image_known_byte_{id}_{byte} = load i8, ptr %image_known_ptr_{id}_{byte}\n  %image_byte_ok_{id}_{byte} = icmp eq i8 %image_known_byte_{id}_{byte}, -1\n"
            ));
            known_checks.push(format!("%image_byte_ok_{id}_{byte}"));
        }
        emit_known_guard(
            &known_checks,
            &format!("image_{id}"),
            body,
            &format!("memory_image_ready_{id}"),
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
        );
        body.push_str(&format!("memory_image_ready_{id}:\n"));
        if layout.kind == MemoryKind::Store {
            body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MemoryReadOnly));
            return Ok(());
        }
        let mut previous = None::<String>;
        for byte in 0..layout.width {
            body.push_str(&format!(
                "  %image_ptr_{id}_{byte} = getelementptr [{image_len} x i8], ptr @hydir_elf_image_bytes, i64 0, i64 %image_index_{id}_{byte}\n  %image_byte_{id}_{byte} = load i8, ptr %image_ptr_{id}_{byte}\n  %image_wide_{id}_{byte} = zext i8 %image_byte_{id}_{byte} to i{load_bits}\n  %image_part_{id}_{byte} = shl i{load_bits} %image_wide_{id}_{byte}, {}\n",
                byte * 8
            ));
            let part = format!("%image_part_{id}_{byte}");
            if let Some(previous_value) = previous {
                let name = format!("%image_acc_{id}_{byte}");
                body.push_str(&format!(
                    "  {name} = or i{load_bits} {previous_value}, {part}\n"
                ));
                previous = Some(name);
            } else {
                previous = Some(part);
            }
        }
        let result = previous.expect("memory width checked nonzero");
        let output_space = pcode_space_id(&layout.value.space)?;
        let output_offset = pcode_offset(layout.value)?;
        body.push_str(&format!(
            "  call void @{load_writer}(ptr %state, i32 {output_space}, i64 {output_offset}, i32 {}, i{load_bits} {result})\n  call void @{load_writer}(ptr %known, i32 {output_space}, i64 {output_offset}, i32 {}, i{load_bits} -1)\n",
            layout.width, layout.width
        ));
        body.push_str(&log_event(
            id,
            &format!("%count_{id}"),
            "image_memory",
            next_label,
        ));
    }
    if let Some(process) = process.filter(|process| process.space() == layout.space.name) {
        emit_process_memory_value(layout, id, body, next_label, process, allocations.is_some())?;
    }
    Ok(())
}

/// Emit a self-contained LLVM module for one bounded concrete CFG path.
/// `state` and `known` are equally sized byte arrays indexed by `byte_map`.
/// A known byte is 0xff, an unknown byte is 0x00. `events` has at least
/// `event_capacity` i32 slots. The function writes successful operation IDs
/// and their count, then returns a `PcodeCfgLlvmStatus` code. Both execution
/// and instruction visits are bounded, including zero-operation loops.
pub fn emit_pcode_cfg_llvm(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
) -> Result<PcodeCfgLlvmArtifact, String> {
    let semantic = snapshot.pcode_function_ir()?.lower_semantics();
    emit_pcode_cfg_llvm_semantic(snapshot, start, semantic, None, None, None, None)
}

/// Emit a v3 module with the validated, immutable ELF bytes embedded in LLVM.
/// The caller still supplies a separate mutable guest RAM window through the
/// v2 function parameters. These windows must not overlap at runtime.
pub fn emit_pcode_cfg_llvm_with_image(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
    image: &PcodeReadOnlyElfWindow,
) -> Result<PcodeCfgLlvmArtifact, String> {
    let semantic = snapshot.pcode_function_ir()?.lower_semantics();
    emit_pcode_cfg_llvm_semantic(snapshot, start, semantic, None, Some(image), None, None)
}

/// Emit a v4 path module with binary-bound PT_LOAD bytes and permissions.
/// Writable ELF globals are private, fresh mutable state for each invocation;
/// unresolved relocation bytes retain an unknown mask until overwritten.
/// The separate guest window can supply explicitly known stack/heap bytes but
/// must not overlap the bounded ELF process span.
pub fn emit_pcode_cfg_llvm_with_process_memory(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
    process: &PcodeElfProcessMemory,
) -> Result<PcodeCfgLlvmArtifact, String> {
    let semantic = snapshot.pcode_function_ir()?.lower_semantics();
    emit_pcode_cfg_llvm_semantic(snapshot, start, semantic, None, None, Some(process), None)
}

/// Emit a v5 module whose two guest windows are exactly the declared stack
/// and heap allocations. The caller supplies byte and known-mask arrays for
/// each range; neither allocation implies initial byte values.
pub fn emit_pcode_cfg_llvm_with_allocations(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
    process: &PcodeElfProcessMemory,
    allocations: &PcodeProcessAllocations,
) -> Result<PcodeCfgLlvmArtifact, String> {
    allocations.validate_for(snapshot, process)?;
    let semantic = snapshot.pcode_function_ir()?.lower_semantics();
    emit_pcode_cfg_llvm_semantic(
        snapshot,
        start,
        semantic,
        None,
        None,
        Some(process),
        Some(allocations),
    )
}

/// Emit a single bounded LLVM state machine over validated function snapshots.
/// The root is the first snapshot. Only Ghidra-evidenced calls into loaded
/// function entries can cross functions; all other calls stop explicitly.
pub fn emit_pcode_interprocedural_cfg_llvm(
    snapshots: &[GhidraSnapshot],
    max_call_depth: usize,
) -> Result<PcodeInterproceduralCfgLlvmArtifact, String> {
    emit_pcode_interprocedural_cfg_llvm_inner(snapshots, max_call_depth, None)
}

/// Emit an opt-in v5 interprocedural module with one shared ELF process and
/// declared stack/heap contract. Only loaded internal RAM callees are entered;
/// PLT and unresolved external calls stop at their source operation.
pub fn emit_pcode_interprocedural_cfg_llvm_with_allocations(
    snapshots: &[GhidraSnapshot],
    max_call_depth: usize,
    process: &PcodeElfProcessMemory,
    allocations: &PcodeProcessAllocations,
) -> Result<PcodeInterproceduralCfgLlvmArtifact, String> {
    emit_pcode_interprocedural_cfg_llvm_inner(
        snapshots,
        max_call_depth,
        Some((process, allocations)),
    )
}

fn emit_pcode_interprocedural_cfg_llvm_inner(
    snapshots: &[GhidraSnapshot],
    max_call_depth: usize,
    allocated: Option<(&PcodeElfProcessMemory, &PcodeProcessAllocations)>,
) -> Result<PcodeInterproceduralCfgLlvmArtifact, String> {
    let root = snapshots
        .first()
        .ok_or("interprocedural LLVM needs a root snapshot")?;
    if snapshots.len() > 128 || max_call_depth > 16 {
        return Err("interprocedural LLVM snapshot or call-depth limit exceeded".into());
    }
    let mut owners = Vec::new();
    let mut semantic = root.pcode_function_ir()?.lower_semantics();
    semantic.instructions.clear();
    let mut entries = BTreeSet::new();
    let mut digests = Vec::new();
    for (owner, snapshot) in snapshots.iter().enumerate() {
        validate_ghidra_snapshot(snapshot, &root.binary_sha256)?;
        if let Some((process, allocations)) = allocated {
            allocations.validate_for(snapshot, process)?;
        }
        snapshot.pcode_cfg_ir()?;
        if snapshot.program != root.program
            || snapshot.address_spaces != root.address_spaces
            || snapshot.functions != root.functions
            || snapshot.flow_overrides_applied != root.flow_overrides_applied
        {
            return Err("interprocedural LLVM snapshots disagree on program identity".into());
        }
        let entry = &snapshot.selected_function.entry;
        if !entries.insert((entry.space.clone(), offset(&entry.offset)?)) {
            return Err("interprocedural LLVM has duplicate function entries".into());
        }
        let lowered = snapshot.pcode_function_ir()?.lower_semantics();
        owners.extend(std::iter::repeat_n(owner, lowered.instructions.len()));
        semantic.instructions.extend(lowered.instructions);
        digests.push(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(snapshot).map_err(|error| error.to_string())?)
        ));
    }
    let context = CallLlvmContext {
        snapshots,
        owners,
        max_call_depth,
        process: allocated.map(|(process, _)| process),
    };
    let mut llvm = emit_pcode_cfg_llvm_semantic(
        root,
        None,
        semantic,
        Some(&context),
        None,
        allocated.map(|(process, _)| process),
        allocated.map(|(_, allocations)| allocations),
    )?;
    llvm.state_abi.push_str(if allocated.is_some() {
        "; loaded internal calls share state, process bytes, stack, and heap; successful CALL and nested RETURN operations append source IDs to events; active-function recursion and call depth stop explicitly"
    } else {
        "; loaded calls share state and guest RAM; successful CALL and nested RETURN operations append source IDs to events; active-function recursion and call depth stop explicitly"
    });
    Ok(PcodeInterproceduralCfgLlvmArtifact {
        schema_version: if allocated.is_some() {
            PCODE_INTERPROCEDURAL_ALLOCATED_PROCESS_CFG_LLVM_VERSION
        } else {
            PCODE_INTERPROCEDURAL_CFG_LLVM_VERSION
        },
        binary_sha256: root.binary_sha256.clone(),
        function_entries: snapshots
            .iter()
            .map(|snapshot| snapshot.selected_function.entry.clone())
            .collect(),
        snapshot_sha256: digests,
        snapshot_diagnostics: Vec::new(),
        max_call_depth,
        llvm,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}

/// Emit LLVM from Hydir's checked P-code rewrite. The transformation is
/// recomputed from the validated snapshot; callers cannot swap in unrelated
/// operations or source addresses. This remains a bounded path artifact.
pub fn emit_pcode_simplified_cfg_llvm(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
) -> Result<PcodeSimplifiedCfgLlvmArtifact, String> {
    let simplification = snapshot.pcode_function_ir()?.simplify_checked()?;
    let llvm = emit_pcode_cfg_llvm_semantic(
        snapshot,
        start,
        simplification.after.lower_semantics(),
        None,
        None,
        None,
        None,
    )?;
    Ok(PcodeSimplifiedCfgLlvmArtifact {
        schema_version: PCODE_SIMPLIFIED_CFG_LLVM_VERSION,
        binary_sha256: snapshot.binary_sha256.clone(),
        simplification,
        llvm,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}

fn emit_pcode_cfg_llvm_semantic(
    snapshot: &GhidraSnapshot,
    start: Option<&PcodeAddress>,
    semantic: PcodeSemanticFunctionIr,
    call_context: Option<&CallLlvmContext<'_>>,
    image: Option<&PcodeReadOnlyElfWindow>,
    process: Option<&PcodeElfProcessMemory>,
    allocations: Option<&PcodeProcessAllocations>,
) -> Result<PcodeCfgLlvmArtifact, String> {
    if image.is_some() && process.is_some() {
        return Err("read-only image and process memory cannot be combined".into());
    }
    if let Some(allocations) = allocations {
        allocations.validate_for(
            snapshot,
            process.ok_or("allocations require process memory")?,
        )?;
    }
    snapshot.pcode_cfg_ir()?;
    let image_binding = image
        .map(|image| validate_image_window(snapshot, image))
        .transpose()?;
    let process_binding = process
        .map(|process| validate_process_memory(snapshot, process))
        .transpose()?;
    if !snapshot.program.language_id.starts_with("x86:LE:64:") {
        return Err("P-code CFG LLVM currently requires x86-64 little endian".into());
    }
    if semantic.instructions.len() > MAX_CFG_INSTRUCTIONS {
        return Err("P-code CFG LLVM instruction limit exceeded".into());
    }
    let operation_count = semantic
        .instructions
        .iter()
        .map(|instruction| instruction.operations.len())
        .sum::<usize>();
    if operation_count > MAX_CFG_OPERATIONS {
        return Err("P-code CFG LLVM operation limit exceeded".into());
    }
    let mut index = BTreeMap::new();
    for (number, instruction) in semantic.instructions.iter().enumerate() {
        if index
            .insert(
                (
                    instruction.address.space.clone(),
                    offset(&instruction.address.offset)?,
                ),
                number,
            )
            .is_some()
        {
            return Err("interprocedural LLVM has overlapping instruction addresses".into());
        }
    }
    let owners = call_context.map(|context| context.owners.as_slice());
    let scoped_indices = call_context.map(|context| {
        (0..context.snapshots.len())
            .map(|owner| {
                index
                    .iter()
                    .filter(|(_, instruction)| context.owners[**instruction] == owner)
                    .map(|(address, instruction)| (address.clone(), *instruction))
                    .collect::<BTreeMap<_, _>>()
            })
            .collect::<Vec<_>>()
    });
    let return_sites = call_context.map(|context| {
        let mut sites = BTreeSet::new();
        for (owner, snapshot) in context.snapshots.iter().enumerate() {
            for call in &snapshot.selected_function.call_targets {
                let call_key = (
                    call.call_site.space.as_str(),
                    offset(&call.call_site.offset).ok(),
                );
                for edge in &snapshot.selected_function.flow_edges {
                    if edge.kind != GhidraFlowKind::Fallthrough
                        || (edge.source.space.as_str(), offset(&edge.source.offset).ok())
                            != call_key
                    {
                        continue;
                    }
                    if let Some(target) = &edge.target
                        && let Ok(address) = offset(&target.offset)
                        && let Some(instruction) = scoped_indices
                            .as_ref()
                            .and_then(|scoped| scoped[owner].get(&(target.space.clone(), address)))
                    {
                        sites.insert(*instruction);
                    }
                }
            }
        }
        sites
    });
    let start = start.unwrap_or(&snapshot.selected_function.entry).clone();
    let start_index = index
        .get(&(start.space.clone(), offset(&start.offset)?))
        .ok_or("P-code CFG LLVM start is not a selected instruction")?;
    let mut fallthroughs = vec![Vec::<Option<PcodeAddress>>::new(); semantic.instructions.len()];
    let flow_edges = call_context
        .map(|context| {
            context
                .snapshots
                .iter()
                .flat_map(|snapshot| &snapshot.selected_function.flow_edges)
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| snapshot.selected_function.flow_edges.iter().collect());
    for edge in flow_edges {
        if edge.kind == GhidraFlowKind::Fallthrough {
            let source = index[&(edge.source.space.clone(), offset(&edge.source.offset)?)];
            fallthroughs[source].push(edge.target.clone());
        }
    }
    let mut byte_keys = BTreeSet::new();
    for instruction in &semantic.instructions {
        for operation in &instruction.operations {
            if matches!(operation.effect, PcodeEffect::Assign { .. })
                && emit_pcode_exact_operation_llvm(operation).is_ok()
            {
                for input in &operation.source.inputs {
                    node_bytes(input, &mut byte_keys)?;
                }
                if let Some(output) = &operation.source.output {
                    node_bytes(output, &mut byte_keys)?;
                }
            } else if operation.source.opcode == 5
                && operation.source.inputs.len() == 2
                && operation.source.inputs[1].size == 1
                && matches!(
                    operation.source.inputs[1].space.as_str(),
                    "register" | "unique" | "const"
                )
            {
                node_bytes(&operation.source.inputs[1], &mut byte_keys)?;
            } else if operation.source.opcode == 6
                && operation.source.inputs.len() == 1
                && (1..=8).contains(&operation.source.inputs[0].size)
                && matches!(
                    operation.source.inputs[0].space.as_str(),
                    "register" | "unique" | "const"
                )
            {
                node_bytes(&operation.source.inputs[0], &mut byte_keys)?;
            } else if call_context.is_some()
                && matches!(operation.source.opcode, 8 | 10)
                && operation.source.inputs.len() == 1
                && (1..=8).contains(&operation.source.inputs[0].size)
                && matches!(
                    operation.source.inputs[0].space.as_str(),
                    "register" | "unique" | "const"
                )
            {
                node_bytes(&operation.source.inputs[0], &mut byte_keys)?;
            } else if matches!(operation.source.opcode, 2 | 3)
                && let Ok(layout) = memory_layout(&operation.source, &semantic.address_spaces)
            {
                node_bytes(layout.pointer.as_ref(), &mut byte_keys)?;
                node_bytes(layout.value, &mut byte_keys)?;
            } else if operation.source.opcode == 1
                && matches!(
                    operation.effect,
                    PcodeEffect::Opaque {
                        class: PcodeOpaqueClass::MemoryRead,
                        ..
                    }
                )
                && let Ok(layout) =
                    direct_ram_copy_layout(&operation.source, &semantic.address_spaces)
            {
                node_bytes(layout.value, &mut byte_keys)?;
            }
        }
    }
    if byte_keys.len() > MAX_STATE_BYTES {
        return Err("P-code CFG LLVM state byte limit exceeded".into());
    }
    let byte_map = byte_keys
        .into_iter()
        .enumerate()
        .map(|(index, (space, offset))| PcodeStateByte {
            space,
            offset: format!("0x{offset:x}"),
            index: index as u32,
        })
        .collect::<Vec<_>>();

    let mut sources = Vec::new();
    let mut sites = Vec::new();
    let mut helper_ir = String::new();
    // Reserve every mapped state byte against the Rust executor's combined
    // one-MiB known-state limit, even if the caller marks all of them known.
    let guest_ram_limit = PCODE_CFG_GUEST_RAM_MAX_BYTES - byte_map.len() as u64;
    let allocation_shape = allocations.map(|allocations| {
        let region = |kind| {
            allocations
                .regions()
                .iter()
                .find(|region| region.kind == kind)
                .map_or((0, 0), |region| (region.base, region.byte_len))
        };
        (
            region(PcodeProcessAllocationKind::Stack),
            region(PcodeProcessAllocationKind::Heap),
        )
    });
    if allocation_shape
        .is_some_and(|((_, stack_len), (_, heap_len))| stack_len + heap_len > guest_ram_limit)
    {
        return Err("declared stack and heap exceed the available guest RAM budget".into());
    }
    let bound_memory = image
        .map(|image| (image.space(), image.base(), image.bytes().len()))
        .or_else(|| {
            process.map(|process| (process.space(), process.base(), process.bytes().len()))
        });
    let (mut memory_argument_check, mut bad_argument_name) = if let Some((space, base, len)) =
        bound_memory
    {
        let image_end = base + len as u64 - 1;
        let image_space_id = semantic
            .address_spaces
            .iter()
            .find(|candidate| candidate.name == space)
            .expect("validated ELF RAM space")
            .id;
        (
            format!(
                "  %bad_image_space = icmp ne i32 %guest_space_id, {image_space_id}\n  %guest_end = add i64 %guest_base, %guest_tail\n  %guest_before_image_end = icmp ule i64 %guest_base, {image_end}\n  %image_before_guest_end = icmp ule i64 {}, %guest_end\n  %overlap_candidate = and i1 %guest_before_image_end, %image_before_guest_end\n  %guest_nonempty = icmp ne i64 %guest_len, 0\n  %image_guest_overlap = and i1 %overlap_candidate, %guest_nonempty\n  %bad_image_window = or i1 %bad_image_space, %image_guest_overlap\n  %bad_image_args = or i1 %bad_args, %bad_image_window\n",
                base
            ),
            "%bad_image_args",
        )
    } else {
        (String::new(), "%bad_args")
    };
    if let Some(((stack_base, stack_len), (heap_base, heap_len))) = allocation_shape {
        memory_argument_check.push_str(&format!(
            "  %bad_heap_ram = icmp eq ptr %heap_ram, null\n  %bad_heap_known = icmp eq ptr %heap_known, null\n  %bad_heap_ptr = or i1 %bad_heap_ram, %bad_heap_known\n  %bad_stack_base = icmp ne i64 %guest_base, {stack_base}\n  %bad_stack_len = icmp ne i64 %guest_len, {stack_len}\n  %bad_heap_base = icmp ne i64 %heap_base, {heap_base}\n  %bad_heap_len = icmp ne i64 %heap_len, {heap_len}\n  %bad_stack_shape = or i1 %bad_stack_base, %bad_stack_len\n  %bad_heap_shape = or i1 %bad_heap_base, %bad_heap_len\n  %bad_allocation_shape = or i1 %bad_stack_shape, %bad_heap_shape\n  %bad_allocation_ptr = or i1 %bad_heap_ptr, %bad_allocation_shape\n  %bad_allocated_args = or i1 %bad_image_args, %bad_allocation_ptr\n"
        ));
        bad_argument_name = "%bad_allocated_args";
    }
    let heap_signature = if allocations.is_some() {
        "ptr %heap_ram, ptr %heap_known, i64 %heap_base, i64 %heap_len, "
    } else {
        ""
    };
    let mut body = format!(
        "define i32 @hydir_pcode_cfg(ptr %state, ptr %known, i32 %guest_space_id, ptr %guest_ram, ptr %guest_known, i64 %guest_base, i64 %guest_len, {heap_signature}ptr %events, ptr %event_count, i32 %event_capacity, i32 %max_steps) {{\n\
         entry:\n  %bad_state = icmp eq ptr %state, null\n  %bad_known = icmp eq ptr %known, null\n\
           %bad_guest_ram = icmp eq ptr %guest_ram, null\n  %bad_guest_known = icmp eq ptr %guest_known, null\n\
           %bad_events = icmp eq ptr %events, null\n  %bad_count = icmp eq ptr %event_count, null\n\
           %bad_a = or i1 %bad_state, %bad_known\n  %bad_b = or i1 %bad_events, %bad_count\n\
           %bad_c = or i1 %bad_guest_ram, %bad_guest_known\n  %bad_d = or i1 %bad_a, %bad_b\n\
           %bad_ptr = or i1 %bad_c, %bad_d\n  %too_many = icmp ugt i32 %max_steps, 262144\n\
           %small_log = icmp ult i32 %event_capacity, %max_steps\n\
           %negative_capacity = icmp slt i32 %event_capacity, 0\n\
           %bad_capacity = or i1 %small_log, %negative_capacity\n\
           %bad_steps = or i1 %too_many, %bad_capacity\n\
           %guest_too_large = icmp ugt i64 %guest_len, {guest_ram_limit}\n\
           %guest_empty = icmp eq i64 %guest_len, 0\n  %guest_tail_raw = sub i64 %guest_len, 1\n\
           %guest_tail = select i1 %guest_empty, i64 0, i64 %guest_tail_raw\n\
           %max_guest_base = sub i64 -1, %guest_tail\n\
           %guest_base_overflow = icmp ugt i64 %guest_base, %max_guest_base\n\
           %bad_guest_range = or i1 %guest_too_large, %guest_base_overflow\n\
           %bad_bounds = or i1 %bad_steps, %bad_guest_range\n\
           %bad_args = or i1 %bad_ptr, %bad_bounds\n\
           {memory_argument_check}br i1 {bad_argument_name}, label %stop_invalid_args, label %initialize\n\
         initialize:\n  store i32 0, ptr %event_count\n  %visit_counter = alloca i32\n\
           store i32 0, ptr %visit_counter\n",
    );
    if let Some(process) = process {
        let len = process.bytes().len();
        body.push_str(&format!(
            "  %process_bytes_array = alloca [{len} x i8]\n\
             %process_bytes = getelementptr [{len} x i8], ptr %process_bytes_array, i64 0, i64 0\n\
             %process_known_array = alloca [{len} x i8]\n\
             %process_known = getelementptr [{len} x i8], ptr %process_known_array, i64 0, i64 0\n\
             call void @llvm.memcpy.p0.p0.i64(ptr %process_bytes, ptr @hydir_process_initial_bytes, i64 {len}, i1 false)\n\
             call void @llvm.memcpy.p0.p0.i64(ptr %process_known, ptr @hydir_process_initial_known, i64 {len}, i1 false)\n"
        ));
    }
    if let Some(context) = call_context {
        body.push_str(
            "  %call_depth = alloca i32\n  store i32 0, ptr %call_depth\n  %return_sites = alloca [16 x i32]\n  %return_addresses = alloca [16 x i64]\n  %return_widths = alloca [16 x i32]\n  %active_functions = alloca [128 x i8]\n"
        );
        for owner in 0..context.snapshots.len() {
            body.push_str(&format!(
                "  %initial_active_{owner} = getelementptr [128 x i8], ptr %active_functions, i32 0, i32 {owner}\n  store i8 {}, ptr %initial_active_{owner}\n",
                u8::from(owner == 0)
            ));
        }
    }
    body.push_str(&format!("  br label %ins_{start_index}\n"));
    for (instruction_index, instruction) in semantic.instructions.iter().enumerate() {
        let current_index = if let (Some(owners), Some(scoped)) = (owners, &scoped_indices) {
            &scoped[owners[instruction_index]]
        } else {
            &index
        };
        body.push_str(&format!(
            "ins_{instruction_index}:\n  %visits_{instruction_index} = load i32, ptr %visit_counter\n\
               %visit_exhausted_{instruction_index} = icmp uge i32 %visits_{instruction_index}, {MAX_RUNTIME_STEPS}\n\
               br i1 %visit_exhausted_{instruction_index}, label %stop_visit_budget, label %enter_{instruction_index}\n\
             enter_{instruction_index}:\n  %visit_next_{instruction_index} = add i32 %visits_{instruction_index}, 1\n\
               store i32 %visit_next_{instruction_index}, ptr %visit_counter\n\
               call void @hydir_clear_unique(ptr %state)\n  call void @hydir_clear_unique(ptr %known)\n"
        ));
        let first_label = if instruction.operations.is_empty() {
            format!("end_{instruction_index}")
        } else {
            format!("op_{instruction_index}_0")
        };
        body.push_str(&format!("  br label %{first_label}\n"));

        for (operation_index, operation) in instruction.operations.iter().enumerate() {
            let id = sources.len();
            let source = &operation.source;
            sources.push(PcodeCfgLlvmSourceOperation {
                address: source.source_address.clone(),
                instruction_address: instruction.address.clone(),
                instruction_index,
                operation_index,
                mnemonic: source.mnemonic.clone(),
                userop_name: source.userop_name.clone(),
            });
            let next_label = if operation_index + 1 == instruction.operations.len() {
                format!("end_{instruction_index}")
            } else {
                format!("op_{instruction_index}_{}", operation_index + 1)
            };
            body.push_str(&format!(
                "op_{instruction_index}_{operation_index}:\n  %count_{id} = load i32, ptr %event_count\n\
                   %budget_{id} = icmp uge i32 %count_{id}, %max_steps\n\
                   br i1 %budget_{id}, label %stop_budget, label %run_{id}\nrun_{id}:\n"
            ));
            match source.opcode {
                4 | 5 => {
                    let conditional = source.opcode == 5;
                    let expected = if conditional { "CBRANCH" } else { "BRANCH" };
                    if source.mnemonic != expected
                        || source.output.is_some()
                        || source.inputs.len() != if conditional { 2 } else { 1 }
                        || conditional && source.inputs[1].size != 1
                    {
                        stop_site(
                            &mut sites,
                            &source.source_address,
                            Some(operation_index),
                            PcodeCfgLlvmStatus::MalformedTarget,
                            "invalid direct branch shape",
                        );
                        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
                        continue;
                    }
                    let target = target_label(
                        &source.inputs[0],
                        instruction_index,
                        operation_index,
                        instruction.operations.len(),
                        current_index,
                    );
                    if conditional {
                        let condition = &source.inputs[1];
                        let mut checks = Vec::new();
                        match known_check(condition, &format!("cond_{id}"), &mut body) {
                            Ok(Some(check)) => checks.push(check),
                            Ok(None) => (),
                            Err(reason) => {
                                stop_site(
                                    &mut sites,
                                    &source.source_address,
                                    Some(operation_index),
                                    PcodeCfgLlvmStatus::MalformedTarget,
                                    reason,
                                );
                                body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
                                continue;
                            }
                        }
                        emit_known_guard(
                            &checks,
                            &format!("cond_{id}"),
                            &mut body,
                            &format!("condition_{id}"),
                            PcodeCfgLlvmStatus::UnknownInput,
                        );
                        body.push_str(&format!("condition_{id}:\n"));
                        let value = if condition.space == "const" {
                            format!("{}", offset(&condition.offset)? & 0xff)
                        } else {
                            let name = format!("%condition_value_{id}");
                            body.push_str(&format!(
                                "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 1)\n",
                                pcode_space_id(&condition.space)?, pcode_offset(condition)?
                            ));
                            name
                        };
                        body.push_str(&format!(
                            "  %take_{id} = icmp ne i64 {value}, 0\n  br i1 %take_{id}, label %taken_{id}, label %false_{id}\n"
                        ));
                        body.push_str(&format!("false_{id}:\n"));
                        body.push_str(&log_event(
                            id,
                            &format!("%count_{id}"),
                            "false",
                            &next_label,
                        ));
                        body.push_str(&format!("taken_{id}:\n"));
                    }
                    match target {
                        Ok(target) => {
                            body.push_str(&log_event(id, &format!("%count_{id}"), "taken", &target))
                        }
                        Err((status, reason)) => {
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                status,
                                reason,
                            );
                            body.push_str(&branch_to_stop(status));
                        }
                    }
                }
                6 => {
                    let pointer = source.inputs.first();
                    let pointer_size = semantic
                        .address_spaces
                        .iter()
                        .find(|space| space.name == instruction.address.space)
                        .map(|space| space.pointer_size);
                    if source.mnemonic != "BRANCHIND"
                        || source.output.is_some()
                        || source.inputs.len() != 1
                        || pointer_size.is_none_or(|size| size == 0 || size > 8)
                        || pointer.is_none_or(|node| Some(node.size) != pointer_size)
                        || !matches!(
                            pointer.map(|node| node.space.as_str()),
                            Some("register" | "unique" | "const")
                        )
                    {
                        stop_site(
                            &mut sites,
                            &source.source_address,
                            Some(operation_index),
                            PcodeCfgLlvmStatus::MalformedTarget,
                            "invalid BRANCHIND target shape, space, or pointer width",
                        );
                        body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::MalformedTarget));
                        continue;
                    }
                    let pointer = pointer.expect("checked above");
                    stop_site(
                        &mut sites,
                        &source.source_address,
                        Some(operation_index),
                        PcodeCfgLlvmStatus::UnknownInput,
                        "BRANCHIND target bytes are unknown",
                    );
                    stop_site(
                        &mut sites,
                        &source.source_address,
                        Some(operation_index),
                        PcodeCfgLlvmStatus::OutOfFunction,
                        "BRANCHIND target is not a selected instruction",
                    );
                    let check = known_check(pointer, &format!("indirect_{id}"), &mut body)?;
                    emit_known_guard(
                        &check.into_iter().collect::<Vec<_>>(),
                        &format!("indirect_{id}"),
                        &mut body,
                        &format!("indirect_known_{id}"),
                        PcodeCfgLlvmStatus::UnknownInput,
                    );
                    body.push_str(&format!("indirect_known_{id}:\n"));
                    let value = if pointer.space == "const" {
                        format!("{}", offset(&pointer.offset)?)
                    } else {
                        let name = format!("%indirect_value_{id}");
                        body.push_str(&format!(
                            "  {name} = call i64 @hydir_read_varnode(ptr %state, i32 {}, i64 {}, i32 {})\n",
                            pcode_space_id(&pointer.space)?,
                            pcode_offset(pointer)?,
                            pointer.size
                        ));
                        name
                    };
                    body.push_str(&format!(
                        "  switch i64 {value}, label %{} [\n",
                        stop_label(PcodeCfgLlvmStatus::OutOfFunction)
                    ));
                    for ((space, address), next) in current_index {
                        if *space == instruction.address.space {
                            body.push_str(&format!(
                                "    i64 {address}, label %indirect_{id}_{next}\n"
                            ));
                        }
                    }
                    body.push_str("  ]\n");
                    for ((space, _), next) in current_index {
                        if *space == instruction.address.space {
                            body.push_str(&format!("indirect_{id}_{next}:\n"));
                            body.push_str(&log_event(
                                id,
                                &format!("%count_{id}"),
                                &format!("indirect_{next}"),
                                &format!("ins_{next}"),
                            ));
                        }
                    }
                }
                7 | 8 | 10 => {
                    if let Some(context) = call_context {
                        if source.opcode == 10 {
                            emit_interprocedural_return(
                                source,
                                id,
                                context.owners[instruction_index],
                                return_sites
                                    .as_ref()
                                    .expect("call context has return sites"),
                                &mut body,
                                &mut sites,
                            )?;
                        } else {
                            emit_interprocedural_call(
                                context,
                                source,
                                &instruction.address,
                                instruction_index,
                                operation_index,
                                id,
                                &index,
                                current_index,
                                &mut body,
                                &mut sites,
                            )?;
                        }
                    } else {
                        let status = if source.opcode == 10 {
                            PcodeCfgLlvmStatus::Return
                        } else {
                            PcodeCfgLlvmStatus::Call
                        };
                        stop_site(
                            &mut sites,
                            &source.source_address,
                            Some(operation_index),
                            status,
                            format!("{} ends the emitted path", source.mnemonic),
                        );
                        body.push_str(&branch_to_stop(status));
                    }
                }
                1 | 2 | 3
                    if source.opcode != 1
                        || matches!(
                            operation.effect,
                            PcodeEffect::Opaque {
                                class: PcodeOpaqueClass::MemoryRead,
                                ..
                            }
                        ) =>
                {
                    let layout = if source.opcode == 1 {
                        direct_ram_copy_layout(source, &semantic.address_spaces)
                    } else {
                        memory_layout(source, &semantic.address_spaces)
                    };
                    match layout {
                        Ok(layout) => {
                            for (status, reason) in [
                                (
                                    PcodeCfgLlvmStatus::MemorySpaceMismatch,
                                    "guest RAM binding does not match P-code space ID",
                                ),
                                (
                                    PcodeCfgLlvmStatus::MemoryUnknownAlias,
                                    "pointer varnode bytes are unknown",
                                ),
                                (
                                    PcodeCfgLlvmStatus::MemoryAddressOverflow,
                                    "scaled memory address overflows u64",
                                ),
                                (
                                    PcodeCfgLlvmStatus::MemoryOutOfBounds,
                                    if image.is_some() {
                                        "memory access is outside guest RAM and read-only ELF image windows"
                                    } else {
                                        "memory access is outside guest RAM window"
                                    },
                                ),
                            ] {
                                if status == PcodeCfgLlvmStatus::MemoryOutOfBounds
                                    && allocations.is_some()
                                {
                                    continue;
                                }
                                stop_site(
                                    &mut sites,
                                    &source.source_address,
                                    Some(operation_index),
                                    status,
                                    reason,
                                );
                            }
                            if layout.kind == MemoryKind::Load {
                                stop_site(
                                    &mut sites,
                                    &source.source_address,
                                    Some(operation_index),
                                    PcodeCfgLlvmStatus::MemoryUnknownBytes,
                                    if image.is_some() || process.is_some() {
                                        "loaded guest RAM or read-only ELF image bytes are unknown"
                                    } else {
                                        "loaded guest RAM bytes are unknown"
                                    },
                                );
                            } else {
                                stop_site(
                                    &mut sites,
                                    &source.source_address,
                                    Some(operation_index),
                                    PcodeCfgLlvmStatus::UnknownInput,
                                    "STORE data varnode bytes are unknown",
                                );
                                if image.is_some_and(|image| image.space() == layout.space.name) {
                                    stop_site(
                                        &mut sites,
                                        &source.source_address,
                                        Some(operation_index),
                                        PcodeCfgLlvmStatus::MemoryUnknownBytes,
                                        "STORE spans unknown bytes in the read-only ELF image window",
                                    );
                                    stop_site(
                                        &mut sites,
                                        &source.source_address,
                                        Some(operation_index),
                                        PcodeCfgLlvmStatus::MemoryReadOnly,
                                        "STORE targets immutable file-backed ELF bytes",
                                    );
                                }
                                if process
                                    .is_some_and(|process| process.space() == layout.space.name)
                                {
                                    if allocations.is_none() {
                                        stop_site(
                                            &mut sites,
                                            &source.source_address,
                                            Some(operation_index),
                                            PcodeCfgLlvmStatus::MemoryUnknownBytes,
                                            "STORE spans unmapped bytes in bounded ELF process memory",
                                        );
                                    }
                                    stop_site(
                                        &mut sites,
                                        &source.source_address,
                                        Some(operation_index),
                                        PcodeCfgLlvmStatus::MemoryReadOnly,
                                        "STORE targets a read-only ELF process mapping",
                                    );
                                    if allocations.is_some() {
                                        stop_site(
                                            &mut sites,
                                            &source.source_address,
                                            Some(operation_index),
                                            PcodeCfgLlvmStatus::MemoryUnmappedWrite,
                                            "STORE crosses an undeclared stack/heap or unmapped ELF byte",
                                        );
                                    }
                                }
                            }
                            emit_memory_operation(
                                &layout,
                                id,
                                &mut body,
                                &next_label,
                                image,
                                process,
                                allocations,
                            )?;
                        }
                        Err((status, reason)) => {
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                status,
                                reason,
                            );
                            body.push_str(&branch_to_stop(status));
                        }
                    }
                }
                _ => {
                    let helper = if matches!(operation.effect, PcodeEffect::Assign { .. }) {
                        emit_pcode_exact_operation_llvm(operation)
                    } else {
                        Err("opaque P-code effect".into())
                    };
                    match helper {
                        Ok(helper) => {
                            let helper_name = format!("hydir_cfg_exact_{id}");
                            helper_ir.push_str(&helper.replacen(
                                "@hydir_pcode_exact(",
                                &format!("@{helper_name}("),
                                1,
                            ));
                            helper_ir.push('\n');
                            let mut checks = Vec::new();
                            for (input_index, input) in source.inputs.iter().enumerate() {
                                if let Some(check) = known_check(
                                    input,
                                    &format!("input_{id}_{input_index}"),
                                    &mut body,
                                )? {
                                    checks.push(check);
                                }
                            }
                            emit_known_guard(
                                &checks,
                                &format!("input_{id}"),
                                &mut body,
                                &format!("value_{id}"),
                                PcodeCfgLlvmStatus::UnknownInput,
                            );
                            body.push_str(&format!("value_{id}:\n"));
                            let mut arguments = Vec::new();
                            for (input_index, input) in source.inputs.iter().enumerate() {
                                if input.space == "const" {
                                    continue;
                                }
                                let bits = input.size * 8;
                                let raw = format!("%raw_{id}_{input_index}");
                                let (raw_bits, read_helper) = if bits > 64 {
                                    (128, "hydir_read_varnode_wide")
                                } else {
                                    (64, "hydir_read_varnode")
                                };
                                body.push_str(&format!(
                                    "  {raw} = call i{raw_bits} @{read_helper}(ptr %state, i32 {}, i64 {}, i32 {})\n",
                                    pcode_space_id(&input.space)?, pcode_offset(input)?, input.size
                                ));
                                let value = if bits == raw_bits {
                                    raw
                                } else {
                                    let typed = format!("%typed_{id}_{input_index}");
                                    body.push_str(&format!(
                                        "  {typed} = trunc i{raw_bits} {raw} to i{bits}\n"
                                    ));
                                    typed
                                };
                                arguments.push(format!("i{bits} {value}"));
                            }
                            if let PcodeEffect::Assign {
                                operation: kind, ..
                            } = &operation.effect
                            {
                                if matches!(
                                    kind,
                                    PcodeExactOp::UnsignedDivide
                                        | PcodeExactOp::SignedDivide
                                        | PcodeExactOp::UnsignedRemainder
                                        | PcodeExactOp::SignedRemainder
                                ) {
                                    let typed_value =
                                        |input_index: usize| -> Result<String, String> {
                                            let input = &source.inputs[input_index];
                                            let bits = input.size * 8;
                                            if input.space == "const" {
                                                let mask = if bits == 64 {
                                                    u64::MAX
                                                } else {
                                                    (1u64 << bits) - 1
                                                };
                                                Ok(format!("{}", offset(&input.offset)? & mask))
                                            } else if bits == 64 {
                                                Ok(format!("%raw_{id}_{input_index}"))
                                            } else {
                                                Ok(format!("%typed_{id}_{input_index}"))
                                            }
                                        };
                                    let divisor = typed_value(1)?;
                                    let bits = source.inputs[1].size * 8;
                                    body.push_str(&format!(
                                        "  %divide_zero_{id} = icmp eq i{bits} {divisor}, 0\n"
                                    ));
                                    let invalid = if *kind == PcodeExactOp::SignedDivide {
                                        let dividend = typed_value(0)?;
                                        let minimum = 1u64 << (bits - 1);
                                        body.push_str(&format!(
                                            "  %divide_minimum_{id} = icmp eq i{bits} {dividend}, {minimum}\n  %divide_negative_one_{id} = icmp eq i{bits} {divisor}, -1\n  %divide_overflow_{id} = and i1 %divide_minimum_{id}, %divide_negative_one_{id}\n  %divide_invalid_{id} = or i1 %divide_zero_{id}, %divide_overflow_{id}\n"
                                        ));
                                        format!("%divide_invalid_{id}")
                                    } else {
                                        format!("%divide_zero_{id}")
                                    };
                                    stop_site(
                                        &mut sites,
                                        &source.source_address,
                                        Some(operation_index),
                                        PcodeCfgLlvmStatus::InvalidOperation,
                                        "undefined P-code division: zero divisor or signed quotient overflow",
                                    );
                                    body.push_str(&format!(
                                        "  br i1 {invalid}, label %{}, label %division_valid_{id}\ndivision_valid_{id}:\n",
                                        stop_label(PcodeCfgLlvmStatus::InvalidOperation)
                                    ));
                                }
                            }
                            let output = source
                                .output
                                .as_ref()
                                .ok_or("exact operation lacks output")?;
                            let bits = output.size * 8;
                            body.push_str(&format!(
                                "  %result_{id} = call i{bits} @{helper_name}({})\n",
                                arguments.join(", ")
                            ));
                            let raw_bits = if bits > 64 { 128 } else { 64 };
                            let raw = if bits == raw_bits {
                                format!("%result_{id}")
                            } else {
                                body.push_str(&format!(
                                    "  %result_raw_{id} = zext i{bits} %result_{id} to i{raw_bits}\n"
                                ));
                                format!("%result_raw_{id}")
                            };
                            let space_id = pcode_space_id(&output.space)?;
                            let output_offset = pcode_offset(output)?;
                            let write_helper = if bits > 64 {
                                "hydir_write_varnode_wide"
                            } else {
                                "hydir_write_varnode"
                            };
                            body.push_str(&format!(
                                "  call void @{write_helper}(ptr %state, i32 {space_id}, i64 {output_offset}, i32 {}, i{raw_bits} {raw})\n\
                                   call void @{write_helper}(ptr %known, i32 {space_id}, i64 {output_offset}, i32 {}, i{raw_bits} -1)\n",
                                output.size, output.size
                            ));
                            body.push_str(&log_event(
                                id,
                                &format!("%count_{id}"),
                                "effect",
                                &next_label,
                            ));
                        }
                        Err(reason) => {
                            let status = if matches!(operation.effect, PcodeEffect::Assign { .. }) {
                                PcodeCfgLlvmStatus::InvalidOperation
                            } else {
                                PcodeCfgLlvmStatus::OpaqueEffect
                            };
                            stop_site(
                                &mut sites,
                                &source.source_address,
                                Some(operation_index),
                                status,
                                reason,
                            );
                            body.push_str(&branch_to_stop(status));
                        }
                    }
                }
            }
        }
        body.push_str(&format!("end_{instruction_index}:\n"));
        match fallthroughs[instruction_index].as_slice() {
            [Some(target)] => {
                let target_key = (target.space.clone(), offset(&target.offset)?);
                if let Some(next) = current_index.get(&target_key) {
                    body.push_str(&format!("  br label %ins_{next}\n"));
                } else {
                    stop_site(
                        &mut sites,
                        &instruction.address,
                        None,
                        PcodeCfgLlvmStatus::OutOfFunction,
                        "fallthrough target is outside selected instructions",
                    );
                    body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::OutOfFunction));
                }
            }
            [] | [None] => {
                stop_site(
                    &mut sites,
                    &instruction.address,
                    None,
                    PcodeCfgLlvmStatus::UnresolvedFlow,
                    "no proven fallthrough target",
                );
                body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::UnresolvedFlow));
            }
            _ => {
                stop_site(
                    &mut sites,
                    &instruction.address,
                    None,
                    PcodeCfgLlvmStatus::AmbiguousFlow,
                    "multiple fallthrough candidates",
                );
                body.push_str(&branch_to_stop(PcodeCfgLlvmStatus::AmbiguousFlow));
            }
        }
    }
    for status in [
        PcodeCfgLlvmStatus::Return,
        PcodeCfgLlvmStatus::Call,
        PcodeCfgLlvmStatus::OpaqueEffect,
        PcodeCfgLlvmStatus::UnsupportedMemory,
        PcodeCfgLlvmStatus::IndirectFlow,
        PcodeCfgLlvmStatus::UnresolvedFlow,
        PcodeCfgLlvmStatus::AmbiguousFlow,
        PcodeCfgLlvmStatus::OutOfFunction,
        PcodeCfgLlvmStatus::MalformedTarget,
        PcodeCfgLlvmStatus::UnknownInput,
        PcodeCfgLlvmStatus::StepBudget,
        PcodeCfgLlvmStatus::InvalidArguments,
        PcodeCfgLlvmStatus::VisitBudget,
        PcodeCfgLlvmStatus::InvalidOperation,
        PcodeCfgLlvmStatus::MemoryUnknownAlias,
        PcodeCfgLlvmStatus::MemoryUnknownBytes,
        PcodeCfgLlvmStatus::MemoryOutOfBounds,
        PcodeCfgLlvmStatus::MemoryAddressOverflow,
        PcodeCfgLlvmStatus::MemorySpaceMismatch,
        PcodeCfgLlvmStatus::MemoryUnsupportedLayout,
        PcodeCfgLlvmStatus::MemoryNonRamSpace,
        PcodeCfgLlvmStatus::MemoryUnknownSpace,
        PcodeCfgLlvmStatus::CallDepth,
        PcodeCfgLlvmStatus::ReturnMismatch,
        PcodeCfgLlvmStatus::RecursiveCall,
    ] {
        body.push_str(&format!(
            "{}:\n  ret i32 {}\n",
            stop_label(status),
            status.code()
        ));
    }
    if image.is_some() || process.is_some() {
        body.push_str(&format!(
            "{}:\n  ret i32 {}\n",
            stop_label(PcodeCfgLlvmStatus::MemoryReadOnly),
            PcodeCfgLlvmStatus::MemoryReadOnly.code()
        ));
    }
    if allocations.is_some() {
        body.push_str(&format!(
            "{}:\n  ret i32 {}\n",
            stop_label(PcodeCfgLlvmStatus::MemoryUnmappedWrite),
            PcodeCfgLlvmStatus::MemoryUnmappedWrite.code()
        ));
    }
    body.push_str("}\n");
    let mut llvm_ir = format!(
        "; Hydir {} concrete CFG path; equivalence unverified.\n\n",
        semantic.source
    );
    llvm_ir.push_str("declare { i64, i1 } @llvm.umul.with.overflow.i64(i64, i64)\n");
    llvm_ir.push_str("declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64)\n\n");
    if process.is_some() {
        llvm_ir.push_str("declare void @llvm.memcpy.p0.p0.i64(ptr, ptr, i64, i1)\n\n");
    }
    if let Some(image) = image {
        llvm_ir.push_str(&image_globals(image));
    }
    if let Some(process) = process {
        llvm_ir.push_str(&process_globals(process));
    }
    llvm_ir.push_str(&helper_definitions(&byte_map));
    llvm_ir.push('\n');
    llvm_ir.push_str(&helper_ir);
    llvm_ir.push_str(&body);
    if llvm_ir.len()
        > if process.is_some() {
            MAX_PROCESS_LLVM_BYTES
        } else {
            MAX_LLVM_BYTES
        }
    {
        return Err("P-code CFG LLVM module exceeds byte limit".into());
    }
    Ok(PcodeCfgLlvmArtifact {
        schema_version: if allocations.is_some() {
            PCODE_CFG_ALLOCATED_PROCESS_LLVM_VERSION
        } else if process.is_some() {
            PCODE_CFG_PROCESS_LLVM_VERSION
        } else if image.is_some() {
            PCODE_CFG_IMAGE_LLVM_VERSION
        } else {
            PCODE_CFG_LLVM_VERSION
        },
        binary_sha256: snapshot.binary_sha256.clone(),
        start,
        source_operations: sources,
        stop_sites: sites,
        state_bytes: byte_map.len(),
        guest_ram_limit_bytes: guest_ram_limit,
        byte_map,
        state_abi: if let Some(((stack_base, stack_len), (heap_base, heap_len))) = allocation_shape
        {
            format!(
                "hydir-pcode-cfg-state-v5: @hydir_pcode_cfg(ptr state, ptr known, i32 guest_space_id, ptr stack_ram, ptr stack_known, i64 stack_base, i64 stack_len, ptr heap_ram, ptr heap_known, i64 heap_base, i64 heap_len, ptr events, ptr event_count, i32 event_capacity, i32 max_steps) -> i32 status; stack=[0x{stack_base:x},0x{:x}), heap=[0x{heap_base:x},0x{:x}); supplied bounds must match the embedded declaration exactly; all arrays must be disjoint and allocated to their declared lengths; STORE preflights its full width and stops with MemoryUnmappedWrite outside ELF mappings and declared allocations; LOAD of unmapped or unknown bytes stops with MemoryUnknownBytes; known byte 0xff, unknown byte 0x00; combined guest bytes<={guest_ram_limit}",
                stack_base + stack_len,
                heap_base + heap_len
            )
        } else if let Some(process) = process {
            format!(
                "hydir-pcode-cfg-state-v4: @hydir_pcode_cfg(ptr state, ptr known, i32 guest_space_id, ptr guest_ram, ptr guest_known, i64 guest_base, i64 guest_len, ptr events, ptr event_count, i32 event_capacity, i32 max_steps) -> i32 status; checked ELF process bytes, known mask, mapped mask and writable mask are embedded at {} in {}; fresh private mutable process bytes and known mask are initialized on every invocation; guest arrays supply a disjoint stack/heap window in the same RAM space and cannot overlap the entire process span; LOAD requires all bytes mapped and known; STORE requires all bytes mapped and writable and marks written bytes known; known byte 0xff, unknown byte 0x00; state/known use byte_map; event_count initialized after argument validation; event_capacity>=max_steps; guest_len<={guest_ram_limit}; max_steps<=262144; arrays must be separate and allocated to declared lengths",
                process.base(),
                process.space()
            )
        } else if let Some(image) = image {
            format!(
                "hydir-pcode-cfg-state-v3: @hydir_pcode_cfg(ptr state, ptr known, i32 guest_space_id, ptr guest_ram, ptr guest_known, i64 guest_base, i64 guest_len, ptr events, ptr event_count, i32 event_capacity, i32 max_steps) -> i32 status; mutable guest arrays hold guest_len bytes in guest_space_id from guest_base byte offset; immutable read-only ELF bytes and known mask are embedded at {} in {}; guest_space_id must match image space ID; guest and image address ranges must not overlap; LOAD requires one full-width known window; STORE to image stops with MemoryReadOnly; known byte 0xff, unknown 0x00; state/known use byte_map; event_count initialized after argument validation; event_capacity>=max_steps; guest_len<={guest_ram_limit}; max_steps<=262144; arrays must be separate and allocated to declared lengths",
                image.base(),
                image.space()
            )
        } else {
            format!(
                "hydir-pcode-cfg-state-v2: @hydir_pcode_cfg(ptr state, ptr known, i32 guest_space_id, ptr guest_ram, ptr guest_known, i64 guest_base, i64 guest_len, ptr events, ptr event_count, i32 event_capacity, i32 max_steps) -> i32 status; state/known use byte_map; guest arrays hold guest_len bytes in guest_space_id from guest_base byte offset; known byte 0xff, unknown 0x00; event_count initialized by callee after argument validation; event_capacity>=max_steps; guest_len<={guest_ram_limit}; max_steps<=262144; arrays must be separate and allocated to their declared lengths"
            )
        },
        read_only_image: image_binding,
        process_memory: process_binding,
        allocations: allocations.cloned(),
        llvm_ir,
        semantic_fidelity: SemanticFidelity::Unknown,
        verification: VerificationStatus::NotRun,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydir_ir::pcode::{
        PcodeConcreteState, PcodeElfProcessMemory, PcodeExecutionStop, PcodeMemoryBoundaryKind,
        PcodePathEvent, PcodePathStop, PcodeProcessAllocation, PcodeReadOnlyElfImage,
        parse_ghidra_snapshot,
    };
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_bit_prefix_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap()
    }

    fn add_zero_fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_add_zero_v2.json"
            )),
            "8e68f73f3d55b242d4c968446a9b011aaad4032443dab3d3b678ca7be10e1874",
        )
        .unwrap()
    }

    fn rdtsc_userop_fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_userop_rdtsc_v2.json"
            )),
            "75f384ca5c4dc59d1af2f56e92d677fc7acae43b6faf0213bd203ef6426f2667",
        )
        .unwrap()
    }

    fn division_fixture(signed: bool) -> GhidraSnapshot {
        let digest = "50b294c6ef92649165ac921b205a76f09e3b27fd6c20f7f72f9c2a507ed4db16";
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../tests/fixtures/ghidra_division.elf"
                )))
            ),
            digest
        );
        let bytes: &[u8] = if signed {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_division_s32_v2.json"
            ))
        } else {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_division_u32_v2.json"
            ))
        };
        let snapshot = parse_ghidra_snapshot(bytes, digest).unwrap();
        assert_eq!(snapshot.program.ghidra_version, "12.1.4");
        assert_eq!(snapshot.program.language_id, "x86:LE:64:default");
        snapshot
    }

    fn stripped_password_mix_fixture() -> GhidraSnapshot {
        let digest = "4ce1c25b8bf0e96350cb893d81511ef6ebee9509c76ef4e6cb28e869299e5288";
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../tests/fixtures/hydir-password-gate-stripped.elf"
                )))
            ),
            digest
        );
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_password_mix_o1_v2.json"
            )),
            digest,
        )
        .unwrap();
        assert_eq!(snapshot.selected_function.entry.offset, "0x2015d0");
        snapshot
    }

    fn stripped_password_secure_equals_fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_password_secure_equals_o1_v2.json"
            )),
            "4ce1c25b8bf0e96350cb893d81511ef6ebee9509c76ef4e6cb28e869299e5288",
        )
        .unwrap()
    }

    fn calls_fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            )),
            "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0",
        )
        .unwrap()
    }

    fn call_snapshots() -> Vec<GhidraSnapshot> {
        let digest = "4b3d29186ad32957cd12f1f4b581f3cad544903f0c4da152603394cc45ee3bb0";
        [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_calls_flow_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prism_leaf_add_v2.json"
            ))
            .as_slice(),
        ]
        .into_iter()
        .map(|bytes| parse_ghidra_snapshot(bytes, digest).unwrap())
        .collect()
    }

    fn choose_call_snapshots() -> Vec<GhidraSnapshot> {
        let digest = "dc459793ce9edcc543c9ffcadbecc27c6a2e1976782f1da4d3adc2119dd27723";
        [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_choose_root_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_choose_right_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_choose_left_v2.json"
            ))
            .as_slice(),
        ]
        .into_iter()
        .map(|bytes| parse_ghidra_snapshot(bytes, digest).unwrap())
        .collect()
    }

    fn call_event_ids(
        artifact: &PcodeCfgLlvmArtifact,
        trace: &hydir_ir::pcode::PcodeInterproceduralTrace,
    ) -> Vec<usize> {
        let mut ids = Vec::new();
        for (segment_index, segment) in trace.segments.iter().enumerate() {
            ids.extend(source_event_ids(artifact, &segment.path));
            if segment_index + 1 == trace.segments.len() {
                continue;
            }
            let source = match &segment.path.stop {
                PcodePathStop::Call { source } | PcodePathStop::Return { source } => source,
                other => panic!("unexpected interprocedural boundary: {other:?}"),
            };
            ids.push(
                artifact
                    .source_operations
                    .iter()
                    .position(|candidate| {
                        candidate.address == source.source_address
                            && candidate.operation_index == source.sequence_index as usize
                    })
                    .unwrap(),
            );
        }
        ids
    }

    #[test]
    fn stripped_password_mix_wide_imul_matches_rust_and_llvm() {
        let snapshot = stripped_password_mix_fixture();
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        assert!(artifact.llvm_ir.contains("mul i128"));
        assert!(artifact.llvm_ir.contains("@hydir_read_varnode_wide"));
        assert!(!artifact.stop_sites.iter().any(|site| {
            site.address.offset == "0x2015ee" && site.status == PcodeCfgLlvmStatus::OpaqueEffect
        }));
        verify(&artifact.llvm_ir);
        for (value, salt) in [(0, 0), (7, 5), (u64::MAX, u64::MAX)] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), value).unwrap();
            seed.write_varnode(&register("0x30", 8), salt).unwrap();
            seed.write_varnode(&register("0x20", 8), 0x700000).unwrap();
            seed.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
            let rust = snapshot
                .execute_concrete_path(&seed, None, 256, 64)
                .unwrap();
            assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
            let expected = (value ^ salt.wrapping_add(0x9e3779b97f4a7c15))
                .rotate_left(13)
                .wrapping_mul(0xbf58476d1ce4e5b9);
            let expected = expected ^ (expected >> 29);
            assert_eq!(
                rust.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                Some(expected)
            );
            let expected_state = expected
                .to_le_bytes()
                .into_iter()
                .enumerate()
                .map(|(index, byte)| ("register".to_owned(), format!("0x{index:x}"), byte, true))
                .collect();
            run_lli_with_guest(
                &artifact,
                &seed,
                &GuestTestMemory {
                    space_id: 433,
                    base: 0x700000,
                    bytes: 0xdeadbeefu64.to_le_bytes().into_iter().map(Some).collect(),
                    expected: Vec::new(),
                    expected_state,
                },
                256,
                PcodeCfgLlvmStatus::Return,
                &source_event_ids(&artifact, &rust),
                Some(expected as u8),
            );
        }
    }

    #[test]
    fn direct_ram_copy_sixteen_bytes_matches_rust_and_llvm() {
        let mut snapshot = fixture();
        snapshot.selected_function.instructions.truncate(1);
        snapshot.selected_function.flow_edges.clear();
        snapshot.selected_function.call_targets.clear();
        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode = vec![PcodeOperation {
            mnemonic: "COPY".to_owned(),
            opcode: 1,
            sequence_index: 0,
            sequence_time: 0,
            source_address: instruction.address.clone(),
            userop_name: None,
            output: Some(register("0x1240", 16)),
            inputs: vec![PcodeVarnode {
                space: "ram".to_owned(),
                offset: "0x700000".to_owned(),
                size: 16,
            }],
        }];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        assert!(artifact.llvm_ir.contains("@hydir_write_varnode_wide"));
        let bytes = (0..16).map(|index| index as u8).collect::<Vec<_>>();
        let mut seed = PcodeConcreteState::default();
        seed.write_memory("ram", 0x700000, 8, 0x0706_0504_0302_0100)
            .unwrap();
        seed.write_memory("ram", 0x700008, 8, 0x0f0e_0d0c_0b0a_0908)
            .unwrap();
        let rust = snapshot.execute_concrete_path(&seed, None, 4, 4).unwrap();
        assert!(matches!(
            rust.stop,
            PcodePathStop::UnresolvedFallthrough { .. }
        ));
        let expected = u128::from_le_bytes(bytes.clone().try_into().unwrap());
        assert_eq!(
            rust.final_state
                .read_varnode_wide(&register("0x1240", 16))
                .unwrap(),
            Some(expected)
        );
        let expected_state = bytes
            .iter()
            .enumerate()
            .map(|(index, byte)| {
                (
                    "register".to_owned(),
                    format!("0x{:x}", 0x1240 + index),
                    *byte,
                    true,
                )
            })
            .collect();
        run_lli_with_guest(
            &artifact,
            &seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x700000,
                bytes: bytes.iter().copied().map(Some).collect(),
                expected: Vec::new(),
                expected_state,
            },
            4,
            PcodeCfgLlvmStatus::UnresolvedFlow,
            &source_event_ids(&artifact, &rust),
            None,
        );
        let mut partial = bytes.iter().copied().map(Some).collect::<Vec<_>>();
        partial[15] = None;
        run_lli_with_guest(
            &artifact,
            &PcodeConcreteState::default(),
            &GuestTestMemory {
                space_id: 433,
                base: 0x700000,
                bytes: partial,
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            4,
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
            &[],
            None,
        );

        snapshot.selected_function.instructions[0].pcode[0].inputs[0].offset =
            "0xfffffffffffffff8".to_owned();
        let overflow = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&overflow.llvm_ir);
        run_lli(
            &overflow,
            &PcodeConcreteState::default(),
            4,
            PcodeCfgLlvmStatus::MemoryAddressOverflow,
            &[],
            None,
        );
    }

    #[test]
    fn stripped_password_secure_equals_uses_file_backed_bytes_in_llvm_replay() {
        let snapshot = stripped_password_secure_equals_fixture();
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let spec = hydir_loader::import_elf(binary).unwrap();
        let phrase_address = 0x2001f0_u64;
        let segment = spec
            .mapped_segments
            .iter()
            .find(|segment| {
                segment.readable
                    && !segment.writable
                    && phrase_address >= segment.virtual_address.0
                    && phrase_address + 12 <= segment.virtual_address.0 + segment.file_size
            })
            .expect("password phrase is in a file-backed read-only segment");
        let file_offset =
            (segment.file_offset.0 + phrase_address - segment.virtual_address.0) as usize;
        let phrase = &binary[file_offset..file_offset + 12];
        assert_eq!(phrase, b"HYDIR-ACCESS");
        let image = PcodeReadOnlyElfImage::from_elf(binary, &snapshot).unwrap();
        let stack = 0x210000_u64;
        let input = 0x210100_u64;
        for first_byte in [b'H', b'h'] {
            let mut candidate = *b"HYDIR-ACCESS";
            candidate[0] = first_byte;
            let expected = u64::from(first_byte == b'H');
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), input).unwrap();
            seed.write_varnode(&register("0x30", 8), 12).unwrap();
            seed.write_varnode(&register("0x20", 8), stack).unwrap();
            seed.write_varnode(&register("0x0", 8), 0).unwrap();
            seed.write_varnode(&register("0x8", 8), 0).unwrap();
            seed.write_memory("ram", stack, 8, 0xdeadbeef).unwrap();
            seed.write_memory(
                "ram",
                input,
                8,
                u64::from_le_bytes(candidate[..8].try_into().unwrap()),
            )
            .unwrap();
            seed.write_memory(
                "ram",
                input + 8,
                4,
                u32::from_le_bytes(candidate[8..12].try_into().unwrap()) as u64,
            )
            .unwrap();
            let rust = snapshot
                .execute_concrete_path_with_image(&seed, &image, None, 1024, 256)
                .unwrap();
            assert!(
                matches!(rust.stop, PcodePathStop::Return { .. }),
                "{:?}",
                rust.stop
            );
            assert_eq!(
                rust.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                Some(expected)
            );
            let mut bytes = vec![None; (input + 12 - phrase_address) as usize];
            let return_bytes = 0xdeadbeefu64.to_le_bytes();
            for (address, source) in [
                (phrase_address, phrase),
                (stack, return_bytes.as_slice()),
                (input, candidate.as_slice()),
            ] {
                for (index, byte) in source.iter().enumerate() {
                    bytes[(address - phrase_address) as usize + index] = Some(*byte);
                }
            }
            run_lli_with_guest(
                &artifact,
                &seed,
                &GuestTestMemory {
                    space_id: 433,
                    base: phrase_address,
                    bytes,
                    expected: Vec::new(),
                    expected_state: Vec::new(),
                },
                1024,
                PcodeCfgLlvmStatus::Return,
                &source_event_ids(&artifact, &rust),
                Some(expected as u8),
            );
        }
    }

    #[test]
    fn image_window_rejects_changed_ghidra_memory_permissions() {
        let mut snapshot = stripped_password_secure_equals_fixture();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let image = PcodeReadOnlyElfImage::from_elf(binary, &snapshot).unwrap();
        let window = image
            .materialize_window(PCODE_CFG_ELF_IMAGE_MAX_BYTES)
            .unwrap();
        assert!(emit_pcode_cfg_llvm_with_image(&snapshot, None, &window).is_ok());
        snapshot.memory_blocks[0].write = !snapshot.memory_blocks[0].write;
        let error = emit_pcode_cfg_llvm_with_image(&snapshot, None, &window).unwrap_err();
        assert!(error.contains("window disagrees with Ghidra snapshot layout"));
    }

    #[test]
    fn stripped_password_secure_equals_two_window_v3_matches_rust() {
        let snapshot = stripped_password_secure_equals_fixture();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let image = PcodeReadOnlyElfImage::from_elf(binary, &snapshot).unwrap();
        let window = image
            .materialize_window(PCODE_CFG_ELF_IMAGE_MAX_BYTES)
            .unwrap();
        assert!(window.base() <= 0x2001f0);
        assert!(window.base() + window.bytes().len() as u64 > 0x2001fb);
        let artifact = emit_pcode_cfg_llvm_with_image(&snapshot, None, &window).unwrap();
        assert_eq!(artifact.schema_version, PCODE_CFG_IMAGE_LLVM_VERSION);
        assert_eq!(artifact.read_only_image.as_ref().unwrap().space, "ram");
        assert!(artifact.state_abi.starts_with("hydir-pcode-cfg-state-v3"));
        assert!(artifact.llvm_ir.contains("@hydir_elf_image_bytes"));
        verify(&artifact.llvm_ir);
        let stack = 0x700000_u64;
        let input = 0x700100_u64;
        for first_byte in [b'H', b'h'] {
            let mut candidate = *b"HYDIR-ACCESS";
            candidate[0] = first_byte;
            let expected = u64::from(first_byte == b'H');
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), input).unwrap();
            seed.write_varnode(&register("0x30", 8), 12).unwrap();
            seed.write_varnode(&register("0x20", 8), stack).unwrap();
            seed.write_varnode(&register("0x0", 8), 0).unwrap();
            seed.write_varnode(&register("0x8", 8), 0).unwrap();
            seed.write_memory("ram", stack, 8, 0xdeadbeef).unwrap();
            seed.write_memory(
                "ram",
                input,
                8,
                u64::from_le_bytes(candidate[..8].try_into().unwrap()),
            )
            .unwrap();
            seed.write_memory(
                "ram",
                input + 8,
                4,
                u32::from_le_bytes(candidate[8..12].try_into().unwrap()) as u64,
            )
            .unwrap();
            let rust = snapshot
                .execute_concrete_path_with_image(&seed, &image, None, 1024, 256)
                .unwrap();
            assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
            assert_eq!(
                rust.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                Some(expected)
            );
            let mut guest = vec![None; (input + 12 - stack) as usize];
            for (address, source) in [
                (stack, 0xdeadbeefu64.to_le_bytes().as_slice()),
                (input, candidate.as_slice()),
            ] {
                for (index, byte) in source.iter().enumerate() {
                    guest[(address - stack) as usize + index] = Some(*byte);
                }
            }
            run_lli_with_guest(
                &artifact,
                &seed,
                &GuestTestMemory {
                    space_id: 433,
                    base: stack,
                    bytes: guest,
                    expected: Vec::new(),
                    expected_state: Vec::new(),
                },
                1024,
                PcodeCfgLlvmStatus::Return,
                &source_event_ids(&artifact, &rust),
                Some(expected as u8),
            );
        }
    }

    #[test]
    fn image_window_boundaries_and_legacy_v2_artifact_are_explicit() {
        let snapshot = stripped_password_secure_equals_fixture();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let image = PcodeReadOnlyElfImage::from_elf(binary, &snapshot).unwrap();
        let window = image
            .materialize_window(PCODE_CFG_ELF_IMAGE_MAX_BYTES)
            .unwrap();
        let artifact = emit_pcode_cfg_llvm_with_image(&snapshot, None, &window).unwrap();
        let legacy = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        assert_eq!(legacy.schema_version, PCODE_CFG_LLVM_VERSION);
        assert!(!legacy.llvm_ir.contains("@hydir_elf_image_bytes"));
        assert!(!legacy.llvm_ir.contains("stop_memory_read_only"));
        assert!(
            serde_json::to_value(&legacy)
                .unwrap()
                .get("read_only_image")
                .is_none()
        );
        verify(&artifact.llvm_ir);
        run_lli_with_guest(
            &artifact,
            &PcodeConcreteState::default(),
            &GuestTestMemory {
                space_id: 433,
                base: 0x2001f0,
                bytes: vec![Some(b'H')],
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            32,
            PcodeCfgLlvmStatus::InvalidArguments,
            &[],
            None,
        );
        run_lli_with_guest(
            &artifact,
            &PcodeConcreteState::default(),
            &GuestTestMemory {
                space_id: 42,
                base: 0x700000,
                bytes: vec![None; 8],
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            32,
            PcodeCfgLlvmStatus::InvalidArguments,
            &[],
            None,
        );

        let mut synthetic = snapshot.clone();
        let instruction = &mut synthetic.selected_function.instructions[0];
        instruction.pcode.truncate(1);
        let operation = &mut instruction.pcode[0];
        operation.mnemonic = "STORE".into();
        operation.opcode = 3;
        operation.output = None;
        operation.inputs = vec![
            PcodeVarnode {
                space: "const".into(),
                offset: "0x1b1".into(),
                size: 4,
            },
            PcodeVarnode {
                space: "const".into(),
                offset: "0x2001f0".into(),
                size: 8,
            },
            PcodeVarnode {
                space: "const".into(),
                offset: "0x58".into(),
                size: 1,
            },
        ];
        let store_artifact = emit_pcode_cfg_llvm_with_image(&synthetic, None, &window).unwrap();
        verify(&store_artifact.llvm_ir);
        assert!(
            store_artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MemoryReadOnly)
        );
        let empty_guest = GuestTestMemory {
            space_id: 433,
            base: 0x700000,
            bytes: Vec::new(),
            expected: Vec::new(),
            expected_state: Vec::new(),
        };
        run_lli_with_guest(
            &store_artifact,
            &PcodeConcreteState::default(),
            &empty_guest,
            32,
            PcodeCfgLlvmStatus::MemoryReadOnly,
            &[],
            None,
        );
        synthetic.selected_function.instructions[0].pcode[0].inputs[1].offset = "0x2001e4".into();
        let gap_store = emit_pcode_cfg_llvm_with_image(&synthetic, None, &window).unwrap();
        run_lli_with_guest(
            &gap_store,
            &PcodeConcreteState::default(),
            &empty_guest,
            32,
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
            &[],
            None,
        );
        let operation = &mut synthetic.selected_function.instructions[0].pcode[0];
        operation.mnemonic = "LOAD".into();
        operation.opcode = 2;
        operation.inputs.truncate(2);
        operation.output = Some(PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 1,
        });
        let gap_load = emit_pcode_cfg_llvm_with_image(&synthetic, None, &window).unwrap();
        run_lli_with_guest(
            &gap_load,
            &PcodeConcreteState::default(),
            &empty_guest,
            32,
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
            &[],
            None,
        );
    }

    #[test]
    fn process_memory_v4_load_store_permissions_and_guest_bounds() {
        let mut snapshot = stripped_password_secure_equals_fixture();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let process = PcodeElfProcessMemory::from_elf(binary, &snapshot, 64 * 1024).unwrap();
        assert_eq!(process.initial_byte("ram", 0x2028f0), Some(0));
        let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
        operation.opcode = 2;
        operation.mnemonic = "LOAD".into();
        operation.inputs = vec![
            PcodeVarnode {
                space: "const".into(),
                offset: "0x1b1".into(),
                size: 4,
            },
            PcodeVarnode {
                space: "const".into(),
                offset: "0x2028f0".into(),
                size: 8,
            },
        ];
        operation.output = Some(PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 1,
        });
        snapshot.selected_function.instructions[0].pcode.truncate(1);
        let load = emit_pcode_cfg_llvm_with_process_memory(&snapshot, None, &process).unwrap();
        assert_eq!(load.schema_version, PCODE_CFG_PROCESS_LLVM_VERSION);
        assert!(load.state_abi.starts_with("hydir-pcode-cfg-state-v4"));
        assert_eq!(load.process_memory.as_ref().unwrap().base, process.base());
        assert!(load.read_only_image.is_none());
        verify(&load.llvm_ir);
        run_lli_with_guest(
            &load,
            &PcodeConcreteState::default(),
            &GuestTestMemory {
                space_id: 433,
                base: 0x700000,
                bytes: Vec::new(),
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            1,
            PcodeCfgLlvmStatus::StepBudget,
            &[0],
            Some(0),
        );
        run_lli_with_guest(
            &load,
            &PcodeConcreteState::default(),
            &GuestTestMemory {
                space_id: 433,
                base: process.base(),
                bytes: vec![None],
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            8,
            PcodeCfgLlvmStatus::InvalidArguments,
            &[],
            None,
        );

        let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
        operation.opcode = 3;
        operation.mnemonic = "STORE".into();
        operation.inputs.push(PcodeVarnode {
            space: "const".into(),
            offset: "0x5a".into(),
            size: 1,
        });
        operation.output = None;
        let store = emit_pcode_cfg_llvm_with_process_memory(&snapshot, None, &process).unwrap();
        verify(&store.llvm_ir);
        run_lli(
            &store,
            &PcodeConcreteState::default(),
            1,
            PcodeCfgLlvmStatus::StepBudget,
            &[0],
            None,
        );
        assert_eq!(process.initial_byte("ram", 0x2028f0), Some(0));

        let mut load_after_store = snapshot.selected_function.instructions[0].pcode[0].clone();
        load_after_store.sequence_index = 1;
        load_after_store.sequence_time += 1;
        load_after_store.opcode = 2;
        load_after_store.mnemonic = "LOAD".into();
        load_after_store.inputs.truncate(2);
        load_after_store.output = Some(PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 1,
        });
        snapshot.selected_function.instructions[0]
            .pcode
            .push(load_after_store);
        let roundtrip = emit_pcode_cfg_llvm_with_process_memory(&snapshot, None, &process).unwrap();
        verify(&roundtrip.llvm_ir);
        run_lli(
            &roundtrip,
            &PcodeConcreteState::default(),
            2,
            PcodeCfgLlvmStatus::StepBudget,
            &[0, 1],
            Some(0x5a),
        );
        snapshot.selected_function.instructions[0].pcode.truncate(1);

        let mut direct_copy = snapshot.clone();
        let operation = &mut direct_copy.selected_function.instructions[0].pcode[0];
        operation.opcode = 1;
        operation.mnemonic = "COPY".into();
        operation.inputs = vec![PcodeVarnode {
            space: "ram".into(),
            offset: "0x2028f0".into(),
            size: 16,
        }];
        operation.output = Some(PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 16,
        });
        let direct_copy =
            emit_pcode_cfg_llvm_with_process_memory(&direct_copy, None, &process).unwrap();
        verify(&direct_copy.llvm_ir);
        run_lli(
            &direct_copy,
            &PcodeConcreteState::default(),
            1,
            PcodeCfgLlvmStatus::StepBudget,
            &[0],
            Some(0),
        );

        snapshot.selected_function.instructions[0].pcode[0].inputs[1].offset = "0x2001f0".into();
        let readonly = emit_pcode_cfg_llvm_with_process_memory(&snapshot, None, &process).unwrap();
        verify(&readonly.llvm_ir);
        run_lli(
            &readonly,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::MemoryReadOnly,
            &[],
            None,
        );

        let mixed_index = (0..process.mapped().len() - 1)
            .find(|&index| {
                process.mapped()[index] == 0xff
                    && process.writable()[index] == 0
                    && process.mapped()[index + 1] == 0
            })
            .expect("fixture has a read-only mapping followed by a gap");
        let mixed_address = process.base() + mixed_index as u64;
        let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
        operation.inputs[1].offset = format!("0x{mixed_address:x}");
        operation.inputs[2].size = 2;
        let rust = snapshot
            .execute_concrete_path_with_process_memory(
                &PcodeConcreteState::default(),
                &process,
                None,
                1,
                4,
            )
            .unwrap();
        assert!(matches!(
            rust.stop,
            PcodePathStop::EffectBoundary {
                boundary: PcodeExecutionStop::MemoryBoundary {
                    reason: PcodeMemoryBoundaryKind::ReadOnlyImageWrite,
                    ..
                }
            }
        ));
        let mixed = emit_pcode_cfg_llvm_with_process_memory(&snapshot, None, &process).unwrap();
        verify(&mixed.llvm_ir);
        assert!(mixed.stop_sites.iter().any(|site| {
            site.status == PcodeCfgLlvmStatus::MemoryUnknownBytes && site.operation_index == Some(0)
        }));
        run_lli(
            &mixed,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::MemoryReadOnly,
            &[],
            None,
        );

        let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
        operation.inputs[1].offset = format!("0x{:x}", mixed_address + 1);
        operation.inputs[2].size = 1;
        let gap = emit_pcode_cfg_llvm_with_process_memory(&snapshot, None, &process).unwrap();
        verify(&gap.llvm_ir);
        assert!(gap.stop_sites.iter().any(|site| {
            site.status == PcodeCfgLlvmStatus::MemoryUnknownBytes && site.operation_index == Some(0)
        }));
        run_lli(
            &gap,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
            &[],
            None,
        );
    }

    #[test]
    fn allocated_process_v5_stack_boundary_matches_rust_without_partial_write() {
        let mut snapshot = stripped_password_secure_equals_fixture();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let process = PcodeElfProcessMemory::from_elf(binary, &snapshot, 64 * 1024).unwrap();
        let allocations = PcodeProcessAllocations::new(
            &snapshot,
            &process,
            vec![
                PcodeProcessAllocation {
                    kind: PcodeProcessAllocationKind::Stack,
                    space: "ram".into(),
                    base: 0x700000,
                    byte_len: 16,
                },
                PcodeProcessAllocation {
                    kind: PcodeProcessAllocationKind::Heap,
                    space: "ram".into(),
                    base: 0x800000,
                    byte_len: 16,
                },
            ],
        )
        .unwrap();
        let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
        operation.opcode = 3;
        operation.mnemonic = "STORE".into();
        operation.inputs = vec![
            PcodeVarnode {
                space: "const".into(),
                offset: "0x1b1".into(),
                size: 4,
            },
            PcodeVarnode {
                space: "const".into(),
                offset: "0x70000f".into(),
                size: 8,
            },
            PcodeVarnode {
                space: "const".into(),
                offset: "0xbeef".into(),
                size: 2,
            },
        ];
        operation.output = None;
        snapshot.selected_function.instructions[0].pcode.truncate(1);
        let mut seed = PcodeConcreteState::default();
        seed.write_memory("ram", 0x70000f, 1, 0xaa).unwrap();
        let gap = process.base()
            + process
                .mapped()
                .windows(2)
                .position(|pair| pair == [0, 0])
                .expect("fixture has a two-byte unmapped process gap") as u64;
        let mixed = process.base()
            + process
                .mapped()
                .windows(2)
                .enumerate()
                .find(|(index, pair)| pair == &[0xff, 0] && process.writable()[*index] == 0)
                .expect("fixture has a read-only byte followed by a gap")
                .0 as u64;

        for (address, status, event_count, byte14, known14, byte15, heap14, heap15) in [
            (
                0x70000f,
                PcodeCfgLlvmStatus::MemoryUnmappedWrite,
                0,
                0,
                0,
                0xaa,
                0,
                0,
            ),
            (
                0x70000e,
                PcodeCfgLlvmStatus::StepBudget,
                1,
                0xef,
                0xff,
                0xbe,
                0,
                0,
            ),
            (
                0x80000e,
                PcodeCfgLlvmStatus::StepBudget,
                1,
                0,
                0,
                0xaa,
                0xef,
                0xbe,
            ),
            (
                gap,
                PcodeCfgLlvmStatus::MemoryUnmappedWrite,
                0,
                0,
                0,
                0xaa,
                0,
                0,
            ),
            (
                mixed,
                PcodeCfgLlvmStatus::MemoryReadOnly,
                0,
                0,
                0,
                0xaa,
                0,
                0,
            ),
            (
                0x900000,
                PcodeCfgLlvmStatus::MemoryUnknownBytes,
                0,
                0,
                0,
                0xaa,
                0,
                0,
            ),
        ] {
            let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
            operation.inputs[1].offset = format!("0x{address:x}");
            if status == PcodeCfgLlvmStatus::MemoryUnknownBytes {
                operation.opcode = 2;
                operation.mnemonic = "LOAD".into();
                operation.inputs.truncate(2);
                operation.output = Some(PcodeVarnode {
                    space: "register".into(),
                    offset: "0x0".into(),
                    size: 2,
                });
            }
            let rust = snapshot
                .execute_concrete_path_with_allocations(&seed, &process, &allocations, None, 1, 4)
                .unwrap();
            if status != PcodeCfgLlvmStatus::StepBudget {
                let expected_reason = if status == PcodeCfgLlvmStatus::MemoryReadOnly {
                    PcodeMemoryBoundaryKind::ReadOnlyImageWrite
                } else if status == PcodeCfgLlvmStatus::MemoryUnknownBytes {
                    PcodeMemoryBoundaryKind::UnknownBytes
                } else {
                    PcodeMemoryBoundaryKind::UnmappedWrite
                };
                assert!(matches!(
                    rust.stop,
                    PcodePathStop::EffectBoundary {
                        boundary: PcodeExecutionStop::MemoryBoundary {
                            reason,
                            ..
                        }
                    } if reason == expected_reason
                ));
                assert_eq!(
                    rust.final_state.read_memory("ram", 0x70000f, 1).unwrap(),
                    Some(0xaa)
                );
                if address == 0x70000f {
                    assert_eq!(
                        rust.final_state.read_memory("ram", 0x700010, 1).unwrap(),
                        None
                    );
                }
            } else {
                assert_eq!(
                    rust.final_state.read_memory("ram", address, 2).unwrap(),
                    Some(0xbeef)
                );
            }
            let artifact =
                emit_pcode_cfg_llvm_with_allocations(&snapshot, None, &process, &allocations)
                    .unwrap();
            assert_eq!(
                artifact.schema_version,
                PCODE_CFG_ALLOCATED_PROCESS_LLVM_VERSION
            );
            assert_eq!(artifact.allocations.as_ref(), Some(&allocations));
            if status != PcodeCfgLlvmStatus::MemoryUnknownBytes {
                assert!(artifact.stop_sites.iter().any(|site| {
                    site.status == PcodeCfgLlvmStatus::MemoryUnmappedWrite
                        && site.address
                            == snapshot.selected_function.instructions[0].pcode[0].source_address
                }));
            }
            verify(&artifact.llvm_ir);
            if Command::new("lli").arg("--version").output().is_err() {
                continue;
            }
            let state_size = artifact.state_bytes.max(1);
            let main = format!(
                "define i32 @main() {{\nentry:\n\
                 %state = alloca [{state_size} x i8]\n  %known = alloca [{state_size} x i8]\n\
                 %stack = alloca [16 x i8]\n  %stack_known = alloca [16 x i8]\n\
                 %heap = alloca [16 x i8]\n  %heap_known = alloca [16 x i8]\n\
                 %events = alloca [1 x i32]\n  %count = alloca i32\n\
                 call void @llvm.memset.p0.i64(ptr %state, i8 0, i64 {state_size}, i1 false)\n\
                 call void @llvm.memset.p0.i64(ptr %known, i8 0, i64 {state_size}, i1 false)\n\
                 call void @llvm.memset.p0.i64(ptr %stack, i8 0, i64 16, i1 false)\n\
                 call void @llvm.memset.p0.i64(ptr %stack_known, i8 0, i64 16, i1 false)\n\
                 call void @llvm.memset.p0.i64(ptr %heap, i8 0, i64 16, i1 false)\n\
                 call void @llvm.memset.p0.i64(ptr %heap_known, i8 0, i64 16, i1 false)\n\
                 %last = getelementptr i8, ptr %stack, i64 15\n  store i8 -86, ptr %last\n\
                 %last_known = getelementptr i8, ptr %stack_known, i64 15\n  store i8 -1, ptr %last_known\n\
                 %status = call i32 @hydir_pcode_cfg(ptr %state, ptr %known, i32 433, ptr %stack, ptr %stack_known, i64 7340032, i64 16, ptr %heap, ptr %heap_known, i64 8388608, i64 16, ptr %events, ptr %count, i32 1, i32 1)\n\
                 %actual_count = load i32, ptr %count\n\
                 %a14 = getelementptr i8, ptr %stack, i64 14\n  %v14 = load i8, ptr %a14\n\
                 %k14 = getelementptr i8, ptr %stack_known, i64 14\n  %m14 = load i8, ptr %k14\n\
                 %v15 = load i8, ptr %last\n\
                 %h14 = getelementptr i8, ptr %heap, i64 14\n  %hv14 = load i8, ptr %h14\n\
                 %h15 = getelementptr i8, ptr %heap, i64 15\n  %hv15 = load i8, ptr %h15\n\
                 %ok_status = icmp eq i32 %status, {}\n\
                 %ok_count = icmp eq i32 %actual_count, {event_count}\n\
                 %ok14 = icmp eq i8 %v14, {byte14}\n\
                 %okm14 = icmp eq i8 %m14, {known14}\n\
                 %ok15 = icmp eq i8 %v15, {byte15}\n\
                 %okh14 = icmp eq i8 %hv14, {heap14}\n\
                 %okh15 = icmp eq i8 %hv15, {heap15}\n\
                 %ok_a = and i1 %ok_status, %ok_count\n\
                 %ok_b = and i1 %ok14, %okm14\n\
                 %ok_c = and i1 %ok_a, %ok_b\n\
                 %ok_d = and i1 %okh14, %okh15\n\
                 %ok_e = and i1 %ok_c, %ok_d\n\
                 %ok = and i1 %ok_e, %ok15\n\
                 %failed = xor i1 %ok, true\n  %result = zext i1 %failed to i32\n  ret i32 %result\n}}\n",
                status.code()
            );
            let module = format!(
                "{}\ndeclare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n{main}",
                artifact.llvm_ir
            );
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), module).unwrap();
            let output = Command::new("lli").arg(file.path()).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn allocated_interprocedural_calls_match_rust_and_stop_on_stack_boundary() {
        let snapshots = choose_call_snapshots();
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_choose_calls.elf"
        ));
        let process = PcodeElfProcessMemory::from_elf(binary, &snapshots[0], 64 * 1024).unwrap();
        for (argument, expected_rax, call_site, return_low) in [
            (1u64, 2u8, "0x201179", 0x7e_u8),
            (0u64, 1u8, "0x20117f", 0x84_u8),
        ] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), argument).unwrap();
            seed.write_varnode(&register("0x20", 8), 0x700000).unwrap();
            seed.write_memory("ram", 0x700000, 8, 0x201195).unwrap();
            for (stack_base, stack_len, expected_status, expected_first, expected_known) in [
                (
                    0x6ffff8_u64,
                    16_u64,
                    PcodeCfgLlvmStatus::Return,
                    return_low,
                    255_u8,
                ),
                (
                    0x6ffffc_u64,
                    12_u64,
                    PcodeCfgLlvmStatus::MemoryUnmappedWrite,
                    0,
                    0,
                ),
            ] {
                let allocations = PcodeProcessAllocations::new(
                    &snapshots[0],
                    &process,
                    vec![PcodeProcessAllocation {
                        kind: PcodeProcessAllocationKind::Stack,
                        space: "ram".into(),
                        base: stack_base,
                        byte_len: stack_len,
                    }],
                )
                .unwrap();
                let rust = hydir_ir::pcode::execute_concrete_call_path_with_allocations(
                    &snapshots,
                    &seed,
                    &process,
                    &allocations,
                    128,
                    16,
                    4,
                )
                .unwrap();
                let artifact = emit_pcode_interprocedural_cfg_llvm_with_allocations(
                    &snapshots,
                    4,
                    &process,
                    &allocations,
                )
                .unwrap();
                assert_eq!(
                    artifact.schema_version,
                    PCODE_INTERPROCEDURAL_ALLOCATED_PROCESS_CFG_LLVM_VERSION
                );
                assert_eq!(
                    artifact.llvm.schema_version,
                    PCODE_CFG_ALLOCATED_PROCESS_LLVM_VERSION
                );
                assert_eq!(artifact.llvm.allocations.as_ref(), Some(&allocations));
                assert_eq!(
                    rust.process_binding.as_ref().unwrap().allocations,
                    allocations
                );
                verify(&artifact.llvm.llvm_ir);
                let expected_events = if expected_status == PcodeCfgLlvmStatus::Return {
                    assert_eq!(rust.calls.len(), 1);
                    assert_eq!(
                        rust.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                        Some(expected_rax as u64)
                    );
                    call_event_ids(&artifact.llvm, &rust)
                } else {
                    assert_eq!(rust.calls.len(), 0);
                    assert!(matches!(
                        rust.stop,
                        hydir_ir::pcode::PcodeCallPathStop::PathBoundary {
                            stop: PcodePathStop::EffectBoundary {
                                boundary: PcodeExecutionStop::MemoryBoundary {
                                    reason: PcodeMemoryBoundaryKind::UnmappedWrite,
                                    ..
                                }
                            }
                        }
                    ));
                    assert!(artifact.llvm.stop_sites.iter().any(|site| {
                        site.status == PcodeCfgLlvmStatus::MemoryUnmappedWrite
                            && site.address.offset == call_site
                            && site.operation_index == Some(1)
                    }));
                    source_event_ids(&artifact.llvm, &rust.segments[0].path)
                };
                if Command::new("lli").arg("--version").output().is_err() {
                    continue;
                }
                let state_len = artifact.llvm.state_bytes.max(1);
                let mut main = format!(
                    "define i32 @main() {{\nentry:\n  %state = alloca [{state_len} x i8]\n  %known = alloca [{state_len} x i8]\n  %stack = alloca [{stack_len} x i8]\n  %stack_known = alloca [{stack_len} x i8]\n  %heap = alloca [1 x i8]\n  %heap_known = alloca [1 x i8]\n  %events = alloca [128 x i32]\n  %count = alloca i32\n"
                );
                for byte in &artifact.llvm.byte_map {
                    let value = seed
                        .read_varnode(&PcodeVarnode {
                            space: byte.space.clone(),
                            offset: byte.offset.clone(),
                            size: 1,
                        })
                        .unwrap();
                    main.push_str(&format!(
                        "  %s{} = getelementptr i8, ptr %state, i64 {}\n  store i8 {}, ptr %s{}\n  %k{} = getelementptr i8, ptr %known, i64 {}\n  store i8 {}, ptr %k{}\n",
                        byte.index, byte.index, value.unwrap_or(0), byte.index,
                        byte.index, byte.index, if value.is_some() { 255 } else { 0 }, byte.index
                    ));
                }
                for index in 0..stack_len {
                    let value = seed.read_memory("ram", stack_base + index, 1).unwrap();
                    main.push_str(&format!(
                        "  %ss{index} = getelementptr i8, ptr %stack, i64 {index}\n  store i8 {}, ptr %ss{index}\n  %sk{index} = getelementptr i8, ptr %stack_known, i64 {index}\n  store i8 {}, ptr %sk{index}\n",
                        value.unwrap_or(0), if value.is_some() { 255 } else { 0 }
                    ));
                }
                main.push_str(&format!(
                    "  %status = call i32 @hydir_pcode_cfg(ptr %state, ptr %known, i32 433, ptr %stack, ptr %stack_known, i64 {stack_base}, i64 {stack_len}, ptr %heap, ptr %heap_known, i64 0, i64 0, ptr %events, ptr %count, i32 128, i32 128)\n  %count_value = load i32, ptr %count\n  %status_ok = icmp eq i32 %status, {}\n  %count_ok = icmp eq i32 %count_value, {}\n  %ok0 = and i1 %status_ok, %count_ok\n",
                    expected_status.code(), expected_events.len()
                ));
                let mut last = "%ok0".to_owned();
                for (index, event) in expected_events.iter().enumerate() {
                    main.push_str(&format!(
                        "  %event_ptr{index} = getelementptr i32, ptr %events, i64 {index}\n  %event_value{index} = load i32, ptr %event_ptr{index}\n  %event_ok{index} = icmp eq i32 %event_value{index}, {event}\n  %ok_event{index} = and i1 {last}, %event_ok{index}\n"
                    ));
                    last = format!("%ok_event{index}");
                }
                main.push_str(&format!(
                    "  %first = load i8, ptr %stack\n  %first_known = load i8, ptr %stack_known\n  %first_ok = icmp eq i8 %first, {expected_first}\n  %known_ok = icmp eq i8 %first_known, {expected_known}\n  %stack_ok = and i1 %first_ok, %known_ok\n  %ok_stack = and i1 {last}, %stack_ok\n"
                ));
                let mut last = "%ok_stack".to_owned();
                if expected_status == PcodeCfgLlvmStatus::Return {
                    let rax = artifact
                        .llvm
                        .byte_map
                        .iter()
                        .find(|byte| byte.space == "register" && byte.offset == "0x0")
                        .unwrap();
                    main.push_str(&format!(
                        "  %rax_ptr = getelementptr i8, ptr %state, i64 {}\n  %rax_low = load i8, ptr %rax_ptr\n  %rax_ok = icmp eq i8 %rax_low, {expected_rax}\n  %ok_rax = and i1 {last}, %rax_ok\n",
                        rax.index
                    ));
                    last = "%ok_rax".to_owned();
                }
                main.push_str(&format!(
                    "  %failed = xor i1 {last}, true\n  %exit = zext i1 %failed to i32\n  ret i32 %exit\n}}\n"
                ));
                let module = format!("{}\n{main}", artifact.llvm.llvm_ir);
                let file = tempfile::NamedTempFile::new().unwrap();
                std::fs::write(file.path(), module).unwrap();
                let output = Command::new("lli").arg(file.path()).output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    #[test]
    fn allocated_interprocedural_llvm_marks_plt_call_source() {
        let mut snapshots = choose_call_snapshots();
        for snapshot in &mut snapshots {
            snapshot
                .memory_blocks
                .iter_mut()
                .find(|block| block.name == ".text")
                .unwrap()
                .name = ".plt".into();
        }
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_choose_calls.elf"
        ));
        let process = PcodeElfProcessMemory::from_elf(binary, &snapshots[0], 64 * 1024).unwrap();
        let allocations = PcodeProcessAllocations::new(
            &snapshots[0],
            &process,
            vec![PcodeProcessAllocation {
                kind: PcodeProcessAllocationKind::Stack,
                space: "ram".into(),
                base: 0x6ffff8,
                byte_len: 16,
            }],
        )
        .unwrap();
        let artifact = emit_pcode_interprocedural_cfg_llvm_with_allocations(
            &snapshots,
            4,
            &process,
            &allocations,
        )
        .unwrap();
        assert!(artifact.llvm.stop_sites.iter().any(|site| {
            site.status == PcodeCfgLlvmStatus::Call
                && site.address.offset == "0x201179"
                && site.reason.contains("internal executable")
        }));
        verify(&artifact.llvm.llvm_ir);
    }

    #[test]
    fn interprocedural_direct_call_llvm_matches_shared_rust_state() {
        let snapshots = call_snapshots();
        let artifact = emit_pcode_interprocedural_cfg_llvm(&snapshots, 4).unwrap();
        assert_eq!(artifact.function_entries.len(), 2);
        assert_eq!(artifact.snapshot_sha256.len(), 2);
        assert_eq!(artifact.llvm.semantic_fidelity, SemanticFidelity::Unknown);
        verify(&artifact.llvm.llvm_ir);
        for (a, b) in [(0u64, 0u64), (7, 5), (u64::MAX, 1)] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), a).unwrap();
            seed.write_varnode(&register("0x30", 8), b).unwrap();
            seed.write_varnode(&register("0x20", 8), 0x700000).unwrap();
            seed.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
            let rust =
                hydir_ir::pcode::execute_concrete_call_path(&snapshots, &seed, 128, 16, 4).unwrap();
            assert!(matches!(
                rust.stop,
                hydir_ir::pcode::PcodeCallPathStop::Return { .. }
            ));
            run_lli_with_guest(
                &artifact.llvm,
                &seed,
                &GuestTestMemory {
                    space_id: 433,
                    base: 0x6ffff0,
                    bytes: vec![
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        Some(0xef),
                        Some(0xbe),
                        Some(0xad),
                        Some(0xde),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(0),
                    ],
                    expected: Vec::new(),
                    expected_state: Vec::new(),
                },
                128,
                PcodeCfgLlvmStatus::Return,
                &call_event_ids(&artifact.llvm, &rust),
                Some(a.wrapping_add(b) as u8),
            );
        }
        let mut alternate_spelling = snapshots.clone();
        alternate_spelling[0].selected_function.call_targets[0]
            .call_site
            .offset = "0x002013ad".to_owned();
        let alternate = emit_pcode_interprocedural_cfg_llvm(&alternate_spelling, 4).unwrap();
        assert!(
            alternate
                .llvm
                .stop_sites
                .iter()
                .all(|site| !site.reason.contains("disagrees with Ghidra call evidence"))
        );
    }

    #[test]
    fn interprocedural_computed_call_llvm_matches_rust_and_reports_missing_callee() {
        let digest = "9568944aec254be3cb78235667b0575d3104cd063101428abc4055dacb067582";
        let snapshots = [
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_root_v2.json"
            ))
            .as_slice(),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_leaf_v2.json"
            ))
            .as_slice(),
        ]
        .into_iter()
        .map(|bytes| parse_ghidra_snapshot(bytes, digest).unwrap())
        .collect::<Vec<_>>();
        let seed = hydir_ir::pcode::parse_pcode_seed(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_seed_v1.json"
            )),
            &snapshots[0],
        )
        .unwrap();
        let artifact = emit_pcode_interprocedural_cfg_llvm(&snapshots, 4).unwrap();
        verify(&artifact.llvm.llvm_ir);
        let rust =
            hydir_ir::pcode::execute_concrete_call_path(&snapshots, &seed, 128, 16, 4).unwrap();
        let guest = GuestTestMemory {
            space_id: 433,
            base: 0x6ffff8,
            bytes: vec![
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(0xef),
                Some(0xbe),
                Some(0xad),
                Some(0xde),
                Some(0),
                Some(0),
                Some(0),
                Some(0),
            ],
            expected: Vec::new(),
            expected_state: Vec::new(),
        };
        run_lli_with_guest(
            &artifact.llvm,
            &seed,
            &guest,
            128,
            PcodeCfgLlvmStatus::Return,
            &call_event_ids(&artifact.llvm, &rust),
            Some(7),
        );

        let missing = emit_pcode_interprocedural_cfg_llvm(&snapshots[..1], 4).unwrap();
        verify(&missing.llvm.llvm_ir);
        assert!(
            missing
                .llvm
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::Call
                    && site.reason.contains("not a loaded"))
        );
        let rust_missing =
            hydir_ir::pcode::execute_concrete_call_path(&snapshots[..1], &seed, 128, 16, 4)
                .unwrap();
        let expected = source_event_ids(&missing.llvm, &rust_missing.segments[0].path);
        run_lli_with_guest(
            &missing.llvm,
            &seed,
            &guest,
            128,
            PcodeCfgLlvmStatus::Call,
            &expected,
            Some(0x74),
        );

        let mut recursive_seed = seed.clone();
        recursive_seed
            .write_varnode(&register("0x0", 8), 0x20117c)
            .unwrap();
        let recursive =
            hydir_ir::pcode::execute_concrete_call_path(&snapshots, &recursive_seed, 128, 16, 4)
                .unwrap();
        assert!(matches!(recursive.stop,
            hydir_ir::pcode::PcodeCallPathStop::CallBoundary { ref reason, .. }
                if reason.contains("recursive")));
        run_lli_with_guest(
            &artifact.llvm,
            &recursive_seed,
            &guest,
            128,
            PcodeCfgLlvmStatus::RecursiveCall,
            &source_event_ids(&artifact.llvm, &recursive.segments[0].path),
            Some(0x7c),
        );

        let depth_zero = emit_pcode_interprocedural_cfg_llvm(&snapshots[..1], 0).unwrap();
        let no_depth =
            hydir_ir::pcode::execute_concrete_call_path(&snapshots[..1], &seed, 128, 16, 0)
                .unwrap();
        run_lli_with_guest(
            &depth_zero.llvm,
            &seed,
            &guest,
            128,
            PcodeCfgLlvmStatus::CallDepth,
            &source_event_ids(&depth_zero.llvm, &no_depth.segments[0].path),
            Some(0x74),
        );
    }

    #[test]
    fn interprocedural_return_width_and_cross_function_fallthrough_stop() {
        let mut snapshots = call_snapshots();
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x38", 8), 7).unwrap();
        seed.write_varnode(&register("0x30", 8), 5).unwrap();
        seed.write_varnode(&register("0x20", 8), 0x700000).unwrap();
        seed.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
        let guest = GuestTestMemory {
            space_id: 433,
            base: 0x6ffff0,
            bytes: vec![
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(0xef),
                Some(0xbe),
                Some(0xad),
                Some(0xde),
                Some(0),
                Some(0),
                Some(0),
                Some(0),
            ],
            expected: Vec::new(),
            expected_state: Vec::new(),
        };
        let leaf_return = snapshots[1]
            .selected_function
            .instructions
            .last_mut()
            .unwrap()
            .pcode
            .last_mut()
            .unwrap();
        assert_eq!(leaf_return.mnemonic, "RETURN");
        leaf_return.inputs[0].size = 4;
        let mismatch =
            hydir_ir::pcode::execute_concrete_call_path(&snapshots, &seed, 128, 16, 4).unwrap();
        assert!(matches!(
            mismatch.stop,
            hydir_ir::pcode::PcodeCallPathStop::ReturnBoundary { .. }
        ));
        let artifact = emit_pcode_interprocedural_cfg_llvm(&snapshots, 4).unwrap();
        verify(&artifact.llvm.llvm_ir);
        let mut expected = source_event_ids(&artifact.llvm, &mismatch.segments[0].path);
        let call = mismatch.segments[0].path.stop.clone();
        let PcodePathStop::Call { source } = call else {
            panic!("expected CALL");
        };
        expected.push(
            artifact
                .llvm
                .source_operations
                .iter()
                .position(|candidate| {
                    candidate.address == source.source_address
                        && candidate.operation_index == source.sequence_index as usize
                })
                .unwrap(),
        );
        expected.extend(source_event_ids(&artifact.llvm, &mismatch.segments[1].path));
        run_lli_with_guest(
            &artifact.llvm,
            &seed,
            &guest,
            128,
            PcodeCfgLlvmStatus::ReturnMismatch,
            &expected,
            Some(12),
        );

        let mut snapshots = call_snapshots();
        let leaf_entry = snapshots[1].selected_function.entry.clone();
        let edge = snapshots[0]
            .selected_function
            .flow_edges
            .iter_mut()
            .find(|edge| {
                edge.source.offset == "0x2013a9" && edge.kind == GhidraFlowKind::Fallthrough
            })
            .unwrap();
        edge.target = Some(leaf_entry);
        let artifact = emit_pcode_interprocedural_cfg_llvm(&snapshots, 4).unwrap();
        verify(&artifact.llvm.llvm_ir);
        let rust = snapshots[0]
            .execute_concrete_path(&seed, None, 128, 16)
            .unwrap();
        assert!(matches!(
            rust.stop,
            PcodePathStop::FallthroughTargetNotSelected { .. }
        ));
        run_lli(
            &artifact.llvm,
            &seed,
            128,
            PcodeCfgLlvmStatus::OutOfFunction,
            &source_event_ids(&artifact.llvm, &rust),
            None,
        );
    }

    fn indirect_jump_fixture() -> GhidraSnapshot {
        parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_indirect_jump_v2.json"
            )),
            "66c6db98e7a88b6434437935e7fcc0bcf960fc5eace744e4d435f65dd253760e",
        )
        .unwrap()
    }

    fn register(offset: &str, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: "register".into(),
            offset: offset.into(),
            size,
        }
    }

    fn source_event_ids(
        artifact: &PcodeCfgLlvmArtifact,
        trace: &hydir_ir::pcode::PcodePathTrace,
    ) -> Vec<usize> {
        trace
            .events
            .iter()
            .filter_map(|event| match event {
                PcodePathEvent::Effect { operation } => Some(&operation.source),
                PcodePathEvent::Branch { source, .. } => Some(source),
                PcodePathEvent::Fallthrough { .. } => None,
            })
            .map(|source| {
                artifact
                    .source_operations
                    .iter()
                    .position(|candidate| {
                        candidate.address == source.source_address
                            && candidate.operation_index == source.sequence_index as usize
                    })
                    .unwrap()
            })
            .collect()
    }

    fn verify(llvm: &str) {
        if Command::new("opt").arg("--version").output().is_err() {
            return;
        }
        let mut child = Command::new("opt")
            .args(["-passes=verify", "-disable-output", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(llvm.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{llvm}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    struct GuestTestMemory {
        space_id: i32,
        base: u64,
        bytes: Vec<Option<u8>>,
        expected: Vec<(usize, u8, bool)>,
        expected_state: Vec<(String, String, u8, bool)>,
    }

    fn run_lli(
        artifact: &PcodeCfgLlvmArtifact,
        seed: &PcodeConcreteState,
        max_steps: u32,
        expected_status: PcodeCfgLlvmStatus,
        expected_events: &[usize],
        expected_rax_low: Option<u8>,
    ) {
        run_lli_with_guest(
            artifact,
            seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0,
                bytes: Vec::new(),
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            max_steps,
            expected_status,
            expected_events,
            expected_rax_low,
        );
    }

    fn run_lli_with_guest(
        artifact: &PcodeCfgLlvmArtifact,
        seed: &PcodeConcreteState,
        guest: &GuestTestMemory,
        max_steps: u32,
        expected_status: PcodeCfgLlvmStatus,
        expected_events: &[usize],
        expected_rax_low: Option<u8>,
    ) {
        if Command::new("lli").arg("--version").output().is_err() {
            return;
        }
        let state_size = artifact.state_bytes.max(1);
        let guest_size = guest.bytes.len().max(1);
        let event_capacity = max_steps.max(1);
        let mut main = format!(
            "define i32 @main() {{\nentry:\n  %state_array = alloca [{state_size} x i8]\n\
               %state = getelementptr [{state_size} x i8], ptr %state_array, i64 0, i64 0\n\
               %known_array = alloca [{state_size} x i8]\n\
               %known = getelementptr [{state_size} x i8], ptr %known_array, i64 0, i64 0\n\
               %guest_array = alloca [{guest_size} x i8]\n\
               %guest = getelementptr [{guest_size} x i8], ptr %guest_array, i64 0, i64 0\n\
               %guest_known_array = alloca [{guest_size} x i8]\n\
               %guest_mask = getelementptr [{guest_size} x i8], ptr %guest_known_array, i64 0, i64 0\n\
               %events_array = alloca [{event_capacity} x i32]\n\
               %events = getelementptr [{event_capacity} x i32], ptr %events_array, i64 0, i64 0\n\
                %event_count = alloca i32\n\
                store i32 0, ptr %event_count\n\
                call void @llvm.memset.p0.i64(ptr %guest, i8 0, i64 {guest_size}, i1 false)\n\
                call void @llvm.memset.p0.i64(ptr %guest_mask, i8 0, i64 {guest_size}, i1 false)\n"
        );
        for byte in &artifact.byte_map {
            let known = seed
                .read_varnode(&PcodeVarnode {
                    space: byte.space.clone(),
                    offset: byte.offset.clone(),
                    size: 1,
                })
                .unwrap();
            main.push_str(&format!(
                "  %s{} = getelementptr i8, ptr %state, i64 {}\n  store i8 {}, ptr %s{}\n\
                   %k{} = getelementptr i8, ptr %known, i64 {}\n  store i8 {}, ptr %k{}\n",
                byte.index,
                byte.index,
                known.unwrap_or(0),
                byte.index,
                byte.index,
                byte.index,
                if known.is_some() { 255 } else { 0 },
                byte.index
            ));
        }
        for index in 0..guest_size {
            if let Some(known) = guest.bytes.get(index).copied().flatten() {
                main.push_str(&format!(
                    "  %guest_s_{index} = getelementptr i8, ptr %guest, i64 {index}\n  store i8 {known}, ptr %guest_s_{index}\n  %guest_k_{index} = getelementptr i8, ptr %guest_mask, i64 {index}\n  store i8 -1, ptr %guest_k_{index}\n",
                ));
            }
        }
        main.push_str(&format!(
            "  %status = call i32 @hydir_pcode_cfg(ptr %state, ptr %known, i32 {}, ptr %guest, ptr %guest_mask, i64 {}, i64 {}, ptr %events, ptr %event_count, i32 {event_capacity}, i32 {max_steps})\n\
               %count = load i32, ptr %event_count\n\
               %status_ok = icmp eq i32 %status, {}\n\
               %count_ok = icmp eq i32 %count, {}\n\
               %ok_initial = and i1 %status_ok, %count_ok\n",
            guest.space_id,
            guest.base,
            guest.bytes.len(),
            expected_status.code(),
            expected_events.len()
        ));
        let mut previous = "%ok_initial".to_owned();
        for (index, event) in expected_events.iter().enumerate() {
            main.push_str(&format!(
                "  %event_ptr_{index} = getelementptr i32, ptr %events, i32 {index}\n\
                   %event_{index} = load i32, ptr %event_ptr_{index}\n\
                   %event_ok_{index} = icmp eq i32 %event_{index}, {event}\n\
                   %ok_{index} = and i1 {previous}, %event_ok_{index}\n"
            ));
            previous = format!("%ok_{index}");
        }
        if let Some(expected) = expected_rax_low {
            let rax_index = artifact
                .byte_map
                .iter()
                .find(|byte| byte.space == "register" && byte.offset == "0x0")
                .unwrap()
                .index;
            main.push_str(&format!(
                "  %rax_ptr = getelementptr i8, ptr %state, i64 {rax_index}\n\
                   %rax = load i8, ptr %rax_ptr\n  %rax_ok = icmp eq i8 %rax, {expected}\n\
                   %ok_rax = and i1 {previous}, %rax_ok\n"
            ));
            previous = "%ok_rax".to_owned();
        }
        for (check, (index, value, known)) in guest.expected.iter().enumerate() {
            main.push_str(&format!(
                "  %guest_result_ptr_{check} = getelementptr i8, ptr %guest, i64 {index}\n  %guest_result_{check} = load i8, ptr %guest_result_ptr_{check}\n  %guest_value_ok_{check} = icmp eq i8 %guest_result_{check}, {value}\n  %guest_known_ptr_{check} = getelementptr i8, ptr %guest_mask, i64 {index}\n  %guest_known_result_{check} = load i8, ptr %guest_known_ptr_{check}\n  %guest_known_ok_{check} = icmp eq i8 %guest_known_result_{check}, {}\n  %guest_ok_{check} = and i1 %guest_value_ok_{check}, %guest_known_ok_{check}\n  %ok_guest_{check} = and i1 {previous}, %guest_ok_{check}\n",
                if *known { 255 } else { 0 }
            ));
            previous = format!("%ok_guest_{check}");
        }
        for (check, (space, offset, value, known)) in guest.expected_state.iter().enumerate() {
            let index = artifact
                .byte_map
                .iter()
                .find(|byte| &byte.space == space && &byte.offset == offset)
                .unwrap()
                .index;
            main.push_str(&format!(
                "  %state_result_ptr_{check} = getelementptr i8, ptr %state, i64 {index}\n  %state_result_{check} = load i8, ptr %state_result_ptr_{check}\n  %state_value_ok_{check} = icmp eq i8 %state_result_{check}, {value}\n  %state_known_ptr_{check} = getelementptr i8, ptr %known, i64 {index}\n  %state_known_result_{check} = load i8, ptr %state_known_ptr_{check}\n  %state_known_ok_{check} = icmp eq i8 %state_known_result_{check}, {}\n  %state_ok_{check} = and i1 %state_value_ok_{check}, %state_known_ok_{check}\n  %ok_state_{check} = and i1 {previous}, %state_ok_{check}\n",
                if *known { 255 } else { 0 }
            ));
            previous = format!("%ok_state_{check}");
        }
        main.push_str(&format!(
            "  %failed = xor i1 {previous}, true\n  %result = zext i1 %failed to i32\n  ret i32 %result\n}}\n"
        ));
        let file = tempfile::NamedTempFile::new().unwrap();
        let module = format!(
            "{}\ndeclare void @llvm.memset.p0.i64(ptr, i8, i64, i1)\n",
            artifact.llvm_ir
        );
        std::fs::write(file.path(), format!("{module}\n{main}")).unwrap();
        let output = Command::new("lli").arg(file.path()).output().unwrap();
        if !output.status.success() {
            let status_main = main.replace("ret i32 %result\n}", "ret i32 %status\n}");
            std::fs::write(file.path(), format!("{module}\n{status_main}")).unwrap();
            let status = Command::new("lli")
                .arg(file.path())
                .output()
                .unwrap()
                .status
                .code();
            let count_main = main.replace("ret i32 %result\n}", "ret i32 %count\n}");
            std::fs::write(file.path(), format!("{module}\n{count_main}")).unwrap();
            let count = Command::new("lli")
                .arg(file.path())
                .output()
                .unwrap()
                .status
                .code();
            panic!(
                "LLVM path mismatch: status={status:?}, events={count:?}, expected_status={expected_status:?}, expected_events={}\n{}",
                expected_events.len(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}\n{main}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn real_ghidra_rdtsc_userop_stops_rust_and_llvm_explicitly() {
        let snapshot = rdtsc_userop_fixture();
        let userop = &snapshot.selected_function.instructions[0].pcode[0];
        assert_eq!(userop.mnemonic, "CALLOTHER");
        assert_eq!(userop.userop_name.as_deref(), Some("rdtsc"));
        assert_eq!(userop.source_address.offset, "0x201174");

        let seed = PcodeConcreteState::default();
        let rust = snapshot.execute_concrete_path(&seed, None, 8, 8).unwrap();
        assert!(matches!(rust.stop, PcodePathStop::EffectBoundary { .. }));
        assert!(rust.events.is_empty());

        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        assert_eq!(artifact.semantic_fidelity, SemanticFidelity::Unknown);
        assert_eq!(
            artifact.source_operations[0].userop_name.as_deref(),
            Some("rdtsc")
        );
        assert!(artifact.stop_sites.iter().any(|site| {
            site.address == userop.source_address
                && site.operation_index == Some(0)
                && site.status == PcodeCfgLlvmStatus::OpaqueEffect
        }));
        verify(&artifact.llvm_ir);
        run_lli(
            &artifact,
            &seed,
            8,
            PcodeCfgLlvmStatus::OpaqueEffect,
            &[],
            None,
        );
    }

    #[test]
    fn division_cfg_llvm_matches_concrete_path_and_stops_before_undefined_results() {
        use hydir_ir::pcode::PcodeExecutionStop;

        for (opcode, mnemonic, left, right, expected_low) in [
            (33, "INT_DIV", u64::MAX, 2, 0xff),
            (35, "INT_REM", u64::MAX, 2, 1),
            (34, "INT_SDIV", (-7i64) as u64, 2, 0xfd),
            (36, "INT_SREM", (-7i64) as u64, 2, 0xff),
            (36, "INT_SREM", i64::MIN as u64, u64::MAX, 0),
        ] {
            let mut snapshot = fixture();
            let source = &mut snapshot.selected_function.instructions[0].pcode[0];
            source.mnemonic = mnemonic.to_owned();
            source.opcode = opcode;
            source.inputs = vec![register("0x38", 8), register("0x30", 8)];
            let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
            verify(&artifact.llvm_ir);
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), left).unwrap();
            seed.write_varnode(&register("0x30", 8), right).unwrap();
            let rust = snapshot.execute_concrete_path(&seed, None, 1, 8).unwrap();
            assert!(matches!(rust.stop, PcodePathStop::OperationBudget { .. }));
            assert_eq!(
                rust.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                Some(match opcode {
                    33 => left / right,
                    35 => left % right,
                    34 => ((left as i64) / (right as i64)) as u64,
                    36 => ((left as i64 as i128) % (right as i64 as i128)) as u64,
                    _ => unreachable!(),
                })
            );
            let events = source_event_ids(&artifact, &rust);
            run_lli(
                &artifact,
                &seed,
                1,
                PcodeCfgLlvmStatus::StepBudget,
                &events,
                Some(expected_low),
            );
        }

        for (opcode, mnemonic, left, right, reason_fragment) in [
            (33, "INT_DIV", 17, 0, "zero"),
            (35, "INT_REM", 17, 0, "zero"),
            (34, "INT_SDIV", 17, 0, "zero"),
            (36, "INT_SREM", 17, 0, "zero"),
            (34, "INT_SDIV", i64::MIN as u64, u64::MAX, "overflows"),
        ] {
            let mut snapshot = fixture();
            let source = &mut snapshot.selected_function.instructions[0].pcode[0];
            source.mnemonic = mnemonic.to_owned();
            source.opcode = opcode;
            source.inputs = vec![register("0x38", 8), register("0x30", 8)];
            let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
            verify(&artifact.llvm_ir);
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), left).unwrap();
            seed.write_varnode(&register("0x30", 8), right).unwrap();
            seed.write_varnode(&register("0x0", 8), 0x5a).unwrap();
            let rust = snapshot.execute_concrete_path(&seed, None, 8, 8).unwrap();
            assert!(matches!(rust.stop,
                PcodePathStop::EffectBoundary {
                    boundary: PcodeExecutionStop::InvalidOperation { ref reason, .. }
                } if reason.contains(reason_fragment)));
            assert_eq!(
                rust.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                Some(0x5a)
            );
            assert!(rust.events.is_empty());
            assert!(
                artifact
                    .stop_sites
                    .iter()
                    .any(|site| site.status == PcodeCfgLlvmStatus::InvalidOperation)
            );
            run_lli(
                &artifact,
                &seed,
                8,
                PcodeCfgLlvmStatus::InvalidOperation,
                &[],
                Some(0x5a),
            );
        }
    }

    #[test]
    fn real_ghidra_division_paths_match_rust_llvm_and_quotient_remainder_oracles() {
        use hydir_ir::pcode::PcodeExecutionStop;

        for signed in [false, true] {
            let snapshot = division_fixture(signed);
            let operations = &snapshot.selected_function.instructions[0].pcode;
            assert_eq!(operations.len(), 11);
            assert_eq!(operations[5].opcode, if signed { 34 } else { 33 });
            assert_eq!(operations[8].opcode, if signed { 36 } else { 35 });
            assert_eq!(operations[5].output.as_ref().unwrap().size, 8);
            assert_eq!(operations[8].output.as_ref().unwrap().size, 8);

            let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
            assert_eq!(artifact.semantic_fidelity, SemanticFidelity::Unknown);
            verify(&artifact.llvm_ir);
            let cases: &[(u32, u32, u32)] = if signed {
                &[
                    (0xffff_fff5, 0xffff_ffff, 3),           // -11 / 3
                    (11, 0, 0xffff_fffd),                    // 11 / -3
                    (0xffff_fff5, 0xffff_ffff, 0xffff_fffd), // -11 / -3
                    (7, 0, 2),
                ]
            } else {
                &[(11, 0, 3), (0xffff_ffff, 0, 3), (0, 1, 3)]
            };
            for &(low, high, divisor) in cases {
                let mut seed = PcodeConcreteState::default();
                seed.write_varnode(&register("0x0", 4), u64::from(low))
                    .unwrap();
                seed.write_varnode(&register("0x10", 4), u64::from(high))
                    .unwrap();
                seed.write_varnode(&register("0x8", 4), u64::from(divisor))
                    .unwrap();
                let trace = snapshot.execute_concrete_path(&seed, None, 11, 8).unwrap();
                assert!(matches!(trace.stop, PcodePathStop::OperationBudget { .. }));
                assert_eq!(source_event_ids(&artifact, &trace).len(), 11);
                let dividend = (u64::from(high) << 32) | u64::from(low);
                let (quotient, remainder) = if signed {
                    let divisor = i64::from(divisor as i32);
                    let quotient = (dividend as i64) / divisor;
                    let remainder = (dividend as i64) % divisor;
                    assert!(i32::try_from(quotient).is_ok());
                    (quotient as u32 as u64, remainder as u32 as u64)
                } else {
                    let quotient = dividend / u64::from(divisor);
                    let remainder = dividend % u64::from(divisor);
                    assert!(u32::try_from(quotient).is_ok());
                    (quotient, remainder)
                };
                assert_eq!(
                    trace.final_state.read_varnode(&register("0x0", 8)).unwrap(),
                    Some(quotient)
                );
                assert_eq!(
                    trace
                        .final_state
                        .read_varnode(&register("0x10", 8))
                        .unwrap(),
                    Some(remainder)
                );
                let mut expected_state = Vec::new();
                for (base, value) in [(0u64, quotient), (0x10, remainder)] {
                    for byte in 0..8 {
                        expected_state.push((
                            "register".to_owned(),
                            format!("0x{:x}", base + byte),
                            ((value >> (byte * 8)) & 0xff) as u8,
                            true,
                        ));
                    }
                }
                run_lli_with_guest(
                    &artifact,
                    &seed,
                    &GuestTestMemory {
                        space_id: 433,
                        base: 0,
                        bytes: Vec::new(),
                        expected: Vec::new(),
                        expected_state,
                    },
                    11,
                    PcodeCfgLlvmStatus::StepBudget,
                    &source_event_ids(&artifact, &trace),
                    Some(quotient as u8),
                );
            }

            let boundaries: &[(u32, u32, u32, &str)] = if signed {
                &[
                    (11, 0, 0, "zero"),
                    (0, 0x8000_0000, 0xffff_ffff, "overflows"),
                ]
            } else {
                &[(11, 0, 0, "zero")]
            };
            for &(low, high, divisor, reason_fragment) in boundaries {
                let mut seed = PcodeConcreteState::default();
                seed.write_varnode(&register("0x0", 4), u64::from(low))
                    .unwrap();
                seed.write_varnode(&register("0x10", 4), u64::from(high))
                    .unwrap();
                seed.write_varnode(&register("0x8", 4), u64::from(divisor))
                    .unwrap();
                let trace = snapshot.execute_concrete_path(&seed, None, 11, 8).unwrap();
                assert!(matches!(trace.stop,
                    PcodePathStop::EffectBoundary {
                        boundary: PcodeExecutionStop::InvalidOperation { ref reason, .. }
                    } if reason.contains(reason_fragment)));
                assert_eq!(source_event_ids(&artifact, &trace).len(), 5);
                run_lli(
                    &artifact,
                    &seed,
                    11,
                    PcodeCfgLlvmStatus::InvalidOperation,
                    &source_event_ids(&artifact, &trace),
                    Some(low as u8),
                );
            }
        }
    }

    #[test]
    fn real_prism_branch_paths_verify_and_match_rust_event_prefixes() {
        let snapshot = fixture();
        let start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013d9".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&start)).unwrap();
        assert_eq!(artifact.schema_version, PCODE_CFG_LLVM_VERSION);
        assert_eq!(artifact.semantic_fidelity, SemanticFidelity::Unknown);
        assert!(
            artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MemoryUnknownAlias)
        );
        verify(&artifact.llvm_ir);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::UnknownInput,
            &[],
            None,
        );
        for (condition, expected_rax) in [(1, 0), (0, 1)] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(
                &PcodeVarnode {
                    space: "register".into(),
                    offset: "0x206".into(),
                    size: 1,
                },
                condition,
            )
            .unwrap();
            seed.write_varnode(
                &PcodeVarnode {
                    space: "register".into(),
                    offset: "0x0".into(),
                    size: 8,
                },
                0,
            )
            .unwrap();
            let rust = snapshot
                .execute_concrete_path(&seed, Some(&start), 8, 8)
                .unwrap();
            assert!(matches!(rust.stop, PcodePathStop::EffectBoundary { .. }));
            let events = rust
                .events
                .iter()
                .filter_map(|event| match event {
                    PcodePathEvent::Effect { operation } => Some(&operation.source),
                    PcodePathEvent::Branch { source, .. } => Some(source),
                    PcodePathEvent::Fallthrough { .. } => None,
                })
                .map(|source| {
                    artifact
                        .source_operations
                        .iter()
                        .position(|candidate| {
                            candidate.address == source.source_address
                                && candidate.operation_index == source.sequence_index as usize
                        })
                        .unwrap()
                })
                .collect::<Vec<_>>();
            assert_eq!(events.len(), if condition == 0 { 2 } else { 1 });
            assert_eq!(
                rust.final_state
                    .read_varnode(&PcodeVarnode {
                        space: "register".into(),
                        offset: "0x0".into(),
                        size: 1,
                    })
                    .unwrap(),
                Some(expected_rax)
            );
            run_lli(
                &artifact,
                &seed,
                8,
                PcodeCfgLlvmStatus::MemoryUnknownAlias,
                &events,
                Some(expected_rax as u8),
            );
        }
    }

    #[test]
    fn real_prism_test_popcount_branch_matches_llvm_from_entry() {
        let snapshot = fixture();
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        assert_eq!(artifact.start, snapshot.selected_function.entry);
        assert!(
            artifact
                .source_operations
                .iter()
                .any(|source| source.mnemonic == "POPCOUNT")
        );
        verify(&artifact.llvm_ir);
        for (second_input, expected_rax, taken) in [(0u64, 0u8, true), (5, 1, false)] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), 7).unwrap();
            seed.write_varnode(&register("0x30", 8), second_input)
                .unwrap();
            seed.write_varnode(&register("0x20", 8), 0x700000).unwrap();
            seed.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
            let rust = snapshot.execute_concrete_path(&seed, None, 64, 8).unwrap();
            assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
            assert_eq!(
                rust.final_state.read_varnode(&register("0x20", 8)).unwrap(),
                Some(0x700008)
            );
            assert_eq!(
                rust.final_state
                    .read_varnode(&register("0x288", 8))
                    .unwrap(),
                Some(0xdeadbeef)
            );
            assert!(rust.events.iter().any(|event| matches!(
                event,
                PcodePathEvent::Branch { taken: Some(value), .. } if *value == taken
            )));
            assert!(rust.events.iter().any(|event| matches!(
                event,
                PcodePathEvent::Effect { operation } if operation.source.mnemonic == "POPCOUNT"
            )));
            let ids = source_event_ids(&artifact, &rust);
            run_lli_with_guest(
                &artifact,
                &seed,
                &GuestTestMemory {
                    space_id: 433,
                    base: 0x700000,
                    bytes: vec![
                        Some(0xef),
                        Some(0xbe),
                        Some(0xad),
                        Some(0xde),
                        Some(0),
                        Some(0),
                        Some(0),
                        Some(0),
                    ],
                    expected: Vec::new(),
                    expected_state: vec![
                        ("register".to_owned(), "0x20".to_owned(), 8, true),
                        ("register".to_owned(), "0x288".to_owned(), 0xef, true),
                    ],
                },
                64,
                PcodeCfgLlvmStatus::Return,
                &ids,
                Some(expected_rax),
            );
        }
    }

    #[test]
    fn real_ghidra_add_zero_rewrite_preserves_bounded_rust_and_llvm_execution() {
        let snapshot = add_zero_fixture();
        let original_llvm = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        let transformed = emit_pcode_simplified_cfg_llvm(&snapshot, None).unwrap();
        assert_eq!(transformed.simplification.rewrites.len(), 1);
        assert_eq!(
            transformed.simplification.rewrites[0].before.mnemonic,
            "INT_ADD"
        );
        assert_eq!(
            transformed.simplification.rewrites[0].after.mnemonic,
            "COPY"
        );
        assert_eq!(
            transformed.simplification.rewrites[0].source_address.offset,
            "0x201177"
        );
        assert_eq!(original_llvm.byte_map, transformed.llvm.byte_map);
        assert!(transformed.llvm.source_operations.iter().any(|operation| {
            operation.address.offset == "0x201177" && operation.mnemonic == "COPY"
        }));
        assert_eq!(transformed.verification, VerificationStatus::NotRun);
        verify(&original_llvm.llvm_ir);
        verify(&transformed.llvm.llvm_ir);

        let mut rewritten_snapshot = snapshot.clone();
        for (instruction, replacement) in rewritten_snapshot
            .selected_function
            .instructions
            .iter_mut()
            .zip(&transformed.simplification.after.instructions)
        {
            instruction.pcode.clone_from(&replacement.pcode);
        }
        for value in [0, 1, 0xff, u64::MAX] {
            let mut seed = PcodeConcreteState::default();
            seed.write_varnode(&register("0x38", 8), value).unwrap();
            seed.write_varnode(&register("0x20", 8), 0x700000).unwrap();
            seed.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
            let original = snapshot.execute_concrete_path(&seed, None, 64, 8).unwrap();
            let rewritten = rewritten_snapshot
                .execute_concrete_path(&seed, None, 64, 8)
                .unwrap();
            assert!(matches!(original.stop, PcodePathStop::Return { .. }));
            assert_eq!(original.stop, rewritten.stop);
            assert_eq!(original.instruction_visits, rewritten.instruction_visits);
            assert_eq!(original.final_state, rewritten.final_state);
            let original_ids = source_event_ids(&original_llvm, &original);
            let rewritten_ids = source_event_ids(&transformed.llvm, &rewritten);
            assert_eq!(original_ids, rewritten_ids);
            let mut expected_state = vec![("register".to_owned(), "0x20".to_owned(), 8, true)];
            for offset in ["0x200", "0x20b", "0x207", "0x206", "0x202"] {
                let expected = original
                    .final_state
                    .read_varnode(&register(offset, 1))
                    .unwrap()
                    .unwrap() as u8;
                expected_state.push(("register".to_owned(), offset.to_owned(), expected, true));
            }
            for byte in 0..8 {
                expected_state.push((
                    "register".to_owned(),
                    format!("0x{byte:x}"),
                    (value >> (byte * 8)) as u8,
                    true,
                ));
            }
            let guest = GuestTestMemory {
                space_id: 433,
                base: 0x700000,
                bytes: vec![
                    Some(0xef),
                    Some(0xbe),
                    Some(0xad),
                    Some(0xde),
                    Some(0),
                    Some(0),
                    Some(0),
                    Some(0),
                ],
                expected: Vec::new(),
                expected_state,
            };
            for (artifact, ids) in [
                (&original_llvm, &original_ids),
                (&transformed.llvm, &rewritten_ids),
            ] {
                run_lli_with_guest(
                    artifact,
                    &seed,
                    &guest,
                    64,
                    PcodeCfgLlvmStatus::Return,
                    ids,
                    Some(value as u8),
                );
            }
        }
    }

    #[test]
    fn synthetic_branch_loop_hits_runtime_operation_budget() {
        let mut snapshot = fixture();
        snapshot.selected_function.instructions.truncate(1);
        snapshot.selected_function.flow_edges.clear();
        let instruction = &mut snapshot.selected_function.instructions[0];
        let mut branch = instruction.pcode[0].clone();
        branch.mnemonic = "BRANCH".into();
        branch.opcode = 4;
        branch.output = None;
        branch.inputs = vec![PcodeVarnode {
            space: "ram".into(),
            offset: instruction.address.offset.clone(),
            size: 8,
        }];
        instruction.pcode = vec![branch];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        let rust = snapshot
            .execute_concrete_path(&PcodeConcreteState::default(), None, 3, 8)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::OperationBudget { .. }));
        assert_eq!(rust.events.len(), 3);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            3,
            PcodeCfgLlvmStatus::StepBudget,
            &[0, 0, 0],
            None,
        );
    }

    #[test]
    fn selected_indirect_branch_matches_rust_path_and_stops_on_unknown_targets() {
        let mut snapshot = fixture();
        snapshot.selected_function.instructions.truncate(2);
        snapshot.selected_function.flow_edges.clear();
        let target = snapshot.selected_function.instructions[1].address.clone();
        let mut branch = snapshot.selected_function.instructions[0].pcode[0].clone();
        branch.mnemonic = "BRANCHIND".into();
        branch.opcode = 6;
        branch.output = None;
        branch.inputs = vec![register("0x0", 8)];
        snapshot.selected_function.instructions[0].pcode = vec![branch];
        let mut ret = snapshot.selected_function.instructions[1].pcode[0].clone();
        ret.mnemonic = "RETURN".into();
        ret.opcode = 10;
        ret.output = None;
        ret.inputs = vec![register("0x0", 8)];
        snapshot.selected_function.instructions[1].pcode = vec![ret];

        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x0", 8), offset(&target.offset).unwrap())
            .unwrap();
        let rust = snapshot.execute_concrete_path(&seed, None, 8, 8).unwrap();
        assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(source_event_ids(&artifact, &rust), vec![0]);
        run_lli(&artifact, &seed, 8, PcodeCfgLlvmStatus::Return, &[0], None);

        let unknown = PcodeConcreteState::default();
        let rust = snapshot
            .execute_concrete_path(&unknown, None, 8, 8)
            .unwrap();
        assert!(matches!(
            rust.stop,
            PcodePathStop::UnknownIndirectTarget { .. }
        ));
        run_lli(
            &artifact,
            &unknown,
            8,
            PcodeCfgLlvmStatus::UnknownInput,
            &[],
            None,
        );

        seed.write_varnode(&register("0x0", 8), 0xdeadbeef).unwrap();
        let rust = snapshot.execute_concrete_path(&seed, None, 8, 8).unwrap();
        assert!(matches!(rust.stop, PcodePathStop::TargetNotSelected { .. }));
        run_lli(
            &artifact,
            &seed,
            8,
            PcodeCfgLlvmStatus::OutOfFunction,
            &[],
            None,
        );
    }

    #[test]
    fn real_ghidra_indirect_jump_matches_rust_and_llvm() {
        let snapshot = indirect_jump_fixture();
        let entry_artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&entry_artifact.llvm_ir);
        for (rdi, budget, expected_indirect) in [(0, 11, false), (1, 12, true)] {
            let mut entry_seed = PcodeConcreteState::default();
            entry_seed
                .write_varnode(&register("0x0", 8), 0x20117b)
                .unwrap();
            entry_seed.write_varnode(&register("0x38", 8), rdi).unwrap();
            let rust = snapshot
                .execute_concrete_path(&entry_seed, None, budget, 8)
                .unwrap();
            assert!(matches!(rust.stop, PcodePathStop::OperationBudget { .. }));
            assert_eq!(
                rust.instruction_visits
                    .iter()
                    .any(|address| address.offset == "0x201179"),
                expected_indirect
            );
            let events = source_event_ids(&entry_artifact, &rust);
            run_lli(
                &entry_artifact,
                &entry_seed,
                budget as u32,
                PcodeCfgLlvmStatus::StepBudget,
                &events,
                Some(7),
            );
        }
        let start = PcodeAddress {
            space: "ram".into(),
            offset: "0x201179".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&start)).unwrap();
        verify(&artifact.llvm_ir);
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x0", 8), 0x20117b).unwrap();
        let rust = snapshot
            .execute_concrete_path(&seed, Some(&start), 2, 8)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::OperationBudget { .. }));
        assert_eq!(rust.instruction_visits.len(), 3);
        let events = source_event_ids(&artifact, &rust);
        assert_eq!(events.len(), 2);
        run_lli(
            &artifact,
            &seed,
            2,
            PcodeCfgLlvmStatus::StepBudget,
            &events,
            Some(7),
        );

        let unknown = PcodeConcreteState::default();
        let rust = snapshot
            .execute_concrete_path(&unknown, Some(&start), 2, 8)
            .unwrap();
        assert!(matches!(
            rust.stop,
            PcodePathStop::UnknownIndirectTarget { .. }
        ));
        run_lli(
            &artifact,
            &unknown,
            2,
            PcodeCfgLlvmStatus::UnknownInput,
            &[],
            None,
        );

        seed.write_varnode(&register("0x0", 8), 0xdeadbeef).unwrap();
        let rust = snapshot
            .execute_concrete_path(&seed, Some(&start), 2, 8)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::TargetNotSelected { .. }));
        run_lli(
            &artifact,
            &seed,
            2,
            PcodeCfgLlvmStatus::OutOfFunction,
            &[],
            None,
        );
    }

    #[test]
    fn narrow_backward_relative_branch_and_unresolved_flow_are_explicit() {
        let mut snapshot = fixture();
        snapshot.selected_function.instructions.truncate(1);
        snapshot.selected_function.flow_edges.clear();
        let instruction = &mut snapshot.selected_function.instructions[0];
        let mut jump_forward = instruction.pcode[0].clone();
        jump_forward.mnemonic = "BRANCH".into();
        jump_forward.opcode = 4;
        jump_forward.output = None;
        jump_forward.inputs = vec![PcodeVarnode {
            space: "const".into(),
            offset: "0x2".into(),
            size: 1,
        }];
        let mut ret = jump_forward.clone();
        ret.mnemonic = "RETURN".into();
        ret.opcode = 10;
        ret.sequence_index = 1;
        ret.sequence_time = 1;
        ret.inputs = vec![PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 8,
        }];
        let mut jump_back = jump_forward.clone();
        jump_back.sequence_index = 2;
        jump_back.sequence_time = 2;
        jump_back.inputs[0].offset = "0xff".into();
        instruction.pcode = vec![jump_forward, ret, jump_back];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        let rust = snapshot
            .execute_concrete_path(&PcodeConcreteState::default(), None, 8, 8)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(rust.events.len(), 2);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::Return,
            &[0, 2],
            None,
        );

        snapshot.selected_function.instructions[0].pcode.truncate(1);
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        assert!(
            artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MalformedTarget)
        );
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::MalformedTarget,
            &[],
            None,
        );

        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode[0].mnemonic = "COPY".into();
        instruction.pcode[0].opcode = 1;
        instruction.pcode[0].output = Some(PcodeVarnode {
            space: "register".into(),
            offset: "0x0".into(),
            size: 8,
        });
        instruction.pcode[0].inputs = vec![PcodeVarnode {
            space: "const".into(),
            offset: "0x1".into(),
            size: 8,
        }];
        let artifact = emit_pcode_cfg_llvm(&snapshot, None).unwrap();
        verify(&artifact.llvm_ir);
        run_lli(
            &artifact,
            &PcodeConcreteState::default(),
            8,
            PcodeCfgLlvmStatus::UnresolvedFlow,
            &[0],
            Some(1),
        );
    }

    #[test]
    fn real_ghidra_store_and_load_match_rust_concrete_paths() {
        let snapshot = calls_fixture();
        let store_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013ad".into(),
        };
        let store_artifact = emit_pcode_cfg_llvm(&snapshot, Some(&store_start)).unwrap();
        assert_eq!(
            store_artifact.guest_ram_limit_bytes,
            PCODE_CFG_GUEST_RAM_MAX_BYTES - store_artifact.state_bytes as u64
        );
        assert!(store_artifact.llvm_ir.contains(&format!(
            "%guest_len, {}",
            store_artifact.guest_ram_limit_bytes
        )));
        verify(&store_artifact.llvm_ir);
        let mut store_seed = PcodeConcreteState::default();
        store_seed
            .write_varnode(&register("0x20", 8), 0x1008)
            .unwrap();
        let store_rust = snapshot
            .execute_concrete_path(&store_seed, Some(&store_start), 8, 4)
            .unwrap();
        assert!(matches!(store_rust.stop, PcodePathStop::Call { .. }));
        assert_eq!(
            store_rust
                .final_state
                .read_memory("ram", 0x1000, 8)
                .unwrap(),
            Some(0x2013b2)
        );
        let store_events = source_event_ids(&store_artifact, &store_rust);
        assert_eq!(store_events.len(), 2);
        let written = 0x2013b2u64.to_le_bytes();
        run_lli_with_guest(
            &store_artifact,
            &store_seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: vec![None; 8],
                expected: written
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| (i, *byte, true))
                    .collect(),
                expected_state: vec![("register".into(), "0x20".into(), 0x00, true)],
            },
            8,
            PcodeCfgLlvmStatus::Call,
            &store_events,
            None,
        );

        let load_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013b6".into(),
        };
        let load_artifact = emit_pcode_cfg_llvm(&snapshot, Some(&load_start)).unwrap();
        verify(&load_artifact.llvm_ir);
        let mut load_seed = PcodeConcreteState::default();
        load_seed
            .write_varnode(&register("0x20", 8), 0x1000)
            .unwrap();
        let value = 0x1122_3344_5566_7788u64;
        load_seed.write_memory("ram", 0x1000, 8, value).unwrap();
        let load_rust = snapshot
            .execute_concrete_path(&load_seed, Some(&load_start), 8, 4)
            .unwrap();
        assert!(matches!(load_rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(
            load_rust
                .final_state
                .read_varnode(&register("0x288", 8))
                .unwrap(),
            Some(value)
        );
        let load_events = source_event_ids(&load_artifact, &load_rust);
        assert_eq!(load_events.len(), 2);
        run_lli_with_guest(
            &load_artifact,
            &load_seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: value.to_le_bytes().into_iter().map(Some).collect(),
                expected: Vec::new(),
                expected_state: value
                    .to_le_bytes()
                    .iter()
                    .enumerate()
                    .map(|(i, byte)| ("register".into(), format!("0x{:x}", 0x288 + i), *byte, true))
                    .collect(),
            },
            8,
            PcodeCfgLlvmStatus::Return,
            &load_events,
            None,
        );
    }

    #[test]
    fn guest_ram_boundaries_stop_before_memory_effects() {
        let snapshot = calls_fixture();
        let start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013b6".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&start)).unwrap();
        verify(&artifact.llvm_ir);
        let known_ram = GuestTestMemory {
            space_id: 433,
            base: 0x1000,
            bytes: vec![Some(0x42); 8],
            expected: Vec::new(),
            expected_state: Vec::new(),
        };
        run_lli_with_guest(
            &artifact,
            &PcodeConcreteState::default(),
            &known_ram,
            8,
            PcodeCfgLlvmStatus::MemoryUnknownAlias,
            &[],
            None,
        );

        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x20", 8), 0x1000).unwrap();
        let mut partial_ram = vec![Some(0x42); 8];
        partial_ram[3] = None;
        let unknown_ram = GuestTestMemory {
            bytes: partial_ram,
            ..known_ram
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &unknown_ram,
            8,
            PcodeCfgLlvmStatus::MemoryUnknownBytes,
            &[],
            None,
        );
        let short_ram = GuestTestMemory {
            bytes: vec![Some(0x42); 4],
            ..unknown_ram
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &short_ram,
            8,
            PcodeCfgLlvmStatus::MemoryOutOfBounds,
            &[],
            None,
        );
        let wrong_space = GuestTestMemory {
            space_id: 42,
            bytes: vec![Some(0x42); 8],
            ..short_ram
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &wrong_space,
            8,
            PcodeCfgLlvmStatus::MemorySpaceMismatch,
            &[],
            None,
        );
        seed.write_varnode(&register("0x20", 8), u64::MAX).unwrap();
        let right_space = GuestTestMemory {
            space_id: 433,
            ..wrong_space
        };
        run_lli_with_guest(
            &artifact,
            &seed,
            &right_space,
            8,
            PcodeCfgLlvmStatus::MemoryAddressOverflow,
            &[],
            None,
        );

        let mut non_ram = snapshot.clone();
        non_ram.selected_function.instructions[3].pcode[0].inputs[0].offset = "0x35".into();
        let non_ram_artifact = emit_pcode_cfg_llvm(&non_ram, Some(&start)).unwrap();
        verify(&non_ram_artifact.llvm_ir);
        assert!(
            non_ram_artifact
                .stop_sites
                .iter()
                .any(|site| site.status == PcodeCfgLlvmStatus::MemoryNonRamSpace)
        );
        run_lli_with_guest(
            &non_ram_artifact,
            &seed,
            &right_space,
            8,
            PcodeCfgLlvmStatus::MemoryNonRamSpace,
            &[],
            None,
        );
    }

    #[test]
    fn addressable_unit_scaling_and_unknown_store_data_match_rust() {
        let mut snapshot = calls_fixture();
        snapshot
            .address_spaces
            .iter_mut()
            .find(|space| space.name == "ram")
            .unwrap()
            .addressable_unit_size = 2;
        let load_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013b6".into(),
        };
        let artifact = emit_pcode_cfg_llvm(&snapshot, Some(&load_start)).unwrap();
        verify(&artifact.llvm_ir);
        let mut seed = PcodeConcreteState::default();
        seed.write_varnode(&register("0x20", 8), 0x800).unwrap();
        let value = 0x0102_0304_0506_0708u64;
        seed.write_memory("ram", 0x1000, 8, value).unwrap();
        let rust = snapshot
            .execute_concrete_path(&seed, Some(&load_start), 8, 4)
            .unwrap();
        assert!(matches!(rust.stop, PcodePathStop::Return { .. }));
        assert_eq!(
            rust.final_state
                .read_varnode(&register("0x288", 8))
                .unwrap(),
            Some(value)
        );
        let events = source_event_ids(&artifact, &rust);
        run_lli_with_guest(
            &artifact,
            &seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: value.to_le_bytes().into_iter().map(Some).collect(),
                expected: Vec::new(),
                expected_state: vec![("register".into(), "0x288".into(), 0x08, true)],
            },
            8,
            PcodeCfgLlvmStatus::Return,
            &events,
            None,
        );

        let mut store_snapshot = calls_fixture();
        store_snapshot.selected_function.instructions[1].pcode[1].inputs[2] = register("0x0", 8);
        let store_start = PcodeAddress {
            space: "ram".into(),
            offset: "0x2013ad".into(),
        };
        let store_artifact = emit_pcode_cfg_llvm(&store_snapshot, Some(&store_start)).unwrap();
        verify(&store_artifact.llvm_ir);
        let mut store_seed = PcodeConcreteState::default();
        store_seed
            .write_varnode(&register("0x20", 8), 0x1008)
            .unwrap();
        let store_rust = store_snapshot
            .execute_concrete_path(&store_seed, Some(&store_start), 8, 4)
            .unwrap();
        assert!(matches!(
            store_rust.stop,
            PcodePathStop::EffectBoundary {
                boundary: hydir_ir::pcode::PcodeExecutionStop::MissingInput { input_index: 2, .. }
            }
        ));
        let events = source_event_ids(&store_artifact, &store_rust);
        assert_eq!(events.len(), 1);
        run_lli_with_guest(
            &store_artifact,
            &store_seed,
            &GuestTestMemory {
                space_id: 433,
                base: 0x1000,
                bytes: vec![None; 8],
                expected: Vec::new(),
                expected_state: Vec::new(),
            },
            8,
            PcodeCfgLlvmStatus::UnknownInput,
            &events,
            None,
        );
    }
}
