//! Versioned, fail-closed PatchLang and whole-function patching.
//!
//! The source-located PatchLang frontend is broader than the current scalar
//! x86-64 backend. Valid programs outside that lowering contract are refused
//! explicitly rather than silently simplified.

mod elf;
mod patchlang;

pub use patchlang::{
    PATCH_LANG_VERSION, PatchExpression, PatchExpressionKind, PatchProgram, PatchStatement,
    PatchType, lower_scalar_return, parse_patch_program, resolved_return,
};

use hydir_backend::{import_elf, lift_symbol, region_contract};
use hydir_core::{Address, PATCH_BUNDLE_VERSION};
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PATCH_SCHEMA_VERSION: u32 = 1;
pub const MAX_PATCH_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchDocument {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_symbol: String,
    pub prototype: String,
    pub replacement: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Atom {
    Arg0,
    Arg1,
    Constant(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReturnExpression {
    Atom(Atom),
    Add(Atom, Atom),
    Sub(Atom, Atom),
}

#[derive(Debug)]
pub struct ValidatedPatch {
    pub document: PatchDocument,
    pub expression: ReturnExpression,
}

#[derive(Debug)]
pub struct PatchedBinary {
    pub content: Vec<u8>,
    pub original_sha256: String,
    pub patched_sha256: String,
    pub function_address: u64,
    pub function_size: u64,
    pub replacement_bytes: Vec<u8>,
    pub original_region: Vec<u8>,
    pub region_bytes_sha256: String,
    pub region_exit: u64,
    pub exit_rsp_delta: i64,
    pub bundle: PatchBundle,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct SourceRange {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PatchIr {
    pub schema_version: u32,
    pub prototype: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expression: Option<ReturnExpression>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_return: Option<PatchExpression>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statements: Vec<PatchStatement>,
    pub inputs: Vec<String>,
    pub outputs: Vec<String>,
    pub exits: Vec<Address>,
    pub memory_effects: Vec<String>,
    pub source_range: SourceRange,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BoundaryAdapter {
    pub entry_bindings: Vec<String>,
    pub exit_bindings: Vec<String>,
    pub exit_rsp_delta: i64,
    pub preserved_locations: Vec<String>,
    pub unresolved_requirements: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementStrategy {
    InPlace,
    EntryTrampoline,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlacementPlan {
    pub strategy: PlacementStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region_entry: Option<Address>,
    pub virtual_address: Address,
    pub original_size: u64,
    pub replacement_size: u64,
    pub padding_byte: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_bytes_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_segment: Option<ExecutableSegmentPlacement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutableSegmentPlacement {
    pub original_file_size: u64,
    pub original_program_header_offset: u64,
    pub original_program_header_count: u16,
    pub program_header_offset: u64,
    pub file_offset: u64,
    pub virtual_address: Address,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PatchRelocationRecord {
    pub offset: u64,
    pub kind: String,
    pub target: String,
    pub addend: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Passed,
    Failed,
    NotRun,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerificationEvidence {
    pub check: String,
    pub status: VerificationStatus,
    pub details: String,
}

/// Reversible, digest-bound result of adapting legacy scalar patch v1 to the
/// canonical patch artifact. `stable_verified` remains false until behavior
/// and complete boundary-state preservation have both been proven.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PatchBundle {
    pub schema_version: u32,
    pub source: PatchDocument,
    pub typed_patch_ir: PatchIr,
    pub region_digest: String,
    pub original_region_hex: String,
    pub compiled_bytes_hex: String,
    pub compiled_bytes_sha256: String,
    pub boundary_adapters: Vec<BoundaryAdapter>,
    pub placement_plan: PlacementPlan,
    pub relocation_records: Vec<PatchRelocationRecord>,
    pub toolchain_digest: String,
    pub original_sha256: String,
    pub patched_sha256: String,
    pub verification_evidence: Vec<VerificationEvidence>,
    pub stable_verified: bool,
}

/// Parse PatchLang, then lower the accepted program through the legacy scalar
/// compatibility adapter.
pub fn parse_return_expression(source: &str) -> Result<ReturnExpression, String> {
    let program = parse_patch_program(source)?;
    lower_scalar_return(&program)
}

pub fn parse_patch_document(bytes: &[u8]) -> Result<(PatchDocument, PatchProgram), String> {
    if bytes.len() > MAX_PATCH_BYTES {
        return Err("patch document exceeds 4096 bytes".to_owned());
    }
    let document: PatchDocument =
        serde_json::from_slice(bytes).map_err(|error| format!("patch JSON {error}"))?;
    if document.schema_version != PATCH_SCHEMA_VERSION {
        return Err("unsupported patch schema version".to_owned());
    }
    if document.binary_sha256.len() != 64
        || !document
            .binary_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("binary_sha256 must be 64 lowercase hexadecimal characters".to_owned());
    }
    if document.function_symbol.is_empty()
        || document.function_symbol.len() > 256
        || document.function_symbol.chars().any(char::is_control)
    {
        return Err("function_symbol must be 1..=256 non-control characters".to_owned());
    }
    if document.prototype != "u64(u64,u64)" {
        return Err("patch requires explicit prototype u64(u64,u64)".to_owned());
    }
    let program = parse_patch_program(&document.replacement)?;
    Ok((document, program))
}

pub fn parse_patch_json(bytes: &[u8]) -> Result<ValidatedPatch, String> {
    let (document, program) = parse_patch_document(bytes)?;
    let expression = lower_scalar_return(&program)?;
    Ok(ValidatedPatch {
        document,
        expression,
    })
}

pub fn parse_patch_bundle_json(bytes: &[u8]) -> Result<PatchBundle, String> {
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("PatchBundle exceeds 2 MiB".to_owned());
    }
    let bundle: PatchBundle =
        serde_json::from_slice(bytes).map_err(|error| format!("PatchBundle JSON {error}"))?;
    validate_patch_bundle(&bundle)?;
    Ok(bundle)
}

pub fn validate_patch_bundle(bundle: &PatchBundle) -> Result<(), String> {
    if bundle.schema_version != PATCH_BUNDLE_VERSION {
        return Err(format!(
            "unsupported PatchBundle schema version {}",
            bundle.schema_version
        ));
    }
    for (label, digest) in [
        ("region", bundle.region_digest.as_str()),
        ("compiled bytes", bundle.compiled_bytes_sha256.as_str()),
        ("toolchain", bundle.toolchain_digest.as_str()),
        ("original binary", bundle.original_sha256.as_str()),
        ("patched binary", bundle.patched_sha256.as_str()),
    ] {
        if !valid_digest(digest) {
            return Err(format!("PatchBundle {label} digest is invalid"));
        }
    }
    if bundle.source.binary_sha256 != bundle.original_sha256 {
        return Err("PatchBundle source and original binary digests differ".to_owned());
    }
    if bundle.typed_patch_ir.schema_version != 1
        || bundle.typed_patch_ir.exits.is_empty()
        || bundle.boundary_adapters.is_empty()
    {
        return Err("PatchBundle PatchIR or boundary adapter is incomplete".to_owned());
    }
    if !bundle.typed_patch_ir.statements.is_empty()
        && !matches!(
            bundle.typed_patch_ir.statements.last(),
            Some(PatchStatement::Return { .. })
        )
    {
        return Err("PatchBundle PatchIR must end in a return terminator".to_owned());
    }
    if !bundle.typed_patch_ir.statements.is_empty()
        && bundle.typed_patch_ir.expression.is_none()
        && bundle.typed_patch_ir.resolved_return.is_none()
    {
        return Err("PatchBundle PatchIR has no resolved return expression".to_owned());
    }
    let original = decode_hex(&bundle.original_region_hex, "original region")?;
    let compiled = decode_hex(&bundle.compiled_bytes_hex, "compiled bytes")?;
    if format!("{:x}", Sha256::digest(&original)) != bundle.region_digest
        || format!("{:x}", Sha256::digest(&compiled)) != bundle.compiled_bytes_sha256
    {
        return Err("PatchBundle embedded byte digest mismatch".to_owned());
    }
    let source_json = serde_json::to_vec(&bundle.source)
        .map_err(|error| format!("PatchBundle source {error}"))?;
    let (_, source_program) = parse_patch_document(&source_json)?;
    if !bundle.typed_patch_ir.statements.is_empty()
        && bundle.typed_patch_ir.statements != source_program.statements
    {
        return Err("PatchBundle statements differ from PatchLang source".to_owned());
    }
    let source_return = resolved_return(&source_program)?;
    if bundle
        .typed_patch_ir
        .resolved_return
        .as_ref()
        .is_some_and(|resolved| resolved != &source_return)
    {
        return Err("PatchBundle resolved return differs from PatchLang source".to_owned());
    }
    if let Some(expression) = bundle.typed_patch_ir.expression {
        if lower_scalar_return(&source_program)? != expression || encode(expression)? != compiled {
            return Err("PatchBundle scalar expression differs from source or bytes".to_owned());
        }
    } else if bundle.typed_patch_ir.resolved_return.is_some()
        && encode_patch_expression(&source_return)? != compiled
    {
        return Err("PatchBundle resolved return differs from compiled bytes".to_owned());
    }
    if bundle.placement_plan.original_size != original.len() as u64
        || bundle.placement_plan.replacement_size != compiled.len() as u64
    {
        return Err("PatchBundle placement sizes do not match embedded bytes".to_owned());
    }
    let entry_bytes = bundle
        .placement_plan
        .entry_bytes_hex
        .as_deref()
        .map(|value| decode_hex(value, "entry bytes"))
        .transpose()?;
    if entry_bytes
        .as_ref()
        .is_some_and(|entry| entry.len() != original.len())
    {
        return Err("PatchBundle entry bytes do not cover the original region".to_owned());
    }
    match bundle.placement_plan.strategy {
        PlacementStrategy::InPlace => {
            if bundle.placement_plan.replacement_size > bundle.placement_plan.original_size
                || bundle.placement_plan.executable_segment.is_some()
                || bundle
                    .placement_plan
                    .region_entry
                    .is_some_and(|entry| entry != bundle.placement_plan.virtual_address)
            {
                return Err("PatchBundle in-place placement is inconsistent".to_owned());
            }
            if let Some(entry) = entry_bytes
                && (!entry.starts_with(&compiled)
                    || entry[compiled.len()..]
                        .iter()
                        .any(|byte| Some(*byte) != bundle.placement_plan.padding_byte))
            {
                return Err("PatchBundle in-place entry bytes are inconsistent".to_owned());
            }
        }
        PlacementStrategy::EntryTrampoline => {
            let entry = entry_bytes.ok_or("PatchBundle trampoline entry bytes are missing")?;
            let region_entry = bundle
                .placement_plan
                .region_entry
                .ok_or("PatchBundle trampoline region entry is missing")?;
            let segment = bundle
                .placement_plan
                .executable_segment
                .as_ref()
                .ok_or("PatchBundle executable segment placement is missing")?;
            let segment_end = segment
                .virtual_address
                .0
                .checked_add(segment.memory_size)
                .ok_or("PatchBundle executable segment address overflows")?;
            let replacement_end = bundle
                .placement_plan
                .virtual_address
                .0
                .checked_add(bundle.placement_plan.replacement_size)
                .ok_or("PatchBundle replacement address overflows")?;
            let displacement = i32::from_le_bytes(
                entry
                    .get(1..5)
                    .ok_or("PatchBundle trampoline encoding is truncated")?
                    .try_into()
                    .map_err(|_| "PatchBundle trampoline displacement is malformed")?,
            );
            let jump_target = i128::from(region_entry.0) + 5 + i128::from(displacement);
            if entry.len() < 5
                || entry.first() != Some(&0xe9)
                || entry[5..].iter().any(|byte| *byte != 0x90)
                || jump_target != i128::from(bundle.placement_plan.virtual_address.0)
                || segment.file_size != segment.memory_size
                || segment.original_file_size > segment.file_offset
                || segment.original_program_header_count == 0
                || segment.alignment < 0x1000
                || !segment.alignment.is_power_of_two()
                || segment.file_offset % segment.alignment
                    != segment.virtual_address.0 % segment.alignment
                || bundle.placement_plan.virtual_address.0 < segment.virtual_address.0
                || replacement_end > segment_end
            {
                return Err("PatchBundle trampoline placement is inconsistent".to_owned());
            }
        }
    }
    if bundle.stable_verified
        && (bundle
            .verification_evidence
            .iter()
            .any(|evidence| evidence.status != VerificationStatus::Passed)
            || bundle
                .boundary_adapters
                .iter()
                .any(|adapter| !adapter.unresolved_requirements.is_empty()))
    {
        return Err("PatchBundle cannot be stable with incomplete evidence".to_owned());
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex(value: &str, label: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || value.len() > 2 * MAX_PATCH_BYTES {
        return Err(format!("PatchBundle {label} hex is invalid or too large"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| ())?;
            u8::from_str_radix(pair, 16).map_err(|_| ())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| format!("PatchBundle {label} is not hexadecimal"))
}

fn encode(expression: ReturnExpression) -> Result<Vec<u8>, String> {
    let bytes: &[u8] = match expression {
        ReturnExpression::Atom(Atom::Arg0) => &[0x48, 0x89, 0xf8, 0xc3],
        ReturnExpression::Atom(Atom::Arg1) => &[0x48, 0x89, 0xf0, 0xc3],
        ReturnExpression::Add(Atom::Arg0, Atom::Arg1)
        | ReturnExpression::Add(Atom::Arg1, Atom::Arg0) => {
            &[0x48, 0x89, 0xf8, 0x48, 0x01, 0xf0, 0xc3]
        }
        ReturnExpression::Sub(Atom::Arg0, Atom::Arg1) => {
            &[0x48, 0x89, 0xf8, 0x48, 0x29, 0xf0, 0xc3]
        }
        ReturnExpression::Sub(Atom::Arg1, Atom::Arg0) => {
            &[0x48, 0x89, 0xf0, 0x48, 0x29, 0xf8, 0xc3]
        }
        ReturnExpression::Atom(Atom::Constant(value)) => {
            let mut bytes = vec![0x48, 0xb8];
            bytes.extend_from_slice(&value.to_le_bytes());
            bytes.push(0xc3);
            return Ok(bytes);
        }
        _ => {
            return Err(
                "expression is parsed but has no sound x86-64 lowering in patch v1".to_owned(),
            );
        }
    };
    Ok(bytes.to_vec())
}

fn emit_patch_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if output.len().saturating_add(bytes.len()) > MAX_PATCH_BYTES {
        return Err(format!(
            "PatchIR compiled code exceeds {MAX_PATCH_BYTES} bytes"
        ));
    }
    output.extend_from_slice(bytes);
    Ok(())
}

fn encode_patch_expression_into(
    expression: &PatchExpression,
    output: &mut Vec<u8>,
    nodes: &mut usize,
) -> Result<(), String> {
    *nodes = nodes
        .checked_add(1)
        .ok_or("PatchIR expression node count overflows")?;
    if *nodes > MAX_PATCH_BYTES {
        return Err("PatchIR expression is too complex".to_owned());
    }
    match &expression.expression {
        PatchExpressionKind::Variable { name } if name == "arg0" => {
            emit_patch_bytes(output, &[0x48, 0x89, 0xf8])
        }
        PatchExpressionKind::Variable { name } if name == "arg1" => {
            emit_patch_bytes(output, &[0x48, 0x89, 0xf0])
        }
        PatchExpressionKind::Variable { name } => Err(format!(
            "PatchIR variable `{name}` was not resolved before compilation"
        )),
        PatchExpressionKind::Constant { value } => {
            emit_patch_bytes(output, &[0x48, 0xb8])?;
            emit_patch_bytes(output, &value.to_le_bytes())
        }
        PatchExpressionKind::Add { left, right }
        | PatchExpressionKind::Subtract { left, right } => {
            encode_patch_expression_into(left, output, nodes)?;
            emit_patch_bytes(output, &[0x50])?;
            encode_patch_expression_into(right, output, nodes)?;
            emit_patch_bytes(output, &[0x48, 0x89, 0xc1, 0x58])?;
            match expression.expression {
                PatchExpressionKind::Add { .. } => emit_patch_bytes(output, &[0x48, 0x01, 0xc8]),
                PatchExpressionKind::Subtract { .. } => {
                    emit_patch_bytes(output, &[0x48, 0x29, 0xc8])
                }
                _ => unreachable!("matched arithmetic expression"),
            }
        }
    }
}

fn encode_patch_expression(expression: &PatchExpression) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut nodes = 0;
    encode_patch_expression_into(expression, &mut output, &mut nodes)?;
    emit_patch_bytes(&mut output, &[0xc3])?;
    Ok(output)
}

fn expression_uses_stack(expression: &PatchExpression) -> bool {
    matches!(
        &expression.expression,
        PatchExpressionKind::Add { .. } | PatchExpressionKind::Subtract { .. }
    )
}

fn relative_jump(from: u64, to: u64) -> Result<[u8; 5], String> {
    let next = from
        .checked_add(5)
        .ok_or("trampoline entry address overflows")?;
    let displacement = i128::from(to) - i128::from(next);
    let displacement = i32::try_from(displacement)
        .map_err(|_| "replacement segment is outside rel32 trampoline reach")?;
    let mut jump = [0u8; 5];
    jump[0] = 0xe9;
    jump[1..].copy_from_slice(&displacement.to_le_bytes());
    Ok(jump)
}

/// Apply a whole-function, entry-only patch to a new ELF byte vector.
///
/// The caller must separately assert the prototype and that no control flow
/// enters the interior of the patched symbol. This library checks hash,
/// format, original liftability, exact symbol extent, relocation absence,
/// and placement safety. It prefers an in-place replacement and otherwise
/// uses a five-byte entry trampoline into an appended RX segment. It never
/// mutates the source slice.
pub fn patch_binary(bytes: &[u8], patch: &ValidatedPatch) -> Result<PatchedBinary, String> {
    let patch_program = parse_patch_program(&patch.document.replacement)?;
    if lower_scalar_return(&patch_program)? != patch.expression {
        return Err("validated patch expression differs from its PatchLang source".to_owned());
    }
    let replacement_bytes = encode(patch.expression)?;
    patch_binary_compiled(
        bytes,
        &patch.document,
        patch_program,
        replacement_bytes,
        Some(patch.expression),
        "builtin-x86_64-scalar-v1",
    )
}

/// Compile the complete currently supported HydIR PatchLang expression tree
/// and apply it through the same fail-closed ELF placement pipeline as v1.
pub fn compile_patch_binary(
    bytes: &[u8],
    document: &PatchDocument,
) -> Result<PatchedBinary, String> {
    let encoded_document =
        serde_json::to_vec(document).map_err(|error| format!("patch JSON {error}"))?;
    let (document, patch_program) = parse_patch_document(&encoded_document)?;
    let resolved = resolved_return(&patch_program)?;
    let replacement_bytes = encode_patch_expression(&resolved)?;
    patch_binary_compiled(
        bytes,
        &document,
        patch_program,
        replacement_bytes,
        None,
        "builtin-x86_64-patchir-v2",
    )
}

fn patch_binary_compiled(
    bytes: &[u8],
    document: &PatchDocument,
    patch_program: PatchProgram,
    replacement_bytes: Vec<u8>,
    legacy_expression: Option<ReturnExpression>,
    compiler: &str,
) -> Result<PatchedBinary, String> {
    let resolved = resolved_return(&patch_program)?;
    let memory_effects =
        if compiler == "builtin-x86_64-patchir-v2" && expression_uses_stack(&resolved) {
            vec!["balanced temporary stack scratch below entry rsp".to_owned()]
        } else {
            Vec::new()
        };
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != document.binary_sha256 {
        return Err("patch binary hash does not match the supplied ELF".to_owned());
    }
    lift_symbol(bytes, &document.function_symbol).map_err(|error| {
        format!("original function is outside the scalar lift contract: {error}")
    })?;
    let contract = region_contract(bytes, &document.function_symbol)
        .map_err(|error| format!("region contract unavailable: {error}"))?;
    if !contract.observed_interior_entries.is_empty() {
        return Err("patch target has an observed entry into its interior".to_owned());
    }
    if contract.exits.len() != 1 || contract.stack_delta != Some(8) {
        return Err(
            "patch requires one proven near-return exit and restored entry stack".to_owned(),
        );
    }
    if !contract.relocations.is_empty()
        || contract.unresolved_facts.iter().any(|fact| {
            fact.starts_with("scalar_cfg:")
                || fact.starts_with("scalar_lift:")
                || fact.starts_with("stack_and_exits:")
        })
    {
        return Err("patch region has unresolved scalar, stack, or relocation facts".to_owned());
    }
    let file = object::File::parse(bytes).map_err(|error| format!("ELF parse failed: {error}"))?;
    if file.format() != BinaryFormat::Elf
        || file.architecture() != Architecture::X86_64
        || !file.is_little_endian()
        || file.kind() != object::ObjectKind::Executable
    {
        return Err("patch v1 requires a linked little-endian x86-64 ELF executable".to_owned());
    }
    let mut matches = file.symbols().filter(|symbol| {
        symbol.kind() == SymbolKind::Text
            && symbol.is_definition()
            && symbol.size() > 0
            && symbol.name().ok() == Some(document.function_symbol.as_str())
    });
    let symbol = matches.next().ok_or("patch function symbol not found")?;
    if matches.next().is_some() {
        return Err("patch function symbol is ambiguous".to_owned());
    }
    let section_index = symbol
        .section_index()
        .ok_or("patch symbol has no section")?;
    let section = file
        .section_by_index(section_index)
        .map_err(|error| format!("patch section unavailable: {error}"))?;
    if section.name().ok() != Some(".text") {
        return Err("patch target must be in .text".to_owned());
    }
    let relative = symbol
        .address()
        .checked_sub(section.address())
        .ok_or("patch symbol precedes .text")?;
    let end = relative
        .checked_add(symbol.size())
        .ok_or("patch symbol extent overflow")?;
    let (section_offset, section_file_size) = section
        .file_range()
        .ok_or("patch .text has no file-backed bytes")?;
    if end > section_file_size || end > section.size() {
        return Err("patch symbol exceeds file-backed .text".to_owned());
    }
    for (relocation, _) in section.relocations() {
        if relative <= relocation && relocation < end {
            return Err("patch target contains a relocation".to_owned());
        }
    }
    let function_size = usize::try_from(symbol.size()).map_err(|_| "patch function too large")?;
    if function_size > 4096 {
        return Err("patch function exceeds the 4096-byte region limit".to_owned());
    }
    let file_start = usize::try_from(
        section_offset
            .checked_add(relative)
            .ok_or("file offset overflow")?,
    )
    .map_err(|_| "file offset too large")?;
    let file_end = file_start
        .checked_add(function_size)
        .ok_or("file range overflow")?;
    let original_region = bytes
        .get(file_start..file_end)
        .ok_or("patch function bytes unavailable")?
        .to_vec();
    if format!("{:x}", Sha256::digest(&original_region)) != contract.bytes_sha256
        || symbol.address() != contract.entry.0
        || symbol.size() != contract.byte_length
    {
        return Err("patch region bytes or symbol extent changed after contract export".to_owned());
    }
    let (content, placement_plan) = if replacement_bytes.len() <= function_size {
        let mut entry_bytes = vec![0x90; function_size];
        entry_bytes[..replacement_bytes.len()].copy_from_slice(&replacement_bytes);
        let mut content = bytes.to_vec();
        content[file_start..file_end].copy_from_slice(&entry_bytes);
        let plan = PlacementPlan {
            strategy: PlacementStrategy::InPlace,
            region_entry: Some(Address(symbol.address())),
            virtual_address: Address(symbol.address()),
            original_size: symbol.size(),
            replacement_size: replacement_bytes.len() as u64,
            padding_byte: Some(0x90),
            entry_bytes_hex: Some(hex_encode(&entry_bytes)),
            executable_segment: None,
        };
        (content, plan)
    } else {
        if function_size < 5 {
            return Err(format!(
                "replacement needs {} bytes and the {}-byte function cannot hold a 5-byte entry trampoline",
                replacement_bytes.len(),
                function_size
            ));
        }
        let appended = elf::append_executable_segment(bytes, &replacement_bytes)?;
        let jump = relative_jump(symbol.address(), appended.code_address)?;
        let mut entry_bytes = vec![0x90; function_size];
        entry_bytes[..jump.len()].copy_from_slice(&jump);
        let mut content = appended.content;
        content[file_start..file_end].copy_from_slice(&entry_bytes);
        let plan = PlacementPlan {
            strategy: PlacementStrategy::EntryTrampoline,
            region_entry: Some(Address(symbol.address())),
            virtual_address: Address(appended.code_address),
            original_size: symbol.size(),
            replacement_size: replacement_bytes.len() as u64,
            padding_byte: Some(0x90),
            entry_bytes_hex: Some(hex_encode(&entry_bytes)),
            executable_segment: Some(ExecutableSegmentPlacement {
                original_file_size: appended.original_file_size,
                original_program_header_offset: appended.original_program_header_offset,
                original_program_header_count: appended.original_program_header_count,
                program_header_offset: appended.program_header_offset,
                file_offset: appended.file_offset,
                virtual_address: Address(appended.virtual_address),
                file_size: appended.file_size,
                memory_size: appended.file_size,
                alignment: appended.alignment,
            }),
        };
        (content, plan)
    };
    let patched_sha256 = format!("{:x}", Sha256::digest(&content));
    let reimported = import_elf(&content)
        .map_err(|error| format!("patched ELF failed native re-import: {error}"))?;
    if reimported.binary_sha256 != patched_sha256 {
        return Err("patched ELF re-import digest differs from produced bytes".to_owned());
    }
    let patched_contract = region_contract(&content, &document.function_symbol)
        .map_err(|error| format!("patched region failed re-import: {error}"))?;
    if patched_contract.entry.0 != symbol.address() || patched_contract.byte_length != symbol.size()
    {
        return Err("patched region extent changed during re-import".to_owned());
    }
    let original_region_hex = hex_encode(&original_region);
    let compiled_bytes_hex = hex_encode(&replacement_bytes);
    let compiled_bytes_sha256 = format!("{:x}", Sha256::digest(&replacement_bytes));
    let toolchain_digest = format!(
        "{:x}",
        Sha256::digest(format!(
            "hydir-patch/{}/{compiler}",
            env!("CARGO_PKG_VERSION")
        ))
    );
    let bundle = PatchBundle {
        schema_version: PATCH_BUNDLE_VERSION,
        source: document.clone(),
        typed_patch_ir: PatchIr {
            schema_version: 1,
            prototype: document.prototype.clone(),
            expression: legacy_expression,
            resolved_return: Some(resolved),
            statements: patch_program.statements,
            inputs: vec!["rdi:u64(arg0)".to_owned(), "rsi:u64(arg1)".to_owned()],
            outputs: vec!["rax:u64(return)".to_owned()],
            exits: contract.exits.clone(),
            memory_effects,
            source_range: patch_program.source_range,
        },
        region_digest: contract.bytes_sha256.clone(),
        original_region_hex,
        compiled_bytes_hex,
        compiled_bytes_sha256,
        boundary_adapters: vec![BoundaryAdapter {
            entry_bindings: vec!["rdi -> arg0".to_owned(), "rsi -> arg1".to_owned()],
            exit_bindings: vec!["return -> rax".to_owned()],
            exit_rsp_delta: contract.stack_delta.expect("proven above"),
            preserved_locations: vec!["rsp restored by near return".to_owned()],
            unresolved_requirements: vec![
                "physical live-out registers and flags are not fully recovered".to_owned(),
                "entry and exit stack alignment residues are not established".to_owned(),
            ],
        }],
        placement_plan,
        relocation_records: Vec::new(),
        toolchain_digest,
        original_sha256: digest.clone(),
        patched_sha256: patched_sha256.clone(),
        verification_evidence: vec![
            VerificationEvidence {
                check: "original_region_digest".to_owned(),
                status: VerificationStatus::Passed,
                details: "original symbol bytes matched the pre-patch RegionSpec".to_owned(),
            },
            VerificationEvidence {
                check: "patched_elf_reimport".to_owned(),
                status: VerificationStatus::Passed,
                details: "output parsed as ELF and retained the selected symbol extent".to_owned(),
            },
            VerificationEvidence {
                check: "differential_behavior".to_owned(),
                status: VerificationStatus::NotRun,
                details: "behavior validation is a separate required gate".to_owned(),
            },
        ],
        stable_verified: false,
    };
    validate_patch_bundle(&bundle)?;
    Ok(PatchedBinary {
        content,
        original_sha256: digest,
        patched_sha256,
        function_address: symbol.address(),
        function_size: symbol.size(),
        replacement_bytes,
        original_region,
        region_bytes_sha256: contract.bytes_sha256,
        region_exit: contract.exits[0].0,
        exit_rsp_delta: contract.stack_delta.expect("proven above"),
        bundle,
    })
}

/// Reverse a HydIR patch after verifying the complete patched-file digest and
/// every placement field needed to identify the modified entry and ELF layout.
pub fn revert_patch_binary(bytes: &[u8], bundle: &PatchBundle) -> Result<Vec<u8>, String> {
    validate_patch_bundle(bundle)?;
    if format!("{:x}", Sha256::digest(bytes)) != bundle.patched_sha256 {
        return Err("patched binary hash does not match the PatchBundle".to_owned());
    }
    let region_entry = bundle
        .placement_plan
        .region_entry
        .ok_or("PatchBundle predates reversible region-entry metadata")?;
    let expected_entry = decode_hex(
        bundle
            .placement_plan
            .entry_bytes_hex
            .as_deref()
            .ok_or("PatchBundle predates reversible entry-byte metadata")?,
        "entry bytes",
    )?;
    let original_region = decode_hex(&bundle.original_region_hex, "original region")?;

    let (file_start, file_end) = {
        let file = object::File::parse(bytes)
            .map_err(|error| format!("patched ELF parse failed: {error}"))?;
        let mut matches = file.symbols().filter(|symbol| {
            symbol.kind() == SymbolKind::Text
                && symbol.is_definition()
                && symbol.size() > 0
                && symbol.name().ok() == Some(bundle.source.function_symbol.as_str())
        });
        let symbol = matches.next().ok_or("patched function symbol not found")?;
        if matches.next().is_some() {
            return Err("patched function symbol is ambiguous".to_owned());
        }
        if symbol.address() != region_entry.0 || symbol.size() != original_region.len() as u64 {
            return Err("patched function extent differs from the PatchBundle".to_owned());
        }
        let section = file
            .section_by_index(
                symbol
                    .section_index()
                    .ok_or("patched function has no section")?,
            )
            .map_err(|error| format!("patched function section unavailable: {error}"))?;
        let relative = symbol
            .address()
            .checked_sub(section.address())
            .ok_or("patched function precedes its section")?;
        let (section_offset, section_file_size) = section
            .file_range()
            .ok_or("patched function section has no file-backed bytes")?;
        let end = relative
            .checked_add(symbol.size())
            .ok_or("patched function extent overflows")?;
        if end > section_file_size {
            return Err("patched function exceeds its file-backed section".to_owned());
        }
        let start = usize::try_from(
            section_offset
                .checked_add(relative)
                .ok_or("patched function file offset overflows")?,
        )
        .map_err(|_| "patched function file offset is too large")?;
        let end = start
            .checked_add(original_region.len())
            .ok_or("patched function file range overflows")?;
        (start, end)
    };

    if bytes.get(file_start..file_end) != Some(expected_entry.as_slice()) {
        return Err("patched entry bytes differ from the PatchBundle".to_owned());
    }
    let mut restored = bytes.to_vec();
    restored[file_start..file_end].copy_from_slice(&original_region);
    if bundle.placement_plan.strategy == PlacementStrategy::EntryTrampoline {
        let segment = bundle
            .placement_plan
            .executable_segment
            .as_ref()
            .ok_or("PatchBundle executable segment placement is missing")?;
        elf::restore_original_layout(
            &mut restored,
            segment.program_header_offset,
            segment.original_file_size,
            segment.original_program_header_offset,
            segment.original_program_header_count,
        )?;
    }
    if format!("{:x}", Sha256::digest(&restored)) != bundle.original_sha256 {
        return Err("reversed binary does not match the original digest".to_owned());
    }
    import_elf(&restored)
        .map_err(|error| format!("reversed ELF failed native re-import: {error}"))?;
    Ok(restored)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn return_parser_tracks_location_and_rejects_unknown_code() {
        assert_eq!(
            parse_return_expression("return arg0 - arg1;").unwrap(),
            ReturnExpression::Sub(Atom::Arg0, Atom::Arg1)
        );
        assert_eq!(
            parse_return_expression("return 0xffffffffffffffff;").unwrap(),
            ReturnExpression::Atom(Atom::Constant(u64::MAX))
        );
        let error = parse_return_expression("return arg0 + call();").unwrap_err();
        assert!(error.contains("replacement:1:"));
        assert!(parse_return_expression("return arg0; system(1);").is_err());
    }

    #[test]
    fn encoding_and_schema_fail_closed() {
        assert_eq!(
            encode(ReturnExpression::Sub(Atom::Arg0, Atom::Arg1)).unwrap(),
            [0x48, 0x89, 0xf8, 0x48, 0x29, 0xf0, 0xc3]
        );
        assert!(encode(ReturnExpression::Add(Atom::Arg0, Atom::Constant(1))).is_err());
        assert!(parse_patch_json(br#"{"schema_version":2}"#).is_err());
        assert!(
            patch_binary(
                b"not an ELF",
                &ValidatedPatch {
                    document: PatchDocument {
                        schema_version: 1,
                        binary_sha256: format!("{:x}", Sha256::digest(b"not an ELF")),
                        function_symbol: "x".to_owned(),
                        prototype: "u64(u64,u64)".to_owned(),
                        replacement: "return arg0;".to_owned()
                    },
                    expression: ReturnExpression::Atom(Atom::Arg0),
                }
            )
            .is_err()
        );
    }

    #[test]
    fn patch_rejects_known_interior_entry() {
        for binary in [
            include_bytes!("../../../fuzz/corpus/elf_import/interior_entry.elf").as_slice(),
            include_bytes!("../../../fuzz/corpus/elf_import/interior_call.elf").as_slice(),
        ] {
            let patch = ValidatedPatch {
                document: PatchDocument {
                    schema_version: PATCH_SCHEMA_VERSION,
                    binary_sha256: format!("{:x}", Sha256::digest(binary)),
                    function_symbol: "hydir_outer".to_owned(),
                    prototype: "u64(u64,u64)".to_owned(),
                    replacement: "return arg0;".to_owned(),
                },
                expression: ReturnExpression::Atom(Atom::Arg0),
            };
            assert!(
                patch_binary(binary, &patch)
                    .unwrap_err()
                    .contains("observed entry into its interior")
            );
        }
    }

    #[test]
    fn scalar_patch_emits_reversible_v2_bundle_and_reimports_output() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/max2.elf");
        let patch = ValidatedPatch {
            document: PatchDocument {
                schema_version: PATCH_SCHEMA_VERSION,
                binary_sha256: format!("{:x}", Sha256::digest(binary)),
                function_symbol: "hydir_max2".to_owned(),
                prototype: "u64(u64,u64)".to_owned(),
                replacement: "return arg0;".to_owned(),
            },
            expression: ReturnExpression::Atom(Atom::Arg0),
        };
        let result = patch_binary(binary, &patch).unwrap();
        assert_eq!(result.bundle.schema_version, PATCH_BUNDLE_VERSION);
        assert_eq!(
            decode_hex(&result.bundle.original_region_hex, "test").unwrap(),
            result.original_region
        );
        assert!(!result.bundle.stable_verified);
        assert_eq!(result.bundle.typed_patch_ir.statements.len(), 1);
        assert!(matches!(
            result.bundle.typed_patch_ir.statements.last(),
            Some(PatchStatement::Return { .. })
        ));
        assert_eq!(
            revert_patch_binary(&result.content, &result.bundle).unwrap(),
            binary.as_slice()
        );
        let serialized = serde_json::to_vec(&result.bundle).unwrap();
        let parsed = parse_patch_bundle_json(&serialized).unwrap();
        assert_eq!(parsed.patched_sha256, result.patched_sha256);
        assert!(
            parsed
                .verification_evidence
                .iter()
                .any(|evidence| evidence.check == "patched_elf_reimport"
                    && evidence.status == VerificationStatus::Passed)
        );

        let mut legacy: serde_json::Value = serde_json::from_slice(&serialized).unwrap();
        legacy["typed_patch_ir"]
            .as_object_mut()
            .unwrap()
            .remove("statements");
        legacy["typed_patch_ir"]
            .as_object_mut()
            .unwrap()
            .remove("resolved_return");
        let placement = legacy["placement_plan"].as_object_mut().unwrap();
        placement.remove("region_entry");
        placement.remove("entry_bytes_hex");
        placement.remove("executable_segment");
        let parsed_legacy = parse_patch_bundle_json(&serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(parsed_legacy.typed_patch_ir.statements.is_empty());
        assert!(parsed_legacy.typed_patch_ir.resolved_return.is_none());
    }

    #[test]
    fn patchir_v2_compiles_nested_assignments_and_reverts_exactly() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/frame.elf");
        let document = PatchDocument {
            schema_version: PATCH_SCHEMA_VERSION,
            binary_sha256: format!("{:x}", Sha256::digest(binary)),
            function_symbol: "hydir_nop_identity".to_owned(),
            prototype: "u64(u64,u64)".to_owned(),
            replacement: "u64 sum = arg0 + arg1;\nsum = sum - arg1;\nreturn sum;".to_owned(),
        };
        let json = serde_json::to_vec(&document).unwrap();
        assert!(parse_patch_document(&json).is_ok());
        assert!(
            parse_patch_json(&json)
                .unwrap_err()
                .contains("nested subtraction")
        );

        let result = compile_patch_binary(binary, &document).unwrap();
        assert_eq!(
            result.bundle.placement_plan.strategy,
            PlacementStrategy::EntryTrampoline
        );
        assert!(result.bundle.typed_patch_ir.expression.is_none());
        assert!(matches!(
            result
                .bundle
                .typed_patch_ir
                .resolved_return
                .as_ref()
                .map(|expression| &expression.expression),
            Some(PatchExpressionKind::Subtract { .. })
        ));
        assert_eq!(result.bundle.typed_patch_ir.statements.len(), 3);
        assert_eq!(
            result.bundle.typed_patch_ir.memory_effects,
            ["balanced temporary stack scratch below entry rsp"]
        );
        assert_eq!(
            result.replacement_bytes,
            [
                0x48, 0x89, 0xf8, 0x50, 0x48, 0x89, 0xf0, 0x48, 0x89, 0xc1, 0x58, 0x48, 0x01, 0xc8,
                0x50, 0x48, 0x89, 0xf0, 0x48, 0x89, 0xc1, 0x58, 0x48, 0x29, 0xc8, 0xc3,
            ]
        );
        assert_eq!(
            revert_patch_binary(&result.content, &result.bundle).unwrap(),
            binary.as_slice()
        );

        let mut tampered = serde_json::to_value(&result.bundle).unwrap();
        tampered["typed_patch_ir"]["resolved_return"]["expression"]["kind"] =
            serde_json::Value::String("add".to_owned());
        assert!(
            parse_patch_bundle_json(&serde_json::to_vec(&tampered).unwrap())
                .unwrap_err()
                .contains("resolved return differs")
        );
    }

    #[test]
    fn oversized_scalar_replacement_uses_a_reimportable_rx_segment_trampoline() {
        let binary = include_bytes!("../../../fuzz/corpus/elf_import/frame.elf");
        let patch = ValidatedPatch {
            document: PatchDocument {
                schema_version: PATCH_SCHEMA_VERSION,
                binary_sha256: format!("{:x}", Sha256::digest(binary)),
                function_symbol: "hydir_nop_identity".to_owned(),
                prototype: "u64(u64,u64)".to_owned(),
                replacement: "return 0x0123456789abcdef;".to_owned(),
            },
            expression: ReturnExpression::Atom(Atom::Constant(0x0123_4567_89ab_cdef)),
        };
        let result = patch_binary(binary, &patch).unwrap();
        assert_eq!(
            result.bundle.placement_plan.strategy,
            PlacementStrategy::EntryTrampoline
        );
        assert!(result.content.len() > binary.len());
        let entry = decode_hex(
            result
                .bundle
                .placement_plan
                .entry_bytes_hex
                .as_deref()
                .unwrap(),
            "test entry",
        )
        .unwrap();
        assert_eq!(entry.len(), 5);
        assert_eq!(entry[0], 0xe9);
        let original_segments = import_elf(binary).unwrap().mapped_segments.len();
        let patched_segments = import_elf(&result.content).unwrap().mapped_segments.len();
        assert_eq!(patched_segments, original_segments + 1);
        validate_patch_bundle(&result.bundle).unwrap();
        assert_eq!(
            revert_patch_binary(&result.content, &result.bundle).unwrap(),
            binary.as_slice()
        );
    }
}
