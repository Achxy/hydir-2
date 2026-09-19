//! Versioned, fail-closed whole-function patching for a tiny scalar ABI slice.
//!
//! It accepts only side-effect-free two-argument return expressions that fit
//! one of the exact, independently encoded x86-64 replacements below.

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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    pub expression: ReturnExpression,
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
    pub virtual_address: Address,
    pub original_size: u64,
    pub replacement_size: u64,
    pub padding_byte: Option<u8>,
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

struct Parser<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Parser<'a> {
    fn skip_space(&mut self) {
        while self.bytes.get(self.at).is_some_and(u8::is_ascii_whitespace) {
            self.at += 1;
        }
    }

    fn error(&self, message: &str) -> String {
        let before = &self.bytes[..self.at.min(self.bytes.len())];
        let line = before.iter().filter(|byte| **byte == b'\n').count() + 1;
        let column = before
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(before.len() + 1, |index| before.len() - index);
        format!("replacement:{line}:{column}: {message}")
    }

    fn keyword(&mut self, keyword: &[u8]) -> Result<(), String> {
        self.skip_space();
        if self.bytes.get(self.at..self.at + keyword.len()) != Some(keyword) {
            return Err(self.error("expected `return`"));
        }
        self.at += keyword.len();
        if self
            .bytes
            .get(self.at)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(self.error("expected whitespace after `return`"));
        }
        Ok(())
    }

    fn atom(&mut self) -> Result<Atom, String> {
        self.skip_space();
        let start = self.at;
        while self
            .bytes
            .get(self.at)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            self.at += 1;
        }
        let token = self.bytes.get(start..self.at).unwrap_or_default();
        match token {
            b"arg0" => Ok(Atom::Arg0),
            b"arg1" => Ok(Atom::Arg1),
            b"" => Err(self.error("expected arg0, arg1, or an unsigned literal")),
            _ => {
                let token = std::str::from_utf8(token)
                    .map_err(|_| self.error("non-ASCII literal is unsupported"))?;
                let number = if let Some(hex) = token.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    token.parse::<u64>()
                }
                .map_err(|_| {
                    self.error("expected an exact u64 decimal or 0x hexadecimal literal")
                })?;
                Ok(Atom::Constant(number))
            }
        }
    }
}

/// Parse a narrow C-compatible `return atom [+|- atom];` statement.
pub fn parse_return_expression(source: &str) -> Result<ReturnExpression, String> {
    if source.len() > 256 || !source.is_ascii() {
        return Err("replacement must be at most 256 ASCII bytes".to_owned());
    }
    let mut parser = Parser {
        bytes: source.as_bytes(),
        at: 0,
    };
    parser.keyword(b"return")?;
    let left = parser.atom()?;
    parser.skip_space();
    let operation = match parser.bytes.get(parser.at) {
        Some(b'+') => {
            parser.at += 1;
            Some(b'+')
        }
        Some(b'-') => {
            parser.at += 1;
            Some(b'-')
        }
        _ => None,
    };
    let expression = if let Some(operation) = operation {
        let right = parser.atom()?;
        if operation == b'+' {
            ReturnExpression::Add(left, right)
        } else {
            ReturnExpression::Sub(left, right)
        }
    } else {
        ReturnExpression::Atom(left)
    };
    parser.skip_space();
    if parser.bytes.get(parser.at) != Some(&b';') {
        return Err(parser.error("expected `;` after return expression"));
    }
    parser.at += 1;
    parser.skip_space();
    if parser.at != parser.bytes.len() {
        return Err(parser.error("unexpected tokens after return statement"));
    }
    Ok(expression)
}

pub fn parse_patch_json(bytes: &[u8]) -> Result<ValidatedPatch, String> {
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
    let expression = parse_return_expression(&document.replacement)?;
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
    let original = decode_hex(&bundle.original_region_hex, "original region")?;
    let compiled = decode_hex(&bundle.compiled_bytes_hex, "compiled bytes")?;
    if format!("{:x}", Sha256::digest(&original)) != bundle.region_digest
        || format!("{:x}", Sha256::digest(&compiled)) != bundle.compiled_bytes_sha256
    {
        return Err("PatchBundle embedded byte digest mismatch".to_owned());
    }
    if bundle.placement_plan.original_size != original.len() as u64
        || bundle.placement_plan.replacement_size != compiled.len() as u64
        || bundle.placement_plan.replacement_size > bundle.placement_plan.original_size
    {
        return Err("PatchBundle placement sizes do not match embedded bytes".to_owned());
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

/// Apply a whole-function, entry-only in-place patch to a new ELF byte vector.
///
/// The caller must separately assert the prototype and that no control flow
/// enters the interior of the patched symbol. This library checks hash,
/// format, original liftability, exact symbol extent, relocation absence,
/// and replacement fit. It never mutates the source slice.
pub fn patch_binary(bytes: &[u8], patch: &ValidatedPatch) -> Result<PatchedBinary, String> {
    let digest = format!("{:x}", Sha256::digest(bytes));
    if digest != patch.document.binary_sha256 {
        return Err("patch binary hash does not match the supplied ELF".to_owned());
    }
    lift_symbol(bytes, &patch.document.function_symbol).map_err(|error| {
        format!("original function is outside the scalar lift contract: {error}")
    })?;
    let contract = region_contract(bytes, &patch.document.function_symbol)
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
            && symbol.name().ok() == Some(patch.document.function_symbol.as_str())
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
    let replacement_bytes = encode(patch.expression)?;
    let function_size = usize::try_from(symbol.size()).map_err(|_| "patch function too large")?;
    if function_size > 4096 || replacement_bytes.len() > function_size {
        return Err(format!(
            "replacement needs {} bytes but function region has {} bytes",
            replacement_bytes.len(),
            function_size
        ));
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
    let mut content = bytes.to_vec();
    content[file_start..file_start + replacement_bytes.len()].copy_from_slice(&replacement_bytes);
    content[file_start + replacement_bytes.len()..file_end].fill(0x90);
    let patched_sha256 = format!("{:x}", Sha256::digest(&content));
    let reimported = import_elf(&content)
        .map_err(|error| format!("patched ELF failed native re-import: {error}"))?;
    if reimported.binary_sha256 != patched_sha256 {
        return Err("patched ELF re-import digest differs from produced bytes".to_owned());
    }
    let patched_contract = region_contract(&content, &patch.document.function_symbol)
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
        Sha256::digest(concat!(
            "hydir-patch/",
            env!("CARGO_PKG_VERSION"),
            "/builtin-x86_64-scalar-v1"
        ))
    );
    let last_line = patch.document.replacement.lines().count().max(1) as u32;
    let last_column = patch
        .document
        .replacement
        .lines()
        .last()
        .map_or(1, |line| line.chars().count() as u32 + 1);
    let bundle = PatchBundle {
        schema_version: PATCH_BUNDLE_VERSION,
        source: patch.document.clone(),
        typed_patch_ir: PatchIr {
            schema_version: 1,
            prototype: patch.document.prototype.clone(),
            expression: patch.expression,
            inputs: vec!["rdi:u64(arg0)".to_owned(), "rsi:u64(arg1)".to_owned()],
            outputs: vec!["rax:u64(return)".to_owned()],
            exits: contract.exits.clone(),
            memory_effects: Vec::new(),
            source_range: SourceRange {
                start_line: 1,
                start_column: 1,
                end_line: last_line,
                end_column: last_column,
            },
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
        placement_plan: PlacementPlan {
            strategy: PlacementStrategy::InPlace,
            virtual_address: Address(symbol.address()),
            original_size: symbol.size(),
            replacement_size: replacement_bytes.len() as u64,
            padding_byte: Some(0x90),
        },
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
    }
}
