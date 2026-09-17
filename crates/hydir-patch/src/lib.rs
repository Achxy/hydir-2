//! Versioned, fail-closed whole-function patching for a tiny scalar ABI slice.
//!
//! The source grammar deliberately mirrors IRENE's edited C return-expression
//! idea, but this is not a parser for the upstream PatchLang or C generally.
//! It accepts only side-effect-free two-argument return expressions that fit
//! one of the exact, independently encoded x86-64 replacements below.

use hydir_backend::lift_symbol;
use object::{Architecture, BinaryFormat, Object, ObjectSection, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PATCH_SCHEMA_VERSION: u32 = 1;
pub const MAX_PATCH_BYTES: usize = 4096;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PatchDocument {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub function_symbol: String,
    pub prototype: String,
    pub replacement: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Atom {
    Arg0,
    Arg1,
    Constant(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    let mut content = bytes.to_vec();
    content[file_start..file_start + replacement_bytes.len()].copy_from_slice(&replacement_bytes);
    content[file_start + replacement_bytes.len()..file_end].fill(0x90);
    let patched_sha256 = format!("{:x}", Sha256::digest(&content));
    Ok(PatchedBinary {
        content,
        original_sha256: digest,
        patched_sha256,
        function_address: symbol.address(),
        function_size: symbol.size(),
        replacement_bytes,
        original_region,
    })
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
}
