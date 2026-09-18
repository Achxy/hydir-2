//! Frontend-neutral facts recovered from a binary. Unknown recovery is never
//! represented as a negative fact.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SPEC_VERSION: u32 = 1;
pub const PROGRAM_SPEC_VERSION: u32 = 2;

/// JSON addresses are strings so no consumer can round a 64-bit address via f64.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Address(pub u64);

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{:016x}", self.0))
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let digits = value
            .strip_prefix("0x")
            .ok_or_else(|| serde::de::Error::custom("address must start with 0x"))?;
        u64::from_str_radix(digits, 16)
            .map(Address)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramSpec {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub target_triple: String,
    pub abi: String,
    pub file_kind: String,
    pub image_base: Option<Address>,
    pub entry_point: Option<Address>,
    pub data_layout: Option<String>,
    /// Address space zero is the ELF process image for linked files. No
    /// runtime load bias is asserted for position-independent executables.
    pub address_spaces: Vec<AddressSpaceSpec>,
    /// PT_LOAD mappings, distinct from file-derived sections.
    pub mapped_segments: Vec<MappedSegmentSpec>,
    /// Sections are file-derived. They are not a reconstructed runtime image.
    pub sections: Vec<SectionSpec>,
    pub functions: Vec<FunctionSpec>,
    pub imports: Vec<ImportSpec>,
    pub relocations: Vec<RelocationSpec>,
    /// Empty collections are not negative facts while recovery is unattempted.
    pub calls: Vec<CallSpec>,
    pub references: Vec<ReferenceSpec>,
    pub call_recovery: RecoveryState,
    pub reference_recovery: RecoveryState,
    pub assumptions: Vec<AssumptionSpec>,
    pub recovery_scope: String,
    pub unresolved_control_flow: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddressSpaceSpec {
    pub id: u32,
    pub name: String,
    pub address_kind: AddressKind,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MappedSegmentSpec {
    pub id: String,
    pub address_space: u32,
    pub virtual_address: Address,
    pub memory_size: u64,
    pub file_offset: Address,
    pub file_size: u64,
    pub alignment: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImportSpec {
    pub library: String,
    pub name: String,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelocationSpec {
    pub location: Address,
    pub address_kind: AddressKind,
    pub source_section: Option<String>,
    pub kind: String,
    pub encoding: String,
    /// Format-specific relocation flags preserve ELF type when the generic
    /// object API reports `Unknown`.
    pub format_flags: String,
    pub size_bits: u8,
    pub addend: i64,
    pub implicit_addend: bool,
    pub target: RelocationTargetSpec,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RelocationTargetSpec {
    Symbol { id: String, name: Option<String> },
    Section { name: String },
    Absolute,
    Unresolved { description: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallSpec {
    pub source: Address,
    pub target: Option<Address>,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReferenceSpec {
    pub source: Address,
    pub target: Option<Address>,
    pub provenance: FactProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryState {
    NotAttempted,
    Partial,
    Complete,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssumptionSpec {
    pub id: String,
    pub statement: String,
    pub scope: String,
    /// Virtual address when an analyst assertion is site-specific.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Address>,
    pub provenance: FactProvenance,
}

/// Analyst-authored project metadata. It is scoped to one immutable binary
/// digest and the project revision that recorded it, never an ELF fact.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalystAnnotation {
    pub id: String,
    pub binary_sha256: String,
    pub created_revision: u64,
    pub kind: AnnotationKind,
    pub address: Option<Address>,
    pub value: String,
    pub scope: String,
    pub provenance: FactProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnnotationKind {
    Name,
    Comment,
    Assumption,
}

impl AnnotationKind {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "name" => Ok(Self::Name),
            "comment" => Ok(Self::Comment),
            "assumption" => Ok(Self::Assumption),
            _ => Err("annotation kind must be name, comment, or assumption"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Comment => "comment",
            Self::Assumption => "assumption",
        }
    }
}

pub fn parse_annotation_address(value: &str) -> Result<Option<Address>, &'static str> {
    if value.is_empty() || value == "-" {
        return Ok(None);
    }
    let digits = value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty() && digits.len() <= 16)
        .ok_or("address must be 0x plus 1..=16 hex digits")?;
    u64::from_str_radix(digits, 16)
        .map(Address)
        .map(Some)
        .map_err(|_| "address must be hexadecimal")
}

pub fn validate_analyst_annotation(
    kind: AnnotationKind,
    address: Option<Address>,
    value: &str,
    scope: &str,
    idempotency_key: &str,
) -> Result<(), String> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > 128
        || idempotency_key.chars().any(char::is_control)
    {
        return Err("annotation idempotency key must be 1..=128 non-control bytes".to_owned());
    }
    if kind == AnnotationKind::Name && address.is_none() {
        return Err("name requires a virtual address".to_owned());
    }
    let max_value = match kind {
        AnnotationKind::Name => 128,
        AnnotationKind::Comment => 2048,
        AnnotationKind::Assumption => 1024,
    };
    if value.trim().is_empty()
        || value.len() > max_value
        || value.chars().any(|character| character == '\0')
        || (kind == AnnotationKind::Name && value.chars().any(char::is_control))
    {
        return Err(format!(
            "annotation value must be 1..={max_value} bytes without forbidden control characters"
        ));
    }
    if scope.trim().is_empty() || scope.len() > 256 || scope.chars().any(char::is_control) {
        return Err("annotation scope must be 1..=256 non-control bytes".to_owned());
    }
    Ok(())
}

pub fn annotation_address_in_spec(spec: &ProgramSpec, address: Address) -> bool {
    spec.mapped_segments.iter().any(|segment| {
        segment.virtual_address.0 <= address.0
            && segment
                .virtual_address
                .0
                .checked_add(segment.memory_size)
                .is_some_and(|end| address.0 < end)
    })
}

pub fn overlay_analyst_assumptions(spec: &mut ProgramSpec, annotations: &[AnalystAnnotation]) {
    for annotation in annotations {
        if annotation.kind == AnnotationKind::Assumption {
            spec.assumptions.push(AssumptionSpec {
                id: annotation.id.clone(),
                statement: annotation.value.clone(),
                scope: annotation.scope.clone(),
                address: annotation.address,
                provenance: annotation.provenance.clone(),
            });
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactProvenance {
    pub source: FactSource,
    pub scope: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactSource {
    ElfMetadata,
    NativeAnalysis,
    AnalystAssertion,
    ValidationEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionSpec {
    pub name: String,
    pub address: Address,
    pub address_kind: AddressKind,
    pub file_offset: Option<Address>,
    pub size: u64,
    pub kind: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionSpec {
    pub id: String,
    pub name: String,
    pub address: Address,
    pub address_kind: AddressKind,
    pub section_name: String,
    pub size: u64,
    pub provenance: String,
    pub control_flow_status: String,
}

/// One-instruction blocks are the current native recovery granularity.
/// Facts here describe reachable bytes in a selected, bounded ELF symbol,
/// not a claim of complete whole-program recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionCfg {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub symbol_name: String,
    pub entry: Address,
    pub address_kind: AddressKind,
    pub symbol_size: u64,
    pub blocks: Vec<BlockSpec>,
    pub edges: Vec<EdgeSpec>,
    pub provenance: String,
    pub recovery_scope: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockSpec {
    pub address: Address,
    pub bytes_hex: String,
    pub mnemonic: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EdgeSpec {
    pub source: Address,
    pub target: Address,
    pub kind: EdgeKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Direct,
    Taken,
    Fallthrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressKind {
    Virtual,
    SectionRelative,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_is_hex_string_not_json_number() {
        let original = Address(0xffff_ffff_ffff_fffe);
        let json = serde_json::to_string(&original).unwrap();
        assert_eq!(json, "\"0xfffffffffffffffe\"");
        let recovered: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered, original);
    }
}
