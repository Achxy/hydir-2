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
    pub provenance: FactProvenance,
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
