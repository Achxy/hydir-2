//! Frontend-neutral facts recovered from a binary. Unknown recovery is never
//! represented as a negative fact.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const SPEC_VERSION: u32 = 1;
pub const PROGRAM_SPEC_VERSION: u32 = 3;

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
    /// Typed analyst facts are separate from ELF-derived facts and begin empty.
    #[serde(default)]
    pub typed_model: TypedModel,
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
pub struct TypedModel {
    pub schema_version: u32,
    pub prototypes: Vec<PrototypeAssertion>,
    pub stack_facts: Vec<StackFact>,
}

impl Default for TypedModel {
    fn default() -> Self {
        Self {
            schema_version: 1,
            prototypes: Vec::new(),
            stack_facts: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    U64,
    Void,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    SysvAmd64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrototypeAssertion {
    pub id: String,
    pub entry: Address,
    pub return_type: ScalarType,
    pub parameters: Vec<ScalarType>,
    pub calling_convention: CallingConvention,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StackFact {
    pub id: String,
    pub function_entry: Address,
    /// Signed displacement from function-entry RSP. This is an assertion,
    /// not an alias proof or an instruction-level stack analysis result.
    pub entry_rsp_offset: i64,
    pub width_bits: u16,
    pub provenance: FactProvenance,
}

pub fn migrate_program_spec(mut spec: ProgramSpec) -> Result<ProgramSpec, String> {
    match spec.schema_version {
        2 => spec.schema_version = PROGRAM_SPEC_VERSION,
        PROGRAM_SPEC_VERSION => {}
        other => return Err(format!("unsupported ProgramSpec schema version {other}")),
    }
    validate_typed_model(&spec)?;
    Ok(spec)
}

pub fn parse_program_spec_json(bytes: &[u8]) -> Result<ProgramSpec, String> {
    let spec: ProgramSpec = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid ProgramSpec JSON: {error}"))?;
    migrate_program_spec(spec)
}

pub fn validate_typed_model(spec: &ProgramSpec) -> Result<(), String> {
    if spec.typed_model.schema_version != 1 {
        return Err(format!(
            "unsupported typed model schema version {}",
            spec.typed_model.schema_version
        ));
    }
    if spec.typed_model.prototypes.len() > 8192 || spec.typed_model.stack_facts.len() > 32768 {
        return Err("typed model exceeds bounded fact count".to_owned());
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut entries = std::collections::BTreeSet::new();
    let valid_id = |id: &str| {
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    };
    for prototype in &spec.typed_model.prototypes {
        if !ids.insert(prototype.id.as_str()) || !entries.insert(prototype.entry) {
            return Err("duplicate typed prototype id or entry".to_owned());
        }
        if !valid_id(&prototype.id) || prototype.parameters.len() > 6 {
            return Err("invalid prototype id or parameter count".to_owned());
        }
        if prototype
            .parameters
            .iter()
            .any(|parameter| *parameter == ScalarType::Void)
        {
            return Err("void is not a parameter type".to_owned());
        }
        if prototype.provenance.source != FactSource::AnalystAssertion {
            return Err("typed prototype must identify analyst assertion provenance".to_owned());
        }
        if !spec.mapped_segments.iter().any(|segment| {
            segment.executable
                && segment.virtual_address.0 <= prototype.entry.0
                && segment
                    .virtual_address
                    .0
                    .checked_add(segment.memory_size)
                    .is_some_and(|end| prototype.entry.0 < end)
        }) {
            return Err(format!(
                "prototype entry 0x{:x} is not in executable mapping",
                prototype.entry.0
            ));
        }
    }
    for fact in &spec.typed_model.stack_facts {
        if !ids.insert(fact.id.as_str()) || !valid_id(&fact.id) {
            return Err("duplicate or invalid stack fact id".to_owned());
        }
        if !matches!(fact.width_bits, 8 | 16 | 32 | 64)
            || !(-65536..=65536).contains(&fact.entry_rsp_offset)
        {
            return Err("stack fact width or displacement is out of bounds".to_owned());
        }
        if fact.provenance.source != FactSource::AnalystAssertion {
            return Err("stack fact must identify analyst assertion provenance".to_owned());
        }
        if !entries.contains(&fact.function_entry) {
            return Err("stack fact has no matching typed prototype".to_owned());
        }
    }
    Ok(())
}

/// Evidence for a symbol-bounded region. Missing machine-state facts remain
/// explicit and prevent this artifact from authorizing a replacement.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionContract {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub symbol_name: String,
    pub address_kind: AddressKind,
    pub entry: Address,
    pub byte_length: u64,
    pub bytes_sha256: String,
    pub bytes_hex: String,
    pub exits: Vec<Address>,
    pub relocations: Vec<RelocationSpec>,
    #[serde(default)]
    pub observed_interior_entries: Vec<InteriorEntryEvidence>,
    pub live_in: Option<Vec<String>>,
    pub live_out: Option<Vec<String>>,
    /// RSP after each reachable near RET relative to RSP at region entry.
    pub stack_delta: Option<i64>,
    pub unresolved_facts: Vec<String>,
    pub replacement_ready: bool,
    pub provenance: FactProvenance,
}

/// A concrete lead that another entry may reach bytes inside a selected region.
/// Its absence is not proof that no indirect or undiscovered entry exists.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InteriorEntryEvidence {
    pub entry: Address,
    pub source: Option<Address>,
    pub reason: String,
    pub provenance: FactProvenance,
}

pub const DISASSEMBLY_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisassemblyReport {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub target_triple: String,
    pub sections: Vec<DisassemblySection>,
    pub functions: Vec<DisassemblyFunction>,
    /// Direct-call targets are leads, never asserted function boundaries.
    #[serde(default)]
    pub candidates: Vec<FunctionCandidate>,
    pub instructions: Vec<DisassemblyInstruction>,
    pub gaps: Vec<DisassemblyGap>,
    pub warnings: Vec<String>,
    pub provenance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionCandidate {
    pub entry: Address,
    pub evidence_site: Address,
    pub evidence_bytes_hex: String,
    pub reason: String,
    pub extent: Option<u64>,
    pub recovery_state: RecoveryState,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisassemblySection {
    pub name: String,
    pub address: Address,
    pub size: u64,
    pub executable: bool,
    pub provenance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisassemblyFunction {
    pub name: String,
    pub entry: Address,
    pub size: u64,
    pub instruction_addresses: Vec<Address>,
    pub provenance: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisassemblyInstruction {
    pub address: Address,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operands: String,
    pub flow: DisassemblyFlow,
    pub branch_target: Option<Address>,
    pub function: Option<String>,
    pub provenance: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisassemblyFlow {
    Next,
    ConditionalBranch,
    UnconditionalBranch,
    Call,
    Return,
    IndirectBranch,
    IndirectCall,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DisassemblyGap {
    pub address: Address,
    pub size: u64,
    pub reason: String,
    pub provenance: String,
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

    #[test]
    fn program_spec_v2_migrates_and_typed_assertions_validate() {
        let provenance = FactProvenance {
            source: FactSource::AnalystAssertion,
            scope: "test".to_owned(),
        };
        let mut spec = ProgramSpec {
            schema_version: PROGRAM_SPEC_VERSION,
            binary_sha256: "a".repeat(64),
            target_triple: "x86_64-unknown-linux-gnu".to_owned(),
            abi: "System V AMD64".to_owned(),
            file_kind: "Executable".to_owned(),
            image_base: None,
            entry_point: Some(Address(0x401000)),
            data_layout: None,
            address_spaces: Vec::new(),
            mapped_segments: vec![MappedSegmentSpec {
                id: "load".to_owned(),
                address_space: 0,
                virtual_address: Address(0x401000),
                memory_size: 0x1000,
                file_offset: Address(0),
                file_size: 0x1000,
                alignment: 0x1000,
                readable: true,
                writable: false,
                executable: true,
                provenance: FactProvenance {
                    source: FactSource::ElfMetadata,
                    scope: "test".to_owned(),
                },
            }],
            sections: Vec::new(),
            functions: Vec::new(),
            imports: Vec::new(),
            relocations: Vec::new(),
            calls: Vec::new(),
            references: Vec::new(),
            call_recovery: RecoveryState::NotAttempted,
            reference_recovery: RecoveryState::NotAttempted,
            assumptions: Vec::new(),
            typed_model: TypedModel::default(),
            recovery_scope: "test".to_owned(),
            unresolved_control_flow: true,
        };
        let mut legacy = serde_json::to_value(&spec).unwrap();
        legacy["schema_version"] = serde_json::json!(2);
        legacy.as_object_mut().unwrap().remove("typed_model");
        let migrated = parse_program_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, PROGRAM_SPEC_VERSION);
        assert!(migrated.typed_model.prototypes.is_empty());

        spec.typed_model.prototypes.push(PrototypeAssertion {
            id: "prototype-main".to_owned(),
            entry: Address(0x401000),
            return_type: ScalarType::U64,
            parameters: vec![ScalarType::U64, ScalarType::U64],
            calling_convention: CallingConvention::SysvAmd64,
            provenance,
        });
        assert!(validate_typed_model(&spec).is_ok());
        spec.typed_model.prototypes[0].entry = Address(0x900000);
        assert!(
            validate_typed_model(&spec)
                .unwrap_err()
                .contains("executable mapping")
        );
    }
}
