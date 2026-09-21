//! Frontend-neutral facts recovered from a binary. Unknown recovery is never
//! represented as a negative fact.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

pub const SPEC_VERSION: u32 = 1;
pub const PROGRAM_SPEC_VERSION: u32 = 5;
pub const REGION_SPEC_VERSION: u32 = 3;
pub const DECOMPILATION_UNIT_VERSION: u32 = 2;
pub const PATCH_BUNDLE_VERSION: u32 = 2;

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

/// Unambiguous location within one ProgramSpec address space. Linked ELF
/// files use address space zero for process virtual memory; relocatable ELF
/// files use a distinct address space for each section.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Location {
    pub address_space: u32,
    pub value: Address,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_location: Option<Location>,
    pub data_layout: Option<String>,
    /// Raw ELF program-header inventory. This includes non-loadable headers
    /// such as PT_DYNAMIC, PT_TLS, PT_GNU_EH_FRAME, and PT_GNU_RELRO.
    #[serde(default)]
    pub program_headers: Vec<ProgramHeaderSpec>,
    /// Dynamic symbols are retained independently from normalized imports and
    /// function seeds so symbol versions and undefined entries are not lost.
    #[serde(default)]
    pub dynamic_symbols: Vec<DynamicSymbolSpec>,
    /// File-derived ranges used by runtime linkage, unwinding, TLS, and
    /// language runtimes. An unwind section range is not an FDE claim.
    #[serde(default)]
    pub runtime_ranges: Vec<RuntimeRangeSpec>,
    /// Individually decoded frame-description ranges. These are entry and
    /// extent evidence from unwind metadata, not proof that every covered
    /// byte is reachable machine code.
    #[serde(default)]
    pub unwind_ranges: Vec<UnwindRangeSpec>,
    /// Parsed init/fini pointer slots. Individual unresolved entries remain
    /// explicit instead of being omitted or guessed.
    #[serde(default)]
    pub pointer_arrays: Vec<RuntimePointerArraySpec>,
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
    /// Proven memory effects and mapped-object facts. An empty collection is
    /// not a claim that the program has no memory effects.
    #[serde(default)]
    pub memory_facts: Vec<MemoryFact>,
    /// Unresolved analysis state that downstream stable operations must honor.
    #[serde(default)]
    pub uncertainties: Vec<UncertaintySpec>,
    /// Artifact-level origins in addition to provenance carried by each fact.
    #[serde(default)]
    pub provenance: Vec<FactProvenance>,
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
pub struct ProgramHeaderSpec {
    pub index: u32,
    pub type_value: u32,
    pub type_name: String,
    pub flags: u32,
    pub file_offset: Address,
    pub location: Location,
    pub physical_address: Address,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DynamicSymbolSpec {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_file: Option<String>,
    #[serde(default)]
    pub version_hidden: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    pub size: u64,
    pub kind: String,
    pub binding: String,
    pub visibility: String,
    pub defined: bool,
    pub provenance: FactProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeRangeKind {
    Plt,
    Got,
    Tls,
    Unwind,
    InitArray,
    FiniArray,
    PreinitArray,
    LanguageMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimeRangeSpec {
    pub id: String,
    pub kind: RuntimeRangeKind,
    pub section_name: String,
    pub location: Location,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_offset: Option<Address>,
    pub size: u64,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnwindRangeSpec {
    pub id: String,
    pub section_name: String,
    /// Byte offset of the FDE record inside its unwind section.
    pub record_offset: u64,
    pub initial_location: Location,
    pub address_range: u64,
    /// True only when the complete range lies in a mapped executable segment.
    pub executable: bool,
    pub provenance: FactProvenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePointerArrayKind {
    Init,
    Fini,
    Preinit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimePointerEntrySpec {
    pub slot: Location,
    pub raw_value: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Location>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_provenance: Option<FactProvenance>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuntimePointerArraySpec {
    pub id: String,
    pub kind: RuntimePointerArrayKind,
    pub section_name: String,
    pub location: Location,
    pub entry_width_bits: u16,
    pub entries: Vec<RuntimePointerEntrySpec>,
    pub trailing_bytes: u8,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location_ref: Option<Location>,
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
    Symbol {
        id: String,
        name: Option<String>,
        /// Canonical base location when the referenced symbol is defined in
        /// this ELF. The relocation addend and encoding still determine the
        /// final relocated value.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        location: Option<Location>,
        #[serde(default)]
        defined: bool,
    },
    Section {
        name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        location: Option<Location>,
    },
    Absolute,
    Unresolved {
        description: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallSpec {
    pub source: Address,
    pub target: Option<Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub return_address: Option<Address>,
    #[serde(default)]
    pub is_tailcall: bool,
    #[serde(default)]
    pub stops_flow: bool,
    #[serde(default)]
    pub noreturn: bool,
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
    InterchangeImport,
    AnalystAssertion,
    ValidationEvidence,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionSpec {
    pub name: String,
    pub address: Address,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryAccessKind {
    Read,
    Write,
    ReadWrite,
}

/// A bounded memory fact. Unknown locations and effects belong in
/// `uncertainties`, never in fabricated `MemoryFact` entries.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryFact {
    pub id: String,
    pub address_space: u32,
    pub location: Address,
    pub size_bytes: u64,
    pub access: MemoryAccessKind,
    pub scope: String,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UncertaintySpec {
    pub id: String,
    pub category: String,
    pub description: String,
    #[serde(default)]
    pub affected_addresses: Vec<Address>,
    pub blocks_stable_operation: bool,
    pub provenance: FactProvenance,
}

pub fn migrate_program_spec(mut spec: ProgramSpec) -> Result<ProgramSpec, String> {
    let legacy_version = spec.schema_version;
    match legacy_version {
        1..=4 => spec.schema_version = PROGRAM_SPEC_VERSION,
        PROGRAM_SPEC_VERSION => {}
        other => return Err(format!("unsupported ProgramSpec schema version {other}")),
    }
    populate_program_locations(&mut spec);
    if legacy_version < PROGRAM_SPEC_VERSION
        && spec.unresolved_control_flow
        && !spec
            .uncertainties
            .iter()
            .any(|uncertainty| uncertainty.category == "control_flow")
    {
        spec.uncertainties.push(UncertaintySpec {
            id: "legacy-unresolved-control-flow".to_owned(),
            category: "control_flow".to_owned(),
            description:
                "Legacy ProgramSpec reported unresolved control flow without structured details"
                    .to_owned(),
            affected_addresses: Vec::new(),
            blocks_stable_operation: true,
            provenance: FactProvenance {
                source: FactSource::NativeAnalysis,
                scope: format!("derived while migrating ProgramSpec v{legacy_version}"),
            },
        });
    }
    validate_program_spec(&spec)?;
    Ok(spec)
}

fn populate_program_locations(spec: &mut ProgramSpec) {
    let has_section_relative = spec
        .sections
        .iter()
        .any(|section| section.address_kind == AddressKind::SectionRelative);
    if spec.address_spaces.is_empty() {
        if has_section_relative {
            for (index, section) in spec.sections.iter().enumerate() {
                spec.address_spaces.push(AddressSpaceSpec {
                    id: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    name: format!("ELF section {}", section.name),
                    address_kind: AddressKind::SectionRelative,
                    provenance: FactProvenance {
                        source: FactSource::ElfMetadata,
                        scope: "derived while migrating a section-relative ProgramSpec".to_owned(),
                    },
                });
            }
        } else {
            spec.address_spaces.push(AddressSpaceSpec {
                id: 0,
                name: "ELF process virtual memory".to_owned(),
                address_kind: AddressKind::Virtual,
                provenance: FactProvenance {
                    source: FactSource::ElfMetadata,
                    scope: "derived while migrating a linked ProgramSpec".to_owned(),
                },
            });
        }
    }
    let section_space = |name: &str, sections: &[SectionSpec]| {
        sections
            .iter()
            .position(|section| section.name == name)
            .and_then(|index| u32::try_from(index + 1).ok())
    };
    for (index, section) in spec.sections.iter_mut().enumerate() {
        if section.location.is_none() {
            section.location = Some(Location {
                address_space: if section.address_kind == AddressKind::Virtual {
                    0
                } else {
                    u32::try_from(index + 1).unwrap_or(u32::MAX)
                },
                value: section.address,
            });
        }
    }
    for function in &mut spec.functions {
        if function.location.is_none() {
            function.location = Some(Location {
                address_space: if function.address_kind == AddressKind::Virtual {
                    0
                } else {
                    section_space(&function.section_name, &spec.sections).unwrap_or(u32::MAX)
                },
                value: function.address,
            });
        }
    }
    for relocation in &mut spec.relocations {
        if relocation.location_ref.is_none() {
            relocation.location_ref = Some(Location {
                address_space: if relocation.address_kind == AddressKind::Virtual {
                    0
                } else {
                    relocation
                        .source_section
                        .as_deref()
                        .and_then(|name| section_space(name, &spec.sections))
                        .unwrap_or(u32::MAX)
                },
                value: relocation.location,
            });
        }
    }
    if spec.entry_location.is_none() {
        spec.entry_location = spec.entry_point.map(|value| Location {
            address_space: 0,
            value,
        });
    }
}

pub fn validate_program_spec(spec: &ProgramSpec) -> Result<(), String> {
    if spec.schema_version != PROGRAM_SPEC_VERSION {
        return Err(format!(
            "ProgramSpec schema version {} is not canonical version {PROGRAM_SPEC_VERSION}",
            spec.schema_version
        ));
    }
    validate_sha256("ProgramSpec binary", &spec.binary_sha256)?;
    let mut address_space_ids = std::collections::BTreeSet::new();
    if spec.address_spaces.iter().any(|space| {
        !address_space_ids.insert(space.id)
            || space.name.is_empty()
            || space.name.len() > 4096
            || space.provenance.scope.is_empty()
    }) {
        return Err("ProgramSpec contains invalid or duplicate address spaces".to_owned());
    }
    let valid_location = |location: Location| address_space_ids.contains(&location.address_space);
    if spec
        .entry_location
        .is_some_and(|location| !valid_location(location))
        || spec.sections.iter().any(|section| {
            section
                .location
                .is_none_or(|location| !valid_location(location))
        })
        || spec.functions.iter().any(|function| {
            function
                .location
                .is_none_or(|location| !valid_location(location))
        })
        || spec.relocations.iter().any(|relocation| {
            relocation
                .location_ref
                .is_none_or(|location| !valid_location(location))
                || match &relocation.target {
                    RelocationTargetSpec::Symbol { location, .. }
                    | RelocationTargetSpec::Section { location, .. } => {
                        location.is_some_and(|location| !valid_location(location))
                    }
                    RelocationTargetSpec::Absolute | RelocationTargetSpec::Unresolved { .. } => {
                        false
                    }
                }
        })
    {
        return Err("ProgramSpec contains a missing or unknown canonical location".to_owned());
    }
    if spec.program_headers.len() > 4096
        || spec.dynamic_symbols.len() > 1_000_000
        || spec.runtime_ranges.len() > 65_536
        || spec.unwind_ranges.len() > 65_536
        || spec.pointer_arrays.len() > 1024
    {
        return Err("ProgramSpec exceeds bounded ELF metadata inventories".to_owned());
    }
    for relocation in &spec.relocations {
        let invalid_target = match &relocation.target {
            RelocationTargetSpec::Symbol {
                id,
                name,
                location,
                defined,
            } => {
                id.is_empty()
                    || id.len() > 256
                    || name.as_ref().is_some_and(|name| name.len() > 4096)
                    || (location.is_some() && !defined)
            }
            RelocationTargetSpec::Section { name, .. } => name.is_empty() || name.len() > 4096,
            RelocationTargetSpec::Absolute => false,
            RelocationTargetSpec::Unresolved { description } => {
                description.is_empty() || description.len() > 4096
            }
        };
        if relocation.kind.is_empty()
            || relocation.kind.len() > 128
            || relocation.encoding.is_empty()
            || relocation.encoding.len() > 128
            || relocation.format_flags.len() > 256
            || relocation
                .source_section
                .as_ref()
                .is_some_and(|name| name.len() > 4096)
            || relocation.provenance.scope.is_empty()
            || invalid_target
        {
            return Err("ProgramSpec contains an invalid relocation".to_owned());
        }
    }
    let mut header_indices = std::collections::BTreeSet::new();
    for header in &spec.program_headers {
        if !header_indices.insert(header.index)
            || header.type_name.is_empty()
            || header.type_name.len() > 128
            || !valid_location(header.location)
            || header.provenance.scope.is_empty()
        {
            return Err("ProgramSpec contains an invalid program header".to_owned());
        }
    }
    let mut metadata_ids = std::collections::BTreeSet::new();
    for symbol in &spec.dynamic_symbols {
        if symbol.id.is_empty()
            || symbol.id.len() > 256
            || !metadata_ids.insert(symbol.id.as_str())
            || symbol.name.len() > 4096
            || symbol
                .version
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
            || symbol
                .version_file
                .as_ref()
                .is_some_and(|value| value.len() > 4096)
            || symbol.kind.is_empty()
            || symbol.kind.len() > 128
            || symbol.binding.is_empty()
            || symbol.binding.len() > 128
            || symbol.visibility.is_empty()
            || symbol.visibility.len() > 128
            || symbol
                .location
                .is_some_and(|location| !valid_location(location))
            || symbol.provenance.scope.is_empty()
        {
            return Err("ProgramSpec contains an invalid dynamic symbol".to_owned());
        }
    }
    metadata_ids.clear();
    for range in &spec.runtime_ranges {
        if range.id.is_empty()
            || range.id.len() > 256
            || !metadata_ids.insert(range.id.as_str())
            || range.section_name.is_empty()
            || range.section_name.len() > 4096
            || range.size == 0
            || !valid_location(range.location)
            || range.provenance.scope.is_empty()
        {
            return Err("ProgramSpec contains an invalid runtime metadata range".to_owned());
        }
    }
    metadata_ids.clear();
    for range in &spec.unwind_ranges {
        let end = range
            .initial_location
            .value
            .0
            .checked_add(range.address_range);
        let executable_mapping = end.is_some_and(|end| {
            spec.mapped_segments.iter().any(|segment| {
                segment.address_space == range.initial_location.address_space
                    && segment.executable
                    && segment.virtual_address.0 <= range.initial_location.value.0
                    && segment
                        .virtual_address
                        .0
                        .checked_add(segment.memory_size)
                        .is_some_and(|segment_end| end <= segment_end)
            })
        });
        let executable_section = end.is_some_and(|end| {
            spec.sections.iter().any(|section| {
                section.location.is_some_and(|location| {
                    location.address_space == range.initial_location.address_space
                        && location.value.0 <= range.initial_location.value.0
                }) && section.kind == "Text"
                    && section
                        .address
                        .0
                        .checked_add(section.size)
                        .is_some_and(|section_end| end <= section_end)
            })
        });
        if range.id.is_empty()
            || range.id.len() > 256
            || !metadata_ids.insert(range.id.as_str())
            || range.section_name.is_empty()
            || range.section_name.len() > 4096
            || range.address_range == 0
            || end.is_none()
            || !valid_location(range.initial_location)
            || (range.executable && !executable_mapping && !executable_section)
            || range.provenance.scope.is_empty()
        {
            return Err("ProgramSpec contains an invalid unwind range".to_owned());
        }
    }
    metadata_ids.clear();
    for array in &spec.pointer_arrays {
        if array.id.is_empty()
            || array.id.len() > 256
            || !metadata_ids.insert(array.id.as_str())
            || array.section_name.is_empty()
            || array.section_name.len() > 4096
            || array.entry_width_bits != 64
            || array.entries.len() > 65_536
            || array.trailing_bytes >= 8
            || !valid_location(array.location)
            || array.provenance.scope.is_empty()
        {
            return Err("ProgramSpec contains an invalid runtime pointer array".to_owned());
        }
        for entry in &array.entries {
            if !valid_location(entry.slot)
                || entry.target.is_some_and(|target| !valid_location(target))
                || entry
                    .target_provenance
                    .as_ref()
                    .is_some_and(|provenance| provenance.scope.is_empty())
                || (entry.target.is_some() != entry.target_provenance.is_some())
            {
                return Err(
                    "ProgramSpec runtime pointer entry uses an unknown address space".to_owned(),
                );
            }
        }
    }
    if spec.memory_facts.len() > 65_536 || spec.uncertainties.len() > 65_536 {
        return Err("ProgramSpec exceeds bounded memory or uncertainty fact count".to_owned());
    }
    let mut ids = std::collections::BTreeSet::new();
    for fact in &spec.memory_facts {
        if !ids.insert(fact.id.as_str())
            || fact.id.is_empty()
            || fact.id.len() > 128
            || fact.size_bytes == 0
            || fact.scope.is_empty()
            || fact.scope.len() > 1024
        {
            return Err("invalid or duplicate ProgramSpec memory fact".to_owned());
        }
        if !spec
            .address_spaces
            .iter()
            .any(|space| space.id == fact.address_space)
        {
            return Err("ProgramSpec memory fact uses an unknown address space".to_owned());
        }
    }
    ids.clear();
    for uncertainty in &spec.uncertainties {
        if !ids.insert(uncertainty.id.as_str())
            || uncertainty.id.is_empty()
            || uncertainty.id.len() > 128
            || uncertainty.category.is_empty()
            || uncertainty.category.len() > 128
            || uncertainty.description.is_empty()
            || uncertainty.description.len() > 4096
            || uncertainty.affected_addresses.len() > 4096
        {
            return Err("invalid or duplicate ProgramSpec uncertainty".to_owned());
        }
    }
    validate_typed_model(spec)?;
    Ok(())
}

pub fn parse_program_spec_json(bytes: &[u8]) -> Result<ProgramSpec, String> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid ProgramSpec JSON: {error}"))?;
    if value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        == Some(1)
    {
        let object = value
            .as_object_mut()
            .ok_or_else(|| "ProgramSpec JSON must be an object".to_owned())?;
        for field in [
            "address_spaces",
            "mapped_segments",
            "imports",
            "relocations",
            "calls",
            "references",
            "assumptions",
        ] {
            object
                .entry(field.to_owned())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
        }
        for field in ["image_base", "entry_point", "data_layout", "entry_location"] {
            object
                .entry(field.to_owned())
                .or_insert(serde_json::Value::Null);
        }
        object
            .entry("call_recovery".to_owned())
            .or_insert_with(|| serde_json::Value::String("not_attempted".to_owned()));
        object
            .entry("reference_recovery".to_owned())
            .or_insert_with(|| serde_json::Value::String("not_attempted".to_owned()));
    }
    let spec: ProgramSpec = serde_json::from_value(value)
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
        if prototype.parameters.contains(&ScalarType::Void) {
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
    #[serde(default)]
    pub calls: Vec<CallSpec>,
    pub relocations: Vec<RelocationSpec>,
    #[serde(default)]
    pub observed_interior_entries: Vec<InteriorEntryEvidence>,
    /// Legacy string locations retained for v2 readers. Canonical v3 writers
    /// use the typed physical location collections below.
    pub live_in: Option<Vec<String>>,
    pub live_out: Option<Vec<String>>,
    #[serde(default)]
    pub physical_live_in: Vec<PhysicalLocationSpec>,
    #[serde(default)]
    pub physical_live_out: Vec<PhysicalLocationSpec>,
    /// RSP after each reachable near RET relative to RSP at region entry.
    pub stack_delta: Option<i64>,
    /// Proven entry RSP residue modulo 16, if known.
    #[serde(default)]
    pub stack_entry_alignment: Option<u8>,
    #[serde(default)]
    pub exit_stack_relations: Vec<ExitStackRelation>,
    #[serde(default)]
    pub global_references: Vec<ReferenceSpec>,
    #[serde(default)]
    pub variable_locations: Vec<VariableLocationSpec>,
    #[serde(default)]
    pub assumptions: Vec<AssumptionSpec>,
    pub unresolved_facts: Vec<String>,
    pub replacement_ready: bool,
    pub provenance: FactProvenance,
}

/// Canonical name for the HydIR region artifact. The historical
/// `RegionContract` name remains a source-compatible alias for existing users.
pub type RegionSpec = RegionContract;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhysicalLocationKind {
    Register,
    Flag,
    Stack,
    Memory,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhysicalLocationSpec {
    pub name: String,
    pub kind: PhysicalLocationKind,
    pub width_bits: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_name: Option<String>,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExitStackRelation {
    pub exit: Address,
    pub rsp_delta: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alignment_mod_16: Option<u8>,
    pub provenance: FactProvenance,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VariableLocationSpec {
    pub variable: String,
    pub location: PhysicalLocationSpec,
    pub valid_from: Address,
    pub valid_to: Address,
    pub provenance: FactProvenance,
}

pub fn migrate_region_spec(mut spec: RegionSpec) -> Result<RegionSpec, String> {
    match spec.schema_version {
        2 => spec.schema_version = REGION_SPEC_VERSION,
        REGION_SPEC_VERSION => {}
        other => return Err(format!("unsupported RegionSpec schema version {other}")),
    }
    validate_region_spec(&spec)?;
    Ok(spec)
}

pub fn parse_region_spec_json(bytes: &[u8]) -> Result<RegionSpec, String> {
    let spec: RegionSpec = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid RegionSpec JSON: {error}"))?;
    migrate_region_spec(spec)
}

pub fn validate_region_spec(spec: &RegionSpec) -> Result<(), String> {
    if spec.schema_version != REGION_SPEC_VERSION {
        return Err(format!(
            "RegionSpec schema version {} is not canonical version {REGION_SPEC_VERSION}",
            spec.schema_version
        ));
    }
    validate_sha256("RegionSpec binary", &spec.binary_sha256)?;
    validate_sha256("RegionSpec bytes", &spec.bytes_sha256)?;
    let bytes = decode_hex(&spec.bytes_hex)?;
    if bytes.len() as u64 != spec.byte_length {
        return Err("RegionSpec byte length does not match bytes_hex".to_owned());
    }
    if format!("{:x}", Sha256::digest(&bytes)) != spec.bytes_sha256 {
        return Err("RegionSpec byte digest does not match bytes_hex".to_owned());
    }
    if spec
        .stack_entry_alignment
        .is_some_and(|alignment| alignment >= 16)
        || spec.exit_stack_relations.iter().any(|relation| {
            relation
                .alignment_mod_16
                .is_some_and(|alignment| alignment >= 16)
        })
    {
        return Err("RegionSpec stack alignment residue must be below 16".to_owned());
    }
    let region_end = spec
        .entry
        .0
        .checked_add(spec.byte_length)
        .ok_or_else(|| "RegionSpec address range overflows".to_owned())?;
    if spec.calls.iter().any(|call| {
        !(spec.entry.0..region_end).contains(&call.source.0) || call.provenance.scope.is_empty()
    }) {
        return Err("RegionSpec contains an invalid call contract".to_owned());
    }
    for location in spec
        .physical_live_in
        .iter()
        .chain(&spec.physical_live_out)
        .chain(
            spec.variable_locations
                .iter()
                .map(|variable| &variable.location),
        )
    {
        if location.name.is_empty()
            || location.name.len() > 128
            || !matches!(
                location.width_bits,
                1 | 8 | 16 | 24 | 32 | 64 | 80 | 96 | 128 | 256 | 512
            )
        {
            return Err("RegionSpec contains an invalid physical location".to_owned());
        }
    }
    if spec.replacement_ready && !spec.unresolved_facts.is_empty() {
        return Err("RegionSpec cannot be replacement-ready with unresolved facts".to_owned());
    }
    Ok(())
}

/// Decode the exact bytes carried by a validated RegionSpec. Consumers use
/// this instead of reparsing the hexadecimal field with divergent limits.
pub fn region_bytes(spec: &RegionSpec) -> Result<Vec<u8>, String> {
    validate_region_spec(spec)?;
    decode_hex(&spec.bytes_hex)
}

fn validate_sha256(label: &str, value: &str) -> Result<(), String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{label} SHA-256 must be 64 hexadecimal characters"));
    }
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) || value.len() > 128 * 1024 * 1024 {
        return Err("RegionSpec bytes_hex must be even-length and bounded".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| "RegionSpec bytes_hex is not UTF-8")?;
            u8::from_str_radix(text, 16).map_err(|_| "RegionSpec bytes_hex is not hexadecimal")
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(str::to_owned)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecompilationDiagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub blocks_stable_operation: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatementAddressProvenance {
    pub c_start_line: u32,
    pub c_end_line: u32,
    pub addresses: Vec<Address>,
    pub provenance: FactProvenance,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompilationStructuralCompleteness {
    #[default]
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompilationSemanticFidelity {
    #[default]
    Unknown,
    Conservative,
    ExactUnderModel,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompilationVerificationStatus {
    #[default]
    NotRun,
    StaticallyValidated,
    DifferentiallyTested,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DecompilationArtifactDigests {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_ir_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_ir_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_ir_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cir_sha256: Option<String>,
}

/// Versioned output of one region decompilation. `cir` remains optional until
/// the native structured representation exists; callers can distinguish the
/// verified LLVM-compatible RegionIR from the deterministic C view.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecompilationUnit {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub region: RegionSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_revision: Option<u64>,
    #[serde(default)]
    pub artifacts: DecompilationArtifactDigests,
    #[serde(default)]
    pub region_ir_llvm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cir: Option<String>,
    pub c_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub low_level_c: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_c: Option<String>,
    #[serde(default)]
    pub structural_completeness: DecompilationStructuralCompleteness,
    #[serde(default)]
    pub semantic_fidelity: DecompilationSemanticFidelity,
    #[serde(default)]
    pub verification: DecompilationVerificationStatus,
    #[serde(default)]
    pub rewrite_ready: bool,
    #[serde(default)]
    pub statement_provenance: Vec<StatementAddressProvenance>,
    #[serde(default)]
    pub diagnostics: Vec<DecompilationDiagnostic>,
    pub engine_version: String,
}

pub fn migrate_decompilation_unit(
    mut unit: DecompilationUnit,
) -> Result<DecompilationUnit, String> {
    match unit.schema_version {
        1 => {
            unit.schema_version = DECOMPILATION_UNIT_VERSION;
            if unit.low_level_c.is_none() {
                unit.low_level_c = Some(unit.c_source.clone());
            }
            unit.structural_completeness = DecompilationStructuralCompleteness::Partial;
            unit.semantic_fidelity = DecompilationSemanticFidelity::Conservative;
            unit.verification = DecompilationVerificationStatus::NotRun;
            unit.rewrite_ready = false;
        }
        DECOMPILATION_UNIT_VERSION => {}
        other => {
            return Err(format!(
                "unsupported DecompilationUnit schema version {other}"
            ));
        }
    }
    validate_decompilation_unit(&unit)?;
    Ok(unit)
}

pub fn parse_decompilation_unit_json(bytes: &[u8]) -> Result<DecompilationUnit, String> {
    let unit: DecompilationUnit = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid DecompilationUnit JSON: {error}"))?;
    migrate_decompilation_unit(unit)
}

pub fn validate_decompilation_unit(unit: &DecompilationUnit) -> Result<(), String> {
    if unit.schema_version != DECOMPILATION_UNIT_VERSION {
        return Err(format!(
            "unsupported DecompilationUnit schema version {}",
            unit.schema_version
        ));
    }
    validate_region_spec(&unit.region)?;
    if unit.binary_sha256 != unit.region.binary_sha256 {
        return Err("DecompilationUnit and RegionSpec binary digests differ".to_owned());
    }
    let has_native_ir = unit.artifacts.machine_ir_sha256.is_some()
        && unit.artifacts.state_ir_sha256.is_some()
        && unit.artifacts.function_ir_sha256.is_some()
        && unit.artifacts.cir_sha256.is_some();
    if (unit.region_ir_llvm.is_empty() && !has_native_ir)
        || unit.region_ir_llvm.len() > 8 * 1024 * 1024
        || unit.region_ir_llvm.contains('\0')
        || unit.c_source.is_empty()
        || unit.c_source.len() > 8 * 1024 * 1024
        || unit.c_source.contains('\0')
        || unit.engine_version.is_empty()
        || unit.engine_version.len() > 128
    {
        return Err("DecompilationUnit source or engine metadata is invalid".to_owned());
    }
    if unit.low_level_c.as_deref().is_none_or(|source| {
        source.is_empty() || source.len() > 8 * 1024 * 1024 || source.contains('\0')
    }) || unit.structured_c.as_deref().is_some_and(|source| {
        source.is_empty() || source.len() > 8 * 1024 * 1024 || source.contains('\0')
    }) || (unit.rewrite_ready
        && (unit.structural_completeness != DecompilationStructuralCompleteness::Complete
            || unit.semantic_fidelity != DecompilationSemanticFidelity::ExactUnderModel))
    {
        return Err("DecompilationUnit native source or readiness is invalid".to_owned());
    }
    for digest in [
        &unit.artifacts.machine_ir_sha256,
        &unit.artifacts.state_ir_sha256,
        &unit.artifacts.function_ir_sha256,
        &unit.artifacts.cir_sha256,
    ]
    .into_iter()
    .flatten()
    {
        validate_sha256("DecompilationUnit artifact", digest)?;
    }
    let c_line_count = unit.c_source.lines().count() as u64;
    let region_end = unit
        .region
        .entry
        .0
        .checked_add(unit.region.byte_length)
        .ok_or_else(|| "DecompilationUnit region range overflows".to_owned())?;
    if unit.statement_provenance.iter().any(|mapping| {
        mapping.c_start_line == 0
            || mapping.c_end_line < mapping.c_start_line
            || u64::from(mapping.c_end_line) > c_line_count
            || mapping.addresses.is_empty()
            || mapping
                .addresses
                .iter()
                .any(|address| !(unit.region.entry.0..region_end).contains(&address.0))
            || mapping.provenance.scope.is_empty()
    }) {
        return Err("DecompilationUnit contains invalid statement provenance".to_owned());
    }
    Ok(())
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

pub const PHYSICAL_REGION_IR_VERSION: u32 = 1;

/// Storage addressed by one machine operation. Stack storage remains distinct
/// from mapped process memory so later lowering cannot silently exchange them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionMemoryClass {
    Stack,
    Mapped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegionMemoryAddress {
    pub class: RegionMemoryClass,
    pub segment: Option<String>,
    pub base: Option<String>,
    pub index: Option<String>,
    pub scale: u32,
    pub displacement: i64,
    pub absolute: Option<u64>,
    pub width_bits: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RegionValue {
    Register { name: String, width_bits: u16 },
    Immediate { value: i64, width_bits: u16 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionAluOperation {
    Add,
    Subtract,
    And,
    Or,
    Xor,
}

/// A typed, operand-complete projection of one decoded machine operation.
/// This is deliberately lower-level than SSA/CIR: it preserves effects that
/// are not yet safe to structure or compile away.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PhysicalRegionOperation {
    Move {
        destination: String,
        source: RegionValue,
        width_bits: u16,
    },
    Load {
        destination: String,
        address: RegionMemoryAddress,
    },
    Store {
        address: RegionMemoryAddress,
        source: RegionValue,
    },
    LoadEffectiveAddress {
        destination: String,
        base: Option<String>,
        index: Option<String>,
        scale: u32,
        displacement: i64,
    },
    Alu {
        operation: RegionAluOperation,
        destination: String,
        source: RegionValue,
        width_bits: u16,
    },
    AluMemory {
        operation: RegionAluOperation,
        address: RegionMemoryAddress,
        source: RegionValue,
    },
    AluRegisterMemory {
        operation: RegionAluOperation,
        destination: String,
        address: RegionMemoryAddress,
    },
    Compare {
        left: RegionValue,
        right: RegionValue,
        width_bits: u16,
    },
    CompareMemory {
        register: Option<String>,
        address: RegionMemoryAddress,
        value: Option<RegionValue>,
    },
    Test {
        left: RegionValue,
        right: RegionValue,
        width_bits: u16,
    },
    SaveRegister {
        register: String,
    },
    RestoreRegister {
        register: String,
    },
    SaveFramePointer,
    RestoreFramePointer,
    SetFramePointer,
    RestoreStackPointerFromFrame,
    AdjustStack {
        operation: RegionAluOperation,
        amount: i64,
    },
    LeaveFrame,
    ConditionalBranch {
        predicate: RegionPredicate,
        true_target: Address,
        false_target: Address,
    },
    Branch {
        target: Address,
    },
    Call {
        target: Address,
    },
    Return,
    Nop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionMemoryEffect {
    None,
    ReadReturnAddress,
    WriteSavedFramePointer,
    ReadSavedFramePointer,
    WriteSavedRegister,
    ReadSavedRegister,
    ReadStackLocal,
    WriteStackLocal,
    ReadWriteStackLocal,
    ReadMappedMemory,
    WriteMappedMemory,
    WriteReturnAddress,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionControlEffect {
    Next,
    DirectBranch,
    ConditionalBranch,
    DirectCall,
    Return,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhysicalRegionEffects {
    pub read_registers: Vec<String>,
    pub written_registers: Vec<String>,
    pub read_flags: Vec<String>,
    pub written_flags: Vec<String>,
    pub memory: RegionMemoryEffect,
    pub control: RegionControlEffect,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PhysicalRegionInstruction {
    pub address: Address,
    pub bytes_hex: String,
    pub mnemonic: String,
    pub operation: PhysicalRegionOperation,
    pub effects: PhysicalRegionEffects,
    pub successors: Vec<Address>,
}

/// General physical-state RegionIR. Construction proves exact decoding and
/// control flow, but it does not claim that imported boundary facts are
/// complete enough for SSA, C emission, or patch lowering.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhysicalRegionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub region_bytes_sha256: String,
    pub entry: Address,
    pub instructions: Vec<PhysicalRegionInstruction>,
    pub exits: Vec<Address>,
    pub calls: Vec<CallSpec>,
    pub physical_inputs: Vec<PhysicalLocationSpec>,
    pub physical_outputs: Vec<PhysicalLocationSpec>,
    pub stack_delta: Option<i64>,
    pub unresolved_facts: Vec<String>,
    pub lowering_ready: bool,
}

pub fn validate_physical_region_ir(
    ir: &PhysicalRegionIr,
    region: &RegionSpec,
) -> Result<(), String> {
    validate_region_spec(region)?;
    if ir.schema_version != PHYSICAL_REGION_IR_VERSION {
        return Err(format!(
            "unsupported PhysicalRegionIR schema version {}",
            ir.schema_version
        ));
    }
    if ir.binary_sha256 != region.binary_sha256
        || ir.region_bytes_sha256 != region.bytes_sha256
        || ir.entry != region.entry
    {
        return Err("PhysicalRegionIR is not digest-bound to its RegionSpec".to_owned());
    }
    if ir.exits != region.exits
        || ir.stack_delta != region.stack_delta
        || ir.unresolved_facts != region.unresolved_facts
    {
        return Err("PhysicalRegionIR boundary contract differs from its RegionSpec".to_owned());
    }
    if ir.lowering_ready {
        return Err(
            "PhysicalRegionIR v1 records semantics but cannot authorize lowering".to_owned(),
        );
    }
    let same_call = |left: &CallSpec, right: &CallSpec| {
        left.source == right.source
            && left.target == right.target
            && left.return_address == right.return_address
            && left.is_tailcall == right.is_tailcall
            && left.stops_flow == right.stops_flow
            && left.noreturn == right.noreturn
    };
    if ir.calls.len() != region.calls.len()
        || !ir
            .calls
            .iter()
            .zip(&region.calls)
            .all(|(left, right)| same_call(left, right))
    {
        return Err("PhysicalRegionIR call contracts differ from its RegionSpec".to_owned());
    }
    let same_location = |left: &PhysicalLocationSpec, right: &PhysicalLocationSpec| {
        left.name == right.name
            && left.kind == right.kind
            && left.width_bits == right.width_bits
            && left.type_name == right.type_name
    };
    if ir.physical_inputs.len() != region.physical_live_in.len()
        || ir.physical_outputs.len() != region.physical_live_out.len()
        || !ir
            .physical_inputs
            .iter()
            .zip(&region.physical_live_in)
            .all(|(left, right)| same_location(left, right))
        || !ir
            .physical_outputs
            .iter()
            .zip(&region.physical_live_out)
            .all(|(left, right)| same_location(left, right))
    {
        return Err("PhysicalRegionIR physical state differs from its RegionSpec".to_owned());
    }
    if ir.instructions.is_empty() || ir.instructions.len() > 4096 {
        return Err("PhysicalRegionIR must contain 1..=4096 instructions".to_owned());
    }
    let region_bytes = decode_hex(&region.bytes_hex)?;
    let region_end = region
        .entry
        .0
        .checked_add(region.byte_length)
        .ok_or_else(|| "PhysicalRegionIR address range overflows".to_owned())?;
    let addresses = ir
        .instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect::<std::collections::BTreeSet<_>>();
    if addresses.len() != ir.instructions.len() || !addresses.contains(&region.entry) {
        return Err(
            "PhysicalRegionIR instruction addresses are not unique and entry-rooted".to_owned(),
        );
    }
    let exits = region
        .exits
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let mut covered = std::collections::BTreeSet::new();
    for instruction in &ir.instructions {
        let bytes = decode_hex(&instruction.bytes_hex)?;
        if bytes.is_empty() || bytes.len() > 15 {
            return Err("PhysicalRegionIR instruction has an invalid x86 byte length".to_owned());
        }
        let offset = instruction
            .address
            .0
            .checked_sub(region.entry.0)
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or_else(|| "PhysicalRegionIR instruction precedes its region".to_owned())?;
        let finish = offset
            .checked_add(bytes.len())
            .ok_or_else(|| "PhysicalRegionIR instruction range overflows".to_owned())?;
        if finish > region_bytes.len() || region_bytes[offset..finish] != bytes {
            return Err("PhysicalRegionIR instruction bytes differ from its RegionSpec".to_owned());
        }
        for byte in instruction.address.0..instruction.address.0 + bytes.len() as u64 {
            if !covered.insert(byte) {
                return Err("PhysicalRegionIR instructions overlap".to_owned());
            }
        }
        if instruction
            .successors
            .iter()
            .any(|successor| !addresses.contains(successor) && !exits.contains(successor))
        {
            return Err(
                "PhysicalRegionIR successor is neither an instruction nor a declared exit"
                    .to_owned(),
            );
        }
        let expected_control = match instruction.operation {
            PhysicalRegionOperation::ConditionalBranch { .. } => {
                RegionControlEffect::ConditionalBranch
            }
            PhysicalRegionOperation::Branch { .. } => RegionControlEffect::DirectBranch,
            PhysicalRegionOperation::Call { .. } => RegionControlEffect::DirectCall,
            PhysicalRegionOperation::Return => RegionControlEffect::Return,
            _ => RegionControlEffect::Next,
        };
        if instruction.effects.control != expected_control {
            return Err("PhysicalRegionIR operation/control effect mismatch".to_owned());
        }
        let memory_for = |class, read, write| match (class, read, write) {
            (RegionMemoryClass::Stack, true, false) => RegionMemoryEffect::ReadStackLocal,
            (RegionMemoryClass::Stack, false, true) => RegionMemoryEffect::WriteStackLocal,
            (RegionMemoryClass::Stack, true, true) => RegionMemoryEffect::ReadWriteStackLocal,
            (RegionMemoryClass::Mapped, true, false) => RegionMemoryEffect::ReadMappedMemory,
            (RegionMemoryClass::Mapped, false, true) => RegionMemoryEffect::WriteMappedMemory,
            _ => RegionMemoryEffect::None,
        };
        let expected_memory = match &instruction.operation {
            PhysicalRegionOperation::Load { address, .. }
            | PhysicalRegionOperation::CompareMemory { address, .. } => {
                memory_for(address.class, true, false)
            }
            PhysicalRegionOperation::Store { address, .. } => {
                memory_for(address.class, false, true)
            }
            PhysicalRegionOperation::AluMemory { address, .. } => {
                memory_for(address.class, true, true)
            }
            PhysicalRegionOperation::AluRegisterMemory { address, .. } => {
                memory_for(address.class, true, false)
            }
            PhysicalRegionOperation::SaveRegister { .. } => RegionMemoryEffect::WriteSavedRegister,
            PhysicalRegionOperation::RestoreRegister { .. } => {
                RegionMemoryEffect::ReadSavedRegister
            }
            PhysicalRegionOperation::SaveFramePointer => RegionMemoryEffect::WriteSavedFramePointer,
            PhysicalRegionOperation::RestoreFramePointer | PhysicalRegionOperation::LeaveFrame => {
                RegionMemoryEffect::ReadSavedFramePointer
            }
            PhysicalRegionOperation::Call { .. } => RegionMemoryEffect::WriteReturnAddress,
            PhysicalRegionOperation::Return => RegionMemoryEffect::ReadReturnAddress,
            _ => RegionMemoryEffect::None,
        };
        if instruction.effects.memory != expected_memory {
            return Err("PhysicalRegionIR operation/memory effect mismatch".to_owned());
        }
        let next = instruction
            .address
            .0
            .checked_add(bytes.len() as u64)
            .map(Address)
            .ok_or_else(|| "PhysicalRegionIR instruction successor overflows".to_owned())?;
        let expected_successors = match &instruction.operation {
            PhysicalRegionOperation::ConditionalBranch {
                true_target,
                false_target,
                ..
            } => vec![*true_target, *false_target],
            PhysicalRegionOperation::Branch { target } => vec![*target],
            PhysicalRegionOperation::Return => Vec::new(),
            PhysicalRegionOperation::Call { .. } if instruction.successors.is_empty() => Vec::new(),
            _ => vec![next],
        };
        if expected_successors != instruction.successors {
            return Err("PhysicalRegionIR operation/successor mismatch".to_owned());
        }
        if !(region.entry.0..region_end).contains(&instruction.address.0) {
            return Err("PhysicalRegionIR instruction lies outside its region".to_owned());
        }
    }
    for call in &ir.calls {
        let instruction = ir
            .instructions
            .iter()
            .find(|instruction| instruction.address == call.source)
            .ok_or_else(|| "PhysicalRegionIR call contract has no instruction".to_owned())?;
        if !matches!(instruction.operation, PhysicalRegionOperation::Call { .. }) {
            return Err("PhysicalRegionIR call contract source is not a call".to_owned());
        }
        if (call.stops_flow || call.noreturn) != instruction.successors.is_empty() {
            return Err(
                "PhysicalRegionIR terminal call contract disagrees with control flow".to_owned(),
            );
        }
    }
    Ok(())
}

pub const REGION_DECISION_IR_VERSION: u32 = 1;

/// A condition consumed by a side-effect-free region decision. Flag names are
/// resolved through the explicit physical input list rather than an implicit
/// function ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionPredicate {
    Equal,
    NotEqual,
    Signed,
    NotSigned,
    Overflow,
    NotOverflow,
    Below,
    AboveOrEqual,
    BelowOrEqual,
    Above,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Greater,
}

impl RegionPredicate {
    pub fn required_flags(self) -> &'static [&'static str] {
        match self {
            Self::Equal | Self::NotEqual => &["ZF"],
            Self::Signed | Self::NotSigned => &["SF"],
            Self::Overflow | Self::NotOverflow => &["OF"],
            Self::Below | Self::AboveOrEqual => &["CF"],
            Self::BelowOrEqual | Self::Above => &["CF", "ZF"],
            Self::Less | Self::GreaterOrEqual => &["SF", "OF"],
            Self::LessOrEqual | Self::Greater => &["ZF", "SF", "OF"],
        }
    }
}

/// An output value proven to be the unchanged value of a physical input.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionPassThroughBinding {
    pub output_index: u32,
    pub input_index: u32,
}

/// Typed RegionIR for a side-effect-free conditional region. This is a narrow
/// first native RegionIR form: it makes both continuations and every live
/// output explicit while refusing instructions that mutate machine state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegionDecisionIr {
    pub schema_version: u32,
    pub binary_sha256: String,
    pub region_bytes_sha256: String,
    pub entry: Address,
    pub instruction_addresses: Vec<Address>,
    pub predicate: RegionPredicate,
    pub true_exit: Address,
    pub false_exit: Address,
    pub physical_inputs: Vec<PhysicalLocationSpec>,
    pub physical_outputs: Vec<PhysicalLocationSpec>,
    pub pass_through: Vec<RegionPassThroughBinding>,
}

pub fn validate_region_decision_ir(
    ir: &RegionDecisionIr,
    region: &RegionSpec,
) -> Result<(), String> {
    validate_region_spec(region)?;
    if ir.schema_version != REGION_DECISION_IR_VERSION {
        return Err(format!(
            "unsupported RegionDecisionIR schema version {}",
            ir.schema_version
        ));
    }
    if ir.binary_sha256 != region.binary_sha256
        || ir.region_bytes_sha256 != region.bytes_sha256
        || ir.entry != region.entry
    {
        return Err("RegionDecisionIR is not digest-bound to its RegionSpec".to_owned());
    }
    let end = region
        .entry
        .0
        .checked_add(region.byte_length)
        .ok_or_else(|| "RegionDecisionIR address range overflows".to_owned())?;
    let instruction_addresses = ir
        .instruction_addresses
        .iter()
        .map(|address| address.0)
        .collect::<std::collections::BTreeSet<_>>();
    if instruction_addresses.len() != ir.instruction_addresses.len()
        || instruction_addresses.is_empty()
        || instruction_addresses
            .iter()
            .any(|address| !(region.entry.0..end).contains(address))
    {
        return Err("RegionDecisionIR contains invalid instruction provenance".to_owned());
    }
    let ir_exits = [ir.true_exit, ir.false_exit]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let region_exits = region
        .exits
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    if ir.true_exit == ir.false_exit
        || region.exits.len() != 2
        || region_exits.len() != 2
        || ir_exits != region_exits
    {
        return Err("RegionDecisionIR exits do not match the RegionSpec".to_owned());
    }
    if ir.physical_inputs.len() > 256
        || ir.physical_outputs.len() > 256
        || ir.physical_inputs.len() != region.physical_live_in.len()
        || ir.physical_outputs.len() != region.physical_live_out.len()
        || ir.pass_through.len() != ir.physical_outputs.len()
    {
        return Err("RegionDecisionIR physical state inventory is invalid".to_owned());
    }
    let same_location = |left: &PhysicalLocationSpec, right: &PhysicalLocationSpec| {
        left.name == right.name
            && left.kind == right.kind
            && left.width_bits == right.width_bits
            && left.type_name == right.type_name
    };
    if !ir
        .physical_inputs
        .iter()
        .zip(&region.physical_live_in)
        .all(|(left, right)| same_location(left, right))
        || !ir
            .physical_outputs
            .iter()
            .zip(&region.physical_live_out)
            .all(|(left, right)| same_location(left, right))
    {
        return Err("RegionDecisionIR physical state differs from its RegionSpec".to_owned());
    }
    let input_names = ir
        .physical_inputs
        .iter()
        .map(|location| location.name.to_ascii_uppercase())
        .collect::<std::collections::BTreeSet<_>>();
    let output_names = ir
        .physical_outputs
        .iter()
        .map(|location| location.name.to_ascii_uppercase())
        .collect::<std::collections::BTreeSet<_>>();
    if input_names.len() != ir.physical_inputs.len()
        || output_names.len() != ir.physical_outputs.len()
    {
        return Err("RegionDecisionIR physical state contains duplicate names".to_owned());
    }
    let mut bound_outputs = std::collections::BTreeSet::new();
    for binding in &ir.pass_through {
        let output_index = usize::try_from(binding.output_index)
            .map_err(|_| "RegionDecisionIR output index overflows")?;
        let input_index = usize::try_from(binding.input_index)
            .map_err(|_| "RegionDecisionIR input index overflows")?;
        let output = ir
            .physical_outputs
            .get(output_index)
            .ok_or_else(|| "RegionDecisionIR output binding is out of range".to_owned())?;
        let input = ir
            .physical_inputs
            .get(input_index)
            .ok_or_else(|| "RegionDecisionIR input binding is out of range".to_owned())?;
        if !bound_outputs.insert(output_index) || !same_location(output, input) {
            return Err("RegionDecisionIR pass-through binding is invalid".to_owned());
        }
    }
    for flag in ir.predicate.required_flags() {
        let input = ir
            .physical_inputs
            .iter()
            .find(|input| input.name.eq_ignore_ascii_case(flag))
            .ok_or_else(|| format!("RegionDecisionIR lacks required {flag} input"))?;
        if !matches!(input.width_bits, 1 | 8) {
            return Err(format!(
                "RegionDecisionIR {flag} input has unsupported width {}",
                input.width_bits
            ));
        }
    }
    Ok(())
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
    Call,
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
            entry_location: Some(Location {
                address_space: 0,
                value: Address(0x401000),
            }),
            data_layout: None,
            program_headers: Vec::new(),
            dynamic_symbols: Vec::new(),
            runtime_ranges: Vec::new(),
            unwind_ranges: Vec::new(),
            pointer_arrays: Vec::new(),
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
            memory_facts: Vec::new(),
            uncertainties: Vec::new(),
            provenance: Vec::new(),
            recovery_scope: "test".to_owned(),
            unresolved_control_flow: true,
        };
        let mut legacy = serde_json::to_value(&spec).unwrap();
        legacy["schema_version"] = serde_json::json!(2);
        legacy.as_object_mut().unwrap().remove("typed_model");
        legacy.as_object_mut().unwrap().remove("memory_facts");
        legacy.as_object_mut().unwrap().remove("uncertainties");
        legacy.as_object_mut().unwrap().remove("provenance");
        legacy.as_object_mut().unwrap().remove("entry_location");
        legacy.as_object_mut().unwrap().remove("program_headers");
        legacy.as_object_mut().unwrap().remove("dynamic_symbols");
        legacy.as_object_mut().unwrap().remove("runtime_ranges");
        legacy.as_object_mut().unwrap().remove("unwind_ranges");
        legacy.as_object_mut().unwrap().remove("pointer_arrays");
        let migrated = parse_program_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, PROGRAM_SPEC_VERSION);
        assert!(migrated.typed_model.prototypes.is_empty());
        assert!(migrated.program_headers.is_empty());
        assert!(migrated.dynamic_symbols.is_empty());
        assert!(migrated.runtime_ranges.is_empty());
        assert!(migrated.unwind_ranges.is_empty());
        assert!(migrated.pointer_arrays.is_empty());
        assert_eq!(migrated.uncertainties.len(), 1);

        legacy["schema_version"] = serde_json::json!(PROGRAM_SPEC_VERSION);
        let current_with_defaulted_inventories =
            parse_program_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert!(
            current_with_defaulted_inventories
                .program_headers
                .is_empty()
        );
        assert!(
            current_with_defaulted_inventories
                .dynamic_symbols
                .is_empty()
        );

        legacy["schema_version"] = serde_json::json!(3);
        let migrated = parse_program_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, PROGRAM_SPEC_VERSION);
        assert_eq!(migrated.uncertainties.len(), 1);

        legacy["schema_version"] = serde_json::json!(4);
        let migrated = parse_program_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, PROGRAM_SPEC_VERSION);
        assert_eq!(
            migrated.entry_location,
            Some(Location {
                address_space: 0,
                value: Address(0x401000)
            })
        );

        legacy["schema_version"] = serde_json::json!(1);
        for field in [
            "address_spaces",
            "mapped_segments",
            "imports",
            "relocations",
            "calls",
            "references",
            "call_recovery",
            "reference_recovery",
            "assumptions",
            "image_base",
            "entry_point",
            "data_layout",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let migrated = parse_program_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, PROGRAM_SPEC_VERSION);
        assert_eq!(migrated.entry_location, None);
        assert_eq!(migrated.call_recovery, RecoveryState::NotAttempted);

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

    #[test]
    fn region_spec_v2_migrates_and_rejects_tampered_bytes() {
        let code = [0xc3];
        let spec = RegionContract {
            schema_version: REGION_SPEC_VERSION,
            binary_sha256: "b".repeat(64),
            symbol_name: "return_only".to_owned(),
            address_kind: AddressKind::Virtual,
            entry: Address(0x401000),
            byte_length: code.len() as u64,
            bytes_sha256: format!("{:x}", Sha256::digest(code)),
            bytes_hex: "c3".to_owned(),
            exits: vec![Address(0x401000)],
            calls: Vec::new(),
            relocations: Vec::new(),
            observed_interior_entries: Vec::new(),
            live_in: None,
            live_out: None,
            physical_live_in: Vec::new(),
            physical_live_out: Vec::new(),
            stack_delta: Some(8),
            stack_entry_alignment: None,
            exit_stack_relations: Vec::new(),
            global_references: Vec::new(),
            variable_locations: Vec::new(),
            assumptions: Vec::new(),
            unresolved_facts: vec!["live state not established".to_owned()],
            replacement_ready: false,
            provenance: FactProvenance {
                source: FactSource::NativeAnalysis,
                scope: "test".to_owned(),
            },
        };
        let mut legacy = serde_json::to_value(&spec).unwrap();
        legacy["schema_version"] = serde_json::json!(2);
        for field in [
            "calls",
            "physical_live_in",
            "physical_live_out",
            "stack_entry_alignment",
            "exit_stack_relations",
            "global_references",
            "variable_locations",
            "assumptions",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let migrated = parse_region_spec_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, REGION_SPEC_VERSION);
        assert!(migrated.physical_live_in.is_empty());

        let mut tampered = serde_json::to_value(&spec).unwrap();
        tampered["bytes_hex"] = serde_json::json!("90");
        assert!(
            parse_region_spec_json(tampered.to_string().as_bytes())
                .unwrap_err()
                .contains("digest")
        );
    }

    #[test]
    fn decompilation_unit_v1_migrates_without_upgrading_claims() {
        let code = [0xc3];
        let region = RegionContract {
            schema_version: REGION_SPEC_VERSION,
            binary_sha256: "c".repeat(64),
            symbol_name: "return_only".to_owned(),
            address_kind: AddressKind::Virtual,
            entry: Address(0x401000),
            byte_length: code.len() as u64,
            bytes_sha256: format!("{:x}", Sha256::digest(code)),
            bytes_hex: "c3".to_owned(),
            exits: Vec::new(),
            calls: Vec::new(),
            relocations: Vec::new(),
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
            unresolved_facts: vec!["legacy boundary state".to_owned()],
            replacement_ready: false,
            provenance: FactProvenance {
                source: FactSource::NativeAnalysis,
                scope: "test".to_owned(),
            },
        };
        let unit = DecompilationUnit {
            schema_version: DECOMPILATION_UNIT_VERSION,
            binary_sha256: region.binary_sha256.clone(),
            region,
            function_id: None,
            model_revision: None,
            artifacts: DecompilationArtifactDigests::default(),
            region_ir_llvm: "define i64 @f() { ret i64 0 }".to_owned(),
            cir: None,
            c_source: "void f(void) {}\n".to_owned(),
            low_level_c: Some("void f(void) {}\n".to_owned()),
            structured_c: None,
            structural_completeness: DecompilationStructuralCompleteness::Partial,
            semantic_fidelity: DecompilationSemanticFidelity::Conservative,
            verification: DecompilationVerificationStatus::NotRun,
            rewrite_ready: false,
            statement_provenance: Vec::new(),
            diagnostics: Vec::new(),
            engine_version: "hydir/legacy".to_owned(),
        };
        let mut legacy = serde_json::to_value(unit).unwrap();
        legacy["schema_version"] = serde_json::json!(1);
        for field in [
            "function_id",
            "model_revision",
            "artifacts",
            "low_level_c",
            "structured_c",
            "structural_completeness",
            "semantic_fidelity",
            "verification",
            "rewrite_ready",
        ] {
            legacy.as_object_mut().unwrap().remove(field);
        }
        let migrated = parse_decompilation_unit_json(legacy.to_string().as_bytes()).unwrap();
        assert_eq!(migrated.schema_version, DECOMPILATION_UNIT_VERSION);
        assert_eq!(migrated.low_level_c.as_deref(), Some("void f(void) {}\n"));
        assert_eq!(
            migrated.semantic_fidelity,
            DecompilationSemanticFidelity::Conservative
        );
        assert!(!migrated.rewrite_ready);
    }

    #[test]
    fn legacy_relocation_symbol_target_defaults_to_unresolved_location() {
        let target: RelocationTargetSpec = serde_json::from_value(serde_json::json!({
            "kind": "symbol",
            "id": "legacy-symbol",
            "name": "callee"
        }))
        .unwrap();
        assert!(matches!(
            target,
            RelocationTargetSpec::Symbol {
                location: None,
                defined: false,
                ..
            }
        ));
    }
}
