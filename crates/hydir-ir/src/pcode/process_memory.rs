//! Versioned, binary-bound initial ELF process bytes and permissions.
//!
//! This is a bounded image of loaded PT_LOAD ranges, not a claim about a
//! complete process. Only disjoint, explicit-addend x86-64 RELATIVE dynamic
//! relocations are applied; other relocation destinations remain unknown.

use super::{GhidraSnapshot, hex_u64, image::snapshot_layout_sha256, validate_ghidra_snapshot};
use object::{
    Architecture, BinaryFormat, Object, ObjectKind, ObjectSegment, RelocationFlags,
    RelocationTarget, SegmentFlags, elf,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const PCODE_ELF_PROCESS_MEMORY_VERSION: u32 = 2;
const PCODE_ELF_PROCESS_MEMORY_V1_VERSION: u32 = 1;
pub const PCODE_ELF_PROCESS_MEMORY_MAX_BYTES: usize = 1_048_576;
pub const PCODE_PROCESS_ALLOCATIONS_VERSION: u32 = 1;
pub const PCODE_PROCESS_ALLOCATION_MAX_BYTES: u64 = 1_048_576;
pub const MAX_PCODE_PROCESS_ALLOCATIONS_JSON_BYTES: usize = 4096;
const MAX_LOAD_SEGMENTS: usize = 4096;
const MAX_REGIONS: usize = 8192;
const MAX_RELOCATIONS: usize = 65_536;

/// A caller-declared allocation, not evidence that an operating system made
/// the allocation. The half-open range starts at `base` and has `byte_len`
/// bytes. Allocation alone never establishes the values of those bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PcodeProcessAllocationKind {
    Stack,
    Heap,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeProcessAllocation {
    pub kind: PcodeProcessAllocationKind,
    pub space: String,
    pub base: u64,
    pub byte_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeProcessAllocations {
    schema_version: u32,
    binary_sha256: String,
    snapshot_layout_sha256: String,
    regions: Vec<PcodeProcessAllocation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredAllocations {
    schema_version: u32,
    regions: Vec<PcodeProcessAllocation>,
}

impl PcodeProcessAllocations {
    /// Parse the caller's small declaration and bind it to the verified ELF
    /// process image. Digest and layout identity are derived, not trusted from
    /// caller JSON. Seed values are validated separately by strict execution.
    pub fn parse_declared(
        json: &[u8],
        snapshot: &GhidraSnapshot,
        process: &PcodeElfProcessMemory,
    ) -> Result<Self, String> {
        if json.is_empty() || json.len() > MAX_PCODE_PROCESS_ALLOCATIONS_JSON_BYTES {
            return Err("process allocation declaration is empty or exceeds 4 KiB".into());
        }
        let declaration: DeclaredAllocations =
            serde_json::from_slice(json).map_err(|error| error.to_string())?;
        if declaration.schema_version != PCODE_PROCESS_ALLOCATIONS_VERSION {
            return Err("unsupported process allocation declaration version".into());
        }
        Self::new(snapshot, process, declaration.regions)
    }

    pub fn new(
        snapshot: &GhidraSnapshot,
        process: &PcodeElfProcessMemory,
        mut regions: Vec<PcodeProcessAllocation>,
    ) -> Result<Self, String> {
        process.validate_for_snapshot(snapshot)?;
        regions.sort_by_key(|region| region.kind as u8);
        let contract = Self {
            schema_version: PCODE_PROCESS_ALLOCATIONS_VERSION,
            binary_sha256: process.binary_sha256.clone(),
            snapshot_layout_sha256: snapshot_layout_sha256(snapshot)?,
            regions,
        };
        contract.validate_for(snapshot, process)?;
        Ok(contract)
    }

    pub fn regions(&self) -> &[PcodeProcessAllocation] {
        &self.regions
    }

    pub fn validate_for(
        &self,
        snapshot: &GhidraSnapshot,
        process: &PcodeElfProcessMemory,
    ) -> Result<(), String> {
        process.validate_for_snapshot(snapshot)?;
        if self.schema_version != PCODE_PROCESS_ALLOCATIONS_VERSION
            || self.binary_sha256 != process.binary_sha256
            || self.snapshot_layout_sha256 != snapshot_layout_sha256(snapshot)?
            || self.regions.len() > 2
        {
            return Err("process allocations disagree with the ELF or Ghidra snapshot".into());
        }
        let process_end = process
            .base
            .checked_add(process.bytes.len() as u64)
            .ok_or("ELF process span overflows")?;
        let mut total = 0u64;
        let mut seen = BTreeSet::new();
        for region in &self.regions {
            if !seen.insert(region.kind as u8)
                || region.space != process.space
                || region.byte_len == 0
            {
                return Err("process allocation kind, space, or size is invalid".into());
            }
            let end = region
                .base
                .checked_add(region.byte_len)
                .ok_or("process allocation address overflows")?;
            total = total
                .checked_add(region.byte_len)
                .ok_or("process allocation size overflows")?;
            if total > PCODE_PROCESS_ALLOCATION_MAX_BYTES
                || (region.base < process_end && process.base < end)
            {
                return Err("process allocation exceeds budget or overlaps the ELF span".into());
            }
        }
        if self.regions.len() == 2 {
            let a = &self.regions[0];
            let b = &self.regions[1];
            if a.base < b.base + b.byte_len && b.base < a.base + a.byte_len {
                return Err("stack and heap allocations overlap".into());
            }
        }
        Ok(())
    }

    pub fn contains(&self, space: &str, address: u64) -> bool {
        self.regions.iter().any(|region| {
            region.space == space
                && address >= region.base
                && address - region.base < region.byte_len
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeElfProcessMemory {
    schema_version: u32,
    binary_sha256: String,
    snapshot_layout_sha256: String,
    space: String,
    base: u64,
    /// One byte per address in the bounded range. Unknown locations hold zero
    /// here but always have a zero `known` mask.
    bytes: Vec<u8>,
    /// `0xff` means the initial byte is established by PT_LOAD or its zero tail.
    known: Vec<u8>,
    /// `0xff` means the address is within a checked loaded ELF mapping.
    mapped: Vec<u8>,
    /// `0xff` means the mapping permits a write.
    writable: Vec<u8>,
    /// Number of destination bytes still hidden by dynamic relocations.
    unresolved_relocation_bytes: usize,
    /// Deserialization alone cannot establish that these bytes came from the
    /// named binary. Only the constructor or canonical parser can bind them.
    #[serde(skip)]
    bound_to_binary: bool,
}

#[derive(Clone, Copy)]
struct Region {
    start: u64,
    end: u64,
    file_offset: Option<usize>,
    writable: bool,
}

impl PcodeElfProcessMemory {
    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }
    pub fn space(&self) -> &str {
        &self.space
    }
    pub fn base(&self) -> u64 {
        self.base
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn known(&self) -> &[u8] {
        &self.known
    }
    pub fn mapped(&self) -> &[u8] {
        &self.mapped
    }
    pub fn writable(&self) -> &[u8] {
        &self.writable
    }
    pub fn unresolved_relocation_bytes(&self) -> usize {
        self.unresolved_relocation_bytes
    }

    pub fn from_elf(
        binary: &[u8],
        snapshot: &GhidraSnapshot,
        max_bytes: usize,
    ) -> Result<Self, String> {
        Self::from_elf_version(
            binary,
            snapshot,
            max_bytes,
            PCODE_ELF_PROCESS_MEMORY_VERSION,
        )
    }

    fn from_elf_version(
        binary: &[u8],
        snapshot: &GhidraSnapshot,
        max_bytes: usize,
        schema_version: u32,
    ) -> Result<Self, String> {
        if !matches!(
            schema_version,
            PCODE_ELF_PROCESS_MEMORY_V1_VERSION | PCODE_ELF_PROCESS_MEMORY_VERSION
        ) {
            return Err("unsupported ELF process memory version".to_owned());
        }
        if max_bytes == 0 || max_bytes > PCODE_ELF_PROCESS_MEMORY_MAX_BYTES {
            return Err("ELF process memory allocation limit is invalid".to_owned());
        }
        let digest = format!("{:x}", Sha256::digest(binary));
        validate_ghidra_snapshot(snapshot, &digest)?;
        let file = object::File::parse(binary).map_err(|error| format!("invalid ELF: {error}"))?;
        if file.format() != BinaryFormat::Elf
            || file.architecture() != Architecture::X86_64
            || !file.is_little_endian()
            || !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic)
        {
            return Err("process memory requires executable x86-64 ELF".to_owned());
        }
        let space = &snapshot.program.image_base.space;
        if !snapshot.address_spaces.iter().any(|candidate| {
            candidate.name == *space
                && candidate.space_type == 1
                && candidate.addressable_unit_size == 1
        }) {
            return Err("Ghidra image base is not byte-addressable RAM".to_owned());
        }
        let mut segments = file.segments();
        let first = segments.next().ok_or("ELF has no PT_LOAD segments")?;
        let mut lowest = first.address();
        let mut segment_count = 1;
        for segment in segments {
            segment_count += 1;
            if segment_count > MAX_LOAD_SEGMENTS {
                return Err("ELF load segment limit exceeded".to_owned());
            }
            lowest = lowest.min(segment.address());
        }
        let load_bias =
            i128::from(hex_u64(&snapshot.program.image_base.offset)?) - i128::from(lowest);
        let mut regions = Vec::new();
        for segment in file.segments() {
            let SegmentFlags::Elf { p_flags } = segment.flags() else {
                return Err("ELF segment has non-ELF flags".to_owned());
            };
            if p_flags & elf::PF_R == 0 || segment.size() == 0 {
                continue;
            }
            let (file_offset, file_len) = segment.file_range();
            if file_len > segment.size() {
                return Err("ELF file-backed segment exceeds mapped size".to_owned());
            }
            let file_offset =
                usize::try_from(file_offset).map_err(|_| "ELF file offset overflows")?;
            let file_len_usize =
                usize::try_from(file_len).map_err(|_| "ELF file length overflows")?;
            if file_offset
                .checked_add(file_len_usize)
                .filter(|end| *end <= binary.len())
                .is_none()
            {
                return Err("ELF PT_LOAD file range exceeds binary".to_owned());
            }
            let start = u64::try_from(i128::from(segment.address()) + load_bias)
                .map_err(|_| "ELF segment cannot map to Ghidra RAM")?;
            let file_end = start
                .checked_add(file_len)
                .ok_or("ELF file range overflows Ghidra RAM")?;
            let end = start
                .checked_add(segment.size())
                .ok_or("ELF mapped range overflows Ghidra RAM")?;
            for block in &snapshot.memory_blocks {
                if block.start.space != *space
                    || !block.loaded
                    || !block.read
                    || block.overlay
                    || block.write != (p_flags & elf::PF_W != 0)
                    || block.execute != (p_flags & elf::PF_X != 0)
                {
                    continue;
                }
                let block_start = hex_u64(&block.start.offset)?;
                let block_end = hex_u64(&block.end.offset)?
                    .checked_add(1)
                    .ok_or("Ghidra block end overflows")?;
                for (part_start, part_end, backed) in
                    [(start, file_end, true), (file_end, end, false)]
                {
                    if backed && !block.initialized {
                        continue;
                    }
                    let lo = part_start.max(block_start);
                    let hi = part_end.min(block_end);
                    if lo >= hi {
                        continue;
                    }
                    let offset = if backed {
                        Some(
                            file_offset
                                .checked_add(
                                    usize::try_from(lo - start)
                                        .map_err(|_| "ELF file displacement overflows")?,
                                )
                                .ok_or("ELF file offset overflows")?,
                        )
                    } else {
                        None
                    };
                    regions.push(Region {
                        start: lo,
                        end: hi,
                        file_offset: offset,
                        writable: block.write,
                    });
                    if regions.len() > MAX_REGIONS {
                        return Err("ELF process region limit exceeded".to_owned());
                    }
                }
            }
        }
        regions.sort_by_key(|region| (region.start, region.end));
        if regions.is_empty() {
            return Err("ELF and Ghidra have no matching loaded bytes".to_owned());
        }
        for pair in regions.windows(2) {
            if pair[0].end > pair[1].start {
                return Err("ELF process regions overlap in Ghidra RAM".to_owned());
            }
        }
        let base = regions[0].start;
        let span = usize::try_from(regions.last().unwrap().end - base)
            .map_err(|_| "ELF process span overflows")?;
        if span == 0 || max_bytes == 0 || span > max_bytes {
            return Err(format!(
                "ELF process memory needs {span} bytes, limit is {max_bytes}"
            ));
        }
        let mut bytes = vec![0; span];
        let mut known = vec![0; span];
        let mut mapped = vec![0; span];
        let mut writable = vec![0; span];
        for region in &regions {
            let lo = usize::try_from(region.start - base).unwrap();
            let hi = usize::try_from(region.end - base).unwrap();
            if let Some(offset) = region.file_offset {
                let source = binary
                    .get(offset..offset + (hi - lo))
                    .ok_or("ELF region exceeds binary")?;
                bytes[lo..hi].copy_from_slice(source);
            }
            known[lo..hi].fill(0xff);
            mapped[lo..hi].fill(0xff);
            if region.writable {
                writable[lo..hi].fill(0xff);
            }
        }
        let mut relocated = BTreeSet::new();
        let mut relocation_hits = vec![0u8; span];
        let mut relative_candidates = Vec::new();
        if let Some(relocations) = file.dynamic_relocations() {
            let mut relocation_count = 0usize;
            for (address, relocation) in relocations {
                relocation_count += 1;
                if relocation_count > MAX_RELOCATIONS {
                    return Err("ELF dynamic relocation count limit exceeded".to_owned());
                }
                // Some ELF relocation records report no generic bit width.
                // Only known x86-64 write widths can be safely masked; COPY
                // and unknown records require a loader contract before use.
                let width = if relocation.size() == 0 {
                    match relocation.flags() {
                        RelocationFlags::Elf { r_type }
                            if matches!(
                                r_type,
                                elf::R_X86_64_RELATIVE
                                    | elf::R_X86_64_GLOB_DAT
                                    | elf::R_X86_64_JUMP_SLOT
                                    | elf::R_X86_64_IRELATIVE
                                    | elf::R_X86_64_64
                            ) =>
                        {
                            8
                        }
                        RelocationFlags::Elf { r_type } if r_type == elf::R_X86_64_TLSDESC => 16,
                        _ => {
                            return Err("ELF dynamic relocation has unknown write width".to_owned());
                        }
                    }
                } else {
                    usize::from(relocation.size()).div_ceil(8)
                };
                if width == 0 || width > 16 {
                    return Err("unsupported ELF dynamic relocation width".to_owned());
                }
                let target = u64::try_from(i128::from(address) + load_bias)
                    .map_err(|_| "ELF relocation cannot map to Ghidra RAM")?;
                let mut destination = Vec::with_capacity(width);
                for byte in 0..width {
                    let Some(at) = target.checked_add(byte as u64) else {
                        return Err("ELF relocation address overflows".to_owned());
                    };
                    if let Some(index) = at
                        .checked_sub(base)
                        .and_then(|index| usize::try_from(index).ok())
                        .filter(|index| *index < span && mapped[*index] == 0xff)
                    {
                        known[index] = 0;
                        relocated.insert(index);
                        relocation_hits[index] = relocation_hits[index].saturating_add(1);
                        destination.push(index);
                    }
                }
                if schema_version == PCODE_ELF_PROCESS_MEMORY_VERSION
                    && matches!(relocation.flags(), RelocationFlags::Elf { r_type } if r_type == elf::R_X86_64_RELATIVE)
                    && width == 8
                    && destination.len() == 8
                    && !relocation.has_implicit_addend()
                    && relocation.target() == RelocationTarget::Absolute
                {
                    if let Ok(value) = u64::try_from(load_bias + i128::from(relocation.addend())) {
                        relative_candidates.push((destination, value.to_le_bytes()));
                    }
                }
            }
        }
        for (destination, value) in relative_candidates {
            if destination.iter().all(|index| relocation_hits[*index] == 1) {
                for (index, byte) in destination.into_iter().zip(value) {
                    bytes[index] = byte;
                    known[index] = 0xff;
                }
            }
        }
        let unresolved_relocation_bytes =
            relocated.iter().filter(|index| known[**index] == 0).count();
        Ok(Self {
            schema_version,
            binary_sha256: digest,
            snapshot_layout_sha256: snapshot_layout_sha256(snapshot)?,
            space: space.clone(),
            base,
            bytes,
            known,
            mapped,
            writable,
            unresolved_relocation_bytes,
            bound_to_binary: true,
        })
    }

    /// Read a serialized contract only after reconstructing it from the exact
    /// ELF and snapshot. A forged digest or altered known byte cannot become
    /// trusted initial process state through JSON deserialization.
    pub fn parse_bound(
        json: &[u8],
        binary: &[u8],
        snapshot: &GhidraSnapshot,
        max_bytes: usize,
    ) -> Result<Self, String> {
        if json.len() > 16 * PCODE_ELF_PROCESS_MEMORY_MAX_BYTES {
            return Err("ELF process memory JSON exceeds limit".to_owned());
        }
        let mut parsed: Self = serde_json::from_slice(json)
            .map_err(|error| format!("invalid ELF process memory JSON: {error}"))?;
        let canonical = Self::from_elf_version(binary, snapshot, max_bytes, parsed.schema_version)?;
        parsed.bound_to_binary = true;
        if parsed != canonical {
            return Err("ELF process memory differs from binary and Ghidra layout".to_owned());
        }
        Ok(canonical)
    }

    pub fn validate_for_snapshot(&self, snapshot: &GhidraSnapshot) -> Result<(), String> {
        if !self.bound_to_binary
            || !matches!(
                self.schema_version,
                PCODE_ELF_PROCESS_MEMORY_V1_VERSION | PCODE_ELF_PROCESS_MEMORY_VERSION
            )
            || self.binary_sha256 != snapshot.binary_sha256
            || self.snapshot_layout_sha256 != snapshot_layout_sha256(snapshot)?
            || self.space != snapshot.program.image_base.space
            || self.bytes.len() != self.known.len()
            || self.bytes.len() != self.mapped.len()
            || self.bytes.len() != self.writable.len()
            || self.bytes.is_empty()
            || self.bytes.len() > PCODE_ELF_PROCESS_MEMORY_MAX_BYTES
        {
            return Err("ELF process memory disagrees with Ghidra snapshot".to_owned());
        }
        for index in 0..self.bytes.len() {
            if !matches!(self.known[index], 0 | 0xff)
                || !matches!(self.mapped[index], 0 | 0xff)
                || !matches!(self.writable[index], 0 | 0xff)
                || (self.known[index] == 0xff && self.mapped[index] != 0xff)
                || (self.writable[index] == 0xff && self.mapped[index] != 0xff)
            {
                return Err("ELF process memory masks are inconsistent".to_owned());
            }
        }
        Ok(())
    }

    pub fn initial_byte(&self, space: &str, address: u64) -> Option<u8> {
        if space != self.space {
            return None;
        }
        let index = address
            .checked_sub(self.base)
            .and_then(|index| usize::try_from(index).ok())?;
        (self.known.get(index) == Some(&0xff)).then(|| self.bytes[index])
    }

    pub fn is_mapped(&self, space: &str, address: u64) -> bool {
        if space != self.space {
            return false;
        }
        address
            .checked_sub(self.base)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.mapped.get(index))
            .copied()
            == Some(0xff)
    }

    pub fn is_writable(&self, space: &str, address: u64) -> bool {
        if space != self.space {
            return false;
        }
        address
            .checked_sub(self.base)
            .and_then(|index| usize::try_from(index).ok())
            .and_then(|index| self.writable.get(index))
            .copied()
            == Some(0xff)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{
        PcodeConcreteState, PcodeExecutionStop, PcodeMemoryBoundaryKind, PcodePathStop,
        PcodeVarnode, parse_ghidra_snapshot,
    };

    fn fixture() -> (Vec<u8>, GhidraSnapshot) {
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let digest = format!("{:x}", Sha256::digest(binary));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_password_secure_equals_o1_v2.json"
            )),
            &digest,
        )
        .unwrap();
        (binary.to_vec(), snapshot)
    }

    fn node(space: &str, offset: &str, size: u32) -> PcodeVarnode {
        PcodeVarnode {
            space: space.into(),
            offset: offset.into(),
            size,
        }
    }

    #[test]
    fn stripped_elf_maps_bss_zero_with_checked_permissions() {
        let (binary, snapshot) = fixture();
        let memory = PcodeElfProcessMemory::from_elf(&binary, &snapshot, 64 * 1024).unwrap();
        memory.validate_for_snapshot(&snapshot).unwrap();
        assert_eq!(memory.initial_byte("ram", 0x2001f0), Some(b'H'));
        assert_eq!(memory.initial_byte("ram", 0x2028f0), Some(0));
        assert!(memory.is_writable("ram", 0x2028f0));
        assert!(!memory.is_writable("ram", 0x2001f0));
        assert!(!memory.is_mapped("ram", 0x2001e4));
        let json = serde_json::to_vec(&memory).unwrap();
        let unbound = serde_json::from_slice::<PcodeElfProcessMemory>(&json).unwrap();
        assert!(unbound.validate_for_snapshot(&snapshot).is_err());
        assert_eq!(
            PcodeElfProcessMemory::parse_bound(&json, &binary, &snapshot, 64 * 1024).unwrap(),
            memory
        );
        let mut forged: serde_json::Value = serde_json::from_slice(&json).unwrap();
        forged["bytes"][0] = serde_json::json!(0);
        assert!(
            PcodeElfProcessMemory::parse_bound(
                &serde_json::to_vec(&forged).unwrap(),
                &binary,
                &snapshot,
                64 * 1024,
            )
            .is_err()
        );
        assert!(PcodeElfProcessMemory::from_elf(&binary, &snapshot, 1).is_err());
    }

    #[test]
    fn v1_process_memory_remains_parseable_against_its_binary() {
        let (binary, snapshot) = fixture();
        let legacy = PcodeElfProcessMemory::from_elf_version(
            &binary,
            &snapshot,
            64 * 1024,
            PCODE_ELF_PROCESS_MEMORY_V1_VERSION,
        )
        .unwrap();
        assert_eq!(legacy.schema_version, 1);
        let json = serde_json::to_vec(&legacy).unwrap();
        assert_eq!(
            PcodeElfProcessMemory::parse_bound(&json, &binary, &snapshot, 64 * 1024).unwrap(),
            legacy
        );
    }

    #[test]
    fn process_executor_reads_bss_and_allows_writable_store() {
        let (binary, mut snapshot) = fixture();
        let memory = PcodeElfProcessMemory::from_elf(&binary, &snapshot, 64 * 1024).unwrap();
        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode.truncate(1);
        let operation = &mut instruction.pcode[0];
        operation.opcode = 2;
        operation.mnemonic = "LOAD".into();
        operation.inputs = vec![node("const", "0x1b1", 4), node("const", "0x2028f0", 8)];
        operation.output = Some(node("register", "0x0", 1));
        let trace = snapshot
            .execute_concrete_path_with_process_memory(
                &PcodeConcreteState::default(),
                &memory,
                None,
                1,
                4,
            )
            .unwrap();
        assert_eq!(
            trace
                .final_state
                .read_varnode(&node("register", "0x0", 1))
                .unwrap(),
            Some(0)
        );

        let operation = &mut snapshot.selected_function.instructions[0].pcode[0];
        operation.opcode = 3;
        operation.mnemonic = "STORE".into();
        operation.inputs.push(node("const", "0x5a", 1));
        operation.output = None;
        let trace = snapshot
            .execute_concrete_path_with_process_memory(
                &PcodeConcreteState::default(),
                &memory,
                None,
                1,
                4,
            )
            .unwrap();
        assert_eq!(
            trace.final_state.read_memory("ram", 0x2028f0, 1).unwrap(),
            Some(0x5a)
        );
        assert_eq!(memory.initial_byte("ram", 0x2028f0), Some(0));
    }

    #[test]
    fn process_executor_checks_readonly_write_and_seed_conflict() {
        let (binary, mut snapshot) = fixture();
        let memory = PcodeElfProcessMemory::from_elf(&binary, &snapshot, 64 * 1024).unwrap();
        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode.truncate(1);
        let operation = &mut instruction.pcode[0];
        operation.opcode = 3;
        operation.mnemonic = "STORE".into();
        operation.inputs = vec![
            node("const", "0x1b1", 4),
            node("const", "0x2001f0", 8),
            node("const", "0x58", 1),
        ];
        operation.output = None;
        let trace = snapshot
            .execute_concrete_path_with_process_memory(
                &PcodeConcreteState::default(),
                &memory,
                None,
                4,
                4,
            )
            .unwrap();
        assert!(matches!(
            trace.stop,
            PcodePathStop::EffectBoundary {
                boundary: PcodeExecutionStop::MemoryBoundary {
                    reason: PcodeMemoryBoundaryKind::ReadOnlyImageWrite,
                    ..
                }
            }
        ));
        let mut seed = PcodeConcreteState::default();
        seed.write_memory("ram", 0x2001f0, 1, 0x58).unwrap();
        assert!(
            snapshot
                .execute_concrete_path_with_process_memory(&seed, &memory, None, 4, 4,)
                .is_err()
        );
        seed = PcodeConcreteState::default();
        seed.write_memory("ram", 0x2028f0, 1, 0x58).unwrap();
        assert!(
            snapshot
                .execute_concrete_path_with_process_memory(&seed, &memory, None, 4, 4,)
                .is_ok()
        );
    }

    #[test]
    fn strict_stack_boundary_rejects_crossing_store_without_partial_write() {
        let (binary, mut snapshot) = fixture();
        let process = PcodeElfProcessMemory::from_elf(&binary, &snapshot, 64 * 1024).unwrap();
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
        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode.truncate(1);
        let operation = &mut instruction.pcode[0];
        operation.opcode = 3;
        operation.mnemonic = "STORE".into();
        operation.inputs = vec![
            node("const", "0x1b1", 4),
            node("const", "0x70000f", 8),
            node("const", "0xbeef", 2),
        ];
        operation.output = None;
        let source = operation.source_address.clone();
        let mut seed = PcodeConcreteState::default();
        seed.write_memory("ram", 0x70000f, 1, 0xaa).unwrap();
        let trace = snapshot
            .execute_concrete_path_with_allocations(&seed, &process, &allocations, None, 1, 4)
            .unwrap();
        assert!(matches!(
            trace.stop,
            PcodePathStop::EffectBoundary {
                boundary: PcodeExecutionStop::MemoryBoundary {
                    source: ref stopped,
                    reason: PcodeMemoryBoundaryKind::UnmappedWrite,
                    ..
                }
            } if stopped.source_address == source
        ));
        assert_eq!(
            trace.final_state.read_memory("ram", 0x70000f, 1).unwrap(),
            Some(0xaa)
        );
        assert_eq!(
            trace.final_state.read_memory("ram", 0x700010, 1).unwrap(),
            None
        );

        snapshot.selected_function.instructions[0].pcode[0].inputs[1].offset = "0x70000e".into();
        let trace = snapshot
            .execute_concrete_path_with_allocations(&seed, &process, &allocations, None, 1, 4)
            .unwrap();
        assert_eq!(
            trace.final_state.read_memory("ram", 0x70000e, 2).unwrap(),
            Some(0xbeef)
        );

        seed.write_memory("ram", 0x900000, 1, 0xff).unwrap();
        assert!(
            snapshot
                .execute_concrete_path_with_allocations(&seed, &process, &allocations, None, 1, 4)
                .unwrap_err()
                .contains("no declared allocation")
        );
    }

    #[test]
    fn declared_allocations_are_bounded_and_bound_to_the_process_layout() {
        let (binary, snapshot) = fixture();
        let process = PcodeElfProcessMemory::from_elf(&binary, &snapshot, 64 * 1024).unwrap();
        let declaration = serde_json::json!({
            "schema_version": 1,
            "regions": [
                {"kind":"stack", "space":"ram", "base":7340032, "byte_len":16},
                {"kind":"heap", "space":"ram", "base":8388608, "byte_len":16}
            ]
        });
        let parsed = PcodeProcessAllocations::parse_declared(
            &serde_json::to_vec(&declaration).unwrap(),
            &snapshot,
            &process,
        )
        .unwrap();
        assert!(parsed.validate_for(&snapshot, &process).is_ok());
        assert!(parsed.contains("ram", 0x70000f));
        assert!(!parsed.contains("ram", 0x700010));
        let mut invalid = declaration.clone();
        invalid["regions"][1]["base"] = serde_json::json!(0x700008);
        assert!(
            PcodeProcessAllocations::parse_declared(
                &serde_json::to_vec(&invalid).unwrap(),
                &snapshot,
                &process,
            )
            .unwrap_err()
            .contains("overlap")
        );
        invalid = declaration.clone();
        invalid["regions"][0]["base"] = serde_json::json!(process.base());
        assert!(
            PcodeProcessAllocations::parse_declared(
                &serde_json::to_vec(&invalid).unwrap(),
                &snapshot,
                &process,
            )
            .unwrap_err()
            .contains("ELF span")
        );
        invalid = declaration;
        invalid["regions"][0]["byte_len"] =
            serde_json::json!(PCODE_PROCESS_ALLOCATION_MAX_BYTES + 1);
        assert!(
            PcodeProcessAllocations::parse_declared(
                &serde_json::to_vec(&invalid).unwrap(),
                &snapshot,
                &process,
            )
            .is_err()
        );
    }
}
