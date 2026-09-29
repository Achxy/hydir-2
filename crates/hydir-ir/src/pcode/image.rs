//! Immutable, binary-bound ELF bytes for concrete Ghidra P-code LOADs.
//!
//! The image is kept beside the mutable concrete state. This avoids copying
//! every code and data byte into each path segment or serializing an entire
//! executable into a trace. The trace still records the binary digest, source
//! P-code operation, effective memory address, and exact value read.

use super::{GhidraSnapshot, hex_u64, validate_ghidra_snapshot};
use crate::pcode::PcodeConcreteState;
use object::{Architecture, BinaryFormat, Object, ObjectKind, ObjectSegment, SegmentFlags, elf};
use sha2::{Digest, Sha256};
use std::sync::Arc;

const MAX_LOAD_SEGMENTS: usize = 4096;
const MAX_IMAGE_REGIONS: usize = 8192;

fn snapshot_layout_sha256(snapshot: &GhidraSnapshot) -> Result<String, String> {
    let layout = serde_json::to_vec(&(
        &snapshot.program.image_base,
        &snapshot.address_spaces,
        &snapshot.memory_blocks,
    ))
    .map_err(|error| format!("cannot serialize Ghidra memory layout: {error}"))?;
    Ok(format!("{:x}", Sha256::digest(layout)))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ImageRegion {
    start: u64,
    end: u64, // exclusive
    file_offset: usize,
}

/// File-backed bytes in read-only ELF PT_LOAD regions also marked loaded and
/// read-only by the matching Ghidra snapshot. BSS, writable data, and gaps
/// remain unknown unless the analyst supplies concrete bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcodeReadOnlyElfImage {
    binary_sha256: String,
    snapshot_layout_sha256: String,
    pub(super) space: String,
    binary: Arc<[u8]>,
    regions: Vec<ImageRegion>,
}

/// A bounded address window over the image. A `known` byte is `0xff` only
/// where both the ELF PT_LOAD and Ghidra mark a file-backed, read-only byte;
/// address gaps remain unknown even when `bytes` contains zero there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcodeReadOnlyElfWindow {
    binary_sha256: String,
    snapshot_layout_sha256: String,
    space: String,
    base: u64,
    bytes: Vec<u8>,
    known: Vec<u8>,
}

impl PcodeReadOnlyElfWindow {
    pub fn binary_sha256(&self) -> &str {
        &self.binary_sha256
    }

    pub fn snapshot_layout_sha256(&self) -> &str {
        &self.snapshot_layout_sha256
    }

    /// The same ELF can be analyzed with different Ghidra block permissions.
    /// The window is valid only for the memory layout used to construct it.
    pub fn validate_for_snapshot(&self, snapshot: &GhidraSnapshot) -> Result<(), String> {
        if self.binary_sha256 != snapshot.binary_sha256
            || self.snapshot_layout_sha256 != snapshot_layout_sha256(snapshot)?
        {
            return Err("read-only ELF window disagrees with Ghidra snapshot layout".to_owned());
        }
        Ok(())
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
}

impl PcodeReadOnlyElfImage {
    /// Materialize the smallest contiguous window covering the eligible
    /// regions. Callers choose a strict allocation limit for their memory ABI.
    pub fn materialize_window(&self, max_bytes: usize) -> Result<PcodeReadOnlyElfWindow, String> {
        let first = self
            .regions
            .first()
            .ok_or("read-only ELF image has no eligible regions")?;
        let last = self
            .regions
            .last()
            .ok_or("read-only ELF image has no eligible regions")?;
        let span = last
            .end
            .checked_sub(first.start)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or("read-only ELF image window size overflows")?;
        if span == 0 || max_bytes == 0 || span > max_bytes {
            return Err(format!(
                "read-only ELF image window requires {span} bytes, limit is {max_bytes}"
            ));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(span)
            .map_err(|_| "read-only ELF image window allocation exceeds limit")?;
        bytes.resize(span, 0);
        let mut known = Vec::new();
        known
            .try_reserve_exact(span)
            .map_err(|_| "read-only ELF image known mask allocation exceeds limit")?;
        known.resize(span, 0);
        for region in &self.regions {
            let start = usize::try_from(region.start - first.start)
                .map_err(|_| "read-only ELF image region offset overflows")?;
            let len = usize::try_from(region.end - region.start)
                .map_err(|_| "read-only ELF image region length overflows")?;
            let end = start
                .checked_add(len)
                .filter(|end| *end <= span)
                .ok_or("read-only ELF image region exceeds window")?;
            let file_end = region
                .file_offset
                .checked_add(len)
                .ok_or("read-only ELF image file offset overflows")?;
            let source = self
                .binary
                .get(region.file_offset..file_end)
                .ok_or("read-only ELF image region exceeds binary")?;
            bytes[start..end].copy_from_slice(source);
            known[start..end].fill(0xff);
        }
        Ok(PcodeReadOnlyElfWindow {
            binary_sha256: self.binary_sha256.clone(),
            snapshot_layout_sha256: self.snapshot_layout_sha256.clone(),
            space: self.space.clone(),
            base: first.start,
            bytes,
            known,
        })
    }

    /// Older v2 snapshots may have no memory-block inventory. They cannot
    /// establish which Ghidra addresses correspond to immutable ELF bytes.
    pub fn has_eligible_blocks(snapshot: &GhidraSnapshot) -> bool {
        snapshot.memory_blocks.iter().any(|block| {
            block.start.space == snapshot.program.image_base.space
                && block.loaded
                && block.initialized
                && block.read
                && !block.write
                && !block.overlay
        })
    }

    /// Bind an ELF image to the exact binary and Ghidra address layout.
    /// `image_base` is used as the load base for ET_DYN as well as ET_EXEC;
    /// only intersections with Ghidra's loaded read-only RAM blocks are kept.
    pub fn from_elf(binary: &[u8], snapshot: &GhidraSnapshot) -> Result<Self, String> {
        let digest = format!("{:x}", Sha256::digest(binary));
        validate_ghidra_snapshot(snapshot, &digest)?;
        let file = object::File::parse(binary).map_err(|error| format!("invalid ELF: {error}"))?;
        if file.format() != BinaryFormat::Elf
            || file.architecture() != Architecture::X86_64
            || !file.is_little_endian()
            || !matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic)
        {
            return Err("read-only P-code image requires executable x86-64 ELF".to_owned());
        }
        let space = &snapshot.program.image_base.space;
        if !snapshot.address_spaces.iter().any(|candidate| {
            candidate.name == *space
                && candidate.space_type == 1
                && candidate.addressable_unit_size == 1
        }) {
            return Err("Ghidra image base is not a byte-addressable RAM space".to_owned());
        }
        let mut segments = file.segments();
        let mut count = 0usize;
        let mut lowest_address = None;
        for segment in segments.by_ref() {
            count += 1;
            if count > MAX_LOAD_SEGMENTS {
                return Err("ELF load segment limit exceeded".to_owned());
            }
            lowest_address = Some(
                lowest_address.map_or(segment.address(), |low: u64| low.min(segment.address())),
            );
        }
        let lowest_address = lowest_address.ok_or("ELF has no PT_LOAD segments")?;
        let image_base = hex_u64(&snapshot.program.image_base.offset)?;
        let load_bias = i128::from(image_base) - i128::from(lowest_address);
        let mut regions = Vec::new();
        for segment in file.segments() {
            let SegmentFlags::Elf { p_flags } = segment.flags() else {
                return Err("ELF load segment has non-ELF flags".to_owned());
            };
            if p_flags & elf::PF_R == 0 || p_flags & elf::PF_W != 0 {
                continue;
            }
            let (offset, size) = segment.file_range();
            if size == 0 {
                continue;
            }
            if size > segment.size() {
                return Err("ELF file-backed segment exceeds memory size".to_owned());
            }
            let file_offset = usize::try_from(offset).map_err(|_| "ELF file offset overflows")?;
            let file_size = usize::try_from(size).map_err(|_| "ELF segment size overflows")?;
            if file_offset
                .checked_add(file_size)
                .filter(|end| *end <= binary.len())
                .is_none()
                || segment
                    .data()
                    .map_err(|error| format!("invalid ELF segment data: {error}"))?
                    .len()
                    != file_size
            {
                return Err("ELF PT_LOAD file range is outside the binary".to_owned());
            }
            let mapped_start = i128::from(segment.address()) + load_bias;
            let mapped_start = u64::try_from(mapped_start)
                .map_err(|_| "ELF load address cannot be mapped to Ghidra RAM")?;
            let mapped_end = mapped_start
                .checked_add(size)
                .ok_or("ELF load address overflows Ghidra RAM")?;
            for block in &snapshot.memory_blocks {
                if block.start.space != *space
                    || !block.loaded
                    || !block.initialized
                    || !block.read
                    || block.write
                    || block.overlay
                {
                    continue;
                }
                let block_start = hex_u64(&block.start.offset)?;
                let block_end = hex_u64(&block.end.offset)?
                    .checked_add(1)
                    .ok_or("Ghidra memory block end overflows")?;
                let start = mapped_start.max(block_start);
                let end = mapped_end.min(block_end);
                if start >= end {
                    continue;
                }
                let displacement = usize::try_from(start - mapped_start)
                    .map_err(|_| "ELF image displacement overflows")?;
                regions.push(ImageRegion {
                    start,
                    end,
                    file_offset: file_offset
                        .checked_add(displacement)
                        .ok_or("ELF image offset overflows")?,
                });
                if regions.len() > MAX_IMAGE_REGIONS {
                    return Err("ELF read-only image region limit exceeded".to_owned());
                }
            }
        }
        regions.sort_by_key(|region| (region.start, region.end));
        for pair in regions.windows(2) {
            if pair[0].end > pair[1].start {
                return Err("ELF read-only image regions overlap in Ghidra RAM".to_owned());
            }
        }
        if regions.is_empty() {
            return Err("ELF and Ghidra have no matching loaded read-only bytes".to_owned());
        }
        Ok(Self {
            binary_sha256: digest,
            snapshot_layout_sha256: snapshot_layout_sha256(snapshot)?,
            space: space.clone(),
            binary: Arc::from(binary),
            regions,
        })
    }

    pub(crate) fn validate_for(
        &self,
        snapshot: &GhidraSnapshot,
        state: &PcodeConcreteState,
    ) -> Result<(), String> {
        if self.binary_sha256 != snapshot.binary_sha256
            || self.space != snapshot.program.image_base.space
            || self.snapshot_layout_sha256 != snapshot_layout_sha256(snapshot)?
        {
            return Err("read-only ELF image disagrees with Ghidra snapshot".to_owned());
        }
        state.validate_readonly_image(self)
    }

    pub(crate) fn byte(&self, space: &str, address: u64) -> Option<u8> {
        if space != self.space {
            return None;
        }
        let index = self
            .regions
            .partition_point(|region| region.start <= address);
        let region = self.regions.get(index.checked_sub(1)?)?;
        if address >= region.end {
            return None;
        }
        let displacement = usize::try_from(address - region.start).ok()?;
        self.binary.get(region.file_offset + displacement).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::{
        PcodeExecutionStop, PcodeMemoryBoundaryKind, PcodePathEvent, PcodePathStop, PcodeVarnode,
        parse_ghidra_snapshot,
    };

    const PASSWORD_DIGEST: &str =
        "4ce1c25b8bf0e96350cb893d81511ef6ebee9509c76ef4e6cb28e869299e5288";

    fn password_fixture() -> (Vec<u8>, GhidraSnapshot) {
        // Ghidra 12.1.4 export of the checked-in stripped ELF at entry
        // 0x2016d0. The ELF comes from tests/fixtures/hydir_password_demo.c.
        let binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/hydir-password-gate-stripped.elf"
        ));
        let snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_password_secure_equals_o1_v2.json"
            )),
            PASSWORD_DIGEST,
        )
        .unwrap();
        (binary.to_vec(), snapshot)
    }

    fn seed(matched: bool) -> PcodeConcreteState {
        let mut state = PcodeConcreteState::default();
        for (offset, value) in [
            ("0x38", 0x700100), // RDI: caller input
            ("0x30", 12),       // RSI: length
            ("0x20", 0x700000), // RSP
            ("0x0", 0),         // RAX before XOR EAX,EAX
            ("0x8", 0),         // RCX before XOR ECX,ECX
        ] {
            state
                .write_varnode(
                    &PcodeVarnode {
                        space: "register".into(),
                        offset: offset.into(),
                        size: 8,
                    },
                    value,
                )
                .unwrap();
        }
        state.write_memory("ram", 0x700000, 8, 0xdeadbeef).unwrap();
        state
            .write_memory(
                "ram",
                0x700100,
                8,
                if matched {
                    0x4341_2d52_4944_5948
                } else {
                    0x4341_2d52_4944_5968
                },
            )
            .unwrap();
        state.write_memory("ram", 0x700108, 4, 0x5353_4543).unwrap();
        state
    }

    #[test]
    fn stripped_secure_equals_reads_binary_phrase_and_keeps_trace_sources() {
        let (binary, snapshot) = password_fixture();
        let image = PcodeReadOnlyElfImage::from_elf(&binary, &snapshot).unwrap();
        assert!(PcodeReadOnlyElfImage::has_eligible_blocks(&snapshot));
        assert_eq!(image.byte("ram", 0x2001f0), Some(b'H'));
        assert_eq!(image.byte("ram", 0x2001fb), Some(b'S'));
        assert_eq!(image.byte("ram", 0x2028f0), None); // writable BSS
        for (matched, expected) in [(true, 1), (false, 0)] {
            let trace = snapshot
                .execute_concrete_path_with_image(&seed(matched), &image, None, 2048, 128)
                .unwrap();
            assert!(matches!(trace.stop, PcodePathStop::Return { .. }));
            let rax = trace
                .final_state
                .read_varnode(&PcodeVarnode {
                    space: "register".into(),
                    offset: "0x0".into(),
                    size: 8,
                })
                .unwrap();
            assert_eq!(rax, Some(expected));
            assert!(trace.events.iter().any(|event| matches!(event,
                PcodePathEvent::Effect { operation }
                if operation.source.source_address.offset == "0x2016f0"
                    && operation.memory_access.as_ref().is_some_and(|access|
                        access.byte_offset == 0x2001f0 && access.value == u64::from(b'H'))
            )));
            let serialized = serde_json::to_vec(&trace).unwrap();
            assert_eq!(
                serde_json::from_slice::<crate::pcode::PcodePathTrace>(&serialized).unwrap(),
                trace
            );
        }
    }

    #[test]
    fn stripped_elf_window_marks_only_eligible_bytes_and_obeys_limit() {
        let (binary, snapshot) = password_fixture();
        let image = PcodeReadOnlyElfImage::from_elf(&binary, &snapshot).unwrap();
        let window = image.materialize_window(64 * 1024).unwrap();
        assert_eq!(window.binary_sha256, snapshot.binary_sha256);
        assert_eq!(window.space, "ram");
        assert_eq!(window.base, 0x200000);
        assert_eq!(window.bytes[0], 0x7f); // ELF header
        assert_eq!(window.known[0], 0xff);
        let phrase = usize::try_from(0x2001f0 - window.base).unwrap();
        assert_eq!(window.bytes[phrase], b'H');
        assert_eq!(window.known[phrase], 0xff);
        let gap = usize::try_from(0x2001e4 - window.base).unwrap();
        assert_eq!(window.bytes[gap], 0);
        assert_eq!(window.known[gap], 0); // between .interp and .rodata
        assert_eq!(window.bytes.len(), window.known.len());
        assert!(image.materialize_window(window.bytes.len() - 1).is_err());
        assert!(image.materialize_window(0).is_err());
    }

    #[test]
    fn image_seed_conflicts_fail_before_path_and_equal_bytes_are_allowed() {
        let (binary, snapshot) = password_fixture();
        let image = PcodeReadOnlyElfImage::from_elf(&binary, &snapshot).unwrap();
        let mut state = seed(true);
        state
            .write_memory("ram", 0x2001f0, 1, u64::from(b'H'))
            .unwrap();
        assert!(
            snapshot
                .execute_concrete_path_with_image(&state, &image, None, 2048, 128)
                .is_ok()
        );
        state
            .write_memory("ram", 0x2001f0, 1, u64::from(b'X'))
            .unwrap();
        let error = snapshot
            .execute_concrete_path_with_image(&state, &image, None, 2048, 128)
            .unwrap_err();
        assert!(error.contains("0x2001f0") && error.contains("conflicts"));

        let mut tampered_binary = binary;
        tampered_binary[0x1f0] ^= 1;
        assert!(PcodeReadOnlyElfImage::from_elf(&tampered_binary, &snapshot).is_err());
    }

    #[test]
    fn write_into_readonly_image_stops_before_state_mutation() {
        let (binary, mut snapshot) = password_fixture();
        let image = PcodeReadOnlyElfImage::from_elf(&binary, &snapshot).unwrap();
        let instruction = &mut snapshot.selected_function.instructions[0];
        instruction.pcode.truncate(1);
        let operation = &mut instruction.pcode[0];
        operation.mnemonic = "STORE".into();
        operation.opcode = 3;
        operation.output = None;
        operation.inputs = vec![
            PcodeVarnode {
                space: "const".into(),
                offset: "0x1b1".into(), // Ghidra RAM space ID
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
        let trace = snapshot
            .execute_concrete_path_with_image(&seed(true), &image, None, 16, 4)
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
        assert_eq!(trace.final_state, seed(true));
    }

    #[test]
    fn old_snapshot_without_blocks_and_dyn_rebase_are_explicit() {
        let (binary, mut snapshot) = password_fixture();
        snapshot.memory_blocks.clear();
        assert!(!PcodeReadOnlyElfImage::has_eligible_blocks(&snapshot));
        assert!(PcodeReadOnlyElfImage::from_elf(&binary, &snapshot).is_err());

        let dyn_binary = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/ghidra_prototype.elf"
        ));
        let digest = format!("{:x}", Sha256::digest(dyn_binary));
        let dyn_snapshot = parse_ghidra_snapshot(
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/fixtures/ghidra_prototype_dwarf_v2.json"
            )),
            &digest,
        )
        .unwrap();
        let image = PcodeReadOnlyElfImage::from_elf(dyn_binary, &dyn_snapshot).unwrap();
        assert_eq!(image.byte("ram", 0x100000), Some(0x7f)); // ELF magic, rebased
        assert_eq!(image.byte("ram", 0x102398), None); // writable PT_LOAD
    }
}
