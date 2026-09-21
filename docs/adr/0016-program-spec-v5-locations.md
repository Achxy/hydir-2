# ADR 0016: ProgramSpec v5 canonical locations

Status: accepted, 2026-09-20.

An address value and an `AddressKind` are insufficient to identify bytes in a
relocatable ELF: several sections may all contain offset zero. ProgramSpec v5
adds `Location { address_space, value }` and canonical locations for entries,
sections, function symbols, and relocations. Linked files use address space
zero. Relocatable files receive one address space per ELF section.

Readers accept ProgramSpec v1 through v5. Legacy v1 JSON is expanded with the
fields introduced by v2 before deserialization; v2 through v4 artifacts are
migrated in memory. Migration derives locations only from facts present in the
saved artifact, validates every resulting address-space reference, and never
rewrites the source file. A migration that cannot identify a location fails
rather than choosing a plausible section.

Writers emit only v5. Existing gRPC services continue carrying JSON artifacts,
so their wire methods do not change merely because the advertised artifact
version increases.

ProgramSpec v5 also carries additive, default-empty inventories for raw program
headers, GNU-versioned dynamic symbols, recognized runtime section ranges, and
init/fini pointer arrays. Linked `.eh_frame` FDEs are additive, default-empty
range facts with canonical initial locations and executable-mapping status.
Pointer slots retain their raw file value separately
from an optional relocation-resolved executable target and its provenance.
Relocation symbol and section targets may likewise carry a canonical base
location plus an explicit definition state. Consumers apply the recorded
encoding and addend; they never interpret an `ET_REL` placeholder displacement
as the final target. Older v5 target objects omit these additive fields and are
read as unresolved.
Legacy artifacts therefore deserialize with empty inventories rather than
acquiring metadata that was never present in the stored file.
