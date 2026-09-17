# ADR 0002: direct CFG and analyst-supplied stripped entry

Status: accepted for the extended M1 slice, 2026-09-17.

The original linear lifter remains as a tested baseline. Named-symbol lifting
now uses a reachable direct-CFG path. It decodes from the symbol entry, checks
overlapping instruction boundaries, rejects any required edge outside the
declared byte extent, and emits one LLVM block per recovered instruction.
Register values and ZF/SF/OF/CF are joined with explicit phi nodes. A
must-defined dataflow check rejects reads uninitialized on any reachable
path, including loop back-edges. The IR has no `nsw`, `nuw`, `undef`,
`poison`, or fabricated `unreachable` for unsupported machine behavior.

This intentionally trades compact IR for inspectable address/byte mappings
and a small auditable semantics boundary. Memory, calls, partial registers,
additional flags, and indirect edges remain unsupported. Compiler pass
effects on address mapping have not yet been modeled.

For stripped linked ELF, the analyst may supply a virtual entry address and
exact byte extent. HydIR checks that range against one text section and
records the provenance as an analyst assumption. It does not search for
functions, infer a prototype, or claim complete stripped-binary recovery.
The trusted-fixture validation still executes without a sandbox and is not a
remote-safe facility.
