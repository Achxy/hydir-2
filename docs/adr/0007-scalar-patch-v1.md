# ADR 0007 — Versioned whole-function scalar patch v1

Status: implemented development subset, 2026-09-17.

IRENE-3's patch workflow edits C semantics for a bounded region, but its
PatchLang/PatchIR and region assumptions are not ported here. To test an
actual editable path without claiming that compatibility, HydIR v1 accepts
a deliberately narrow C-like `return` expression in a versioned JSON
document. Rust parses and validates it with source positions, then lowers
only six proven scalar expression shapes to fixed x86-64 instruction bytes.

The input hash, target symbol, ABI assertion, entry-only assumption,
file-backed symbol extent, relocation absence, and replacement size are
checked before a new ELF is produced. Unused bytes in the target symbol
become NOPs. Original bytes and binary remain immutable. The CLI requires
an explicit trusted-fixture flag because it has no hostile-input sandbox.

Remote `ApplyPatch` accepts the same document through an authenticated
project, runs decoding and patching in the limited child worker, and commits
the new ELF as a transactionally new project revision. The operation is
owner-scoped, revision-checked, and idempotent by request key; it does not
execute the result. Validation of the deliberate behavior change remains
client-side and trusted-fixture-only.

This path does not prove there are no inbound transfers to the interior of
the patched symbol. The analyst must assert that fact, and broader
region patching remains a release blocker. See `docs/PATCHING.md` for the
exact grammar and tested boundaries.
