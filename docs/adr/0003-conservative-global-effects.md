# ADR 0003: Bounded direct-call global-effect analysis

Status: implemented as a narrow M3 slice, 2026-09-17.

HydIR analyzes reachable instructions from each nonempty, at-most-4096-byte
text symbol in a linked x86-64 ELF. It resolves direct calls only when their
target exactly matches a selected symbol entry, records RIP-relative accesses
to mapped data-like sections, then propagates may-read/may-write sets and an
unknown-effect bit to a fixed point over the call graph. It computes SCC IDs
separately so recursive relationships are visible. Binary content hashes are
included in reports; local and remote operations run the same implementation.

Unknown calls, indirect control flow, invalid/overlapping decoding, and
non-RIP memory accesses taint the summary rather than being silently treated
as pure. The implicit call/return stack accesses are treated as stack-local
under a declared System V stack assumption. This does not prove that a
malicious binary preserves a valid stack, and the report does not claim that
enumerated mapped addresses are exhaustive when `unknown_global_effects`
is true. Linked ELF analysis does not resolve relocatable-object targets,
stripped function boundaries, or arbitrary dynamic dispatch.

The fixture changes a callee from no mapped-global write to a concrete write;
the caller's propagated summary changes. An indirect-call fixture retains an
unknown-effect flag. This satisfies one bounded interprocedural property but
does not deliver M3's pass, C, or patch gates.
