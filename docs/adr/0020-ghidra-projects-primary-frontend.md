# ADR 0020: Ghidra projects are the primary external frontend

Status: accepted, 2026-09-26.

Hydir is a separate binary lifting and reverse-engineering framework that
consumes analyzed Ghidra projects and P-code. The first integration uses a
versioned, bounded export from a Ghidra GUI or headless project. It does not
require Hydir's analysis engine to run inside the Ghidra process.

Raw instruction P-code is imported as semantic input. High/decompiler P-code,
symbols, prototypes, types, CFG, and analyst changes are imported with distinct
provenance and fidelity. The importer validates binary identity, Ghidra
language/compiler specifications, address spaces, bit widths, op ordering,
references, and flow. Unsupported operations remain explicit effects.

Hydir's versioned IR is canonical after import. Existing native x86-64 ELF
analysis remains available for compatibility and cross-checks. LLVM remains
an optional export as decided in ADR 0019; verifier-clean text alone does not
establish semantic equivalence. The desktop app and Ghidra extension are
clients of the framework, not mandatory hosts for it.

This decision supersedes the CTF-centered product and release framing in the
historical workflow proposal. CTF and VM cases remain useful tests and later
applications of the framework.
