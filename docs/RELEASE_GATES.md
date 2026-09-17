# Release gates and current boundary — 2026-09-18

This is a development checkpoint, not a completed SegFault submission or a
released decompiler. `bash scripts/demo-linux-docker.sh` is the integrated
reproduction command; the exact final artifacts and counts are in
[`EVIDENCE.md`](EVIDENCE.md). A clean committed source snapshot can be created
with `bash scripts/package-source-snapshot.sh`; it is not a public AGPL
corresponding-source offer.

| Milestone | Verified here | Still blocking completion |
| --- | --- | --- |
| M0 baseline | Rust 1.96.0, Cargo lockfile, Debian Clang/LLVM 14.0.6 image, upstream/notice snapshot | Complete per-file license/native dependency audit, one compatible Remill/Anvill/Rellic/MLIR set, upstream reference lift |
| M1 native vertical slice | Ghidra-free ELF import and scalar CFG-to-LLVM lift; 20 distinct supported functions, 21,168/21,168 tested input pairs across 21 variants; explicit unsupported refusal | Stack/buffer and partial-register semantics, optimization-level diversity, broader ABI and binary corpus |
| M2 shared product | egui initial window visually inspected on macOS; explicit remote upload/pass/rebuild headless probes, owner-scoped SQLite revisions/artifacts, authenticated loopback gRPC, durable lift jobs, replay/cancel, Python SDK subset | Reliable visual interaction QA, full typed operation parity, fine-grained roles, quotas/audit, non-loopback TLS, hostile-input isolation |
| M3 analysis/editing | Local/remote named allowlisted LLVM pass experiment with GUI local/remote pass editor, conservative interprocedural mapped-global effect propagation, bounded scalar LLVM-to-C with 21,168 compiled-C/native matches, and versioned/local/remote whole-function scalar patch v1 with GUI editor and intentional-behavior checks | High-level C structuring/native Rellic compatibility, broader PatchLang/region semantics |
| M4 whole execution | Three fully decoded static freestanding ELFs rebuilt locally into distinct executables with five stdout/stderr/exit matches; one remote rebuilt ELF with three client-side matches and GUI/SDK/CLI typed operations; five semantic refusal cases | Restricted execution-validation API/sandbox, broader stack/OS semantics, independent native-Linux/Windows smoke evidence |
| M5 release | Reproducible integrated Docker gate, local clean-tree source snapshot, opt-in matching-source build and verified retrieval for a clean revision | Security/failure campaign, license/notice closure, installer/release packaging, performance and memory evaluation |

## C-backend boundary and feasibility finding

The [official Rellic build guide](https://github.com/lifting-bits/rellic#dependencies)
lists LLVM and Clang 16 and says that the bitcode consumed by Rellic must use
the same LLVM version. This checkout's tested producer/optimizer/linker set is
14.0.6. The [LLVM C Backend](https://github.com/JuliaHubOSS/llvm-cbe#installation-instructions)
currently documents LLVM 20 on its main branch, and is not a drop-in
substitute for Rellic's structuring route. No Rellic integration is built or
claimed here. Instead, the first-party `hydir-c` backend emits compilable
C11 for only the exact raw scalar LLVM grammar this checkout produces. It
uses explicit gotos and SSA edge copies, and does not recover high-level
source structures. It is independently implemented, not ported Rellic code.

An older, separate Apache-2.0 HydIR checkout has Rust C-recovery work, but
no code from it was copied into this
AGPL checkout, and its model/dependency compatibility and file-level notices
have not been audited here.

The high-level C/Rellic gate still needs a compatible LLVM 16 environment or
an audited adaptation of the older Rust recovery stack. The tested scalar C
path does not imply general patch-region editing or arbitrary-program
decompilation.
