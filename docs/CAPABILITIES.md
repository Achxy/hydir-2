# Capability matrix — 2026-09-17

Legend: **yes** means implemented and tested in this checkout; **partial**
means a restricted contract; **no** means absent. Import never implies safe
lifting or rebuilding.

| Target / operation | Import | Global analysis | Function lift | C output | Patching | Whole-executable rebuild | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| x86-64 little-endian linked ELF, symbolized, Linux SysV | yes | partial: bounded symbol call graph and conservative mapped-global effects | partial: symbol-bounded scalar two-argument functions with direct branches/loops | no | no | partial: only the freestanding subset below | `hydirctl inspect/analyze/cfg/lift/rebuild`, LLVM verification, trusted differential tests |
| x86-64 linked ELF, stripped | partial: sections; analyst entry/size required | no: symbol scope unavailable | partial: same scalar CFG subset with explicit entry/size | no | no | no | `cfg-at/lift-at/validate-at` on stripped max fixture, 1,008 matches |
| x86-64 ELF with calls or memory effects | yes | partial: direct-call propagation and unknown-effect flag | no | no | no | no | `demo-analysis.sh` global write and indirect-call fixture; lift rejects unsupported semantics |
| Freestanding static symbolized Linux x86-64 ELF, complete `.text` symbol coverage, direct control flow, bounded mapped data, read/write/exit | yes | partial | separate stateful complete-program LLVM lift; not the `u64(u64,u64)` function API | no | no | **yes, restricted/local-only** | `demo-recompile.sh`: three whole programs, five controlled behavior matches, five semantic-rejection cases |
| Other ELF architectures or endian modes | no | no | no | no | no | no | Import rejection |
| PE/Mach-O | no | no | no | no | no | no | Import rejection |

The initial `ProgramSpec` records content hash, target, ABI description,
file-derived sections, and ELF symbol facts. A separate, versioned
`FunctionCfg` records reachable one-instruction blocks, original bytes,
direct edges, and provenance for a selected symbol or supplied entry. The
global model still lacks mapped segments, relocations, references, and typed
assumptions. The separate service has SQLite project and immutable binary
revisions, but those are not yet integrated into `ProgramSpec`. These are
versioned starting models, not the complete contract in the implementation
plan.

The local CLI supports an explicit, allowlisted LLVM 14.0.6 pass sequence:
`instcombine`, `sccp`, `simplifycfg`, and `dce`. It saves raw, canonical
before, and after IR snapshots plus SHA-256 diagnostics in a new experiment
directory. This is tested on a trusted scalar function fixture, not on
arbitrary binaries and not through the current remote API or GUI.

`hydirctl rebuild` is a separate, fail-closed complete-program path. It
requires an entry at a sized `_start` symbol, non-overlapping sized symbols
covering all `.text` bytes, no dynamic linking, a bounded `.rodata/.data/.bss`
image, supported direct calls/branches and full-width instructions, and
definite register/flag initialization. It emits stateful LLVM IR and links a
freestanding read/write/exit bridge; guest addresses are translated into a
bounded memory image with ownership/write-permission checks. A conservative
constant-flow check proves the syscall number, descriptor, and buffer extent
at each read/write callsite. It rejects stack
accesses, indirect edges, unknown instructions, unsupported syscalls at
runtime, and outputs to an existing directory. The guest stack is explicitly
unobserved in this subset; host call/return implements direct call nesting.
This is neither general x86-64 support nor a hostile-binary sandbox. It is
not exposed by the GUI, remote API, or Python SDK yet.

The `hydir` egui app can open a local ELF, create an authenticated loopback
project, explicitly upload an ELF to it, or reopen an existing project, then
browse function facts, reachable CFG,
machine bytes, and LLVM IR. Only the separate labelled upload action transfers
bytes. A
desktop smoke run was attempted on macOS; automated visual/interaction QA is
still outstanding. The `hydird` gRPC service supports authenticated loopback discovery,
idempotent project creation, immutable binary uploads, project inspection,
symbol-scoped CFG/lift, conservative global-effect analysis, owner-scoped durable lift jobs with event replay and
cancellation, and artifact retrieval. It does not support remote
execution, TLS/non-loopback clients, or full authorization
roles. There is a Python SDK for the implemented API subset, but no Ghidra
adapter or C decompiler. The effect analysis is a tested interprocedural subset, not full
M3 completion.
