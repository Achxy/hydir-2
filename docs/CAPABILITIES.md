# Capability matrix — 2026-09-17

Legend: **yes** means implemented and tested in this checkout; **partial**
means a restricted contract; **no** means absent. Import never implies safe
lifting or rebuilding.

| Target / operation | Import | Global analysis | Function lift | C output | Patching | Whole-executable rebuild | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| x86-64 little-endian linked ELF, symbolized, Linux SysV | yes | partial: bounded symbol call graph and conservative mapped-global effects | partial: symbol-bounded scalar two-argument functions with direct branches/loops | no | no | no | `hydirctl inspect/analyze/cfg/lift`, LLVM verification, trusted differential tests |
| x86-64 linked ELF, stripped | partial: sections; analyst entry/size required | no: symbol scope unavailable | partial: same scalar CFG subset with explicit entry/size | no | no | no | `cfg-at/lift-at/validate-at` on stripped max fixture, 1,008 matches |
| x86-64 ELF with calls or memory effects | yes | partial: direct-call propagation and unknown-effect flag | no | no | no | no | `demo-analysis.sh` global write and indirect-call fixture; lift rejects unsupported semantics |
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

The `hydir` egui app can open a local ELF or explicitly inspect an existing
authenticated loopback project, then browse function facts, reachable CFG,
machine bytes, and LLVM IR. Its remote path does not upload binaries. A
desktop smoke run was attempted on macOS; automated visual/interaction QA is
still outstanding. The `hydird` gRPC service supports authenticated loopback discovery,
idempotent project creation, immutable binary uploads, project inspection,
symbol-scoped CFG/lift, conservative global-effect analysis, owner-scoped durable lift jobs with event replay and
cancellation, and artifact retrieval. It does not support remote
execution, TLS/non-loopback clients, or full authorization
roles. There is no Python SDK, Ghidra adapter, C decompiler, or executable
rebuild yet. The effect analysis is a tested interprocedural subset, not full
M3 completion.
