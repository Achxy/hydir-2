# Capability matrix — 2026-09-18

Legend: **yes** means implemented and tested in this checkout; **partial**
means a restricted contract; **no** means absent. Import never implies safe
lifting or rebuilding.

| Target / operation | Import | Global analysis | Function lift | C output | Patching | Whole-executable rebuild | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| x86-64 little-endian linked ELF, symbolized, Linux SysV | yes | partial: bounded symbol call graph and conservative mapped-global effects | partial: symbol-bounded scalar two-argument functions with direct branches/loops | partial: compilable C11 with explicit CFG/gotos and SSA copies for the same scalar subset | partial: trusted whole-function scalar return-expression replacement with size/hash/entry-only checks | partial: only the freestanding subset below | `hydirctl inspect/analyze/cfg/lift/decompile/patch/rebuild`, LLVM verification, 20 distinct trusted scalar functions |
| x86-64 linked ELF, stripped | partial: sections; analyst entry/size required | no: symbol scope unavailable | partial: same scalar CFG subset with explicit entry/size | partial: same subset with supplied entry/size | no | no | `cfg-at/lift-at/decompile-at/validate-c-at` on stripped max fixture, 1,008 C matches |
| x86-64 ELF with calls or memory effects | yes | partial: direct-call propagation and unknown-effect flag | no | no | no | no | `demo-analysis.sh` global write and indirect-call fixture; lift rejects unsupported semantics |
| Freestanding static symbolized Linux x86-64 ELF, complete `.text` symbol coverage, direct control flow, bounded mapped data, read/write/exit | yes | partial | separate stateful complete-program LLVM lift; not the `u64(u64,u64)` function API | no | no | **yes, restricted local/authenticated-loopback** | `demo-recompile.sh`: three whole programs, five controlled behavior matches, five semantic-rejection cases; `demo-remote.sh`: one remote rebuilt program, three controlled client-side matches, revision/restart/isolation checks |
| Other ELF architectures or endian modes | no | no | no | no | no | no | Import rejection |
| PE/Mach-O | no | no | no | no | no | no | Import rejection |

The v2 `ProgramSpec` records content hash, target, ABI description, ELF entry,
file-derived sections, loadable segments with file/memory extents and
permissions, imports, section and dynamic relocations, and ELF symbol facts.
Relocation records retain raw ELF type flags when the generic parser cannot
classify them. Dynamic relocation targets use the dynamic symbol table, not
the separate debugging symbol table. Plain `inspect` still pairs empty
call/reference arrays with explicit `not_attempted` states; emptiness is not
evidence of no calls or references. The separate `analyze-spec` operation
joins bounded reachable-symbol call and memory-reference instruction sites
with native-analysis provenance. It marks both recovery states `partial`,
retains unknown targets as null, and records its analysis contract as an
assumption. Inventory count and metadata-name caps bound inspection output.
An ELF with generic System V OSABI is labelled `x86_64-unknown-elf` rather
than asserting Linux from the OSABI alone. A separate, versioned
`FunctionCfg` records reachable one-instruction blocks, original bytes,
direct edges, and provenance for a selected symbol or supplied entry. The
global model still lacks complete call/reference recovery. The remote
service now persists owner-scoped, digest-bound analyst names, comments, and
assumptions as immutable project revisions. A separate private local SQLite
store persists path-bound projects and digest-scoped analyst facts across
CLI/GUI restarts. Local and remote `inspect`/`analyze-spec` overlay only the
assumptions, with explicit analyst provenance and optional virtual address;
names/comments remain in separate ledgers and do not change recovered
semantics. Local records are not automatically transferred to remote projects.
These are versioned starting models, not the
complete contract in the implementation plan.

The scalar patch v1 operation accepts a versioned JSON document with a
source-located C-like `return` expression, an exact input hash, and the
asserted `u64(u64,u64)` prototype. It emits a new ELF only when its byte
replacement fits in the original symbol extent and no relocations occur
there. The analyst must assert that no control flow enters the function
interior. Remote patching makes an owner-scoped new binary revision and is
idempotent; neither local nor remote patching runs arbitrary samples. This
does not cover general C edits, patch regions, or the upstream PatchLang.
See [patching](PATCHING.md).

The scalar C operation consumes the raw HydIR LLVM lift and rejects syntax
outside its exact grammar. It is not a general C decompiler or a Rellic
integration; the emitted C retains labels/gotos. Across 21 supported scalar
variants (20 distinct functions plus a stripped variant), compiled C matched
native execution on 21,168/21,168 tested input pairs. This is fixture evidence,
not equivalence proof or evidence for memory/call-heavy functions.

The local and authenticated remote CLIs support an explicit, allowlisted LLVM 14.0.6 pass sequence:
`instcombine`, `sccp`, `simplifycfg`, and `dce`. It saves raw, canonical
before, and after IR snapshots plus SHA-256 diagnostics in a new experiment
directory. The remote API stores those snapshots and a report as owner-scoped
artifacts under a new immutable project revision retaining the same ELF. It is tested on a trusted scalar
function fixture, not on arbitrary binaries. The GUI has local and remote
pass editors with verified before/after IR and new-directory local artifacts.

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
This is neither general x86-64 support nor a hostile-binary sandbox. The same
rebuild engine is now invoked by the local CLI/GUI or a fixed-toolchain remote
worker. The remote API creates an owner-scoped immutable revision and IR, ELF,
and report artifacts; the Python SDK and GUI expose that typed operation.
Only the trusted client-side demo executes and compares the rebuilt ELF.

The `hydir` egui app can open a local ELF, create an authenticated loopback
project, explicitly upload an ELF to it, or reopen an existing project, then
browse function facts, reachable CFG,
machine bytes, LLVM IR, and bounded scalar C. Only the separate labelled upload action transfers
bytes. A
private v2 local project database saves navigator/inspector pane widths and
the recent local ELF path; reopening that file requires an explicit button
press. Credentials, binary bytes, and remote sessions are not saved in the
workbench setting.
A local/remote pass editor, restricted local/remote rebuild controls, and scalar
patch v1 editor use the same first-party libraries or typed remote operations
as the CLI. The patch editor requires an explicit entry-only assertion and
never executes the patched ELF. A
desktop window was visually inspected on macOS in its dark-first local-project
state; automated pointer/keyboard interaction QA remains outstanding. The `hydird` gRPC service supports authenticated loopback discovery,
idempotent project creation, immutable binary uploads, project inspection,
symbol-scoped CFG/lift/C, conservative global-effect analysis, owner-scoped durable lift jobs with event replay and
cancellation, named pass execution, whole-executable rebuilding for the restricted subset,
scalar patching as a new revision, artifact retrieval, and optional matching-source retrieval. It does not support remote
execution, TLS/non-loopback clients, or full authorization
roles. There is a Python SDK for the implemented API subset, but no Ghidra
adapter or general C decompiler. The effect analysis is a tested interprocedural subset, not full
M3 completion.
