# HydIR

HydIR is an early, independently implemented binary-lifting workbench. This
checkout contains a tested **M1 native vertical slice**, a **partial M2
desktop and local-authenticated RPC slice**, and a narrowly tested local
whole-executable recompilation subset. It is not the complete remote/decompilation/
recompilation product described in the project plan. It imports little-endian
x86-64 ELF without Ghidra, lifts a deliberately small class of functions from
machine bytes to LLVM IR, differentially executes trusted fixtures on Linux
x86-64, and exposes import/CFG/lift artifacts through a persistent local-only
service.

The `hydir` egui desktop workbench opens local ELF files and can create or
open authenticated loopback projects. It shows function facts,
reachable disassembly/CFG, LLVM IR, assumptions, and diagnostics in resizable
panes. Opening a local binary never uploads it; sending a binary requires the
separate, labelled remote-upload action and creates a new immutable revision.
Saved layouts and C output are not yet implemented. It can start, monitor,
cancel, and retrieve a remote lift job and display a conservative global-effect
analysis. The local CLI has a named LLVM pass experiment for trusted fixtures;
there is no GUI/remote pass editor. The analysis is not complete whole-program
recovery.

## Build and inspect

Rust 1.96.0 is pinned in `rust-toolchain.toml`; `Cargo.lock` pins crates.
The demo additionally needs Clang with x86-64 ELF and LLVM IR support. Native
execution validation requires Linux x86-64.

```sh
cargo test --locked --workspace
cargo run --locked --bin hydir
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydirctl -- inspect /path/to/program.elf
cargo run --locked --bin hydirctl -- analyze /path/to/linked-program.elf
cargo run --locked --bin hydirctl -- cfg /path/to/program.elf function_name
cargo run --locked --bin hydirctl -- lift /path/to/program.elf function_name --assume-u64x2 --output lifted.ll
cargo run --locked --bin hydirctl -- transform /path/to/program.elf function_name --assume-u64x2 --trusted-fixture --passes instcombine,sccp,simplifycfg,dce --output-dir /path/to/new-experiment --opt opt
cargo run --locked --bin hydirctl -- rebuild /path/to/trusted-static-program.elf --trusted-fixture --output-dir /path/to/new-rebuild
```

On a Linux x86-64 host with Clang, `bash scripts/demo-local.sh` builds four
trusted assembly functions, imports them, exports per-function CFG JSON,
lifts them, verifies the IR if `opt` is installed, and compares 1,008
executions per function (eight boundary cases and 1,000 seeded cases). It
also strips one fixture and repeats CFG, lift, IR verification, and 1,008
comparisons using an explicitly supplied entry and byte extent. Artifacts
are written to a fresh `target/demo-local/run.*` directory.

On macOS with Docker Desktop, `bash scripts/demo-linux-docker.sh` builds the
pinned Linux x86-64 development image and runs the tests plus demo there.
On Linux x86-64, `bash scripts/demo-remote.sh` runs the separate-process,
authenticated service/client fixture, including durable lift jobs, event
replay, restart, cancellation, GUI create/upload logic, and cross-project
denial checks. See
[remote operation and threat model](docs/REMOTE.md).
`bash scripts/demo-analysis.sh` checks direct-call propagation of a mapped
global write and conservative treatment of an indirect call in a linked ELF.
`bash scripts/demo-passes.sh` saves raw, canonical before, and after LLVM IR;
it verifies the named pipeline with pinned LLVM `opt` 14.0.6 and compares a
transformed trusted fixture on eight boundary inputs. An IR change and a
verifier pass are not, by themselves, a behavioral proof.
`bash scripts/demo-recompile.sh` lifts the complete decoded `.text` of three
trusted, static freestanding ELFs to stateful LLVM IR, links a bounded guest
memory/syscall bridge into new executables, verifies IR, and compares five
controlled executions (stdout, stderr, exit status). It includes direct
calls, branches, a loop, shared globals, `.bss`, and input-dependent output.
This is local-only and rejects code outside its declared instruction and OS
subset; it is not general ELF recompilation or a remote feature.
The [Python SDK](sdk/python/README.md) wraps the same authenticated gRPC
subset. With its pinned dependencies installed, `bash scripts/demo-sdk.sh
/path/to/trusted-x86_64-elf-with-hydir_max2` exercises a separate Python
client against `hydird`, including explicit upload, analysis, event replay,
and digest-checked artifact export.

The `validate` command runs the original binary and lifted runner **without a
sandbox** and requires `--trusted-fixture`. Never use it on an untrusted sample.
There is no remote execution endpoint, and the current RPC service cannot
bind outside loopback.

For a local developer-only source snapshot of a clean committed tree, run
`bash scripts/package-source-snapshot.sh`. It verifies that the archive
contains the license, notices, lockfile, runtime, and protocol, and excludes
local design context and project data. This is not a release or AGPL remote
source offer; license/notice review and matching deployed-build verification
remain open.

## Exact supported lift contract

- Input: little-endian x86-64 ELF with a nonzero-size text function symbol.
  For a linked stripped ELF, `cfg-at`, `lift-at`, and `validate-at` instead
  require an analyst-supplied virtual entry (`0x...`) and exact size in bytes.
  This is not automatic stripped-code discovery.
- Analyst assertion via `--assume-u64x2`: the selected function has SysV AMD64
  prototype `u64(u64, u64)`. HydIR does not infer or verify that prototype.
- Accepted instructions: full-width scalar `mov`, non-RIP-relative `lea`,
  `add`/`sub`, `cmp`/`test`, `nop`, `ret`, direct `jmp`, and direct integer
  condition branches. Supported registers are RAX/RDI/RSI/RDX/RCX. Inputs
  begin in RDI/RSI; every returning path must define RAX. ZF/SF/OF/CF are
  modeled for accepted arithmetic and branch conditions.
- Reachable direct branches must stay inside the selected byte extent and
  land on non-overlapping instruction boundaries. Unknown instruction or
  state semantics, memory access, calls, indirect edges, partial registers,
  and uninitialized reads on any recovered path are rejected. Wrapping
  arithmetic emits plain LLVM integer operations without `nsw`/`nuw`.
- Import is broader than lift. `inspect` lists ELF symbol facts, while `cfg`
  performs an explicit symbol-scoped recovery. A liftable function is not a
  recompilable executable.
- `lift --output` creates a new artifact or accepts byte-identical content;
  it refuses to overwrite an existing binary or differing artifact.

See [capabilities](docs/CAPABILITIES.md), [evidence](docs/EVIDENCE.md),
