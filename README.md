# HydIR

HydIR is an early, independently implemented binary-lifting workbench. This
checkout contains a tested **M1 native vertical slice**, a **partial M2
desktop and local-authenticated RPC slice**, bounded scalar C emission, and a narrowly tested
whole-executable recompilation subset. It is not the complete remote/decompilation/
recompilation product described in the project plan. It imports little-endian
x86-64 ELF without Ghidra, lifts a deliberately small class of functions from
machine bytes to LLVM IR, differentially executes trusted fixtures on Linux
x86-64, and exposes import/CFG/lift artifacts through a persistent local-only
service.

The `hydir` egui desktop workbench opens local ELF files and can create or
open authenticated loopback projects. It shows function facts,
reachable disassembly/CFG, LLVM IR, scalar C, assumptions, and diagnostics in resizable
panes. Opening a local binary never uploads it; sending a binary requires the
separate, labelled remote-upload action and creates a new immutable revision.
Saved layouts and high-level structured C recovery are not yet implemented. It can start, monitor,
cancel, and retrieve a remote lift job and display a conservative global-effect
analysis. The workbench also has local/remote named-pass editing with verified
before/after IR and separately authorized local/remote rebuild flows for trusted
fixtures. Local pass and rebuild actions require pinned Linux LLVM/Clang tools
and new output directories; remote rebuild exports only to a new file. A
separate scalar patch v1 editor supports explicit local/remote whole-function
replacement with entry-only and trusted-fixture assertions.
The analysis is not complete whole-program
recovery.

## Build and inspect

Rust 1.96.0 is pinned in `rust-toolchain.toml`; `Cargo.lock` pins crates.
The demo additionally needs Clang with x86-64 ELF and LLVM IR support. Native
execution validation requires Linux x86-64.

```sh
cargo test --locked --workspace
cargo run --locked --bin hydir
cargo run --locked --bin hydir -- --open-local /path/to/program.elf function_name
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydirctl -- inspect /path/to/program.elf
cargo run --locked --bin hydirctl -- analyze /path/to/linked-program.elf
cargo run --locked --bin hydirctl -- analyze-spec /path/to/linked-program.elf
cargo run --locked --bin hydirctl -- cfg /path/to/program.elf function_name
cargo run --locked --bin hydirctl -- lift /path/to/program.elf function_name --assume-u64x2 --output lifted.ll
cargo run --locked --bin hydirctl -- decompile /path/to/program.elf function_name --assume-u64x2 --output lifted.c
cargo run --locked --bin hydirctl -- patch /path/to/trusted.elf /path/to/patch-v1.json --trusted-fixture --assume-u64x2 --assume-entry-only --output /path/to/new.elf
cargo run --locked --bin hydirctl -- transform /path/to/program.elf function_name --assume-u64x2 --trusted-fixture --passes instcombine,sccp,simplifycfg,dce --output-dir /path/to/new-experiment --opt opt
cargo run --locked --bin hydirctl -- rebuild /path/to/trusted-static-program.elf --trusted-fixture --output-dir /path/to/new-rebuild
```

On a Linux x86-64 host with Clang, `bash scripts/demo-local.sh` builds four
trusted assembly functions, imports them, exports per-function CFG JSON,
lifts them, emits C, verifies the IR if `opt` is installed, and compares 1,008
executions per function (eight boundary cases and 1,000 seeded cases). It
also strips one fixture and repeats CFG, lift, C, IR verification, and 1,008
comparisons using an explicitly supplied entry and byte extent. Artifacts
are written to a fresh `target/demo-local/run.*` directory.
`bash scripts/demo-corpus.sh` separately checks 16 more distinct scalar
functions (identity, wrapping arithmetic, signed/unsigned comparison,
bit test, bounded loops): each is lifted, converted to C, LLVM-verified, and compared with
native execution on 1,008 inputs for both LLVM and compiled C. Together with the four distinct functions
in `demo-local.sh`, this makes 20 distinct supported scalar functions. It
does not cover optimized compiler output, stack/buffer access, or high-level C structuring.

On macOS with Docker Desktop, `bash scripts/demo-linux-docker.sh` builds the
pinned Linux x86-64 development image and runs the tests plus demo there.
On Linux x86-64, `bash scripts/demo-remote.sh` runs the separate-process,
authenticated service/client fixture, including durable lift jobs, event
replay, restart, cancellation, GUI create/upload logic, and cross-project
denial checks. See
[remote operation and threat model](docs/REMOTE.md).
`bash scripts/demo-analysis.sh` checks direct-call propagation of a mapped
global write, conservative treatment of an indirect call, and a partial
`ProgramSpec` with provenance-bearing call/reference instruction sites.
`bash scripts/demo-passes.sh` saves raw, canonical before, and after LLVM IR;
it verifies the named pipeline with pinned LLVM `opt` 14.0.6 and compares a
transformed trusted fixture on eight boundary inputs. An IR change and a
verifier pass are not, by themselves, a behavioral proof.
`hydirctl remote transform` runs the same allowlisted LLVM 14 pipeline in a
limited service worker and returns owner-scoped, hash-addressed IR snapshots
in a new immutable project revision that retains the same ELF bytes. It has
no arbitrary plugin path.
`bash scripts/demo-recompile.sh` lifts the complete decoded `.text` of three
trusted, static freestanding ELFs to stateful LLVM IR, links a bounded guest
memory/syscall bridge into new executables, verifies IR, and compares five
controlled executions (stdout, stderr, exit status). It includes direct
calls, branches, a loop, shared globals, `.bss`, and input-dependent output.
The same bounded rebuild is available through the authenticated loopback RPC,
CLI, Python SDK, and egui workbench. It rejects code outside its declared
instruction and OS subset; this is not general ELF recompilation or a
hostile-input sandbox. No server-side binary execution is exposed.
`bash scripts/demo-patch.sh` checks the separate scalar whole-function
in-place patch subset: it produces a new ELF, validates four intentional
behavior cases, and rejects size/hash/overwrite errors. The authenticated
remote demo also applies that patch as an immutable project revision and
checks idempotent replay after restart. See [patching contract](docs/PATCHING.md).
The [Python SDK](sdk/python/README.md) wraps the same authenticated gRPC
subset. With its pinned dependencies installed, `bash scripts/demo-sdk.sh
/path/to/trusted-x86_64-elf-with-hydir_max2 /path/to/trusted-freestanding-elf` exercises a separate Python
client against `hydird`, including explicit upload, analysis, event replay,
digest-checked artifact export, and whole-executable rebuilding. On macOS with
Docker Desktop, `bash scripts/demo-sdk-linux-docker.sh` builds the pinned
Python/Clang test environment and runs that integration with repository
fixtures. `sdk/python/examples/validate_program.py` separately compares
trusted original/rebuilt ELFs in no-network, read-only, resource-controlled
Docker runs and saves a per-case report; Docker is not a hostile-binary
sandbox or an equivalence proof.

The `validate` command runs the original binary and lifted runner **without a
sandbox** and requires `--trusted-fixture`. Never use it on an untrusted sample.
There is no remote execution endpoint, and the current RPC service cannot
bind outside loopback.

For a local developer source snapshot of a clean committed tree, run
`bash scripts/package-source-snapshot.sh`. It verifies that the archive
contains the license, notices, lockfile, runtime, and protocol, and excludes
local design context and project data. `bash scripts/demo-source-offer.sh`
builds an opt-in `hydird` with that matching archive embedded, then checks
discovery and hash-checked RPC retrieval. This is a technical source-delivery
gate, not a release or completed redistribution-license review.

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
[measured development evaluation](docs/EVALUATION.md),
[release gates](docs/RELEASE_GATES.md),
