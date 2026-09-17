# HydIR

HydIR is an early, independently implemented binary-lifting workbench. This
checkout currently contains an **M1 native vertical slice**, not the complete
desktop/remote/decompilation/recompilation product described in the project
plan. It imports little-endian x86-64 ELF without Ghidra, lifts a deliberately
small class of symbol-bounded functions from machine bytes to LLVM IR, and can
differentially execute a trusted fixture on Linux x86-64.

## Build and inspect

Rust 1.96.0 is pinned in `rust-toolchain.toml`; `Cargo.lock` pins crates.
The demo additionally needs Clang with x86-64 ELF and LLVM IR support. Native
execution validation requires Linux x86-64.

```sh
cargo test --locked --workspace
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydirctl -- inspect /path/to/program.elf
cargo run --locked --bin hydirctl -- cfg /path/to/program.elf function_name
cargo run --locked --bin hydirctl -- lift /path/to/program.elf function_name --assume-u64x2 --output lifted.ll
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

The `validate` command runs the original binary and lifted runner **without a
sandbox** and requires `--trusted-fixture`. Never use it on an untrusted sample.
There is no remote execution endpoint.

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
