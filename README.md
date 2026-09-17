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
cargo run --locked --bin hydirctl -- lift /path/to/program.elf function_name --assume-u64x2 --output lifted.ll
```

On a Linux x86-64 host with Clang, `bash scripts/demo-local.sh` builds the
trusted assembly fixture, imports it, lifts it, verifies the IR if `opt` is
installed, and compares 1,008 executions (eight boundary cases and 1,000
seeded cases). It creates a fresh `target/demo-local/run.*` directory with
`program-spec.json`, `add2-lifted.ll`, and `differential-report.json`.

On macOS with Docker Desktop, `bash scripts/demo-linux-docker.sh` builds the
pinned Linux x86-64 development image and runs the tests plus demo there.

The `validate` command runs the original binary and lifted runner **without a
sandbox** and requires `--trusted-fixture`. Never use it on an untrusted sample.
There is no remote execution endpoint.

## Exact supported lift contract

- Input: little-endian x86-64 ELF with a nonzero-size text function symbol.
- Analyst assertion via `--assume-u64x2`: the selected function has SysV AMD64
  prototype `u64(u64, u64)`. HydIR does not infer or verify that prototype.
- Accepted instructions: full-width register `mov`, `lea` (non-RIP-relative),
  register `add`/`sub`, `nop`, and one final `ret`. Inputs begin in RDI/RSI;
  the return value must be defined in RAX.
- The function may not access memory, call, branch, use a partial register,
  depend on flags, or depend on an uninitialized register. All such cases are
  rejected. Wrapping arithmetic emits plain LLVM integer operations without
  `nsw` or `nuw` assumptions.
- Import is broader than lift. Symbol inventory is not CFG recovery, and a
  liftable function is not a recompilable executable.
- `lift --output` creates a new artifact or accepts byte-identical content;
  it refuses to overwrite an existing binary or differing artifact.

See [capabilities](docs/CAPABILITIES.md), [evidence](docs/EVIDENCE.md),
