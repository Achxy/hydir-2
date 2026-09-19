# HydIR fuzz targets

The targets exercise ELF import and disassembly, scalar CFG lifting, and the
restricted LLVM-to-C parser. They are crash and refusal checks, not semantic
proof. [`corpus/elf_import/MANIFEST.json`](corpus/elf_import/MANIFEST.json)
records every checked-in ELF's source, entry, exact length, SHA-256, and pinned
Clang/LLD 22.1.8 revision. `corpus/elf_import/max2.elf` was built from
`tests/fixtures/max2.S`; `corpus/cfg_lift/max2` contains the function's 12 bytes.
`corpus/cfg_lift/mov32` exercises a 32-bit register write and return.
`corpus/elf_import/frame.elf` comes from `tests/fixtures/scalar_corpus.S` and
seeds a balanced frame contract case.
`corpus/elf_import/stack.elf` and `corpus/cfg_lift/stack_branch` exercise
bounded stack-local CFG joins and frame analysis.
`corpus/elf_import/interior_entry.elf` and `interior_call.elf` exercise
interior-entry evidence and patch refusal. They come from the matching
`tests/fixtures/interior_*.S` sources, built with Clang and LLD 22.1.8:

```sh
clang --target=x86_64-unknown-linux-gnu -nostdlib -fuse-ld=lld -no-pie \
  -Wl,--build-id=none -Wl,-e,_start tests/fixtures/interior_entry.S \
  -o fuzz/corpus/elf_import/interior_entry.elf
clang --target=x86_64-unknown-linux-gnu -nostdlib -fuse-ld=lld -no-pie \
  -Wl,--build-id=none -Wl,-e,_start tests/fixtures/interior_call.S \
  -o fuzz/corpus/elf_import/interior_call.elf
```

On a Linux development host with `cargo-fuzz` installed:

```sh
cargo fuzz run elf_import
cargo fuzz run cfg_lift
cargo fuzz run c_output
```

`.github/workflows/fuzz.yml` replays the checked-in seeds and runs each target
for a bounded 30 seconds on native Linux. It uploads crash artifacts on
failure. This CI job has not run in the current Windows worktree. On this
Windows host `cargo check --manifest-path fuzz/Cargo.toml --bins` passes;
plain `cargo build` cannot link a libFuzzer entry point without cargo-fuzz.

Keep minimized crashes under the matching `corpus/` directory as regression
seeds, with a description of the failure and the toolchain revision.
