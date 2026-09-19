# IRENE-3 comparison experiment

Status: protocol prepared; no IRENE-3 build, Ghidra export, or patch run has
been completed on this Windows host. Results must remain empty until measured
on an isolated Linux x86-64 installation.

## Pinned comparison input

- IRENE-3 source: `trailofbits/irene3` commit
  `d97aee937ebb6d1cb8a362748c56414404eb75ff`; repository license:
  AGPL-3.0. Keep its build and dependencies outside the HydIR source tree.
- HydIR source: record `git rev-parse HEAD` and the worktree diff hash when
  running; this implementation is currently an uncommitted worktree.
- Use the same symbolized, linked Linux x86-64 ELF for both tools. Start with
  `tests/fixtures/max2.S`, `tests/fixtures/add2.S`, and
  `tests/fixtures/scalar_corpus.S` linked with `scalar_main.c` using
  `-DHYDIR_FUNCTION=hydir_max2`; record the compiler, version, flags, binary
  SHA-256, symbol entry, and bytes. Record any IRENE-3 refusal as a refusal,
  rather than changing the input silently.

## Procedure on Linux

Build the shared fixture in a scratch directory:

```sh
clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_max2 \
  tests/fixtures/max2.S tests/fixtures/add2.S \
  tests/fixtures/scalar_corpus.S tests/fixtures/scalar_main.c \
  -o target/irene3-comparison.elf
sha256sum target/irene3-comparison.elf
```

1. Build the fixture and save `hydirctl region`, `hydirctl lift`, and
   `hydirctl decompile` artifacts for each named function. Run the native
   semantic gate on the same machine.
2. In a separate checkout at the pinned IRENE-3 commit, follow its `justfile`
   to install prerequisites, build IRENE-3, and run the Ghidra plugin and C++
   tests. Record the exact Ghidra fork and LLVM versions obtained by that
   checkout. Its current `justfile` specifies LLVM 17 and a Ghidra 10.3
   development fork; these are not HydIR's LLVM toolchain.
3. Export a Ghidra specification with `just generate-spec <binary> <spec>`,
   then run `just decompile-spec <spec> <out.c>` and
   `just decompile-spec-ll <spec> <out.ll>`. Preserve the specification, tool
   logs, and output hashes. The README's `decompile-binary` example is absent
   from the pinned `justfile`; use its defined recipes.
4. In Ghidra, follow IRENE-3's documented region selection and patch UI for
   one entry/one exit block. Preserve the exported patch C and JSON, exact
   selected bytes, entry/exit machine locations, and resulting ELF. Execute
   original and patched fixtures on a directed input set, documenting the
   intended changed inputs and unchanged outputs.
5. Compare region boundaries, assumptions, stack state, C/LLVM output, patch
   placement, refusals, and observed behavior. Label Ghidra and IRENE-3 facts
   as external evidence; do not promote them to HydIR's native proof.

## Evidence table to fill after execution

| Fixture | HydIR region/hash | IRENE-3 spec/region | Entry/exit assumptions | Lift/lower outcome | Patch outcome | Behavior cases |
| --- | --- | --- | --- | --- | --- | --- |
| `hydir_max2` | pending | pending | pending | pending | pending | pending |
| `hydir_add2` | pending | pending | pending | pending | pending | pending |
| `hydir_frame_balance` | pending | pending | pending | pending | pending | pending |
| `hydir_stack_branch` | pending | pending | pending | pending | pending | pending |

Sources: [IRENE-3 repository and license](https://github.com/trailofbits/irene3),
[pinned build recipes](https://github.com/trailofbits/irene3/blob/d97aee937ebb6d1cb8a362748c56414404eb75ff/justfile),
[usage instructions](https://github.com/trailofbits/irene3/blob/d97aee937ebb6d1cb8a362748c56414404eb75ff/USAGE.md).
