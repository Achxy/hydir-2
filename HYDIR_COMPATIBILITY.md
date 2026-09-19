# HydIR compatibility experiment

Status: HydIR-side artifacts are now measured; no external reference build,
Ghidra export, or reference patch run has been completed on this Windows host.
External result cells remain pending until measured on an isolated Linux
x86-64 installation.

## HydIR implementation checkpoint — 2026-09-19

- The rewritten upstream history was preserved and the working implementation
  was recovered through rescue branch
  `rescue/hydir-pre-integration-20260919` onto
  `feature/hydir-native-interchange`.
- `third_party/hydir-reference` records the exact external commit as a
  test-only Git submodule. Its nested dependencies are not initialized by the
  HydIR build and it is not a runtime dependency.
- All five checked-in ELF seeds were regenerated with pinned Clang/LLD 22.1.8.
  Their sources, entry points, lengths, hashes, and common command arguments are
  recorded in `fuzz/corpus/elf_import/MANIFEST.json` and enforced by a Rust test.
- Canonical native artifacts now exist as `ProgramSpec` v4, `RegionSpec` v3,
  `DecompilationUnit` v1, and `PatchBundle` v2. Program readers accept v2/v3;
  region readers accept v2. Decompilation units retain validated many-to-one
  machine-address/C-statement provenance. Missing CIR, complete physical
  liveness, stack alignment, and behavior evidence are explicit blockers.
- Preserved `hydir.v1` and additive `hydir.v2` services run together. v2 covers
  region/decompilation artifacts, patch compilation/application, and structural
  verification. Python clients negotiate v2 with v1 fallback.
- HydIR-owned `hydir.interchange.server.HydirInterchange` and
  `hydir.patch.server.HydirPatchService` protobuf schemas are now compiled
  into the Rust API. The local server mounts both HydIR service names,
  accepts the 2,000,000-byte streaming convention, bounds the total
  specification to 64 MiB, and refuses non-empty semantic output until region
  live-state and adapter proofs exist.
- The public pinned x86-64 Fibonacci interchange fixture parses and validates
  natively: source SHA-256 `acb261fcea612eb5951cecc0b5a16f76fe78af57e2e55895b8756effa4ffbd89`,
  21,168 bytes, 7 functions, 23 blocks, 27 memory ranges, 5 globals, and 71
  symbols. All 23 block extents resolve to one exact executable memory range.
  Its target is `ARCH_AMD64` / `OS_LINUX`. Original wire bytes are retained
  losslessly; the decoded pinned-schema view has deterministic canonical
  re-encoding.
- Binding that fixture to its matching 16,184-byte upstream ELF succeeds for
  all 23 regions and emits validated `RegionSpec` v3 artifacts with rebased ELF
  addresses, exact bytes/digests, CFG exits, imported physical live state,
  variable locations, and stack relations. UID 26 binds to `0x11a9`, 11 bytes,
  region SHA-256 `f3d11c178e965e08a1bec6d110d7e93714fbf3c8b62c376d1fa52d52d1fc17aa`,
  successor `0x11b4`, and RSP delta -8. Imported evidence is explicitly marked
  `interchange_import`; native proof gaps keep every imported region
  `replacement_ready=false`.
- The native compatibility report currently binds 23/23 regions and recovers
  exact declared-exit CFGs for 23/23. Direct-call edges remain typed separately
  from continuation exits. Block 47's missing fallthrough is justified only by
  its address-specific imported HydIR `stop` contract; `noreturn` and `stop`
  remain distinct facts. Its imported target `0x3` conflicts with the natively
  decoded `0x1090` and is retained as an unresolved cross-check, not silently
  trusted. Typed RegionDecisionIR now lifts and emits deterministic C for 1/23
  isolated regions: UID 35's two-exit `JG` consumes its imported ZF/SF/OF
  inputs, returns the exact continuation address, and carries all seven live
  outputs through explicit input/output bindings. LLVM 22 verification, Clang
  C compilation, and all eight boolean flag combinations pass. The remaining
  22 regions still fail closed. Mapped/TLS memory and RBX saves are typed
  MachineIR but remain semantic blockers alongside general entry/exit adapters,
  mid-function frame state, memory contracts, and resolved-call contracts.
  This result is deliberately separate from whole-function lifting: the pinned
  92-byte `fibIterative` function now lifts completely with typed dword red-zone
  locals, 32-bit arithmetic/comparisons and flags. LLVM `opt -passes=verify`
  accepts the output, generated C compiles with Clang 22.1.8, and 63 cases
  (`n=-16..46`, with nonzero high input bits) match an independent Fibonacci
  oracle. CET `ENDBR64` and RBX/R10-R15 register effects are also modeled,
  including corrected data-flow accounting for all six SysV integer arguments.
- Rust workspace tests, fuzz-target compilation, warnings-as-errors Clippy,
  protocol tests, and Python SDK boundary tests pass locally. The Triton oracle,
  native Linux semantic/differential gates, Ghidra workflow, and external reference
  suite remain unmeasured here.

## Pinned comparison input

- External reference source commit:
  `d97aee937ebb6d1cb8a362748c56414404eb75ff`; repository license:
  AGPL-3.0. Build the test-only submodule and its dependencies in a separate
  reference environment; they are not part of the HydIR runtime.
- HydIR source: record `git rev-parse HEAD` and require a clean worktree when
  running. Results from a modified tree must carry a diff hash and cannot be
  promoted to release evidence.
- Use the same symbolized, linked Linux x86-64 ELF for both tools. Start with
  `tests/fixtures/max2.S`, `tests/fixtures/add2.S`, and
  `tests/fixtures/scalar_corpus.S` linked with `scalar_main.c` using
  `-DHYDIR_FUNCTION=hydir_max2`; record the compiler, version, flags, binary
  SHA-256, symbol entry, and bytes. Record any external refusal as a refusal,
  rather than changing the input silently.

## Procedure on Linux

Build the shared fixture in a scratch directory:

```sh
clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_max2 \
  tests/fixtures/max2.S tests/fixtures/add2.S \
  tests/fixtures/scalar_corpus.S tests/fixtures/scalar_main.c \
  -o target/hydir-comparison.elf
sha256sum target/hydir-comparison.elf
```

1. Build the fixture and save `hydirctl region`, `hydirctl lift`, and
   `hydirctl decompile` artifacts for each named function. Run the native
   semantic gate on the same machine.
2. In a separate checkout at the pinned external commit, follow its `justfile`
   to install prerequisites, build the reference, and run the Ghidra plugin and C++
   tests. Record the exact Ghidra fork and LLVM versions obtained by that
   checkout. Its current `justfile` specifies LLVM 17 and a Ghidra 10.3
   development fork; these are not HydIR's LLVM toolchain.
3. Export a Ghidra specification with `just generate-spec <binary> <spec>`,
   then run `just decompile-spec <spec> <out.c>` and
   `just decompile-spec-ll <spec> <out.ll>`. Preserve the specification, tool
   logs, and output hashes. The README's `decompile-binary` example is absent
   from the pinned `justfile`; use its defined recipes.
4. In Ghidra, follow the reference's documented region selection and patch UI for
   one entry/one exit block. Preserve the exported patch C and JSON, exact
   selected bytes, entry/exit machine locations, and resulting ELF. Execute
   original and patched fixtures on a directed input set, documenting the
   intended changed inputs and unchanged outputs.
5. Compare region boundaries, assumptions, stack state, C/LLVM output, patch
   placement, refusals, and observed behavior. Label Ghidra and reference facts
   as external evidence; do not promote them to HydIR's native proof.

## Evidence table to fill after execution

| Fixture | HydIR region/hash | External spec/region | Entry/exit assumptions | Lift/lower outcome | Patch outcome | Behavior cases |
| --- | --- | --- | --- | --- | --- | --- |
| `hydir_max2` | v3; ELF `48b09f9d…`; region `5190c43d…`; 12 bytes at `0x201174` | pending | 1 return, RSP +8; live state/alignment unresolved | native LLVM and deterministic C succeed; DecompilationUnit maps 1 structured C statement to 5 machine addresses and retains 2 blocking diagnostics | scalar v1→bundle v2 succeeds structurally; stable=false | local patch unit/re-import only; Linux behavior pending |
| `hydir_add2` | v3; scratch ELF `42e88968…`; region `d9cf89c5…`; 5 bytes at `0x201174` | pending | 1 return, RSP +8; live state/alignment unresolved | native LLVM/C measured locally | pending | pending |
| `hydir_frame_balance` | v3; ELF `86e289c9…`; region `604c9f73…`; 18 bytes at `0x2011d2` | pending | 1 return, RSP +8; live state/alignment unresolved | CFG/stack analysis succeeds locally | pending | pending |
| `hydir_stack_branch` | v3; ELF `5e2f4266…`; region `2bfd6347…`; 28 bytes at `0x2011f9` | pending | 1 return, RSP +8; stack local proven elsewhere; live state/alignment unresolved | CFG/stack-local lift tests pass locally | pending | pending |

The external source URL is recorded in `.gitmodules`; build recipes, usage
instructions, and licensing are preserved inside the pinned test-only submodule.
