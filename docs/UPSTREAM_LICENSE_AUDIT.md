# IRENE-3 source and license boundary — 2026-09-18

This is an engineering inventory, not legal advice or a redistribution
clearance. A fresh read-only checkout of `trailofbits/irene3` resolved `main`
to `d97aee937ebb6d1cb8a362748c56414404eb75ff`, the same revision
recorded in `PROVENANCE.md`. Its checkout contains 405 tracked paths. No
IRENE-3 implementation, generated code, schema, or Ghidra plugin source is
copied into the current HydIR build. The only direct file match is the
verbatim root AGPLv3 license text: both SHA-256 values are
`8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef`.

File-level notices that must not be flattened into the root license if any
of these components is later adapted or bundled:

| Upstream path at `d97aee9` | Observed notice | Current HydIR use |
| --- | --- | --- |
| `LICENSE` | AGPLv3 | Verbatim license text only |
| `irene-ghidra/LICENSE` and 31 files with explicit Apache header | Apache-2.0 / Ghidra-origin headers | None; adapter absent |
| `irene-ghidra/src/main/antlr/C.g4` | Sam Harwell three-clause BSD notice | None |
| `irene-ghidra/src/main/scala/anvill/BiasedDisjointSet.scala` | Typelevel MIT notice | None |
| `include/irene3/Version.h`, `lib/Version.cpp.in`, `lib/CMakeLists.txt`, `cmake/git_watcher.cmake` | Andrew Hardin MIT-derived version-tracking notices | None |
| `utils/TargetTblGenBackend/Main.cpp` | Apache-2.0 WITH LLVM-exception | None |
| `gradlew`, `gradlew.bat` | Gradle Apache-2.0 headers | None |
| Root C++ files inspected in `bin/`, `include/`, `lib/` | Trail of Bits copyright and root-LICENSE references | None |

The table identifies exceptions found by scanning tracked source headers and
reading the named files; it is not a representation that all 405 paths or
submodule/vendor payloads have completed legal review. In particular,
upstream submodules were not fetched, the future native dependency set is
not locked to one LLVM version, and transitive crate/Python/native package
notices for a binary distribution remain open. Preserve each applicable
source header and modification notice if porting a component; do not infer
permission from a package-level license expression alone. A qualified legal
review remains required before distribution.

The architectural constraint is also current: [Rellic's own build guide](https://github.com/lifting-bits/rellic#dependencies)
specifies LLVM/Clang 16 and matching bitcode, while this tested HydIR worker
uses LLVM/Clang 14.0.6. No compatible Rellic boundary or upstream reference
lift has been built here. The existing scalar C11 output is first-party,
goto-based, and not a Rellic port.
