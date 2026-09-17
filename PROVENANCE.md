# Provenance and port ledger

Audit snapshot: 2026-09-17. `trailofbits/irene3` `main` resolved to
`d97aee937ebb6d1cb8a362748c56414404eb75ff` (commit date 2026-02-13).
This records a revision, **not** a claim that the repository is unmaintained.
Its submodule pointers were inspected but not fetched or built.

| Component inspected | Upstream revision/source | HydIR destination | Status | Regression evidence |
| --- | --- | --- | --- | --- |
| C++ codegen and protobuf service | IRENE-3 `d97aee9`, `bin/Codegen` | none | Not ported or invoked | None |
| Patch language/parser and PatchIR | IRENE-3 `d97aee9`, `lib/PatchLang`, `lib/PatchIR` | none | Not ported | None |
| LLVM/Anvill/Remill transformation passes | IRENE-3 `d97aee9`, `lib/Transforms` | none | Not ported | None |
| Ghidra plugin and specifications | IRENE-3 `d97aee9`, `irene-ghidra`, `tests/specs` | none | Not ported | None |
| Existing patch tests and CI scripts | IRENE-3 `d97aee9`, `tests`, `scripts/test-ci.py` | none | Reviewed as reference only | None |
| Native ELF symbol and bounded-address reader | `object` 0.39.1 | `hydir-backend` | Newly implemented integration | Symbolized and stripped local demos |
| x86 decoder and direct CFG recovery | `iced-x86` 1.21.0 | `hydir-backend` | Newly implemented integration | Byte-pattern tests and CFG fixture exports |
| Scalar LLVM IR emission with explicit register/flag joins | No copied upstream code | `hydir-backend` | Newly implemented, narrow subset | LLVM verifier and five differential fixture variants |
| Versioned gRPC schema and client/server | `tonic`/`prost` 0.14.6/0.14.4 | `hydir-api`, `hydir-cli`, `hydir-server` | Newly implemented integration; local-only subset | Separate-process remote demo and protocol unit tests |
| Transactional project store | `rusqlite` 0.40.2 | `hydir-server` | Newly implemented subset | Restart, isolation, malformed-upload, rotation tests |
| Desktop workbench | `eframe`/`egui` 0.36.2 | `hydir-gui` | Newly implemented local and explicit remote inspection subset | macOS compile/unit smoke; Linux unit build, visual QA pending |

IRENE-3 C++ code, generated sources, schemas, and tests are not vendored or
translated here. Its root is AGPLv3; its `irene-ghidra/LICENSE` is Apache-2.0,
and some Scala files carry additional per-file notices. If any upstream
component is later ported, retain its file-level notices, mark modifications,
and obtain a legal review of the combined distribution. The root AGPL text in
this repository is verbatim from the standard license text in IRENE-3; it is
license text, not an implementation port.

The currently selected application toolchain is Rust 1.96.0 and
`Cargo.lock`'s exact crate versions. LLVM/Clang 22.1.8 was used to verify the
first emitted module on macOS. No single compatible pinned set for Remill,
Anvill, Rellic, MLIR, and Ghidra has yet been selected or tested; the M0
native-dependency gate remains open.
