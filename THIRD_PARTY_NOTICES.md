# Third-party notices (development snapshot)

This first-party code uses the following direct crates at the exact versions
resolved in `Cargo.lock`. SPDX identifiers below are from Cargo package
metadata; package license files and transitive dependency notices must be
collected and reviewed before distributing binaries or a source archive.
`cargo metadata --locked` found 43 registry packages in the dependency graph,
all with a nonempty package-level license expression. Some include Unicode,
LLVM-exception, Zlib, or LGPL alternatives; these expressions are not a
substitute for reading and preserving their actual license files.

| Package | Locked version | Declared license | Role |
| --- | --- | --- | --- |
| `iced-x86` | 1.21.0 | MIT | Machine instruction decoding |
| `object` | 0.39.1 | Apache-2.0 OR MIT | ELF parsing |
| `serde` | 1.0.229 | MIT OR Apache-2.0 | Typed model serialization |
| `serde_json` | 1.0.151 | MIT OR Apache-2.0 | CLI JSON output |
| `sha2` | 0.10.9 | MIT OR Apache-2.0 | Binary content hashes |
| `tempfile` | 3.27.0 | MIT OR Apache-2.0 | Trusted fixture validation temp files |

IRENE-3, Anvill, Remill, Rellic, MLIR, and Ghidra are not linked, bundled, or
invoked by the current build. Their licensing and version compatibility remain
research inputs, not current binary dependencies. The AGPLv3 text in
`LICENSE` governs HydIR's first-party code. No release package or remote
corresponding-source offer has been prepared yet because no release or service
exists.
