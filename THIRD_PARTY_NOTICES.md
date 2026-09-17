# Third-party notices (development snapshot)

This first-party code uses the following direct crates at the exact versions
resolved in `Cargo.lock`. SPDX identifiers below are from Cargo package
metadata; package license files and transitive dependency notices must be
collected and reviewed before distributing binaries or a source archive.
`cargo metadata --locked` found 388 registry packages in the dependency graph,
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
| `tonic`, `tonic-prost`, `tonic-prost-build` | 0.14.6 | MIT | Typed gRPC client, server, and code generation |
| `prost` | 0.14.4 | Apache-2.0 | Protocol message encoding |
| `protoc-bin-vendored` | 3.2.0 | MIT | Reproducible protocol compiler |
| `tokio` | 1.53.1 | MIT | Asynchronous RPC runtime |
| `libc` | 0.2.189 | MIT OR Apache-2.0 | Linux child-worker resource limits |
| `rusqlite` | 0.40.2 | MIT | Persistent SQLite project and artifact store |
| `uuid` | 1.26.1 | Apache-2.0 OR MIT | Project IDs and generated local credentials |
| `eframe`, `egui` | 0.36.2 | MIT OR Apache-2.0 | Native desktop workbench |

IRENE-3, Anvill, Remill, Rellic, MLIR, and Ghidra are not linked, bundled, or
invoked by the current build. Their licensing and version compatibility remain
research inputs, not current binary dependencies. The AGPLv3 text in
`LICENSE` governs HydIR's first-party code. No release package or remote
public corresponding-source offer has been made. A clean-revision archive can
be embedded and hash-served by a development service; its third-party notice
sufficiency has not been reviewed. The current service is a
development-only authenticated loopback slice; it is not release-ready.
The [IRENE-3 source/license inventory](docs/UPSTREAM_LICENSE_AUDIT.md)
records file-level Apache, BSD, MIT, and LLVM-exception variants in the
upstream checkout; none of those implementation files is bundled here.

The C11 emitter and restricted C-like patch parser/encoder in this checkout
are first-party code. They were not copied or translated from IRENE-3,
Rellic, or the separate older HydIR checkout. Their upstream-inspired scope
is recorded in `PROVENANCE.md` and the patching contract.

The development Python SDK uses `grpcio` 1.84.0 (Apache-2.0), `protobuf`
7.36.1 (BSD-3-Clause), and `typing-extensions` 4.16.0 (PSF-2.0), with
`grpcio-tools` 1.84.0 (Apache-2.0) and `setuptools` 84.0.0 (MIT) used for
generation/build. This is a package-metadata inventory, not a complete
redistribution notice audit. No SDK wheel has been published.
`Dockerfile.sdk` installs Debian Python 3.11 packages and the pinned Python
runtime packages into a separate development test image. Redistributing that
image would require its own package-level license/notice audit.

The trusted local pass experiment invokes Debian LLVM `opt` 14.0.6 from the
development image. LLVM is a separate native tool, not statically linked into
these Rust binaries. Its license and runtime redistribution obligations must
be included if a future package bundles it.
The restricted local and authenticated-loopback rebuild paths also invoke Clang and LLVM `opt` 14.0.6,
and links a first-party C guest-memory/syscall runtime into generated ELF
artifacts. No LLVM library is statically linked into `hydirctl`; generated
artifacts and toolchain redistribution still need a distribution notice audit.
The development Docker image additionally installs Debian Git
`1:2.39.5-0+deb12u3` for clean-revision source-archive verification. This
tool is not embedded in the HydIR executables; distributing the development
image would require its own package/license review.
