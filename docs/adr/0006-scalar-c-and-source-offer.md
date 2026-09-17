# ADR 0006 — Bounded scalar C emission and matching source archive

Status: implemented development subset, 2026-09-17.

`hydir-c` consumes only the raw direct-CFG LLVM grammar produced by the
first-party scalar lifter. It rejects unknown operations, malformed edges,
undefined SSA names, and mismatched phi predecessor sets. It emits C11 with
explicit labels/gotos and parallel edge copies for phis. Integer arithmetic
is unsigned and modular; signed comparisons use a sign-bit transform. The
output is real, compilable C derived from lifted machine bytes, but not
high-level structured C, Rellic parity, or general LLVM-to-C support.
Failure in C emission leaves the CFG and LLVM lift available.

The same operation is available through local CLI, the authenticated
owner-scoped `Decompile` RPC, Python SDK, and local/remote GUI views. The
service runs conversion inside its bounded child worker and stores the C
artifact under the project revision. Validation executes trusted fixtures
only; the server exposes no execution endpoint.

For development builds, `hydird` embeds no source archive by default.
An explicit build with `HYDIR_SOURCE_REVISION` and
`HYDIR_SOURCE_ARCHIVE` is accepted only when the checkout is clean, the
revision equals `HEAD`, and a bounded tar has the matching root. The
archive bytes are embedded in the binary; `Discover` advertises their
revision and SHA-256, and authenticated `GetSource` returns exactly those
bytes. The CLI and SDK hash-check the transfer. This creates a testable
matching-source delivery mechanism, not a completed redistribution-license
review or permission to deploy a public service.
