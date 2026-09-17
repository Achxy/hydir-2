# ADR 0008 — Revisioned remote named LLVM transformation

Status: implemented development subset, 2026-09-18.

The local named-pass experiment is shared through `hydir-transform` so the
authenticated service can run exactly the same allowlist with fixed LLVM
`opt` 14.0.6. The service accepts only 1–4 unique names from
`instcombine,sccp,simplifycfg,dce`; it accepts no plugin path or arbitrary
LLVM pipeline syntax. The child worker receives ELF bytes, not a server path,
and returns bounded raw/before/after IR plus a JSON report. These are LLVM
verification artifacts, not a behavioral-equivalence proof.

Although the executable bytes are unchanged, a pass experiment is a project
transformation. It therefore creates a new immutable project revision with
the same binary hash and four owner-scoped artifacts. A transaction commits
the revision, artifacts, and idempotency record together. An exact retry
returns the original result even after restart; a different request with the
same key fails. The request is revision-checked again after the worker runs,
so a concurrent mutation cannot attach results to the wrong revision.

This is not a general remote compiler service. There is no uploaded pass
plugin, arbitrary shell execution, hostile-input sandbox, or remote sample
execution. Child-process and resource limits remain a development isolation
measure, not a public-service security boundary.
