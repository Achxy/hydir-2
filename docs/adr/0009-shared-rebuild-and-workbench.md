# ADR 0009 — Shared rebuild operation and explicit workbench authorization

Status: accepted for the development slice, 2026-09-18.

The restricted whole-executable rebuilder now lives in `hydir-recompile`, so
the local CLI and service worker use the same LLVM generation, tool-version
check, linker invocation, and report. The server accepts only binary bytes,
an expected revision, an idempotency key, and an explicit trusted-fixture
assertion; it supplies fixed LLVM/Clang paths and creates a new project
revision with owner-scoped artifacts. It does not expose arbitrary commands,
flags, native plugins, or execution. A Linux process group is killed when a
worker times out or is cancelled, but the worker retains the service account's
host privileges. Therefore this is resource/process-tree isolation, not a
hostile-input sandbox or approval for public remote access.

The egui workbench uses the same first-party transform/rebuild libraries for
local operations and the typed RPC for remote operations.
Its trusted-fixture checkbox starts unchecked, and unsupported/disconnected
actions remain disabled with a reason. It verifies returned artifact digests,
media types, and revisions. Rebuilt ELF export creates a new file rather than
overwriting an existing one. Execution comparison remains an explicit,
client-side trusted-fixture demo step; no server or GUI execution occurs.

This decision deliberately leaves broad ELF coverage, arbitrary pass plugins,
remote execution, TLS/non-loopback transport, fine-grained roles, and hostile
worker sandboxing outside this slice. Those remain release blockers rather
than being inferred from the bounded demonstration.
