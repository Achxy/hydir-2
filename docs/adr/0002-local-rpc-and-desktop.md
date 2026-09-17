# ADR 0002: authenticated loopback RPC and explicit desktop connection

Status: accepted as a partial M2 implementation, 2026-09-17.

HydIR now exposes the narrow M1 native operations through a versioned tonic
gRPC service. SQLite records identities, owner-scoped projects, immutable
binary revisions, and content-addressed IR artifacts. The CLI is the only
current upload path. The egui workbench may open a local ELF or explicitly
connect to an existing remote project, with a conspicuous mode indicator; it
never silently transfers a local binary.

The service deliberately refuses non-loopback binding and offers no execution
endpoint. Parsing and lifting use child processes with an output cap and
deadline, but these workers are not sandboxed and have the service user's
privileges. These restrictions preserve a useful multi-client development slice
without representing it as a hostile-sample sandbox or public deployment.
Remote mutation/execution roles, durable jobs, cancellation, OS quotas, audit
events, TLS, and corresponding-source delivery are prerequisites for a public
service. SQLite files and credentials are owner-private on Unix.

The GUI performs parsing, lifting, and RPC on a background thread over bounded
channels. Its dense dark-first layout keeps source, provenance, and unsupported
states visible, but is not a completed decompiler interface: passes, C output,
global analysis, patching, and executable rebuilding do not yet exist.
