# ADR 0012: revisioned analyst facts for remote projects

Status: accepted for the development checkpoint, 2026-09-18.

The v2 ELF inventory and bounded analysis overlay must not present analyst
claims as independently recovered binary facts. `hydird` therefore persists
name, comment, and assumption records in an owner-scoped SQLite ledger. An
accepted write requires a current project revision and an idempotency key;
it creates a new immutable revision pointing to the same binary digest.
Exact retries return the original revision, while a changed request with the
same key is rejected. Records retain their creation revision, binary SHA-256,
optional virtual address, scope, and `analyst_assertion` provenance. Names
require an address; addressed facts must lie in a linked ELF load mapping.
Values, scopes, keys, and count are bounded. Schema migration 6 preserves
prior projects and restart recovery.

`ListAnnotations` returns the current binary's ledger. Remote `Inspect` and
`AnalyzeSpec` additionally overlay only assumption records into
`ProgramSpec.assumptions`; addressed assumptions retain their virtual
address. Name and comment records stay in the separate ledger and do not
silently rename recovered symbols or alter machine semantics. Identical
binary bytes reuploaded to the same project reuse the digest-scoped ledger;
a different binary digest does not receive those records. Binary-specific
annotations are not a proof of prototype, reachability, or behavior.

The CLI, Python SDK, and remote egui Inspector expose these operations.
ADR 0013 adds a separate private local-project database, superseding the
local-persistence gap at the time of this decision. Analysis summaries and
lifts do not yet use these
assumptions as semantic inputs or cache keys; any operation that needs an
asserted prototype still requires its explicit assertion flag. The feature
does not close full local/remote parity or project-model completeness.
