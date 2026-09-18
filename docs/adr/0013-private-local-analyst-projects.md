# ADR 0013: private path-bound local analyst projects

Status: accepted for the development checkpoint, 2026-09-18.

Opening a local ELF now attaches it to a SQLite project keyed by its canonical
file path. The store keeps a stable project ID, monotonically increasing
revision, current binary SHA-256, prior revision digests, bounded analyst
facts, and idempotency requests. It does not copy the ELF into the database
or upload it. The default database lives in HydIR's per-user data directory;
`HYDIR_LOCAL_DB` selects an absolute path for both the CLI and GUI. New Unix
files are owner-private and an existing database with group/other access or
an unsupported schema version is rejected. Schema v1 was the first local
schema; v2 adds saved workbench settings with a transactional migration.
Future schema changes still require explicit migrations.

Names, comments, and assumptions use the shared local/remote validation
functions. Writes require a current revision and an idempotency key, produce
a new revision transactionally, and reject a changed request under the same
key. Facts are scoped to the binary digest and carry explicit analyst-
assertion provenance. A changed file at the same path advances the revision
and does not receive facts for another digest. The GUI does disk/database work
on its worker thread and keeps a visible `LOCAL · NO UPLOAD` state. Local
`inspect`/`analyze-spec` overlay only assumptions; names/comments remain in
the ledger and cannot silently alter recovered machine semantics.

This is an on-device analyst ledger, not local/remote replication or a full
project content-addressed artifact store. Existing binary transforms still
have their own output/revision contracts. Assumptions do not yet parameterize
lift/cache semantics; explicit prototype/trust assertions remain mandatory.
SQLite mode restrictions are not a hostile-input sandbox, and no automatic
project migration or synced layout persistence is claimed.
