# Authenticated service

`hydird` stores revisioned projects and provides explicit ELF upload,
inspection, CFG and global-effect analysis, scalar lift/C artifacts, named
pass experiments, annotations, restricted rebuild/patch operations, and
durable jobs. The mounted `hydir.v1` and `hydir.v2` services retain existing
operations. `hydir.v3` adds native program-analysis jobs and per-stage artifact
retrieval. The remote CLI covers the established v1/v2 commands; the
[Python SDK](../../../sdk/python/README.md) negotiates v3, then v2 or v1 when a newer
service is unavailable. The service never executes uploaded binaries.

```bash
# Create an identity once; save the one-time credential in a private 0600 file.
cargo run --locked --bin hydird -- identity create /path/to/hydird.sqlite analyst

# Start the service in a separate terminal.
cargo run --locked --bin hydird -- serve /path/to/hydird.sqlite 127.0.0.1:50051

# Point the CLI at the service and the saved credential.
export HYDIR_ENDPOINT=http://127.0.0.1:50051
export HYDIR_TOKEN_FILE=/private/path/analyst.token
cargo run --locked --bin hydirctl -- remote discover
cargo run --locked --bin hydirctl -- remote create demo unique-request-key
cargo run --locked --bin hydirctl -- remote upload <project-id> <expected-revision> /path/to/program.elf
```

## Project and native-analysis lifecycle

Project creation returns an ID and revision. Upload is the explicit transfer
boundary and creates a new immutable binary revision. Subsequent reads and
mutations supply the expected revision so an artifact cannot silently be
associated with a different ELF. The v3 native interface has these operations:

| Operation | Contract |
| --- | --- |
| `Discover` | Reports API version and the supported ProgramSpec, FunctionIndex, IR, and DecompilationUnit schema versions. |
| `StartProgramAnalysis` | Starts an isolated analysis job for a project revision. An idempotency key identifies retries of the same request; the job records its project and revision. |
| `GetAnalysisJob`, `CancelAnalysisJob`, `StreamAnalysisEvents` | Read status, request cancellation, or replay sequenced events from an `after_sequence` cursor. |
| `GetProgramArtifact` | Retrieves `program_spec`, `function_index`, or `coverage` for the program, or `machine`, `state`, `function`, `cir`, `llvm`, or `unit` for a FunctionIndex ID or unambiguous name. Each response includes bytes, media type, SHA-256, and project revision. |
| `UpdateAnalystFact` | Appends a revision-checked, idempotent name, comment, or assumption with analyst provenance. A fact does not become an ELF-derived proof. |

The Python SDK checks returned revision, content digest, media type, and JSON
schema version before exposing a native artifact. Its
`get_program_artifact(...)` method requires a selector for function-scoped
stages and rejects one for program-scoped stages. The remote CLI currently
provides the established v1/v2 operations; use the SDK or v3 gRPC contract
for these native methods. See the [SDK reference](../../../sdk/python/README.md) and
[v3 schema](../../../crates/hydir-api/proto/hydir_v3.proto).

## Authorization and transport

Projects use ordered `viewer`, `analyst`, `operator`, and `admin` roles. Existing
owners migrate to `admin`; new projects create their owner ACL atomically.
Administrative access changes are offline database-owner operations and append
an audit event:

```bash
cargo run --locked --bin hydird -- identity create /path/to/hydird.sqlite reviewer
cargo run --locked --bin hydird -- access grant /path/to/hydird.sqlite <project-id> analyst reviewer viewer
cargo run --locked --bin hydird -- access list /path/to/hydird.sqlite <project-id> analyst
cargo run --locked --bin hydird -- access revoke /path/to/hydird.sqlite <project-id> analyst reviewer
```

Roles are checked per operation. Analysts can start v3 analysis, retrieve v3
artifacts, and append analyst facts; operators can mutate binaries, and admins
can manage project access. The project owner cannot be downgraded or removed.

Plaintext service mode is restricted to loopback. The additive `serve-tls`
mode accepts non-loopback connections through TLS. Certificate and key paths
must be absolute, the key must be private on Unix, and clients validate the
certificate against configured trust roots:

```bash
cargo run --locked --bin hydird -- serve-tls /path/to/hydird.sqlite 0.0.0.0:50051 /run/secrets/tls.crt /run/secrets/tls.key
export HYDIR_ENDPOINT=https://hydir.example:50051
```

`serve-oidc` replaces static-token authentication with a pinned RS256 JWKS while
retaining mandatory TLS. Tokens must carry a matching issuer and audience plus
valid `exp`, optional `nbf`, and non-empty `sub` claims. The JWKS path is
absolute and bounded; unknown keys or algorithms fail closed:

```bash
cargo run --locked --bin hydird -- serve-oidc \
  /path/to/hydird.sqlite 0.0.0.0:50051 \
  /run/secrets/tls.crt /run/secrets/tls.key \
  https://identity.example/tenant hydir-api /run/config/oidc-jwks.json
export HYDIR_ENDPOINT=https://hydir.example:50051
export HYDIR_TOKEN_FILE=/private/path/access.jwt
```

OIDC subjects are registered as deterministic opaque HydIR principals on first
successful authentication. A database operator can resolve those principals
for ACL administration with `hydird identity list-oidc <database.sqlite>`.

## Content storage

The additive content-storage migration keeps existing inline SQLite objects
readable and allows new binary/artifact payloads to be written to a verified,
content-addressed filesystem store. Metadata remains revisioned in SQLite;
each read rechecks both the recorded size and SHA-256 digest. The object root
must be an absolute real directory and must not be group/world writable on
Unix:

```bash
cargo run --locked --bin hydird -- serve-oidc-cas \
  /path/to/hydird.sqlite 0.0.0.0:50051 \
  /run/secrets/tls.crt /run/secrets/tls.key \
  https://identity.example/tenant hydir-api /run/config/oidc-jwks.json \
  /var/lib/hydir/objects
```

Filesystem objects are written through same-directory temporary files and an
atomic rename. A failed database transaction can leave an unreferenced object,
which is harmless in the immutable CAS and may be reclaimed by future storage
maintenance tooling. Back up the SQLite database and object root together.

`serve-oidc-s3` stores the same digest-derived immutable keys in AWS S3 or an
S3-compatible HTTPS service. It uses the standard AWS credential provider
chain, streams reads through a 64 MiB hard bound, and verifies SHA-256 after
every read. Pass `-` for the AWS-managed endpoint and/or an empty object prefix;
custom endpoints must be origin-only HTTPS URLs:

```bash
cargo run --locked --bin hydird -- serve-oidc-s3 \
  /path/to/hydird.sqlite 0.0.0.0:50051 \
  /run/secrets/tls.crt /run/secrets/tls.key \
  https://identity.example/tenant hydir-api /run/config/oidc-jwks.json \
  - us-east-1 hydir-artifacts production
```

HydIR records only the S3 key, backend kind, digest, and size in metadata. It
never stores cloud credentials in the project database or command line.

## Deployment boundary

The TLS/OIDC/SQLite/filesystem-CAS mode is a secure deployment foundation, not
the completed production profile. Automatic discovery/key refresh, PostgreSQL,
quotas, audit export, and Kubernetes packaging remain required before that
profile is release-ready.

Upload is never implicit: the last command is the transfer boundary. Use the project ID and revision returned by the preceding commands for subsequent `remote inspect`, `cfg`, `lift`, `decompile`, `artifact`, or `job-*` operations. Credential files must not be group- or world-readable.
