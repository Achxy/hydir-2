# Local-authenticated RPC slice and threat model

The first `hydird` service is a development slice of the planned remote
product. The versioned protobuf schema is in `crates/hydir-api/proto/`.
`hydirctl remote` and `hydird` use the same backend `import_elf`, CFG
recovery, and lift functions as local CLI commands. No Ghidra or source
fixture is read by the lifting server.

## Reproducible demonstration

On Linux x86-64 with the pinned Rust toolchain and Clang:

```sh
bash scripts/demo-remote.sh
```

The script creates a private temporary development database and two random
credentials, starts `hydird` on loopback, uploads a fixture binary, inspects
it, recovers its CFG, lifts it, generates compiled scalar C, downloads both
artifacts, restarts the server, retrieves the same artifacts, starts an idempotent background lift,
replays its event stream after restart, and checks that the second identity
cannot read the first identity's project, job, LLVM artifact, or C artifact. It leaves artifacts in
`target/demo-remote/run.*` for inspection. The credential files and database
are mode-restricted by `umask 077`; do not publish that directory.

For manual use, `hydird identity create <database.sqlite> <principal>` prints
a 64-character random credential once. Save it to a private file (mode 0600),
then start `hydird serve <database.sqlite> 127.0.0.1:50051`. Set
`HYDIR_ENDPOINT=http://127.0.0.1:50051` and `HYDIR_TOKEN_FILE` to that file
before running `hydirctl remote discover`. `hydirctl remote` without arguments
prints available operations, including `analyze` for a linked ELF project.
`hydird identity rotate` replaces a principal's
credential and immediately revokes its predecessor.

In `hydir`, expand **Remote project · explicit transfer**, enter the loopback
endpoint and private credential-file path, then create a project or enter an
existing project ID. Opening never uploads. To send bytes, enter an ELF path
and press **Upload ELF to remote project**; this creates an immutable revision.
The workbench checks discovery version, project revision, model hash,
and returned IR/C artifact digests. It supports inspect/CFG/lift/scalar-C, a bounded
global-effect report, and lift-job start/monitor/cancel/artifact retrieval.
Credentials stay out of the displayed project label. The headless
`--probe-create-upload` path exercises the same transfer functions, but is not
a visual UI test.
The Inspector displays whether this service build offers a matching committed
source archive, its revision and digest, and the explicit CLI download command.

Projects have an owner identity and an integer revision. Uploaded binaries
are verified by SHA-256 and parsed as ELF before a new immutable revision is
recorded. A revision precondition is required for upload, inspect, analyze, CFG, and
lift. Project creation uses an idempotency key. Lifted IR is a SHA-256-addressed
artifact scoped to a project revision. Artifact retrieval rechecks ownership;
remote commands verify the returned digest and refuse to overwrite differing
local files. The database schema version is checked on startup; unknown newer
versions are rejected rather than silently changed. On Unix the database must
be a regular, owner-private file; newly created files use mode 0600.

`job-start-lift` requires the project revision, an explicit prototype
assertion, and an idempotency key. At most two jobs may be queued/running per
identity. `job` and `job-cancel` are owner-scoped. `job-events` accepts an
exclusive sequence cursor and replays stored events before following new
ones; the stream checks credential validity again while connected. Terminal
jobs and their events survive restart. Queued/running jobs become
`interrupted` on restart rather than silently resuming. Cancellation aborts
the child-worker task and waits up to five seconds for it to stop; it is not
an OS process-tree sandbox.

The Python client in `sdk/python/` uses the same `.proto` contract and
loopback/credential rules. `scripts/demo-sdk.sh` runs its unit tests and a
separate-client integration smoke test against a locally started `hydird`,
given a trusted x86-64 ELF containing `hydir_max2`. It does not provide
pass/patch/rebuild/execute calls because the service does not expose those
operations yet. It does expose scalar C and an optional source-archive retrieval.

## Matching-source development build

A normal `hydird` development build advertises no archive. After a clean
commit, `bash scripts/package-source-snapshot.sh` creates a revision-named
tar. Build `hydird` with both `HYDIR_SOURCE_REVISION=<full HEAD SHA>` and
`HYDIR_SOURCE_ARCHIVE=<absolute archive path>` set. Its build script rejects
a dirty or nonmatching checkout and embeds the bounded archive bytes into
the binary. `Discover` advertises the revision and SHA-256; authenticated
`GetSource`, `hydirctl remote source --output <new-file.tar>`, and the Python
SDK return/check the same bytes. `bash scripts/demo-source-offer.sh` exercises
that complete matching-source flow on loopback. This technical mechanism
does not complete the third-party notice/legal review needed before release.

## Security boundary and missing release gates

This service binds only to loopback and uses bearer credentials generated by
the local administrator. The client refuses plaintext non-loopback addresses.
No credential is compiled into the binary. Server SQL errors do not include
request credentials. A caller cannot send a server filesystem path, code
plugin, shell command, or execution request through this API. Project and
artifact reads from another identity return not-found errors.

This is **not a hostile-binary sandbox**. ELF parsing, CFG recovery, and
lifting run in a fresh `hydird worker` child process with a 30-second deadline
and 16 MiB output cap. On Linux the child also starts with a cleared
environment and `setrlimit` caps of 2 GiB address space, 25 CPU seconds,
16 MiB regular-file size, 64 open descriptors, and zero core-dump bytes.
It receives bytes on stdin, not a user-controlled
server path; a crash does not directly unwind the network server. The child
still has the service user's filesystem/network privileges. There are no
isolated network/filesystem namespaces, disposable sandbox, lifetime job/storage quotas,
rate limits, detailed audit logs, or fine-grained read/analyze/mutate roles.
The binary/message/output/time/active-job bounds are resource controls, not a
security proof. Do not expose this build to untrusted clients or samples.
Non-loopback/TLS deployment and execution validation remain unavailable.
The matching-source endpoint exists only in an explicitly built, clean-tree
binary and is not a public release offer. No public deployment is authorized
or claimed.
