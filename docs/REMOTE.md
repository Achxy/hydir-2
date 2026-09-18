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

The script creates a private development database and two credentials,
starts `hydird` on loopback, uploads a fixture binary, inspects it, recovers
its CFG, lifts it, and compiles scalar C. It runs an allowlisted LLVM pass
experiment, verifies the after-IR, and confirms the new project revision
retains the same binary hash. It rebuilds one complete trusted ELF into a new
revision, retrieves its LLVM/ELF artifacts after restart, and compares three
controlled input cases on the client. GUI pass and rebuild probes exercise
the same remote operations and export a verified ELF. It also applies a bounded scalar patch into a new revision and
starts an idempotent background lift. After restart it retrieves the same
artifacts, replays the patch and lift events, and checks that the second
identity cannot read or transform the first identity's project or artifacts.
It also saves a scoped analyst assumption, checks exact-key retry and
analyzed-spec provenance, runs the GUI annotation operation probe, verifies
the ledger after restart, and denies the second identity access to it.
It leaves artifacts in
`target/demo-remote/run.*` for inspection. The credential files and database
are mode-restricted by `umask 077`; do not publish that directory.

For manual use, `hydird identity create <database.sqlite> <principal>` prints
a 64-character random credential once. Save it to a private file (mode 0600),
then start `hydird serve <database.sqlite> 127.0.0.1:50051`. Set
`HYDIR_ENDPOINT=http://127.0.0.1:50051` and `HYDIR_TOKEN_FILE` to that file
before running `hydirctl remote discover`. `hydirctl remote` without arguments
prints available operations, including `analyze` and `analyze-spec` for a
linked ELF project. The latter returns a partial, provenance-bearing
`ProgramSpec`; it does not claim all call or memory-reference sites.
`hydird identity rotate` replaces a principal's
credential and immediately revokes its predecessor.

`hydirctl remote annotations <project-id> <revision>` lists the current
binary's owner-scoped analyst ledger. `hydirctl remote annotate <project-id>
<revision> <idempotency-key> <name|comment|assumption> <hex-address|->
<scope> <value>` adds a bounded fact as a new immutable revision. `-` means
program-wide; a name requires an address, and addressed facts must lie in a
linked ELF load mapping. Exact-key retry returns the same revision; a
changed request with the same key fails. Only assumptions are overlaid into
remote `inspect` and `analyze-spec` with `analyst_assertion` provenance.
Names/comments do not change machine facts. None of these facts substitute
for the explicit trust or prototype assertions required by other operations.

In `hydir`, expand **Remote project · explicit transfer**, enter the loopback
endpoint and private credential-file path, then create a project or enter an
existing project ID. Opening never uploads. To send bytes, enter an ELF path
and press **Upload ELF to remote project**; this creates an immutable revision.
The workbench checks discovery version, project revision, model hash,
and returned IR/C artifact digests. It supports inspect/CFG/lift/scalar-C, a bounded
global-effect report with bounded call/reference sites, and lift-job
start/monitor/cancel/artifact retrieval.
The **Passes** tab runs the named pass pipeline and shows verified before/after
IR. The Inspector requires a visible trusted-fixture assertion before remote
whole-executable rebuilding, then permits hash-checked ELF export only to a
new local file. The workbench never executes the ELF.
The scalar patch v1 section generates a typed, hash-bound patch request for
the selected function and requires both trusted-fixture and entry-only
assertions. The resulting ELF has a new revision; remote export is digest-
checked and new-file-only. The GUI probes cover both local and remote patch
operation functions, not visual interaction.
The Inspector includes an explicitly unverified analyst ledger and form for
the selected virtual address or a program-wide fact. Remote saving uses the
same revisioned API as the CLI. Local ELF mode uses a separate private,
path-bound SQLite project ledger through the same shared fact validation;
opening a local file never transfers it. The ledgers do not auto-sync.
Credentials stay out of the displayed project label. The headless
`--probe-create-upload`, `--probe-transform`, and `--probe-rebuild` paths
exercise the same operation functions, but are not visual UI tests.
The Inspector displays whether this service build offers a matching committed
source archive, its revision and digest, and the explicit CLI download command.

`hydirctl local project|inspect|analyze-spec|annotations <elf>` opens the
on-device project. `hydirctl local annotate <elf> <revision> <key>
<name|comment|assumption> <hex-address|-> <scope> <value>` creates a revisioned
fact; `--db <absolute-private-sqlite>` or `HYDIR_LOCAL_DB` selects a test or
custom database. The GUI uses `HYDIR_LOCAL_DB` or the same user-data default.
The original ELF stays on disk unchanged. Only assumptions are overlaid into
the local `ProgramSpec`; names/comments stay separately visible. Changing
file bytes at the same canonical path advances the project revision and
hides facts for the previous digest. `bash scripts/demo-local-project.sh`
checks restart, exact-key replay, stale/conflicting writes, GUI/CLI sharing,
and digest isolation on a disposable fixture copy.

Projects have an owner identity and an integer revision. Uploaded binaries
are verified by SHA-256 and parsed as ELF before a new immutable revision is
recorded. A revision precondition is required for upload, inspect, analyze,
analyze-spec, CFG, and
lift. Patch v1 additionally requires an exact input hash, explicit
trusted-fixture/prototype/entry-only assertions, and an idempotency key. It
creates a new immutable binary revision and an owner-scoped ELF artifact;
retrying the same key and patch returns that revision after restart. Project
creation uses an idempotency key. Lifted IR is a SHA-256-addressed
artifact scoped to a project revision. Artifact retrieval rechecks ownership;
remote commands verify the returned digest and refuse to overwrite differing
local files. The database schema version is checked on startup; unknown newer
versions are rejected rather than silently changed. On Unix the database must
be a regular, owner-private file; newly created files use mode 0600.

`remote transform` requires a current revision, an idempotency key, explicit trusted-fixture and
prototype assertions, and 1–4 distinct passes from `instcombine,sccp,simplifycfg,dce`.
The worker invokes fixed `/usr/bin/opt-14` and refuses other LLVM versions;
it saves raw, canonical before, after, and JSON report artifacts under a new
immutable project revision with the same binary hash. An exact retry returns
that revision after restart; a changed request with the same key is denied.
LLVM verification does not establish behavioral equivalence.

`remote rebuild` requires a current revision, an idempotency key, and a
trusted-fixture assertion. The worker invokes fixed `/usr/bin/opt-14` and
`/usr/bin/clang-14`, not client-provided executables or arbitrary flags. It
imports the compiled ELF, creates a new binary revision, and saves owner-scoped
IR, ELF, and report artifacts. Exact retries after restart return the same
revision; other principals cannot read it. CLI, SDK, and GUI verify artifact
hashes, types, and revisions. The server does not execute either ELF; only the
trusted demo client compares their declared behavior.

`job-start-lift` requires the project revision, an explicit prototype
assertion, and an idempotency key. At most two jobs may be queued/running per
identity. `job` and `job-cancel` are owner-scoped. `job-events` accepts an
exclusive sequence cursor and replays stored events before following new
ones; the stream checks credential validity again while connected. Terminal
jobs and their events survive restart. Queued/running jobs become
`interrupted` on restart rather than silently resuming. Cancellation aborts
the child-worker task and waits up to five seconds for it to stop. On Linux,
the worker runs in a process group that is killed on timeout, error, or
cancellation, including compiler descendants. This is not an OS security sandbox.

The Python client in `sdk/python/` uses the same `.proto` contract and
loopback/credential rules. `scripts/demo-sdk.sh` runs its unit tests and a
separate-client integration smoke test against a locally started `hydird`,
given a trusted x86-64 ELF containing `hydir_max2`. With a second trusted
freestanding ELF, it also runs the Python rebuild example and compares three
controlled cases on the client. `demo-sdk-linux-docker.sh` builds the pinned
Python image and supplies both fixtures. It exposes rebuild without
execution, the named pass experiment, scalar C, patch v1, and optional source
retrieval.

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

This is **not a hostile-binary sandbox**. ELF parsing, CFG recovery, lifting,
and rebuilding run in a fresh `hydird worker` child process with a 30-second deadline
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
