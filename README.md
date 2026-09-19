<h1 align="center">HydIR</h1>

<p align="center">
  <strong>Open an x86-64 ELF, follow a function, and inspect what HydIR can recover.</strong><br>
  A local workbench with CLI tools for the parts that need saved artifacts.
</p>

<p align="center">
  <a href="https://hydir.wiki/">Documentation</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#native-analysis-workbench">Workbench</a> ·
  <a href="#verified-scalar-lift">Evidence</a> ·
  <a href="#symbolic-exploration-with-triton">Triton</a> ·
  <a href="#authenticated-service">Remote API</a>
</p>

[![HydIR egui workbench with a selected ELF function, its lifted LLVM IR, inspector, diagnostics, and console](assets/screenshots/studio-lift.png)](assets/screenshots/studio-lift.png)

*The native egui workbench analyzing `hydir_max2`: local ELF, machine-byte-derived LLVM IR, and the selected function's scope in one view.*

Start with a function you can name. HydIR opens little-endian x86-64 ELF files without uploading them, shows the function's bytes and reachable branches, and turns supported semantics into inspectable LLVM IR and C. The same native core is available through the desktop app, CLI, Python SDK, and authenticated local-or-TLS service.

The checked-in [`hydir_max2` walkthrough](https://hydir.wiki/articles/max2) shows the whole path on a 16-byte function. HydIR is an engineering workbench for a bounded subset, not a general decompiler: unsupported instructions or memory behavior, unresolved calls, unmodelled partial registers, and ambiguous recovery paths stop the lift instead of being guessed.

## Native analysis workbench

The desktop workbench keeps the program tree, analysis views, inspector, and diagnostics visible at once. It can:

- disassemble executable sections with recursive recovery from symbols and entry points
- show uncertain linear-sweep regions and undecodable gaps instead of silently promoting them to functions
- inspect CFG, LLVM IR, scalar C, named pass results, and conservative global effects
- save local names, comments, assumptions, and pane layout in a private SQLite project
- create an authenticated local-or-TLS project only through an explicit transfer action
- apply bounded transforms, rebuilds, and scalar patches to new output paths

The disassembly view ties each recovered instruction to its address and bytes. Branches and unsupported regions remain inspectable instead of being silently turned into source code.

[![egui disassembly cutout with decoded instruction addresses and bytes](assets/screenshots/egui-disassembly.webp)](assets/screenshots/egui-disassembly.webp)

Selecting a function fills the inspector with its entry, extent, source, asserted ABI, and recovered CFG scope. These are facts and explicit assumptions about the selected function, not a guessed prototype.

<p align="center"><img src="assets/screenshots/egui-inspector.webp" width="42%" alt="egui inspector cutout showing the selected function's ELF facts, ABI assertion, and CFG count"></p>

Opening a local ELF does not upload it. Credentials are not persisted and remote projects do not reconnect automatically. Plaintext service connections remain loopback-only; remote connections require TLS.

## Verified scalar lift

After reading one lift, it is fair to ask whether it behaves like the original. The demo scripts answer that question for 20 distinct scalar fixture functions. They emit LLVM IR and C, run the LLVM verifier where the required tools are available, and compare each output path with native execution on 1,008 input pairs.

```bash
bash scripts/demo-local.sh
bash scripts/demo-corpus.sh
```

The bounded scalar contract now also covers proven balanced frames, initialized
nonoverlapping 32/64-bit stack locals (including the SysV leaf red zone),
32-bit arithmetic/comparisons with explicit flags, `mov` zero-extension, and
RIP-relative address formation, plus direct calls to uniquely bounded scalar
leaf symbols. Other memory, unresolved calls, and unmodelled aliases remain
explicit refusals.

RegionSpec v3 CFG recovery is a separate structural stage. It requires decoded
external edges to match the declared continuation exits exactly, records direct
call targets with a distinct edge kind, and does not promote imported liveness
or stack facts into semantic proof. MachineIR preserves mapped/TLS memory and
non-frame register-save effects, while the scalar lift refuses them until a
physical-state and memory contract is available.
Imported call-site `stop`/`noreturn` facts are kept distinct, source-attributed,
and may suppress a region fallthrough only at their exact instruction address.

The scripts save the CFG, LLVM IR, C, and comparison reports, so you can read what was checked. A finite pass says something useful about those fixtures; it does not prove equivalence for arbitrary programs. The UI also keeps failures specific: an unsupported call can stop C generation without discarding an already recovered CFG or LLVM lift.

[![egui C output cutout refusing an unsupported call while retaining other analysis results](assets/screenshots/egui-refusal.webp)](assets/screenshots/egui-refusal.webp)

## HydIR interchange checkpoint

HydIR owns its protobuf contracts under the `hydir.interchange` and
`hydir.patch` namespaces. Specifications are decoded under explicit inventory,
nesting, value, chunk, and total-size limits; the original bytes are retained
for lossless forwarding. A specification can be bound to its matching ELF and
converted block-by-block into RegionSpec v3:

```bash
cargo run --locked --bin hydirctl -- hydir-spec-inspect program.proto
cargo run --locked --bin hydirctl -- hydir-spec-region \
  program.proto program.elf 26 --output region.json
cargo run --locked --bin hydirctl -- hydir-spec-lift \
  program.proto program.elf 26 --output physical-region-ir.json
cargo run --locked --bin hydirctl -- hydir-spec-decompile \
  program.proto program.elf 35 --output decompilation-unit.json
cargo run --locked --bin hydirctl -- hydir-spec-report \
  program.proto program.elf
```

`PhysicalRegionIR` v1 covers every instruction in the pinned 23-region corpus.
It records typed operations and operands, exact successors, register/flag and
memory effects, physical boundary locations, stack deltas, unresolved facts,
and byte/digest provenance. This decoded artifact does not imply lowering or
replacement safety. The structured decision form remains the narrower proven
path: it binds imported flag inputs, both exact continuations, and unchanged
live outputs before emitting LLVM-compatible text and deterministic C.

The local server mounts both HydIR services and accepts the bounded streaming
chunk convention. For non-empty programs it currently returns a fail-closed
precondition error instead of fabricating C or PatchIR while physical adapters
remain incomplete. The pinned external reference repository is a test-only
submodule and is not linked into HydIR:

```bash
git submodule update --init third_party/hydir-reference
```

Measured compatibility and remaining semantic blockers are recorded in
[HYDIR_COMPATIBILITY.md](HYDIR_COMPATIBILITY.md).

## Symbolic exploration with Triton

Triton lets you ask a different kind of question: what input could produce a chosen output? HydIR's Triton bridge explores direct paths in a selected x86-64 function and reports symbolic expressions and path conditions. Use a Python interpreter with Triton installed; `doctor` checks whether HydIR can import it.

```bash
export HYDIR_TRITON_PYTHON=/path/to/python-with-triton
cargo run --locked --bin hydirctl -- doctor
cargo run --locked --bin hydirctl -- triton /path/to/program.elf function_name
```

In the workbench, select a function and use **Run Triton**. The bottom console also accepts a small, restricted set of Triton statements, entered one at a time. The [Triton walkthrough](https://hydir.wiki/articles/triton-api) begins with one instruction and shows how to ask for a model. The bridge is separate from the LLVM lift; its explored paths do not establish whole-program equivalence.

## Authenticated service

`hydird` provides revisioned projects, explicit ELF upload, inspection, CFG and global-effect analysis, lift and scalar C artifacts, named pass experiments, annotations, bounded rebuild/patch operations, and durable lift jobs with events and cancellation. It preserves `hydir.v1` and adds `hydir.v2` region, DecompilationUnit, PatchBundle compile/apply, and structural verification operations. The CLI and [Python SDK](sdk/python/README.md) use the same authenticated API. The service does not execute uploaded binaries. Plaintext service mode is restricted to loopback; non-loopback deployments must use TLS.

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

Viewers can read project artifacts, analysts can create analysis/annotation
work, operators can mutate binaries, and admins can manage project access. The
project owner cannot be downgraded or removed.

The additive `serve-tls` mode accepts non-loopback connections only through TLS. Certificate and key paths must be absolute, the key must be private on Unix, and clients validate the certificate against configured trust roots:

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

The TLS/OIDC/SQLite/filesystem-CAS mode is a secure deployment foundation, not
the completed production profile. Automatic discovery/key refresh, PostgreSQL,
quotas, audit export, and Kubernetes packaging remain required before that
profile is release-ready.

Upload is never implicit: the last command is the transfer boundary. Use the project ID and revision returned by the preceding commands for subsequent `remote inspect`, `cfg`, `lift`, `decompile`, `artifact`, or `job-*` operations. Credential files must not be group- or world-readable.

## Documentation site

The [HydIR wiki](https://hydir.wiki/) is a static site in `blog/`. To preview it
locally with the same clean URLs used on Vercel, run
`python scripts/serve-wiki-site.py` and open `http://127.0.0.1:8765/`.
Run `python scripts/check-wiki-site.py` to check its routes and assets.

## License

HydIR is released under the [GNU Affero General Public License v3.0 only](LICENSE).
