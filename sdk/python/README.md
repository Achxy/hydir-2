# HydIR Python SDK (compatible v1/v2 plus additive v3)

For local Ghidra-backed lifting, `LocalGhidra` calls the same `hydirctl`
worker as the desktop app. It needs no service credentials:

```python
from hydir_sdk import LocalGhidra

client = LocalGhidra("hydirctl")
snapshot = client.analyze("sample.elf", "snapshot.json")
state = client.artifact("state", "sample.elf", "snapshot.json")
```

`analyze(..., function=0x...)` selects another function from the managed
Ghidra project. `artifact` also accepts `pcode`, `semantics`, `cfg`,
`llvm-prefix`, and `llvm-standalone`;
`llvm_operation` emits LLVM for one exact P-code operation. Artifacts are
checked against the binary SHA-256, and a function-level state artifact is
an effect inventory rather than an executable lift. `llvm-standalone` provides
a runnable byte-state module for the supported straight-line prefix, with an
explicit stop reason; it does not claim whole-function equivalence.
`trace_prefix(binary, snapshot, seed, max_operations=4096)` runs the bounded
concrete interpreter against a binary-bound JSON seed and returns its trace.
`trace_path(...)` follows a bounded path through selected instructions and
returns source-linked branch events and its explicit stop reason.

This SDK is backed by the same protobuf schema as `hydirctl remote` and
`hydird`. It supports authenticated loopback or TLS discovery, project creation,
explicit ELF upload, inspect/CFG/lift/scalar-C, bounded global-effect analysis,
durable lift jobs and event streams, a named allowlisted LLVM 14 pass
experiment, restricted whole-executable rebuilding, and verified artifact
download. There is no remote execution endpoint.

`negotiate_api()` prefers `hydir.v3`, then falls back through v2 to v1 only
when the newer endpoint reports `UNIMPLEMENTED`. v3 exposes isolated native
whole-program jobs, replayable events, revision-checked analyst facts, and
digest/media/schema/revision-checked ProgramSpec, FunctionIndex, coverage,
MachineIR, StateIR, FunctionIR, CIR, LLVM-export, and DecompilationUnit
artifacts. `get_program_artifact(...)` never executes the input and requires a
FunctionIndex selector for function-scoped stages.

`analyze_ghidra_snapshot(project_id, revision, snapshot, stage)` sends an
exported Ghidra snapshot as bytes or a file path to the v3 service. The
project must already contain the same binary. The server checks the snapshot
digest against that binary and runs a bounded worker. Supported stages are
`snapshot`, `pcode`, `semantics`, `state`, `cfg`, `coverage`, `llvm-cfg`, and `slice`. For
`llvm-cfg`, pass `start_address=0x...` to select a CFG entry. For `slice`, pass
`instruction_index` and `operation_index`, plus optional `input_index`. The SDK checks the
artifact hash, media type, schema version, and project revision before
returning JSON.
`analyze_ghidra_binary(project_id, revision, "snapshot")` asks the service to
run its managed Ghidra worker on the already uploaded ELF, returning the
validated function index and selected function snapshot. Pass
`selected_function_entry=0x...` for another Ghidra function, then request
`pcode`, `state`, `llvm-cfg`, or `slice`. The explicit automatic flag prevents an
empty legacy snapshot request from starting analysis.
For local snapshots, `LocalGhidra.slice(binary, snapshot, instruction_index,
operation_index, input_index=None)` returns a bounded backward P-code value
slice with source operations and explicit unresolved boundaries.

v2 methods expose digest-checked
`RegionSpec` v3, `PhysicalRegionIR` v1, and `DecompilationUnit` v1 JSON, compile scalar patch v1 into
reversible `PatchBundle` v2, apply it with revision/idempotency protection, and
request structural bundle verification. Behavioral verification remains false
until a separate execution gate supplies evidence.

`lift_region(...)` returns exact decoded operations, successors, physical
register/flag/memory effects, boundary locations, and unresolved proof facts.
Its `lowering_ready` field must be true before a caller treats it as patchable;
successful decoding alone is not a C or replacement-safety claim.

`decompile(project_id, revision, symbol, assume_u64x2=True)` returns C11
from the bounded scalar LLVM lift; it is not a general or Rellic-compatible
decompiler. `get_source()` retrieves the exact source tar advertised by a
matching-source build and verifies its SHA-256. Ordinary development builds
do not embed such an archive, so `get_source()` then fails explicitly.
`apply_patch(...)` accepts the versioned scalar patch v1
document and requires three explicit assertions. It commits a new project
revision and returns hash-checked ELF bytes; it does not execute them. The
`examples/patch_scalar.py` script demonstrates an explicit trusted-fixture
upload and patch, with a new output path.
`transform(...)` requires explicit trusted-fixture and prototype assertions.
It creates a new immutable project revision retaining the same ELF bytes,
and returns a report plus hash-checked raw/before/after LLVM IR artifacts;
LLVM verification is not
behavioral equivalence. `examples/pass_experiment.py` demonstrates the
explicit upload, named pass request, and no-overwrite artifact export.
`examples/global_analysis.py` saves the conservative cross-function report
and a partial `ProgramSpec` with provenance-bearing call/reference sites
through the typed `Analyze` and `AnalyzeSpec` operations. It needs two new,
distinct output paths and does not claim complete control-flow recovery.
`examples/annotate_program.py` explicitly uploads a trusted ELF, adds a
revisioned, scoped analyst name/comment/assumption, checks its binary-bound
ledger, and exports JSON to a new file. Analyst facts are unverified;
assumptions appear in remote inspected/analyzed specifications but do not
satisfy explicit prototype/trust flags for other operations. The SDK checks
the returned project, revision, and binary identity.
`rebuild(...)` requires an explicit trusted-fixture assertion. It creates a
new immutable binary revision and returns digest-checked ELF/IR/report
artifacts without executing the ELF. `examples/rebuild_program.py` shows
explicit upload and new-file-only export. Use only the documented static
freestanding Linux x86-64 subset; the service worker is not a hostile-input
sandbox.
`examples/validate_program.py` is an opt-in, client-side Docker comparison
for trusted static ELFs. It requires `--trusted-fixture`, a JSON list of
hex-encoded stdin cases, and a new report path. It compares stdout, stderr,
and exit status under no-network, read-only, CPU/memory/process/time controls.
This does not establish hostile-input isolation or general equivalence. The
remote service still has no execution endpoint. A ready case list is
`../../tests/fixtures/whole_choice_cases.json`.

Install Python 3.10+ in a private virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install .
```

For the runnable smoke example, first run an authenticated `hydird` service
and create a private credential file as described in
remote operation.
Then supply a trusted x86-64 ELF and a symbol with the asserted
`u64(u64,u64)` prototype:

```sh
.venv/bin/python examples/smoke.py http://127.0.0.1:50051 /private/token.txt /path/to/fixture.elf hydir_max2 /new/output/directory
```

On a Docker-equipped host, `bash ../../scripts/demo-sdk-linux-docker.sh`
builds a pinned Linux SDK image and runs the separate-process smoke and
rebuild examples. The scripts retain private fixture artifacts under
`target/demo-sdk/`; do not publish credentials or that directory.

`examples/batch_lift.py` accepts only the symbols explicitly named on its
command line. Passing a symbol asserts the same prototype for it; the SDK
does not infer signatures. No sample is uploaded without a call to
`upload_binary`. Artifact bytes are SHA-256 checked before being returned,
and `export_artifact` refuses to overwrite an existing path. The client
rejects plaintext non-loopback endpoints and non-private credential files.
`https://host:port` endpoints use gRPC TLS with its default trust roots; callers
using a private CA may pass its PEM bytes as `root_certificates`.
Credential files may contain either a local 64-character static token or a
bounded compact OIDC JWT; the server remains responsible for signature and
claim validation.

Generated `hydir*_pb2.py` and `hydir*_pb2_grpc.py` correspond to the v1, v2, and v3
schemas in `crates/hydir-api/proto/`, produced with `grpcio-tools==1.84.0`.
Regenerate after API changes with:

```sh
python -m grpc_tools.protoc -I../../crates/hydir-api/proto \
  --python_out=hydir_sdk --grpc_python_out=hydir_sdk \
  ../../crates/hydir-api/proto/hydir.proto \
  ../../crates/hydir-api/proto/hydir_v2.proto \
  ../../crates/hydir-api/proto/hydir_v3.proto
```

After regeneration, change generated sibling imports to relative imports (for
example, `from . import hydir_v2_pb2`) so the package imports correctly.
