# HydIR Python SDK (API v1 subset)

This SDK is backed by the same protobuf schema as `hydirctl remote` and
`hydird`. It supports authenticated loopback discovery, project creation,
explicit ELF upload, inspect/CFG/lift/scalar-C, bounded global-effect analysis,
durable lift jobs and event streams, a named allowlisted LLVM 14 pass
experiment, restricted whole-executable rebuilding, and verified artifact
download. There is no remote execution endpoint.

`decompile(project_id, revision, symbol, assume_u64x2=True)` returns C11
from the bounded scalar LLVM lift; it is not a general or Rellic-compatible
decompiler. `get_source()` retrieves the exact source tar advertised by a
matching-source build and verifies its SHA-256. Ordinary development builds
do not embed such an archive, so `get_source()` then fails explicitly.
`apply_patch(...)` accepts the versioned [scalar patch v1](../../docs/PATCHING.md)
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
through the typed `Analyze` operation.
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
[remote operation](../../docs/REMOTE.md).
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

Generated `hydir_pb2.py` and `hydir_pb2_grpc.py` correspond to
`crates/hydir-api/proto/hydir.proto`, produced with `grpcio-tools==1.84.0`.
Regenerate after API changes with:

```sh
python -m grpc_tools.protoc -I../../crates/hydir-api/proto \
  --python_out=hydir_sdk --grpc_python_out=hydir_sdk \
  ../../crates/hydir-api/proto/hydir.proto
```

After regeneration, change `import hydir_pb2` in the generated gRPC file to
`from . import hydir_pb2` so the package imports correctly.
