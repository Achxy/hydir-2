# HydIR semantic evidence gate

Run `python3 scripts/semantic-gate.py` on native Linux x86-64 with Rust 1.96,
Clang, GCC, and `opt` available. The GitHub Actions workflow
`.github/workflows/semantic-gate.yml` runs the same command. It compiles four
well-defined C functions with GCC and Clang at `-O0`, `-O1`, and `-O2`, and
forty-five hand-written assembly functions, including every accepted x86-64
condition code. Each compiled binary is preserved
under `target/semantic-gate/<timestamp>/`.

The JSON report records tool versions, input binary digests, decoded
instruction families, a source-tree digest covering the gate, fixtures, and
relevant implementation files (including uncommitted files), the Git revision,
explicit lift refusals, LLVM verification, LLVM/native
and compiled-C/native cases, mismatches, elapsed time, and peak child RSS. It
summarizes outcomes by compiler setting and instruction family. A supported
function with a comparison mismatch fails the gate. An unsupported function
counts as rejected, not as matched.
The gate accepts a validator result only when its JSON identifies the expected
binary, symbol, and backend and accounts for every directed, random, and solver
case. Empty or malformed validator output fails the gate even if the process
exits successfully.

When the Triton binary-analysis Python bindings are available, the gate asks
Triton to solve each recovered return path and passes the resulting two-u64
inputs to both differential validators through `--cases-file`. It records
solved, rejected, and unavailable oracle states separately. The CI job installs
`triton-library` in a Python virtual environment. Solving a path supplies a
test input, not a proof that every possible input is equivalent. CI uses
`--require-triton-witness`, which fails if no supported branched function gets
a solver witness.
The gate checks that every solver witness is a distinct pair of u64 inputs;
missing or malformed solver output is recorded as a refusal.
`tests/instruction_oracle_test.py` separately checks Triton's concrete state
after directed scalar, flag, branch, frame, memory-slot, call, and return
instructions. These one-step checks test the expected architectural effects
used when constructing fixtures; they do not alone prove HydIR's emitted IR.
CI also requires all forty-five declared hand-assembly functions to match
both backends. Optimized compiler outputs still count explicit refusals
separately.
Every accepted condition-code fixture must produce witnesses for both return
paths; a solver refusal on one of these declared fixtures fails CI.

This gate is scoped to trusted, symbolized, two-argument scalar fixtures.
It has not yet been run on native Linux in this working tree. It does not
establish instruction-level equivalence or correctness of whole-program
rebuilding. The `fuzz/` targets compile and
have seeds, but a sustained fuzz campaign has not yet been run.

`hydir-semantics` is now the typed decoder used by the scalar CFG lifter and
the overlapping register/immediate operations in the restricted rebuilder.
It distinguishes 32-bit writes and their required zero extension. Balanced
frame operations and bounded, nonoverlapping four- and eight-byte stack locals
can be represented in the scalar lift after stack proof; leaf functions may
use the 128-byte SysV red zone. Dword arithmetic and comparisons compute
ZF/SF/OF/CF at 32-bit width before zero-extending register results. Each local
read must follow a same-width write on every path; other memory widths and
unresolved or mixed-width aliases remain rejected. Stack-adjustment flags
reaching a conditional branch also reject lifting. Direct calls have a typed
target and return-address effect.
The scalar symbol lifter accepts a direct call only to a unique bounded
scalar leaf symbol in the same linked ELF, with an aligned stack, no caller
relocation, and definite arguments. It invalidates caller-saved registers and
flags after the call, apart from the callee's proven RAX return. Raw
`lift-at` and unresolved calls still reject. The restricted rebuilder accepts
direct calls only to its discovered function entries. A transitive callee
may-write summary invalidates exactly the tracked registers and zero flag that
the callee can modify; a post-call read of one of those locations needs a new
definition. The summary does not infer a callee return value.

`ProgramSpec` schema 3 includes a versioned typed model for function
prototypes and stack facts. Readers migrate schema 2 inputs explicitly.
`hydirctl lift-model` accepts a matching linked ELF and a typed prototype;
its LLVM output records binary and model digests plus the assertion ID.
For a `lift-model` target, a 64-bit stack assertion is accepted only when its
entry-RSP offset matches a proven local slot; the assertion ID and typed-model
digest are embedded in LLVM. `validate` and `validate-c` accept `--model` and
copy the same digest and assertion IDs into their JSON report. Other widths
and unproven offsets are rejected.

`hydirctl region <linked-elf> <function-symbol>` exports exact bytes, their
hash, reachable return sites, relocation records, and a stack delta when
bounded stack analysis proves balanced direct paths. Unknown live locations,
stack alignment, alternate entries, and relocation applicability remain
unresolved. Its
`replacement_ready` field therefore remains false; no region replacement
is authorized by this artifact.
Region schema 2 also records observed entries into the selected symbol's
interior, including ELF entry points, nested text symbols, and direct edges
from recursively decoded code. An empty list does not prove that no other
entry exists. The whole-function patch refuses any observed interior entry
even when the caller supplies `--assume-entry-only`.
The existing trusted whole-function `patch` command now checks the exported
region bytes hash, unique near-return exit, restored entry stack, scalar CFG
and lift proof, and relocation absence before producing a new ELF. It still
requires the explicit `--assume-entry-only` analyst assertion and the SysV
prototype. This does not establish arbitrary block replacement or permit
the read-only region artifact to claim `replacement_ready`.

For recovery comparison, save `hydirctl disassemble <elf>` as JSON and run
`python3 scripts/compare-recovery.py <elf> <hydir.json> --ghidra <graph.json>`.
The optional `--ddisasm-gtirb <binary.gtirb>` path uses matching `gtirb` and
`gtirb-functions` Python packages. The report lists agreeing, HydIR-only, and
external-only candidate entries and hashes each evidence file. Ghidra's graph
format and GTIRB do not supply a verified input-ELF digest here, so external
entries retain an explicit unverified identity label and never authorize a
lift boundary. The GTIRB adapter follows the official `functionEntries`
auxiliary data API via `gtirb-functions` (source revision
`a4240ca95bcd06141d2afb0d990380e970623ca7`, MIT). The DDisasm adapter has
been exercised with a synthetic GTIRB 2.3.2 / gtirb-functions 1.1.0 file on
this host, but has not been exercised with a real DDisasm output file.
