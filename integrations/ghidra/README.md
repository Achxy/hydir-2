# Ghidra snapshot exporter

`HydIRSnapshot.java` runs as a Ghidra post-analysis script. It exports a program
function index, one function's **raw instruction P-code**, analyzed flow edges,
and call targets in Hydir snapshot schema v2. Flow and call sections are
optional so earlier v2 snapshots remain readable. It does not lift, simplify,
or type the P-code. Those steps belong to
Hydir's Rust core. `HydIRExport.java` remains the separate v1 graph exporter.

Hydir normally launches headless Ghidra for the user. The default path builds
and runs the pinned `Dockerfile.worker` image, including Ghidra 12.1.4 and JDK
21. On a development machine, set `HYDIR_GHIDRA_HOME` to an unpacked Ghidra
12.1.4 directory instead. The container path has not been run on the current
Windows development host because Docker is unavailable there.

```powershell
$env:HYDIR_GHIDRA_HOME = 'C:\path\to\ghidra_12.1.4_PUBLIC' # optional local override
cargo run -p hydir-cli -- ghidra analyze .\demo\hydir-prism.elf --output .\snapshot.json
cargo run -p hydir-cli -- ghidra-snapshot verify .\demo\hydir-prism.elf .\snapshot.json
cargo run -p hydir-cli -- ghidra-snapshot semantics .\demo\hydir-prism.elf .\snapshot.json --output .\semantic-ir.json
cargo run -p hydir-cli -- ghidra-snapshot state .\demo\hydir-prism.elf .\snapshot.json --output .\state-ir.json
cargo run -p hydir-cli -- ghidra-snapshot cfg .\demo\hydir-prism.elf .\snapshot.json --output .\cfg-ir.json
cargo run -p hydir-cli -- ghidra-snapshot llvm-prefix .\demo\hydir-prism.elf .\snapshot.json --output .\prefix.json
cargo run -p hydir-cli -- ghidra-snapshot llvm-standalone .\demo\hydir-prism.elf .\snapshot.json --output .\standalone.json
cargo run -p hydir-cli -- ghidra-snapshot trace-prefix .\demo\hydir-prism.elf .\snapshot.json .\seed.json --max-ops 4096 --output .\trace.json
cargo run -p hydir-cli -- ghidra-snapshot trace-path .\demo\hydir-prism.elf .\snapshot.json .\seed.json --start 0x2013d9 --max-ops 4096 --max-visits 1024 --output .\path.json
```

For manual exporter debugging (PowerShell, with Ghidra 12.1.4 installed):

```powershell
$ghidra = 'C:\path\to\ghidra_12.1.4_PUBLIC'
$binary = (Resolve-Path '.\demo\hydir-prism.elf').Path
$scripts = (Resolve-Path '.\integrations\ghidra').Path
$snapshot = Join-Path (Get-Location) 'snapshot.json'
$projectDir = Join-Path $env:TEMP 'hydir-ghidra-projects'
New-Item -ItemType Directory -Force -Path $projectDir | Out-Null
& "$ghidra\support\analyzeHeadless.bat" $projectDir HydirSnapshotDemo `
  -import $binary -scriptPath $scripts `
  -postScript HydIRSnapshot.java $snapshot $binary `
  -deleteProject
```

The third script argument is an optional `0x`-prefixed function entry offset.
Without it, the exporter selects the first indexed function with a body. For a
real caller, pass an entry from the function index so selection is explicit.

Hydir validates the export against the same binary and emits a versioned
PcodeFunctionIr artifact:

```powershell
cargo run -p hydir-cli -- ghidra-snapshot verify $binary $snapshot
cargo run -p hydir-cli -- ghidra-snapshot pcode $binary $snapshot --output .\pcode-ir.json
```

Hydir's semantic artifact classifies a bounded integer/bitwise P-code subset
as exact operations and retains other operations as explicit opaque effects.
The state artifact records ordered reads, writes, and possible effects for a
selected function. The worker keeps an analyzed Ghidra project in Hydir's user
cache and reuses it when another function is selected for the same binary and
tool version.
The CFG artifact joins instruction nodes to analyzed edges and keeps calls
separate. Its completeness is explicitly `incomplete`, including when all
visible edges have concrete targets.
`ghidra-snapshot llvm-op` emits LLVM for one selected exact operation. These
artifacts are inspectable building blocks; they do not yet represent a complete
function lift or establish whole-function equivalence. The raw
PcodeFunctionIr artifact reports `semantic_fidelity: unknown` and
`verification: not_run`.
`llvm-prefix` emits a bounded straight-line state transition module with source
operation provenance and an explicit stop reason. Its external read, write,
and unique-clear helpers follow the ABI recorded in the artifact. It requires
explicit fallthrough evidence before crossing an instruction boundary and
stops before memory, control, and unsupported effects.
`llvm-standalone` packages that same exact prefix with Rust-generated LLVM
definitions for those helpers and a compact byte map. Overlapping register and
unique varnodes share bytes. A caller seeds a `state_bytes`-sized buffer from
`byte_map` and invokes `@hydir_pcode_prefix(ptr)`; the return value is the
number of executed P-code operations. The module can run under `lli`, but it
still stops at the prefix boundary and does not represent a complete function.
The concrete P-code executor can cross a RAM `LOAD` or `STORE` when the address,
width, and required bytes are supplied in its state; unknown memory remains a
reported boundary. Memory is not yet part of the standalone LLVM prefix.

`trace-prefix` takes a binary-bound seed file. Register offsets and memory
offsets are bytes; memory entries are grouped by Ghidra address-space name.
The seed's function entry must match the selected snapshot function. For
example, after copying the snapshot's digest and entry:

```json
{
  "schema_version": 1,
  "binary_sha256": "<64-character SHA-256 from snapshot>",
  "entry": {"space": "ram", "offset": "0x2013cf"},
  "registers": [
    {"offset": "0x38", "size": 8, "value": "0xf0f"},
    {"offset": "0x30", "size": 8, "value": "0xff"}
  ],
  "memory": []
}
```

Each seed value must fit its declared 1..=8-byte width. Overlapping entries,
unknown spaces, and mismatched binary or function identities are rejected.
The trace records each executed operation, concrete memory access, final
state, and exact stop reason. It does not claim whole-function equivalence.
`trace-path` uses the same seed and follows one concrete route through the
selected function's analyzed instructions. `--start` optionally selects an
instruction in that function, which is useful when earlier instructions have
unsupported effects. The path artifact records each instruction visit and
branch event, and stops on unknown control, a call or return, or a budget.
The desktop workbench's **Concrete path trace** panel creates a seed template
for the selected function, accepts register and RAM values in that format,
and links trace events back to their source instructions. The GUI and CLI use
the same `hydir_ir::pcode::parse_pcode_seed` validation.

The JSON includes the SHA-256 of the supplied original binary and requires it
to match Ghidra's recorded import hash. Addresses are objects
with `space` and lowercase hexadecimal `offset`; P-code varnodes add a byte
`size`. `sequence_index` is the zero-based array position for each instruction;
`sequence_time` is Ghidra's sub-address, retained for relative P-code branches.
`source_address` comes from the P-code sequence number. `bytes` reflects
Ghidra's effective instruction length, while `parsed_bytes` records all bytes
the instruction prototype parsed when a length override is present. P-code is
from `Instruction.getPcode(true)`, including analyzed flow overrides, and is
distinct from decompiler high P-code. The top-level
`flow_overrides_applied: true` records this choice. `CALLOTHER` retains the language-defined
name in `userop_name` when Ghidra can resolve its constant ID; other ops use
`null`.

`selected_function.flow_edges` records fallthrough, branch, and call edges
from Ghidra's analyzed instruction flow. A `null` target keeps computed or
otherwise unresolved flow visible. `call_targets` indexes call sites
separately; a resolved call target can be opened from Hydir's GUI. These are
Ghidra analysis facts rather than a proven complete CFG.

The export fails on missing functions/instructions, mismatched input hashes,
or any size cap: 65,536 functions, 256 address spaces, 16,384 selected
instructions, 262,144 total P-code ops, 256 ops per instruction, 256 inputs per
op, 32 bytes per instruction, or 16 MiB JSON. It does not write a truncated
snapshot. The output file is replaced only after a complete snapshot is built.
