# Ghidra snapshot exporter

`HydIRSnapshot.java` runs as a Ghidra post-analysis script. It exports a program
function index, one function's **raw instruction P-code**, analyzed flow edges,
call targets, memory blocks, defined symbols, and source-tagged function
prototype evidence in Hydir snapshot schema v2.
These additional sections are optional so earlier v2 snapshots remain
readable. It does not lift, simplify,
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
cargo run -p hydir-cli -- ghidra-project save .\demo\hydir-prism.elf .\snapshot.json
cargo run -p hydir-cli -- ghidra-project get .\demo\hydir-prism.elf --function 0x2013cf --output .\saved-snapshot.json
cargo run -p hydir-cli -- ghidra-snapshot verify .\demo\hydir-prism.elf .\snapshot.json
cargo run -p hydir-cli -- ghidra-snapshot semantics .\demo\hydir-prism.elf .\snapshot.json --output .\semantic-ir.json
cargo run -p hydir-cli -- ghidra-snapshot state .\demo\hydir-prism.elf .\snapshot.json --output .\state-ir.json
cargo run -p hydir-cli -- ghidra-snapshot cfg .\demo\hydir-prism.elf .\snapshot.json --output .\cfg-ir.json
cargo run -p hydir-cli -- ghidra-snapshot coverage .\demo\hydir-prism.elf .\snapshot.json --output .\coverage.json
cargo run -p hydir-cli -- ghidra-snapshot slice .\demo\hydir-prism.elf .\snapshot.json --instruction 0 --op 0 --output .\slice.json
cargo run -p hydir-cli -- ghidra-snapshot llvm-prefix .\demo\hydir-prism.elf .\snapshot.json --output .\prefix.json
cargo run -p hydir-cli -- ghidra-snapshot llvm-standalone .\demo\hydir-prism.elf .\snapshot.json --output .\standalone.json
cargo run -p hydir-cli -- ghidra-snapshot llvm-cfg .\demo\hydir-prism.elf .\snapshot.json --start 0x2013d9 --output .\cfg-llvm.json
cargo run -p hydir-cli -- ghidra-snapshot trace-prefix .\demo\hydir-prism.elf .\snapshot.json .\seed.json --max-ops 4096 --output .\trace.json
cargo run -p hydir-cli -- ghidra-snapshot trace-path .\demo\hydir-prism.elf .\snapshot.json .\seed.json --start 0x2013d9 --max-ops 4096 --max-visits 1024 --output .\path.json
```

For manual exporter debugging (PowerShell, with Ghidra 12.1.4 installed):

```powershell
$ghidra = 'C:\path\to\ghidra_12.1.4_PUBLIC'
$binary = (Resolve-Path '.\demo\hydir-prism.elf').Path
$scripts = Join-Path $env:TEMP 'hydir-snapshot-scripts'
New-Item -ItemType Directory -Force -Path $scripts | Out-Null
Copy-Item -LiteralPath (Resolve-Path '.\integrations\ghidra\HydIRSnapshot.java').Path `
  -Destination (Join-Path $scripts 'HydIRSnapshot.java') -Force
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
The isolated script directory keeps Ghidra from compiling unrelated extension
and legacy exporter Java files during this manual run.

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
tool version. The desktop workbench also records each validated
selected-function snapshot in its local project database. Identical results
are deduplicated; saved content is hash checked and tied to the opened ELF
digest. A project-save warning does not hide a successfully analyzed
function. The database schema is v5; back up the database before opening it
with an older Hydir build.
The `ghidra-project save|get` commands and `LocalGhidra.save_snapshot` /
`saved_snapshot` allow an external script to preserve and reopen the same
validated snapshot without rerunning Ghidra. `HYDIR_LOCAL_DB` can point to an
absolute alternate database path for isolated projects or tests.
Schema v2 optionally carries analyzed memory block ranges and permissions,
plus defined program and external symbols with source, type, and namespace
evidence. Older v2 snapshots without these arrays still import. Metadata is
evidence for analysis, not lifted machine semantics. The desktop P-code view
lists the memory map and symbols; RAM entries link to the selected source
address.
Function entries may also carry bounded Ghidra signature, parameter, return
type, calling convention, and type-kind evidence. The exporter omits default
signatures, and old v2 snapshots without prototypes remain valid. Hydir keeps
analysis-derived signatures as evidence. Imported or user-defined signatures
become model prototypes only when every type maps unambiguously and the pinned
Ghidra language/compiler convention maps to the ELF ABI. Ghidra 12.1.4 calls
the default convention in its x86-64 gcc spec `__stdcall`, although that spec
uses the System V AMD64 argument registers; the convention name alone is not
an ABI proof.
The checked-in `tests/fixtures/ghidra_prototype.elf` and its snapshot were
produced from `tests/fixtures/ghidra_prototype.c` with Clang 22.1.8:

```powershell
clang -target x86_64-unknown-linux-gnu -g -O1 -fno-omit-frame-pointer -nostdlib -fuse-ld=lld '-Wl,-e,_start' '-Wl,--build-id=none' -o tests\fixtures\ghidra_prototype.elf tests\fixtures\ghidra_prototype.c
```

The ELF SHA-256 is `9234e3336c9439dc9da001709156cd48f5bf1aedb4725a0534144a909acac61f`.
`slice` follows a bounded backward chain of P-code value dependencies and
reports constants, entry values, control merges, memory, and opaque effects as
boundaries. It keeps source operation addresses and never marks a path proven.
The CFG artifact joins instruction nodes to analyzed edges and keeps calls
separate. Its completeness is explicitly `incomplete`, including when all
visible edges have concrete targets.
`coverage` inventories every raw P-code operation by opcode and distinguishes
pure assignments modelled exactly under Hydir's P-code rules from opaque
effects. Its bounded opaque-site list links source addresses to reasons. These
counts do not establish equivalence to machine code. The same report is
available from `LocalGhidra.artifact("coverage", ...)` and the desktop P-code
view.
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

`llvm-cfg` emits a runnable, bounded CFG path module for the selected function
with an optional instruction start. Its compact `byte_map` indexes separate
state and known-byte arrays. Artifact v2 adds one guest RAM window: the
`guest_ram` and `guest_known` arrays contain `guest_len` bytes starting at
`guest_base`, and `guest_space_id` is Ghidra's numeric RAM space ID. A known
byte is `0xff`; the runtime accepts up to the artifact's
`guest_ram_limit_bytes` (1 MiB minus mapped state bytes). The entry is
`@hydir_pcode_cfg(ptr state, ptr known, i32 guest_space_id, ptr guest_ram,
ptr guest_known, i64 guest_base, i64 guest_len, ptr events, ptr event_count,
i32 event_capacity, i32 max_steps)`. It logs successful operation IDs and
returns a numeric stop status. Known RAM loads/stores can execute; unknown
addresses or bytes, wrong spaces, out-of-range accesses, calls, and unresolved
flow stop explicitly. Source operations and static stop sites map back to
Ghidra addresses. The module remains `semantic_fidelity: unknown` and
`verification: not_run`; `opt` verification and fixture comparisons do not
prove arbitrary whole-function equivalence. The Python SDK exposes this as
`LocalGhidra.llvm_cfg(...)`, and the desktop P-code view can generate and copy
the same CFG LLVM.

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
