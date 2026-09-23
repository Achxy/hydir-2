# Typed native decompilation

Hydir's editable `AnalysisModel v1` is a JSON artifact bound to the SHA-256 of
one ELF. It holds function names and prototypes, stack objects, and named
primitive, pointer, array, struct, union, enum, and alias types. Each model
fact carries evidence. Native inference records a partial aggregate size as
an observed lower bound; it does not claim the end of the object was found.

```text
hydirctl model init program.elf --output model.json
hydirctl model import-dwarf program.elf model.json --output model-dwarf.json
hydirctl model infer program.elf model-dwarf.json --output model-inferred.json
hydirctl model verify program.elf model-inferred.json
hydirctl lift program.elf --function some_function --ir high-level --model model-inferred.json
hydirctl lift program.elf --function some_function --ir high-level-cfg --model model-inferred.json
hydirctl decompile program.elf --function some_function --view typed --model model-inferred.json
```

Each output file must be new or byte-identical to an existing file. The model
can be edited as JSON and verified before reuse. The `infer` command analyzes
at most 256 discovered functions and reports lift failures, bounds, and type
conflicts. DWARF import supports bounded ELF debug sections, relocations,
fixed member offsets, supported primitive/pointer/array types, recursive
aggregates, and fixed SysV function prototypes. Unsupported debug expressions
and unresolved type references remain unimported.

Native inference follows unchanged pointer arguments through resolved direct
calls. It merges compatible callee field constraints into the caller's partial
aggregate to a bounded fixed point, including recursive call components.
When a loaded 64-bit field is passed to a resolved callee whose argument is
independently inferred as an aggregate pointer, inference can type that field
as a pointer, including a recursive `next` field. Competing callee pointer
types leave the field unresolved and record the conflict.
Overlapping or incompatible constraints become visible conflicts. Indexed
accesses do not establish array bounds without other evidence; bounded DWARF
is the current source of proven array sizes.

To keep analyst edits in the local project, use `hydirctl local project
program.elf` to obtain its current revision, then `hydirctl local model-put
program.elf <revision> <idempotency-key> model-inferred.json`. `hydirctl local
model program.elf` reads the saved model, and `hydirctl local decompile-typed
program.elf <function>` uses it. The private SQLite project checks the ELF
digest and expected revision, records each model edit as a new revision, and
rejects stale writes. An ELF change starts a fresh digest-scoped model view.
The local typed-C cache checks content hashes and keys entries by binary
digest, model revision, analysis version, options, and function entry. On a
model edit it carries only entries whose referenced types, own function facts,
and transitive callees are unchanged.
Local model saves mark changed facts as analyst assertions while retaining
earlier native and DWARF evidence, even when an editor omits it from the JSON.
An analyst field type that differs from the previous model type also creates
a visible conflict with the earlier evidence. New DWARF and native facts keep
their original source labels.

`HighLevelCIR v1` lowers complete, linear functions whose supported 64-bit
operations have exact native effects. It recognizes a closed `rbp` frame with
fixed, aligned 64-bit spills and reloads, and balanced stack adjustment.
Resolved direct calls with a fixed, explicit SysV prototype become C call
expressions; their caller-saved registers are invalidated. The scalar pair
and direct-call fixtures emit typed C at both `-O0` and `-O2`. It carries
instruction-address provenance and produces a C11 typed view with checked
field offsets. `HighLevelCfgCir v3` covers a separate bounded 64-bit subset
with direct branches, joins, loops, and normalized `mov` loads/stores. It snapshots
live comparison operands and arithmetic results from normalized ExpressionIR
zero-flag assignments. A 64-bit `sub` snapshots its ordered operands before
the destination write, so subsequent signed and unsigned comparisons can use
the same predicate as `cmp`, including when both paths join before a branch.
The C11 renderer folds
single-entry chains, private diamonds, and simple pre-test loops into readable
statements. Other control flow retains explicit gotos. A flag snapshot is
inlined into a condition only when that branch is its sole reader. The typed
command and desktop view try v1 first,
then v3; the local project caches v1 output and regenerates v3 output. Both
artifacts retain instruction sites. The CFG subset emits bytewise little-endian
C11 helpers for its 64-bit memory accesses and carries ExpressionIR alias-region
versions on each load/store. A validated pointer-to-struct or pointer-to-union
parameter can name a fixed 64-bit field across CFG branches and loops when its
base register is unchanged throughout the function. The generated address uses
`offsetof` and the model's layout assertions while the bytewise helper preserves
unaligned and alias-safe access. A modeled fixed-size array field with eight-byte
elements can also name indexed loads and stores; the address retains the exact
index arithmetic and uses `sizeof` for the modeled element. This annotation does
not establish that a runtime index is in bounds. An array of named structs can
identify one eight-byte element field when the element has an exact modeled
size and a stable integer parameter or a single entry-block assignment proves
the effective index stride. The emitted C names the parent array and nested
field through `offsetof` and ties the stride to `sizeof` the element type.
A modified pointer or index, unsupported
stride, overlapping union interpretation, or unmatched width stays as a raw
memory access. It still rejects other memory operations, calls,
unsupported flag origins, opaque effects, and non-64-bit operands. The native
`low` and `structured` views remain available for those
functions. Typed C is marked semantically conservative and never rewrite
ready; the source-level view does not model all machine fault and environment
behavior.

The CFG lowerer consumes freshly computed `ExpressionIR v1` assignments for
supported scalar register writes, including the `xor reg, reg` zeroing idiom.
It also checks normalized zero-flag assignments and branch conditions, so
`jz`/`jnz` after supported 64-bit arithmetic can be rendered and tested.
Dead flag snapshots are omitted. Signed, carry, and compound branch conditions
use the bounded compare/test/subtract interpretation; arbitrary flag SSA and
other arithmetic carry/overflow sources remain future work. The memory helpers use integer-to-pointer
conversion in the supported x86-64 execution environment. The CFG lowerer also
handles normalized 64-bit `lea` expressions. A single-write register derived
in the entry block from an unchanged pointer parameter by a copy or constant
offset can carry that parameter's modeled field names through branches and
loops. The field annotation records the derived register and offset; emission
checks its dominating assignment and keeps the register in the C address.
Derived pointers from later blocks, changing bases, and struct arrays without
a proven index multiplier remain raw in the CFG view. Absolute memory addresses
remain unsupported until their ELF load bias is represented in the C view.

The v3 API and Python SDK expose `analysis_model`, `high_level_cir`,
`high_level_cfg_cir`, and `typed_c` read artifacts. Each artifact uses the same bounded automatic model
for the current binary revision, so `HighLevelCIR.model_revision` matches the
model artifact's `revision`. The desktop native explorer has Typed C and Types
tabs; selecting a type evidence or C statement address links to the existing
MachineIR and Evidence views. A saved local project model takes precedence in
the desktop view. Remote model edits and server-side artifact caching are later
work.
