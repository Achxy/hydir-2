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
fixed, aligned 64-bit spills and reloads, so the scalar pair fixture emits
typed C at both `-O0` and `-O2`. It carries instruction-address
provenance and produces a C11 typed view with checked field offsets. Branches,
calls, indexed accesses, unsupported widths, and opaque effects currently
return a diagnostic. The native `low` and `structured` views remain available
for those functions. Typed C is marked semantically conservative and never
rewrite ready; the source-level view does not model all machine fault and
environment behavior.

The v3 API and Python SDK expose `analysis_model`, `high_level_cir`, and
`typed_c` read artifacts. Each artifact uses the same bounded automatic model
for the current binary revision, so `HighLevelCIR.model_revision` matches the
model artifact's `revision`. The desktop native explorer has Typed C and Types
tabs; selecting a type evidence or C statement address links to the existing
MachineIR and Evidence views. A saved local project model takes precedence in
the desktop view. Remote model edits and server-side artifact caching are later
work.
