# Typed models: from evidence to C

An AnalysisModel v1 is tied to one ELF SHA-256. It records names, prototypes, stack objects, and named types alongside evidence. A type edit changes the interpretation used by typed output; it does not change the executable.

## Build and verify a model

Use fresh output paths at each stage. The following commands assume `hydirctl` is on PATH; from a checkout, prefix them with `cargo run --locked --bin hydirctl --`.

```text
hydirctl model init program.elf --output model.json
hydirctl model import-dwarf program.elf model.json --output model-dwarf.json
hydirctl model infer program.elf model-dwarf.json --output model-inferred.json
hydirctl model verify program.elf model-inferred.json
hydirctl decompile program.elf --function some_function --view typed --model model-inferred.json
```

DWARF import requires usable debug information. A stripped binary may have no DWARF to import. Keep the initial model and inspect the import report before inference. Function selectors identify a real discovered function; `some_function` is a placeholder, not a built-in example.

## Import Ghidra prototype evidence

A validated snapshot can contribute function/type evidence:

```text
hydirctl model import-ghidra program.elf model.json snapshot.json --output model-ghidra.json
hydirctl model verify program.elf model-ghidra.json
```

The snapshot must match the ELF. A calling-convention spelling alone is not an ABI proof. A prototype must have unambiguous supported types and a convention compatible with the binary. Raw P-code remains the semantic input; decompiler hints remain evidence.

## Understand evidence and conflicts

Model evidence distinguishes ELF metadata, DWARF, Ghidra analysis, native analysis, analyst assertions, and legacy typed models. An address can connect a fact to its source instruction. Inference must not silently overwrite analyst assertions or turn an unresolved observation into proof.

| Observation | What follows | What does not follow |
| --- | --- | --- |
| Fixed offset load through a pointer | Evidence of a field access | Full aggregate size or source field name |
| Indexed load | Evidence of a stride or element access | Runtime bounds or a proven array length |
| Compatible callee constraints | A bounded inference opportunity | A complete interprocedural type proof |
| Analyst name/type edit | A saved interpretation | Machine-derived correctness |

Named primitives, pointers, arrays, structs, unions, enums, and aliases let the model describe layouts while retaining unresolved facts. The parser limits model JSON to 16 MiB; named types, functions, fields, and imported hints have additional caps.

## Inspect high-level artifacts

```text
hydirctl lift program.elf --function some_function --ir high-level --model model-inferred.json
hydirctl lift program.elf --function some_function --ir high-level-cfg --model model-inferred.json
```

The linear and CFG paths have different supported subsets. A typed view may name fields and expose source-like decisions, but raw loads, labels, or a refusal can remain when the evidence is insufficient. Native low-level output is available separately:

```text
hydirctl decompile program.elf --function some_function --view low
hydirctl decompile program.elf --function some_function --view unit
```

Read instruction provenance, diagnostics, semantic fidelity, and rewrite readiness with the C. A successful C rendering is not authorization to replace the original function.

## Save analyst edits in a local project

```text
hydirctl local project program.elf
hydirctl local model-put program.elf REVISION UNIQUE_REQUEST_KEY model-inferred.json
hydirctl local model program.elf
hydirctl local decompile-typed program.elf some_function
```

Replace `REVISION` with the revision returned by the project command and choose a unique request key. Stale revisions are rejected. A different ELF digest starts a different model view. In the desktop, Types and Typed C provide the same evidence-oriented navigation; selecting a statement or evidence address links back to machine instructions.

## Remote model lifecycle

The SDK exposes `get_analysis_model` and `save_analysis_model`. Read the current project revision, increment the model's own revision as required, and save with an idempotency key. A retry of an uncertain save reuses that key. After the saved revision is read back, request typed C for that revision.

See the [SDK guide](/docs/python-sdk) for method contracts and the [service guide](/docs/service) for project revisions.

## Implementation references

- [Model schema and validation](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-model/src/lib.rs)
- [CLI commands](https://github.com/Achxy/hydir-2/blob/main/crates/hydir-cli/src/main.rs)

These references identify the implementation behind the guide; the workflow above is available entirely on this site.
