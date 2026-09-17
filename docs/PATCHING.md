# Scalar whole-function patch v1

This is a deliberately small, C-compatible `return`-expression subset, not
the full IRENE PatchLang, general C parsing, or a live-process patcher. The
parser and x86-64 lowering are first-party Rust. It accepts a JSON document:

```json
{
  "schema_version": 1,
  "binary_sha256": "<64 lowercase hex characters>",
  "function_symbol": "hydir_example",
  "prototype": "u64(u64,u64)",
  "replacement": "return arg0 - arg1;"
}
```

The C-like grammar is `return atom;` or `return atom + atom;` or
`return atom - atom;`, where atoms are `arg0`, `arg1`, or exact unsigned
decimal/`0x` literals. The encoder currently lowers only `arg0`, `arg1`,
a constant, `arg0 + arg1`, `arg0 - arg1`, and `arg1 - arg0`. Other parsed
expressions are rejected before any output is created. Parser failures give
replacement line/column positions; malformed JSON gives JSON positions.

The target must be a linked little-endian x86-64 ELF with one sized `.text`
symbol. Its original function must pass the scalar `u64(u64,u64)` lift gate.
The replacement must fit wholly inside that symbol's file-backed extent,
which must contain no relocations. Unused bytes become NOPs. The original
ELF is never changed; local and remote operations create a separate ELF.
An analyst must assert that all external transfers enter at the function
entry, with no edges into the region interior. HydIR does **not** prove
that assumption; using the patch on arbitrary programs is unsafe.

Local CLI:

```sh
hydirctl patch input.elf patch.json --trusted-fixture --assume-u64x2 --assume-entry-only --output patched.elf
```

Remote CLI, after an explicit project upload:

```sh
hydirctl remote patch PROJECT_ID REVISION patch.json IDEMPOTENCY_KEY --trusted-fixture --assume-u64x2 --assume-entry-only --output patched.elf
```

The remote operation requires the owning identity and current revision,
checks the JSON's input hash in a bounded child worker, commits the patched
binary as a new project revision, and stores the ELF as an owner-scoped
SHA-256 artifact. Retrying the same idempotency key and request returns the
same revision and bytes, including after restart. It never executes the
sample. Output path existence is checked before the CLI sends a remote
mutation, and local files are never overwritten. The remote worker output
limit is 16 MiB, below the general upload limit.

`bash scripts/demo-patch.sh` runs four intentional subtraction cases, saves
their native/patched outputs, and checks unchanged stderr/exit behavior plus
size, hash, and overwrite refusals. `bash scripts/demo-remote.sh` exercises
owner isolation, idempotent patch replay after restart, a new binary revision,
and patched behavior. These observations are not a whole-program patch
correctness proof or a claim about unsupported inputs.
