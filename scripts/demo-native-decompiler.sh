#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Native decompiler gate requires Linux x86-64.' >&2
  exit 2
fi
for tool in clang gcc python3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

mkdir -p target/demo-native-decompiler
run_dir="$(mktemp -d target/demo-native-decompiler/run.XXXXXX)"
cargo build --locked -q -p hydir-cli
hydirctl="${CARGO_TARGET_DIR:-target}/debug/hydirctl"
fixtures=(
  fuzz/corpus/elf_import/max2.elf
  fuzz/corpus/elf_import/unwind_discovery_stripped.elf
  fuzz/corpus/elf_import/jump_table.elf
  fuzz/corpus/elf_import/relocatable_metadata.o
  fuzz/corpus/elf_import/relative_jump_table.o
  fuzz/corpus/elf_import/avx2_integer.o
  fuzz/corpus/elf_import/atomics.o
  fuzz/corpus/elf_import/string_ops.o
  fuzz/corpus/elf_import/tail_calls.o
  fuzz/corpus/elf_import/avx512_opaque.o
  fuzz/corpus/elf_import/bmi2_shifts.o
  fuzz/corpus/elf_import/scalar_float_moves.o
  fuzz/corpus/elf_import/scalar_float_arithmetic.o
  fuzz/corpus/elf_import/packed_float_arithmetic.o
  fuzz/corpus/elf_import/x87_common.o
  fuzz/corpus/elf_import/extended_state.o
  fuzz/corpus/elf_import/xsave_state.o
  fuzz/corpus/elf_import/system_state.o
  fuzz/corpus/elf_import/aligned_vectors.o
  fuzz/corpus/elf_import/cpp_rtti.o
  fuzz/corpus/elf_import/rust_real.o
  fuzz/corpus/elf_import/go_pclntab_stripped.elf
)

for fixture in "${fixtures[@]}"; do
  stem="$(basename "$fixture")"
  output="$run_dir/$stem"
  "$hydirctl" discover "$fixture" > "$run_dir/$stem.functions.json"
  "$hydirctl" coverage "$fixture" > "$run_dir/$stem.coverage.json"
  "$hydirctl" decompile-all "$fixture" --output-dir "$output"
done
"$hydirctl" discover fuzz/corpus/elf_import/unwind_discovery.elf \
  > "$run_dir/unwind-discovery-truth.functions.json"

# A second independent emission proves canonical output for the same digest.
"$hydirctl" decompile-all "${fixtures[0]}" --output-dir "$run_dir/determinism-a"
"$hydirctl" decompile-all "${fixtures[0]}" --output-dir "$run_dir/determinism-b"
diff -ru "$run_dir/determinism-a" "$run_dir/determinism-b"

c_sources=0
while IFS= read -r -d '' source; do
  c_sources=$((c_sources + 1))
  clang -std=c11 -Wall -Wextra -Werror -c "$source" -o "$source.clang.o"
  gcc -std=c11 -Wall -Wextra -Werror -c "$source" -o "$source.gcc.o"
done < <(find "$run_dir" -type f -name '*.c' -print0)

python3 - "$run_dir" "$c_sources" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
coverages = [json.loads(path.read_text()) for path in sorted(root.glob("*.coverage.json"))]
indexes = [json.loads(path.read_text()) for path in sorted(root.glob("*.functions.json"))]
if len(coverages) != 22 or len(indexes) != 23:
    raise SystemExit("native gate did not produce all coverage and FunctionIndex artifacts")
truth = json.loads((root / "unwind-discovery-truth.functions.json").read_text())
stripped = json.loads((root / "unwind_discovery_stripped.elf.functions.json").read_text())
truth_entries = {item["entry"]["value"] for item in truth["functions"]}
stripped_entries = {item["entry"]["value"] for item in stripped["functions"]}
true_positives = len(truth_entries & stripped_entries)
precision = true_positives / len(stripped_entries) if stripped_entries else 0.0
recall = true_positives / len(truth_entries) if truth_entries else 0.0
fixture_c_sources = sum(
    1
    for path in root.glob("*/*.c")
    if not path.parent.name.startswith("determinism-")
)
summary = {
    "schema_version": 1,
    "fixtures": len(coverages),
    "discovered_functions": sum(item["discovered_functions"] for item in coverages),
    "lifted_functions": sum(item["lifted_functions"] for item in coverages),
    "exact_functions": sum(item["exact_functions"] for item in coverages),
    "conservative_functions": sum(item["conservative_functions"] for item in coverages),
    "partial_functions": sum(item["partial_functions"] for item in coverages),
    "exact_instructions": sum(item["exact_instructions"] for item in coverages),
    "opaque_instructions": sum(item["opaque_instructions"] for item in coverages),
    "fixture_c_translation_units": fixture_c_sources,
    "c_translation_units_compiled_by_clang_and_gcc": int(sys.argv[2]),
    "deterministic_reemission": True,
    "controlled_stripped_function_precision": precision,
    "controlled_stripped_function_recall": recall,
}
expected = {
    "discovered_functions": 45,
    "lifted_functions": 45,
    "exact_functions": 21,
    "conservative_functions": 24,
    "partial_functions": 4,
    "exact_instructions": 430,
    "opaque_instructions": 6,
    "fixture_c_translation_units": 86,
    # Two max2 views are emitted twice more for the determinism comparison.
    "c_translation_units_compiled_by_clang_and_gcc": 90,
}
for field, value in expected.items():
    if summary[field] != value:
        raise SystemExit(
            f"native gate {field} changed: expected {value}, got {summary[field]}"
        )
if precision < 0.98 or recall < 0.90:
    raise SystemExit("controlled stripped discovery fell below its precision/recall gate")
(root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
PY

echo "native decompiler gate passed: $run_dir"
