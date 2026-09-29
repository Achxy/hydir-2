#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Real-ELF stress gate requires Linux x86-64.' >&2
  exit 2
fi
for tool in clang gcc python3 /usr/bin/time; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

fixture="fuzz/corpus/elf_import/go_real_stripped.elf"
[[ -f "$fixture" ]] || { echo "missing pinned fixture: $fixture" >&2; exit 2; }
mkdir -p target/demo-real-elf-stress
run_dir="$(mktemp -d target/demo-real-elf-stress/run.XXXXXX)"

cargo build --locked --release -q -p hydir-cli
hydirctl="${CARGO_TARGET_DIR:-target}/release/hydirctl"
/usr/bin/time -f '%e %M' -o "$run_dir/coverage.metrics" \
  "$hydirctl" coverage "$fixture" > "$run_dir/coverage.json"
/usr/bin/time -f '%e %M' -o "$run_dir/decompile.metrics" \
  "$hydirctl" decompile-all "$fixture" --output-dir "$run_dir/decompiled" \
  > "$run_dir/manifest.json"

# This held-out ELF must produce byte-for-byte stable artifacts on a fresh
# second run. Measure both passes; timing and RSS are evidence, not thresholds.
/usr/bin/time -f '%e %M' -o "$run_dir/coverage-repeat.metrics" \
  "$hydirctl" coverage "$fixture" > "$run_dir/coverage-repeat.json"
/usr/bin/time -f '%e %M' -o "$run_dir/decompile-repeat.metrics" \
  "$hydirctl" decompile-all "$fixture" --output-dir "$run_dir/decompiled-repeat" \
  > "$run_dir/manifest-repeat.json"

python3 - "$run_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def tree_sha(directory):
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        if path.is_file():
            digest.update(path.relative_to(directory).as_posix().encode())
            digest.update(b'\0')
            digest.update(bytes.fromhex(sha(path)))
    return digest.hexdigest()

if sha(root / 'coverage.json') != sha(root / 'coverage-repeat.json'):
    raise SystemExit('held-out coverage output changed between identical runs')
if sha(root / 'manifest.json') != sha(root / 'manifest-repeat.json'):
    raise SystemExit('held-out manifest changed between identical runs')
first_tree = tree_sha(root / 'decompiled')
if first_tree != tree_sha(root / 'decompiled-repeat'):
    raise SystemExit('held-out decompilation artifacts changed between identical runs')

def metrics(name):
    seconds, max_rss_kib = (root / f'{name}.metrics').read_text().split()
    return {'elapsed_ms': round(float(seconds) * 1000),
            'peak_rss_kib': int(max_rss_kib)}

report = {
    'schema_version': 1,
    'binary_sha256': hashlib.sha256(pathlib.Path('fuzz/corpus/elf_import/go_real_stripped.elf').read_bytes()).hexdigest(),
    'coverage_sha256': sha(root / 'coverage.json'),
    'manifest_sha256': sha(root / 'manifest.json'),
    'artifact_tree_sha256': first_tree,
    'runs': {name: metrics(name) for name in
             ('coverage', 'decompile', 'coverage-repeat', 'decompile-repeat')},
}
(root / 'determinism.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
PY

python3 - "$run_dir" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
coverage = json.loads((root / "coverage.json").read_text())
expected = {
    "discovered_functions": 1481,
    "attempted_functions": 1481,
    "lifted_functions": 1481,
    "exact_functions": 157,
    "conservative_functions": 1324,
    "partial_functions": 4,
    "exact_instructions": 116592,
    "opaque_instructions": 37,
}
for field, value in expected.items():
    if coverage[field] != value:
        raise SystemExit(
            f"real-ELF stress {field} changed: expected {value}, got {coverage[field]}"
        )
if set(coverage["opaque_families"]) != {"syscall"}:
    raise SystemExit("real-ELF stress gained an unexpected opaque instruction family")

manifest = json.loads((root / "manifest.json").read_text())
results = manifest["results"]
if len(results) != 1481:
    raise SystemExit(f"expected 1481 batch results, got {len(results)}")
output = root / "decompiled"
for item in results:
    if item["status"] != "decompiled":
        raise SystemExit(f"function did not decompile: {item}")
    for field in ("low_level_c", "unit"):
        if not (output / item[field]).is_file():
            raise SystemExit(f"missing {field} artifact for {item['function_id']}")
structured = sum(item["structured_c"] is not None for item in results)
if structured != 165:
    raise SystemExit(f"expected 165 structured views, got {structured}")
PY

c_sources=0
while IFS= read -r -d '' source; do
  c_sources=$((c_sources + 1))
  clang -std=c11 -Wall -Wextra -Werror -c "$source" -o "$source.clang.o"
  gcc -std=c11 -Wall -Wextra -Werror -c "$source" -o "$source.gcc.o"
done < <(find "$run_dir/decompiled" -type f -name '*.c' -print0)

python3 - "$run_dir" "$c_sources" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
c_sources = int(sys.argv[2])
if c_sources != 1646:
    raise SystemExit(f"expected 1646 C translation units, compiled {c_sources}")
coverage = json.loads((root / "coverage.json").read_text())
summary = {
    "schema_version": 1,
    "binary_sha256": coverage["binary_sha256"],
    "functions_decompiled": 1481,
    "low_level_c_compiled_by_clang_and_gcc": 1481,
    "structured_c_compiled_by_clang_and_gcc": 165,
    "exact_instructions": coverage["exact_instructions"],
    "opaque_instructions": coverage["opaque_instructions"],
    "opaque_families": coverage["opaque_families"],
    "determinism": json.loads((root / "determinism.json").read_text()),
}
(root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
print(json.dumps(summary, sort_keys=True))
PY

echo "real-ELF stress gate passed: $run_dir"
