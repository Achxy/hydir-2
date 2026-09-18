#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cli="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"
python="${HYDIR_TRITON_PYTHON:-python3}"
demo_dir="${CARGO_TARGET_DIR:-$repo_dir/target}/demo-triton"

if [[ ! -x "$cli" ]]; then
  cargo build --locked --bin hydirctl
fi
if ! "$python" -c 'import triton' >/dev/null 2>&1; then
  echo "Triton Python bindings are required; set HYDIR_TRITON_PYTHON" >&2
  exit 2
fi

mkdir -p "$demo_dir"
clang -O0 -no-pie tests/fixtures/add2.S tests/fixtures/add2_main.c -o "$demo_dir/add2"
clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_max2 tests/fixtures/max2.S tests/fixtures/scalar_main.c -o "$demo_dir/max2"
"$cli" triton "$demo_dir/add2" hydir_add2 > "$demo_dir/add2.json"
"$cli" triton "$demo_dir/max2" hydir_max2 > "$demo_dir/max2.json"
"$python" - "$demo_dir/add2.json" "$demo_dir/max2.json" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    report = json.load(open(path, encoding="utf-8"))
    assert report["backend"] == "triton"
    assert report["architecture"] == "x86_64"
    assert report["instructions"]
    assert "rax" in report["final_registers"]
print("Triton ELF symbolic bridge: PASS")
PY
