#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "demo-local requires a Linux x86-64 host (or container)" >&2
  exit 2
fi

demo_base="${HYDIR_DEMO_DIR:-$repo_dir/target/demo-local}"
mkdir -p "$demo_base"
demo_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
echo "HydIR demo artifacts: $demo_dir"
clang -O0 -no-pie tests/fixtures/add2.S tests/fixtures/add2_main.c -o "$demo_dir/add2-original"
clang -c tests/fixtures/unsupported.S -o "$demo_dir/unsupported.o"
cargo build --locked --bin hydirctl
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" inspect "$demo_dir/add2-original" > "$demo_dir/program-spec.json"
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" lift "$demo_dir/add2-original" hydir_add2 --assume-u64x2 --output "$demo_dir/add2-lifted.ll"
if "${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" lift "$demo_dir/unsupported.o" hydir_unsupported --assume-u64x2 > "$demo_dir/unsupported.ll" 2> "$demo_dir/unsupported-diagnostic.txt"; then
  echo "unsupported fixture unexpectedly lifted" >&2
  exit 1
fi
grep -q 'unsupported Push' "$demo_dir/unsupported-diagnostic.txt"
if command -v opt >/dev/null 2>&1; then
  opt -passes=verify -disable-output "$demo_dir/add2-lifted.ll"
fi
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" validate "$demo_dir/add2-original" hydir_add2 --assume-u64x2 --trusted-fixture --clang clang > "$demo_dir/differential-report.json"
sed -n '1,80p' "$demo_dir/differential-report.json"
