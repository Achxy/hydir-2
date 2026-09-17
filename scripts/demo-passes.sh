#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "demo-passes requires Linux x86-64" >&2
  exit 2
fi
demo_base="${HYDIR_PASSES_DEMO_DIR:-$repo_dir/target/demo-passes}"
mkdir -p "$demo_base"
demo_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_max2 \
  tests/fixtures/max2.S tests/fixtures/scalar_main.c \
  -o "$demo_dir/max2-original"
cargo run --quiet --locked --bin hydirctl -- transform \
  "$demo_dir/max2-original" hydir_max2 --assume-u64x2 --trusted-fixture \
  --passes instcombine,sccp,simplifycfg,dce \
  --output-dir "$demo_dir/experiment" --opt opt > "$demo_dir/transform.json"
grep -q '"llvm_verified": true' "$demo_dir/transform.json"
grep -q '"ir_text_changed": true' "$demo_dir/transform.json"
if cmp -s "$demo_dir/experiment/before.ll" "$demo_dir/experiment/after.ll"; then
  echo "pass pipeline unexpectedly made no observable IR change" >&2
  exit 1
fi
clang -O0 -DHYDIR_FUNCTION=hydir_lifted \
  "$demo_dir/experiment/after.ll" tests/fixtures/scalar_main.c \
  -o "$demo_dir/transformed-runner"
cases=("0 0" "1 2" "2 1" "18446744073709551615 0" \
  "0 18446744073709551615" "9223372036854775808 1" "42 999" "999 42")
for pair in "${cases[@]}"; do
  read -r left right <<< "$pair"
  "$demo_dir/max2-original" "$left" "$right" > "$demo_dir/native.out" 2> "$demo_dir/native.err"
  "$demo_dir/transformed-runner" "$left" "$right" > "$demo_dir/transformed.out" 2> "$demo_dir/transformed.err"
  cmp "$demo_dir/native.out" "$demo_dir/transformed.out"
  cmp "$demo_dir/native.err" "$demo_dir/transformed.err"
done
echo "HydIR named LLVM pass pipeline passed: 8 trusted boundary inputs; artifacts: $demo_dir"
