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
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" decompile "$demo_dir/add2-original" hydir_add2 --assume-u64x2 --output "$demo_dir/add2.c"
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" validate-c "$demo_dir/add2-original" hydir_add2 --assume-u64x2 --trusted-fixture --clang clang > "$demo_dir/add2-c-differential-report.json"
for fixture in max2 signed_max2 repeat16; do
  symbol="hydir_$fixture"
  clang -O0 -no-pie -DHYDIR_FUNCTION="$symbol" \
    "tests/fixtures/$fixture.S" tests/fixtures/scalar_main.c \
    -o "$demo_dir/$fixture-original"
  "${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" lift \
    "$demo_dir/$fixture-original" "$symbol" --assume-u64x2 \
    --output "$demo_dir/$fixture-lifted.ll"
  "${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" cfg \
    "$demo_dir/$fixture-original" "$symbol" > "$demo_dir/$fixture-cfg.json"
  if command -v opt >/dev/null 2>&1; then
    opt -passes=verify -disable-output "$demo_dir/$fixture-lifted.ll"
  fi
  "${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" validate \
    "$demo_dir/$fixture-original" "$symbol" --assume-u64x2 \
    --trusted-fixture --clang clang > "$demo_dir/$fixture-differential-report.json"
  "${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" decompile \
    "$demo_dir/$fixture-original" "$symbol" --assume-u64x2 \
    --output "$demo_dir/$fixture.c"
  "${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" validate-c \
    "$demo_dir/$fixture-original" "$symbol" --assume-u64x2 \
    --trusted-fixture --clang clang > "$demo_dir/$fixture-c-differential-report.json"
done
read -r max_entry_hex max_size_hex < <(nm -S --defined-only "$demo_dir/max2-original" | awk '$4 == "hydir_max2" {print $1, $2}')
if [[ -z "${max_entry_hex:-}" || -z "${max_size_hex:-}" ]]; then
  echo "could not identify max2 fixture entry before stripping" >&2
  exit 1
fi
max_size_bytes=$((16#$max_size_hex))
cp "$demo_dir/max2-original" "$demo_dir/max2-stripped"
strip --strip-all "$demo_dir/max2-stripped"
if nm "$demo_dir/max2-stripped" 2>/dev/null | grep -q hydir_max2; then
  echo "stripped fixture still contains the hydir_max2 symbol" >&2
  exit 1
fi
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" cfg-at \
  "$demo_dir/max2-stripped" "0x$max_entry_hex" "$max_size_bytes" \
  > "$demo_dir/max2-stripped-cfg.json"
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" lift-at \
  "$demo_dir/max2-stripped" "0x$max_entry_hex" "$max_size_bytes" \
  --assume-u64x2 --output "$demo_dir/max2-stripped-lifted.ll"
if command -v opt >/dev/null 2>&1; then
  opt -passes=verify -disable-output "$demo_dir/max2-stripped-lifted.ll"
fi
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" validate-at \
  "$demo_dir/max2-stripped" "0x$max_entry_hex" "$max_size_bytes" \
  --assume-u64x2 --trusted-fixture --clang clang \
  > "$demo_dir/max2-stripped-differential-report.json"
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" decompile-at \
  "$demo_dir/max2-stripped" "0x$max_entry_hex" "$max_size_bytes" \
  --assume-u64x2 --output "$demo_dir/max2-stripped.c"
"${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl" validate-c-at \
  "$demo_dir/max2-stripped" "0x$max_entry_hex" "$max_size_bytes" \
  --assume-u64x2 --trusted-fixture --clang clang \
  > "$demo_dir/max2-stripped-c-differential-report.json"
for report in "$demo_dir"/*differential-report.json; do
  echo "$report"
  sed -n '1,24p' "$report"
done
