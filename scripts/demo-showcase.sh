#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "demo-showcase requires Linux x86-64 (or the pinned Docker image)" >&2
  exit 2
fi

demo_base="${HYDIR_SHOWCASE_DIR:-$repo_dir/target/demo-showcase}"
mkdir -p "$demo_base"
run_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
echo "HydIR showcase artifacts: $run_dir"

clang -nostdlib -no-pie -Wl,--build-id=none -Wl,-e,_start \
  tests/fixtures/hydir_showcase.S -o "$run_dir/hydir-showcase"
cargo build --locked --bin hydirctl
client="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"

printf 'HYDR' | "$run_dir/hydir-showcase" > "$run_dir/original-good.out"
printf 'NOPE' | "$run_dir/hydir-showcase" > "$run_dir/original-bad.out"
grep -q 'ACCESS GRANTED' "$run_dir/original-good.out"
grep -q 'ACCESS DENIED' "$run_dir/original-bad.out"

"$client" inspect "$run_dir/hydir-showcase" > "$run_dir/inspect.json"
"$client" analyze "$run_dir/hydir-showcase" > "$run_dir/analyze.json"
"$client" cfg "$run_dir/hydir-showcase" hydir_max2 > "$run_dir/max2-cfg.json"
"$client" lift "$run_dir/hydir-showcase" hydir_max2 --assume-u64x2 \
  --output "$run_dir/max2.ll"
"$client" decompile "$run_dir/hydir-showcase" hydir_max2 --assume-u64x2 \
  --output "$run_dir/max2.c"

max_digest="$(sha256sum "$run_dir/hydir-showcase" | awk '{print $1}')"
printf '{"schema_version":1,"binary_sha256":"%s","function_symbol":"hydir_max2","prototype":"u64(u64,u64)","replacement":"return arg0 - arg1;"}\n' \
  "$max_digest" > "$run_dir/patch.json"
"$client" patch "$run_dir/hydir-showcase" "$run_dir/patch.json" \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$run_dir/patched"
printf 'HYDR' | "$run_dir/patched" > "$run_dir/patched-good.out"
grep -q 'ACCESS DENIED' "$run_dir/patched-good.out"

"$client" rebuild "$run_dir/hydir-showcase" --trusted-fixture \
  --output-dir "$run_dir/rebuilt"
for input in HYDR NOPE; do
  printf '%s' "$input" | "$run_dir/hydir-showcase" > "$run_dir/original-$input.out"
  printf '%s' "$input" | "$run_dir/rebuilt/rebuilt" > "$run_dir/rebuilt-$input.out"
  cmp "$run_dir/original-$input.out" "$run_dir/rebuilt-$input.out"
done

echo "showcase passed"
echo "good input: HYDR -> $(tail -n 1 "$run_dir/original-good.out")"
echo "patched HYDR -> $(tail -n 1 "$run_dir/patched-good.out")"
echo "rebuilt binary matches original for HYDR and NOPE"
