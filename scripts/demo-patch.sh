#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'patch behavior gate requires Linux x86-64' >&2
  exit 2
fi
mkdir -p target/demo-patch
run_dir="$(mktemp -d target/demo-patch/run.XXXXXX)"
cargo build --locked -q -p hydir-cli
client="${CARGO_TARGET_DIR:-target}/debug/hydirctl"

clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_patch_target \
  tests/fixtures/patch_target.S tests/fixtures/scalar_main.c \
  -o "$run_dir/original"
digest="$(sha256sum "$run_dir/original" | awk '{print $1}')"
printf '{"schema_version":1,"binary_sha256":"%s","function_symbol":"hydir_patch_target","prototype":"u64(u64,u64)","replacement":"return arg0 - arg1;"}\n' \
  "$digest" > "$run_dir/patch.json"
"$client" patch "$run_dir/original" "$run_dir/patch.json" \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$run_dir/patched" > "$run_dir/patch-report.json"
test -x "$run_dir/patched"
test "$(sha256sum "$run_dir/patched" | awk '{print $1}')" != "$digest"

printf 'arg0\targ1\toriginal\texpected_patched\tobserved_patched\texit\tstderr_bytes\n' > "$run_dir/cases.tsv"
case_index=0
for input_pair in '9 4 5' '4 9 18446744073709551611' '0 0 0' \
                  '18446744073709551615 1 18446744073709551614'; do
  case_index=$((case_index + 1))
  read -r input_a input_b expected <<< "$input_pair"
  "$run_dir/original" "$input_a" "$input_b" > "$run_dir/original-$case_index.out" 2> "$run_dir/original-$case_index.err"
  "$run_dir/patched" "$input_a" "$input_b" > "$run_dir/patched-$case_index.out" 2> "$run_dir/patched-$case_index.err"
  original="$(tr -d '\n' < "$run_dir/original-$case_index.out")"
  observed="$(tr -d '\n' < "$run_dir/patched-$case_index.out")"
  test "$observed" = "$expected"
  test ! -s "$run_dir/patched-$case_index.err"
  test ! -s "$run_dir/original-$case_index.err"
  printf '%s\t%s\t%s\t%s\t%s\t0\t0\n' "$input_a" "$input_b" "$original" "$expected" "$observed" >> "$run_dir/cases.tsv"
done
test "$(sed -n '2p' "$run_dir/cases.tsv" | cut -f3)" != "$(sed -n '2p' "$run_dir/cases.tsv" | cut -f5)"

if "$client" patch "$run_dir/original" "$run_dir/patch.json" \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$run_dir/patched" > "$run_dir/overwrite.out" 2> "$run_dir/overwrite.err"; then
  echo 'patch unexpectedly overwrote existing artifact' >&2
  exit 1
fi
grep -q 'refusing to overwrite' "$run_dir/overwrite.err"

clang -O0 -no-pie tests/fixtures/add2.S tests/fixtures/add2_main.c \
  -o "$run_dir/add2-original"
small_digest="$(sha256sum "$run_dir/add2-original" | awk '{print $1}')"
printf '{"schema_version":1,"binary_sha256":"%s","function_symbol":"hydir_add2","prototype":"u64(u64,u64)","replacement":"return 18446744073709551615;"}\n' \
  "$small_digest" > "$run_dir/oversize.json"
if "$client" patch "$run_dir/add2-original" "$run_dir/oversize.json" \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$run_dir/oversize-patched" > "$run_dir/oversize.out" 2> "$run_dir/oversize.err"; then
  echo 'oversize patch unexpectedly accepted' >&2
  exit 1
fi
grep -q 'replacement needs 11 bytes' "$run_dir/oversize.err"
test ! -e "$run_dir/oversize-patched"

printf '{"schema_version":1,"binary_sha256":"%064d","function_symbol":"hydir_patch_target","prototype":"u64(u64,u64)","replacement":"return arg0 - arg1;"}\n' 0 > "$run_dir/wrong-hash.json"
if "$client" patch "$run_dir/original" "$run_dir/wrong-hash.json" \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$run_dir/wrong-hash-patched" > "$run_dir/wrong-hash.out" 2> "$run_dir/wrong-hash.err"; then
  echo 'wrong-hash patch unexpectedly accepted' >&2
  exit 1
fi
test ! -e "$run_dir/wrong-hash-patched"
grep -q 'binary hash does not match' "$run_dir/wrong-hash.err"

echo "patch gate passed: 4 intentional behavior cases, unchanged stderr/exit, size/hash/overwrite refusals; $run_dir"
