#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Scalar corpus gate requires Linux x86-64.' >&2
  exit 2
fi
mkdir -p target/demo-corpus
run_dir="$(mktemp -d target/demo-corpus/run.XXXXXX)"
cargo build --locked -q -p hydir-cli
functions=(
  identity_a identity_b sub_ab sub_ba add3 twice_a twice_b
  min_u min_s equal not_equal less_u less_s bit_overlap repeat3 repeat4
)
printf 'function\tattempted\tmatched\tmismatched\n' > "$run_dir/ledger.tsv"
for function in "${functions[@]}"; do
  symbol="hydir_$function"
  clang -O0 -no-pie -DHYDIR_FUNCTION="$symbol" \
    tests/fixtures/scalar_corpus.S tests/fixtures/scalar_main.c \
    -o "$run_dir/$function-original"
  "${CARGO_TARGET_DIR:-target}/debug/hydirctl" lift "$run_dir/$function-original" "$symbol" \
    --assume-u64x2 --output "$run_dir/$function.ll"
  opt -passes=verify -disable-output "$run_dir/$function.ll"
  "${CARGO_TARGET_DIR:-target}/debug/hydirctl" validate "$run_dir/$function-original" "$symbol" \
    --assume-u64x2 --trusted-fixture --clang clang \
    > "$run_dir/$function.report.json"
  grep -q '"cases_attempted": 1008' "$run_dir/$function.report.json"
  grep -q '"cases_matched": 1008' "$run_dir/$function.report.json"
  grep -q '"cases_mismatched": 0' "$run_dir/$function.report.json"
  printf '%s\t1008\t1008\t0\n' "$symbol" >> "$run_dir/ledger.tsv"
  echo "matched $symbol: 1008/1008"
done
echo "scalar corpus gate passed: 16 new functions, 16128/16128 cases; $run_dir"
