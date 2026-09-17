#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'Whole-program fixture gate requires Linux x86-64.' >&2
  exit 2
fi

mkdir -p target/demo-recompile
run_dir="$(mktemp -d target/demo-recompile/run.XXXXXX)"
cargo build --locked -q -p hydir-cli
for name in whole_hello whole_choice whole_loop; do
  clang -nostdlib -no-pie -Wl,--build-id=none -o "$run_dir/$name" "tests/fixtures/$name.S"
  "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/$name" --trusted-fixture --output-dir "$run_dir/rebuilt-$name" > "$run_dir/$name.report.json"
  opt -verify -disable-output "$run_dir/rebuilt-$name/whole.ll"
  if cmp -s "$run_dir/$name" "$run_dir/rebuilt-$name/rebuilt"; then
    echo "rebuilt output is byte-identical to original: $name" >&2
    exit 1
  fi
done

compare_case() {
  local name="$1" input="$2" label="$3" original_status rebuilt_status
  set +e
  printf '%s' "$input" | timeout 5 "$run_dir/$name" > "$run_dir/$name.$label.original.stdout" 2> "$run_dir/$name.$label.original.stderr"
  original_status=$?
  printf '%s' "$input" | timeout 5 "$run_dir/rebuilt-$name/rebuilt" > "$run_dir/$name.$label.rebuilt.stdout" 2> "$run_dir/$name.$label.rebuilt.stderr"
  rebuilt_status=$?
  set -e
  [[ "$original_status" == "$rebuilt_status" ]] || { echo "$name/$label exit mismatch: $original_status != $rebuilt_status" >&2; exit 1; }
  cmp "$run_dir/$name.$label.original.stdout" "$run_dir/$name.$label.rebuilt.stdout"
  cmp "$run_dir/$name.$label.original.stderr" "$run_dir/$name.$label.rebuilt.stderr"
  echo "matched $name/$label: stdout, stderr, exit=$original_status"
}

compare_case whole_hello '' empty
compare_case whole_choice A a
compare_case whole_choice B b
compare_case whole_choice '' eof
compare_case whole_loop '' empty

if "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/whole_hello" --output-dir "$run_dir/should-reject" > "$run_dir/no-trust.stdout" 2> "$run_dir/no-trust.stderr"; then
  echo 'rebuild accepted an untrusted invocation' >&2
  exit 1
fi
clang -nostdlib -no-pie -Wl,--build-id=none -o "$run_dir/unsupported" tests/fixtures/whole_unsupported.S
if "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/unsupported" --trusted-fixture --output-dir "$run_dir/should-reject-unsupported" > "$run_dir/unsupported.stdout" 2> "$run_dir/unsupported.stderr"; then
  echo 'rebuild accepted an unsupported binary' >&2
  exit 1
fi
grep -q 'unmodelled initialization effect Push' "$run_dir/unsupported.stderr"
clang -nostdlib -no-pie -Wl,--build-id=none -o "$run_dir/uninitialized" tests/fixtures/whole_uninitialized.S
if "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/uninitialized" --trusted-fixture --output-dir "$run_dir/should-reject-uninitialized" > "$run_dir/uninitialized.stdout" 2> "$run_dir/uninitialized.stderr"; then
  echo 'rebuild accepted an uninitialized register read' >&2
  exit 1
fi
grep -q 'read before definite initialization' "$run_dir/uninitialized.stderr"
clang -nostdlib -no-pie -Wl,--build-id=none -o "$run_dir/ro-write" tests/fixtures/whole_ro_write.S
if "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/ro-write" --trusted-fixture --output-dir "$run_dir/should-reject-ro-write" > "$run_dir/ro-write.stdout" 2> "$run_dir/ro-write.stderr"; then
  echo 'rebuild accepted a write to read-only guest data' >&2
  exit 1
fi
grep -q 'write to read-only guest data' "$run_dir/ro-write.stderr"
clang -nostdlib -no-pie -Wl,--build-id=none -o "$run_dir/unmapped-buffer" tests/fixtures/whole_unmapped_buffer.S
if "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/unmapped-buffer" --trusted-fixture --output-dir "$run_dir/should-reject-unmapped-buffer" > "$run_dir/unmapped-buffer.stdout" 2> "$run_dir/unmapped-buffer.stderr"; then
  echo 'rebuild accepted an unmapped syscall buffer' >&2
  exit 1
fi
grep -q 'syscall buffer below mapped data' "$run_dir/unmapped-buffer.stderr"
clang -nostdlib -no-pie -Wl,--build-id=none -o "$run_dir/unsupported-syscall" tests/fixtures/whole_unsupported_syscall.S
if "${CARGO_TARGET_DIR:-target}/debug/hydirctl" rebuild "$run_dir/unsupported-syscall" --trusted-fixture --output-dir "$run_dir/should-reject-unsupported-syscall" > "$run_dir/unsupported-syscall.stdout" 2> "$run_dir/unsupported-syscall.stderr"; then
  echo 'rebuild accepted an unsupported syscall' >&2
  exit 1
fi
grep -q 'unknown or unsupported syscall number' "$run_dir/unsupported-syscall.stderr"
echo "whole-program fixture gate passed: $run_dir"
