#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo "demo-password-showcase requires Linux x86-64 (or the pinned Docker image)" >&2
  exit 2
fi

demo_base="${HYDIR_PASSWORD_DEMO_DIR:-$repo_dir/target/demo-password-showcase}"
mkdir -p "$demo_base"
run_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
echo "HydIR password-demo artifacts: $run_dir"

clang -O1 -fno-stack-protector -fno-builtin -fno-asynchronous-unwind-tables \
  -fno-unwind-tables -nostdlib -no-pie \
  -Wl,--build-id=none -Wl,-e,_start \
  tests/fixtures/hydir_password_demo.c -o "$run_dir/hydir-password-gate.elf"
cargo build --locked --bin hydirctl
client="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"

printf 'HYDIR-ACCESS\n' | "$run_dir/hydir-password-gate.elf" > "$run_dir/good.out"
printf 'NOT-THE-PASSWORD\n' | "$run_dir/hydir-password-gate.elf" > "$run_dir/bad.out"
grep -q 'ACCESS GRANTED' "$run_dir/good.out"
grep -q 'ACCESS DENIED' "$run_dir/bad.out"

"$client" inspect "$run_dir/hydir-password-gate.elf" > "$run_dir/inspect.json"
"$client" analyze "$run_dir/hydir-password-gate.elf" > "$run_dir/analyze.json"

echo "password demo passed"
echo "ELF: $run_dir/hydir-password-gate.elf"
echo "Open it in HydIR, then inspect hydir_policy_route and hydir_password_score."
