#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: bash scripts/demo-sdk.sh /path/to/trusted-x86_64-elf-with-hydir_max2 [/path/to/trusted-freestanding-elf]" >&2
  exit 2
fi
binary="$1"
rebuild_binary="${2:-}"
python="${HYDIR_SDK_PYTHON:-python3}"
"$python" -c 'import grpc, google.protobuf' >/dev/null
base="$repo_dir/target/demo-sdk"
mkdir -p "$base"
demo_dir="$(mktemp -d "$base/run.XXXXXX")"
port="${HYDIR_SDK_DEMO_PORT:-50552}"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cargo build --locked --bin hydird --bin hydirctl
server_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydird"
client_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"
"$server_bin" identity create "$demo_dir/projects.sqlite" alice \
  | awk '/credential \(save securely/ {print $NF}' > "$demo_dir/alice.token"
test "$(wc -c < "$demo_dir/alice.token")" -eq 65
"$server_bin" serve "$demo_dir/projects.sqlite" "127.0.0.1:$port" \
  > "$demo_dir/server.log" 2>&1 &
server_pid=$!
export HYDIR_ENDPOINT="http://127.0.0.1:$port"
export HYDIR_TOKEN_FILE="$demo_dir/alice.token"
for _ in {1..40}; do
  if "$client_bin" remote discover > "$demo_dir/discover.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "hydird exited before readiness" >&2
    exit 1
  fi
  sleep 0.25
done
grep -q '"api_version": 1' "$demo_dir/discover.json"
PYTHONPATH="$repo_dir/sdk/python" "$python" -m unittest discover -s sdk/python/tests -v
PYTHONPATH="$repo_dir/sdk/python" "$python" sdk/python/examples/smoke.py \
  "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" "$binary" hydir_max2 \
  "$demo_dir/output" > "$demo_dir/sdk-smoke.txt"
test -s "$demo_dir/output/lifted.ll"
clang -nostdlib -no-pie -Wl,-e,_start tests/fixtures/global_effects.S \
  -o "$demo_dir/global-effects"
PYTHONPATH="$repo_dir/sdk/python" "$python" sdk/python/examples/global_analysis.py \
  "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" "$demo_dir/global-effects" \
  "$demo_dir/analysis.json" "$demo_dir/analyzed-spec.json" > "$demo_dir/sdk-analysis.txt"
grep -q '"unknown_global_effects": true' "$demo_dir/analysis.json"
grep -q '"call_recovery": "partial"' "$demo_dir/analyzed-spec.json"
grep -q '"reference_recovery": "partial"' "$demo_dir/analyzed-spec.json"
if [[ -n "$rebuild_binary" ]]; then
  grep -q '"whole_rebuild": true' "$demo_dir/discover.json"
  PYTHONPATH="$repo_dir/sdk/python" "$python" sdk/python/examples/rebuild_program.py \
    "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" "$rebuild_binary" \
    "$demo_dir/rebuild-output" > "$demo_dir/sdk-rebuild.txt"
  test -x "$demo_dir/rebuild-output/rebuilt"
  test -s "$demo_dir/rebuild-output/whole.ll"
  test -s "$demo_dir/rebuild-output/report.json"
  for choice in A B ''; do
    original_status=0
    rebuilt_status=0
    printf '%s' "$choice" | timeout 5 "$rebuild_binary" > "$demo_dir/original.stdout" 2> "$demo_dir/original.stderr" || original_status=$?
    printf '%s' "$choice" | timeout 5 "$demo_dir/rebuild-output/rebuilt" > "$demo_dir/rebuilt.stdout" 2> "$demo_dir/rebuilt.stderr" || rebuilt_status=$?
    test "$original_status" -eq "$rebuilt_status"
    cmp "$demo_dir/original.stdout" "$demo_dir/rebuilt.stdout"
    cmp "$demo_dir/original.stderr" "$demo_dir/rebuilt.stderr"
  done
fi
echo "HydIR Python SDK integration passed; artifacts: $demo_dir"
