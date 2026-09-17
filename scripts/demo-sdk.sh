#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ $# -ne 1 ]]; then
  echo "Usage: bash scripts/demo-sdk.sh /path/to/trusted-x86_64-elf-with-hydir_max2" >&2
  exit 2
fi
binary="$1"
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
echo "HydIR Python SDK integration passed; artifacts: $demo_dir"
