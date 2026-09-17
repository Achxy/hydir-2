#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
  echo 'source-offer demo currently requires Linux x86-64' >&2
  exit 2
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'source-offer build requires a clean committed checkout' >&2
  exit 1
fi
revision="$(git rev-parse HEAD)"
archive="$repo_dir/target/source-snapshot/hydir-source-$revision.tar"
bash scripts/package-source-snapshot.sh
test -f "$archive"
export HYDIR_SOURCE_REVISION="$revision"
export HYDIR_SOURCE_ARCHIVE="$archive"
cargo build --locked --bin hydird --bin hydirctl

demo_base="${HYDIR_SOURCE_DEMO_DIR:-$repo_dir/target/demo-source}"
mkdir -p "$demo_base"
demo_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
server_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydird"
client_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"
port="${HYDIR_SOURCE_DEMO_PORT:-50552}"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

"$server_bin" identity create "$demo_dir/projects.sqlite" source-reader \
  | awk '/credential \(save securely/ {print $NF}' > "$demo_dir/token"
export HYDIR_ENDPOINT="http://127.0.0.1:$port"
export HYDIR_TOKEN_FILE="$demo_dir/token"
"$server_bin" serve "$demo_dir/projects.sqlite" "127.0.0.1:$port" \
  > "$demo_dir/server.log" 2>&1 &
server_pid=$!
for _ in {1..40}; do
  if "$client_bin" remote discover > "$demo_dir/discover.json" 2>/dev/null; then
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo 'hydird exited before source-offer readiness' >&2
    exit 1
  fi
  sleep 0.25
done
grep -q "\"source_revision\": \"$revision\"" "$demo_dir/discover.json"
"$client_bin" remote source --output "$demo_dir/offered-source.tar" \
  > "$demo_dir/source.json"
cmp "$archive" "$demo_dir/offered-source.tar"
expected_sha="$(sha256sum "$archive" | awk '{print $1}')"
grep -q "\"sha256\": \"$expected_sha\"" "$demo_dir/source.json"
grep -q "\"source_sha256\": \"$expected_sha\"" "$demo_dir/discover.json"
tar -tf "$demo_dir/offered-source.tar" | grep -Fx "hydir-source-$revision/crates/hydir-c/src/lib.rs" >/dev/null
echo "matching embedded source archive offered: $revision · $expected_sha · $demo_dir"
