#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "demo-remote currently requires Linux x86-64" >&2
  exit 2
fi

demo_base="${HYDIR_REMOTE_DEMO_DIR:-$repo_dir/target/demo-remote}"
mkdir -p "$demo_base"
demo_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
port="${HYDIR_REMOTE_DEMO_PORT:-50551}"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
}
trap cleanup EXIT

cargo build --locked --bin hydird --bin hydirctl --bin hydir
server_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydird"
client_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"
gui_bin="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydir"
clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_max2 \
  tests/fixtures/max2.S tests/fixtures/scalar_main.c \
  -o "$demo_dir/max2-original"
clang -c tests/fixtures/unsupported.S -o "$demo_dir/unsupported.o"
clang -nostdlib -no-pie -Wl,-e,_start \
  tests/fixtures/global_effects.S -o "$demo_dir/global-effects"

"$server_bin" identity create "$demo_dir/projects.sqlite" alice \
  | awk '/credential \(save securely/ {print $NF}' > "$demo_dir/alice.token"
"$server_bin" identity create "$demo_dir/projects.sqlite" bob \
  | awk '/credential \(save securely/ {print $NF}' > "$demo_dir/bob.token"
test "$(wc -c < "$demo_dir/alice.token")" -eq 65
test "$(wc -c < "$demo_dir/bob.token")" -eq 65

export HYDIR_ENDPOINT="http://127.0.0.1:$port"
export HYDIR_TOKEN_FILE="$demo_dir/alice.token"

start_server() {
  "$server_bin" serve "$demo_dir/projects.sqlite" "127.0.0.1:$port" \
    > "$demo_dir/server.log" 2>&1 &
  server_pid=$!
  for _ in {1..40}; do
    if "$client_bin" remote discover > "$demo_dir/discovery.json" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "hydird exited before readiness" >&2
      return 1
    fi
    sleep 0.25
  done
  echo "hydird did not become ready" >&2
  return 1
}

start_server
"$client_bin" remote create Alice-demo request-alice-1 > "$demo_dir/alice-project.json"
alice_id="$(sed -n 's/.*"project_id": "\([^"]*\)".*/\1/p' "$demo_dir/alice-project.json")"
test -n "$alice_id"
"$client_bin" remote create Alice-demo request-alice-1 > "$demo_dir/alice-create-retry.json"
cmp "$demo_dir/alice-project.json" "$demo_dir/alice-create-retry.json"
"$client_bin" remote upload "$alice_id" 0 "$demo_dir/max2-original" > "$demo_dir/upload.json"
if "$client_bin" remote inspect "$alice_id" 0 > "$demo_dir/stale.out" 2> "$demo_dir/stale.err"; then
  echo "stale project revision unexpectedly accepted" >&2
  exit 1
fi
grep -q 'stale project revision' "$demo_dir/stale.err"
"$client_bin" remote inspect "$alice_id" 1 > "$demo_dir/inspect.json"
"$client_bin" remote cfg "$alice_id" 1 hydir_max2 > "$demo_dir/cfg.json"
"$gui_bin" --probe-remote "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" "$alice_id" hydir_max2 \
  > "$demo_dir/gui-remote-probe.txt"
"$client_bin" remote lift "$alice_id" 1 hydir_max2 --assume-u64x2 \
  --output "$demo_dir/remote-lift.ll" > "$demo_dir/lift.json"
artifact_sha="$(sed -n 's/.*"sha256": "\([^"]*\)".*/\1/p' "$demo_dir/lift.json")"
test "${#artifact_sha}" -eq 64
grep -q '"kind":"taken"' "$demo_dir/cfg.json"
grep -q '"schema_version":1' "$demo_dir/inspect.json"
if command -v opt >/dev/null 2>&1; then
  opt -passes=verify -disable-output "$demo_dir/remote-lift.ll"
fi
"$client_bin" remote job-start-lift "$alice_id" 1 hydir_max2 alice-lift-job-1 --assume-u64x2 \
  > "$demo_dir/alice-job-start.json"
alice_job_id="$(sed -n 's/.*"job_id": "\([^"]*\)".*/\1/p' "$demo_dir/alice-job-start.json")"
test -n "$alice_job_id"
"$client_bin" remote job-start-lift "$alice_id" 1 hydir_max2 alice-lift-job-1 --assume-u64x2 \
  > "$demo_dir/alice-job-retry.json"
grep -q "$alice_job_id" "$demo_dir/alice-job-retry.json"
for _ in {1..40}; do
  "$client_bin" remote job "$alice_id" "$alice_job_id" > "$demo_dir/alice-job.json"
  if grep -q '"state": "succeeded"' "$demo_dir/alice-job.json"; then
    break
  fi
  sleep 0.25
done
grep -q '"state": "succeeded"' "$demo_dir/alice-job.json"
"$client_bin" remote job-events "$alice_id" "$alice_job_id" 0 > "$demo_dir/alice-job-events.jsonl"
grep -q '"state":"queued"' "$demo_dir/alice-job-events.jsonl"
grep -q '"state":"succeeded"' "$demo_dir/alice-job-events.jsonl"

"$client_bin" remote create Alice-effects request-alice-effects-1 > "$demo_dir/effects-project.json"
effects_id="$(sed -n 's/.*"project_id": "\([^"]*\)".*/\1/p' "$demo_dir/effects-project.json")"
test -n "$effects_id"
"$client_bin" remote upload "$effects_id" 0 "$demo_dir/global-effects" > "$demo_dir/effects-upload.json"
"$client_bin" remote analyze "$effects_id" 1 > "$demo_dir/effects-analysis.json"
grep -q '"direct_callees":\["hydir_leaf"\]' "$demo_dir/effects-analysis.json"
grep -q '"section":".data"' "$demo_dir/effects-analysis.json"
grep -q '"unknown_global_effects":true' "$demo_dir/effects-analysis.json"

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
start_server
"$client_bin" remote project "$alice_id" > "$demo_dir/reopened-project.json"
"$client_bin" remote artifact "$alice_id" "$artifact_sha" \
  --output "$demo_dir/after-restart.ll" > "$demo_dir/artifact.json"
cmp "$demo_dir/remote-lift.ll" "$demo_dir/after-restart.ll"
"$client_bin" remote job "$alice_id" "$alice_job_id" > "$demo_dir/alice-job-after-restart.json"
grep -q '"state": "succeeded"' "$demo_dir/alice-job-after-restart.json"
"$client_bin" remote job-events "$alice_id" "$alice_job_id" 0 > "$demo_dir/alice-job-events-replayed.jsonl"
cmp "$demo_dir/alice-job-events.jsonl" "$demo_dir/alice-job-events-replayed.jsonl"

export HYDIR_TOKEN_FILE="$demo_dir/bob.token"
"$client_bin" remote create Bob-demo request-bob-1 > "$demo_dir/bob-project.json"
bob_id="$(sed -n 's/.*"project_id": "\([^"]*\)".*/\1/p' "$demo_dir/bob-project.json")"
test -n "$bob_id"
"$client_bin" remote upload "$bob_id" 0 "$demo_dir/unsupported.o" > "$demo_dir/bob-upload.json"
"$client_bin" remote inspect "$bob_id" 1 > "$demo_dir/bob-inspect.json"
if "$client_bin" remote lift "$bob_id" 1 hydir_unsupported --assume-u64x2 \
  --output "$demo_dir/unsupported.ll" > "$demo_dir/unsupported.out" 2> "$demo_dir/unsupported.err"; then
  echo "unsupported remote function unexpectedly lifted" >&2
  exit 1
fi
grep -q 'unsupported Push' "$demo_dir/unsupported.err"
"$client_bin" remote job-start-lift "$bob_id" 1 hydir_unsupported bob-lift-job-1 --assume-u64x2 \
  > "$demo_dir/bob-job-start.json"
bob_job_id="$(sed -n 's/.*"job_id": "\([^"]*\)".*/\1/p' "$demo_dir/bob-job-start.json")"
test -n "$bob_job_id"
"$client_bin" remote job-cancel "$bob_id" "$bob_job_id" > "$demo_dir/bob-job-cancel.json"
grep -Eq '"state": "(cancelled|failed)"' "$demo_dir/bob-job-cancel.json"
"$client_bin" remote job-events "$bob_id" "$bob_job_id" 0 > "$demo_dir/bob-job-events.jsonl"
if "$client_bin" remote job "$alice_id" "$alice_job_id" > "$demo_dir/denied-job.out" 2> "$demo_dir/denied-job.err"; then
  echo "Bob unexpectedly accessed Alice's job" >&2
  exit 1
fi
grep -q 'job not found' "$demo_dir/denied-job.err"
if "$client_bin" remote analyze "$effects_id" 1 > "$demo_dir/denied-analysis.out" 2> "$demo_dir/denied-analysis.err"; then
  echo "Bob unexpectedly analyzed Alice's binary" >&2
  exit 1
fi
grep -q 'project not found' "$demo_dir/denied-analysis.err"
if "$client_bin" remote project "$alice_id" > "$demo_dir/denied-project.out" 2> "$demo_dir/denied-project.err"; then
  echo "Bob unexpectedly accessed Alice's project" >&2
  exit 1
fi
if "$client_bin" remote artifact "$alice_id" "$artifact_sha" \
  --output "$demo_dir/denied-artifact.ll" \
  > "$demo_dir/denied-artifact.out" 2> "$demo_dir/denied-artifact.err"; then
  echo "Bob unexpectedly accessed Alice's artifact" >&2
  exit 1
fi
grep -q 'project not found' "$demo_dir/denied-project.err"
grep -q 'artifact not found' "$demo_dir/denied-artifact.err"

"$server_bin" identity rotate "$demo_dir/projects.sqlite" alice \
  | awk '/new credential \(save securely/ {print $NF}' > "$demo_dir/alice-rotated.token"
test "$(wc -c < "$demo_dir/alice-rotated.token")" -eq 65
export HYDIR_TOKEN_FILE="$demo_dir/alice.token"
if "$client_bin" remote project "$alice_id" > "$demo_dir/old-token.out" 2> "$demo_dir/old-token.err"; then
  echo "rotated-out credential unexpectedly accepted" >&2
  exit 1
fi
grep -q 'invalid bearer credential' "$demo_dir/old-token.err"
export HYDIR_TOKEN_FILE="$demo_dir/alice-rotated.token"
"$client_bin" remote project "$alice_id" > "$demo_dir/rotated-project.json"

echo "HydIR local-authenticated remote slice passed; artifacts: $demo_dir"
