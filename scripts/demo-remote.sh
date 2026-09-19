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
clang -nostdlib -no-pie -Wl,--build-id=none \
  tests/fixtures/whole_choice.S -o "$demo_dir/whole-choice-original"

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
grep -q '"named_pass_transform": true' "$demo_dir/discovery.json"
grep -q '"scalar_patch_v1": true' "$demo_dir/discovery.json"
grep -q '"whole_rebuild": true' "$demo_dir/discovery.json"
grep -q '"analyzed_program_spec": true' "$demo_dir/discovery.json"
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
"$gui_bin" --probe-create-upload "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" "$demo_dir/max2-original" \
  > "$demo_dir/gui-transfer-probe.txt"
"$gui_bin" --probe-remote "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" "$alice_id" hydir_max2 \
  > "$demo_dir/gui-remote-probe.txt"
"$client_bin" remote lift "$alice_id" 1 hydir_max2 --assume-u64x2 \
  --output "$demo_dir/remote-lift.ll" > "$demo_dir/lift.json"
"$client_bin" remote decompile "$alice_id" 1 hydir_max2 --assume-u64x2 \
  --output "$demo_dir/remote-decompile.c" > "$demo_dir/decompile.json"
c_sha="$(sed -n 's/.*"sha256": "\([^"]*\)".*/\1/p' "$demo_dir/decompile.json")"
test "${#c_sha}" -eq 64
clang -std=c11 -O0 "$demo_dir/remote-decompile.c" tests/fixtures/scalar_main.c \
  -DHYDIR_FUNCTION=hydir_lifted -o "$demo_dir/remote-c-runner" 2> "$demo_dir/remote-c-compile.err" || {
    cat "$demo_dir/remote-c-compile.err" >&2
    exit 1
  }
for input_pair in '0 0' '42 9' '18446744073709551615 1'; do
  read -r input_a input_b <<< "$input_pair"
  "$demo_dir/max2-original" "$input_a" "$input_b" > "$demo_dir/original-sample.out"
  "$demo_dir/remote-c-runner" "$input_a" "$input_b" > "$demo_dir/c-sample.out"
  cmp "$demo_dir/original-sample.out" "$demo_dir/c-sample.out"
done
artifact_sha="$(sed -n 's/.*"sha256": "\([^"]*\)".*/\1/p' "$demo_dir/lift.json")"
test "${#artifact_sha}" -eq 64
grep -q '"kind":"taken"' "$demo_dir/cfg.json"
grep -q '"schema_version":3' "$demo_dir/inspect.json"
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
"$client_bin" remote analyze-spec "$effects_id" 1 > "$demo_dir/effects-analyzed-spec.json"
grep -q '"direct_callees":\["hydir_leaf"\]' "$demo_dir/effects-analysis.json"
grep -q '"section":".data"' "$demo_dir/effects-analysis.json"
grep -q '"unknown_global_effects":true' "$demo_dir/effects-analysis.json"
grep -q '"call_recovery":"partial"' "$demo_dir/effects-analyzed-spec.json"
grep -q '"reference_recovery":"partial"' "$demo_dir/effects-analyzed-spec.json"
grep -q '"source":"native_analysis"' "$demo_dir/effects-analyzed-spec.json"
"$client_bin" remote annotate "$effects_id" 1 effects-assumption-1 assumption - \
  'trusted fixture only' 'entry follows the fixture caller contract' \
  > "$demo_dir/effects-annotated.json"
grep -q '"revision": 2' "$demo_dir/effects-annotated.json"
"$client_bin" remote annotate "$effects_id" 1 effects-assumption-1 assumption - \
  'trusted fixture only' 'entry follows the fixture caller contract' \
  > "$demo_dir/effects-annotation-retry.json"
cmp "$demo_dir/effects-annotated.json" "$demo_dir/effects-annotation-retry.json"
"$client_bin" remote annotations "$effects_id" 2 > "$demo_dir/effects-annotations.json"
grep -q '"source":"analyst_assertion"' "$demo_dir/effects-annotations.json"
"$client_bin" remote analyze-spec "$effects_id" 2 > "$demo_dir/effects-analyzed-with-assumption.json"
grep -q '"statement":"entry follows the fixture caller contract"' "$demo_dir/effects-analyzed-with-assumption.json"
"$gui_bin" --probe-annotation "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" \
  "$demo_dir/global-effects" > "$demo_dir/gui-annotation-probe.txt"
grep -q 'one persistent analyst fact' "$demo_dir/gui-annotation-probe.txt"

"$client_bin" remote create Alice-transform request-alice-transform-1 > "$demo_dir/transform-project.json"
transform_id="$(sed -n 's/.*"project_id": "\([^"]*\)".*/\1/p' "$demo_dir/transform-project.json")"
test -n "$transform_id"
"$client_bin" remote upload "$transform_id" 0 "$demo_dir/max2-original" > "$demo_dir/transform-upload.json"
"$client_bin" remote transform "$transform_id" 1 hydir_max2 alice-transform-1 \
  --assume-u64x2 --trusted-fixture --passes instcombine,sccp,simplifycfg,dce \
  --output-dir "$demo_dir/remote-transform" > "$demo_dir/transform-reply.json"
grep -q '"llvm_verified": true' "$demo_dir/remote-transform/report.json"
grep -q '"ir_text_changed": true' "$demo_dir/transform-reply.json"
opt -passes=verify -disable-output "$demo_dir/remote-transform/after.ll"
if "$client_bin" remote transform "$transform_id" 1 hydir_max2 rejected-plugin \
  --assume-u64x2 --trusted-fixture --passes load=/tmp/plugin.so \
  --output-dir "$demo_dir/rejected-plugin" \
  > "$demo_dir/rejected-plugin.out" 2> "$demo_dir/rejected-plugin.err"; then
  echo "unallowlisted remote pass unexpectedly accepted" >&2
  exit 1
fi
test ! -e "$demo_dir/rejected-plugin"
if "$client_bin" remote transform "$transform_id" 1 hydir_max2 rejected-overwrite \
  --assume-u64x2 --trusted-fixture --passes dce \
  --output-dir "$demo_dir/remote-transform" \
  > "$demo_dir/transform-overwrite.out" 2> "$demo_dir/transform-overwrite.err"; then
  echo "remote transform unexpectedly overwrote experiment output" >&2
  exit 1
fi
grep -q 'output directory exists' "$demo_dir/transform-overwrite.err"
transform_after_sha="$(sed -n 's/.*"after_sha256": "\([^"]*\)".*/\1/p' "$demo_dir/transform-reply.json")"
test "${#transform_after_sha}" -eq 64
"$client_bin" remote project "$transform_id" > "$demo_dir/transform-current.json"
grep -q '"revision": 2' "$demo_dir/transform-current.json"
transform_binary_sha="$(sed -n 's/.*"binary_sha256": "\([^"]*\)".*/\1/p' "$demo_dir/transform-upload.json")"
grep -q "$transform_binary_sha" "$demo_dir/transform-current.json"
"$gui_bin" --probe-transform "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" \
  "$demo_dir/max2-original" hydir_max2 > "$demo_dir/gui-transform-probe.txt"
grep -q 'verified before/after IR' "$demo_dir/gui-transform-probe.txt"

"$client_bin" remote create Alice-rebuild request-alice-rebuild-1 > "$demo_dir/rebuild-project.json"
rebuild_id="$(sed -n 's/.*"project_id": "\([^"]*\)".*/\1/p' "$demo_dir/rebuild-project.json")"
test -n "$rebuild_id"
"$client_bin" remote upload "$rebuild_id" 0 "$demo_dir/whole-choice-original" > "$demo_dir/rebuild-upload.json"
"$client_bin" remote rebuild "$rebuild_id" 1 alice-rebuild-1 \
  --trusted-fixture --output-dir "$demo_dir/remote-rebuild" > "$demo_dir/rebuild-reply.json"
grep -q '"revision": 2' "$demo_dir/rebuild-reply.json"
opt -verify -disable-output "$demo_dir/remote-rebuild/whole.ll"
test -x "$demo_dir/remote-rebuild/rebuilt"
if cmp -s "$demo_dir/whole-choice-original" "$demo_dir/remote-rebuild/rebuilt"; then
  echo "remote rebuild copied the original ELF" >&2
  exit 1
fi
for choice in A B ''; do
  printf '%s' "$choice" | timeout 5 "$demo_dir/whole-choice-original" > "$demo_dir/rebuild-original.stdout" 2> "$demo_dir/rebuild-original.stderr"
  printf '%s' "$choice" | timeout 5 "$demo_dir/remote-rebuild/rebuilt" > "$demo_dir/rebuild-output.stdout" 2> "$demo_dir/rebuild-output.stderr"
  cmp "$demo_dir/rebuild-original.stdout" "$demo_dir/rebuild-output.stdout"
  cmp "$demo_dir/rebuild-original.stderr" "$demo_dir/rebuild-output.stderr"
done
rebuild_sha="$(sed -n 's/.*"binary_sha256": "\([^"]*\)".*/\1/p' "$demo_dir/rebuild-reply.json")"
test "${#rebuild_sha}" -eq 64
"$client_bin" remote project "$rebuild_id" > "$demo_dir/rebuild-current.json"
grep -q '"revision": 2' "$demo_dir/rebuild-current.json"
"$gui_bin" --probe-rebuild "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" \
  "$demo_dir/whole-choice-original" "$demo_dir/gui-rebuilt" > "$demo_dir/gui-rebuild-probe.txt"
grep -q 'exported ELF SHA-256' "$demo_dir/gui-rebuild-probe.txt"
test -x "$demo_dir/gui-rebuilt"
for choice in A B ''; do
  printf '%s' "$choice" | timeout 5 "$demo_dir/whole-choice-original" > "$demo_dir/gui-original.stdout" 2> "$demo_dir/gui-original.stderr"
  printf '%s' "$choice" | timeout 5 "$demo_dir/gui-rebuilt" > "$demo_dir/gui-rebuilt.stdout" 2> "$demo_dir/gui-rebuilt.stderr"
  cmp "$demo_dir/gui-original.stdout" "$demo_dir/gui-rebuilt.stdout"
  cmp "$demo_dir/gui-original.stderr" "$demo_dir/gui-rebuilt.stderr"
done

max_digest="$(sha256sum "$demo_dir/max2-original" | awk '{print $1}')"
printf '{"schema_version":1,"binary_sha256":"%s","function_symbol":"hydir_max2","prototype":"u64(u64,u64)","replacement":"return arg0 - arg1;"}\n' \
  "$max_digest" > "$demo_dir/patch.json"
"$client_bin" remote patch "$alice_id" 1 "$demo_dir/patch.json" alice-patch-1 \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$demo_dir/remote-patched" > "$demo_dir/patch-reply.json"
patched_sha="$(sed -n 's/.*"binary_sha256": "\([^"]*\)".*/\1/p' "$demo_dir/patch-reply.json")"
test "${#patched_sha}" -eq 64
grep -q '"revision": 2' "$demo_dir/patch-reply.json"
test "$("$demo_dir/max2-original" 9 4)" = 9
test "$("$demo_dir/remote-patched" 9 4)" = 5
"$gui_bin" --probe-remote-patch "$HYDIR_ENDPOINT" "$HYDIR_TOKEN_FILE" \
  "$demo_dir/max2-original" hydir_max2 'return arg0 - arg1;' \
  "$demo_dir/gui-remote-patched" > "$demo_dir/gui-patch-probe.txt"
grep -q 'exported ELF SHA-256' "$demo_dir/gui-patch-probe.txt"
test "$("$demo_dir/gui-remote-patched" 9 4)" = 5
"$client_bin" remote project "$alice_id" > "$demo_dir/after-patch-project.json"
grep -q '"revision": 2' "$demo_dir/after-patch-project.json"
"$client_bin" remote lift "$alice_id" 2 hydir_max2 --assume-u64x2 \
  --output "$demo_dir/patched-lift.ll" > "$demo_dir/patched-lift.json"

kill "$server_pid"
wait "$server_pid" 2>/dev/null || true
server_pid=""
start_server
"$client_bin" remote annotations "$effects_id" 2 > "$demo_dir/effects-annotations-after-restart.json"
cmp "$demo_dir/effects-annotations.json" "$demo_dir/effects-annotations-after-restart.json"
"$client_bin" remote project "$alice_id" > "$demo_dir/reopened-project.json"
grep -q '"revision": 2' "$demo_dir/reopened-project.json"
"$client_bin" remote patch "$alice_id" 1 "$demo_dir/patch.json" alice-patch-1 \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$demo_dir/remote-patched-retry" > "$demo_dir/patch-retry.json"
cmp "$demo_dir/remote-patched" "$demo_dir/remote-patched-retry"
grep -q '"revision": 2' "$demo_dir/patch-retry.json"
"$client_bin" remote artifact "$alice_id" "$patched_sha" \
  --output "$demo_dir/after-restart-patched" > "$demo_dir/patched-artifact.json"
cmp "$demo_dir/remote-patched" "$demo_dir/after-restart-patched"
"$client_bin" remote artifact "$alice_id" "$artifact_sha" \
  --output "$demo_dir/after-restart.ll" > "$demo_dir/artifact.json"
cmp "$demo_dir/remote-lift.ll" "$demo_dir/after-restart.ll"
"$client_bin" remote artifact "$alice_id" "$c_sha" \
  --output "$demo_dir/after-restart.c" > "$demo_dir/c-artifact.json"
cmp "$demo_dir/remote-decompile.c" "$demo_dir/after-restart.c"
"$client_bin" remote artifact "$transform_id" "$transform_after_sha" \
  --output "$demo_dir/transform-after-restart.ll" > "$demo_dir/transform-artifact.json"
cmp "$demo_dir/remote-transform/after.ll" "$demo_dir/transform-after-restart.ll"
"$client_bin" remote artifact "$rebuild_id" "$rebuild_sha" \
  --output "$demo_dir/rebuild-after-restart" > "$demo_dir/rebuild-artifact.json"
cmp "$demo_dir/remote-rebuild/rebuilt" "$demo_dir/rebuild-after-restart"
"$client_bin" remote rebuild "$rebuild_id" 1 alice-rebuild-1 \
  --trusted-fixture --output-dir "$demo_dir/remote-rebuild-retry" > "$demo_dir/rebuild-retry.json"
cmp "$demo_dir/remote-rebuild/rebuilt" "$demo_dir/remote-rebuild-retry/rebuilt"
"$client_bin" remote project "$rebuild_id" > "$demo_dir/rebuild-after-retry.json"
grep -q '"revision": 2' "$demo_dir/rebuild-after-retry.json"
"$client_bin" remote transform "$transform_id" 1 hydir_max2 alice-transform-1 \
  --assume-u64x2 --trusted-fixture --passes instcombine,sccp,simplifycfg,dce \
  --output-dir "$demo_dir/remote-transform-retry" > "$demo_dir/transform-retry.json"
cmp "$demo_dir/remote-transform/after.ll" "$demo_dir/remote-transform-retry/after.ll"
grep -q '"project_revision": 2' "$demo_dir/transform-retry.json"
"$client_bin" remote project "$transform_id" > "$demo_dir/transform-after-retry.json"
grep -q '"revision": 2' "$demo_dir/transform-after-retry.json"
if "$client_bin" remote transform "$transform_id" 1 hydir_max2 alice-transform-1 \
  --assume-u64x2 --trusted-fixture --passes dce \
  --output-dir "$demo_dir/transform-key-conflict" \
  > "$demo_dir/transform-key-conflict.out" 2> "$demo_dir/transform-key-conflict.err"; then
  echo "changed transform unexpectedly reused an idempotency key" >&2
  exit 1
fi
grep -q 'different transform request' "$demo_dir/transform-key-conflict.err"
test ! -e "$demo_dir/transform-key-conflict"
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
if "$client_bin" remote analyze-spec "$effects_id" 1 > "$demo_dir/denied-spec.out" 2> "$demo_dir/denied-spec.err"; then
  echo "Bob unexpectedly analyzed Alice's specification" >&2
  exit 1
fi
grep -q 'project not found' "$demo_dir/denied-spec.err"
if "$client_bin" remote annotations "$effects_id" 2 > "$demo_dir/denied-annotations.out" 2> "$demo_dir/denied-annotations.err"; then
  echo "Bob unexpectedly listed Alice's annotations" >&2
  exit 1
fi
grep -q 'project not found' "$demo_dir/denied-annotations.err"
if "$client_bin" remote transform "$transform_id" 1 hydir_max2 bob-denied-transform \
  --assume-u64x2 --trusted-fixture --passes dce \
  --output-dir "$demo_dir/denied-transform" \
  > "$demo_dir/denied-transform.out" 2> "$demo_dir/denied-transform.err"; then
  echo "Bob unexpectedly transformed Alice's binary" >&2
  exit 1
fi
grep -q 'project not found' "$demo_dir/denied-transform.err"
if "$client_bin" remote rebuild "$rebuild_id" 1 bob-denied-rebuild \
  --trusted-fixture --output-dir "$demo_dir/denied-rebuild" \
  > "$demo_dir/denied-rebuild.out" 2> "$demo_dir/denied-rebuild.err"; then
  echo "Bob unexpectedly rebuilt Alice's binary" >&2
  exit 1
fi
grep -q 'project not found' "$demo_dir/denied-rebuild.err"
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
if "$client_bin" remote artifact "$alice_id" "$c_sha" \
  --output "$demo_dir/denied-c-artifact.c" \
  > "$demo_dir/denied-c-artifact.out" 2> "$demo_dir/denied-c-artifact.err"; then
  echo "Bob unexpectedly accessed Alice's C artifact" >&2
  exit 1
fi
if "$client_bin" remote patch "$alice_id" 1 "$demo_dir/patch.json" bob-denied-patch-1 \
  --trusted-fixture --assume-u64x2 --assume-entry-only \
  --output "$demo_dir/denied-patched" > "$demo_dir/denied-patch.out" 2> "$demo_dir/denied-patch.err"; then
  echo "Bob unexpectedly patched Alice's project" >&2
  exit 1
fi
test ! -e "$demo_dir/denied-patched"
grep -q 'project not found' "$demo_dir/denied-project.err"
grep -q 'artifact not found' "$demo_dir/denied-artifact.err"
grep -q 'artifact not found' "$demo_dir/denied-c-artifact.err"
grep -q 'project not found' "$demo_dir/denied-patch.err"

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
