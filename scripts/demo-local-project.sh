#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
demo_base="$repo_dir/target/demo-local-project"
mkdir -p "$demo_base"
demo_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
binary="$demo_dir/sample.elf"

if [[ $# -eq 1 ]]; then
  cp "$1" "$binary"
elif [[ $# -eq 0 && "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]]; then
  clang -nostdlib -no-pie -Wl,-e,_start tests/fixtures/global_effects.S -o "$binary"
else
  echo 'Usage: bash scripts/demo-local-project.sh [trusted x86-64 linked ELF]' >&2
  echo 'Without an argument, this demo builds its fixture on Linux x86-64.' >&2
  exit 2
fi

export HYDIR_LOCAL_DB="$demo_dir/analyst.sqlite"
cargo build --quiet --locked --bin hydirctl --bin hydir
cli="$repo_dir/target/debug/hydirctl"
gui="$repo_dir/target/debug/hydir"

"$cli" local project "$binary" > "$demo_dir/project-1.json"
revision="$(sed -n 's/.*"revision": \([0-9][0-9]*\).*/\1/p' "$demo_dir/project-1.json")"
[[ "$revision" == 1 ]]
"$cli" local inspect "$binary" > "$demo_dir/inspect-1.json"
entry="$(sed -n 's/.*"entry_point": "\(0x[0-9a-fA-F]*\)".*/\1/p' "$demo_dir/inspect-1.json" | head -n 1)"
[[ -n "$entry" ]]

"$cli" local annotate "$binary" 1 name-key name "$entry" entry reviewed_entry \
  > "$demo_dir/project-2.json"
grep -q '"revision": 2' "$demo_dir/project-2.json"
"$cli" local annotate "$binary" 1 name-key name "$entry" entry reviewed_entry \
  > "$demo_dir/name-retry.json"
cmp "$demo_dir/project-2.json" "$demo_dir/name-retry.json"
if "$cli" local annotate "$binary" 1 name-key name "$entry" entry changed_name \
  > "$demo_dir/conflicting-key.out" 2>&1; then
  echo 'Conflicting local annotation idempotency key was accepted' >&2
  exit 1
fi
if "$cli" local annotate "$binary" 1 stale-key comment - program stale_fact \
  > "$demo_dir/stale-revision.out" 2>&1; then
  echo 'Stale local annotation revision was accepted' >&2
  exit 1
fi
"$cli" local annotate "$binary" 2 assumption-key assumption - whole-binary trusted_fixture_only \
  > "$demo_dir/project-3.json"
grep -q '"revision": 3' "$demo_dir/project-3.json"
"$cli" local annotations "$binary" > "$demo_dir/annotations-3.json"
grep -q 'reviewed_entry' "$demo_dir/annotations-3.json"
grep -q 'trusted_fixture_only' "$demo_dir/annotations-3.json"
"$cli" local analyze-spec "$binary" > "$demo_dir/analyzed-spec-3.json"
grep -q 'trusted_fixture_only' "$demo_dir/analyzed-spec-3.json"
grep -q 'analyst_assertion' "$demo_dir/analyzed-spec-3.json"

"$gui" --probe-local-annotation "$binary" > "$demo_dir/gui-probe.out"
grep -q 'private revision 4' "$demo_dir/gui-probe.out"
"$gui" --probe-workbench "$binary" > "$demo_dir/workbench-probe.out"
grep -q 'workbench save/reopen operations passed' "$demo_dir/workbench-probe.out"
"$cli" local annotations "$binary" > "$demo_dir/annotations-4.json"
grep -q 'GUI local analyst assertion' "$demo_dir/annotations-4.json"

# Mutate only the disposable fixture copy; the source input is untouched.
printf X >> "$binary"
"$cli" local project "$binary" > "$demo_dir/project-5.json"
grep -q '"revision": 5' "$demo_dir/project-5.json"
"$cli" local annotations "$binary" > "$demo_dir/annotations-5.json"
grep -q '"annotations": \[\]' "$demo_dir/annotations-5.json"

echo 'HydIR private local project, CLI/GUI sharing, retry/stale checks, and digest isolation passed'
echo "HydIR local project artifacts: $demo_dir"
