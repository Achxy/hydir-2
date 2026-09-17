#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "demo-analysis requires Linux x86-64" >&2
  exit 2
fi

demo_base="${HYDIR_ANALYSIS_DEMO_DIR:-$repo_dir/target/demo-analysis}"
mkdir -p "$demo_base"
demo_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
clang -nostdlib -no-pie -Wl,-e,_start \
  tests/fixtures/global_effects.S -o "$demo_dir/global-effects"
cargo run --quiet --locked --bin hydirctl -- analyze "$demo_dir/global-effects" \
  > "$demo_dir/analysis.json"
awk '
  /"name": "hydir_parent"/ { in_parent=1; next }
  in_parent && /"name": / { exit }
  in_parent && /"hydir_leaf"/ { called=1 }
  in_parent && /"possible_global_writes": \[/ { writes=1 }
  in_parent && writes && /"section": ".data"/ { propagated=1 }
  END { if (!(called && propagated)) exit 1 }
' "$demo_dir/analysis.json"
awk '
  /"name": "hydir_indirect"/ { in_indirect=1; next }
  in_indirect && /"name": / { exit }
  in_indirect && /"unknown_global_effects": true/ { unknown=1 }
  END { if (!unknown) exit 1 }
' "$demo_dir/analysis.json"
echo "HydIR cross-function global-effect analysis passed"
echo "HydIR analysis artifacts: $demo_dir"
