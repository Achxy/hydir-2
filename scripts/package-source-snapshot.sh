#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'source snapshot requires a clean committed checkout' >&2
  exit 1
fi
revision="$(git rev-parse HEAD)"
prefix="hydir-source-$revision"
mkdir -p target/source-snapshot
archive="target/source-snapshot/$prefix.tar"
if [[ -e "$archive" ]]; then
  candidate="$(mktemp target/source-snapshot/.candidate.XXXXXX)"
  trap 'rm -f "$candidate"' EXIT
  git archive --format=tar --prefix="$prefix/" --output="$candidate" HEAD
  if ! cmp -s "$candidate" "$archive"; then
    echo "existing source snapshot differs from the committed tree: $archive" >&2
    exit 1
  fi
else
  git archive --format=tar --prefix="$prefix/" --output="$archive" HEAD
fi
for required in LICENSE Cargo.lock rust-toolchain.toml Dockerfile.m1 Dockerfile.sdk PROVENANCE.md THIRD_PARTY_NOTICES.md docs/EVALUATION.md crates/hydir-api/proto/hydir.proto crates/hydir-c/src/lib.rs crates/hydir-patch/src/lib.rs crates/hydir-project/src/lib.rs crates/hydir-cli/src/local.rs crates/hydir-transform/src/lib.rs crates/hydir-recompile/src/lib.rs crates/hydir-server/build.rs native/whole-runtime/runtime.c sdk/python/examples/rebuild_program.py sdk/python/examples/validate_program.py tests/fixtures/whole_choice_cases.json scripts/demo-local-project.sh scripts/demo-recompile.sh scripts/demo-patch.sh scripts/demo-passes.sh scripts/demo-sdk-linux-docker.sh; do
  if ! tar -tf "$archive" | grep -Fx "$prefix/$required" >/dev/null; then
    echo "archive missing required source: $required" >&2
    exit 1
  fi
done
if tar -tf "$archive" | grep -E '(^|/)(target|\.git|\.impeccable\.md|copilot-instructions\.md)(/|$)|\.(sqlite|token)$' >/dev/null; then
  echo 'archive contains excluded development context or project data' >&2
  exit 1
fi
echo "revision: $revision"
echo "archive: $archive"
if command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$archive"
else
  sha256sum "$archive"
fi
