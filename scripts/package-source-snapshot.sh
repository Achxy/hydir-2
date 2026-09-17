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
  echo "refusing to overwrite $archive" >&2
  exit 1
fi
git archive --format=tar --prefix="$prefix/" --output="$archive" HEAD
for required in LICENSE Cargo.lock rust-toolchain.toml Dockerfile.m1 PROVENANCE.md THIRD_PARTY_NOTICES.md crates/hydir-api/proto/hydir.proto native/whole-runtime/runtime.c scripts/demo-recompile.sh; do
  if ! tar -tf "$archive" | grep -Fxq "$prefix/$required"; then
    echo "archive missing required source: $required" >&2
    exit 1
  fi
done
if tar -tf "$archive" | grep -Eq '(^|/)(target|\.git|\.impeccable\.md|copilot-instructions\.md)(/|$)|\.(sqlite|token)$'; then
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
