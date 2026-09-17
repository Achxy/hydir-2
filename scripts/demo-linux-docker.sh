#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
docker build --platform linux/amd64 -t hydir-m1:local -f "$repo_dir/Dockerfile.m1" "$repo_dir"
docker run --rm --platform linux/amd64 \
  -v "$repo_dir:/work" -w /work \
  -e CARGO_TARGET_DIR=/work/target/linux-x86_64 \
  hydir-m1:local bash -c 'rustc --version && clang --version | head -1 && cargo test --locked --workspace && cargo clippy --locked --workspace --all-targets -- -D warnings && bash scripts/demo-local.sh && bash scripts/demo-remote.sh'
