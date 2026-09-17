#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$repo_dir/target/linux-cargo-registry"
docker build --platform linux/amd64 -t hydir-m1:local -f "$repo_dir/Dockerfile.m1" "$repo_dir"
docker build --platform linux/amd64 -t hydir-sdk:local -f "$repo_dir/Dockerfile.sdk" "$repo_dir"
docker run --rm --platform linux/amd64 \
  -v "$repo_dir:/work" -w /work \
  -v "$repo_dir/target/linux-cargo-registry:/usr/local/cargo/registry" \
  -e CARGO_TARGET_DIR=/work/target/linux-x86_64 \
  -e CARGO_INCREMENTAL=0 \
  hydir-sdk:local bash -c '
    set -euo pipefail
    mkdir -p target/demo-sdk-fixtures
    fixture_dir="$(mktemp -d target/demo-sdk-fixtures/run.XXXXXX)"
    clang -O0 -no-pie -DHYDIR_FUNCTION=hydir_max2 tests/fixtures/max2.S tests/fixtures/scalar_main.c -o "$fixture_dir/max2"
    clang -nostdlib -no-pie -Wl,--build-id=none tests/fixtures/whole_choice.S -o "$fixture_dir/whole-choice"
    bash scripts/demo-sdk.sh "$fixture_dir/max2" "$fixture_dir/whole-choice"
  '
