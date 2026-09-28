#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"

demo_base="${HYDIR_PASSWORD_LIFT_DIR:-$repo_dir/target/demo-ghidra-password-lift}"
mkdir -p "$demo_base"
run_dir="$(mktemp -d "$demo_base/run.XXXXXX")"
binary="$repo_dir/tests/fixtures/hydir-password-gate-stripped.elf"

cargo build --locked -p hydir-cli --bin hydirctl
client="${CARGO_TARGET_DIR:-$repo_dir/target}/debug/hydirctl"
"$client" ghidra analyze "$binary" --function 0x2016d0 \
  --output "$run_dir/secure-equals-snapshot.json"
"$client" ghidra-snapshot coverage "$binary" \
  "$run_dir/secure-equals-snapshot.json" \
  --output "$run_dir/coverage.json"
"$client" ghidra-snapshot llvm-cfg "$binary" \
  "$run_dir/secure-equals-snapshot.json" \
  --output "$run_dir/cfg-llvm.json"
"$client" ghidra-snapshot llvm-cfg-image "$binary" \
  "$run_dir/secure-equals-snapshot.json" \
  --output "$run_dir/cfg-llvm-image.json"

python3 - "$binary" "$run_dir" <<'PY'
import hashlib
import json
import pathlib
import sys

binary = pathlib.Path(sys.argv[1])
run_dir = pathlib.Path(sys.argv[2])
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
registers = [
    {"offset": "0x38", "size": 8, "value": "0x700100"},
    {"offset": "0x30", "size": 8, "value": "0xc"},
    {"offset": "0x20", "size": 8, "value": "0x700000"},
    {"offset": "0x0", "size": 8, "value": "0x0"},
    {"offset": "0x8", "size": 8, "value": "0x0"},
]
for name, first_eight in (
    ("match", "0x43412d5249445948"),
    ("mismatch", "0x43412d5249445968"),
):
    seed = {
        "schema_version": 1,
        "binary_sha256": digest,
        "entry": {"space": "ram", "offset": "0x2016d0"},
        "registers": registers,
        "memory": [
            {"space": "ram", "byte_offset": "0x700000", "size": 8, "value": "0xdeadbeef"},
            {"space": "ram", "byte_offset": "0x700100", "size": 8, "value": first_eight},
            {"space": "ram", "byte_offset": "0x700108", "size": 4, "value": "0x53534543"},
        ],
    }
    (run_dir / f"{name}-seed.json").write_text(json.dumps(seed, indent=2) + "\n")
PY

for outcome in match mismatch; do
  "$client" ghidra-snapshot trace-path "$binary" \
    "$run_dir/secure-equals-snapshot.json" "$run_dir/$outcome-seed.json" \
    --max-ops 2048 --max-visits 128 --output "$run_dir/$outcome-trace.json"
done

python3 - "$run_dir" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
snapshot = json.loads((run_dir / "secure-equals-snapshot.json").read_text())
coverage = json.loads((run_dir / "coverage.json").read_text())
llvm = json.loads((run_dir / "cfg-llvm.json").read_text())
image_llvm = json.loads((run_dir / "cfg-llvm-image.json").read_text())
assert snapshot["selected_function"]["entry"]["offset"] == "0x2016d0"
assert snapshot["binary_sha256"] == llvm["binary_sha256"]
assert "define " in llvm["llvm_ir"]
assert image_llvm["schema_version"] == 3
assert image_llvm["binary_sha256"] == snapshot["binary_sha256"]
assert image_llvm["read_only_image"]["known_byte_count"] > 0
assert "define " in image_llvm["llvm_ir"]
(run_dir / "cfg-llvm-image.ll").write_text(image_llvm["llvm_ir"])
assert coverage["binary_sha256"] == snapshot["binary_sha256"]
for name, expected in (("match", 1), ("mismatch", 0)):
    trace = json.loads((run_dir / f"{name}-trace.json").read_text())
    assert trace["stop"]["kind"] == "return"
    assert trace["final_state"]["register_bytes"]["0"] == expected
    assert any(
        event.get("kind") == "effect"
        and event["operation"]["source"]["source_address"]["offset"] == "0x2016f0"
        and event["operation"].get("memory_access") is not None
        and event["operation"]["memory_access"]["byte_offset"] == 0x2001F0
        for event in trace["events"]
    )
    print(f"{name}: return {expected}, {len(trace['instruction_visits'])} visits")
PY
clang -x ir -c "$run_dir/cfg-llvm-image.ll" -o "$run_dir/cfg-llvm-image.o"

echo "Hydir bounded Ghidra-backed path demo passed; artifacts: $run_dir"
echo "Open the binary in the Hydir GUI: cargo run --locked -p hydir-gui --bin hydir -- --open-local $binary"
