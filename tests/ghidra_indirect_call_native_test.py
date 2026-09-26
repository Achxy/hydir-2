#!/usr/bin/env python3
"""Compare a Ghidra CALLIND path with CPU execution of the same ELF."""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "tests" / "fixtures" / "ghidra_indirect_call.elf"
CALLER = ROOT / "tests" / "fixtures" / "ghidra_indirect_root_v2.json"
CALLEE = ROOT / "tests" / "fixtures" / "ghidra_indirect_leaf_v2.json"
GDB_SCRIPT = ROOT / "tests" / "fixtures" / "ghidra_indirect_call_native.gdb"


class IndirectCallNativeTests(unittest.TestCase):
    def test_concrete_indirect_call_matches_cpu(self):
        if sys.platform != "linux":
            self.skipTest("native execution requires Linux")
        self.assertEqual(platform.machine(), "x86_64")
        self.assertTrue(shutil.which("gdb"), "GDB is required")
        caller = json.loads(CALLER.read_text(encoding="utf-8"))
        callee = json.loads(CALLEE.read_text(encoding="utf-8"))
        digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        self.assertEqual(caller["binary_sha256"], digest)
        self.assertEqual(callee["binary_sha256"], digest)
        return_address = next(row["entry"]["offset"] for row in caller["functions"]
                              if row["name"] == "_start")

        with tempfile.TemporaryDirectory(prefix="hydir-indirect-native-") as scratch:
            temp = Path(scratch)
            native_binary = temp / "indirect.elf"
            shutil.copyfile(BINARY, native_binary)
            native_binary.chmod(0o700)
            seed = {
                "schema_version": 1,
                "binary_sha256": digest,
                "entry": caller["selected_function"]["entry"],
                "registers": [
                    {"offset": "0x0", "size": 8,
                     "value": callee["selected_function"]["entry"]["offset"]},
                    {"offset": "0x20", "size": 8, "value": "0x700000"},
                ],
                "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8,
                            "value": return_address}],
            }
            seed_path = temp / "seed.json"
            seed_path.write_text(json.dumps(seed), encoding="utf-8")
            hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target" / "debug" / "hydirctl"))
            result = subprocess.run(
                [hydirctl, "ghidra-snapshot", "trace-calls", str(BINARY), str(CALLER),
                 str(seed_path), "--callee", str(CALLEE), "--max-ops", "128",
                 "--max-visits", "16", "--max-depth", "4"],
                cwd=ROOT, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            trace = json.loads(result.stdout)
            native = subprocess.run(
                ["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT), str(native_binary)],
                cwd=ROOT, env={**os.environ, "HYDIR_NATIVE_CALLER": str(CALLER),
                               "HYDIR_NATIVE_CALLEE": str(CALLEE),
                               "HYDIR_NATIVE_RETURN": return_address},
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
            rows = [line.removeprefix("HYDIR_NATIVE_RESULT=")
                    for line in native.stdout.splitlines()
                    if line.startswith("HYDIR_NATIVE_RESULT=")]
            self.assertEqual(len(rows), 1, native.stdout + native.stderr)
            observed = json.loads(rows[0])

        self.assertEqual(trace["stop"]["kind"], "return")
        self.assertEqual(len(trace["calls"]), 1)
        self.assertEqual(len(trace["segments"]), 3)
        visits = [row["offset"] for segment in trace["segments"]
                  for row in segment["path"]["instruction_visits"]]
        self.assertEqual(observed["instruction_visits"], visits)
        self.assertEqual(observed["return_pc"], return_address)
        self.assertEqual(observed["stack_delta"], 8)
        self.assertEqual(observed["rax"], 7)
        registers = trace["final_state"]["register_bytes"]
        self.assertEqual(sum(registers[str(i)] << (8 * i) for i in range(8)), observed["rax"])


if __name__ == "__main__":
    unittest.main()
