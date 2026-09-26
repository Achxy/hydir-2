#!/usr/bin/env python3
"""Compare a real Ghidra BRANCHIND path with native x86-64 execution."""

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
BINARY = ROOT / "tests" / "fixtures" / "ghidra_indirect_jump.elf"
SNAPSHOT = ROOT / "tests" / "fixtures" / "ghidra_indirect_jump_v2.json"
GDB_SCRIPT = ROOT / "tests" / "fixtures" / "prism_bit_gate_native.gdb"


def register_value(trace, offset):
    values = trace["final_state"]["register_bytes"]
    return sum(values[str(offset + index)] << (8 * index) for index in range(8))


class IndirectJumpNativeTests(unittest.TestCase):
    def test_both_paths_match_native_execution(self):
        if sys.platform != "linux":
            self.skipTest("native execution requires Linux")
        self.assertEqual(platform.machine(), "x86_64")
        self.assertTrue(shutil.which("gdb"), "GDB is required")
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        self.assertEqual(snapshot["binary_sha256"], digest)
        target = "0x20117b"
        ret_address = next(row["entry"]["offset"] for row in snapshot["functions"]
                           if row["name"] == "_start")

        with tempfile.TemporaryDirectory(prefix="hydir-indirect-jump-") as scratch:
            temp = Path(scratch)
            native_binary = temp / "indirect-jump.elf"
            shutil.copyfile(BINARY, native_binary)
            native_binary.chmod(0o700)
            hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target" / "debug" / "hydirctl"))
            for rdi, expected_indirect in ((0, False), (1, True)):
                with self.subTest(rdi=rdi):
                    seed = {
                        "schema_version": 1,
                        "binary_sha256": digest,
                        "entry": snapshot["selected_function"]["entry"],
                        "registers": [
                            {"offset": "0x0", "size": 8, "value": target},
                            {"offset": "0x38", "size": 8, "value": f"0x{rdi:x}"},
                            {"offset": "0x20", "size": 8, "value": "0x700000"},
                        ],
                        "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8,
                                    "value": ret_address}],
                    }
                    seed_path = temp / f"seed-{rdi}.json"
                    seed_path.write_text(json.dumps(seed), encoding="utf-8")
                    rust = subprocess.run(
                        [hydirctl, "ghidra-snapshot", "trace-path", str(BINARY),
                         str(SNAPSHOT), str(seed_path), "--max-ops", "32", "--max-visits", "8"],
                        cwd=ROOT, capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(rust.returncode, 0, rust.stderr)
                    trace = json.loads(rust.stdout)
                    native = subprocess.run(
                        ["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT),
                         str(native_binary)],
                        cwd=ROOT,
                        env={**os.environ, "HYDIR_NATIVE_SNAPSHOT": str(SNAPSHOT),
                             "HYDIR_NATIVE_RETURN": ret_address,
                             "HYDIR_NATIVE_RDI": f"0x{rdi:x}", "HYDIR_NATIVE_RSI": "0x0",
                             "HYDIR_NATIVE_RAX": target},
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
                    rows = [line.removeprefix("HYDIR_NATIVE_RESULT=")
                            for line in native.stdout.splitlines()
                            if line.startswith("HYDIR_NATIVE_RESULT=")]
                    self.assertEqual(len(rows), 1, native.stdout + native.stderr)
                    observed = json.loads(rows[0])
                    visits = [row["offset"] for row in trace["instruction_visits"]]
                    self.assertEqual(trace["stop"]["kind"], "return")
                    self.assertEqual("0x201179" in visits, expected_indirect)
                    self.assertEqual(observed["instruction_visits"], visits)
                    self.assertEqual(observed["return_pc"], ret_address)
                    self.assertEqual(observed["stack_delta"], 8)
                    self.assertEqual(observed["registers"]["rax"], 7)
                    self.assertEqual(register_value(trace, 0x0), 7)
                    self.assertEqual(register_value(trace, 0x38), rdi)


if __name__ == "__main__":
    unittest.main()
