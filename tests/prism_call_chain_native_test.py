#!/usr/bin/env python3
"""Bounded Hydir direct-call trace against the exact PRISM ELF under GDB."""

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
BINARY = ROOT / "demo" / "hydir-prism.elf"
CALLER = ROOT / "tests" / "fixtures" / "ghidra_prism_calls_flow_v2.json"
CALLEE = ROOT / "tests" / "fixtures" / "ghidra_prism_leaf_add_v2.json"
GDB_SCRIPT = ROOT / "tests" / "fixtures" / "prism_call_chain_native.gdb"
CASES = ((7, 5), (0, 0), (0xffffffffffffffff, 1))
REGISTER_OFFSETS = {"rax": 0x0, "rdi": 0x38, "rsi": 0x30,
                    "cf": 0x200, "zf": 0x206, "sf": 0x207, "of": 0x20b}


def register_value(trace, offset, size):
    values = trace["final_state"]["register_bytes"]
    return sum(values[str(offset + index)] << (8 * index) for index in range(size))


class PrismCallChainNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.caller = json.loads(CALLER.read_text(encoding="utf-8"))
        cls.callee = json.loads(CALLEE.read_text(encoding="utf-8"))
        cls.digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        assert cls.caller["binary_sha256"] == cls.digest
        assert cls.callee["binary_sha256"] == cls.digest
        cls.return_address = int(next(
            row["entry"]["offset"] for row in cls.caller["functions"]
            if row["name"] == "_start"
        ), 16)
        cls.temporary = tempfile.TemporaryDirectory(prefix="hydir-native-call-chain-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.temp = Path(cls.temporary.name)
        cls.native_binary = cls.temp / "hydir-prism.elf"
        shutil.copyfile(BINARY, cls.native_binary)
        cls.native_binary.chmod(0o700)

    def hydir_trace(self, a, b):
        seed = {
            "schema_version": 1,
            "binary_sha256": self.digest,
            "entry": self.caller["selected_function"]["entry"],
            "registers": [
                {"offset": "0x38", "size": 8, "value": f"0x{a:x}"},
                {"offset": "0x30", "size": 8, "value": f"0x{b:x}"},
                {"offset": "0x20", "size": 8, "value": "0x700000"},
            ],
            "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8,
                        "value": f"0x{self.return_address:x}"}],
        }
        seed_path = self.temp / f"seed-{a:x}-{b:x}.json"
        seed_path.write_text(json.dumps(seed), encoding="utf-8")
        hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target" / "debug" / "hydirctl"))
        result = subprocess.run(
            [hydirctl, "ghidra-snapshot", "trace-calls", str(BINARY), str(CALLER),
             str(seed_path), "--callee", str(CALLEE), "--max-ops", "128",
             "--max-visits", "16", "--max-depth", "4"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def native_trace(self, a, b):
        env = {**os.environ, "HYDIR_NATIVE_CALLER": str(CALLER),
               "HYDIR_NATIVE_CALLEE": str(CALLEE),
               "HYDIR_NATIVE_RETURN": f"0x{self.return_address:x}",
               "HYDIR_NATIVE_RDI": f"0x{a:x}", "HYDIR_NATIVE_RSI": f"0x{b:x}"}
        result = subprocess.run(
            ["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT), str(self.native_binary)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line.removeprefix("HYDIR_NATIVE_RESULT=") for line in result.stdout.splitlines()
                if line.startswith("HYDIR_NATIVE_RESULT=")]
        self.assertEqual(len(rows), 1, result.stdout + result.stderr)
        return json.loads(rows[0])

    def test_real_direct_call_matches_cpu_execution(self):
        if sys.platform != "linux":
            self.skipTest("native execution requires Linux")
        self.assertEqual(platform.machine(), "x86_64")
        self.assertTrue(shutil.which("gdb"), "GDB is required")
        for a, b in CASES:
            with self.subTest(a=a, b=b):
                trace = self.hydir_trace(a, b)
                native = self.native_trace(a, b)
                self.assertEqual(trace["stop"]["kind"], "return")
                self.assertEqual(len(trace["calls"]), 1)
                self.assertEqual(len(trace["segments"]), 3)
                visits = [row["offset"] for segment in trace["segments"]
                          for row in segment["path"]["instruction_visits"]]
                self.assertEqual(native["instruction_visits"], visits)
                self.assertEqual(native["return_pc"], f"0x{self.return_address:x}")
                self.assertEqual(native["stack_delta"], 8)
                self.assertEqual(register_value(trace, 0x20, 8), 0x700008)
                self.assertEqual(native["registers"]["rax"], (a + b) & 0xffffffffffffffff)
                for name in ("rax", "rdi", "rsi"):
                    self.assertEqual(native["registers"][name],
                                     register_value(trace, REGISTER_OFFSETS[name], 8), name)
                for name in ("cf", "zf", "sf", "of"):
                    self.assertEqual(native["flags"][name],
                                     register_value(trace, REGISTER_OFFSETS[name], 1), name)


if __name__ == "__main__":
    unittest.main()
