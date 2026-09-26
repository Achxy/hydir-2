#!/usr/bin/env python3
"""Bounded Rust P-code trace versus CPU execution of one exact PRISM ELF body.

Requires Linux x86-64, GDB, and HYDIRCTL_BIN. Each case starts at
hydir_stage_bit_gate with a synthetic SysV call frame and executes RET.
This proves only the listed register, flag, path, and stack observations for
the listed seeds; it does not establish whole-program or LLVM equivalence.
"""

import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "demo" / "hydir-prism.elf"
SNAPSHOT = ROOT / "tests" / "fixtures" / "ghidra_prism_bit_gate_oracle_v2.json"
GDB_SCRIPT = ROOT / "tests" / "fixtures" / "prism_bit_gate_native.gdb"
CASES = (
    ("taken", 7, 0, 0, 1, ["0x2013cf", "0x2013d6", "0x2013d9", "0x2013e2"]),
    ("not_taken", 7, 1, 1, 0,
     ["0x2013cf", "0x2013d6", "0x2013d9", "0x2013db", "0x2013e2"]),
)
REGISTER_OFFSETS = {"rax": 0x0, "rsi": 0x30, "rdi": 0x38,
                    "cf": 0x200, "zf": 0x206, "sf": 0x207, "of": 0x20B}


def register_value(trace, offset, size):
    byte_map = trace["final_state"]["register_bytes"]
    return sum(byte_map[str(offset + index)] << (8 * index) for index in range(size))


class PrismBitGateNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        binary = BINARY.read_bytes()
        cls.digest = hashlib.sha256(binary).hexdigest()
        cls.entry = cls.snapshot["selected_function"]["entry"]
        cls.return_address = next(
            int(item["address"]["offset"], 16)
            for item in cls.snapshot["symbols"]
            if item["name"] == "_start" and item["address"]["space"] == "ram"
        )
        cls.temporary = tempfile.TemporaryDirectory(prefix="hydir-native-bit-gate-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.temp = Path(cls.temporary.name)

    def test_snapshot_identifies_exact_elf_and_function(self):
        binary = BINARY.read_bytes()
        self.assertEqual(self.snapshot["binary_sha256"], self.digest)
        self.assertEqual(binary[:4], b"\x7fELF")
        self.assertEqual(binary[4:6], b"\x02\x01")  # ELF64 little endian
        self.assertEqual(struct.unpack_from("<H", binary, 16)[0], 2)  # ET_EXEC
        self.assertEqual(struct.unpack_from("<H", binary, 18)[0], 62)  # x86-64
        self.assertEqual(self.entry, {"space": "ram", "offset": "0x2013cf"})
        selected = self.snapshot["selected_function"]
        self.assertEqual(
            [row["mnemonic"] for row in selected["instructions"]],
            ["MOV", "TEST", "JZ", "MOV", "RET"],
        )
        self.assertEqual(selected["instructions"][-1]["pcode"][-1]["mnemonic"], "RETURN")

    def rust_trace(self, label, rdi, rsi):
        seed = {
            "schema_version": 1,
            "binary_sha256": self.digest,
            "entry": self.entry,
            "registers": [
                {"offset": "0x38", "size": 8, "value": f"0x{rdi:x}"},
                {"offset": "0x30", "size": 8, "value": f"0x{rsi:x}"},
                {"offset": "0x20", "size": 8, "value": "0x700000"},
            ],
            "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8,
                        "value": f"0x{self.return_address:x}"}],
        }
        seed_path = self.temp / f"{label}.json"
        seed_path.write_text(json.dumps(seed), encoding="utf-8")
        hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target" / "debug" / "hydirctl"))
        self.assertTrue(Path(hydirctl).is_file(), f"missing hydirctl binary: {hydirctl}")
        command = [hydirctl, "ghidra-snapshot", "trace-path", str(BINARY),
                   str(SNAPSHOT), str(seed_path), "--max-ops", "32", "--max-visits", "8"]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def native_trace(self, rdi, rsi):
        self.assertTrue(shutil.which("gdb"), "GDB is required for native differential gate")
        env = {**os.environ, "HYDIR_NATIVE_SNAPSHOT": str(SNAPSHOT),
               "HYDIR_NATIVE_RETURN": f"0x{self.return_address:x}",
               "HYDIR_NATIVE_RDI": f"0x{rdi:x}", "HYDIR_NATIVE_RSI": f"0x{rsi:x}"}
        result = subprocess.run(["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT),
                                 str(BINARY)], cwd=ROOT, env=env, capture_output=True,
                                text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line.removeprefix("HYDIR_NATIVE_RESULT=") for line in result.stdout.splitlines()
                if line.startswith("HYDIR_NATIVE_RESULT=")]
        self.assertEqual(len(rows), 1, result.stdout + result.stderr)
        return json.loads(rows[0])

    def test_two_branch_outcomes_match_actual_elf_execution(self):
        if sys.platform != "linux":
            self.skipTest("native execution requires Linux")
        self.assertEqual(platform.machine(), "x86_64", "native gate requires Linux x86-64")
        self.test_snapshot_identifies_exact_elf_and_function()
        for label, rdi, rsi, expected_rax, expected_zf, expected_visits in CASES:
            with self.subTest(label=label):
                rust = self.rust_trace(label, rdi, rsi)
                native = self.native_trace(rdi, rsi)
                self.assertEqual(rust["stop"]["kind"], "return")
                self.assertEqual(rust["binary_sha256"], self.digest)
                self.assertEqual(native["instruction_visits"],
                                 [row["offset"] for row in rust["instruction_visits"]])
                self.assertEqual(native["instruction_visits"], expected_visits)
                self.assertEqual(native["registers"]["rax"], expected_rax)
                self.assertEqual(native["flags"]["zf"], expected_zf)
                self.assertEqual(native["return_pc"], f"0x{self.return_address:x}")
                self.assertEqual(native["stack_delta"], 8)
                self.assertEqual(register_value(rust, 0x20, 8), 0x700008)
                self.assertEqual(register_value(rust, 0x288, 8), self.return_address)
                for name in ("rax", "rdi", "rsi"):
                    self.assertEqual(native["registers"][name],
                                     register_value(rust, REGISTER_OFFSETS[name], 8), name)
                for name in ("cf", "zf", "sf", "of"):
                    self.assertEqual(native["flags"][name],
                                     register_value(rust, REGISTER_OFFSETS[name], 1), name)


if __name__ == "__main__":
    unittest.main()
