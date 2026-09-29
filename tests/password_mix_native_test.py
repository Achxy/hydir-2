#!/usr/bin/env python3
"""Replay one stripped password-demo function against native x86-64 execution.

The selected Ghidra 12.1.4 snapshot, Rust path interpreter, and CPU must agree
on the listed seeds, instruction visits, IMUL flags, and return value. This is
a bounded function check, not a general equivalence claim.
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
BINARY = ROOT / "tests" / "fixtures" / "hydir-password-gate-stripped.elf"
SNAPSHOT = ROOT / "tests" / "fixtures" / "ghidra_password_mix_o1_v2.json"
GDB_SCRIPT = ROOT / "tests" / "fixtures" / "prism_bit_gate_native.gdb"
IMUL = "0x2015ee"
MASK64 = (1 << 64) - 1
MASK128 = (1 << 128) - 1
CASES = ((0, 0), (7, 5), (MASK64, MASK64), (MASK64 >> 1, 2))


def state_register(trace, offset, size):
    byte_map = trace["final_state"]["register_bytes"]
    return sum(byte_map[str(offset + index)] << (8 * index) for index in range(size))


def signed64(value):
    return value if value < (1 << 63) else value - (1 << 64)


class PasswordMixNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        binary = BINARY.read_bytes()
        cls.digest = hashlib.sha256(binary).hexdigest()
        cls.entry = cls.snapshot["selected_function"]["entry"]
        cls.return_address = struct.unpack_from("<Q", binary, 24)[0]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hydir-password-native-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.temp = Path(cls.temporary.name)
        cls.native_binary = cls.temp / "password-gate.elf"
        shutil.copyfile(BINARY, cls.native_binary)
        cls.native_binary.chmod(0o700)

    def test_snapshot_binds_stripped_elf_and_imul(self):
        binary = BINARY.read_bytes()
        self.assertEqual(self.snapshot["binary_sha256"], self.digest)
        self.assertEqual(binary[:6], b"\x7fELF\x02\x01")
        self.assertEqual(struct.unpack_from("<H", binary, 16)[0], 2)
        self.assertEqual(struct.unpack_from("<H", binary, 18)[0], 62)
        self.assertEqual(self.entry, {"space": "ram", "offset": "0x2015d0"})
        instructions = self.snapshot["selected_function"]["instructions"]
        self.assertEqual([row["mnemonic"] for row in instructions].count("IMUL"), 1)
        self.assertEqual(next(row["address"]["offset"] for row in instructions
                              if row["mnemonic"] == "IMUL"), IMUL)
        self.assertEqual(instructions[-1]["mnemonic"], "RET")

    def rust_trace(self, label, value, salt):
        seed = {
            "schema_version": 1,
            "binary_sha256": self.digest,
            "entry": self.entry,
            "registers": [
                {"offset": "0x38", "size": 8, "value": f"0x{value:x}"},
                {"offset": "0x30", "size": 8, "value": f"0x{salt:x}"},
                {"offset": "0x20", "size": 8, "value": "0x700000"},
            ],
            "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8,
                        "value": f"0x{self.return_address:x}"}],
        }
        seed_path = self.temp / f"{label}.json"
        seed_path.write_text(json.dumps(seed), encoding="utf-8")
        hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target" / "debug" / "hydirctl"))
        self.assertTrue(Path(hydirctl).is_file(), f"missing hydirctl binary: {hydirctl}")
        result = subprocess.run(
            [hydirctl, "ghidra-snapshot", "trace-path", str(BINARY), str(SNAPSHOT),
             str(seed_path), "--max-ops", "256", "--max-visits", "64"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def native_trace(self, value, salt):
        self.assertTrue(shutil.which("gdb"), "GDB is required for native differential gate")
        env = {**os.environ, "HYDIR_NATIVE_SNAPSHOT": str(SNAPSHOT),
               "HYDIR_NATIVE_RETURN": f"0x{self.return_address:x}",
               "HYDIR_NATIVE_RDI": f"0x{value:x}",
               "HYDIR_NATIVE_RSI": f"0x{salt:x}",
               "HYDIR_NATIVE_OBSERVE_INSTRUCTION": IMUL}
        result = subprocess.run(
            ["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT), str(self.native_binary)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line.removeprefix("HYDIR_NATIVE_RESULT=") for line in result.stdout.splitlines()
                if line.startswith("HYDIR_NATIVE_RESULT=")]
        self.assertEqual(len(rows), 1, result.stdout + result.stderr)
        return json.loads(rows[0])

    def assert_rust_semantics(self, rust, value, salt):
        self.assertEqual(rust["stop"]["kind"], "return")
        self.assertEqual(rust["binary_sha256"], self.digest)
        imul = [event["operation"] for event in rust["events"]
                if event["kind"] == "effect"
                and event["operation"]["source"]["source_address"]["offset"] == IMUL]
        self.assertEqual(len(imul), 8)
        outputs = {(op["source"]["output"]["space"],
                    op["source"]["output"]["offset"]): int(op["output_value"], 16)
                   for op in imul}
        left = (value ^ ((salt + 0x9e3779b97f4a7c15) & MASK64))
        left = ((left << 13) | (left >> 51)) & MASK64
        product = signed64(left) * signed64(0xbf58476d1ce4e5b9)
        self.assertEqual(outputs[("unique", "0x92f00")], product & MASK128)
        overflow = int(product < -(1 << 63) or product >= (1 << 63))
        self.assertEqual(outputs[("register", "0x200")], overflow)
        self.assertEqual(outputs[("register", "0x20b")], overflow)
        low_product = product & MASK64
        self.assertEqual(state_register(rust, 0x0, 8), low_product ^ (low_product >> 29))
        return outputs

    def test_stripped_function_rust_path_has_complete_wide_imul(self):
        self.test_snapshot_binds_stripped_elf_and_imul()
        for index, (value, salt) in enumerate(CASES):
            with self.subTest(value=value, salt=salt):
                self.assert_rust_semantics(self.rust_trace(f"rust-{index}", value, salt),
                                           value, salt)

    def test_128_bit_imul_and_return_match_native(self):
        if sys.platform != "linux":
            self.skipTest("native execution requires Linux")
        self.assertEqual(platform.machine(), "x86_64")
        self.test_snapshot_binds_stripped_elf_and_imul()
        for index, (value, salt) in enumerate(CASES):
            with self.subTest(value=value, salt=salt):
                rust = self.rust_trace(f"case-{index}", value, salt)
                native = self.native_trace(value, salt)
                outputs = self.assert_rust_semantics(rust, value, salt)
                self.assertEqual(
                    [row["offset"] for row in rust["instruction_visits"]],
                    native["instruction_visits"],
                )
                self.assertEqual(native["return_pc"], f"0x{self.return_address:x}")
                self.assertEqual(native["stack_delta"], 8)
                self.assertEqual(state_register(rust, 0x20, 8), 0x700008)
                self.assertEqual(state_register(rust, 0x0, 8), native["registers"]["rax"])
                self.assertEqual(state_register(rust, 0x38, 8), native["registers"]["rdi"])
                self.assertEqual(state_register(rust, 0x30, 8), native["registers"]["rsi"])

                self.assertEqual(outputs[("register", "0x200")], native["observed_flags"]["cf"])
                self.assertEqual(outputs[("register", "0x20b")], native["observed_flags"]["of"])


if __name__ == "__main__":
    program = unittest.main(exit=False)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        for case, details in program.result.failures + program.result.errors:
            message = f"{case.id()}: {details[-1800:]}"
            message = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=Hydir password native differential::{message}", flush=True)
    if not program.result.wasSuccessful():
        raise SystemExit(1)
