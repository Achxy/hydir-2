#!/usr/bin/env python3
"""Compare image-backed P-code paths with the stripped ELF's CPU behavior."""

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
BINARY = ROOT / "tests/fixtures/hydir-password-gate-stripped.elf"
SNAPSHOT = ROOT / "tests/fixtures/ghidra_password_secure_equals_o1_v2.json"
GDB_SCRIPT = ROOT / "tests/fixtures/prism_bit_gate_native.gdb"
CASES = (
    ("match", b"HYDIR-ACCESS", 12, 1),
    ("mismatch", b"hYDIR-ACCESS", 12, 0),
    ("wrong-length", b"HYDIR-ACCESS", 11, 0),
)


class PasswordSecureEqualsNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = BINARY.read_bytes()
        cls.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        cls.digest = hashlib.sha256(cls.binary).hexdigest()
        cls.entry = cls.snapshot["selected_function"]["entry"]
        cls.return_address = struct.unpack_from("<Q", cls.binary, 24)[0]
        cls.temporary = tempfile.TemporaryDirectory(prefix="hydir-password-equals-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.temp = Path(cls.temporary.name)
        cls.native_binary = cls.temp / "password-gate.elf"
        shutil.copyfile(BINARY, cls.native_binary)
        cls.native_binary.chmod(0o700)

    def rust_trace(self, name, candidate, length):
        seed = {
            "schema_version": 1,
            "binary_sha256": self.digest,
            "entry": self.entry,
            "registers": [
                {"offset": "0x38", "size": 8, "value": "0x700100"},
                {"offset": "0x30", "size": 8, "value": hex(length)},
                {"offset": "0x20", "size": 8, "value": "0x700000"},
                {"offset": "0x0", "size": 8, "value": "0x0"},
                {"offset": "0x8", "size": 8, "value": "0x0"},
            ],
            "memory": [
                {"space": "ram", "byte_offset": "0x700000", "size": 8,
                 "value": hex(self.return_address)},
                {"space": "ram", "byte_offset": "0x700100", "size": 8,
                 "value": hex(int.from_bytes(candidate[:8], "little"))},
                {"space": "ram", "byte_offset": "0x700108", "size": 4,
                 "value": hex(int.from_bytes(candidate[8:], "little"))},
            ],
        }
        seed_path = self.temp / f"{name}-seed.json"
        seed_path.write_text(json.dumps(seed), encoding="utf-8")
        hydirctl = Path(os.environ.get(
            "HYDIRCTL_BIN", str(ROOT / "target/debug/hydirctl")))
        self.assertTrue(hydirctl.is_file(), f"missing hydirctl binary: {hydirctl}")
        result = subprocess.run(
            [str(hydirctl), "ghidra-snapshot", "trace-path", str(BINARY),
             str(SNAPSHOT), str(seed_path), "--max-ops", "2048", "--max-visits", "128"],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def native_trace(self, candidate, length):
        self.assertTrue(shutil.which("gdb"), "GDB is required for native differential gate")
        env = {
            **os.environ,
            "HYDIR_NATIVE_SNAPSHOT": str(SNAPSHOT),
            "HYDIR_NATIVE_RETURN": hex(self.return_address),
            "HYDIR_NATIVE_RSI": hex(length),
            "HYDIR_NATIVE_RAX": "0x0",
            "HYDIR_NATIVE_INPUT_HEX": candidate.hex(),
            "HYDIR_NATIVE_MAX_VISITS": "128",
        }
        result = subprocess.run(
            ["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT),
             str(self.native_binary)],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line.removeprefix("HYDIR_NATIVE_RESULT=")
                for line in result.stdout.splitlines()
                if line.startswith("HYDIR_NATIVE_RESULT=")]
        self.assertEqual(len(rows), 1, result.stdout + result.stderr)
        return json.loads(rows[0])

    def test_image_backed_trace_returns_for_both_inputs(self):
        self.assertEqual(self.snapshot["binary_sha256"], self.digest)
        self.assertEqual(self.entry, {"space": "ram", "offset": "0x2016d0"})
        for name, candidate, length, expected in CASES:
            with self.subTest(case=name):
                trace = self.rust_trace(name, candidate, length)
                self.assertEqual(trace["stop"]["kind"], "return")
                self.assertEqual(trace["final_state"]["register_bytes"]["0"], expected)
                loads = [event["operation"]["memory_access"] for event in trace["events"]
                         if event["kind"] == "effect"
                         and event["operation"]["source"]["mnemonic"] == "LOAD"
                         and event["operation"]["memory_access"] is not None]
                if length == 12:
                    self.assertTrue(any(load["byte_offset"] == 0x2001F0
                                        and load["value"] == ord("H") for load in loads))
                else:
                    self.assertFalse(any(load["byte_offset"] == 0x2001F0
                                         for load in loads))

    def test_instruction_visits_and_return_match_native(self):
        if sys.platform != "linux":
            self.skipTest("native execution requires Linux")
        self.assertEqual(platform.machine(), "x86_64")
        for name, candidate, length, expected in CASES:
            with self.subTest(case=name):
                trace = self.rust_trace(name, candidate, length)
                native = self.native_trace(candidate, length)
                self.assertEqual(
                    [visit["offset"] for visit in trace["instruction_visits"]],
                    native["instruction_visits"],
                )
                self.assertEqual(native["registers"]["rax"], expected)
                self.assertEqual(native["return_pc"], hex(self.return_address))
                self.assertEqual(native["stack_delta"], 8)


if __name__ == "__main__":
    unittest.main()
