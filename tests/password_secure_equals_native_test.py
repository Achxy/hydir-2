#!/usr/bin/env python3
"""Compare image-backed P-code paths with the stripped ELF's CPU behavior."""

import hashlib
import ctypes
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


def seed_register(byte_map, state, known, offset, value):
    for byte in range(8):
        index = byte_map[("register", offset + byte)]
        state[index] = (value >> (byte * 8)) & 0xFF
        known[index] = 0xFF


def read_register(byte_map, state, known, offset):
    indexes = [byte_map[("register", offset + byte)] for byte in range(8)]
    if any(known[index] != 0xFF for index in indexes):
        raise AssertionError(f"register 0x{offset:x} contains unknown bytes")
    return int.from_bytes(bytes(state[index] for index in indexes), "little")


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

    def test_image_backed_llvm_matches_rust_and_native(self):
        if sys.platform == "linux":
            self.assertEqual(platform.machine(), "x86_64")
        self.assertTrue(shutil.which("clang"), "Clang is required")
        hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target/debug/hydirctl"))
        emitted = subprocess.run(
            [hydirctl, "ghidra-snapshot", "llvm-cfg-image", str(BINARY),
             str(SNAPSHOT)],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(emitted.returncode, 0, emitted.stderr)
        artifact = json.loads(emitted.stdout)
        self.assertEqual(artifact["schema_version"], 3)
        self.assertEqual(artifact["binary_sha256"], self.digest)
        self.assertEqual(artifact["read_only_image"]["space"], "ram")
        self.assertGreater(artifact["read_only_image"]["known_byte_count"], 0)
        byte_map = {
            (entry["space"], int(entry["offset"], 16)): entry["index"]
            for entry in artifact["byte_map"]
        }
        self.assertEqual(len(byte_map), artifact["state_bytes"])
        with tempfile.TemporaryDirectory(
                prefix="hydir-password-llvm-",
                ignore_cleanup_errors=sys.platform == "win32") as scratch:
            module = Path(scratch) / "image.ll"
            library = Path(scratch) / ("image.dll" if sys.platform == "win32" else "image.so")
            module.write_text(artifact["llvm_ir"], encoding="utf-8")
            link_options = (["-Wl,/export:hydir_pcode_cfg"] if sys.platform == "win32"
                            else ["-fPIC", "-x", "ir"])
            compiled = subprocess.run(
                ["clang", "-shared", *link_options, str(module), "-o", str(library)],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            loaded_library = ctypes.CDLL(str(library))
            lifted = loaded_library.hydir_pcode_cfg
            u8p = ctypes.POINTER(ctypes.c_uint8)
            lifted.argtypes = [
                u8p, u8p, ctypes.c_int32, u8p, u8p, ctypes.c_uint64,
                ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32, ctypes.c_int32,
            ]
            lifted.restype = ctypes.c_int32

            for name, candidate, length, expected in CASES:
                with self.subTest(case=name):
                    rust = self.rust_trace(name, candidate, length)
                    native = (self.native_trace(candidate, length)
                              if sys.platform == "linux" else None)
                    state = (ctypes.c_uint8 * max(1, artifact["state_bytes"]))()
                    known = (ctypes.c_uint8 * max(1, artifact["state_bytes"]))()
                    seed_register(byte_map, state, known, 0x38, 0x700100)  # RDI
                    seed_register(byte_map, state, known, 0x30, length)  # RSI
                    seed_register(byte_map, state, known, 0x20, 0x700000)  # RSP
                    seed_register(byte_map, state, known, 0x0, 0)  # RAX
                    seed_register(byte_map, state, known, 0x8, 0)
                    guest = (ctypes.c_uint8 * 0x110)()
                    guest_known = (ctypes.c_uint8 * 0x110)()
                    for address, source in ((0, self.return_address.to_bytes(8, "little")),
                                            (0x100, candidate)):
                        for index, value in enumerate(source):
                            guest[address + index] = value
                            guest_known[address + index] = 0xFF
                    events = (ctypes.c_uint32 * 2048)()
                    event_count = ctypes.c_uint32(0)
                    status = lifted(
                        state, known, 433, guest, guest_known, 0x700000,
                        len(guest), events, ctypes.byref(event_count), 2048, 2048,
                    )
                    self.assertEqual(status, 1)  # PcodeCfgLlvmStatus::Return
                    self.assertGreater(event_count.value, 0)
                    self.assertLessEqual(event_count.value, 2048)
                    visits = []
                    for operation_id in events[:event_count.value]:
                        self.assertLess(operation_id, len(artifact["source_operations"]))
                        address = artifact["source_operations"][operation_id][
                            "instruction_address"]["offset"]
                        if not visits or visits[-1] != address:
                            visits.append(address)
                    self.assertEqual(
                        visits,
                        [visit["offset"] for visit in rust["instruction_visits"]],
                    )
                    self.assertEqual(read_register(byte_map, state, known, 0x0), expected)
                    if native is not None:
                        self.assertEqual(visits, native["instruction_visits"])
                        self.assertEqual(read_register(byte_map, state, known, 0x0),
                                         native["registers"]["rax"])
                        self.assertEqual(read_register(byte_map, state, known, 0x20),
                                         0x700000 + native["stack_delta"])
                    else:
                        self.assertEqual(read_register(byte_map, state, known, 0x20),
                                         0x700008)
                    self.assertEqual(bytes(guest[:8]),
                                     self.return_address.to_bytes(8, "little"))
            if sys.platform == "win32":
                del lifted
                free_library = ctypes.windll.kernel32.FreeLibrary
                free_library.argtypes = [ctypes.c_void_p]
                free_library.restype = ctypes.c_int
                self.assertTrue(free_library(loaded_library._handle))
                loaded_library._handle = 0


if __name__ == "__main__":
    unittest.main()
