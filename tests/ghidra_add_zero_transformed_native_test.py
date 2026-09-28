#!/usr/bin/env python3
"""Execute a checked Ghidra P-code rewrite as LLVM against the native ELF."""

import ctypes
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
BINARY = ROOT / "tests/fixtures/ghidra_add_zero.elf"
SNAPSHOT = ROOT / "tests/fixtures/ghidra_add_zero_v2.json"
GDB_SCRIPT = ROOT / "tests/fixtures/prism_bit_gate_native.gdb"
INPUTS = (0, 1, 255, 0x100, 0x123456789ABCDEF0, 0x8000000000000000,
          0xFFFFFFFFFFFFFFFF)


def register_bytes(byte_map, state, known, offset, size=8):
    indexes = [byte_map[("register", offset + byte)] for byte in range(size)]
    if any(known[index] != 255 for index in indexes):
        raise AssertionError(f"register 0x{offset:x} has unknown output bytes")
    return sum(state[index] << (8 * byte) for byte, index in enumerate(indexes))


def seed_register(byte_map, state, known, offset, value):
    for byte in range(8):
        index = byte_map[("register", offset + byte)]
        state[index] = (value >> (byte * 8)) & 0xFF
        known[index] = 255


class TransformedPcodeNativeTests(unittest.TestCase):
    def test_transformed_llvm_matches_exact_native_elf(self):
        if sys.platform != "linux":
            self.skipTest("native ELF replay requires Linux")
        self.assertEqual(platform.machine(), "x86_64")
        self.assertTrue(shutil.which("clang"), "Clang is required")
        self.assertTrue(shutil.which("gdb"), "GDB is required")

        digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        self.assertEqual(snapshot["binary_sha256"], digest)
        return_address = next(
            int(row["entry"]["offset"], 16) for row in snapshot["functions"]
            if row["name"] == "_start"
        )
        hydirctl = os.environ.get("HYDIRCTL_BIN", str(ROOT / "target/debug/hydirctl"))
        emitted = subprocess.run(
            [hydirctl, "ghidra-snapshot", "llvm-cfg-simplified", str(BINARY),
             str(SNAPSHOT)],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(emitted.returncode, 0, emitted.stderr)
        artifact = json.loads(emitted.stdout)
        self.assertEqual(artifact["binary_sha256"], digest)
        self.assertEqual(artifact["llvm"]["binary_sha256"], digest)
        self.assertEqual(artifact["verification"], "not_run")
        rewrites = artifact["simplification"]["rewrites"]
        self.assertEqual(len(rewrites), 1)
        self.assertEqual(rewrites[0]["before"]["mnemonic"], "INT_ADD")
        self.assertEqual(rewrites[0]["after"]["mnemonic"], "COPY")
        self.assertEqual(rewrites[0]["source_address"]["offset"], "0x201177")
        llvm = artifact["llvm"]
        byte_map = {
            (entry["space"], int(entry["offset"], 16)): entry["index"]
            for entry in llvm["byte_map"]
        }
        self.assertEqual(len(byte_map), llvm["state_bytes"])
        self.assertLessEqual(llvm["state_bytes"], 65536)

        with tempfile.TemporaryDirectory(prefix="hydir-transformed-native-") as scratch:
            temp = Path(scratch)
            module = temp / "transformed.ll"
            library = temp / "transformed.so"
            native_binary = temp / "add-zero.elf"
            module.write_text(llvm["llvm_ir"], encoding="utf-8")
            compiled = subprocess.run(
                ["clang", "-shared", "-fPIC", "-x", "ir", str(module), "-o",
                 str(library)],
                cwd=ROOT, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            shutil.copyfile(BINARY, native_binary)
            native_binary.chmod(0o700)

            transformed = ctypes.CDLL(str(library)).hydir_pcode_cfg
            u8p = ctypes.POINTER(ctypes.c_uint8)
            transformed.argtypes = [
                u8p, u8p, ctypes.c_int32, u8p, u8p, ctypes.c_uint64,
                ctypes.c_uint64, ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32, ctypes.c_int32,
            ]
            transformed.restype = ctypes.c_int32

            for value in INPUTS:
                with self.subTest(value=value):
                    native = subprocess.run(
                        ["gdb", "-nx", "-q", "--batch", "-x", str(GDB_SCRIPT),
                         str(native_binary)],
                        cwd=ROOT,
                        env={**os.environ, "HYDIR_NATIVE_SNAPSHOT": str(SNAPSHOT),
                             "HYDIR_NATIVE_RETURN": f"0x{return_address:x}",
                             "HYDIR_NATIVE_RDI": f"0x{value:x}",
                             "HYDIR_NATIVE_RSI": "0x0", "HYDIR_NATIVE_MAX_VISITS": "4"},
                        capture_output=True, text=True, timeout=30,
                    )
                    self.assertEqual(native.returncode, 0, native.stdout + native.stderr)
                    rows = [line.removeprefix("HYDIR_NATIVE_RESULT=")
                            for line in native.stdout.splitlines()
                            if line.startswith("HYDIR_NATIVE_RESULT=")]
                    self.assertEqual(len(rows), 1, native.stdout + native.stderr)
                    observed = json.loads(rows[0])

                    state = (ctypes.c_uint8 * max(1, llvm["state_bytes"]))()
                    known = (ctypes.c_uint8 * max(1, llvm["state_bytes"]))()
                    seed_register(byte_map, state, known, 0x38, value)  # RDI
                    seed_register(byte_map, state, known, 0x20, 0x700000)  # RSP
                    guest = (ctypes.c_uint8 * 8)(*return_address.to_bytes(8, "little"))
                    guest_known = (ctypes.c_uint8 * 8)(*[255] * 8)
                    events = (ctypes.c_uint32 * 64)()
                    event_count = ctypes.c_uint32(0)
                    status = transformed(
                        state, known, 433, guest, guest_known, 0x700000, 8,
                        events, ctypes.byref(event_count), 64, 64,
                    )
                    self.assertEqual(status, 1)  # PcodeCfgLlvmStatus::Return
                    self.assertGreater(event_count.value, 0)
                    self.assertLessEqual(event_count.value, 64)
                    source_operations = llvm["source_operations"]
                    visits = []
                    for index in events[:event_count.value]:
                        self.assertLess(index, len(source_operations))
                        address = source_operations[index]["instruction_address"]["offset"]
                        if not visits or visits[-1] != address:
                            visits.append(address)
                    self.assertEqual(visits, observed["instruction_visits"])
                    self.assertEqual(observed["return_pc"], return_address)
                    self.assertEqual(observed["stack_delta"], 8)
                    self.assertEqual(register_bytes(byte_map, state, known, 0x0),
                                     observed["registers"]["rax"])
                    self.assertEqual(register_bytes(byte_map, state, known, 0x38),
                                     observed["registers"]["rdi"])
                    self.assertEqual(register_bytes(byte_map, state, known, 0x20),
                                     0x700000 + observed["stack_delta"])
                    for flag, offset in (("cf", 0x200), ("zf", 0x206),
                                         ("sf", 0x207), ("of", 0x20B)):
                        self.assertEqual(register_bytes(byte_map, state, known, offset, 1),
                                         observed["flags"][flag], flag)
                    self.assertEqual(bytes(guest), return_address.to_bytes(8, "little"))
                    self.assertEqual(bytes(guest_known), bytes([255] * 8))


if __name__ == "__main__":
    unittest.main()
