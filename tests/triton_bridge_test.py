#!/usr/bin/env python3
"""Focused protocol tests for the optional Triton bridge."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "scripts" / "triton_bridge.py"


def triton_python() -> str | None:
    """Find a Python interpreter with Triton without assuming its install path."""
    candidates = [os.environ.get("HYDIR_TRITON_PYTHON"), sys.executable]
    if os.name == "nt":
        launcher = shutil.which("py")
        if launcher:
            listing = subprocess.run(
                [launcher, "-0p"], text=True, capture_output=True, check=False
            )
            if listing.returncode == 0:
                candidates.extend(
                    token
                    for line in listing.stdout.splitlines()
                    for token in line.split()
                    if token.lower().endswith(".exe")
                )
    else:
        candidates.extend([shutil.which("python3"), shutil.which("python")])

    for candidate in dict.fromkeys(candidate for candidate in candidates if candidate):
        try:
            result = subprocess.run(
                [candidate, "-c", "import triton"],
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError:
            continue
        if result.returncode == 0:
            return candidate
    return None


TRITON_PYTHON = triton_python()


class TritonBridgeTests(unittest.TestCase):
    def run_bridge(self, request: dict) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [TRITON_PYTHON or sys.executable, str(BRIDGE)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            env=os.environ.copy(),
            check=False,
        )

    def test_malformed_request_fails_structurally(self) -> None:
        result = self.run_bridge({"schema_version": 999})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unsupported request schema", result.stderr)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_symbolic_add2(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "add2",
                "entry_address": 0x401000,
                "code_hex": "4889f84801f0c3",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["function_symbol"], "add2")
        self.assertEqual(output["code_size"], 7)
        self.assertEqual(output["symbolic_inputs"], ["arg0", "arg1"])
        self.assertGreaterEqual(len(output["instructions"]), 3)
        self.assertIn("bvadd", output["final_registers"]["rax"])

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_symbolic_max2_merges_both_paths(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "max2",
                "entry_address": 0x401000,
                "code_hex": "4889f84839f773034889f0c3",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(len(output["paths"]), 2)
        self.assertIn("ite", output["final_registers"]["rax"])
        self.assertIn("ref!0", output["final_registers"]["rax"])
        self.assertIn("ref!1", output["final_registers"]["rax"])

    def test_non_hex_digest_fails(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "g" * 64,
                "function_symbol": "add2",
                "entry_address": 0x401000,
                "code_hex": "c3",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("binary_sha256 must be hexadecimal", result.stderr)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_call_is_rejected_instead_of_lifted_linearly(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "call_like",
                "entry_address": 0x401000,
                "code_hex": "e800000000c3",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("call at", result.stderr)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_loop_is_rejected_with_a_bounded_error(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "loop_like",
                "entry_address": 0x401000,
                "code_hex": "ebfe",
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("control-flow loop", result.stderr)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_scoped_console_executes_symbolic_model_example(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "operation": "console",
                "commands": [
                    "from triton import *",
                    "ctx = TritonContext(ARCH.X86_64)",
                    "ctx.setConcreteRegisterValue(ctx.registers.rip, 0x40000)",
                    "ctx.symbolizeRegister(ctx.registers.rax, 'my_rax')",
                    "ctx.processing(Instruction(b'\\x48\\x35\\x34\\x12\\x00\\x00'))",
                    "ctx.processing(Instruction(b'\\x48\\x89\\xc1'))",
                    "rcx_expr = ctx.getSymbolicRegister(ctx.registers.rcx)",
                    "print(rcx_expr)",
                    "ctx.getModel(rcx_expr.getAst() == 0xdead)",
                    "hex(0xcc99 ^ 0x1234)",
                ],
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = json.loads(result.stdout)["entries"]
        self.assertIn("MOV operation", entries[7]["output"][0])
        self.assertIn("my_rax:64 = 0xcc99", entries[8]["output"][0])
        self.assertEqual(entries[9]["output"], ["'0xdead'"])

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_scoped_console_rejects_arbitrary_python(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "operation": "console",
                "commands": ["import os"],
            }
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the Triton console subset", result.stderr)


if __name__ == "__main__":
    unittest.main()
