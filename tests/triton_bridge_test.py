#!/usr/bin/env python3
"""Focused protocol tests for the optional Triton bridge."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "scripts" / "triton_bridge.py"


class TritonBridgeTests(unittest.TestCase):
    def run_bridge(self, request: dict) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(BRIDGE)],
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

    @unittest.skipUnless(
        __import__("importlib.util").util.find_spec("triton") is not None,
        "Triton Python bindings are optional",
    )
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


if __name__ == "__main__":
    unittest.main()
