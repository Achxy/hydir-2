#!/usr/bin/env python3
"""Focused protocol tests for the optional Triton bridge."""

from __future__ import annotations

import json
import importlib.util
import os
import shutil
import subprocess
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_solver_uncertainty_does_not_discard_a_path_as_unsat(self) -> None:
        specification = importlib.util.spec_from_file_location("hydir_triton_bridge", BRIDGE)
        assert specification is not None and specification.loader is not None
        bridge = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(bridge)

        solver_state = types.SimpleNamespace(
            SAT=1, UNSAT=2, TIMEOUT=3, UNKNOWN=4, OUTOFMEM=5
        )
        branch = types.SimpleNamespace(
            isMultipleBranches=lambda: True,
            getBranchConstraints=lambda: [{"constraint": "selected_path"}],
        )
        for status, label in ((3, "timeout"), (4, "unknown"), (5, "outofmem")):
            context = types.SimpleNamespace(
                getPathConstraints=lambda: [branch],
                getModel=lambda predicate, **options: ({}, status, 2000),
            )
            with self.subTest(status=label), patch.dict(
                sys.modules, {"triton": types.SimpleNamespace(SOLVER_STATE=solver_state)}
            ):
                with self.assertRaisesRegex(ValueError, label):
                    bridge.path_witness(context, (0,))

        context = types.SimpleNamespace(
            getPathConstraints=lambda: [branch],
            getModel=lambda predicate, **options: ({}, solver_state.UNSAT, 2),
        )
        with patch.dict(sys.modules, {"triton": types.SimpleNamespace(SOLVER_STATE=solver_state)}):
            self.assertIsNone(bridge.path_witness(context, (0,)))

    @staticmethod
    def snapshot_request() -> dict:
        # movzx eax, byte ptr [rdi]; cmp eax, 0x41; sete al;
        # movzx eax, al; ret. The seed is 'B' and the goal needs 'A'.
        code = bytes.fromhex("0fb60783f8410f94c00fb6c0c3")
        code_page = code + bytes(4096 - len(code))
        input_page = b"B" + bytes(4095)
        stack_page = (0x4000).to_bytes(8, "little") + bytes(4088)
        registers = {name: 0 for name in (
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
            "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags",
        )}
        registers.update(rip=0x1000, rdi=0x2000, rsp=0x3000, eflags=0x202)
        return {
            "schema_version": 1,
            "operation": "snapshot_return",
            "binary_sha256": "0" * 64,
            "input_sha256": "1" * 64,
            "snapshot_sha256": "2" * 64,
            "probe_sha256": "3" * 64,
            "code_address": 0x1000,
            "code_hex": code.hex(),
            "registers": registers,
            "pages": [
                {"address": 0x1000, "bytes_hex": code_page.hex(),
                 "writable": False, "executable": True},
                {"address": 0x2000, "bytes_hex": input_page.hex(),
                 "writable": True, "executable": False},
                {"address": 0x3000, "bytes_hex": stack_page.hex(),
                 "writable": True, "executable": False},
            ],
            "symbolic_origin": {
                "id": "byte0", "channel": {"kind": "stdin"}, "offset": 0,
                "length": 1, "encoding": "raw", "alphabet_hex": "",
            },
            "origin_address": 0x2000,
            "seed_hex": "42",
            "origin_probe_evidence": "byte_equality_only",
            "assumptions": [
                "analyst_selected_origin_address_has_input_channel_bytes",
                "selected_code_extent_and_captured_pages_cover_this_function_path",
            ],
            "return_equals": 1,
            "max_seeds": 4,
            "max_instructions_per_seed": 32,
            "max_solver_queries": 32,
            "wall_timeout_ms": 20000,
            "solver_timeout_ms": 1000,
        }

    def test_snapshot_request_rejects_uncaptured_register_or_memory(self) -> None:
        missing_register = self.snapshot_request()
        del missing_register["registers"]["rbx"]
        result = self.run_bridge(missing_register)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("captured integer register set", result.stderr)

        missing_input_page = self.snapshot_request()
        missing_input_page["pages"] = missing_input_page["pages"][:1]
        result = self.run_bridge(missing_input_page)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not capture byte", result.stderr)

        forged_code = self.snapshot_request()
        forged_code["code_hex"] = "90" + forged_code["code_hex"][2:]
        result = self.run_bridge(forged_code)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("code_hex disagrees", result.stderr)

        overlapping = self.snapshot_request()
        overlapping["origin_address"] = 0x1000
        overlapping["seed_hex"] = "0f"
        result = self.run_bridge(overlapping)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("origin overlaps captured code", result.stderr)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_snapshot_return_finds_byte_function_witness(self) -> None:
        result = self.run_bridge(self.snapshot_request())
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "function_witness")
        self.assertEqual(report["candidate_hex"], "41")
        self.assertEqual(report["origin_probe_evidence"], "byte_equality_only")
        self.assertEqual(report["return_equals"], 1)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_snapshot_return_flips_a_branch_after_failed_seed(self) -> None:
        request = self.snapshot_request()
        code = bytes.fromhex("8a073c417506b801000000c331c0c3")
        request["code_hex"] = code.hex()
        request["pages"][0]["bytes_hex"] = (code + bytes(4096 - len(code))).hex()
        result = self.run_bridge(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "function_witness")
        self.assertEqual(report["candidate_hex"], "41")
        self.assertGreaterEqual(report["explored_seeds"], 2)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_snapshot_return_reports_query_budget_without_unsat_claim(self) -> None:
        request = self.snapshot_request()
        request["max_solver_queries"] = 1
        code = bytes.fromhex("8a073c417506b801000000c331c0c3")
        request["code_hex"] = code.hex()
        request["pages"][0]["bytes_hex"] = (code + bytes(4096 - len(code))).hex()
        result = self.run_bridge(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "budget_exhausted")
        self.assertIsNone(report["candidate_hex"])
        self.assertEqual(report["solver_queries"], 1)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_snapshot_return_reports_instruction_budget_on_loop(self) -> None:
        request = self.snapshot_request()
        request["code_hex"] = "ebfe"
        request["pages"][0]["bytes_hex"] = (bytes.fromhex("ebfe") + bytes(4094)).hex()
        request["max_instructions_per_seed"] = 8
        result = self.run_bridge(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "budget_exhausted")
        self.assertIsNone(report["candidate_hex"])
        self.assertEqual(report["processed_instructions"], 8)

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_snapshot_return_marks_uncaptured_runtime_read_unsupported(self) -> None:
        request = self.snapshot_request()
        request["registers"]["rdi"] = 0x5000
        result = self.run_bridge(request)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "unsupported_effect")
        self.assertIsNone(report["candidate_hex"])
        self.assertIn("uncaptured memory", report["diagnostic"])

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
    def test_longer_symbol_uses_at_most_fifteen_opcode_bytes(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "long_add",
                "entry_address": 0x401000,
                "code_hex": "90" * 20 + "4889f84801f0c3",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["paths"][0]["input_witness"], [0, 0])

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_function_longer_than_instruction_window(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "longer_than_15_bytes",
                "entry_address": 0x401000,
                "code_hex": "90" * 16 + "c3",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["instructions"]), 17)

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
        self.assertIn("arg0", output["final_registers"]["rax"])
        self.assertIn("arg1", output["final_registers"]["rax"])
        self.assertNotIn("ref!", output["final_registers"]["rax"])
        witnesses = [path["input_witness"] for path in output["paths"]]
        self.assertEqual(len(witnesses), 2)
        self.assertTrue(any(a < b for a, b in witnesses))
        self.assertTrue(any(a >= b for a, b in witnesses))

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_nested_branch_witnesses_satisfy_each_path(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "nested",
                "entry_address": 0x401000,
                "code_hex": "4889f84839f772034889f04883ff0074044883c001c3",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        witnesses = {tuple(path["input_witness"])
                     for path in json.loads(result.stdout)["paths"]}
        self.assertEqual(len(witnesses), 4)
        self.assertEqual({(a < b, a == 0) for a, b in witnesses},
                         {(False, False), (False, True), (True, False), (True, True)})

    @unittest.skipUnless(TRITON_PYTHON, "Triton Python bindings are optional")
    def test_direct_jump_after_branch_keeps_distinct_stack_values(self) -> None:
        result = self.run_bridge(
            {
                "schema_version": 1,
                "binary_sha256": "0" * 64,
                "function_symbol": "stack_branch",
                "entry_address": 0x401000,
                "code_hex": "4883ec104839f7730648893424eb0448893c24488b04244883c410c3",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = json.loads(result.stdout)["paths"]
        self.assertEqual(len(paths), 2)
        self.assertNotEqual(paths[0]["rax"], paths[1]["rax"])
        self.assertNotIn("ref!", paths[0]["rax"] + paths[1]["rax"])

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
