import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hydir_sdk import LocalGhidra


class LocalGhidraTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / "input.elf"
        self.binary.write_bytes(b"\x7fELF")
        self.snapshot = Path(self.directory.name) / "snapshot.json"
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.client = LocalGhidra("hydirctl-test")

    def test_analyze_selects_function_and_checks_binary_identity(self):
        def run(*args):
            self.assertEqual(args[:2], ("ghidra", "analyze"))
            self.assertEqual(args[-2:], ("--function", "0x401000"))
            self.snapshot.write_text(json.dumps({
                "binary_sha256": self.digest,
                "selected_function": {"entry": {"offset": "0x401000"}},
            }), encoding="utf-8")
            return b"{}"

        with patch.object(self.client, "_run", side_effect=run):
            result = self.client.analyze(self.binary, self.snapshot, function=0x401000)
        self.assertEqual(result["binary_sha256"], self.digest)

        self.snapshot.write_text(json.dumps({"binary_sha256": "0" * 64}), encoding="utf-8")
        with patch.object(self.client, "_run", side_effect=run):
            # The wrong digest is rejected after the worker returns.
            with self.assertRaises(RuntimeError):
                self.client.artifact("state", self.binary, self.snapshot)

    def test_artifact_is_bound_to_binary_and_kind(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "schema_version": 1,
        }).encode()) as run:
            artifact = self.client.artifact("state", self.binary, self.snapshot)
        self.assertEqual(artifact["schema_version"], 1)
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "state"))
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "schema_version": 1,
            "cfg_completeness": "incomplete",
        }).encode()):
            self.assertEqual(self.client.artifact("cfg", self.binary, self.snapshot)["cfg_completeness"], "incomplete")
        with self.assertRaises(ValueError):
            self.client.artifact("made-up", self.binary, self.snapshot)

    def test_cfg_llvm_can_start_at_a_selected_instruction(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        artifact = {"binary_sha256": self.digest, "schema_version": 1, "stop_sites": []}
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()) as run:
            result = self.client.llvm_cfg(self.binary, self.snapshot, start=0x401000)
        self.assertEqual(result["stop_sites"], [])
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "llvm-cfg"))
        self.assertEqual(run.call_args.args[-2:], ("--start", "0x401000"))
        with self.assertRaises(ValueError):
            self.client.llvm_cfg(self.binary, self.snapshot, start=-1)

    def test_concrete_trace_forwards_seed_and_checks_identity(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        seed = Path(self.directory.name) / "seed.json"
        seed.write_text("{}", encoding="utf-8")
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "executed": [],
        }).encode()) as run:
            result = self.client.trace_prefix(self.binary, self.snapshot, seed, max_operations=3)
        self.assertEqual(result["executed"], [])
        self.assertEqual(run.call_args.args[1], "trace-prefix")
        self.assertEqual(run.call_args.args[-2:], ("--max-ops", "3"))
        with self.assertRaises(ValueError):
            self.client.trace_prefix(self.binary, self.snapshot, seed, max_operations=-1)
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "events": [],
        }).encode()) as run:
            path = self.client.trace_path(self.binary, self.snapshot, seed, start=0x401000)
        self.assertEqual(path["events"], [])
        self.assertEqual(run.call_args.args[1], "trace-path")
        self.assertEqual(run.call_args.args[-2:], ("--start", "0x401000"))
