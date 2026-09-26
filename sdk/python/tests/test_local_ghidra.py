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
        with self.assertRaises(ValueError):
            self.client.artifact("made-up", self.binary, self.snapshot)
