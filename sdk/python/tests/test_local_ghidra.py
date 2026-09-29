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

    def test_import_project_checks_program_binary_and_selected_function(self):
        project = Path(self.directory.name) / "Expert.gpr"
        project.write_bytes(b"")
        project.with_suffix(".rep").mkdir()

        def run(*args):
            self.assertEqual(args[:2], ("ghidra", "import-project"))
            self.assertEqual(args[2:4], (str(self.binary), str(project)))
            self.assertEqual(args[4:6], ("--program", "firmware/main.elf"))
            self.assertEqual(args[-2:], ("--function", "0x401000"))
            self.snapshot.write_text(json.dumps({
                "binary_sha256": self.digest,
                "selected_function": {"entry": {"offset": "0x401000"}},
            }), encoding="utf-8")
            return b"{}"

        with patch.object(self.client, "_run", side_effect=run):
            result = self.client.import_project(
                self.binary, project, "firmware/main.elf", self.snapshot,
                function=0x401000,
            )
        self.assertEqual(result["binary_sha256"], self.digest)
        with patch.object(self.client, "_run") as worker:
            for selector in ("../main.elf", "/main.elf", "firmware/*.elf", "firmware//main.elf", "firmware/\nmain.elf"):
                with self.assertRaises(ValueError):
                    self.client.import_project(self.binary, project, selector, self.snapshot)
            worker.assert_not_called()
        with patch.object(self.client, "_run", return_value=b"{}"):
            with self.assertRaises(RuntimeError):
                self.client.import_project(
                    self.binary, project, "firmware/main.elf", self.snapshot,
                    function=0x401001,
                )

        self.snapshot.write_text(json.dumps({
            "binary_sha256": "0" * 64,
            "selected_function": {"entry": {"offset": "0x401000"}},
        }), encoding="utf-8")
        with patch.object(self.client, "_run", return_value=b"{}"):
            with self.assertRaises(RuntimeError):
                self.client.import_project(
                    self.binary, project, "firmware/main.elf", self.snapshot,
                    function=0x401000,
                )

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
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "schema_version": 1,
            "opaque_effects": 2,
        }).encode()):
            self.assertEqual(self.client.artifact("coverage", self.binary, self.snapshot)["opaque_effects"], 2)
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "schema_version": 1,
            "stop_sites": [{"reason": "unsupported user operation"}],
        }).encode()) as run:
            self.assertEqual(len(self.client.artifact("capability", self.binary, self.snapshot)["stop_sites"]), 1)
            self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "capability"))
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "schema_version": 1,
            "rewrites": [],
        }).encode()) as run:
            self.assertEqual(self.client.artifact("simplify", self.binary, self.snapshot)["rewrites"], [])
            self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "simplify"))
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
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()) as run:
            self.client.llvm_cfg(self.binary, self.snapshot, simplified=True)
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "llvm-cfg-simplified"))
        image_artifact = {**artifact, "schema_version": 3}
        with patch.object(self.client, "_run", return_value=json.dumps(image_artifact).encode()) as run:
            self.client.llvm_cfg(self.binary, self.snapshot, image=True)
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "llvm-cfg-image"))
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()):
            with self.assertRaises(RuntimeError):
                self.client.llvm_cfg(self.binary, self.snapshot, image=True)
        process_artifact = {**artifact, "schema_version": 4, "process_memory": {"space": "ram"}}
        with patch.object(self.client, "_run", return_value=json.dumps(process_artifact).encode()) as run:
            self.client.llvm_cfg(self.binary, self.snapshot, process=True)
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "llvm-cfg-process"))
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()):
            with self.assertRaises(RuntimeError):
                self.client.llvm_cfg(self.binary, self.snapshot, process=True)
        allocations = Path(self.directory.name) / "allocations.json"
        allocations.write_text('{"schema_version":1,"regions":[]}', encoding="utf-8")
        allocated_artifact = {
            **artifact, "schema_version": 5,
            "process_memory": {"space": "ram"}, "allocations": {"regions": []},
        }
        with patch.object(self.client, "_run", return_value=json.dumps(allocated_artifact).encode()) as run:
            self.client.llvm_cfg(self.binary, self.snapshot, allocations=allocations)
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "llvm-cfg-allocated"))
        self.assertEqual(run.call_args.args[-2:], ("--allocations", str(allocations.resolve())))
        with self.assertRaises(ValueError):
            self.client.llvm_cfg(self.binary, self.snapshot, process=True, allocations=allocations)
        with self.assertRaises(ValueError):
            self.client.llvm_cfg(self.binary, self.snapshot, image=True, simplified=True)
        with self.assertRaises(ValueError):
            self.client.llvm_cfg(self.binary, self.snapshot, process=True, image=True)
        with self.assertRaises(ValueError):
            self.client.llvm_cfg(self.binary, self.snapshot, start=-1)

    def test_observed_call_rediscovery_uses_bounded_cli_contract(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        input_path = Path(self.directory.name) / "input.json"
        trace_path = Path(self.directory.name) / "trace.json"
        input_path.write_text("{}", encoding="utf-8")
        trace_path.write_text("{}", encoding="utf-8")
        plan = {
            "schema_version": 1, "binary_sha256": self.digest,
            "changed_targets": [], "unresolved_call_sites": [],
        }
        with patch.object(self.client, "_run", return_value=json.dumps(plan).encode()) as run:
            self.assertEqual(
                self.client.rediscover_calls(self.binary, self.snapshot, input_path, trace_path),
                plan,
            )
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "rediscover-calls"))
        applied = {
            "schema_version": 2, "binary_sha256": self.digest,
            "selected_function": {"entry": {"space": "ram", "offset": "0x401000"}},
        }
        with patch.object(self.client, "_run", return_value=json.dumps(applied).encode()) as run:
            self.assertEqual(
                self.client.rediscover_calls(
                    self.binary, self.snapshot, input_path, trace_path, apply=True
                ),
                applied,
            )
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "rediscover-apply"))
        with patch.object(self.client, "_run", return_value=b"{}"):
            with self.assertRaises(RuntimeError):
                self.client.rediscover_calls(self.binary, self.snapshot, input_path, trace_path)

        jump_plan = {
            "schema_version": 1, "binary_sha256": self.digest,
            "changed_targets": [], "unresolved_jump_sites": [],
        }
        with patch.object(self.client, "_run", return_value=json.dumps(jump_plan).encode()) as run:
            self.assertEqual(
                self.client.rediscover_jumps(self.binary, self.snapshot, input_path, trace_path),
                jump_plan,
            )
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "rediscover-jumps"))
        with patch.object(self.client, "_run", return_value=json.dumps(applied).encode()) as run:
            self.assertEqual(
                self.client.rediscover_jumps(
                    self.binary, self.snapshot, input_path, trace_path, apply=True,
                ),
                applied,
            )
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "rediscover-jumps-apply"))

    def test_observed_path_comparison_uses_bounded_cli_contract(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        paths = [Path(self.directory.name) / name for name in
                 ("input.json", "trace.json", "seed.json")]
        for path in paths:
            path.write_text("{}", encoding="utf-8")
        comparison = {
            "schema_version": 1, "binary_sha256": self.digest,
            "verdict": "inconclusive", "inconclusive_reasons": ["unknown memory"],
        }
        with patch.object(self.client, "_run", return_value=json.dumps(comparison).encode()) as run:
            self.assertEqual(
                self.client.compare_observed_path(self.binary, self.snapshot, *paths),
                comparison,
            )
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "compare-observed-path"))
        self.assertEqual(run.call_args.args[-2:], ("--memory", "readonly"))
        with self.assertRaises(ValueError):
            self.client.compare_observed_path(self.binary, self.snapshot, *paths, memory="unknown")
        allocations = Path(self.directory.name) / "allocations.json"
        allocations.write_text('{"schema_version":1,"regions":[]}', encoding="utf-8")
        with patch.object(self.client, "_run", return_value=json.dumps(comparison).encode()) as run:
            self.client.compare_observed_path(
                self.binary, self.snapshot, *paths, memory="allocated", allocations=allocations,
            )
        self.assertEqual(run.call_args.args[-2:], ("--allocations", str(allocations.resolve())))
        with self.assertRaises(ValueError):
            self.client.compare_observed_path(
                self.binary, self.snapshot, *paths, memory="allocated",
            )
        with patch.object(self.client, "_run", return_value=b"{}"):
            with self.assertRaises(RuntimeError):
                self.client.compare_observed_path(self.binary, self.snapshot, *paths)

    def test_call_trace_uses_managed_worker_and_checks_binary(self):
        seed = Path(self.directory.name) / "seed.json"
        seed.write_text("{}", encoding="utf-8")
        artifact = {"binary_sha256": self.digest, "schema_version": 1, "calls": []}
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()) as run:
            result = self.client.trace_calls(self.binary, seed, function=0x401000)
        self.assertEqual(result["calls"], [])
        self.assertEqual(run.call_args.args[:2], ("ghidra", "trace-calls"))
        self.assertIn("--function", run.call_args.args)
        self.assertIn("0x401000", run.call_args.args)
        allocations = Path(self.directory.name) / "allocations.json"
        allocations.write_text('{"schema_version":1,"regions":[]}', encoding="utf-8")
        allocated = {**artifact, "schema_version": 3}
        with patch.object(self.client, "_run", return_value=json.dumps(allocated).encode()) as run:
            self.client.trace_calls(self.binary, seed, function=0x401000, allocations=allocations)
        self.assertEqual(run.call_args.args[-2:], ("--allocations", str(allocations.resolve())))
        with self.assertRaises(ValueError):
            self.client.trace_calls(self.binary, seed, function=0x401000, max_depth=17)
        with patch.object(self.client, "_run", return_value=b'{"binary_sha256":"wrong"}'):
            with self.assertRaises(RuntimeError):
                self.client.trace_calls(self.binary, seed, function=0x401000)

    def test_interprocedural_cfg_llvm_checks_all_snapshot_identities(self):
        callee = Path(self.directory.name) / "callee.json"
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        callee.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        artifact = {
            "schema_version": 1, "binary_sha256": self.digest,
            "function_entries": [{}, {}], "snapshot_sha256": ["a", "b"],
            "llvm": {"binary_sha256": self.digest, "llvm_ir": "define i32 @hydir_pcode_cfg() { ret i32 1 }"},
        }
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()) as run:
            result = self.client.llvm_cfg_calls(self.binary, self.snapshot, (callee,), max_depth=2)
        self.assertEqual(len(result["function_entries"]), 2)
        self.assertEqual(run.call_args.args[:2], ("ghidra-snapshot", "llvm-cfg-calls"))
        self.assertIn("--callee", run.call_args.args)
        self.assertEqual(run.call_args.args[-2:], ("--max-depth", "2"))
        allocations = Path(self.directory.name) / "allocations.json"
        allocations.write_text('{"schema_version":1,"regions":[]}', encoding="utf-8")
        allocated = {**artifact, "llvm": {**artifact["llvm"], "schema_version": 5, "allocations": {}}}
        with patch.object(self.client, "_run", return_value=json.dumps(allocated).encode()) as run:
            self.client.llvm_cfg_calls(
                self.binary, self.snapshot, (callee,), allocations=allocations,
            )
        self.assertEqual(run.call_args.args[-2:], ("--allocations", str(allocations.resolve())))
        with self.assertRaises(ValueError):
            self.client.llvm_cfg_calls(self.binary, self.snapshot, (callee,), max_depth=17)
        callee.write_text(json.dumps({"binary_sha256": "0" * 64}), encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.client.llvm_cfg_calls(self.binary, self.snapshot, (callee,))

    def test_automatic_call_cfg_llvm_uses_managed_worker(self):
        seed = Path(self.directory.name) / "seed.json"
        seed.write_text("{}", encoding="utf-8")
        artifact = {
            "schema_version": 1, "binary_sha256": self.digest,
            "llvm": {"binary_sha256": self.digest, "llvm_ir": "module"},
        }
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()) as run:
            self.client.llvm_cfg_calls_auto(self.binary, seed, function=0x401000, max_functions=2)
        self.assertEqual(run.call_args.args[:2], ("ghidra", "llvm-cfg-calls"))
        self.assertIn("0x401000", run.call_args.args)
        self.assertIn("--max-functions", run.call_args.args)
        allocations = Path(self.directory.name) / "allocations.json"
        allocations.write_text('{"schema_version":1,"regions":[]}', encoding="utf-8")
        allocated = {**artifact, "llvm": {**artifact["llvm"], "schema_version": 5, "allocations": {}}}
        with patch.object(self.client, "_run", return_value=json.dumps(allocated).encode()) as run:
            self.client.llvm_cfg_calls_auto(
                self.binary, seed, function=0x401000, allocations=allocations,
            )
        self.assertEqual(run.call_args.args[-2:], ("--allocations", str(allocations.resolve())))
        with self.assertRaises(ValueError):
            self.client.llvm_cfg_calls_auto(self.binary, seed, function=0x401000, max_depth=17)

    def test_slice_uses_bounded_source_artifact(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        artifact = {
            "schema_version": 1,
            "binary_sha256": self.digest,
            "path_proven": False,
            "steps": [],
            "boundaries": [],
        }
        with patch.object(self.client, "_run", return_value=json.dumps(artifact).encode()) as run:
            result = self.client.slice(self.binary, self.snapshot, 3, 2, input_index=1)
        self.assertEqual(result["path_proven"], False)
        self.assertEqual(run.call_args.args[-6:],
                         ("--instruction", "3", "--op", "2", "--input", "1"))
        with self.assertRaises(ValueError):
            self.client.slice(self.binary, self.snapshot, -1, 0)
        with patch.object(self.client, "_run", return_value=json.dumps({
            **artifact, "path_proven": True,
        }).encode()):
            with self.assertRaises(RuntimeError):
                self.client.slice(self.binary, self.snapshot, 0, 0)

    def test_saved_snapshot_roundtrip_commands_check_binary_and_function(self):
        self.snapshot.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        saved = {"binary_sha256": self.digest, "selected_function": {"space": "ram", "offset": "0x401000"}}
        with patch.object(self.client, "_run", return_value=json.dumps(saved).encode()) as run:
            self.client.save_snapshot(self.binary, self.snapshot)
        self.assertEqual(run.call_args.args[:2], ("ghidra-project", "save"))
        reopened = {"binary_sha256": self.digest, "selected_function": {"entry": saved["selected_function"]}}
        with patch.object(self.client, "_run", return_value=json.dumps(reopened).encode()) as run:
            self.assertEqual(self.client.saved_snapshot(self.binary, 0x401000), reopened)
        self.assertEqual(run.call_args.args[-2:], ("--function", "0x401000"))
        with patch.object(self.client, "_run", return_value=json.dumps(reopened).encode()):
            with self.assertRaises(RuntimeError):
                self.client.saved_snapshot(self.binary, 0x401001)

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
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "events": [],
        }).encode()) as run:
            self.client.trace_path(self.binary, self.snapshot, seed, memory="process")
        self.assertEqual(run.call_args.args[-2:], ("--memory", "process"))
        allocations = Path(self.directory.name) / "allocations.json"
        allocations.write_text('{"schema_version":1,"regions":[]}', encoding="utf-8")
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "events": [],
        }).encode()) as run:
            self.client.trace_path(
                self.binary, self.snapshot, seed, memory="allocated", allocations=allocations,
            )
        self.assertEqual(run.call_args.args[-2:], ("--allocations", str(allocations.resolve())))
        with self.assertRaises(ValueError):
            self.client.trace_path(self.binary, self.snapshot, seed, memory="allocated")
        with self.assertRaises(ValueError):
            self.client.trace_path(self.binary, self.snapshot, seed, memory="invented")
        with patch.object(self.client, "_run", return_value=json.dumps({
            "binary_sha256": self.digest, "schema_version": 1,
        }).encode()) as run:
            self.client.artifact("process-memory", self.binary, self.snapshot)
        self.assertEqual(run.call_args.args[1], "process-memory")

    def test_observe_checks_input_and_selected_function(self):
        input_path = Path(self.directory.name) / "input.json"
        input_path.write_text(json.dumps({"binary_sha256": self.digest}), encoding="utf-8")
        trace = {
            "schema_version": 1, "binary_sha256": self.digest,
            "input_sha256": "a" * 64, "selected_elf_vaddr": 0x401000,
            "status": "completed", "events": [],
        }
        with patch.object(self.client, "_run", return_value=json.dumps(trace).encode()) as run:
            self.assertEqual(
                self.client.observe(self.binary, input_path, function=0x401000)["status"],
                "completed",
            )
        self.assertEqual(run.call_args.args[:2], ("observe", "frida"))
        self.assertEqual(run.call_args.args[-2:], ("--function", "0x401000"))
        with patch.object(self.client, "_run", return_value=json.dumps({
            **trace, "schema_version": 2,
        }).encode()):
            self.client.observe(self.binary, input_path, function=0x401000)
        with patch.object(self.client, "_run", return_value=json.dumps({
            **trace, "selected_elf_vaddr": 0x401001,
        }).encode()):
            with self.assertRaises(RuntimeError):
                self.client.observe(self.binary, input_path, function=0x401000)
        input_path.write_text(json.dumps({"binary_sha256": "0" * 64}), encoding="utf-8")
        with patch.object(self.client, "_run") as run:
            with self.assertRaises(ValueError):
                self.client.observe(self.binary, input_path, function=0x401000)
            run.assert_not_called()

    def test_observation_seed_uses_checked_cli_bridge(self):
        input_path = Path(self.directory.name) / "input.json"
        trace_path = Path(self.directory.name) / "trace.json"
        input_path.write_text("{}", encoding="utf-8")
        trace_path.write_text("{}", encoding="utf-8")
        selected = {"space": "ram", "offset": "0x401000"}
        self.snapshot.write_text(json.dumps({
            "binary_sha256": self.digest,
            "selected_function": {"entry": selected},
        }), encoding="utf-8")
        seed = {"schema_version": 1, "binary_sha256": self.digest,
                "entry": selected, "registers": [], "memory": []}
        with patch.object(self.client, "_run", return_value=json.dumps(seed).encode()) as run:
            self.assertEqual(self.client.seed_from_observation(
                self.binary, input_path, self.snapshot, trace_path), seed)
        self.assertEqual(run.call_args.args[:2], ("observe", "seed"))
        with patch.object(self.client, "_run", return_value=json.dumps({
            **seed, "memory": [{"space": "ram"}],
        }).encode()):
            with self.assertRaises(RuntimeError):
                self.client.seed_from_observation(
                    self.binary, input_path, self.snapshot, trace_path)
