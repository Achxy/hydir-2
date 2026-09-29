import os
import tempfile
import unittest
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

from hydir_sdk import HydirClient
from hydir_sdk import hydir_pb2 as proto
from hydir_sdk import hydir_v2_pb2 as proto_v2
from hydir_sdk import hydir_v3_pb2 as proto_v3


class ClientBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.token = Path(self.directory.name) / "token"
        self.token.write_text("a" * 64, encoding="ascii")
        os.chmod(self.token, 0o600)

    def test_plaintext_non_loopback_is_refused(self):
        with self.assertRaises(ValueError):
            HydirClient("http://192.0.2.1:50051", self.token)
        with HydirClient("https://hydir.example:50051", self.token):
            pass
        with self.assertRaises(ValueError):
            HydirClient("https://hydir.example:50051/api", self.token)

    def test_compact_jwt_credential_is_accepted_without_network_use(self):
        self.token.write_text("eyJhbGciOiJSUzI1NiJ9.e30.signature", encoding="ascii")
        with HydirClient("https://hydir.example:50051", self.token):
            pass
        self.token.write_text("header..signature", encoding="ascii")
        with self.assertRaises(ValueError):
            HydirClient("https://hydir.example:50051", self.token)

    @unittest.skipUnless(os.name == "posix", "Unix file modes required")
    def test_non_private_credential_is_refused(self):
        os.chmod(self.token, 0o644)
        with self.assertRaises(ValueError):
            HydirClient("http://127.0.0.1:50051", self.token)

    def test_artifact_hash_is_checked_and_export_never_overwrites(self):
        with self.assertRaises(RuntimeError):
            HydirClient._checked_artifact(proto.ArtifactReply(content=b"IR", sha256="0" * 64))
        output = Path(self.directory.name) / "artifact.ll"
        HydirClient.export_artifact(b"IR", output)
        with self.assertRaises(FileExistsError):
            HydirClient.export_artifact(b"different", output)
        self.assertEqual(output.read_bytes(), b"IR")

    def test_decompile_requires_explicit_prototype(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.decompile("project", 1, "symbol", assume_u64x2=False)

    def test_patch_requires_all_assertions_before_network_use(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.apply_patch(
                    "project", 1, b"{}", trusted_fixture=True,
                    assume_u64x2=True, assume_entry_only=False,
                )

    def test_v2_region_artifact_is_hash_media_schema_and_revision_checked(self):
        content = json.dumps({
            "schema_version": 3,
            "binary_sha256": "a" * 64,
        }).encode("utf-8")
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            client._call = lambda *_: proto_v2.ArtifactReply(
                sha256=__import__("hashlib").sha256(content).hexdigest(),
                media_type="application/vnd.hydir.region-spec+json;version=3",
                content=content,
                project_revision=4,
            )
            region = client.get_region("project", 4, "symbol", assume_u64x2=True)
            self.assertEqual(region["schema_version"], 3)
            with self.assertRaises(ValueError):
                client.get_region("project", 4, "symbol", assume_u64x2=False)

    def test_v2_physical_region_ir_is_checked_and_requires_prototype(self):
        content = json.dumps({
            "schema_version": 1,
            "binary_sha256": "a" * 64,
            "lowering_ready": False,
        }).encode("utf-8")
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            client._call = lambda *_: proto_v2.ArtifactReply(
                sha256=__import__("hashlib").sha256(content).hexdigest(),
                media_type="application/vnd.hydir.physical-region-ir+json;version=1",
                content=content,
                project_revision=4,
            )
            ir = client.lift_region("project", 4, "symbol", assume_u64x2=True)
            self.assertFalse(ir["lowering_ready"])
            with self.assertRaises(ValueError):
                client.lift_region("project", 4, "symbol", assume_u64x2=False)

    def test_v2_patch_compile_requires_all_assertions_before_network_use(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.compile_patch_bundle(
                    "project", 1, b"{}", trusted_fixture=True,
                    assume_u64x2=False, assume_entry_only=True,
                )
            with self.assertRaises(ValueError):
                client.verify_patch_bundle("project", 1, b"")

    def test_v3_native_artifacts_are_hash_media_schema_and_revision_checked(self):
        content = json.dumps({
            "schema_version": 5,
            "binary_sha256": "a" * 64,
        }).encode("utf-8")
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=__import__("hashlib").sha256(content).hexdigest(),
                media_type="application/vnd.hydir.program-spec+json;version=5",
                content=content,
                project_revision=4,
            )
            artifact = client.get_program_artifact("project", 4, "program_spec")
            self.assertEqual(artifact["schema_version"], 5)
            with self.assertRaises(ValueError):
                client.get_program_artifact("project", 4, "machine")
            with self.assertRaises(ValueError):
                client.get_program_artifact("project", 4, "coverage", "function")
            cfg_content = json.dumps({
                "schema_version": 3,
                "binary_sha256": "a" * 64,
                "model_revision": 1,
                "blocks": [],
            }).encode("utf-8")
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=__import__("hashlib").sha256(cfg_content).hexdigest(),
                media_type="application/vnd.hydir.high-level-cfg-cir+json;version=3",
                content=cfg_content,
                project_revision=4,
            )
            artifact = client.get_program_artifact(
                "project", 4, "high_level_cfg_cir", "hydir_cfg_sum"
            )
            self.assertEqual(artifact["schema_version"], 3)

    def test_v3_frida_observation_job_and_artifact_are_revision_checked(self):
        binary_sha = "a" * 64
        spec = {"schema_version": 1, "binary_sha256": binary_sha}
        selected = 0x401000
        trace = {
            "schema_version": 2, "binary_sha256": binary_sha,
            "selected_elf_vaddr": selected, "observer": "hydir-frida-observer",
            "status": "completed", "events": [],
        }
        content = json.dumps(trace).encode()
        digest = hashlib.sha256(content).hexdigest()
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            requests = []

            def start_call(method, request):
                self.assertIs(method, client._stub_v3.StartFridaObservation)
                requests.append(request)
                return proto_v3.JobReply(
                    project_id="project", job_id="job", project_revision=4,
                    kind="frida-observation", state="queued",
                )

            client._call = start_call
            job = client.start_frida_observation(
                "project", 4, spec, selected, idempotency_key="frida-1",
            )
            self.assertEqual(job.job_id, "job")
            self.assertEqual(requests[0].expected_revision, 4)
            self.assertEqual(requests[0].selected_elf_vaddr, selected)
            self.assertEqual(json.loads(requests[0].input_spec_json), spec)
            with self.assertRaises(ValueError):
                client.start_frida_observation("project", 4, spec, 0)
            with self.assertRaises(ValueError):
                client.start_frida_observation("project", 4, spec, selected,
                                               idempotency_key="bad\nkey")

            def artifact_call(method, request):
                self.assertIs(method, client._stub_v3.GetFridaObservation)
                self.assertEqual(request.job_id, "job")
                return proto_v3.ArtifactReply(
                    sha256=digest,
                    media_type="application/vnd.hydir.dynamic-trace+json;version=2",
                    content=content, project_revision=4,
                )

            client._call = artifact_call
            self.assertEqual(client.get_frida_observation(
                "project", "job", revision=4, artifact_sha256=digest,
                binary_sha256=binary_sha, selected_elf_vaddr=selected,
            ), trace)
            with self.assertRaises(RuntimeError):
                client.get_frida_observation(
                    "project", "job", revision=5, artifact_sha256=digest,
                    binary_sha256=binary_sha, selected_elf_vaddr=selected,
                )
            changed = dict(trace, exit_code=0)
            changed_content = json.dumps(changed).encode()
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(changed_content).hexdigest(),
                media_type="application/vnd.hydir.dynamic-trace+json;version=2",
                content=changed_content, project_revision=4,
            )
            with self.assertRaises(RuntimeError):
                client.get_frida_observation(
                    "project", "job", revision=4,
                    artifact_sha256=hashlib.sha256(changed_content).hexdigest(),
                    binary_sha256=binary_sha, selected_elf_vaddr=selected,
                )

    def test_v3_analysis_model_read_and_revisioned_save(self):
        model = {"schema_version": 1, "binary_sha256": "a" * 64, "revision": 2}
        content = json.dumps(model).encode("utf-8")
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            requests = []

            def read_call(method, request):
                self.assertIs(method, client._stub_v3.GetAnalysisModel)
                requests.append(request)
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(content).hexdigest(),
                    media_type="application/vnd.hydir.analysis-model+json;version=1",
                    content=content,
                    project_revision=4,
                )

            client._call = read_call
            self.assertEqual(client.get_analysis_model("project", 4), model)
            self.assertEqual(requests[0].expected_revision, 4)

            def save_call(method, request):
                self.assertIs(method, client._stub_v3.SaveAnalysisModel)
                requests.append(request)
                return proto_v3.MutationReply(
                    project_id="project", revision=5, binary_sha256="a" * 64,
                )

            client._call = save_call
            reply = client.save_analysis_model(
                "project", 4, model, idempotency_key="edit-1",
            )
            self.assertEqual(reply.revision, 5)
            self.assertEqual(requests[1].idempotency_key, "edit-1")
            self.assertEqual(json.loads(requests[1].model_json), model)
            with self.assertRaises(ValueError):
                client.save_analysis_model("project", 4, {"schema_version": 2})
            with self.assertRaises(ValueError):
                client.save_analysis_model("project", 4, model, idempotency_key="\n")

    def test_v3_ghidra_snapshot_artifact_uses_revisioned_rpc_and_checks_reply(self):
        snapshot = Path(self.directory.name) / "snapshot.json"
        snapshot.write_bytes(b'{"schema_version":2}')
        artifact = json.dumps({"schema_version": 2, "llvm_ir": "define void @f() {}"}).encode()
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            requests = []

            def call(method, request):
                self.assertIs(method, client._stub_v3.AnalyzeGhidraSnapshot)
                requests.append(request)
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(artifact).hexdigest(),
                    media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=2",
                    content=artifact,
                    project_revision=4,
                )

            client._call = call
            result = client.analyze_ghidra_snapshot(
                "project", 4, snapshot, "llvm-cfg", start_address=0x20137C
            )
            self.assertEqual(result["schema_version"], 2)
            self.assertEqual(len(requests), 1)
            self.assertEqual(requests[0].snapshot_json, snapshot.read_bytes())
            self.assertEqual(requests[0].start_address, "0x20137c")
            self.assertEqual(requests[0].expected_revision, 4)
            self.assertEqual(requests[0].stage, "llvm-cfg")

            image_artifact = json.dumps({
                "schema_version": 3,
                "read_only_image": {
                    "space": "ram", "base": 0x200000, "byte_len": 1,
                    "known_byte_count": 1, "contents_sha256": "a" * 64,
                },
            }).encode()
            client._call = lambda _, request: (
                requests.append(request) or proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(image_artifact).hexdigest(),
                    media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=3",
                    content=image_artifact,
                    project_revision=4,
                )
            )
            image_result = client.analyze_ghidra_snapshot(
                "project", 4, snapshot, "llvm-cfg-image", start_address=0x20137C
            )
            self.assertEqual(image_result["read_only_image"]["known_byte_count"], 1)
            self.assertEqual(requests[-1].stage, "llvm-cfg-image")
            self.assertEqual(requests[-1].start_address, "0x20137c")
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(artifact).hexdigest(),
                media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=3",
                content=artifact,
                project_revision=4,
            )
            with self.assertRaises(RuntimeError):
                client.analyze_ghidra_snapshot("project", 4, snapshot, "llvm-cfg-image")

            process_artifact = json.dumps({
                "schema_version": 1,
                "binary_sha256": "a" * 64,
                "snapshot_layout_sha256": "b" * 64,
                "space": "ram", "base": 0x200000,
                "bytes": [42, 0], "known": [255, 255],
                "mapped": [255, 255], "writable": [0, 255],
            }).encode()
            client._call = lambda _, request: (
                requests.append(request) or proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(process_artifact).hexdigest(),
                    media_type="application/vnd.hydir.pcode-process-memory+json;version=1",
                    content=process_artifact,
                    project_revision=4,
                )
            )
            process_result = client.analyze_ghidra_snapshot(
                "project", 4, snapshot, "process-memory"
            )
            self.assertEqual(process_result["writable"], [0, 255])
            self.assertEqual(requests[-1].stage, "process-memory")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "process-memory", start_address=0x10
                )

            process_llvm_artifact = json.dumps({
                "schema_version": 4,
                "process_memory": {
                    "space": "ram", "base": 0x200000, "byte_len": 2,
                    "known_byte_count": 2, "mapped_byte_count": 2,
                    "writable_byte_count": 1, "contents_sha256": "c" * 64,
                },
            }).encode()
            client._call = lambda _, request: (
                requests.append(request) or proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(process_llvm_artifact).hexdigest(),
                    media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=4",
                    content=process_llvm_artifact,
                    project_revision=4,
                )
            )
            process_llvm = client.analyze_ghidra_snapshot(
                "project", 4, snapshot, "llvm-cfg-process", start_address=0x20137C
            )
            self.assertEqual(process_llvm["process_memory"]["writable_byte_count"], 1)
            self.assertEqual(requests[-1].start_address, "0x20137c")

            simplified = json.dumps({"schema_version": 1, "rewrites": []}).encode()
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(simplified).hexdigest(),
                media_type="application/vnd.hydir.pcode-simplification+json;version=1",
                content=simplified,
                project_revision=4,
            )
            self.assertEqual(
                client.analyze_ghidra_snapshot("project", 4, snapshot, "simplify")["rewrites"],
                [],
            )

            capability = json.dumps({"schema_version": 1, "stop_sites": []}).encode()
            client._call = lambda _, request: (
                requests.append(request) or proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(capability).hexdigest(),
                    media_type="application/vnd.hydir.pcode-capability+json;version=1",
                    content=capability,
                    project_revision=4,
                )
            )
            self.assertEqual(
                client.analyze_ghidra_snapshot("project", 4, snapshot, "capability")["stop_sites"],
                [],
            )
            self.assertEqual(requests[-1].stage, "capability")

            transformed = json.dumps({"schema_version": 1, "simplification": {"rewrites": []}}).encode()
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(transformed).hexdigest(),
                media_type="application/vnd.hydir.pcode-simplified-cfg-llvm+json;version=1",
                content=transformed,
                project_revision=4,
            )
            self.assertEqual(
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "llvm-cfg-simplified", start_address=0x20137C
                )["simplification"]["rewrites"],
                [],
            )

            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(artifact).hexdigest(),
                media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=2",
                content=artifact,
                project_revision=5,
            )
            with self.assertRaises(RuntimeError):
                client.analyze_ghidra_snapshot("project", 4, snapshot.read_bytes(), "llvm-cfg")

    def test_v3_allocated_process_llvm_requires_declared_ranges_and_v5_binding(self):
        snapshot = b'{"schema_version":2}'
        declaration = b'{"schema_version":1,"regions":[]}'
        artifact = json.dumps({
            "schema_version": 5, "binary_sha256": "a" * 64,
            "process_memory": {
                "space": "ram", "base": 0x200000, "byte_len": 2,
                "known_byte_count": 2, "mapped_byte_count": 2,
                "writable_byte_count": 1, "contents_sha256": "b" * 64,
            },
            "allocations": {
                "schema_version": 1, "binary_sha256": "a" * 64,
                "snapshot_layout_sha256": "c" * 64, "regions": [],
            },
            "state_abi": "hydir-pcode-cfg-state-v5: test",
        }).encode()
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            requests = []

            def call(method, request):
                self.assertIs(method, client._stub_v3.AnalyzeGhidraSnapshot)
                requests.append(request)
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(artifact).hexdigest(), content=artifact,
                    media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=5",
                    project_revision=4,
                )

            client._call = call
            result = client.analyze_ghidra_snapshot(
                "project", 4, snapshot, "llvm-cfg-process-allocated",
                start_address=0x20137C, allocations=declaration,
            )
            self.assertEqual(result["allocations"]["schema_version"], 1)
            self.assertEqual(requests[-1].allocation_json, declaration)
            self.assertEqual(requests[-1].start_address, "0x20137c")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "llvm-cfg-process-allocated"
                )
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "llvm-cfg-process", allocations=declaration
                )
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "llvm-cfg-process-allocated", allocations=b"x" * 4097
                )
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(artifact).hexdigest(), content=artifact,
                media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=4",
                project_revision=4,
            )
            with self.assertRaises(RuntimeError):
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "llvm-cfg-process-allocated", allocations=declaration
                )
            wrong = json.loads(artifact)
            wrong["allocations"]["regions"] = [
                {"kind": "stack", "space": "ram", "base": 7340032, "byte_len": 16}
            ]
            wrong_bytes = json.dumps(wrong).encode()
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(wrong_bytes).hexdigest(), content=wrong_bytes,
                media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=5",
                project_revision=4,
            )
            with self.assertRaises(RuntimeError):
                client.analyze_ghidra_snapshot(
                    "project", 4, snapshot, "llvm-cfg-process-allocated", allocations=declaration
                )

    def test_v3_observation_artifacts_are_revision_and_claim_checked(self):
        snapshot = b'{"schema_version":2}'
        input_spec = b'{"schema_version":1}'
        trace = b'{"schema_version":1}'
        seed = b'{"schema_version":1}'
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            requests = []

            def call(method, request):
                self.assertIs(method, client._stub_v3.AnalyzeGhidraObservation)
                requests.append(request)
                if request.stage == "observed-call-rediscovery":
                    content = b'{"schema_version":1,"changed_targets":[]}'
                    media_type = "application/vnd.hydir.observed-call-rediscovery+json;version=1"
                else:
                    content = b'{"schema_version":1,"same_initial_state_proven":false}'
                    media_type = "application/vnd.hydir.pcode-observed-path-comparison+json;version=1"
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(content).hexdigest(),
                    media_type=media_type, content=content, project_revision=4,
                )

            client._call = call
            plan = client.analyze_ghidra_observation(
                "project", 4, snapshot, input_spec, trace, "observed-call-rediscovery"
            )
            self.assertEqual(plan["changed_targets"], [])
            self.assertEqual(requests[-1].snapshot_json, snapshot)
            self.assertEqual(requests[-1].input_spec_json, input_spec)
            self.assertEqual(requests[-1].trace_json, trace)
            self.assertEqual(requests[-1].seed_json, b"")
            comparison = client.analyze_ghidra_observation(
                "project", 4, snapshot, input_spec, trace,
                "observed-path-comparison", seed=seed,
            )
            self.assertIs(comparison["same_initial_state_proven"], False)
            self.assertEqual(requests[-1].seed_json, seed)
            client._call = lambda *_: self.fail("invalid request reached server")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_observation(
                    "project", 4, snapshot, input_spec, trace, "observed-path-comparison"
                )
            with self.assertRaises(ValueError):
                client.analyze_ghidra_observation(
                    "project", 4, snapshot, input_spec, trace, "observed-call-rediscovery", seed=seed
                )
            with self.assertRaises(ValueError):
                client.analyze_ghidra_observation(
                    "project", 4, b"", input_spec, trace, "observed-call-rediscovery"
                )
            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(b'{"schema_version":1,"same_initial_state_proven":true}').hexdigest(),
                media_type="application/vnd.hydir.pcode-observed-path-comparison+json;version=1",
                content=b'{"schema_version":1,"same_initial_state_proven":true}',
                project_revision=4,
            )
            with self.assertRaises(RuntimeError):
                client.analyze_ghidra_observation(
                    "project", 4, snapshot, input_spec, trace,
                    "observed-path-comparison", seed=seed,
                )

    def test_v3_ghidra_snapshot_rejects_invalid_request_before_network(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            client._call = lambda *_: self.fail("invalid request reached the server")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot("project", 4, b"{}", "llvm-prefix")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot("project", 4, b"{}", "cfg", start_address=0x10)
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot("project", 4, b"{}", "llvm-cfg", start_address="0xGG")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot("project", 4, b"", "pcode")
            oversized = Path(self.directory.name) / "oversized.json"
            with oversized.open("wb") as handle:
                handle.truncate(16 * 1024 * 1024 + 1)
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot("project", 4, oversized, "pcode")

    def test_v3_ghidra_slice_preserves_zero_index_presence_and_fidelity(self):
        content = json.dumps({
            "schema_version": 1, "binary_sha256": "a" * 64,
            "path_proven": False, "steps": [], "boundaries": [],
        }).encode()
        requests = []
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            def call(_method, request):
                requests.append(request)
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(content).hexdigest(),
                    media_type="application/vnd.hydir.pcode-slice+json;version=1",
                    content=content, project_revision=4,
                )
            client._call = call
            result = client.analyze_ghidra_snapshot(
                "project", 4, b"{}", "slice",
                instruction_index=0, operation_index=0, input_index=0,
            )
            self.assertIs(result["path_proven"], False)
            self.assertTrue(requests[0].HasField("instruction_index"))
            self.assertTrue(requests[0].HasField("operation_index"))
            self.assertTrue(requests[0].HasField("input_index"))
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot("project", 4, b"{}", "slice")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_snapshot(
                    "project", 4, b"{}", "state", instruction_index=0,
                )

    def test_v3_automatic_ghidra_uses_uploaded_binary_and_selected_entry(self):
        content = json.dumps({"schema_version": 1, "binary_sha256": "a" * 64}).encode()
        requests = []
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            def call(method, request):
                self.assertIs(method, client._stub_v3.AnalyzeGhidraSnapshot)
                requests.append(request)
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(content).hexdigest(),
                    media_type="application/vnd.hydir.pcode-ir+json;version=1",
                    content=content, project_revision=4,
                )
            client._call = call
            self.assertEqual(
                client.analyze_ghidra_binary(
                    "project", 4, "pcode", selected_function_entry=0x101320,
                )["schema_version"],
                1,
            )
            self.assertTrue(requests[0].automatic)
            self.assertEqual(requests[0].snapshot_json, b"")
            self.assertEqual(requests[0].selected_function_entry, "0x101320")
            with self.assertRaises(ValueError):
                client.analyze_ghidra_binary(
                    "project", 4, "pcode", selected_function_entry="0xGG",
                )
            self.assertEqual(len(requests), 1)

    def test_v3_direct_call_trace_is_seed_and_revision_bound(self):
        digest = "a" * 64
        seed = json.dumps({
            "schema_version": 1,
            "binary_sha256": digest,
            "entry": {"space": "ram", "offset": "0x2013a9"},
            "registers": [], "memory": [],
        }).encode()
        trace = json.dumps({
            "schema_version": 2, "binary_sha256": digest,
            "root_entry": {"space": "ram", "offset": "0x2013a9"},
            "segments": [], "calls": [],
        }).encode()
        requests = []
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            def call(method, request, **kwargs):
                self.assertIs(method, client._stub_v3.TraceGhidraCalls)
                requests.append((request, kwargs))
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(trace).hexdigest(),
                    media_type="application/vnd.hydir.pcode-call-trace+json;version=2",
                    content=trace, project_revision=4,
                )
            client._call = call
            result = client.trace_ghidra_calls(
                "project", 4, seed, function_entry=0x2013a9, max_functions=2,
            )
            self.assertEqual(result["root_entry"]["offset"], "0x2013a9")
            self.assertEqual(requests[0][0].seed_json, seed)
            self.assertEqual(requests[0][0].max_functions, 2)
            self.assertEqual(requests[0][1]["timeout"], 180.0)
            with self.assertRaises(ValueError):
                client.trace_ghidra_calls("project", 4, seed, function_entry=0x2013a2)
            with self.assertRaises(ValueError):
                client.trace_ghidra_calls(
                    "project", 4, seed, function_entry=0x2013a9, max_functions=9,
                )
            self.assertEqual(len(requests), 1)

    def test_v3_call_cfg_llvm_checks_artifact_identity(self):
        digest = "a" * 64
        seed = json.dumps({
            "schema_version": 1, "binary_sha256": digest,
            "entry": {"space": "ram", "offset": "0x2013a9"},
            "registers": [], "memory": [],
        }).encode()
        artifact = {
            "schema_version": 1, "binary_sha256": digest,
            "function_entries": [{"space": "ram", "offset": "0x2013a9"}],
            "snapshot_sha256": ["b" * 64], "snapshot_diagnostics": [],
            "llvm": {
                "schema_version": 2, "binary_sha256": digest,
                "start": {"space": "ram", "offset": "0x2013a9"},
                "llvm_ir": "define void @f() { ret void }",
            },
        }
        requests = []
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            def call(method, request, **kwargs):
                self.assertIs(method, client._stub_v3.BuildGhidraCallCfgLlvm)
                requests.append((request, kwargs))
                content = json.dumps(artifact).encode()
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(content).hexdigest(),
                    media_type="application/vnd.hydir.pcode-interprocedural-cfg-llvm+json;version=1",
                    content=content, project_revision=4,
                )
            client._call = call
            self.assertEqual(
                client.build_ghidra_call_cfg_llvm(
                    "project", 4, seed, function_entry=0x2013a9, max_functions=2,
                )["function_entries"][0]["offset"],
                "0x2013a9",
            )
            self.assertEqual(requests[0][0].seed_json, seed)
            self.assertEqual(requests[0][0].max_functions, 2)
            self.assertEqual(requests[0][1]["timeout"], 180.0)
            artifact["llvm"]["binary_sha256"] = "0" * 64
            with self.assertRaises(RuntimeError):
                client.build_ghidra_call_cfg_llvm(
                    "project", 4, seed, function_entry=0x2013a9,
                )
            with self.assertRaises(ValueError):
                client.build_ghidra_call_cfg_llvm(
                    "project", 4, seed, function_entry=0x2013a2,
                )
            self.assertEqual(len(requests), 2)

    def test_v3_function_assessment_is_seed_bound_and_unverified(self):
        digest = "a" * 64
        entry = {"space": "ram", "offset": "0x2013a9"}
        seed = json.dumps({
            "schema_version": 1, "binary_sha256": digest,
            "entry": entry, "registers": [], "memory": [],
        }).encode()
        artifact = {
            "schema_version": 1, "binary_sha256": digest,
            "seed_sha256": hashlib.sha256(seed).hexdigest(),
            "entry": entry, "static_capability": {},
            "trace": {"root_entry": entry}, "verification": "not_run",
        }
        requests = []
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            def call(method, request, **kwargs):
                self.assertIs(method, client._stub_v3.AssessGhidraFunction)
                requests.append(request)
                content = json.dumps(artifact).encode()
                return proto_v3.ArtifactReply(
                    sha256=hashlib.sha256(content).hexdigest(),
                    media_type="application/vnd.hydir.pcode-function-assessment+json;version=1",
                    content=content, project_revision=4,
                )
            client._call = call
            self.assertEqual(
                client.assess_ghidra_function("project", 4, seed, function_entry=0x2013a9)["entry"],
                entry,
            )
            self.assertEqual(requests[0].seed_json, seed)
            artifact["verification"] = "passed"
            with self.assertRaises(RuntimeError):
                client.assess_ghidra_function("project", 4, seed, function_entry=0x2013a9)

    def test_v3_fact_updates_validate_before_network_use_and_check_identity(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.update_analyst_fact_v3(
                    "project", 1, kind="name", value="entry", scope="binary"
                )
            client._call = lambda *_: proto_v3.MutationReply(
                project_id="other", revision=2, binary_sha256="a" * 64,
            )
            with self.assertRaises(RuntimeError):
                client.update_analyst_fact_v3(
                    "project", 1, kind="comment", value="reviewed", scope="binary"
                )

    def test_transform_rejects_untrusted_or_unallowlisted_pipeline(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.transform(
                    "project", 1, "symbol", "dce", assume_u64x2=True,
                    trusted_fixture=False,
                )
            with self.assertRaises(ValueError):
                client.transform(
                    "project", 1, "symbol", "load=/tmp/plugin.so", assume_u64x2=True,
                    trusted_fixture=True,
                )

    def test_rebuild_requires_trusted_fixture_before_network_use(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.rebuild("project", 1, trusted_fixture=False)

    def test_annotation_rejects_bad_kind_scope_and_address_before_network_use(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            with self.assertRaises(ValueError):
                client.add_annotation("project", 1, kind="instruction", value="x", scope="binary")
            with self.assertRaises(ValueError):
                client.add_annotation("project", 1, kind="name", value="entry", scope="binary")
            with self.assertRaises(ValueError):
                client.add_annotation("project", 1, kind="comment", value="x", scope=" ")
            with self.assertRaises(ValueError):
                client.add_annotation(
                    "project", 1, kind="assumption", value="x", scope="binary", address="0xZZ"
                )
            with self.assertRaises(ValueError):
                client.add_annotation(
                    "project", 1, kind="name", value="false\nverified", scope="binary", address="0x401000"
                )

    def test_annotation_client_rejects_mismatched_remote_identity(self):
        with HydirClient("http://127.0.0.1:50051", self.token) as client:
            client._call = lambda *_: SimpleNamespace(json=json.dumps({
                "project_id": "other", "revision": 2,
                "binary_sha256": "a" * 64, "annotations": [],
            }))
            with self.assertRaises(RuntimeError):
                client.list_annotations("project", 2)
            client._call = lambda *_: proto.ProjectReply(
                project_id="project", revision=9, binary_sha256="a" * 64,
            )
            with self.assertRaises(RuntimeError):
                client.add_annotation("project", 1, kind="comment", value="note", scope="binary")


if __name__ == "__main__":
    unittest.main()
