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

            client._call = lambda *_: proto_v3.ArtifactReply(
                sha256=hashlib.sha256(artifact).hexdigest(),
                media_type="application/vnd.hydir.pcode-cfg-llvm+json;version=2",
                content=artifact,
                project_revision=5,
            )
            with self.assertRaises(RuntimeError):
                client.analyze_ghidra_snapshot("project", 4, snapshot.read_bytes(), "llvm-cfg")

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
