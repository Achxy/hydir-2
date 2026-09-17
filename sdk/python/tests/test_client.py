import os
import tempfile
import unittest
from pathlib import Path

from hydir_sdk import HydirClient
from hydir_sdk import hydir_pb2 as proto


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
        with self.assertRaises(ValueError):
            HydirClient("https://127.0.0.1:50051", self.token)

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


if __name__ == "__main__":
    unittest.main()
