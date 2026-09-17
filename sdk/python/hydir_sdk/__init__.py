"""Client-side HydIR operations. Never uploads or executes a sample implicitly."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit
from uuid import uuid4

import grpc

from . import hydir_pb2 as proto
from .hydir_pb2_grpc import HydirStub

MAX_BINARY_BYTES = 64 * 1024 * 1024


class HydirClient:
    """Authenticated loopback client; remote API version 1 only.

    Mutations accept explicit project revisions. Pass the same idempotency key
    when retrying create-project or lift-job requests after an uncertain reply.
    """

    def __init__(self, endpoint: str, token_file: str | os.PathLike[str], timeout: float = 30.0):
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "http"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.port is None
        ):
            raise ValueError("Endpoint must be explicit http://loopback-address:port")
        try:
            address = ipaddress.ip_address(parsed.hostname or "")
        except ValueError as error:
            raise ValueError("Endpoint must use a numeric loopback address") from error
        if not address.is_loopback:
            raise ValueError("Plaintext non-loopback connections are refused")
        token_path = Path(token_file)
        if os.name == "posix" and token_path.stat().st_mode & 0o077:
            raise ValueError("Credential file must be private (chmod 600)")
        token = token_path.read_text(encoding="ascii").strip()
        if len(token) != 64 or any(character not in "0123456789abcdefABCDEF" for character in token):
            raise ValueError("Credential file must contain a 64-character hex token")
        self._metadata = (("authorization", "Bearer " + token),)
        self._timeout = timeout
        target = f"[{address}]:{parsed.port}" if address.version == 6 else f"{address}:{parsed.port}"
        self._channel = grpc.insecure_channel(
            target,
            options=(
                ("grpc.max_receive_message_length", MAX_BINARY_BYTES + 1024),
                ("grpc.max_send_message_length", MAX_BINARY_BYTES + 1024),
            ),
        )
        self._stub = HydirStub(self._channel)

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> "HydirClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _call(self, method, request):
        return method(request, metadata=self._metadata, timeout=self._timeout)

    def discover(self):
        reply = self._call(self._stub.Discover, proto.DiscoverRequest())
        if reply.api_version != 1:
            raise RuntimeError(f"Unsupported HydIR API version {reply.api_version}")
        return reply

    def get_source(self) -> tuple[str, bytes]:
        """Retrieve and hash-check the exact source archive advertised by this build."""
        discovery = self.discover()
        if len(discovery.source_revision) != 40 or len(discovery.source_sha256) != 64:
            raise RuntimeError("Service has no matching source archive offer")
        reply = self._call(self._stub.GetSource, proto.SourceRequest())
        if reply.revision != discovery.source_revision or reply.sha256 != discovery.source_sha256:
            raise RuntimeError("Source offer changed between discovery and retrieval")
        actual = hashlib.sha256(reply.content).hexdigest()
        if actual != reply.sha256:
            raise RuntimeError("Source archive SHA-256 verification failed")
        return reply.revision, reply.content

    def create_project(self, name: str, *, idempotency_key: str | None = None):
        return self._call(
            self._stub.CreateProject,
            proto.CreateProjectRequest(name=name, idempotency_key=idempotency_key or str(uuid4())),
        )

    def get_project(self, project_id: str):
        return self._call(self._stub.GetProject, proto.ProjectRequest(project_id=project_id))

    def upload_binary(self, project_id: str, expected_revision: int, path: str | os.PathLike[str]):
        """Explicitly transfer one local ELF into a new immutable project revision."""
        with Path(path).open("rb") as source:
            content = source.read(MAX_BINARY_BYTES + 1)
        if not content or len(content) > MAX_BINARY_BYTES:
            raise ValueError("Binary must be 1..=64 MiB")
        digest = hashlib.sha256(content).hexdigest()
        reply = self._call(
            self._stub.UploadBinary,
            proto.UploadBinaryRequest(
                project_id=project_id,
                expected_revision=expected_revision,
                content_sha256=digest,
                content=content,
            ),
        )
        if reply.binary_sha256 != digest or reply.revision != expected_revision + 1:
            raise RuntimeError("Upload returned an unexpected hash or revision")
        return reply

    def inspect(self, project_id: str, revision: int) -> dict:
        reply = self._call(
            self._stub.Inspect,
            proto.ProjectRequest(project_id=project_id, expected_revision=revision),
        )
        return json.loads(reply.json)

    def analyze(self, project_id: str, revision: int) -> dict:
        reply = self._call(
            self._stub.Analyze,
            proto.ProjectRequest(project_id=project_id, expected_revision=revision),
        )
        return json.loads(reply.json)

    def recover_cfg(self, project_id: str, revision: int, symbol: str) -> dict:
        reply = self._call(
            self._stub.RecoverCfg,
            proto.FunctionRequest(
                project_id=project_id, expected_revision=revision, function_symbol=symbol
            ),
        )
        return json.loads(reply.json)

    @staticmethod
    def _checked_artifact(reply, expected_sha256: str | None = None, revision: int | None = None) -> bytes:
        actual = hashlib.sha256(reply.content).hexdigest()
        if actual != reply.sha256 or (expected_sha256 is not None and actual != expected_sha256):
            raise RuntimeError("Artifact SHA-256 verification failed")
        if revision is not None and reply.project_revision != revision:
            raise RuntimeError("Artifact revision verification failed")
        return reply.content

    def lift(self, project_id: str, revision: int, symbol: str, *, assume_u64x2: bool) -> bytes:
        if not assume_u64x2:
            raise ValueError("Explicit u64(u64,u64) prototype assertion is required")
        reply = self._call(
            self._stub.Lift,
            proto.FunctionRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
            ),
        )
        return self._checked_artifact(reply, revision=revision)

    def decompile(self, project_id: str, revision: int, symbol: str, *, assume_u64x2: bool) -> bytes:
        """Return C emitted from the raw lifted scalar LLVM subset."""
        if not assume_u64x2:
            raise ValueError("Explicit u64(u64,u64) prototype assertion is required")
        reply = self._call(
            self._stub.Decompile,
            proto.FunctionRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
            ),
        )
        return self._checked_artifact(reply, revision=revision)

    def transform(
        self, project_id: str, revision: int, symbol: str, passes: str, *,
        assume_u64x2: bool, trusted_fixture: bool, idempotency_key: str | None = None,
    ) -> tuple[dict, dict[str, bytes]]:
        """Run pinned named LLVM passes; return the report and verified IR artifacts."""
        if not (assume_u64x2 and trusted_fixture):
            raise ValueError("Transform requires u64x2 and trusted-fixture assertions")
        allowed = {"instcombine", "sccp", "simplifycfg", "dce"}
        names = passes.split(",")
        if not 1 <= len(names) <= 4 or len(set(names)) != len(names) or any(
            name not in allowed for name in names
        ):
            raise ValueError("Pass list must contain 1..=4 unique allowlisted names")
        reply = self._call(
            self._stub.Transform,
            proto.TransformRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
                trusted_fixture=True,
                passes=passes,
                idempotency_key=idempotency_key or str(uuid4()),
            ),
        )
        if reply.project_id != project_id or reply.project_revision != revision + 1:
            raise RuntimeError("Transform returned an unexpected project or revision")
        digests = {
            "raw.ll": reply.raw_sha256,
            "before.ll": reply.before_sha256,
            "after.ll": reply.after_sha256,
            "report.json": reply.report_sha256,
        }
        artifacts: dict[str, bytes] = {}
        for name, digest in digests.items():
            artifact = self._call(
                self._stub.GetArtifact,
                proto.ArtifactRequest(project_id=project_id, sha256=digest),
            )
            artifacts[name] = self._checked_artifact(
                artifact, expected_sha256=digest, revision=reply.project_revision
            )
        if artifacts["report.json"] != reply.report_json.encode("utf-8"):
            raise RuntimeError("Transform report bytes differ from reply")
        if (artifacts["before.ll"] != artifacts["after.ll"]) != reply.ir_text_changed:
            raise RuntimeError("Transform change flag differs from IR artifacts")
        return json.loads(reply.report_json), artifacts

    def apply_patch(
        self, project_id: str, revision: int, patch_json: bytes, *,
        idempotency_key: str | None = None, trusted_fixture: bool,
        assume_u64x2: bool, assume_entry_only: bool,
    ) -> tuple[int, bytes]:
        """Create an immutable patched revision; never executes its ELF."""
        if not (trusted_fixture and assume_u64x2 and assume_entry_only):
            raise ValueError("Patch requires trusted-fixture, u64x2, and entry-only assertions")
        if not patch_json or len(patch_json) > 4096:
            raise ValueError("Patch document must be 1..=4096 bytes")
        reply = self._call(
            self._stub.ApplyPatch,
            proto.PatchRequest(
                project_id=project_id,
                expected_revision=revision,
                patch_json=patch_json,
                idempotency_key=idempotency_key or str(uuid4()),
                trusted_fixture=True,
                assume_u64x2=True,
                assume_entry_only=True,
            ),
        )
        if reply.project_id != project_id or reply.revision != revision + 1:
            raise RuntimeError("Patch returned an unexpected project revision")
        if reply.binary_sha256 != reply.artifact_sha256:
            raise RuntimeError("Patch binary and artifact digests differ")
        artifact = self._call(
            self._stub.GetArtifact,
            proto.ArtifactRequest(project_id=project_id, sha256=reply.artifact_sha256),
        )
        if artifact.media_type != "application/x-elf":
            raise RuntimeError("Patch did not return an ELF artifact")
        return reply.revision, self._checked_artifact(
            artifact, expected_sha256=reply.binary_sha256, revision=reply.revision
        )

    def rebuild(
        self, project_id: str, revision: int, *, trusted_fixture: bool,
        idempotency_key: str | None = None,
    ) -> tuple[int, dict[str, bytes]]:
        """Build a new complete-program ELF revision without executing it."""
        if not trusted_fixture:
            raise ValueError("Rebuild requires a trusted-fixture assertion")
        reply = self._call(
            self._stub.Rebuild,
            proto.RebuildRequest(
                project_id=project_id,
                expected_revision=revision,
                trusted_fixture=True,
                idempotency_key=idempotency_key or str(uuid4()),
            ),
        )
        if reply.project_id != project_id or reply.revision != revision + 1:
            raise RuntimeError("Rebuild returned an unexpected project or revision")
        expected = {
            "whole.ll": (reply.ir_sha256, "text/x-llvm-ir"),
            "rebuilt": (reply.binary_sha256, "application/x-elf"),
            "report.json": (reply.report_sha256, "application/json"),
        }
        artifacts: dict[str, bytes] = {}
        for name, (digest, media_type) in expected.items():
            artifact = self._call(
                self._stub.GetArtifact,
                proto.ArtifactRequest(project_id=project_id, sha256=digest),
            )
            if artifact.media_type != media_type:
                raise RuntimeError("Rebuild artifact media type mismatch")
            artifacts[name] = self._checked_artifact(
                artifact, expected_sha256=digest, revision=reply.revision
            )
        if artifacts["report.json"] != reply.report_json.encode("utf-8"):
            raise RuntimeError("Rebuild report bytes differ from reply")
        return reply.revision, artifacts

    def get_artifact(self, project_id: str, sha256: str) -> bytes:
        reply = self._call(
            self._stub.GetArtifact,
            proto.ArtifactRequest(project_id=project_id, sha256=sha256),
        )
        return self._checked_artifact(reply, expected_sha256=sha256)

    def start_lift_job(
        self, project_id: str, revision: int, symbol: str, *,
        assume_u64x2: bool, idempotency_key: str | None = None,
    ):
        if not assume_u64x2:
            raise ValueError("Explicit u64(u64,u64) prototype assertion is required")
        return self._call(
            self._stub.StartLiftJob,
            proto.StartLiftJobRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
                idempotency_key=idempotency_key or str(uuid4()),
            ),
        )

    def get_job(self, project_id: str, job_id: str):
        return self._call(self._stub.GetJob, proto.JobRequest(project_id=project_id, job_id=job_id))

    def cancel_job(self, project_id: str, job_id: str):
        return self._call(self._stub.CancelJob, proto.JobRequest(project_id=project_id, job_id=job_id))

    def job_events(self, project_id: str, job_id: str, after_sequence: int = 0) -> Iterator:
        return self._call(
            self._stub.StreamJobEvents,
            proto.JobEventRequest(
                project_id=project_id, job_id=job_id, after_sequence=after_sequence
            ),
        )

    @staticmethod
    def export_artifact(content: bytes, path: str | os.PathLike[str]) -> None:
        """Write a verified artifact to a new private file; never overwrite."""
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(content)
