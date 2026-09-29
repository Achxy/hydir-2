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
from . import hydir_v2_pb2 as proto_v2
from . import hydir_v3_pb2 as proto_v3
from .hydir_pb2_grpc import HydirStub
from .hydir_v2_pb2_grpc import HydirV2Stub
from .hydir_v3_pb2_grpc import HydirV3Stub
from .ghidra import LocalGhidra

MAX_BINARY_BYTES = 64 * 1024 * 1024
MAX_GHIDRA_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_PCODE_SEED_BYTES = 1024 * 1024
MAX_ANALYSIS_MODEL_BYTES = 16 * 1024 * 1024
MAX_INPUT_SPEC_BYTES = 2 * 1024 * 1024
FRIDA_TRACE_MEDIA_TYPE = "application/vnd.hydir.dynamic-trace+json;version=2"


class HydirClient:
    """Authenticated local-or-TLS client with additive v1/v2/v3 negotiation.

    Mutations accept explicit project revisions. Pass the same idempotency key
    when retrying create-project or lift-job requests after an uncertain reply.
    """

    def __init__(
        self,
        endpoint: str,
        token_file: str | os.PathLike[str],
        timeout: float = 30.0,
        root_certificates: bytes | None = None,
    ):
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme not in {"http", "https"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.port is None
            or not parsed.hostname
        ):
            raise ValueError(
                "Endpoint must be an explicit http/https host and port without "
                "credentials, path, query, or fragment"
            )
        address = None
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            pass
        if parsed.scheme == "http" and (address is None or not address.is_loopback):
            raise ValueError("Plaintext connections require a numeric loopback address")
        token_path = Path(token_file)
        if os.name == "posix" and token_path.stat().st_mode & 0o077:
            raise ValueError("Credential file must be private (chmod 600)")
        token = token_path.read_text(encoding="ascii").strip()
        is_static = len(token) == 64 and all(
            character in "0123456789abcdefABCDEF" for character in token
        )
        segments = token.split(".")
        is_compact_jwt = (
            len(token) <= 16 * 1024
            and len(segments) == 3
            and all(
                segment
                and all(
                    character.isascii()
                    and (character.isalnum() or character in "-_")
                    for character in segment
                )
                for segment in segments
            )
        )
        if not (is_static or is_compact_jwt):
            raise ValueError("Credential file must contain a bounded static token or compact JWT")
        self._metadata = (("authorization", "Bearer " + token),)
        self._timeout = timeout
        host = parsed.hostname
        target = f"[{host}]:{parsed.port}" if ":" in host else f"{host}:{parsed.port}"
        options = (
            ("grpc.max_receive_message_length", MAX_BINARY_BYTES + 1024),
            ("grpc.max_send_message_length", MAX_BINARY_BYTES + 1024),
        )
        if parsed.scheme == "https":
            credentials = grpc.ssl_channel_credentials(root_certificates=root_certificates)
            self._channel = grpc.secure_channel(target, credentials, options=options)
        else:
            self._channel = grpc.insecure_channel(target, options=options)
        self._stub = HydirStub(self._channel)
        self._stub_v2 = HydirV2Stub(self._channel)
        self._stub_v3 = HydirV3Stub(self._channel)

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> "HydirClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _call(self, method, request, *, timeout: float | None = None):
        return method(
            request, metadata=self._metadata,
            timeout=self._timeout if timeout is None else timeout,
        )

    def discover(self):
        reply = self._call(self._stub.Discover, proto.DiscoverRequest())
        if reply.api_version != 1:
            raise RuntimeError(f"Unsupported HydIR API version {reply.api_version}")
        return reply

    def discover_v2(self):
        reply = self._call(self._stub_v2.Discover, proto_v2.DiscoverRequest())
        if reply.api_version != 2:
            raise RuntimeError(f"Unsupported HydIR API version {reply.api_version}")
        return reply

    def discover_v3(self):
        reply = self._call(self._stub_v3.Discover, proto_v3.DiscoverRequest())
        if reply.api_version != 3:
            raise RuntimeError(f"Unsupported HydIR API version {reply.api_version}")
        return reply

    def negotiate_api(self) -> tuple[int, object]:
        """Prefer v3 while retaining transparent v2 and v1 compatibility paths."""
        try:
            return 3, self.discover_v3()
        except grpc.RpcError as error:
            if error.code() != grpc.StatusCode.UNIMPLEMENTED:
                raise
        try:
            return 2, self.discover_v2()
        except grpc.RpcError as error:
            if error.code() != grpc.StatusCode.UNIMPLEMENTED:
                raise
        return 1, self.discover()

    def get_program_artifact(
        self, project_id: str, revision: int, stage: str,
        function_selector: str | None = None,
    ) -> dict | bytes:
        """Fetch a digest-checked native artifact without executing the ELF."""
        media_types = {
            "program_spec": ("application/vnd.hydir.program-spec+json;version=5", 5),
            "function_index": ("application/vnd.hydir.function-index+json;version=1", 1),
            "coverage": ("application/vnd.hydir.coverage+json;version=1", 1),
            "machine": ("application/vnd.hydir.machine-ir+json;version=1", 1),
            "state": ("application/vnd.hydir.state-ir+json;version=1", 1),
            "function": ("application/vnd.hydir.function-ir+json;version=1", 1),
            "cir": ("application/vnd.hydir.cir+json;version=1", 1),
            "llvm": ("text/x-llvm-ir", None),
            "unit": ("application/vnd.hydir.decompilation-unit+json;version=2", 2),
            "analysis_model": ("application/vnd.hydir.analysis-model+json;version=1", 1),
            "high_level_cir": ("application/vnd.hydir.high-level-cir+json;version=1", 1),
            "high_level_cfg_cir": ("application/vnd.hydir.high-level-cfg-cir+json;version=3", 3),
            "typed_c": ("text/x-c;view=typed", None),
        }
        if stage not in media_types:
            raise ValueError("Unsupported native artifact stage")
        function_scoped = stage in {"machine", "state", "function", "cir", "llvm", "unit", "high_level_cir", "high_level_cfg_cir", "typed_c"}
        if function_scoped and not function_selector:
            raise ValueError("Function-scoped native artifact requires a selector")
        if not function_scoped and function_selector:
            raise ValueError("Program-scoped native artifact cannot include a selector")
        if function_selector and (
            len(function_selector.encode("utf-8")) > 256
            or any(ord(character) < 32 for character in function_selector)
        ):
            raise ValueError("Function selector exceeds the supported bounds")
        reply = self._call(
            self._stub_v3.GetProgramArtifact,
            proto_v3.ProgramArtifactRequest(
                project_id=project_id,
                expected_revision=revision,
                stage=stage,
                function_selector=function_selector or "",
            ),
        )
        content = self._checked_artifact(reply, revision=revision)
        expected_media_type, schema_version = media_types[stage]
        if reply.media_type != expected_media_type:
            raise RuntimeError("Native artifact media type verification failed")
        if schema_version is None:
            return content
        value = json.loads(content)
        if not isinstance(value, dict) or value.get("schema_version") != schema_version:
            raise RuntimeError("Native artifact schema version verification failed")
        return value

    def get_analysis_model(self, project_id: str, revision: int) -> dict:
        """Read the binary-bound AnalysisModel at a project revision."""
        reply = self._call(
            self._stub_v3.GetAnalysisModel,
            proto_v3.AnalysisModelRequest(
                project_id=project_id, expected_revision=revision,
            ),
        )
        return self._checked_json_artifact(
            reply,
            revision=revision,
            media_type="application/vnd.hydir.analysis-model+json;version=1",
            schema_version=1,
        )

    def save_analysis_model(
        self, project_id: str, revision: int, model: dict | bytes,
        *, idempotency_key: str | None = None,
    ):
        """Save a complete model edit with an optimistic project revision check."""
        if not isinstance(revision, int) or revision < 0:
            raise ValueError("Project revision must be nonnegative")
        if isinstance(model, dict):
            raw = json.dumps(model, separators=(",", ":"), sort_keys=True).encode("utf-8")
        elif isinstance(model, bytes):
            raw = model
        else:
            raise TypeError("Model must be a JSON object or UTF-8 JSON bytes")
        if not 0 < len(raw) <= MAX_ANALYSIS_MODEL_BYTES:
            raise ValueError("AnalysisModel exceeds the 16 MiB limit")
        value = json.loads(raw)
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("Expected AnalysisModel v1 JSON object")
        key = idempotency_key or str(uuid4())
        if not 0 < len(key.encode("utf-8")) <= 128 or any(ord(ch) < 32 for ch in key):
            raise ValueError("Idempotency key exceeds the supported bounds")
        reply = self._call(
            self._stub_v3.SaveAnalysisModel,
            proto_v3.SaveAnalysisModelRequest(
                project_id=project_id,
                expected_revision=revision,
                idempotency_key=key,
                model_json=raw,
            ),
        )
        if (
            reply.project_id != project_id
            or reply.revision != revision + 1
            or len(reply.binary_sha256) != 64
        ):
            raise RuntimeError("Model revision or binary identity differs from request")
        return reply

    def analyze_ghidra_snapshot(
        self,
        project_id: str,
        revision: int,
        snapshot: bytes | str | os.PathLike[str],
        stage: str,
        *,
        start_address: int | str | None = None,
        instruction_index: int | None = None,
        operation_index: int | None = None,
        input_index: int | None = None,
        selected_function_entry: int | str | None = None,
        automatic: bool = False,
    ) -> dict:
        """Analyze a Ghidra export bound to this project's uploaded binary.

        The service checks the binary digest and revision, runs the bounded
        analysis in an isolated worker, and returns a versioned JSON artifact.
        """
        media_types = {
            "snapshot": ("application/vnd.hydir.ghidra-snapshot+json;version=2", 2),
            "pcode": ("application/vnd.hydir.pcode-ir+json;version=1", 1),
            "simplify": ("application/vnd.hydir.pcode-simplification+json;version=1", 1),
            "semantics": ("application/vnd.hydir.pcode-semantic-ir+json;version=1", 1),
            "state": ("application/vnd.hydir.pcode-state-ir+json;version=1", 1),
            "cfg": ("application/vnd.hydir.pcode-cfg-ir+json;version=1", 1),
            "coverage": ("application/vnd.hydir.pcode-coverage+json;version=1", 1),
            "capability": ("application/vnd.hydir.pcode-capability+json;version=1", 1),
            "llvm-cfg": ("application/vnd.hydir.pcode-cfg-llvm+json;version=2", 2),
            "llvm-cfg-image": ("application/vnd.hydir.pcode-cfg-llvm+json;version=3", 3),
            "llvm-cfg-simplified": ("application/vnd.hydir.pcode-simplified-cfg-llvm+json;version=1", 1),
            "slice": ("application/vnd.hydir.pcode-slice+json;version=1", 1),
        }
        if stage not in media_types:
            raise ValueError("Unsupported Ghidra snapshot artifact stage")
        if start_address is not None and stage not in {"llvm-cfg", "llvm-cfg-image", "llvm-cfg-simplified"}:
            raise ValueError("Start address is supported only for CFG LLVM stages")
        if stage == "slice":
            if instruction_index is None or operation_index is None:
                raise ValueError("Slice requires instruction and operation indices")
            for label, index in (("instruction", instruction_index),
                                 ("operation", operation_index), ("input", input_index)):
                if index is not None and (
                    not isinstance(index, int) or not 0 <= index <= 0xFFFFFFFF
                ):
                    raise ValueError(f"{label} index must be a 32-bit unsigned integer")
        elif any(index is not None for index in
                 (instruction_index, operation_index, input_index)):
            raise ValueError("Operation indices are supported only for slice")
        if isinstance(start_address, int):
            if not 0 <= start_address <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError("Start address must fit in 64 bits")
            start_address = f"0x{start_address:x}"
        if start_address is not None and (
            not start_address.startswith("0x")
            or not 1 <= len(start_address[2:]) <= 16
            or any(character not in "0123456789abcdef" for character in start_address[2:])
        ):
            raise ValueError("Start address must be 0x plus 1..=16 lowercase hex digits")
        if selected_function_entry is not None and not automatic:
            raise ValueError("Selected function entry requires automatic Ghidra analysis")
        if isinstance(selected_function_entry, int):
            if not 0 <= selected_function_entry <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError("Selected function entry must fit in 64 bits")
            selected_function_entry = f"0x{selected_function_entry:x}"
        if selected_function_entry is not None and (
            not selected_function_entry.startswith("0x")
            or not 1 <= len(selected_function_entry[2:]) <= 16
            or any(character not in "0123456789abcdef" for character in selected_function_entry[2:])
        ):
            raise ValueError("Selected function entry must be 0x plus 1..=16 lowercase hex digits")
        if isinstance(snapshot, bytes):
            content = snapshot
        else:
            path = Path(snapshot)
            if path.stat().st_size > MAX_GHIDRA_SNAPSHOT_BYTES:
                raise ValueError("Ghidra snapshot exceeds 16 MiB")
            content = path.read_bytes()
        if len(content) > MAX_GHIDRA_SNAPSHOT_BYTES or (not automatic and not content):
            raise ValueError("Ghidra snapshot must be 1..=16 MiB")
        if automatic and content:
            raise ValueError("Automatic Ghidra analysis does not accept a caller snapshot")
        request = proto_v3.GhidraSnapshotArtifactRequest(
            project_id=project_id,
            expected_revision=revision,
            snapshot_json=content,
            stage=stage,
            start_address=start_address or "",
            selected_function_entry=selected_function_entry or "",
            automatic=automatic,
        )
        if stage == "slice":
            request.instruction_index = instruction_index
            request.operation_index = operation_index
            if input_index is not None:
                request.input_index = input_index
        reply = self._call(self._stub_v3.AnalyzeGhidraSnapshot, request)
        expected_media_type, schema_version = media_types[stage]
        artifact = self._checked_json_artifact(
            reply,
            revision=revision,
            media_type=expected_media_type,
            schema_version=schema_version,
        )
        if stage == "slice" and artifact.get("path_proven") is not False:
            raise RuntimeError("P-code slice has an unsupported path-proof claim")
        if stage == "llvm-cfg-image":
            image = artifact.get("read_only_image")
            if (
                not isinstance(image, dict)
                or not isinstance(image.get("space"), str)
                or type(image.get("base")) is not int
                or type(image.get("byte_len")) is not int
                or type(image.get("known_byte_count")) is not int
                or not 0 <= image["base"] <= 0xFFFFFFFFFFFFFFFF
                or not 1 <= image["known_byte_count"] <= image["byte_len"] <= 65_536
                or not isinstance(image.get("contents_sha256"), str)
                or len(image["contents_sha256"]) != 64
                or any(character not in "0123456789abcdef"
                       for character in image["contents_sha256"])
            ):
                raise RuntimeError("Image-backed CFG LLVM lacks a valid ELF image binding")
        return artifact

    def analyze_ghidra_binary(
        self,
        project_id: str,
        revision: int,
        stage: str,
        *,
        selected_function_entry: int | str | None = None,
        start_address: int | str | None = None,
        instruction_index: int | None = None,
        operation_index: int | None = None,
        input_index: int | None = None,
    ) -> dict:
        """Analyze the project's uploaded ELF with managed headless Ghidra."""
        return self.analyze_ghidra_snapshot(
            project_id, revision, b"", stage,
            selected_function_entry=selected_function_entry,
            start_address=start_address,
            instruction_index=instruction_index,
            operation_index=operation_index,
            input_index=input_index,
            automatic=True,
        )

    def trace_ghidra_calls(
        self,
        project_id: str,
        revision: int,
        seed: bytes | str | os.PathLike[str],
        *,
        function_entry: int | str,
        max_functions: int | None = None,
        max_operations: int | None = None,
        max_visits: int | None = None,
        max_depth: int | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Trace a seeded direct-call path through the uploaded ELF."""
        return self._ghidra_call_artifact(
            project_id, revision, seed, function_entry=function_entry, llvm=False,
            max_functions=max_functions, max_operations=max_operations,
            max_visits=max_visits, max_depth=max_depth, timeout=timeout,
        )

    def build_ghidra_call_cfg_llvm(
        self,
        project_id: str,
        revision: int,
        seed: bytes | str | os.PathLike[str],
        *,
        function_entry: int | str,
        max_functions: int | None = None,
        max_operations: int | None = None,
        max_visits: int | None = None,
        max_depth: int | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Emit bounded interprocedural CFG LLVM from an uploaded ELF and seed."""
        return self._ghidra_call_artifact(
            project_id, revision, seed, function_entry=function_entry, llvm=True,
            max_functions=max_functions, max_operations=max_operations,
            max_visits=max_visits, max_depth=max_depth, timeout=timeout,
        )

    def assess_ghidra_function(
        self,
        project_id: str,
        revision: int,
        seed: bytes | str | os.PathLike[str],
        *,
        function_entry: int | str,
        max_functions: int | None = None,
        max_operations: int | None = None,
        max_visits: int | None = None,
        max_depth: int | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Assess one seed against loaded Ghidra functions and LLVM emission."""
        return self._ghidra_call_artifact(
            project_id, revision, seed, function_entry=function_entry,
            llvm=False, assessment=True, max_functions=max_functions,
            max_operations=max_operations, max_visits=max_visits,
            max_depth=max_depth, timeout=timeout,
        )

    def _ghidra_call_artifact(
        self,
        project_id: str,
        revision: int,
        seed: bytes | str | os.PathLike[str],
        *,
        function_entry: int | str,
        llvm: bool,
        assessment: bool = False,
        max_functions: int | None = None,
        max_operations: int | None = None,
        max_visits: int | None = None,
        max_depth: int | None = None,
        timeout: float | None = None,
    ) -> dict:
        """Validate and request a seeded Ghidra call artifact."""
        if isinstance(function_entry, bool):
            raise ValueError("Function entry must be a 64-bit address")
        if isinstance(function_entry, int):
            entry = function_entry
        elif isinstance(function_entry, str) and function_entry.startswith("0x"):
            digits = function_entry[2:]
            if not 1 <= len(digits) <= 16 or any(
                character not in "0123456789abcdef" for character in digits
            ):
                raise ValueError("Function entry must be lowercase hexadecimal")
            entry = int(digits, 16)
        else:
            raise ValueError("Function entry must be a 64-bit address")
        if not 0 <= entry <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("Function entry must fit in 64 bits")
        function_hex = f"0x{entry:x}"
        if isinstance(seed, bytes):
            content = seed
        else:
            path = Path(seed)
            if path.stat().st_size > MAX_PCODE_SEED_BYTES:
                raise ValueError("P-code call seed exceeds 1 MiB")
            content = path.read_bytes()
        if not 1 <= len(content) <= MAX_PCODE_SEED_BYTES:
            raise ValueError("P-code call seed must be 1..=1 MiB")
        try:
            seed_json = json.loads(content)
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("P-code call seed is invalid JSON") from error
        if (
            not isinstance(seed_json, dict)
            or seed_json.get("schema_version") != 1
            or not isinstance(seed_json.get("entry"), dict)
            or seed_json["entry"].get("offset") != function_hex
            or not isinstance(seed_json.get("binary_sha256"), str)
            or len(seed_json["binary_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in seed_json["binary_sha256"])
        ):
            raise ValueError("P-code call seed version, entry, or digest is invalid")
        limits = (
            ("max_functions", max_functions, 1, 8),
            ("max_operations", max_operations, 0, 65_536),
            ("max_visits", max_visits, 0, 65_536),
            ("max_depth", max_depth, 0, 16),
        )
        for name, value, minimum, maximum in limits:
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"{name} must be {minimum}..={maximum}")
        if timeout is not None and timeout <= 0:
            raise ValueError("timeout must be positive")
        request = proto_v3.GhidraCallTraceRequest(
            project_id=project_id,
            expected_revision=revision,
            function_entry=function_hex,
            seed_json=content,
        )
        for name, value, _, _ in limits:
            if value is not None:
                setattr(request, name, value)
        reply = self._call(
            (self._stub_v3.BuildGhidraCallCfgLlvm if llvm
             else self._stub_v3.AssessGhidraFunction if assessment
             else self._stub_v3.TraceGhidraCalls),
            request,
            timeout=max(self._timeout, 180.0) if timeout is None else timeout,
        )
        artifact = self._checked_json_artifact(
            reply, revision=revision,
            media_type=(
                "application/vnd.hydir.pcode-interprocedural-cfg-llvm+json;version=1"
                if llvm else "application/vnd.hydir.pcode-function-assessment+json;version=1"
                if assessment else "application/vnd.hydir.pcode-call-trace+json;version=2"
            ),
            schema_version=1 if llvm or assessment else 2,
        )
        if artifact.get("binary_sha256") != seed_json["binary_sha256"]:
            raise RuntimeError("Ghidra call artifact belongs to another binary")
        if llvm:
            entries = artifact.get("function_entries")
            module = artifact.get("llvm")
            if (
                not isinstance(entries, list) or not entries
                or not isinstance(entries[0], dict)
                or entries[0] != seed_json["entry"]
                or not isinstance(module, dict)
                or module.get("binary_sha256") != seed_json["binary_sha256"]
                or module.get("schema_version") != 2
                or module.get("start") != seed_json["entry"]
                or not isinstance(module.get("llvm_ir"), str)
            ):
                raise RuntimeError("Ghidra call LLVM artifact differs from the requested binary or function")
        elif assessment:
            if (
                artifact.get("entry") != seed_json["entry"]
                or artifact.get("seed_sha256") != hashlib.sha256(content).hexdigest()
                or not isinstance(artifact.get("static_capability"), dict)
                or not isinstance(artifact.get("trace"), dict)
                or artifact["trace"].get("root_entry") != seed_json["entry"]
                or artifact.get("verification") != "not_run"
            ):
                raise RuntimeError("Ghidra assessment differs from the requested seed or function")
        elif artifact.get("root_entry", {}).get("offset") != function_hex:
            raise RuntimeError("Ghidra call trace differs from the requested function")
        return artifact

    def start_program_analysis(
        self, project_id: str, revision: int, *, idempotency_key: str | None = None,
    ):
        return self._call(
            self._stub_v3.StartProgramAnalysis,
            proto_v3.StartProgramAnalysisRequest(
                project_id=project_id,
                expected_revision=revision,
                idempotency_key=idempotency_key or str(uuid4()),
            ),
        )

    def start_frida_observation(
        self, project_id: str, revision: int, input_spec: dict | bytes,
        selected_elf_vaddr: int, *, snapshot_json: bytes | None = None,
        idempotency_key: str | None = None,
    ):
        """Queue a bounded Linux x86-64 observation of the uploaded ELF."""
        if not 0 < selected_elf_vaddr < 1 << 64:
            raise ValueError("Selected ELF address must be a nonzero 64-bit integer")
        content = (
            json.dumps(input_spec, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if isinstance(input_spec, dict) else input_spec
        )
        if not isinstance(content, bytes) or not 0 < len(content) <= MAX_INPUT_SPEC_BYTES:
            raise ValueError("InputSpec must be bounded JSON bytes or a dictionary")
        try:
            spec = json.loads(content)
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("InputSpec is not valid JSON") from error
        digest = spec.get("binary_sha256") if isinstance(spec, dict) else None
        if (
            spec.get("schema_version") != 1
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("InputSpec version or binary digest is invalid")
        snapshot = snapshot_json or b""
        if not isinstance(snapshot, bytes) or len(snapshot) > MAX_GHIDRA_SNAPSHOT_BYTES:
            raise ValueError("Ghidra snapshot must be at most 16 MiB JSON bytes")
        key = idempotency_key or str(uuid4())
        if not 1 <= len(key) <= 128 or any(ord(character) < 32 for character in key):
            raise ValueError("Idempotency key must be 1..=128 non-control characters")
        reply = self._call(
            self._stub_v3.StartFridaObservation,
            proto_v3.StartFridaObservationRequest(
                project_id=project_id, expected_revision=revision,
                idempotency_key=key, input_spec_json=content,
                selected_elf_vaddr=selected_elf_vaddr, snapshot_json=snapshot,
            ),
        )
        if (
            reply.project_id != project_id
            or reply.project_revision != revision
            or reply.kind != "frida-observation"
            or not reply.job_id
        ):
            raise RuntimeError("Frida job identity differs from request")
        return reply

    def get_frida_observation(
        self, project_id: str, job_id: str, *, revision: int,
        artifact_sha256: str, binary_sha256: str, selected_elf_vaddr: int,
    ) -> dict:
        """Fetch a completed DynamicTrace v2 with its job and binary identity."""
        if not job_id or revision < 0 or not 0 < selected_elf_vaddr < 1 << 64:
            raise ValueError("Frida job identity is invalid")
        for digest in (artifact_sha256, binary_sha256):
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ValueError("Frida artifact and binary digests must be lowercase SHA-256")
        reply = self._call(
            self._stub_v3.GetFridaObservation,
            proto_v3.FridaObservationArtifactRequest(project_id=project_id, job_id=job_id),
        )
        content = self._checked_artifact(
            reply, expected_sha256=artifact_sha256, revision=revision,
        )
        if reply.media_type != FRIDA_TRACE_MEDIA_TYPE:
            raise RuntimeError("Frida artifact media type differs from DynamicTrace v2")
        trace = json.loads(content)
        if (
            not isinstance(trace, dict)
            or trace.get("schema_version") != 2
            or trace.get("binary_sha256") != binary_sha256
            or trace.get("selected_elf_vaddr") != selected_elf_vaddr
            or "exit_code" in trace
        ):
            raise RuntimeError("Frida trace identity or exit-code claim is invalid")
        return trace

    def get_analysis_job(self, project_id: str, job_id: str):
        return self._call(
            self._stub_v3.GetAnalysisJob,
            proto_v3.JobRequest(project_id=project_id, job_id=job_id),
        )

    def cancel_analysis_job(self, project_id: str, job_id: str):
        return self._call(
            self._stub_v3.CancelAnalysisJob,
            proto_v3.JobRequest(project_id=project_id, job_id=job_id),
        )

    def analysis_events(
        self, project_id: str, job_id: str, after_sequence: int = 0,
    ) -> Iterator:
        if after_sequence < 0:
            raise ValueError("Event sequence cannot be negative")
        return self._call(
            self._stub_v3.StreamAnalysisEvents,
            proto_v3.JobEventRequest(
                project_id=project_id,
                job_id=job_id,
                after_sequence=after_sequence,
            ),
        )

    def update_analyst_fact_v3(
        self, project_id: str, revision: int, *, kind: str, value: str,
        scope: str, address: str | None = None, idempotency_key: str | None = None,
    ):
        """Append a revision-checked analyst fact through the native v3 API."""
        if kind not in {"name", "comment", "assumption"}:
            raise ValueError("Analyst fact kind must be name, comment, or assumption")
        if kind == "name" and not address:
            raise ValueError("Name facts require an address")
        if not value.strip() or not scope.strip():
            raise ValueError("Analyst fact value and scope are required")
        max_value = {"name": 128, "comment": 2048, "assumption": 1024}[kind]
        if (
            len(value.encode("utf-8")) > max_value
            or "\x00" in value
            or (kind == "name" and any(character in "\r\n\t" for character in value))
            or len(scope.encode("utf-8")) > 256
            or any(ord(character) < 32 for character in scope)
        ):
            raise ValueError("Analyst fact value or scope exceeds the supported bounds")
        if address is not None and (
            not address.startswith("0x")
            or not 1 <= len(address[2:]) <= 16
            or any(character not in "0123456789abcdefABCDEF" for character in address[2:])
        ):
            raise ValueError("Address must be 0x plus 1..=16 hex digits")
        reply = self._call(
            self._stub_v3.UpdateAnalystFact,
            proto_v3.AnalystFactRequest(
                project_id=project_id,
                expected_revision=revision,
                idempotency_key=idempotency_key or str(uuid4()),
                kind=kind,
                address=address or "",
                value=value,
                scope=scope,
            ),
        )
        if (
            reply.project_id != project_id
            or reply.revision != revision + 1
            or len(reply.binary_sha256) != 64
        ):
            raise RuntimeError("Analyst fact revision or binary identity differs from request")
        return reply

    @staticmethod
    def _checked_json_artifact(
        reply, *, revision: int, media_type: str, schema_version: int,
    ) -> dict:
        content = HydirClient._checked_artifact(reply, revision=revision)
        if reply.media_type != media_type:
            raise RuntimeError("Artifact media type verification failed")
        value = json.loads(content)
        if not isinstance(value, dict) or value.get("schema_version") != schema_version:
            raise RuntimeError("Artifact schema version verification failed")
        return value

    def get_region(
        self, project_id: str, revision: int, symbol: str, *, assume_u64x2: bool,
    ) -> dict:
        if not assume_u64x2:
            raise ValueError("Explicit u64(u64,u64) prototype assertion is required")
        reply = self._call(
            self._stub_v2.GetRegion,
            proto_v2.RegionRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
            ),
        )
        return self._checked_json_artifact(
            reply,
            revision=revision,
            media_type="application/vnd.hydir.region-spec+json;version=3",
            schema_version=3,
        )

    def lift_region(
        self, project_id: str, revision: int, symbol: str, *, assume_u64x2: bool,
    ) -> dict:
        """Return digest-checked PhysicalRegionIR without claiming C/patch readiness."""
        if not assume_u64x2:
            raise ValueError("Explicit u64(u64,u64) prototype assertion is required")
        reply = self._call(
            self._stub_v2.LiftRegion,
            proto_v2.RegionRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
            ),
        )
        return self._checked_json_artifact(
            reply,
            revision=revision,
            media_type="application/vnd.hydir.physical-region-ir+json;version=1",
            schema_version=1,
        )

    def decompile_region(
        self, project_id: str, revision: int, symbol: str, *, assume_u64x2: bool,
    ) -> dict:
        if not assume_u64x2:
            raise ValueError("Explicit u64(u64,u64) prototype assertion is required")
        reply = self._call(
            self._stub_v2.DecompileRegion,
            proto_v2.RegionRequest(
                project_id=project_id,
                expected_revision=revision,
                function_symbol=symbol,
                assume_u64x2=True,
            ),
        )
        unit = self._checked_json_artifact(
            reply,
            revision=revision,
            media_type="application/vnd.hydir.decompilation-unit+json;version=1",
            schema_version=1,
        )
        if unit.get("binary_sha256") != unit.get("region", {}).get("binary_sha256"):
            raise RuntimeError("DecompilationUnit and RegionSpec binary identities differ")
        return unit

    def compile_patch_bundle(
        self, project_id: str, revision: int, patch_json: bytes, *,
        trusted_fixture: bool, assume_u64x2: bool, assume_entry_only: bool,
        idempotency_key: str | None = None,
    ) -> dict:
        request = self._v2_patch_request(
            project_id,
            revision,
            patch_json,
            trusted_fixture=trusted_fixture,
            assume_u64x2=assume_u64x2,
            assume_entry_only=assume_entry_only,
            idempotency_key=idempotency_key,
        )
        reply = self._call(self._stub_v2.CompilePatch, request)
        return self._checked_json_artifact(
            reply,
            revision=revision,
            media_type="application/vnd.hydir.patch-bundle+json;version=2",
            schema_version=2,
        )

    def apply_patch_v2(
        self, project_id: str, revision: int, patch_json: bytes, *,
        trusted_fixture: bool, assume_u64x2: bool, assume_entry_only: bool,
        idempotency_key: str | None = None,
    ) -> tuple[int, str, dict]:
        request = self._v2_patch_request(
            project_id,
            revision,
            patch_json,
            trusted_fixture=trusted_fixture,
            assume_u64x2=assume_u64x2,
            assume_entry_only=assume_entry_only,
            idempotency_key=idempotency_key,
        )
        reply = self._call(self._stub_v2.ApplyPatch, request)
        if reply.project_id != project_id or reply.revision != revision + 1:
            raise RuntimeError("Patch returned an unexpected project revision")
        artifact = self._call(
            self._stub.GetArtifact,
            proto.ArtifactRequest(project_id=project_id, sha256=reply.patch_bundle_sha256),
        )
        bundle = self._checked_json_artifact(
            artifact,
            revision=revision,
            media_type="application/vnd.hydir.patch-bundle+json;version=2",
            schema_version=2,
        )
        if bundle.get("patched_sha256") != reply.binary_sha256:
            raise RuntimeError("PatchBundle and patched revision binary identities differ")
        return reply.revision, reply.binary_sha256, bundle

    def verify_patch_bundle(
        self, project_id: str, revision: int, patch_bundle_json: bytes,
    ) -> dict:
        if not patch_bundle_json or len(patch_bundle_json) > 2 * 1024 * 1024:
            raise ValueError("PatchBundle must be 1..=2 MiB")
        reply = self._call(
            self._stub_v2.VerifyPatch,
            proto_v2.VerifyPatchRequest(
                project_id=project_id,
                expected_revision=revision,
                patch_bundle_json=patch_bundle_json,
            ),
        )
        report = json.loads(reply.report_json)
        if not reply.structurally_valid or report.get("structurally_valid") is not True:
            raise RuntimeError("PatchBundle structural verification failed")
        if reply.behavior_verified != bool(report.get("behavior_verified")):
            raise RuntimeError("PatchBundle behavior-verification status differs from report")
        return report

    @staticmethod
    def _v2_patch_request(
        project_id: str, revision: int, patch_json: bytes, *,
        trusted_fixture: bool, assume_u64x2: bool, assume_entry_only: bool,
        idempotency_key: str | None,
    ):
        if not (trusted_fixture and assume_u64x2 and assume_entry_only):
            raise ValueError("Patch requires trusted-fixture, u64x2, and entry-only assertions")
        if not patch_json or len(patch_json) > 4096:
            raise ValueError("Patch document must be 1..=4096 bytes")
        return proto_v2.PatchRequest(
            project_id=project_id,
            expected_revision=revision,
            idempotency_key=idempotency_key or str(uuid4()),
            patch_json=patch_json,
            trusted_fixture=True,
            assume_u64x2=True,
            assume_entry_only=True,
        )

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

    def analyze_spec(self, project_id: str, revision: int) -> dict:
        reply = self._call(
            self._stub.AnalyzeSpec,
            proto.ProjectRequest(project_id=project_id, expected_revision=revision),
        )
        return json.loads(reply.json)

    def list_annotations(self, project_id: str, revision: int) -> dict:
        reply = self._call(
            self._stub.ListAnnotations,
            proto.ProjectRequest(project_id=project_id, expected_revision=revision),
        )
        ledger = json.loads(reply.json)
        digest = ledger.get("binary_sha256")
        if (
            ledger.get("project_id") != project_id
            or ledger.get("revision") != revision
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(ledger.get("annotations"), list)
        ):
            raise RuntimeError("Annotation ledger identity or shape differs from request")
        for annotation in ledger["annotations"]:
            if not isinstance(annotation, dict) or annotation.get("binary_sha256") != digest:
                raise RuntimeError("Annotation fact is not bound to the requested binary")
        return ledger

    def add_annotation(
        self, project_id: str, revision: int, *, kind: str, value: str,
        scope: str, address: str | None = None, idempotency_key: str | None = None,
    ):
        """Append a scoped analyst fact as a new immutable project revision."""
        if kind not in {"name", "comment", "assumption"}:
            raise ValueError("Annotation kind must be name, comment, or assumption")
        if kind == "name" and not address:
            raise ValueError("Name annotations require an address")
        if not value.strip() or not scope.strip():
            raise ValueError("Annotation value and scope are required")
        max_value = {"name": 128, "comment": 2048, "assumption": 1024}[kind]
        if (
            len(value.encode("utf-8")) > max_value
            or "\x00" in value
            or (kind == "name" and any(character in "\r\n\t" for character in value))
            or len(scope.encode("utf-8")) > 256
            or any(ord(character) < 32 for character in scope)
        ):
            raise ValueError("Annotation value or scope exceeds the supported bounds")
        if address is not None and (
            not address.startswith("0x")
            or not 1 <= len(address[2:]) <= 16
            or any(character not in "0123456789abcdefABCDEF" for character in address[2:])
        ):
            raise ValueError("Address must be 0x plus 1..=16 hex digits")
        reply = self._call(
            self._stub.AddAnnotation,
            proto.AnnotationRequest(
                project_id=project_id,
                expected_revision=revision,
                idempotency_key=idempotency_key or str(uuid4()),
                kind=kind,
                address=address or "",
                value=value,
                scope=scope,
            ),
        )
        if (
            reply.project_id != project_id
            or reply.revision != revision + 1
            or len(reply.binary_sha256) != 64
        ):
            raise RuntimeError("Annotation revision or binary identity differs from request")
        return reply

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
