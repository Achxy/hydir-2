"""Local Ghidra-backed Hydir frontend, using the same hydirctl worker as the GUI."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any


MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_BINARY_BYTES = 64 * 1024 * 1024


class LocalGhidra:
    """Run automatic local analysis and read binary-bound artifacts.

    ``hydirctl`` provisions the pinned worker, or uses ``HYDIR_GHIDRA_HOME``.
    The caller chooses a snapshot path and can inspect the artifact without a
    service or Ghidra UI. This class does not assert executable equivalence.
    """

    def __init__(self, hydirctl: str | os.PathLike[str] = "hydirctl", timeout: float = 3600):
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.hydirctl = str(hydirctl)
        self.timeout = timeout

    @staticmethod
    def _digest(binary: Path) -> str:
        if not binary.is_file():
            raise ValueError("binary must be a regular file")
        if not 0 < binary.stat().st_size <= MAX_BINARY_BYTES:
            raise ValueError("binary exceeds Hydir's size limit")
        digest = hashlib.sha256()
        with binary.open("rb") as source:
            for block in iter(lambda: source.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()

    @staticmethod
    def _snapshot(snapshot: Path, digest: str) -> dict[str, Any]:
        if not snapshot.is_file() or not 0 < snapshot.stat().st_size <= MAX_SNAPSHOT_BYTES:
            raise RuntimeError("Ghidra snapshot is absent or exceeds Hydir's size limit")
        data = json.loads(snapshot.read_bytes())
        if not isinstance(data, dict) or data.get("binary_sha256") != digest:
            raise RuntimeError("Ghidra snapshot belongs to another binary")
        return data

    def _run(self, *args: str) -> bytes:
        result = subprocess.run(
            [self.hydirctl, *args],
            capture_output=True,
            timeout=self.timeout,
            check=False,
        )
        if result.returncode:
            detail = (result.stderr or result.stdout)[:4096].decode("utf-8", errors="replace")
            raise RuntimeError(f"hydirctl failed ({result.returncode}): {detail}")
        return result.stdout

    def analyze(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        *,
        function: int | None = None,
    ) -> dict[str, Any]:
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve()
        digest = self._digest(binary_path)
        if snapshot_path == binary_path:
            raise ValueError("snapshot path must differ from binary")
        args = ["ghidra", "analyze", str(binary_path), "--output", str(snapshot_path)]
        if function is not None:
            if not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
                raise ValueError("function entry must be a 64-bit address")
            args.extend(["--function", hex(function)])
        self._run(*args)
        data = self._snapshot(snapshot_path, digest)
        if function is not None:
            selected = data.get("selected_function", {}).get("entry", {}).get("offset")
            if not isinstance(selected, str) or int(selected, 16) != function:
                raise RuntimeError("Ghidra returned a different function")
        return data

    def artifact(
        self,
        kind: str,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
    ) -> dict[str, Any]:
        if kind not in {"pcode", "semantics", "state", "cfg", "llvm-prefix", "llvm-standalone"}:
            raise ValueError("artifact kind must be pcode, semantics, state, cfg, llvm-prefix, or llvm-standalone")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        self._snapshot(snapshot_path, self._digest(binary_path))
        data = json.loads(self._run("ghidra-snapshot", kind, str(binary_path), str(snapshot_path)))
        if not isinstance(data, dict) or data.get("binary_sha256") != self._digest(binary_path):
            raise RuntimeError("Hydir artifact belongs to another binary")
        return data

    def llvm_operation(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        instruction: int,
        operation: int,
    ) -> str:
        if not 0 <= instruction <= 0xFFFFFFFFFFFFFFFF or operation < 0:
            raise ValueError("invalid instruction address or operation index")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        self._snapshot(snapshot_path, self._digest(binary_path))
        return self._run(
            "ghidra-snapshot", "llvm-op", str(binary_path), str(snapshot_path),
            "--instruction", hex(instruction), "--op", str(operation),
        ).decode("utf-8")

    def trace_prefix(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        seed: str | os.PathLike[str],
        *,
        max_operations: int = 4096,
    ) -> dict[str, Any]:
        """Run a bounded concrete prefix with a binary-bound seed JSON file."""
        if not 0 <= max_operations <= 262144:
            raise ValueError("P-code operation budget must be 0..262144")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        seed_path = Path(seed).resolve(strict=True)
        digest = self._digest(binary_path)
        self._snapshot(snapshot_path, digest)
        data = json.loads(self._run(
            "ghidra-snapshot", "trace-prefix", str(binary_path), str(snapshot_path),
            str(seed_path), "--max-ops", str(max_operations),
        ))
        if not isinstance(data, dict) or data.get("binary_sha256") != digest:
            raise RuntimeError("Hydir trace belongs to another binary")
        return data

    def trace_path(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        seed: str | os.PathLike[str],
        *,
        start: int | None = None,
        max_operations: int = 4096,
        max_visits: int = 1024,
    ) -> dict[str, Any]:
        """Follow one bounded concrete path through selected Ghidra instructions."""
        if start is not None and not 0 <= start <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("P-code start must be a 64-bit address")
        if not 0 <= max_operations <= 262144 or not 0 <= max_visits <= 262144:
            raise ValueError("P-code path budgets must be 0..262144")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        seed_path = Path(seed).resolve(strict=True)
        digest = self._digest(binary_path)
        self._snapshot(snapshot_path, digest)
        args = [
            "ghidra-snapshot", "trace-path", str(binary_path), str(snapshot_path), str(seed_path),
            "--max-ops", str(max_operations), "--max-visits", str(max_visits),
        ]
        if start is not None:
            args.extend(["--start", hex(start)])
        data = json.loads(self._run(*args))
        if not isinstance(data, dict) or data.get("binary_sha256") != digest:
            raise RuntimeError("Hydir trace belongs to another binary")
        return data
