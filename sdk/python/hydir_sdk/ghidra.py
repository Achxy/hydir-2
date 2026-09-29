"""Local Ghidra-backed Hydir frontend, using the same hydirctl worker as the GUI."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Any
import unicodedata


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

    def import_project(
        self,
        binary: str | os.PathLike[str],
        project: str | os.PathLike[str],
        program: str,
        snapshot: str | os.PathLike[str],
        *,
        function: int | None = None,
    ) -> dict[str, Any]:
        """Export one program from a closed, analyst-edited Ghidra project.

        The CLI stages an isolated project copy and verifies the original ELF.
        This route runs fresh on each call, so later project edits are visible.
        """
        binary_path = Path(binary).resolve(strict=True)
        project_path = Path(project).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve()
        digest = self._digest(binary_path)
        if project_path.suffix.lower() != ".gpr" or not project_path.is_file():
            raise ValueError("project must be a .gpr file")
        if not project_path.with_suffix(".rep").is_dir():
            raise ValueError("project needs a matching .rep directory")
        if (not isinstance(program, str) or not program or program.startswith("/")
                or "\\" in program or ":" in program or any(
                    not part or part in {".", ".."} or any(
                        ch in "*?[]" or unicodedata.category(ch) == "Cc" for ch in part
                    )
                    for part in program.split("/"))):
            raise ValueError("program must be an exact project-relative path")
        if snapshot_path in {binary_path, project_path}:
            raise ValueError("snapshot path must differ from binary and project")
        args = ["ghidra", "import-project", str(binary_path), str(project_path),
                "--program", program, "--output", str(snapshot_path)]
        if function is not None:
            if not isinstance(function, int) or not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
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
        if kind not in {"pcode", "simplify", "semantics", "state", "cfg", "coverage", "capability", "llvm-prefix", "llvm-standalone", "llvm-cfg", "llvm-cfg-simplified"}:
            raise ValueError("artifact kind must be pcode, simplify, semantics, state, cfg, coverage, capability, llvm-prefix, llvm-standalone, llvm-cfg, or llvm-cfg-simplified")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        self._snapshot(snapshot_path, self._digest(binary_path))
        data = json.loads(self._run("ghidra-snapshot", kind, str(binary_path), str(snapshot_path)))
        if not isinstance(data, dict) or data.get("binary_sha256") != self._digest(binary_path):
            raise RuntimeError("Hydir artifact belongs to another binary")
        return data

    def save_snapshot(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
    ) -> dict[str, Any]:
        """Store a validated snapshot in Hydir's local project database."""
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        digest = self._digest(binary_path)
        self._snapshot(snapshot_path, digest)
        data = json.loads(self._run("ghidra-project", "save", str(binary_path), str(snapshot_path)))
        if not isinstance(data, dict) or data.get("binary_sha256") != digest:
            raise RuntimeError("Saved Ghidra project belongs to another binary")
        return data

    def saved_snapshot(
        self,
        binary: str | os.PathLike[str],
        function: int,
    ) -> dict[str, Any]:
        """Reopen a saved selected-function snapshot without running Ghidra."""
        if not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("function entry must be a 64-bit address")
        binary_path = Path(binary).resolve(strict=True)
        digest = self._digest(binary_path)
        data = json.loads(self._run(
            "ghidra-project", "get", str(binary_path), "--function", hex(function)
        ))
        entry = data.get("selected_function", {}).get("entry", {}).get("offset") if isinstance(data, dict) else None
        if (not isinstance(data, dict) or data.get("binary_sha256") != digest
                or entry != hex(function)):
            raise RuntimeError("Saved Ghidra snapshot belongs to another binary or function")
        return data

    def llvm_cfg(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        *,
        start: int | None = None,
        simplified: bool = False,
        image: bool = False,
    ) -> dict[str, Any]:
        """Emit bounded CFG-aware LLVM with explicit stop status and provenance.

        ``image=True`` binds file-backed read-only ELF bytes into a version 3
        module. The original version 2 ABI remains the default.
        """
        if start is not None and not 0 <= start <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("start must be a 64-bit address")
        if image and simplified:
            raise ValueError("image and simplified LLVM modes cannot be combined")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        digest = self._digest(binary_path)
        self._snapshot(snapshot_path, digest)
        stage = "llvm-cfg-image" if image else "llvm-cfg-simplified" if simplified else "llvm-cfg"
        args = ["ghidra-snapshot", stage, str(binary_path), str(snapshot_path)]
        if start is not None:
            args.extend(["--start", hex(start)])
        data = json.loads(self._run(*args))
        if not isinstance(data, dict) or data.get("binary_sha256") != digest:
            raise RuntimeError("Hydir CFG LLVM artifact belongs to another binary")
        if image and data.get("schema_version") != 3:
            raise RuntimeError("Hydir image-backed CFG LLVM artifact has the wrong version")
        return data

    def llvm_cfg_calls(
        self,
        binary: str | os.PathLike[str],
        root_snapshot: str | os.PathLike[str],
        callees: tuple[str | os.PathLike[str], ...] = (),
        *,
        max_depth: int = 4,
    ) -> dict[str, Any]:
        """Emit bounded LLVM across loaded, validated Ghidra call snapshots."""
        if not isinstance(max_depth, int) or not 0 <= max_depth <= 16:
            raise ValueError("max_depth must be between 0 and 16")
        if len(callees) > 127:
            raise ValueError("at most 127 callee snapshots are supported")
        binary_path = Path(binary).resolve(strict=True)
        digest = self._digest(binary_path)
        paths = [Path(root_snapshot).resolve(strict=True)]
        paths.extend(Path(callee).resolve(strict=True) for callee in callees)
        for path in paths:
            self._snapshot(path, digest)
        args = ["ghidra-snapshot", "llvm-cfg-calls", str(binary_path), str(paths[0])]
        for path in paths[1:]:
            args.extend(["--callee", str(path)])
        args.extend(["--max-depth", str(max_depth)])
        data = json.loads(self._run(*args))
        if (not isinstance(data, dict) or data.get("schema_version") != 1
                or data.get("binary_sha256") != digest
                or not isinstance(data.get("llvm"), dict)
                or data["llvm"].get("binary_sha256") != digest
                or not isinstance(data.get("snapshot_sha256"), list)
                or len(data["snapshot_sha256"]) != len(paths)
                or not isinstance(data.get("function_entries"), list)
                or len(data["function_entries"]) != len(paths)):
            raise RuntimeError("Hydir call CFG LLVM artifact is invalid or belongs to another binary")
        return data

    def llvm_cfg_calls_auto(
        self,
        binary: str | os.PathLike[str],
        seed: str | os.PathLike[str],
        *,
        function: int,
        max_functions: int = 8,
        max_operations: int = 4096,
        max_visits: int = 1024,
        max_depth: int = 8,
    ) -> dict[str, Any]:
        """Analyze a binary and lift the callees reached by one concrete seed."""
        if not isinstance(function, int) or not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("function entry must be a 64-bit address")
        if not 1 <= max_functions <= 32 or not 0 <= max_depth <= 16:
            raise ValueError("call-path function or depth limit is invalid")
        if not 0 <= max_operations <= 262144 or not 0 <= max_visits <= 262144:
            raise ValueError("call-path operation or visit budget is invalid")
        binary_path = Path(binary).resolve(strict=True)
        seed_path = Path(seed).resolve(strict=True)
        digest = self._digest(binary_path)
        data = json.loads(self._run(
            "ghidra", "llvm-cfg-calls", str(binary_path), str(seed_path),
            "--function", hex(function), "--max-functions", str(max_functions),
            "--max-ops", str(max_operations), "--max-visits", str(max_visits),
            "--max-depth", str(max_depth),
        ))
        if (not isinstance(data, dict) or data.get("schema_version") != 1
                or data.get("binary_sha256") != digest
                or not isinstance(data.get("llvm"), dict)
                or data["llvm"].get("binary_sha256") != digest):
            raise RuntimeError("Hydir automatic call CFG LLVM artifact belongs to another binary")
        return data

    def slice(
        self,
        binary: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        instruction_index: int,
        operation_index: int,
        *,
        input_index: int | None = None,
    ) -> dict[str, Any]:
        """Explain a P-code input through bounded, source-linked dependencies."""
        for label, index in (("instruction", instruction_index), ("operation", operation_index),
                             ("input", input_index)):
            if index is not None and (not isinstance(index, int) or not 0 <= index <= 0xFFFFFFFF):
                raise ValueError(f"{label} index must be a 32-bit unsigned integer")
        binary_path = Path(binary).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        digest = self._digest(binary_path)
        self._snapshot(snapshot_path, digest)
        args = ["ghidra-snapshot", "slice", str(binary_path), str(snapshot_path),
                "--instruction", str(instruction_index), "--op", str(operation_index)]
        if input_index is not None:
            args.extend(["--input", str(input_index)])
        data = json.loads(self._run(*args))
        if (not isinstance(data, dict) or data.get("binary_sha256") != digest
                or data.get("schema_version") != 1 or data.get("path_proven") is not False):
            raise RuntimeError("Hydir P-code slice identity or fidelity is invalid")
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

    def trace_calls(
        self,
        binary: str | os.PathLike[str],
        seed: str | os.PathLike[str],
        *,
        function: int,
        max_functions: int = 8,
        max_operations: int = 4096,
        max_visits: int = 1024,
        max_depth: int = 8,
    ) -> dict[str, Any]:
        """Ask Hydir's managed Ghidra worker for direct callees and trace one path."""
        if not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("function entry must be a 64-bit address")
        if not 1 <= max_functions <= 32 or not 0 <= max_depth <= 16:
            raise ValueError("call-path function or depth limit is invalid")
        if not 0 <= max_operations <= 262144 or not 0 <= max_visits <= 262144:
            raise ValueError("call-path operation or visit budget is invalid")
        binary_path = Path(binary).resolve(strict=True)
        seed_path = Path(seed).resolve(strict=True)
        digest = self._digest(binary_path)
        data = json.loads(self._run(
            "ghidra", "trace-calls", str(binary_path), str(seed_path),
            "--function", hex(function), "--max-functions", str(max_functions),
            "--max-ops", str(max_operations), "--max-visits", str(max_visits),
            "--max-depth", str(max_depth),
        ))
        if not isinstance(data, dict) or data.get("binary_sha256") != digest:
            raise RuntimeError("Hydir call trace belongs to another binary")
        return data

    def assess(
        self,
        binary: str | os.PathLike[str],
        seed: str | os.PathLike[str],
        *,
        function: int,
        max_functions: int = 8,
        max_operations: int = 4096,
        max_visits: int = 1024,
        max_depth: int = 8,
    ) -> dict[str, Any]:
        """Assess a seeded Ghidra lift with the managed worker."""
        if not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("function entry must be a 64-bit address")
        if not 1 <= max_functions <= 32 or not 0 <= max_depth <= 16:
            raise ValueError("assessment function or depth limit is invalid")
        if not 0 <= max_operations <= 262144 or not 0 <= max_visits <= 262144:
            raise ValueError("assessment operation or visit budget is invalid")
        binary_path = Path(binary).resolve(strict=True)
        seed_path = Path(seed).resolve(strict=True)
        digest = self._digest(binary_path)
        seed_digest = hashlib.sha256(seed_path.read_bytes()).hexdigest()
        data = json.loads(self._run(
            "ghidra", "assess", str(binary_path), str(seed_path),
            "--function", hex(function), "--max-functions", str(max_functions),
            "--max-ops", str(max_operations), "--max-visits", str(max_visits),
            "--max-depth", str(max_depth),
        ))
        if (
            not isinstance(data, dict) or data.get("binary_sha256") != digest
            or data.get("seed_sha256") != seed_digest
            or data.get("entry", {}).get("offset") != hex(function)
            or data.get("verification") != "not_run"
        ):
            raise RuntimeError("Hydir assessment belongs to another binary, seed, or function")
        return data

    def observe(
        self,
        binary: str | os.PathLike[str],
        input_spec: str | os.PathLike[str],
        *,
        function: int,
        snapshot: str | os.PathLike[str] | None = None,
    ) -> dict[str, Any]:
        """Collect a bounded Frida path through Hydir's Linux observer.

        A completed path is execution evidence; it is not an exit-code or CFG
        completeness claim.
        """
        if not 0 <= function <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("observed function entry must be a 64-bit address")
        binary_path = Path(binary).resolve(strict=True)
        input_path = Path(input_spec).resolve(strict=True)
        digest = self._digest(binary_path)
        if not 0 < input_path.stat().st_size <= 2 * 1024 * 1024:
            raise ValueError("InputSpec is empty or exceeds Hydir's size limit")
        requested_input = json.loads(input_path.read_bytes())
        if not isinstance(requested_input, dict) or requested_input.get("binary_sha256") != digest:
            raise ValueError("InputSpec belongs to another binary")
        args = ["observe", "frida", str(binary_path), str(input_path),
                "--function", hex(function)]
        if snapshot is not None:
            snapshot_path = Path(snapshot).resolve(strict=True)
            selected = self._snapshot(snapshot_path, digest).get("selected_function", {}).get("entry", {})
            if selected.get("space") != "ram":
                raise ValueError("Ghidra snapshot must select RAM code")
            args.extend(["--snapshot", str(snapshot_path)])
        data = json.loads(self._run(*args))
        if (
            not isinstance(data, dict) or data.get("schema_version") not in (1, 2)
            or data.get("binary_sha256") != digest
            or data.get("selected_elf_vaddr") != function
            or not isinstance(data.get("input_sha256"), str)
            or len(data["input_sha256"]) != 64
        ):
            raise RuntimeError("Hydir observation belongs to another binary, input, or function")
        return data

    def seed_from_observation(
        self,
        binary: str | os.PathLike[str],
        input_spec: str | os.PathLike[str],
        snapshot: str | os.PathLike[str],
        trace: str | os.PathLike[str],
    ) -> dict[str, Any]:
        """Map one non-rebased Frida v2 entry context to a partial P-code seed."""
        binary_path = Path(binary).resolve(strict=True)
        input_path = Path(input_spec).resolve(strict=True)
        snapshot_path = Path(snapshot).resolve(strict=True)
        trace_path = Path(trace).resolve(strict=True)
        digest = self._digest(binary_path)
        selected = self._snapshot(snapshot_path, digest).get("selected_function", {}).get("entry")
        data = json.loads(self._run(
            "observe", "seed", str(binary_path), str(input_path),
            str(snapshot_path), str(trace_path),
        ))
        if (not isinstance(data, dict) or data.get("schema_version") != 1
                or data.get("binary_sha256") != digest or data.get("entry") != selected
                or not isinstance(data.get("registers"), list)
                or data.get("memory") != []):
            raise RuntimeError("Frida-derived seed is invalid or belongs to another binary")
        return data
