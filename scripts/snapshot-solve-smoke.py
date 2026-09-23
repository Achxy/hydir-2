#!/usr/bin/env python3
"""Linux gate: captured post-input state -> Triton witness -> original ELF replay."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import traceback


ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "target" / "debug" / "hydirctl"


def run(*arguments: object) -> str:
    result = subprocess.run(
        [str(argument) for argument in arguments],
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(str(argument) for argument in arguments)} failed: "
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def symbol_end(binary: Path, name: str) -> int:
    for line in run("nm", "-S", "--defined-only", binary).splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-1] == name:
            return int(parts[0], 16) + int(parts[1], 16)
    raise RuntimeError(f"symbol {name} has no sized definition")


def main() -> None:
    if sys.platform != "linux":
        raise RuntimeError("snapshot solve smoke requires Linux")
    if not CTL.is_file():
        run("cargo", "build", "--locked", "-p", "hydir-cli", "-q")
    with tempfile.TemporaryDirectory(prefix="hydir-snapshot-solve-") as directory:
        work = Path(directory)
        binary = work / "validator.elf"
        spec_path = work / "input.json"
        snapshot_path = work / "snapshot.json"
        probe_path = work / "probe.json"
        plan_path = work / "plan.json"
        candidate_path = work / "candidate.json"
        slice_path = work / "slice.json"
        claim_path = work / "claim.json"
        recipe_path = work / "recipe.json"
        report_path = work / "solve-report.json"
        run(
            "clang", "-O1", "-fPIE", "-pie", "-fno-omit-frame-pointer",
            ROOT / "tests" / "fixtures" / "snapshot_validator.c", "-o", binary,
        )
        spec = json.loads(run(CTL, "replay", "init", binary))
        spec["stdin_hex"] = "42"
        spec["origins"] = [{
            "id": "byte0", "channel": {"kind": "stdin"}, "offset": 0,
            "length": 1, "encoding": "raw", "alphabet_hex": "",
        }]
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        failing = json.loads(run(CTL, "replay", binary, spec_path))
        assert failing["status"] == "goal_mismatched", failing
        run(CTL, "capture", binary, spec_path, "--function", "check_byte",
            "--output", snapshot_path)
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        assert snapshot["status"] == "stopped", snapshot
        run(CTL, "snapshot", "probe-origin", binary, spec_path, snapshot_path,
            "byte0", "--register", "rdi", "--output", probe_path)
        probe = json.loads(probe_path.read_text(encoding="utf-8"))
        assert probe["status"] == "matched", probe
        code_bytes = symbol_end(binary, "check_byte") - snapshot["stop"]["elf_vaddr"]
        assert 1 <= code_bytes <= 4096, code_bytes
        run(CTL, "snapshot", "plan-return", binary, spec_path, snapshot_path,
            probe_path, "--code-bytes", code_bytes, "--return", 1,
            "--output", plan_path)
        run(CTL, "snapshot", "verify-plan", binary, spec_path, snapshot_path,
            probe_path, plan_path)
        run(CTL, "solve", "snapshot-return", binary, spec_path, snapshot_path,
            probe_path, plan_path, "--candidate-output", candidate_path,
            "--slice-output", slice_path, "--claim-output", claim_path,
            "--recipe-output", recipe_path,
            "--output", report_path)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
        slice_report = json.loads(slice_path.read_text(encoding="utf-8"))
        claim = json.loads(claim_path.read_text(encoding="utf-8"))
        recipe = json.loads(recipe_path.read_text(encoding="utf-8"))
        assert report["bridge"]["status"] == "function_witness", report
        assert report["claim"] == "native_validated_candidate", report
        assert report["native_replay"]["status"] == "goal_matched", report
        assert candidate["stdin_hex"] == "41", candidate
        assert slice_report == report["bridge"]["input_condition_slice"], slice_report
        assert slice_report["relevant_origin_offsets"] == [0], slice_report
        assert slice_report["binary_sha256"] == report["binary_sha256"], slice_report
        assert slice_report["ast_walk_complete"], slice_report
        assert any(decision["origin_offsets"] == [0]
                   for decision in slice_report["decisions"]), slice_report
        assert claim == recipe["claim"] == report["investigation_claim"], claim
        assert report["original_replay"]["status"] == "goal_mismatched", report
        assert recipe["recorded_original_replay"]["status"] == "goal_mismatched", recipe
        assert claim["changed_bytes"] == [{
            "origin_offset": 0, "channel_offset": 0,
            "before": 0x42, "after": 0x41,
        }], claim
        verified = json.loads(run(CTL, "recipe", "verify", binary, recipe_path))
        assert verified["valid"], verified
        assert verified["verification_scope"] == "recorded_artifact_consistency_only", verified
        reproduced = json.loads(run(CTL, "recipe", "replay", binary, recipe_path))
        assert reproduced["claim_reproduced"], reproduced
        assert reproduced["fresh_original_replay"]["status"] == "goal_mismatched", reproduced
        assert reproduced["fresh_candidate_replay"]["status"] == "goal_matched", reproduced

        tampered = work / "tampered-recipe.json"
        recipe["candidate_input"]["stdin_hex"] = "43"
        tampered.write_text(json.dumps(recipe), encoding="utf-8")
        rejected = subprocess.run(
            [str(CTL), "recipe", "verify", str(binary), str(tampered)],
            text=True, capture_output=True, check=False,
        )
        assert rejected.returncode != 0, rejected.stdout
        recipe["candidate_input"]["stdin_hex"] = "41"
        recipe["claim"]["replay_sha256"] = "0" * 64
        tampered.write_text(json.dumps(recipe), encoding="utf-8")
        rejected_claim = subprocess.run(
            [str(CTL), "recipe", "verify", str(binary), str(tampered)],
            text=True, capture_output=True, check=False,
        )
        assert rejected_claim.returncode != 0, rejected_claim.stdout
        again = json.loads(run(CTL, "replay", binary, candidate_path))
        assert again["status"] == "goal_matched", again
        print("snapshot solve and native replay gate passed")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        detail = traceback.format_exc()[-4000:]
        annotation = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Captured-state solve smoke::{annotation}", flush=True)
        raise
