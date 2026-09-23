#!/usr/bin/env python3
"""Exercise fresh replay across argv, stdin, and file input on Linux CI."""

import hashlib
import json
import subprocess
import tempfile
import traceback
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "target" / "debug" / "hydirctl"


def run(*args: object) -> None:
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def expect_report(path: Path, status: str, exit_code: int) -> None:
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["status"] == status, report
    assert report["exit_code"] == exit_code, report
    assert report["schema_version"] == 1, report
    assert len(report["binary_sha256"]) == 64, report
    assert len(report["input_sha256"]) == 64, report


def symbol_address(binary: Path, symbol: str) -> int:
    result = subprocess.run(
        ["nm", "-an", str(binary)], cwd=ROOT, check=True, capture_output=True, text=True
    )
    matches = [
        int(parts[0], 16)
        for line in result.stdout.splitlines()
        if len(parts := line.split()) == 3 and parts[2] == symbol
    ]
    assert len(matches) == 1, matches
    return matches[0]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hydir-replay-smoke-") as directory:
        work = Path(directory)
        binary = work / "replay_channels.elf"
        specification = work / "input.json"
        matching = work / "matching.json"
        mismatching = work / "mismatching.json"
        crashed = work / "crashed.json"
        snapshot_path = work / "snapshot.json"
        stripped = work / "replay_channels.stripped.elf"
        stripped_specification = work / "stripped-input.json"
        stripped_snapshot_path = work / "stripped-snapshot.json"
        stripped_probe_path = work / "stripped-origin-probe.json"
        run("clang", "-O1", "-fPIE", "-pie", ROOT / "tests" / "fixtures" / "replay_channels.c", "-o", binary)
        validator_address = symbol_address(binary, "check_line")
        run("strip", "--strip-all", "-o", stripped, binary)
        stripped_nm = subprocess.run(
            ["nm", "-an", str(stripped)], cwd=ROOT, capture_output=True, text=True
        )
        assert "check_line" not in stripped_nm.stdout, stripped_nm.stdout
        run("cargo", "build", "--locked", "-q", "-p", "hydir-cli")
        run(CTL, "replay", "init", binary, "--output", specification)
        spec = json.loads(specification.read_text(encoding="utf-8"))
        spec["argv_hex"] = [b"open".hex()]
        spec["stdin_hex"] = b"secret\n".hex()
        spec["files"] = [{"path": "data/key", "bytes_hex": b"key".hex()}]
        spec["origins"] = [
            {"id": "phrase", "channel": {"kind": "stdin"}, "offset": 0,
             "length": 6, "encoding": "ascii", "alphabet_hex": ""}
        ]
        spec["goal"] = {
            "exit_code": 0,
            "stdout_contains_hex": b"ACCESS GRANTED".hex(),
            "stderr_contains_hex": None,
        }
        specification.write_text(json.dumps(spec), encoding="utf-8")
        run(CTL, "replay", "verify", binary, specification)
        run(CTL, "replay", binary, specification, "--output", matching)
        expect_report(matching, "goal_matched", 0)
        run(CTL, "capture", binary, specification, "--function", "main", "--output", snapshot_path)
        run(CTL, "snapshot", "verify", binary, specification, snapshot_path)
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        assert snapshot["status"] == "stopped", snapshot
        assert snapshot["thread_count"] == 1, snapshot
        assert snapshot["stop"]["runtime_pc"] == snapshot["stop"]["elf_vaddr"] + snapshot["stop"]["load_bias"], snapshot
        assert any(page["value"]["state"] == "present" for page in snapshot["pages"]), snapshot
        stripped_spec = dict(spec)
        stripped_spec["binary_sha256"] = hashlib.sha256(stripped.read_bytes()).hexdigest()
        stripped_specification.write_text(json.dumps(stripped_spec), encoding="utf-8")
        run(CTL, "replay", "verify", stripped, stripped_specification)
        run(CTL, "capture", stripped, stripped_specification, "--address", hex(validator_address), "--output", stripped_snapshot_path)
        run(CTL, "snapshot", "verify", stripped, stripped_specification, stripped_snapshot_path)
        stripped_snapshot = json.loads(stripped_snapshot_path.read_text(encoding="utf-8"))
        assert stripped_snapshot["status"] == "stopped", stripped_snapshot
        assert stripped_snapshot["stop"]["elf_vaddr"] == validator_address, stripped_snapshot
        assert stripped_snapshot["stop"]["load_bias"] != 0, stripped_snapshot
        assert stripped_snapshot["stop"]["symbol"] is None, stripped_snapshot
        origin = stripped_spec["origins"][0]
        assert origin["channel"]["kind"] == "stdin", origin
        source = bytes.fromhex(stripped_spec["stdin_hex"])
        expected = source[origin["offset"]:origin["offset"] + origin["length"]]
        argument = stripped_snapshot["registers"]["rdi"]
        assert argument["state"] == "present", stripped_snapshot
        run(CTL, "snapshot", "probe-origin", stripped, stripped_specification,
            stripped_snapshot_path, origin["id"], "--register", "rdi", "--output", stripped_probe_path)
        run(CTL, "snapshot", "verify-origin", stripped, stripped_specification,
            stripped_snapshot_path, stripped_probe_path)
        probe = json.loads(stripped_probe_path.read_text(encoding="utf-8"))
        assert probe["status"] == "matched", probe
        assert probe["evidence"] == "byte_equality_only", probe
        assert probe["runtime_address"] == argument["value"], probe
        assert probe["observed_hex"] == expected.hex(), probe
        spec["stdin_hex"] = b"wrong\n".hex()
        specification.write_text(json.dumps(spec), encoding="utf-8")
        run(CTL, "replay", binary, specification, "--output", mismatching)
        expect_report(mismatching, "goal_mismatched", 1)
        spec["argv_hex"] = [b"crash".hex()]
        spec["goal"] = {"exit_code": 139, "stdout_contains_hex": None, "stderr_contains_hex": None}
        specification.write_text(json.dumps(spec), encoding="utf-8")
        run(CTL, "replay", binary, specification, "--output", crashed)
        crash_report = json.loads(crashed.read_text(encoding="utf-8"))
        assert crash_report["status"] == "runner_error", crash_report
        assert crash_report["exit_code"] is None, crash_report
        assert crash_report["diagnostic"], crash_report


if __name__ == "__main__":
    try:
        main()
    except Exception:
        detail = traceback.format_exc()[-4000:]
        annotation = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Native replay smoke::{annotation}", flush=True)
        raise
