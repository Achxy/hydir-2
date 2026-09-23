#!/usr/bin/env python3
"""Exercise fresh replay across argv, stdin, and file input on Linux CI."""

import json
import subprocess
import tempfile
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


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="hydir-replay-smoke-") as directory:
        work = Path(directory)
        binary = work / "replay_channels.elf"
        specification = work / "input.json"
        matching = work / "matching.json"
        mismatching = work / "mismatching.json"
        crashed = work / "crashed.json"
        run("clang", "-O1", ROOT / "tests" / "fixtures" / "replay_channels.c", "-o", binary)
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
    main()
