"""Compare trusted original/rebuilt static ELFs in disposable Docker runs.

Usage: python validate_program.py --trusted-fixture ORIGINAL REBUILT CASES_JSON NEW_REPORT_JSON

CASES_JSON is a list of {"label": "case-name", "stdin_hex": "41"} objects.
Docker resource controls here are not a hostile-binary sandbox or equivalence proof.
No project, token, host directory, or network is mounted into the containers.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

MAX_BINARY_BYTES = 16 * 1024 * 1024
MAX_INPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
IMAGE = "hydir-m1:local"


def check_binary(path: Path) -> None:
    if not path.is_file() or path.stat().st_size > MAX_BINARY_BYTES:
        raise ValueError(f"not a regular ELF under 16 MiB: {path}")
    with path.open("rb") as source:
        if source.read(4) != b"\x7fELF":
            raise ValueError(f"not an ELF: {path}")


def run_case(binary: Path, input_bytes: bytes) -> dict[str, object]:
    name = f"hydir-validation-{uuid4().hex}"
    command = [
        "docker", "run", "--rm", "--name", name,
        "--platform", "linux/amd64", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "32", "--memory", "128m", "--cpus", "1",
        "--user", "65534:65534", "--mount",
        f"type=bind,src={binary},dst=/sample,readonly",
        "--entrypoint", "/usr/bin/timeout", IMAGE, "5", "/sample",
    ]
    try:
        completed = subprocess.run(command, input=input_bytes, capture_output=True, timeout=30, check=False)
    except subprocess.TimeoutExpired as error:
        subprocess.run(["docker", "kill", name], capture_output=True, timeout=5, check=False)
        raise RuntimeError(f"Docker run exceeded 30 seconds including startup: {name}") from error
    if len(completed.stdout) > MAX_OUTPUT_BYTES or len(completed.stderr) > MAX_OUTPUT_BYTES:
        raise RuntimeError("container output exceeded 1 MiB per stream")
    if completed.returncode == 125:
        raise RuntimeError(f"Docker could not start the sample: {completed.stderr.decode(errors='replace')}")
    if completed.returncode == 124:
        raise RuntimeError("sample exceeded its 5-second execution limit")
    return {
        "exit_status": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stdout_hex": completed.stdout.hex(),
        "stderr_hex": completed.stderr.hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-fixture", action="store_true")
    parser.add_argument("original", type=Path)
    parser.add_argument("rebuilt", type=Path)
    parser.add_argument("cases_json", type=Path)
    parser.add_argument("report_json", type=Path)
    args = parser.parse_args()
    if not args.trusted_fixture:
        parser.error("explicit --trusted-fixture assertion is required")
    for binary in (args.original, args.rebuilt):
        check_binary(binary)
    report_path = args.report_json.resolve()
    if report_path.exists():
        parser.error("report path exists; refusing to overwrite")
    cases = json.loads(args.cases_json.read_text(encoding="utf-8"))
    if not isinstance(cases, list) or not 1 <= len(cases) <= 128:
        parser.error("cases must be a JSON list of 1..=128 inputs")
    results = []
    with tempfile.TemporaryDirectory(prefix="hydir-validation-", dir=report_path.parent) as temporary:
        prepared = []
        for index, binary in enumerate((args.original, args.rebuilt)):
            target = Path(temporary) / f"sample-{index}"
            shutil.copyfile(binary, target)
            target.chmod(0o555)
            prepared.append(target)
        for case in cases:
            if not isinstance(case, dict) or set(case) != {"label", "stdin_hex"}:
                parser.error("each case must contain exactly label and stdin_hex")
            label, input_hex = case["label"], case["stdin_hex"]
            if not isinstance(label, str) or not label or len(label) > 128 or not isinstance(input_hex, str):
                parser.error("case label or input is invalid")
            try:
                input_bytes = bytes.fromhex(input_hex)
            except ValueError as error:
                parser.error(f"invalid stdin_hex for {label}: {error}")
            if len(input_bytes) > MAX_INPUT_BYTES:
                parser.error(f"stdin exceeds 64 KiB for {label}")
            original = run_case(prepared[0], input_bytes)
            rebuilt = run_case(prepared[1], input_bytes)
            results.append({"label": label, "matched": original == rebuilt, "original": original, "rebuilt": rebuilt})
    report = {
        "scope": "trusted static ELF; Docker no-network/read-only/resource-controlled client-side checks",
        "sandbox_limit": "Docker controls do not establish hostile-input isolation",
        "image": IMAGE,
        "original_sha256": hashlib.sha256(args.original.read_bytes()).hexdigest(),
        "rebuilt_sha256": hashlib.sha256(args.rebuilt.read_bytes()).hexdigest(),
        "cases_attempted": len(results),
        "cases_matched": sum(case["matched"] for case in results),
        "cases": results,
    }
    descriptor = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as destination:
        json.dump(report, destination, indent=2)
        destination.write("\n")
    print(f"matched {report['cases_matched']}/{report['cases_attempted']} controlled cases; report: {report_path}")
    if report["cases_matched"] != report["cases_attempted"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
