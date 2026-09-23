#!/usr/bin/env python3
"""Require the Linux runner to report only capabilities proven by the live gate."""

import json
from pathlib import Path
import subprocess
import traceback


ROOT = Path(__file__).resolve().parents[1]
CTL = ROOT / "target" / "debug" / "hydirctl"


def main() -> None:
    output = subprocess.check_output([str(CTL), "doctor"], cwd=ROOT, text=True)
    report = json.loads(output)
    required = (
        "bubblewrap_isolation_ready",
        "native_replay_v1",
        "execution_snapshot_v1",
        "gdb_capture_v1",
        "snapshot_return_solve_v1",
    )
    missing = [name for name in required if report.get(name) is not True]
    assert not missing, {"missing": missing, "host": report.get("host")}
    print("live Linux replay, capture, and bounded solve capabilities reported")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        detail = traceback.format_exc()[-4000:]
        annotation = detail.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Live capability report::{annotation}", flush=True)
        raise
