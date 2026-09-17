"""Explicitly upload an ELF and save its conservative cross-function report.

Usage: python global_analysis.py ENDPOINT TOKEN_FILE ELF NEW_REPORT.json
"""

import json
import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    endpoint, token_file, binary, report_path = sys.argv[1:]
    output = Path(report_path)
    if output.exists():
        raise SystemExit("Report path exists; refusing to overwrite it")
    with HydirClient(endpoint, token_file) as client:
        project = client.create_project("Python global analysis")
        uploaded = client.upload_binary(project.project_id, project.revision, binary)
        report = client.analyze(project.project_id, uploaded.revision)
        if report.get("binary_sha256") != uploaded.binary_sha256:
            raise RuntimeError("Analysis report binary digest does not match upload")
        content = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        client.export_artifact(content, output)
        print(f"project={project.project_id} revision={uploaded.revision} report={output}")


if __name__ == "__main__":
    main()
