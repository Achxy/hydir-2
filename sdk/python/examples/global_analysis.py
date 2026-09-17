"""Explicitly upload an ELF and save its conservative cross-function report.

Usage: python global_analysis.py ENDPOINT TOKEN_FILE ELF NEW_REPORT.json NEW_SPEC.json
"""

import json
import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) != 6:
        raise SystemExit(__doc__)
    endpoint, token_file, binary, report_path, spec_path = sys.argv[1:]
    output = Path(report_path)
    spec_output = Path(spec_path)
    if output == spec_output or output.exists() or spec_output.exists():
        raise SystemExit("Output paths must be distinct and new; refusing to overwrite")
    with HydirClient(endpoint, token_file) as client:
        project = client.create_project("Python global analysis")
        uploaded = client.upload_binary(project.project_id, project.revision, binary)
        report = client.analyze(project.project_id, uploaded.revision)
        spec = client.analyze_spec(project.project_id, uploaded.revision)
        if report.get("binary_sha256") != uploaded.binary_sha256:
            raise RuntimeError("Analysis report binary digest does not match upload")
        if spec.get("binary_sha256") != uploaded.binary_sha256:
            raise RuntimeError("Analyzed specification binary digest does not match upload")
        content = json.dumps(report, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        spec_content = json.dumps(spec, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        client.export_artifact(content, output)
        client.export_artifact(spec_content, spec_output)
        print(f"project={project.project_id} revision={uploaded.revision} report={output} spec={spec_output}")


if __name__ == "__main__":
    main()
