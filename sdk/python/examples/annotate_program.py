"""Upload a trusted ELF, append one analyst fact, and export its fact ledger.

Usage: python annotate_program.py ENDPOINT TOKEN_FILE ELF KIND ADDRESS_OR_DASH SCOPE VALUE NEW_LEDGER.json
KIND is name, comment, or assumption. '-' records a program-wide fact.
"""

import json
import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) != 9:
        raise SystemExit(__doc__)
    endpoint, token_file, binary, kind, address, scope, value, ledger_path = sys.argv[1:]
    output = Path(ledger_path)
    if output.exists():
        raise SystemExit("Ledger path exists; refusing to overwrite it")
    with HydirClient(endpoint, token_file) as client:
        project = client.create_project("Python analyst annotations")
        uploaded = client.upload_binary(project.project_id, project.revision, binary)
        annotated = client.add_annotation(
            project.project_id,
            uploaded.revision,
            kind=kind,
            address=None if address == "-" else address,
            scope=scope,
            value=value,
        )
        if annotated.revision != uploaded.revision + 1:
            raise RuntimeError("Annotation did not create exactly one project revision")
        ledger = client.list_annotations(project.project_id, annotated.revision)
        if ledger.get("binary_sha256") != uploaded.binary_sha256:
            raise RuntimeError("Annotation ledger digest does not match upload")
        if not ledger.get("annotations"):
            raise RuntimeError("Annotation ledger is unexpectedly empty")
        if kind == "assumption":
            spec = client.analyze_spec(project.project_id, annotated.revision)
            if not any(
                fact.get("provenance", {}).get("source") == "analyst_assertion"
                and fact.get("statement") == value
                for fact in spec.get("assumptions", [])
            ):
                raise RuntimeError("Analyst assumption is absent from analyzed specification")
        content = json.dumps(ledger, indent=2, sort_keys=True).encode("utf-8") + b"\n"
        client.export_artifact(content, output)
        print(f"project={project.project_id} revision={annotated.revision} ledger={output}")


if __name__ == "__main__":
    main()
