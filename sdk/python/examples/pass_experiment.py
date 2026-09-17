"""Explicitly upload a trusted scalar ELF and save one named LLVM experiment.

Usage: python pass_experiment.py ENDPOINT TOKEN_FILE TRUSTED_ELF SYMBOL PASSES NEW_OUTPUT_DIR
"""

import json
import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) != 7:
        raise SystemExit(__doc__)
    endpoint, token_file, binary, symbol, passes, output_dir = sys.argv[1:]
    output = Path(output_dir)
    if output.exists():
        raise SystemExit("Output directory exists; refusing to overwrite it")
    with HydirClient(endpoint, token_file) as client:
        project = client.create_project("Python pass experiment")
        uploaded = client.upload_binary(project.project_id, project.revision, binary)
        report, artifacts = client.transform(
            project.project_id, uploaded.revision, symbol, passes,
            assume_u64x2=True, trusted_fixture=True,
        )
        output.mkdir(parents=True, exist_ok=False)
        for name, content in artifacts.items():
            client.export_artifact(content, output / name)
        print(json.dumps({
            "project_id": project.project_id,
            "revision": uploaded.revision + 1,
            "report": report,
            "output_dir": str(output),
        }, indent=2))


if __name__ == "__main__":
    main()
