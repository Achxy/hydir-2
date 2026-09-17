"""Explicitly upload and rebuild a trusted freestanding ELF without running it.

Usage: python rebuild_program.py ENDPOINT TOKEN_FILE TRUSTED_ELF NEW_OUTPUT_DIR
"""

import os
import sys
from pathlib import Path

from hydir_sdk import HydirClient


def main() -> None:
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    endpoint, token_file, binary, output_dir = sys.argv[1:]
    output = Path(output_dir)
    if output.exists():
        raise SystemExit("Output directory exists; refusing to overwrite it")
    with HydirClient(endpoint, token_file) as client:
        project = client.create_project("Python whole-program rebuild")
        uploaded = client.upload_binary(project.project_id, project.revision, binary)
        revision, artifacts = client.rebuild(
            project.project_id, uploaded.revision, trusted_fixture=True
        )
        output.mkdir(parents=True, exist_ok=False)
        for name, content in artifacts.items():
            client.export_artifact(content, output / name)
        if os.name == "posix":
            (output / "rebuilt").chmod(0o700)
        print(f"project={project.project_id} revision={revision} output={output}")


if __name__ == "__main__":
    main()
