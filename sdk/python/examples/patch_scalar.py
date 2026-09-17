"""Explicit trusted-fixture, entry-only scalar patch through the HydIR API.

This creates a project, uploads the supplied ELF, and returns a new patched
ELF file. It does not execute the original or patched binary.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

from hydir_sdk import HydirClient, MAX_BINARY_BYTES


def main() -> int:
    if len(sys.argv) != 8 or sys.argv[7] != "--trusted-fixture":
        print(
            "usage: patch_scalar.py ENDPOINT TOKEN_FILE TRUSTED_ELF SYMBOL "
            "'return arg0 - arg1;' NEW_ELF --trusted-fixture",
            file=sys.stderr,
        )
        return 2
    _, endpoint, token_file, original, symbol, replacement, output, _ = sys.argv
    original_path = Path(original)
    if original_path.stat().st_size > MAX_BINARY_BYTES:
        raise ValueError("Trusted ELF exceeds the 64 MiB client limit")
    content = original_path.read_bytes()
    patch_json = json.dumps(
        {
            "schema_version": 1,
            "binary_sha256": hashlib.sha256(content).hexdigest(),
            "function_symbol": symbol,
            "prototype": "u64(u64,u64)",
            "replacement": replacement,
        },
        separators=(",", ":"),
    ).encode("ascii")
    with HydirClient(endpoint, token_file) as client:
        project = client.create_project("Explicit scalar patch example")
        uploaded = client.upload_binary(project.project_id, project.revision, original_path)
        revision, patched = client.apply_patch(
            project.project_id,
            uploaded.revision,
            patch_json,
            trusted_fixture=True,
            assume_u64x2=True,
            assume_entry_only=True,
        )
        HydirClient.export_artifact(patched, output)
    if os.name == "posix":
        os.chmod(output, 0o700)
    print(
        json.dumps(
            {
                "project_id": project.project_id,
                "revision": revision,
                "patched_sha256": hashlib.sha256(patched).hexdigest(),
                "output": output,
                "execution_validation": "not performed",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
