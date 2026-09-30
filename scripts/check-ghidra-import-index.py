#!/usr/bin/env python3
"""Check that Ghidra's direct call and ELF JUMP_SLOT identify one import."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "tests/fixtures/ghidra_import_calls.elf"
CLIENT = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug/hydirctl"))


def run(*args):
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT,
                            capture_output=True, text=True, timeout=240)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}):\n"
                             f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not CLIENT.is_file():
        raise RuntimeError(f"build hydirctl first: {CLIENT}")
    with tempfile.TemporaryDirectory(prefix="hydir-import-") as scratch:
        directory = args.output_dir or Path(scratch)
        directory.mkdir(parents=True, exist_ok=True)
        catalog_path = directory / "catalog.json"
        run(CLIENT, "ghidra", "analyze", BINARY, "--output", catalog_path)
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        matches = [item for item in catalog["functions"]
                   if item["name"] == "hydir_import_strlen"]
        if len(matches) != 1:
            raise AssertionError("Ghidra did not discover the imported-call fixture")
        snapshot_path = directory / "strlen.json"
        if catalog["selected_function"]["entry"] == matches[0]["entry"]:
            snapshot_path = catalog_path
        else:
            run(CLIENT, "ghidra", "analyze", BINARY, "--function",
                matches[0]["entry"]["offset"], "--output", snapshot_path)
        imports_path = directory / "imports.json"
        run(CLIENT, "ghidra-snapshot", "imports", BINARY, snapshot_path,
            "--output", imports_path)
        imports = json.loads(imports_path.read_text(encoding="utf-8"))
        digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
        if imports["schema_version"] != 1 or imports["binary_sha256"] != digest:
            raise AssertionError("import index identity differs from the ELF")
        names = {item["name"] for item in imports["imports"]}
        if names != {"strlen", "memcmp"}:
            raise AssertionError(f"JUMP_SLOT import names differ: {names}")
        linked = [call for call in imports["calls"] if call["name"] == "strlen"]
        if len(linked) != 1:
            raise AssertionError(f"Ghidra CALL did not link to checked strlen PLT stub: {imports['calls']}")
        if linked[0]["got"] not in [item["got"] for item in imports["imports"]
                                      if item["name"] == "strlen"]:
            raise AssertionError("linked call GOT slot differs from relocation")
        print(json.dumps({"binary_sha256": digest, "imports": sorted(names),
                          "linked_call": linked[0]}, sort_keys=True))


if __name__ == "__main__":
    main()
