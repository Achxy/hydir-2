#!/usr/bin/env python3
"""Check that Ghidra's direct call and ELF JUMP_SLOT identify one import."""

import argparse
import ctypes
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
        layout = {item["name"]: item for item in json.loads(
            snapshot_path.read_text(encoding="utf-8"))["register_layout"]}
        for name in ("RAX", "RDI", "RSP"):
            if name not in layout or layout[name]["size_bytes"] != 8:
                raise AssertionError(f"Ghidra did not export the SysV {name} register")
        allocation_path = directory / "allocations.json"
        allocation_path.write_text(json.dumps({
            "schema_version": 1,
            "regions": [{"kind": "stack", "space": "ram",
                         "base": 0x6ffff8, "byte_len": 16}],
        }), encoding="utf-8")

        def contract_trace(name, selected_snapshot):
            selected = json.loads(selected_snapshot.read_text(encoding="utf-8"))
            seed_path = directory / f"{name}-seed.json"
            seed_path.write_text(json.dumps({
                "schema_version": 1, "binary_sha256": digest,
                "entry": selected["selected_function"]["entry"],
                "registers": [{
                    "offset": layout["RSP"]["storage"]["offset"],
                    "size": 8, "value": "0x700000",
                }],
                "memory": [{"space": "ram", "byte_offset": "0x700000",
                            "size": 8, "value": "0xdeadbeef"}],
            }), encoding="utf-8")
            trace_path = directory / f"{name}-trace.json"
            run(CLIENT, "ghidra-snapshot", "trace-calls-imports", BINARY,
                selected_snapshot, seed_path, "--allocations", allocation_path,
                "--max-ops", "256", "--max-visits", "64", "--max-depth", "4",
                "--output", trace_path)
            return json.loads(trace_path.read_text(encoding="utf-8"))

        strlen_trace = contract_trace("strlen", snapshot_path)
        if (strlen_trace["schema_version"] != 4
                or strlen_trace["stop"]["kind"] != "return"
                or len(strlen_trace["contracted_imports"]) != 1
                or strlen_trace["contracted_imports"][0]["name"] != "strlen"
                or "resolves to" not in strlen_trace["contracted_imports"][0]["binding_assumption"]
                or strlen_trace["contracted_imports"][0]["result"] != 5):
            raise AssertionError(f"checked strlen trace did not return 5: {strlen_trace['stop']}")
        native = ctypes.CDLL(str(BINARY.resolve())).hydir_import_strlen
        native.restype = ctypes.c_size_t
        if native() != 5:
            raise AssertionError("native strlen fixture did not return 5")

        memcmp = [item for item in catalog["functions"]
                  if item["name"] == "hydir_import_memcmp"]
        if len(memcmp) != 1:
            raise AssertionError("Ghidra did not discover the unsupported import fixture")
        memcmp_snapshot = directory / "memcmp.json"
        run(CLIENT, "ghidra", "analyze", BINARY, "--function",
            memcmp[0]["entry"]["offset"], "--output", memcmp_snapshot)
        memcmp_trace = contract_trace("memcmp", memcmp_snapshot)
        if (memcmp_trace["stop"]["kind"] != "call_boundary"
                or "no checked SysV call contract" not in memcmp_trace["stop"]["reason"]
                or memcmp_trace.get("contracted_imports")):
            raise AssertionError("unsupported memcmp was silently treated as exact")
        print(json.dumps({"binary_sha256": digest, "imports": sorted(names),
                          "linked_call": linked[0], "strlen_result": 5,
                          "memcmp_stop": memcmp_trace["stop"]["kind"]}, sort_keys=True))


if __name__ == "__main__":
    main()
