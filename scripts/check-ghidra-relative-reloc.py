#!/usr/bin/env python3
"""Check a PIE RELATIVE relocation against Ghidra mapping and Rust execution."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/ghidra_relative_reloc.S"
CLIENT = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug/hydirctl"))


def run(*args, timeout=180):
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}):\n"
                             f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    return result.stdout


def symbol_address(symbols, name):
    match = re.search(rf"^([0-9a-fA-F]+)\s+\w\s+{re.escape(name)}$", symbols, re.M)
    if match is None:
        raise AssertionError(f"missing PIE symbol {name}")
    return int(match.group(1), 16)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not CLIENT.is_file():
        raise RuntimeError(f"build hydirctl first: {CLIENT}")
    with tempfile.TemporaryDirectory(prefix="hydir-relative-") as scratch:
        directory = args.output_dir or Path(scratch)
        directory.mkdir(parents=True, exist_ok=True)
        binary = directory / "relative.elf"
        run("clang", "-nostdlib", "-pie",
            "-Wl,--build-id=none", "-Wl,-e,_start", SOURCE, "-o", binary)
        if "R_X86_64_RELATIVE" not in run("readelf", "--relocs", binary):
            raise AssertionError("PIE fixture lacks R_X86_64_RELATIVE")
        symbols = run("nm", binary)
        entry = symbol_address(symbols, "hydir_read_target")
        pointer = symbol_address(symbols, "hydir_pointer")
        target = symbol_address(symbols, "hydir_target")
        start = symbol_address(symbols, "_start")
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        catalog_path = directory / "catalog.json"
        run(CLIENT, "ghidra", "analyze", binary, "--output", catalog_path,
            timeout=240)
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        matches = [item for item in catalog["functions"]
                   if item["name"] == "hydir_read_target"]
        if len(matches) != 1:
            raise AssertionError("Ghidra did not discover the PIE fixture function")
        selected_entry = int(matches[0]["entry"]["offset"], 16)
        snapshot_path = directory / "snapshot.json"
        if catalog["selected_function"]["entry"] == matches[0]["entry"]:
            snapshot_path = catalog_path
        else:
            run(CLIENT, "ghidra", "analyze", binary, "--function",
                hex(selected_entry), "--output", snapshot_path, timeout=240)
        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
        if snapshot["binary_sha256"] != digest:
            raise AssertionError("PIE snapshot digest differs from ELF")
        analyzed_entry = int(snapshot["selected_function"]["entry"]["offset"], 16)
        bias = analyzed_entry - entry
        if bias < 0:
            raise AssertionError("Ghidra PIE load bias is negative")
        memory_path = directory / "process-memory.json"
        run(CLIENT, "ghidra-snapshot", "process-memory", binary, snapshot_path,
            "--output", memory_path)
        memory = json.loads(memory_path.read_text(encoding="utf-8"))
        if memory["schema_version"] != 2 or memory["binary_sha256"] != digest:
            raise AssertionError("PIE process memory version or digest differs")
        index = pointer + bias - memory["base"]
        if index < 0 or index + 8 > len(memory["bytes"]):
            raise AssertionError("relocation destination is outside process image")
        if memory["known"][index:index + 8] != [255] * 8:
            raise AssertionError("disjoint R_X86_64_RELATIVE remains unknown")
        actual_pointer = int.from_bytes(bytes(memory["bytes"][index:index + 8]), "little")
        if actual_pointer != target + bias or memory["unresolved_relocation_bytes"] != 0:
            raise AssertionError("R_X86_64_RELATIVE did not resolve to mapped target")
        allocations = directory / "allocations.json"
        allocations.write_text(json.dumps({"schema_version": 1, "regions": [
            {"kind": "stack", "space": "ram", "base": 0x700000,
             "byte_len": 0x100}]}), encoding="utf-8")
        seed = directory / "seed.json"
        seed.write_text(json.dumps({"schema_version": 1, "binary_sha256": digest,
                                    "entry": snapshot["selected_function"]["entry"],
                                    "registers": [{"offset": "0x20", "size": 8,
                                                   "value": "0x700080"}],
                                    "memory": [{"space": "ram", "byte_offset": "0x700080",
                                                "size": 8, "value": hex(start + bias)}]}),
                        encoding="utf-8")
        trace_path = directory / "trace.json"
        run(CLIENT, "ghidra-snapshot", "trace-path", binary, snapshot_path, seed,
            "--memory", "allocated", "--allocations", allocations,
            "--max-ops", "64", "--max-visits", "8", "--output", trace_path)
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        value = int.from_bytes(bytes(trace["final_state"]["register_bytes"][str(i)]
                                     for i in range(8)), "little")
        if trace["stop"]["kind"] != "return" or value != 42:
            raise AssertionError(f"PIE relocation Rust execution failed: {trace['stop']}")
        llvm_path = directory / "llvm.json"
        run(CLIENT, "ghidra-snapshot", "llvm-cfg-allocated", binary, snapshot_path,
            "--allocations", allocations, "--output", llvm_path)
        llvm = json.loads(llvm_path.read_text(encoding="utf-8"))
        if (llvm["schema_version"] != 5 or
                llvm["process_memory"]["unresolved_relocation_bytes"] != 0):
            raise AssertionError("LLVM artifact did not consume resolved PIE process memory")
        module = directory / "relative.ll"
        module.write_text(llvm["llvm_ir"], encoding="utf-8")
        run("clang", "-x", "ir", "-c", module, "-o", directory / "relative.o")
        result = {"binary_sha256": digest, "schema_version": 2,
                  "relocation_address": hex(pointer + bias),
                  "resolved_pointer": hex(actual_pointer), "result": value}
        (directory / "report.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
