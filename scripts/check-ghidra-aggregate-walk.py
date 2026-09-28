#!/usr/bin/env python3
"""Differential Ghidra lift of an independent linked-list ELF fixture."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/hydir_aggregate_walk.c"
GDB_SCRIPT = ROOT / "tests/fixtures/ghidra_aggregate_native.gdb"
spec = importlib.util.spec_from_file_location("ghidra_matrix", ROOT / "scripts/check-ghidra-opt-matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)

CASES = (
    ("empty", (), 4, 0),
    ("one", (2,), 4, 8),
    ("two", (2, 3), 4, 20),
    ("zero-scale", (2, 3), 0, 0),
)


def build_variants(directory):
    clang = shutil.which("clang")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    strip = shutil.which("llvm-strip") or shutil.which("strip")
    if not all((clang, nm, strip)):
        raise RuntimeError("clang, llvm-nm/nm, and llvm-strip/strip are required")
    variants = {}
    for level in ("o0", "o2"):
        dwarf = directory / f"walk-{level}-dwarf.elf"
        flags = (["--target=x86_64-unknown-linux-gnu", "-fuse-ld=lld"]
                 if sys.platform == "win32" else [])
        matrix.run([clang, *flags, f"-{level.upper()}", "-g", "-fno-stack-protector",
                    "-fno-builtin", "-nostdlib", "-static", "-no-pie",
                    "-Wl,--build-id=none", "-Wl,-e,_start", SOURCE, "-o", dwarf])
        binary = dwarf.read_bytes()
        program_offset = struct.unpack_from("<Q", binary, 32)[0]
        program_size, program_count = struct.unpack_from("<HH", binary, 54)
        if any(struct.unpack_from("<I", binary, program_offset + i * program_size)[0] == 3
               for i in range(program_count)):
            raise AssertionError(f"aggregate ELF has a program interpreter: {dwarf}")
        entries = []
        for row in matrix.run([nm, dwarf]).splitlines():
            match = re.fullmatch(r"\s*([0-9a-fA-F]+)\s+[Tt]\s+hydir_walk_nodes", row)
            if match:
                entries.append(int(match.group(1), 16))
        if len(entries) != 1:
            raise AssertionError(f"missing unique hydir_walk_nodes: {dwarf}")
        stripped = directory / f"walk-{level}-stripped.elf"
        shutil.copy2(dwarf, stripped)
        matrix.run([strip, "--strip-all", stripped])
        variants[level] = (dwarf, stripped, entries[0])
    return variants


def seed_for(binary, entry, nodes, scale):
    return_address = struct.unpack_from("<Q", binary.read_bytes(), 24)[0]
    registers = [(0x38, 0x700100 if nodes else 0), (0x30, scale),
                 (0x20, 0x700000), (0x28, 0x700200), (0, 0), (8, 0),
                 (0x18, 0), (0xa0, 0), (0xa8, 0), (0xb0, 0), (0xb8, 0)]
    memory = [(0x700000, return_address)]
    for index, value in enumerate(nodes):
        base = 0x700100 + index * 0x20
        next_address = base + 0x20 if index + 1 < len(nodes) else 0
        memory.extend(((base, value), (base + 8, next_address)))
    return {
        "schema_version": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "entry": {"space": "ram", "offset": hex(entry)},
        "registers": [{"offset": hex(offset), "size": 8, "value": hex(value)}
                      for offset, value in registers],
        "memory": [{"space": "ram", "byte_offset": hex(address),
                    "size": 8, "value": hex(value)} for address, value in memory],
    }


def native_result(binary, snapshot_path, nodes, scale):
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return None
    if not shutil.which("gdb"):
        raise RuntimeError("GDB is required for the Linux native aggregate gate")
    env = {**os.environ,
           "HYDIR_NATIVE_SNAPSHOT": str(snapshot_path),
           "HYDIR_NATIVE_NODES": json.dumps(nodes),
           "HYDIR_NATIVE_SCALE": str(scale)}
    output = matrix.run(["gdb", "-nx", "-q", "--batch", "-x", GDB_SCRIPT, binary],
                        env=env, timeout=90)
    results = [json.loads(line.removeprefix("HYDIR_NATIVE_RESULT="))
               for line in output.splitlines()
               if line.startswith("HYDIR_NATIVE_RESULT=")]
    if len(results) != 1:
        raise AssertionError(f"missing native aggregate result: {output[-2000:]}")
    return results[0]


def check_variant(directory, client, binary, entry):
    label = binary.stem
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    snapshot_path = directory / f"{label}-snapshot.json"
    matrix.run([client, "ghidra", "analyze", binary, "--function", hex(entry),
                "--output", snapshot_path], timeout=180)
    snapshot = matrix.load(snapshot_path)
    selected = snapshot["selected_function"]
    if snapshot["binary_sha256"] != digest or selected["entry"]["offset"] != hex(entry):
        raise AssertionError(f"aggregate snapshot binding failed: {label}")
    llvm_path = directory / f"{label}-llvm.json"
    matrix.run([client, "ghidra-snapshot", "llvm-cfg-image", binary,
                snapshot_path, "--output", llvm_path])
    artifact = matrix.load(llvm_path)
    if artifact["schema_version"] != 3 or artifact["binary_sha256"] != digest:
        raise AssertionError(f"aggregate LLVM binding failed: {label}")
    module_path = llvm_path.with_suffix(".ll")
    module_path.write_text(artifact["llvm_ir"], encoding="utf-8")
    seeds = {}
    traces = {}
    native = {}
    for name, nodes, scale, expected in CASES:
        seed = seed_for(binary, entry, nodes, scale)
        seeds[name] = seed
        seed_path = directory / f"{label}-{name}-seed.json"
        seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
        trace_path = directory / f"{label}-{name}-trace.json"
        matrix.run([client, "ghidra-snapshot", "trace-path", binary,
                    snapshot_path, seed_path, "--max-ops", "8192",
                    "--max-visits", "512", "--output", trace_path])
        trace = matrix.load(trace_path)
        traces[name] = trace
        if (trace["stop"]["kind"] != "return" or
                trace["final_state"]["register_bytes"].get("0") != expected or
                len(trace["instruction_visits"]) < (1 if not nodes else 5)):
            raise AssertionError(f"aggregate Rust result failed: {label}/{name}: {trace['stop']}")
        native_row = native_result(binary, snapshot_path, nodes, scale)
        if native_row is not None:
            if (native_row["result"] != expected or
                    native_row["verified_instruction_bytes"] != len(selected["instructions"])):
                raise AssertionError(f"aggregate native result failed: {label}/{name}")
            native[name] = "matched_output_and_code_bytes"
    llvm = matrix.llvm_cases(artifact, module_path, "walk", CASES, seeds, traces)
    print(f"{label}: " + ", ".join(
        f"{name}={traces[name]['stop']['kind']}/{llvm[name]['status']}"
        for name, *_ in CASES), flush=True)
    return {"binary_sha256": digest, "entry": hex(entry),
            "instructions": selected["instructions"], "llvm": llvm, "native": native}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "target/ghidra-aggregate-walk")
    args = parser.parse_args()
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    client = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug" /
                                 ("hydirctl.exe" if sys.platform == "win32" else "hydirctl")))
    if not client.is_file():
        raise RuntimeError(f"build hydirctl first: {client}")
    report = {"schema_version": 1, "source": str(SOURCE.relative_to(ROOT)),
              "variants": {}}
    for level, (dwarf, stripped, entry) in build_variants(directory).items():
        pair = {}
        for binary, debug in ((dwarf, "dwarf"), (stripped, "stripped")):
            pair[debug] = check_variant(directory, client, binary, entry)
        if pair["dwarf"]["instructions"] != pair["stripped"]["instructions"]:
            raise AssertionError(f"aggregate raw P-code changed after stripping: {level}")
        for row in pair.values():
            del row["instructions"]
        report["variants"].update({f"{level}-{debug}": row
                                   for debug, row in pair.items()})
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                               encoding="utf-8")
    print(f"Ghidra aggregate walk gate passed: {directory / 'report.json'}")


if __name__ == "__main__":
    main()
