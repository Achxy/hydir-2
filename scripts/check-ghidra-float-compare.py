#!/usr/bin/env python3
"""Compare real x86 SSE floating-point branches in Rust, LLVM, and native code."""

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
SOURCE = ROOT / "tests/fixtures/ghidra_float_compare.S"
spec = importlib.util.spec_from_file_location(
    "ghidra_matrix", ROOT / "scripts/check-ghidra-opt-matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)


def bits32(value):
    return struct.unpack("<I", struct.pack("<f", value))[0]


def bits64(value):
    return struct.unpack("<Q", struct.pack("<d", value))[0]


CASES = {
    32: (
        ("less", bits32(1.0), bits32(2.0), 1),
        ("equal", bits32(-3.5), bits32(-3.5), 2),
        ("greater", bits32(3.0), bits32(2.0), 3),
        ("signed-zero", bits32(0.0), bits32(-0.0), 2),
        ("nan-left", 0x7fc00001, bits32(1.0), 4),
        ("nan-right", bits32(1.0), 0x7fc00001, 4),
        ("negative-infinity", bits32(float("-inf")), bits32(1.0), 1),
    ),
    64: (
        ("less", bits64(1.0), bits64(2.0), 1),
        ("equal", bits64(-3.5), bits64(-3.5), 2),
        ("greater", bits64(3.0), bits64(2.0), 3),
        ("signed-zero", bits64(0.0), bits64(-0.0), 2),
        ("nan-left", 0x7ff8000000000001, bits64(1.0), 4),
        ("nan-right", bits64(1.0), 0x7ff8000000000001, 4),
        ("negative-infinity", bits64(float("-inf")), bits64(1.0), 1),
    ),
}


def build_elf(directory):
    compiler = shutil.which("clang")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if not compiler or not nm:
        raise RuntimeError("clang and nm are required")
    binary = directory / "float-compare.elf"
    target = (["--target=x86_64-unknown-linux-gnu", "-fuse-ld=lld"]
              if sys.platform == "win32" else [])
    matrix.run([compiler, *target, "-g", "-nostdlib", "-static", "-no-pie",
                "-Wl,--build-id=none", "-Wl,-e,_start", SOURCE, "-o", binary])
    symbols = {}
    for row in matrix.run([nm, binary]).splitlines():
        match = re.fullmatch(
            r"\s*([0-9a-fA-F]+)\s+[Tt]\s+(hydir_float_gate32|hydir_float_gate64)", row)
        if match:
            symbols[match.group(2)] = int(match.group(1), 16)
    if set(symbols) != {"hydir_float_gate32", "hydir_float_gate64"}:
        raise AssertionError(f"missing float functions: {symbols}")
    return binary, symbols


def seed_for(binary, entry, left, right):
    return_address = struct.unpack_from("<Q", binary.read_bytes(), 24)[0]
    registers = ((0x1200, left), (0x1240, right), (0x20, 0x700000),
                 (0x28, 0x700200), (0, 0))
    return {
        "schema_version": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "entry": entry,
        "registers": [{"offset": hex(offset), "size": 8, "value": hex(value)}
                      for offset, value in registers],
        "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8,
                    "value": hex(return_address)}],
    }


def native_cases(directory, width):
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return []
    scalar = "float" if width == 32 else "double"
    integer = "uint32_t" if width == 32 else "uint64_t"
    macro = "UINT32_C" if width == 32 else "UINT64_C"
    function = f"hydir_float_gate{width}"
    checks = []
    for index, (name, left, right, expected) in enumerate(CASES[width], 1):
        checks.append(
            f"  {{ {integer} x = {macro}(0x{left:x}), y = {macro}(0x{right:x}); "
            f"{scalar} a, b; memcpy(&a, &x, sizeof a); memcpy(&b, &y, sizeof b); "
            f"if ({function}(a, b) != {expected}) return {index}; }} /* {name} */")
    source = directory / f"native-{width}.c"
    source.write_text(
        "#include <stdint.h>\n#include <string.h>\n"
        f"extern uint32_t {function}({scalar}, {scalar});\n"
        "int main(void) {\n" + "\n".join(checks) + "\n  return 0;\n}\n",
        encoding="utf-8")
    compilers = []
    for compiler in ("clang", "gcc"):
        if not shutil.which(compiler):
            raise RuntimeError(f"{compiler} is required for Linux native float comparison")
        executable = directory / f"native-{width}-{compiler}"
        assembly_object = directory / f"native-{width}-{compiler}-fixture.o"
        c_object = directory / f"native-{width}-{compiler}-main.o"
        matrix.run([compiler, "-DHYDIR_FLOAT_HARNESS", "-c", SOURCE,
                    "-o", assembly_object])
        matrix.run([compiler, "-std=c11", "-O2", "-fno-fast-math", "-Wall",
                    "-Wextra", "-Werror", "-c", source, "-o", c_object])
        matrix.run([compiler, assembly_object, c_object, "-o", executable])
        matrix.run([executable])
        compilers.append(compiler)
    return compilers


def check_function(directory, client, binary, entry, width):
    symbol = f"hydir_float_gate{width}"
    snapshot_path = directory / f"{symbol}-snapshot.json"
    matrix.run([client, "ghidra", "analyze", binary, "--function", hex(entry),
                "--output", snapshot_path], timeout=180)
    snapshot = matrix.load(snapshot_path)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    selected = snapshot["selected_function"]
    if snapshot["binary_sha256"] != digest or selected["entry"]["offset"] != hex(entry):
        raise AssertionError(f"{symbol}: Ghidra snapshot binding failed")
    first = selected["instructions"][0]
    if first["mnemonic"] != ("UCOMISS" if width == 32 else "UCOMISD"):
        raise AssertionError(f"{symbol}: unexpected SSE instruction")
    floating = [op for instruction in selected["instructions"] for op in instruction["pcode"]
                if op["opcode"] in (41, 42, 43, 44, 46)]
    if sorted(op["mnemonic"] for op in floating) != [
            "FLOAT_EQUAL", "FLOAT_LESS", "FLOAT_NAN", "FLOAT_NAN"]:
        raise AssertionError(f"{symbol}: Ghidra emitted a different float contract")
    if any(op["output"]["size"] != 1 or
           any(value["size"] != width // 8 for value in op["inputs"])
           for op in floating):
        raise AssertionError(f"{symbol}: float varnode widths changed")
    coverage_path = directory / f"{symbol}-coverage.json"
    matrix.run([client, "ghidra-snapshot", "coverage", binary,
                snapshot_path, "--output", coverage_path])
    coverage = matrix.load(coverage_path)
    for opcode in (41, 43, 46):
        rows = [row for row in coverage["by_opcode"] if row["opcode"] == opcode]
        if len(rows) != 1 or rows[0]["exact_assignments"] != rows[0]["operations"]:
            raise AssertionError(f"{symbol}: float opcode {opcode} is not exact")
    artifact_path = directory / f"{symbol}-llvm.json"
    matrix.run([client, "ghidra-snapshot", "llvm-cfg-image", binary,
                snapshot_path, "--output", artifact_path])
    artifact = matrix.load(artifact_path)
    if artifact["schema_version"] != 3 or artifact["binary_sha256"] != digest:
        raise AssertionError(f"{symbol}: LLVM artifact binding failed")
    module_path = artifact_path.with_suffix(".ll")
    module_path.write_text(artifact["llvm_ir"], encoding="utf-8")
    verifier = shutil.which("opt")
    if not verifier:
        raise RuntimeError("LLVM opt is required for verifier coverage")
    matrix.run([verifier, "-passes=verify", "-disable-output", module_path])
    seeds = {}
    traces = {}
    for name, left, right, expected in CASES[width]:
        seed = seed_for(binary, selected["entry"], left, right)
        seeds[name] = seed
        seed_path = directory / f"{symbol}-{name}-seed.json"
        seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
        trace_path = directory / f"{symbol}-{name}-trace.json"
        matrix.run([client, "ghidra-snapshot", "trace-path", binary,
                    snapshot_path, seed_path, "--max-ops", "8192",
                    "--max-visits", "512", "--output", trace_path])
        trace = matrix.load(trace_path)
        if trace["stop"]["kind"] != "return" or matrix.read_trace_register(trace, 0, 4) != expected:
            raise AssertionError(f"{symbol}/{name}: Rust result differs: {trace['stop']}")
        traces[name] = trace
    llvm = matrix.llvm_cases(artifact, module_path, "float", CASES[width], seeds, traces)
    native = native_cases(directory, width)
    return {"entry": hex(entry), "float_operations": len(floating),
            "cases": len(CASES[width]), "llvm": llvm, "native_compilers": native}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "target/ghidra-float-compare")
    args = parser.parse_args()
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    client = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug" /
                                 ("hydirctl.exe" if sys.platform == "win32" else "hydirctl")))
    if not client.is_file():
        raise RuntimeError(f"build hydirctl first: {client}")
    binary, symbols = build_elf(directory)
    report = {"schema_version": 1, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "functions": {}}
    for width in (32, 64):
        symbol = f"hydir_float_gate{width}"
        report["functions"][symbol] = check_function(
            directory, client, binary, symbols[symbol], width)
        (directory / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Ghidra floating comparison gate passed: {directory / 'report.json'}")


if __name__ == "__main__":
    main()
