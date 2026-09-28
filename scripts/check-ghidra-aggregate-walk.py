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
MASK64 = (1 << 64) - 1


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


def native_result(binary, snapshot_path, nodes, scale, return_bits=32):
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return None
    if not shutil.which("gdb"):
        raise RuntimeError("GDB is required for the Linux native aggregate gate")
    env = {**os.environ,
           "HYDIR_NATIVE_SNAPSHOT": str(snapshot_path),
           "HYDIR_NATIVE_NODES": json.dumps(nodes),
           "HYDIR_NATIVE_SCALE": str(scale),
           "HYDIR_NATIVE_RETURN_BITS": str(return_bits)}
    output = matrix.run(["gdb", "-nx", "-q", "--batch", "-x", GDB_SCRIPT, binary],
                        env=env, timeout=90)
    results = [json.loads(line.removeprefix("HYDIR_NATIVE_RESULT="))
               for line in output.splitlines()
               if line.startswith("HYDIR_NATIVE_RESULT=")]
    if len(results) != 1:
        raise AssertionError(f"missing native aggregate result: {output[-2000:]}")
    return results[0]


def check_dwarf_layout(directory, client, binary):
    model_path = directory / f"{binary.stem}-model.json"
    imported_path = directory / f"{binary.stem}-dwarf-model.json"
    matrix.run([client, "model", "init", binary, "--output", model_path])
    matrix.run([client, "model", "import-dwarf", binary, model_path,
                "--output", imported_path])
    matrix.run([client, "model", "verify", binary, imported_path])
    model = matrix.load(imported_path)
    nodes = [row for row in model["types"]
             if row["name"].startswith("Node_") and
             row["kind"]["kind"] == "struct" and
             {field["name"] for field in row["kind"]["fields"]} == {"value", "next"}]
    if len(nodes) != 1 or nodes[0]["size_bytes"] != 16:
        raise AssertionError(f"DWARF Node layout missing in {binary}")
    node = nodes[0]
    fields = {field["name"]: field for field in node["kind"]["fields"]}
    if (fields["value"]["offset_bytes"] != 0 or
            fields["value"]["ty"] != {"kind": "primitive", "name": "i32"} or
            fields["next"]["offset_bytes"] != 8 or
            fields["next"]["ty"] !=
            {"kind": "pointer", "to": {"kind": "named", "id": node["id"]}} or
            any(not field["evidence"] or
                any(evidence["source"] != "dwarf" for evidence in field["evidence"])
                for field in fields.values())):
        raise AssertionError(f"DWARF Node fields are wrong in {binary}")
    return {"size_bytes": 16, "value_offset": 0, "next_offset": 8,
            "recursive_pointer": True}


def check_typed_walk(directory, client, binary):
    model_path = directory / f"{binary.stem}-dwarf-model.json"
    model = matrix.load(model_path)
    nodes = [row for row in model["types"] if row["name"].startswith("Node64_")]
    if len(nodes) != 1 or nodes[0]["size_bytes"] != 16:
        raise AssertionError("DWARF Node64 layout is missing")
    fields = {field["name"]: field for field in nodes[0]["kind"]["fields"]}
    if (set(fields) != {"value", "next"} or
            fields["value"]["offset_bytes"] != 0 or
            fields["value"]["ty"] != {"kind": "primitive", "name": "u64"} or
            fields["next"]["offset_bytes"] != 8 or
            fields["next"]["ty"] !=
            {"kind": "pointer", "to": {"kind": "named", "id": nodes[0]["id"]}}):
        raise AssertionError("DWARF Node64 fields or recursive pointer are wrong")
    node_name = nodes[0]["name"]
    typed_c = matrix.run([client, "decompile", binary, "--function",
                          "hydir_walk_nodes64", "--view", "typed",
                          "--model", model_path])
    if (f"struct {node_name} *" not in typed_c or
            "hydir_walk_nodes64" not in typed_c or
            "hydir_rcx * hydir_rsi" not in typed_c or
            f"hydir_load_u64((hydir_rdi + (uint64_t)offsetof(struct {node_name}, value)))" not in typed_c or
            f"hydir_load_u64((hydir_rdi + (uint64_t)offsetof(struct {node_name}, next)))" not in typed_c):
        raise AssertionError("typed C lost the recursive prototype, fields, or modular product")
    output = directory / f"{binary.stem}-typed.c"
    output.write_text(typed_c, encoding="utf-8")
    wrap = ((1 << 63) + MASK64) * 3 & MASK64
    harness = output.with_name(f"{binary.stem}-typed-harness.c")
    harness.write_text(
        typed_c + f"\nint main(void) {{\n"
        f"  struct {node_name} tail = {{ UINT64_C(3), 0 }};\n"
        f"  struct {node_name} head = {{ UINT64_C(2), &tail }};\n"
        "  if (hydir_walk_nodes64(0, 4) != 0) return 1;\n"
        "  if (hydir_walk_nodes64(&tail, 4) != 12) return 2;\n"
        "  if (hydir_walk_nodes64(&head, 4) != 20) return 3;\n"
        "  tail.value = UINT64_MAX;\n"
        "  head.value = UINT64_C(0x8000000000000000);\n"
        f"  if (hydir_walk_nodes64(&head, 3) != UINT64_C({wrap})) return 4;\n"
        "  return 0;\n}\n", encoding="utf-8")
    compilers = []
    for compiler in ("clang", "gcc"):
        if not shutil.which(compiler):
            continue
        executable = directory / f"{binary.stem}-{compiler}-typed"
        if sys.platform == "win32":
            executable = executable.with_suffix(".exe")
        matrix.run([compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                    harness, "-o", executable])
        matrix.run([executable])
        compilers.append(compiler)
    if "clang" not in compilers or sys.platform == "linux" and "gcc" not in compilers:
        raise AssertionError("strict C11 compiler coverage is incomplete")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    entries = []
    for row in matrix.run([nm, binary]).splitlines():
        match = re.fullmatch(r"\s*([0-9a-fA-F]+)\s+[Tt]\s+hydir_walk_nodes64", row)
        if match:
            entries.append(int(match.group(1), 16))
    if len(entries) != 1:
        raise AssertionError("missing unique hydir_walk_nodes64 symbol")
    snapshot_path = directory / f"{binary.stem}-typed-snapshot.json"
    matrix.run([client, "ghidra", "analyze", binary, "--function", hex(entries[0]),
                "--output", snapshot_path], timeout=180)
    snapshot = matrix.load(snapshot_path)
    if (snapshot["binary_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest() or
            snapshot["selected_function"]["entry"]["offset"] != hex(entries[0])):
        raise AssertionError("typed native snapshot selected the wrong function")
    cases = (
        ("empty", (), 4, 0),
        ("one", (3,), 4, 12),
        ("two", (2, 3), 4, 20),
        ("wrap", (1 << 63, MASK64), 3, wrap),
    )
    llvm_path = directory / f"{binary.stem}-typed-llvm.json"
    matrix.run([client, "ghidra-snapshot", "llvm-cfg-image", binary,
                snapshot_path, "--output", llvm_path])
    artifact = matrix.load(llvm_path)
    if artifact["schema_version"] != 3 or artifact["binary_sha256"] != snapshot["binary_sha256"]:
        raise AssertionError("typed walk LLVM binding failed")
    module_path = llvm_path.with_suffix(".ll")
    module_path.write_text(artifact["llvm_ir"], encoding="utf-8")
    seeds = {}
    traces = {}
    for name, values, scale, expected in cases:
        seed = seed_for(binary, entries[0], values, scale)
        seeds[name] = seed
        seed_path = directory / f"{binary.stem}-typed-{name}-seed.json"
        seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
        trace_path = directory / f"{binary.stem}-typed-{name}-trace.json"
        matrix.run([client, "ghidra-snapshot", "trace-path", binary,
                    snapshot_path, seed_path, "--max-ops", "8192",
                    "--max-visits", "512", "--output", trace_path])
        trace = matrix.load(trace_path)
        if (trace["stop"]["kind"] != "return" or
                matrix.read_trace_register(trace, 0, 8) != expected):
            raise AssertionError(f"typed walk Rust path failed: {name}: {trace['stop']}")
        traces[name] = trace
    llvm = matrix.llvm_cases(artifact, module_path, "walk64", cases, seeds, traces)
    native = {}
    for name, values, scale, expected in cases:
        result = native_result(binary, snapshot_path, values, scale, 64)
        if result is not None:
            if (result["result"] != expected or
                    result["verified_instruction_bytes"] !=
                    len(snapshot["selected_function"]["instructions"])):
                raise AssertionError(f"typed/native mismatch: {name}: {result}")
            native[name] = expected
    return {"model_revision": model["revision"], "node_size_bytes": 16,
            "strict_c11_compilers": compilers, "llvm": llvm,
            "native_results": native}


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
                matrix.read_trace_register(trace, 0, 4) != expected or
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
    result = {"binary_sha256": digest, "entry": hex(entry),
            "instructions": selected["instructions"], "llvm": llvm, "native": native}
    if "dwarf" in label:
        result["dwarf_layout"] = check_dwarf_layout(directory, client, binary)
    return result


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
    variants = build_variants(directory)
    for level, (dwarf, stripped, entry) in variants.items():
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
    report["typed_walk"] = check_typed_walk(directory, client, variants["o2"][0])
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                           encoding="utf-8")
    print(f"Ghidra aggregate walk gate passed: {directory / 'report.json'}")


if __name__ == "__main__":
    main()
