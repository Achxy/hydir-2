#!/usr/bin/env python3
"""Cold desktop import and differential Ghidra lift of a stripped frame parser.

The fixture is independent of the password, PRISM, aggregate, and floating
fixtures. The source-level frame oracle below, Rust P-code path, compiled LLVM
path, and native CPU execution of the exact ELF are checked separately.
"""

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
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/hydir_frame_holdout.c"
GDB_SCRIPT = ROOT / "tests/fixtures/ghidra_frame_holdout_native.gdb"
spec = importlib.util.spec_from_file_location(
    "ghidra_matrix", ROOT / "scripts/check-ghidra-opt-matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
call_spec = importlib.util.spec_from_file_location(
    "ghidra_call_loop", ROOT / "scripts/check-ghidra-call-loop.py")
call_loop = importlib.util.module_from_spec(call_spec)
call_spec.loader.exec_module(call_loop)

MASK32 = (1 << 32) - 1
STEP_BUDGET = 32768
VISIT_BUDGET = 2048


def source_state(payload):
    state = 0xC0DE1234
    for index, byte in enumerate(payload):
        state = (state ^ (byte + 17 * index)) * 0x01000193 & MASK32
        state ^= state >> 13
    return state


def make_frame(payload):
    return bytes((0xA7, len(payload))) + payload + bytes((source_state(payload) & 0xFF,))


def source_accept(frame):
    if len(frame) < 3 or frame[0] != 0xA7:
        return 0
    count = frame[1]
    if count > 12 or len(frame) != count + 3:
        return 0
    return int(source_state(frame[2:2 + count]) & 0xFF == frame[-1])


def cases():
    payload = bytes((0, 0x40, 0xFF, 0x12))
    four = make_frame(payload)
    maximum = make_frame(bytes(range(12)))
    rows = (
        ("short", bytes((0xA7, 0)), 0, 0),
        ("bad-tag", bytes((0xA6, 0, 0x34)), 0, 0),
        ("oversized", bytes((0xA7, 13)) + bytes(range(13)) + b"\0", 0, 0),
        ("wrong-size", bytes((0xA7, 2, 0x11, 0x22)), 0, 0),
        ("empty-valid", make_frame(b""), 1, 0),
        ("one-valid", make_frame(b"\x05"), 1, 1),
        ("four-valid", four, 1, 4),
        ("four-bad-trailer", four[:-1] + bytes((four[-1] ^ 0x80,)), 0, 4),
        ("max-valid", maximum, 1, 12),
    )
    for name, frame, expected, calls in rows:
        if source_accept(frame) != expected:
            raise AssertionError(f"source oracle disagrees on {name}")
        yield name, frame, expected, calls


def build_stripped(directory):
    clang = shutil.which("clang")
    strip = shutil.which("llvm-strip") or shutil.which("strip")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if not all((clang, strip, nm)):
        raise RuntimeError("clang, strip, and llvm-nm/nm are required")
    dwarf = directory / "frame-oracle-dwarf.elf"
    stripped = directory / "frame-holdout-stripped.elf"
    target = (["--target=x86_64-unknown-linux-gnu", "-fuse-ld=lld"]
              if sys.platform == "win32" else [])
    matrix.run([clang, *target, "-O1", "-g", "-fno-stack-protector", "-fno-builtin",
                "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
                "-Wl,-e,_start", SOURCE, "-o", dwarf])
    elf = dwarf.read_bytes()
    if elf[:5] != b"\x7fELF\x02" or struct.unpack_from("<H", elf, 18)[0] != 62:
        raise AssertionError("holdout is not an x86-64 ELF")
    program_offset = struct.unpack_from("<Q", elf, 32)[0]
    program_size, program_count = struct.unpack_from("<HH", elf, 54)
    if any(struct.unpack_from("<I", elf, program_offset + i * program_size)[0] == 3
           for i in range(program_count)):
        raise AssertionError("holdout has a dynamic program interpreter")
    entries = {}
    for row in matrix.run([nm, dwarf]).splitlines():
        match = re.fullmatch(
            r"\s*([0-9a-fA-F]+)\s+[Tt]\s+(hydir_frame_accept|hydir_frame_step)", row)
        if match:
            entries[match.group(2)] = int(match.group(1), 16)
    if set(entries) != {"hydir_frame_accept", "hydir_frame_step"}:
        raise AssertionError(f"missing holdout functions: {entries}")
    shutil.copy2(dwarf, stripped)
    matrix.run([strip, "--strip-all", stripped])
    if b"hydir_frame_accept" in stripped.read_bytes():
        raise AssertionError("holdout ELF still contains source function names")
    return stripped, entries


def seed_for(binary, entry, frame):
    return_address = struct.unpack_from("<Q", binary.read_bytes(), 24)[0]
    registers = [(0x38, 0x700100), (0x30, len(frame)),
                 (0x20, 0x700000), (0x28, 0x700200), (0, 0), (8, 0),
                 (0x18, 0), (0xA0, 0), (0xA8, 0), (0xB0, 0), (0xB8, 0)]
    memory = [(0x700000, 8, return_address)]
    for offset in range(0, len(frame), 8):
        chunk = frame[offset:offset + 8]
        memory.append((0x700100 + offset, len(chunk),
                       int.from_bytes(chunk, "little")))
    return {
        "schema_version": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "entry": {"space": "ram", "offset": hex(entry)},
        "registers": [{"offset": hex(offset), "size": 8, "value": hex(value)}
                      for offset, value in registers],
        "memory": [{"space": "ram", "byte_offset": hex(address),
                    "size": size, "value": hex(value)}
                   for address, size, value in memory],
    }


def native_result(binary, root_snapshot, step_snapshot, frame):
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return None
    if not shutil.which("gdb"):
        raise RuntimeError("GDB is required for native holdout execution")
    env = {**os.environ, "HYDIR_NATIVE_SNAPSHOT": str(root_snapshot),
           "HYDIR_NATIVE_CALLEE_SNAPSHOT": str(step_snapshot),
           "HYDIR_NATIVE_FRAME_HEX": frame.hex()}
    output = matrix.run(["gdb", "-nx", "-q", "--batch", "-x", GDB_SCRIPT, binary],
                        env=env, timeout=90)
    rows = [json.loads(line.removeprefix("HYDIR_NATIVE_RESULT="))
            for line in output.splitlines()
            if line.startswith("HYDIR_NATIVE_RESULT=")]
    if len(rows) != 1:
        raise AssertionError(f"missing native result: {output[-2000:]}")
    return rows[0]


def desktop_probe(directory, binary, entry):
    gui = Path(os.environ.get("HYDIR_GUI_BIN", ROOT / "target/debug" /
                          ("hydir.exe" if sys.platform == "win32" else "hydir")))
    if not gui.is_file():
        raise RuntimeError(f"build the Hydir desktop for the one-action gate: {gui}")
    with tempfile.TemporaryDirectory(prefix="hydir-frame-gui-", dir=directory) as scratch:
        env = {**os.environ, "HYDIR_LOCAL_DB": str(Path(scratch) / "workbench.sqlite")}
        output = matrix.run([gui, "--probe-ghidra-demo", binary, hex(entry)],
                            env=env, timeout=600)
    match = re.search(
        r"(\d+) Ghidra functions, selected 0x[0-9a-f]+, (\d+) P-code rows, "
        r"(\d+) state rows, (\d+) CFG LLVM source operations, "
        r"(\d+) slice steps, (\d+) disassembly instructions", output)
    if not match or min(map(int, match.groups())) <= 0:
        raise AssertionError(f"desktop did not populate all linked views: {output}")
    return {"functions": int(match[1]), "pcode_rows": int(match[2]),
            "state_rows": int(match[3]), "llvm_source_operations": int(match[4]),
            "slice_steps": int(match[5]), "disassembly_instructions": int(match[6])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "target/ghidra-frame-holdout")
    args = parser.parse_args()
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    client = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug" /
                                 ("hydirctl.exe" if sys.platform == "win32" else "hydirctl")))
    if not client.is_file():
        raise RuntimeError(f"build hydirctl first: {client}")
    binary, entries = build_stripped(directory)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    snapshots = {}
    for name, entry in entries.items():
        path = directory / f"{name}-snapshot.json"
        matrix.run([client, "ghidra", "analyze", binary,
                    "--function", hex(entry), "--output", path], timeout=180)
        snapshot = matrix.load(path)
        if (snapshot["binary_sha256"] != digest or
                snapshot["selected_function"]["entry"]["offset"] != hex(entry) or
                not snapshot["selected_function"]["instructions"]):
            raise AssertionError(f"Ghidra did not bind {name} to the stripped ELF")
        snapshots[name] = (path, snapshot)
    root_path, root = snapshots["hydir_frame_accept"]
    step_path, step = snapshots["hydir_frame_step"]
    indexed = {row["entry"]["offset"] for row in root["functions"]}
    if not {hex(entry) for entry in entries.values()} <= indexed or len(indexed) < 3:
        raise AssertionError("automatic Ghidra function index missed the parser or callee")
    mnemonics = {op["mnemonic"] for row in root["selected_function"]["instructions"]
                 for op in row["pcode"]}
    if not {"LOAD", "CALL", "CBRANCH", "RETURN"} <= mnemonics:
        raise AssertionError(f"fixture lost its memory, call, or control flow: {mnemonics}")
    artifact_path = directory / "frame-calls-llvm.json"
    matrix.run([client, "ghidra-snapshot", "llvm-cfg-calls", binary,
                root_path, "--callee", step_path, "--max-depth", "8",
                "--output", artifact_path])
    artifact = matrix.load(artifact_path)
    if (artifact["schema_version"] != 1 or artifact["binary_sha256"] != digest or
            artifact["semantic_fidelity"] != "unknown" or
            artifact["llvm"]["semantic_fidelity"] != "unknown" or
            artifact["snapshot_diagnostics"] or
            {row["offset"] for row in artifact["function_entries"]} !=
            {hex(entry) for entry in entries.values()}):
        raise AssertionError("LLVM module lost digest, call graph, or honest fidelity")
    module_path = directory / "frame-calls.ll"
    module_path.write_text(artifact["llvm"]["llvm_ir"], encoding="utf-8")
    verifier = shutil.which("opt")
    if verifier:
        matrix.run([verifier, "-passes=verify", "-disable-output", module_path])
    results = {}
    for name, frame, expected, expected_calls in cases():
        seed = seed_for(binary, entries["hydir_frame_accept"], frame)
        seed_path = directory / f"{name}-seed.json"
        seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
        trace_path = directory / f"{name}-trace.json"
        matrix.run([client, "ghidra-snapshot", "trace-calls", binary,
                    root_path, seed_path, "--callee", step_path,
                    "--max-ops", str(STEP_BUDGET),
                    "--max-visits", str(VISIT_BUDGET), "--max-depth", "8",
                    "--output", trace_path])
        trace = matrix.load(trace_path)
        if (trace["binary_sha256"] != digest or
                trace["stop"]["kind"] != "return" or
                matrix.read_trace_register(trace, 0, 4) != expected or
                len(trace["calls"]) != expected_calls or
                trace["snapshot_diagnostics"]):
            raise AssertionError(f"Rust failed exact holdout path {name}: {trace['stop']}")
        llvm = call_loop.llvm_result(artifact, module_path, seed, trace, expected)
        native = native_result(binary, root_path, step_path, frame)
        if native is not None and (
                native["result"] != expected or
                native["verified_instructions"] !=
                sum(len(snapshot["selected_function"]["instructions"])
                    for _, snapshot in snapshots.values())):
            raise AssertionError(f"native ELF differs on {name}: {native}")
        results[name] = {"expected": expected, "calls": expected_calls,
                         "rust_stop": "return", "llvm_status": llvm["status"],
                         "llvm_events": llvm["events"],
                         "native": "matched_output_and_code_bytes" if native else "unavailable"}
        print(f"{name}: Rust return={expected}, LLVM events={llvm['events']}, "
              f"native={results[name]['native']}", flush=True)
    auto_seed = directory / "four-valid-seed.json"
    automatic_path = directory / "automatic-four-valid-trace.json"
    matrix.run([client, "ghidra", "trace-calls", binary, auto_seed,
                "--function", hex(entries["hydir_frame_accept"]),
                "--max-functions", "2", "--max-ops", str(STEP_BUDGET),
                "--max-visits", str(VISIT_BUDGET), "--max-depth", "8",
                "--output", automatic_path], timeout=180)
    automatic = matrix.load(automatic_path)
    if (automatic["stop"]["kind"] != "return" or
            matrix.read_trace_register(automatic, 0, 4) != 1 or
            len(automatic["calls"]) != 4 or automatic["snapshot_diagnostics"]):
        raise AssertionError("automatic reached-callee collection failed")
    desktop = desktop_probe(directory, binary, entries["hydir_frame_accept"])
    report = {
        "schema_version": 1,
        "source_oracle": SOURCE.relative_to(ROOT).as_posix(),
        "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        "binary_sha256": digest,
        "binary": str(binary),
        "stripped": True,
        "function_entries": {name: hex(entry) for name, entry in entries.items()},
        "desktop": desktop,
        "cases": results,
        "automatic_callee_collection": "four calls, return 1, no diagnostics",
        "bounded_path_fidelity": "exact_for_listed_inputs_only",
        "whole_function_fidelity": artifact["semantic_fidelity"],
        "whole_function_verification": artifact["verification"],
        "llvm_syntax_verifier": "opt -passes=verify" if verifier else "unavailable",
        "limitations": ["Paths and inputs outside this fixture are unverified",
                        "Native CPU comparison runs only on Linux x86-64"],
    }
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                           encoding="utf-8")
    print(f"Stripped frame holdout passed: {directory / 'report.json'}")


if __name__ == "__main__":
    main()
