#!/usr/bin/env python3
"""Differential gate for a real ELF loop with repeated direct calls.

Uses the four binaries built by check-ghidra-opt-matrix.py. Ghidra exports
both functions afresh, Rust follows each concrete call path, compiled LLVM
replays the exact source P-code event sequence, and Linux GDB runs the ELF.
"""

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ghidra_matrix", ROOT / "scripts/check-ghidra-opt-matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)

CASES = (
    ("empty", b""),
    ("one-letter", b"A"),
    ("phrase", b"HYDIR-ACCESS"),
)
RAM_BASE = 0x6fff00
RAM_SIZE = 0x300
STEP_BUDGET = 32768
VISIT_BUDGET = 2048


def source_score(candidate):
    lane = 0x48445949522d4445
    score = 0
    for index, ch in enumerate(candidate):
        value = lane ^ ch
        value ^= (index + 0x31 + 0x9e3779b97f4a7c15) & matrix.MASK64
        value = ((value << 13) | (value >> 51)) & matrix.MASK64
        value = value * 0xbf58476d1ce4e5b9 & matrix.MASK64
        lane = value ^ (value >> 29)
        if ord("A") <= ch <= ord("Z"):
            score += 7
        elif ord("0") <= ch <= ord("9"):
            score += 5
        elif ch in (ord("-"), ord("_")):
            score += 9
        else:
            score += 2
    return score + (lane & 15)


def symbols_for(binary):
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if not nm:
        raise RuntimeError("llvm-nm or nm is required")
    symbols = {}
    for row in matrix.run([nm, binary]).splitlines():
        match = re.fullmatch(r"\s*([0-9a-fA-F]+)\s+[Tt]\s+(hydir_password_score|hydir_mix64)", row)
        if match:
            symbols[match.group(2)] = int(match.group(1), 16)
    if set(symbols) != {"hydir_password_score", "hydir_mix64"}:
        raise AssertionError(f"missing loop or callee in {binary}: {symbols}")
    return symbols


def seed_for(binary, entry, candidate):
    seed = matrix.seed_for(binary, {"space": "ram", "offset": hex(entry)},
                           "score", ("seed", candidate, len(candidate), 0))
    # Ghidra ia.sinc maps RBX to 0x18 and R12..R15 to 0xa0..0xb8.
    # The optimized prologue saves their incoming values before using them.
    for offset in (0x18, 0xa0, 0xa8, 0xb0, 0xb8):
        seed["registers"].append({"offset": hex(offset), "size": 8,
                                  "value": "0x0"})
    return seed


def trace_events(trace, artifact):
    source_ids = {(row["instruction_address"]["space"],
                   row["instruction_address"]["offset"], row["operation_index"]): index
                  for index, row in enumerate(artifact["source_operations"])}
    result = []
    for segment_index, segment in enumerate(trace["segments"]):
        for event in segment["path"]["events"]:
            if event["kind"] == "fallthrough":
                continue
            if event["kind"] == "effect":
                source = event["operation"]["source"]
            elif event["kind"] == "branch":
                source = event["source"]
            else:
                raise AssertionError(f"unexpected Rust event: {event['kind']}")
            key = (source["source_address"]["space"],
                   source["source_address"]["offset"], source["sequence_index"])
            result.append(source_ids[key])
        # The segmented Rust trace records CALL and nested RETURN as path
        # stops, while the unified LLVM module logs their source operations.
        # The final root RETURN is a status and is not logged by LLVM.
        if segment_index + 1 < len(trace["segments"]):
            source = segment["path"]["stop"]["source"]
            key = (source["source_address"]["space"],
                   source["source_address"]["offset"], source["sequence_index"])
            result.append(source_ids[key])
    return result


def llvm_result(artifact, module_path, seed, trace, expected):
    llvm = artifact["llvm"]
    library = module_path.with_suffix(".dll" if sys.platform == "win32" else ".so")
    flags = ["-Wl,/export:hydir_pcode_cfg"] if sys.platform == "win32" else ["-fPIC"]
    matrix.run(["clang", "-shared", *flags, module_path, "-o", library])
    loaded = ctypes.CDLL(str(library.resolve()))
    lifted = loaded.hydir_pcode_cfg
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lifted.argtypes = [u8p, u8p, ctypes.c_int32, u8p, u8p,
                       ctypes.c_uint64, ctypes.c_uint64,
                       ctypes.POINTER(ctypes.c_uint32),
                       ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32,
                       ctypes.c_int32]
    lifted.restype = ctypes.c_int32
    byte_map = {(row["space"], int(row["offset"], 16)): row["index"]
                for row in llvm["byte_map"]}
    state = (ctypes.c_uint8 * llvm["state_bytes"])()
    known = (ctypes.c_uint8 * llvm["state_bytes"])()
    for row in seed["registers"]:
        matrix.seed_llvm_register(byte_map, state, known,
                                  int(row["offset"], 16), int(row["value"], 16))
    guest = (ctypes.c_uint8 * RAM_SIZE)()
    guest_known = (ctypes.c_uint8 * RAM_SIZE)()
    for row in seed["memory"]:
        start = int(row["byte_offset"], 16) - RAM_BASE
        if start < 0 or start + row["size"] > RAM_SIZE:
            raise AssertionError("seed is outside the guest RAM window")
        value = int(row["value"], 16).to_bytes(row["size"], "little")
        for index, byte in enumerate(value):
            guest[start + index] = byte
            guest_known[start + index] = 0xff
    events = (ctypes.c_uint32 * STEP_BUDGET)()
    event_count = ctypes.c_uint32(0)
    try:
        status = lifted(state, known, 433, guest, guest_known, RAM_BASE, RAM_SIZE,
                        events, ctypes.byref(event_count), STEP_BUDGET, STEP_BUDGET)
        expected_events = trace_events(trace, llvm)
        actual_events = list(events[:event_count.value])
        if status != 1 or actual_events != expected_events:
            first = next((index for index, (actual, wanted) in
                          enumerate(zip(actual_events, expected_events))
                          if actual != wanted), min(len(actual_events), len(expected_events)))
            raise AssertionError(
                f"LLVM/Rust call path differs: status={status}, "
                f"LLVM events={len(actual_events)}, Rust events={len(expected_events)}, "
                f"first mismatch={first}, LLVM={actual_events[first:first + 3]}, "
                f"Rust={expected_events[first:first + 3]}"
            )
        value = matrix.read_llvm_register(byte_map, state, known, 0, 8)
        if value != expected:
            raise AssertionError(f"LLVM returned {value}, expected {expected}")
        return {"status": status, "result": value, "events": event_count.value}
    finally:
        if sys.platform == "win32":
            del lifted
            free_library = ctypes.windll.kernel32.FreeLibrary
            free_library.argtypes = [ctypes.c_void_p]
            free_library.restype = ctypes.c_int
            if not free_library(loaded._handle):
                raise RuntimeError("FreeLibrary failed for call-loop module")
            loaded._handle = 0


def check_variant(directory, client, level, debug):
    label = f"{level}-{debug}"
    binary = directory / f"password-{label}.elf"
    if not binary.is_file():
        raise RuntimeError(f"build the optimization matrix first: {binary}")
    symbol_binary = (directory / f"password-{level}-dwarf.elf"
                     if debug == "stripped" else binary)
    symbols = symbols_for(symbol_binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    snapshots = {}
    for name, entry in symbols.items():
        path = directory / f"{label}-{name}-snapshot.json"
        matrix.run([client, "ghidra", "analyze", binary, "--function", hex(entry),
                    "--output", path], timeout=180)
        snapshot = matrix.load(path)
        if (snapshot["binary_sha256"] != digest or
                snapshot["selected_function"]["entry"]["offset"] != hex(entry)):
            raise AssertionError(f"bad snapshot binding: {label}/{name}")
        snapshots[name] = (path, snapshot)
    root_path, root = snapshots["hydir_password_score"]
    callee_path, callee = snapshots["hydir_mix64"]
    artifact_path = directory / f"{label}-score-calls-llvm.json"
    matrix.run([client, "ghidra-snapshot", "llvm-cfg-calls", binary, root_path,
                "--callee", callee_path, "--max-depth", "8", "--output", artifact_path])
    artifact = matrix.load(artifact_path)
    if (artifact["binary_sha256"] != digest or artifact["schema_version"] != 1 or
            {x["offset"] for x in artifact["function_entries"]} !=
            {hex(symbols["hydir_password_score"]), hex(symbols["hydir_mix64"])}):
        raise AssertionError(f"bad interprocedural LLVM binding: {label}")
    module_path = directory / f"{label}-score-calls.ll"
    module_path.write_text(artifact["llvm"]["llvm_ir"], encoding="utf-8")
    results = {}
    for name, candidate in CASES:
        expected = source_score(candidate)
        seed = seed_for(binary, symbols["hydir_password_score"], candidate)
        seed_path = directory / f"{label}-score-{name}-seed.json"
        seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
        trace_path = directory / f"{label}-score-{name}-trace.json"
        matrix.run([client, "ghidra-snapshot", "trace-calls", binary, root_path,
                    seed_path, "--callee", callee_path, "--max-ops", str(STEP_BUDGET),
                    "--max-visits", str(VISIT_BUDGET), "--max-depth", "8",
                    "--output", trace_path])
        trace = matrix.load(trace_path)
        if (trace["binary_sha256"] != digest or trace["stop"]["kind"] != "return" or
                matrix.read_trace_register(trace, 0, 8) != expected or
                len(trace["calls"]) != len(candidate)):
            raise AssertionError(f"wrong Rust loop/call path: {label}/{name}: {trace['stop']}")
        native_case = (name, candidate, len(candidate), expected)
        native = matrix.native_result(binary, root_path, "score", native_case,
                                      callee_snapshot=callee_path)
        if native is not None and (
                native["result"] != expected or
                native["verified_instruction_bytes"] !=
                sum(len(row["selected_function"]["instructions"])
                    for _, row in snapshots.values())):
            raise AssertionError(f"native loop/call mismatch: {label}/{name}: {native}")
        llvm = llvm_result(artifact, module_path, seed, trace, expected)
        results[name] = {"result": expected, "calls": len(trace["calls"]),
                         "rust_operations": trace["executed_operations"],
                         "llvm_events": llvm["events"],
                         "native": "matched_output_and_code_bytes" if native else "unavailable"}
    if level == "o2" and debug == "dwarf":
        # Exercise the user-facing automatic path, including demand-driven
        # callee collection, using the same full phrase seed.
        seed_path = directory / f"{label}-score-phrase-seed.json"
        auto_path = directory / f"{label}-score-automatic-trace.json"
        matrix.run([client, "ghidra", "trace-calls", binary, seed_path,
                    "--function", hex(symbols["hydir_password_score"]),
                    "--max-functions", "2", "--max-ops", str(STEP_BUDGET),
                    "--max-visits", str(VISIT_BUDGET), "--max-depth", "8",
                    "--output", auto_path], timeout=180)
        automatic = matrix.load(auto_path)
        if (automatic["stop"]["kind"] != "return" or
                matrix.read_trace_register(automatic, 0, 8) !=
                results["phrase"]["result"] or len(automatic["calls"]) != 12 or
                automatic["snapshot_diagnostics"]):
            raise AssertionError("automatic Ghidra call collection regressed")
    print(f"{label}/score: " + ", ".join(
        f"{name}={result['result']}/{result['calls']}calls"
        for name, result in results.items()), flush=True)
    return {"binary_sha256": digest, "function_entries": symbols,
            "instruction_counts": {name: len(row["selected_function"]["instructions"])
                                   for name, (_, row) in snapshots.items()},
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--matrix-dir", type=Path,
                        default=ROOT / "target/ghidra-opt-matrix")
    args = parser.parse_args()
    directory = args.matrix_dir.resolve()
    client = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug" /
                                 ("hydirctl.exe" if sys.platform == "win32" else "hydirctl")))
    if not client.is_file():
        raise RuntimeError(f"build hydirctl first: {client}")
    report = {"schema_version": 1, "variants": {}}
    for level in ("o0", "o2"):
        for debug in ("dwarf", "stripped"):
            label = f"{level}-{debug}"
            report["variants"][label] = check_variant(directory, client, level, debug)
            (directory / "call-loop-report.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Ghidra call-loop gate passed: {directory / 'call-loop-report.json'}")


if __name__ == "__main__":
    main()
