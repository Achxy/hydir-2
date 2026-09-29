#!/usr/bin/env python3
"""Exercise a real recursive ELF through Ghidra, Rust P-code, LLVM, and Linux."""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/ghidra_recursive_calls.S"
CLIENT = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug/hydirctl"))
STACK_BASE = 0x700100
STACK_SIZE = 0x108
ENTRY_RSP = STACK_BASE + 0x100
MAX_OPS = 512


def run(*args, timeout=180):
    result = subprocess.run([str(arg) for arg in args], cwd=ROOT,
                            capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise AssertionError(f"{args[0]} failed ({result.returncode}):\n"
                             f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    return result.stdout


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def register_value(state, offset, width=8):
    values = state["register_bytes"]
    return int.from_bytes(bytes(values[str(offset + index)]
                                for index in range(width)), "little")


def source_event_ids(trace, llvm):
    lookup = {(row["address"]["space"], row["address"]["offset"],
               row["operation_index"]): index
              for index, row in enumerate(llvm["source_operations"])}
    ids = []
    for segment_index, segment in enumerate(trace["segments"]):
        path = segment["path"]
        for event in path["events"]:
            if event["kind"] == "fallthrough":
                continue
            source = event["operation"]["source"] if event["kind"] == "effect" else event["source"]
            ids.append(lookup[(source["source_address"]["space"],
                               source["source_address"]["offset"],
                               source["sequence_index"])])
        if segment_index + 1 < len(trace["segments"]):
            source = path["stop"]["source"]
            ids.append(lookup[(source["source_address"]["space"],
                               source["source_address"]["offset"],
                               source["sequence_index"])])
    return ids


def llvm_run(artifact, module, seed, expected_events, space_id):
    library = module.with_suffix(".so")
    if not library.is_file():
        run("clang", "-shared", "-fPIC", "-x", "ir", module, "-o", library)
    loaded = ctypes.CDLL(str(library))
    lifted = loaded.hydir_pcode_cfg
    byte_pointer = ctypes.POINTER(ctypes.c_uint8)
    lifted.argtypes = [byte_pointer, byte_pointer, ctypes.c_int32,
                       byte_pointer, byte_pointer, ctypes.c_uint64, ctypes.c_uint64,
                       byte_pointer, byte_pointer, ctypes.c_uint64, ctypes.c_uint64,
                       ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
                       ctypes.c_int32, ctypes.c_int32]
    lifted.restype = ctypes.c_int32
    llvm = artifact["llvm"]
    byte_map = {(row["space"], int(row["offset"], 16)): row["index"]
                for row in llvm["byte_map"]}
    state = (ctypes.c_uint8 * llvm["state_bytes"])()
    known = (ctypes.c_uint8 * llvm["state_bytes"])()
    for item in seed["registers"]:
        offset = int(item["offset"], 16)
        for byte_index, byte in enumerate(int(item["value"], 16).to_bytes(item["size"], "little")):
            index = byte_map.get(("register", offset + byte_index))
            if index is not None:
                state[index], known[index] = byte, 255
    stack = (ctypes.c_uint8 * STACK_SIZE)()
    stack_known = (ctypes.c_uint8 * STACK_SIZE)()
    for item in seed["memory"]:
        start = int(item["byte_offset"], 16) - STACK_BASE
        assert 0 <= start and start + item["size"] <= STACK_SIZE
        for index, byte in enumerate(int(item["value"], 16).to_bytes(item["size"], "little")):
            stack[start + index], stack_known[start + index] = byte, 255
    heap = (ctypes.c_uint8 * 1)()
    heap_known = (ctypes.c_uint8 * 1)()
    events = (ctypes.c_uint32 * MAX_OPS)()
    event_count = ctypes.c_uint32(0)
    status = lifted(state, known, space_id, stack, stack_known,
                    STACK_BASE, STACK_SIZE, heap, heap_known, 0, 0,
                    events, ctypes.byref(event_count), MAX_OPS, MAX_OPS)
    actual_events = list(events[:event_count.value])
    if status != 1 or actual_events != expected_events:
        first = next((index for index, (got, want) in
                      enumerate(zip(actual_events, expected_events)) if got != want),
                     min(len(actual_events), len(expected_events)))
        raise AssertionError(f"compiled LLVM differs at event {first}: "
                             f"status={status}, events={len(actual_events)}/"
                             f"{len(expected_events)}")
    def result_register(offset):
        indexes = [byte_map[("register", offset + index)] for index in range(8)]
        if any(known[index] != 255 for index in indexes):
            raise AssertionError(f"compiled LLVM returned unknown register {offset:#x}")
        return int.from_bytes(bytes(state[index] for index in indexes), "little")
    memory = {STACK_BASE + index: stack[index]
              for index in range(STACK_SIZE) if stack_known[index] == 255}
    return result_register(0), result_register(0x20), event_count.value, memory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not CLIENT.is_file():
        raise RuntimeError(f"build hydirctl first: {CLIENT}")
    with tempfile.TemporaryDirectory(prefix="hydir-recursion-") as scratch:
        directory = args.output_dir or Path(scratch)
        directory.mkdir(parents=True, exist_ok=True)
        binary = directory / "recursive.elf"
        run("clang", "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
            "-Wl,-e,_start", SOURCE, "-o", binary)
        symbols = run("nm", binary)
        match = re.search(r"^([0-9a-fA-F]+)\s+T\s+hydir_recursive_sum$", symbols, re.M)
        if match is None:
            raise AssertionError("recursive function symbol missing")
        entry = int(match.group(1), 16)
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        return_address = struct.unpack_from("<Q", binary.read_bytes(), 24)[0]
        snapshot_path = directory / "snapshot.json"
        run(CLIENT, "ghidra", "analyze", binary, "--function", hex(entry),
            "--output", snapshot_path, timeout=240)
        snapshot = read_json(snapshot_path)
        if snapshot["binary_sha256"] != digest or len(snapshot["selected_function"]["instructions"]) < 8:
            raise AssertionError("Ghidra recursion snapshot is incomplete")
        allocations_path = directory / "allocations.json"
        allocations_path.write_text(json.dumps({"schema_version": 1, "regions": [
            {"kind": "stack", "space": "ram", "base": STACK_BASE,
             "byte_len": STACK_SIZE}]}), encoding="utf-8")
        llvm_path = directory / "llvm.json"
        run(CLIENT, "ghidra-snapshot", "llvm-cfg-calls", binary, snapshot_path,
            "--allocations", allocations_path, "--max-depth", "8",
            "--output", llvm_path)
        artifact = read_json(llvm_path)
        if artifact["binary_sha256"] != digest or len(artifact["function_entries"]) != 1:
            raise AssertionError("interprocedural LLVM selected the wrong functions")
        module = directory / "recursive.ll"
        module.write_text(artifact["llvm"]["llvm_ir"], encoding="utf-8")
        results = {}
        for value in (0, 3):
            seed = {"schema_version": 1, "binary_sha256": digest,
                    "entry": snapshot["selected_function"]["entry"],
                    "registers": [
                        {"offset": "0x38", "size": 8, "value": hex(value)},
                        {"offset": "0x20", "size": 8, "value": hex(ENTRY_RSP)}],
                    "memory": [{"space": "ram", "byte_offset": hex(ENTRY_RSP),
                                "size": 8, "value": hex(return_address)}]}
            seed_path = directory / f"seed-{value}.json"
            seed_path.write_text(json.dumps(seed), encoding="utf-8")
            trace_path = directory / f"trace-{value}.json"
            run(CLIENT, "ghidra-snapshot", "trace-calls", binary, snapshot_path,
                seed_path, "--allocations", allocations_path, "--max-ops", str(MAX_OPS),
                "--max-visits", "128", "--max-depth", "8", "--output", trace_path)
            trace = read_json(trace_path)
            expected = value * (value + 1) // 2
            if (trace["stop"]["kind"] != "return" or
                    register_value(trace["final_state"], 0) != expected or
                    register_value(trace["final_state"], 0x20) != ENTRY_RSP + 8 or
                    len(trace["calls"]) != value):
                raise AssertionError(f"Rust recursion failed for {value}: {trace['stop']}")
            space_id = next(row["id"] for row in snapshot["address_spaces"]
                            if row["name"] == "ram")
            actual, rsp, event_count, memory = llvm_run(
                artifact, module, seed, source_event_ids(trace, artifact["llvm"]), space_id)
            if actual != expected or rsp != ENTRY_RSP + 8:
                raise AssertionError(f"LLVM recursion returned {actual}, RSP={rsp:#x}")
            rust_memory = trace["final_state"]["memory_bytes"].get("ram", {})
            for address, byte in rust_memory.items():
                address = int(address)
                if STACK_BASE <= address < STACK_BASE + STACK_SIZE and memory.get(address) != byte:
                    raise AssertionError(f"LLVM stack differs from Rust at {address:#x}")
            results[str(value)] = {"result": actual, "calls": len(trace["calls"]),
                                   "llvm_events": event_count}
        native = subprocess.run([str(binary)], cwd=ROOT, capture_output=True, timeout=10)
        if native.returncode != 6:
            raise AssertionError(f"native recursion returned exit code {native.returncode}")
        report = {"schema_version": 1, "binary_sha256": digest, "cases": results,
                  "native_exit_code": native.returncode}
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                               encoding="utf-8")
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
