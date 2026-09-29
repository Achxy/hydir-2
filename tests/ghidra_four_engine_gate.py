#!/usr/bin/env python3
"""Independent four-engine instruction/state gate for a real x86-64 ELF.

Ghidra EmulatorHelper, Hydir Rust P-code, compiled Hydir LLVM, and the native
CPU execute the same function input. Each collector records RAX and the return
slot after every machine instruction. This bounded fixture proves only these
watched bytes and paths, never whole-function or all-input equivalence.
"""

import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "tests/fixtures/ghidra_add_zero.elf"
SNAPSHOT = ROOT / "tests/fixtures/ghidra_add_zero_v2.json"
ORACLE = ROOT / "integrations/ghidra/HydIROracle.java"
GDB = ROOT / "tests/fixtures/prism_bit_gate_native.gdb"
HYDIRCTL = Path(os.environ.get("HYDIRCTL_BIN", ROOT / "target/debug/hydirctl"))
GHIDRA_HOME = Path(os.environ["HYDIR_GHIDRA_HOME"])
MASK64 = (1 << 64) - 1
VALUES = (0, 0xFEDCBA9876543210)


def run(command, *, env=None, timeout=120):
    result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode != 0:
        raise AssertionError(f"{command[0]} failed ({result.returncode}):\n"
                             f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}")
    return result.stdout


def encoded(value):
    return "h" + value.encode().hex()


def pair(value):
    return (value & MASK64).to_bytes(8, "little")


def bytes_at(state, space, offset):
    mapping = state["register_bytes"] if space == "register" else state["memory_bytes"].get(space, {})
    return [mapping.get(str(offset + byte)) for byte in range(8)]


def watches():
    return ([{"space": "register", "offset": hex(byte)} for byte in range(8)] +
            [{"space": "ram", "offset": hex(0x700000 + byte)} for byte in range(8)])


def step(address, rax, return_slot):
    return {"address": {"space": "ram", "offset": address},
            "bytes": list(rax) + list(return_slot)}


def evidence(engine, digest, seed_digest, steps):
    return {"schema_version": 1, "binary_sha256": digest,
            "seed_sha256": seed_digest, "engine": engine,
            "watches": watches(), "steps": steps,
            "stop_kind": "return", "stop_reason": "selected function returned",
            "complete": True}


def oracle_results(directory, entry, return_address):
    scripts = directory / "scripts"
    scripts.mkdir()
    shutil.copy2(ORACLE, scripts / ORACLE.name)
    projects = directory / "projects"
    projects.mkdir()
    command = [str(GHIDRA_HOME / "support/analyzeHeadless"), str(projects),
               "HydirFourEngineGate", "-import", str(BINARY),
               "-scriptPath", str(scripts)]
    for value in VALUES:
        command += ["-postScript", ORACLE.name,
                    str(directory / f"ghidra-{value:x}.json"), str(BINARY),
                    entry, "8", encoded(f"RDI=0x{value:x};RSP=0x700000"),
                    encoded(f"0x700000:8:0x{return_address:x}"),
                    encoded("RAX"), encoded("0x700000:8")]
    command += ["-deleteProject"]
    run(command, timeout=240)
    return {value: json.loads((directory / f"ghidra-{value:x}.json").read_text())
            for value in VALUES}


def rust_steps(seed_path, addresses):
    full = json.loads(run([str(HYDIRCTL), "ghidra-snapshot", "trace-path",
                           str(BINARY), str(SNAPSHOT), str(seed_path),
                           "--max-ops", "64", "--max-visits", "8"]))
    if full["stop"]["kind"] != "return":
        raise AssertionError(f"Rust did not return: {full['stop']}")
    if [row["offset"] for row in full["instruction_visits"]] != addresses:
        raise AssertionError("Rust instruction path differs from Ghidra")
    counts = {}
    count = 0
    for event in full["events"]:
        if event["kind"] == "effect":
            source = event["operation"]["source"]
        elif event["kind"] == "branch":
            source = event["source"]
        else:
            continue
        count += 1
        counts[source["source_address"]["offset"]] = count
    result = []
    for address in addresses:
        if address == addresses[-1]:
            state = full["final_state"]
        else:
            if address not in counts:
                raise AssertionError(f"Rust has no executed operations for {address}")
            prefix = json.loads(run([str(HYDIRCTL), "ghidra-snapshot", "trace-path",
                                     str(BINARY), str(SNAPSHOT), str(seed_path),
                                     "--max-ops", str(counts[address]), "--max-visits", "8"]))
            if prefix["stop"]["kind"] != "operation_budget":
                raise AssertionError(f"Rust prefix did not stop at budget: {prefix['stop']}")
            state = prefix["final_state"]
        result.append(step(address, bytes_at(state, "register", 0),
                           bytes_at(state, "ram", 0x700000)))
    return result


def llvm_setup(directory, ram_id):
    artifact = json.loads(run([str(HYDIRCTL), "ghidra-snapshot", "llvm-cfg",
                               str(BINARY), str(SNAPSHOT)]))
    module = directory / "lifted.ll"
    module.write_text(artifact["llvm_ir"])
    library = directory / "lifted.so"
    run(["clang", "-shared", "-fPIC", "-x", "ir", str(module), "-o", str(library)])
    loaded = ctypes.CDLL(str(library))
    function = loaded.hydir_pcode_cfg
    u8p = ctypes.POINTER(ctypes.c_uint8)
    function.argtypes = [u8p, u8p, ctypes.c_int32, u8p, u8p,
                         ctypes.c_uint64, ctypes.c_uint64,
                         ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
                         ctypes.c_int32, ctypes.c_int32]
    function.restype = ctypes.c_int32
    byte_map = {(row["space"], int(row["offset"], 16)): row["index"]
                for row in artifact["byte_map"]}
    return loaded, function, artifact, byte_map, ram_id


def llvm_run(setup, seed, limit, return_address):
    _, function, artifact, byte_map, ram_id = setup
    state = (ctypes.c_uint8 * artifact["state_bytes"])()
    known = (ctypes.c_uint8 * artifact["state_bytes"])()
    for item in seed["registers"]:
        offset = int(item["offset"], 16)
        for index, byte in enumerate(int(item["value"], 16).to_bytes(item["size"], "little")):
            mapped = byte_map.get(("register", offset + index))
            if mapped is not None:
                state[mapped], known[mapped] = byte, 255
    guest = (ctypes.c_uint8 * 8)(*pair(return_address))
    guest_known = (ctypes.c_uint8 * 8)(*[255] * 8)
    events = (ctypes.c_uint32 * 64)()
    event_count = ctypes.c_uint32(0)
    status = function(state, known, ram_id, guest, guest_known,
                      0x700000, 8, events, ctypes.byref(event_count), 64, limit)
    rax = [state[byte_map[("register", byte)]]
           if known[byte_map[("register", byte)]] == 255 else None
           for byte in range(8)]
    memory = [guest[index] if guest_known[index] == 255 else None for index in range(8)]
    return status, list(events[:event_count.value]), rax, memory


def llvm_steps(setup, seed, addresses, return_address):
    artifact = setup[2]
    status, events, _, _ = llvm_run(setup, seed, 64, return_address)
    if status != 1:
        raise AssertionError(f"compiled LLVM did not return: {status}")
    sources = artifact["source_operations"]
    visits = []
    counts = {}
    for index, operation_id in enumerate(events):
        address = sources[operation_id]["instruction_address"]["offset"]
        if not visits or visits[-1] != address:
            visits.append(address)
        counts[address] = index + 1
    if visits != addresses:
        raise AssertionError(f"compiled LLVM path differs: {visits} != {addresses}")
    result = []
    for address in addresses:
        limit = counts[address]
        _, prefix_events, rax, memory = llvm_run(setup, seed, limit, return_address)
        if len(prefix_events) != limit:
            raise AssertionError(f"LLVM prefix ended before {address}")
        result.append(step(address, rax, memory))
    return result


def native_steps(value, return_address, addresses):
    env = {**os.environ, "HYDIR_NATIVE_SNAPSHOT": str(SNAPSHOT),
           "HYDIR_NATIVE_RETURN": hex(return_address),
           "HYDIR_NATIVE_RDI": hex(value), "HYDIR_NATIVE_RSI": "0x0",
           "HYDIR_NATIVE_MAX_VISITS": "8"}
    output = run(["gdb", "-nx", "-q", "--batch", "-x", str(GDB), str(BINARY)],
                 env=env, timeout=90)
    rows = [json.loads(line.removeprefix("HYDIR_NATIVE_RESULT="))
            for line in output.splitlines() if line.startswith("HYDIR_NATIVE_RESULT=")]
    if len(rows) != 1 or rows[0]["instruction_visits"] != addresses:
        raise AssertionError("native instruction visits differ from Ghidra")
    return [step(row["address"], pair(row["rax"]), pair(row["return_slot"]))
            for row in rows[0]["step_registers"]]


def main():
    if not HYDIRCTL.is_file() or not GHIDRA_HOME.is_dir():
        raise RuntimeError("build hydirctl and set HYDIR_GHIDRA_HOME")
    snapshot = json.loads(SNAPSHOT.read_text())
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if snapshot["binary_sha256"] != digest:
        raise AssertionError("fixture snapshot belongs to another ELF")
    entry = snapshot["selected_function"]["entry"]["offset"]
    return_address = struct.unpack_from("<Q", BINARY.read_bytes(), 24)[0]
    ram_id = next(row["id"] for row in snapshot["address_spaces"] if row["name"] == "ram")
    with tempfile.TemporaryDirectory(prefix="hydir-four-engine-") as scratch:
        directory = Path(scratch)
        oracles = oracle_results(directory, entry, return_address)
        setup = llvm_setup(directory, ram_id)
        for value in VALUES:
            oracle = oracles[value]
            if oracle["binary_sha256"] != digest or oracle["stop"]["kind"] != "return":
                raise AssertionError("independent Ghidra oracle did not return")
            addresses = [row["address"]["offset"] for row in oracle["steps"]]
            seed = {"schema_version": 1, "binary_sha256": digest,
                    "entry": snapshot["selected_function"]["entry"],
                    "registers": [
                        {"offset": "0x38", "size": 8, "value": hex(value)},
                        {"offset": "0x20", "size": 8, "value": "0x700000"}],
                    "memory": [{"space": "ram", "byte_offset": "0x700000",
                                "size": 8, "value": hex(return_address)}]}
            seed_path = directory / f"seed-{value:x}.json"
            seed_path.write_text(json.dumps(seed))
            seed_digest = hashlib.sha256(seed_path.read_bytes()).hexdigest()
            ghidra_steps = [step(row["address"]["offset"],
                                 pair(int(row["register_values"][0], 16))
                                 if row["register_values"][0] is not None else [None] * 8,
                                 pair(int(row["memory_values"][0], 16))
                                 if row["memory_values"][0] is not None else [None] * 8)
                            for row in oracle["steps"]]
            rows = [
                evidence("ghidra", digest, seed_digest, ghidra_steps),
                evidence("hydir_rust", digest, seed_digest, rust_steps(seed_path, addresses)),
                evidence("compiled_llvm", digest, seed_digest,
                         llvm_steps(setup, seed, addresses, return_address)),
                evidence("native", digest, seed_digest,
                         native_steps(value, return_address, addresses)),
            ]
            paths = []
            for row in rows:
                path = directory / f"{row['engine']}-{value:x}.json"
                path.write_text(json.dumps(row))
                paths.append(str(path))
            comparison = json.loads(run([str(HYDIRCTL), "compare-executions", str(BINARY),
                                         str(seed_path), *paths]))
            if comparison["verdict"] != "matched_observed_contract":
                raise AssertionError(f"four-engine comparison failed: {comparison['first_difference']} "
                                     f"{comparison['inconclusive_reasons']}")
            # Deliberate arithmetic and memory corruption must locate ADD.
            add_address = addresses[1]
            for byte_index, kind in ((0, "state_byte"), (8, "state_byte")):
                fault = json.loads(json.dumps(rows[1]))
                fault["steps"][1]["bytes"][byte_index] ^= 1
                paths[1] = str(directory / f"fault-{byte_index}-{value:x}.json")
                Path(paths[1]).write_text(json.dumps(fault))
                report = json.loads(run([str(HYDIRCTL), "compare-executions", str(BINARY),
                                         str(seed_path), *paths]))
                first = report["first_difference"]
                if (report["verdict"] != "diverged" or first["kind"] != kind
                        or first["address"]["offset"] != add_address):
                    raise AssertionError("comparison did not source-link a deliberate state fault")
            paths[1] = str(directory / f"hydir_rust-{value:x}.json")
            path_fault = json.loads(json.dumps(rows[3]))
            path_fault["steps"][1]["address"]["offset"] = "0x201999"
            paths[3] = str(directory / f"path-fault-{value:x}.json")
            Path(paths[3]).write_text(json.dumps(path_fault))
            report = json.loads(run([str(HYDIRCTL), "compare-executions", str(BINARY),
                                     str(seed_path), *paths]))
            first = report["first_difference"]
            if (report["verdict"] != "diverged" or first["kind"] != "instruction_path"
                    or first["address"]["offset"] != addresses[0]):
                raise AssertionError("comparison did not source-link a deliberate path fault")
            print(f"four engines agree for RDI={value:#x} across {len(addresses)} instructions")


if __name__ == "__main__":
    main()
