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
            return json.loads(trace_path.read_text(encoding="utf-8")), seed_path

        strlen_trace, strlen_seed_path = contract_trace("strlen", snapshot_path)
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

        llvm_path = directory / "strlen-llvm.json"
        run(CLIENT, "ghidra-snapshot", "llvm-cfg-calls-imports", BINARY,
            snapshot_path, "--allocations", allocation_path,
            "--max-depth", "4", "--output", llvm_path)
        llvm_artifact = json.loads(llvm_path.read_text(encoding="utf-8"))
        if (llvm_artifact["schema_version"] != 3
                or llvm_artifact["llvm"]["schema_version"] != 6
                or [call["name"] for call in llvm_artifact["import_calls"]] != ["strlen"]):
            raise AssertionError("import LLVM artifact lacks the checked call")
        source = directory / "strlen.ll"
        source.write_text(llvm_artifact["llvm"]["llvm_ir"], encoding="utf-8")
        library = directory / "strlen-lifted.so"
        run("clang", "-shared", "-fPIC", source, "-o", library)
        lifted = ctypes.CDLL(str(library.resolve())).hydir_pcode_cfg
        u8p = ctypes.POINTER(ctypes.c_uint8)
        lifted.argtypes = [u8p, u8p, ctypes.c_int32,
                           u8p, u8p, ctypes.c_uint64, ctypes.c_uint64,
                           u8p, u8p, ctypes.c_uint64, ctypes.c_uint64,
                           ctypes.POINTER(ctypes.c_uint32),
                           ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32, ctypes.c_int32]
        lifted.restype = ctypes.c_int32
        llvm = llvm_artifact["llvm"]
        byte_map = {(row["space"], int(row["offset"], 16)): row["index"]
                    for row in llvm["byte_map"]}
        state = (ctypes.c_uint8 * llvm["state_bytes"])()
        known = (ctypes.c_uint8 * llvm["state_bytes"])()
        seed = json.loads(strlen_seed_path.read_text(encoding="utf-8"))
        for register in seed["registers"]:
            start = int(register["offset"], 16)
            value = int(register["value"], 16)
            for byte in range(register["size"]):
                key = ("register", start + byte)
                if key in byte_map:
                    state[byte_map[key]] = (value >> (byte * 8)) & 0xff
                    known[byte_map[key]] = 0xff
        stack_base = 0x6ffff8
        stack = (ctypes.c_uint8 * 16)()
        stack_known = (ctypes.c_uint8 * 16)()
        for region in seed["memory"]:
            start = int(region["byte_offset"], 16) - stack_base
            value = int(region["value"], 16).to_bytes(region["size"], "little")
            if start < 0 or start + len(value) > 16:
                raise AssertionError("seed memory is outside declared stack")
            for index, byte in enumerate(value):
                stack[start + index] = byte
                stack_known[start + index] = 0xff
        heap = (ctypes.c_uint8 * 1)()
        heap_known = (ctypes.c_uint8 * 1)()
        events = (ctypes.c_uint32 * 256)()
        event_count = ctypes.c_uint32()
        status = lifted(state, known, 433, stack, stack_known, stack_base, 16,
                        heap, heap_known, 0, 0, events, ctypes.byref(event_count),
                        256, 256)
        rax = int(layout["RAX"]["storage"]["offset"], 16)
        result = sum(state[byte_map[("register", rax + byte)]] << (byte * 8)
                     for byte in range(8))
        if status != 1 or result != 5:
            raise AssertionError(f"compiled LLVM strlen differs: status={status}, rax={result}")
        sources = {(row["instruction_address"]["space"], row["instruction_address"]["offset"],
                    row["operation_index"]): index
                   for index, row in enumerate(llvm["source_operations"])}
        expected_events = []
        for segment_index, segment in enumerate(strlen_trace["segments"]):
            for event in segment["path"]["events"]:
                operation = event.get("operation", {}).get("source") if event["kind"] == "effect" else event.get("source")
                if operation is None:
                    continue
                key = (operation["source_address"]["space"],
                       operation["source_address"]["offset"],
                       operation["sequence_index"])
                expected_events.append(sources[key])
            if segment_index + 1 < len(strlen_trace["segments"]):
                operation = segment["path"]["stop"]["source"]
                key = (operation["source_address"]["space"],
                       operation["source_address"]["offset"],
                       operation["sequence_index"])
                expected_events.append(sources[key])
        actual_events = list(events[:event_count.value])
        if actual_events != expected_events:
            first = next((index for index, (actual, wanted) in
                          enumerate(zip(actual_events, expected_events))
                          if actual != wanted), min(len(actual_events), len(expected_events)))
            raise AssertionError(f"LLVM/Rust strlen events differ at {first}: "
                                 f"{actual_events[first:first + 3]} != {expected_events[first:first + 3]}")

        memcmp = [item for item in catalog["functions"]
                  if item["name"] == "hydir_import_memcmp"]
        if len(memcmp) != 1:
            raise AssertionError("Ghidra did not discover the unsupported import fixture")
        memcmp_snapshot = directory / "memcmp.json"
        run(CLIENT, "ghidra", "analyze", BINARY, "--function",
            memcmp[0]["entry"]["offset"], "--output", memcmp_snapshot)
        memcmp_trace, _ = contract_trace("memcmp", memcmp_snapshot)
        if (memcmp_trace["stop"]["kind"] != "call_boundary"
                or "no checked SysV call contract" not in memcmp_trace["stop"]["reason"]
                or memcmp_trace.get("contracted_imports")):
            raise AssertionError("unsupported memcmp was silently treated as exact")
        print(json.dumps({"binary_sha256": digest, "imports": sorted(names),
                          "linked_call": linked[0], "strlen_result": 5,
                          "llvm_strlen_status": status,
                          "llvm_strlen_events": len(actual_events),
                          "memcmp_stop": memcmp_trace["stop"]["kind"]}, sort_keys=True))


if __name__ == "__main__":
    main()
