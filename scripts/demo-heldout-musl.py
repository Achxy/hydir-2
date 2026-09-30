#!/usr/bin/env python3
"""Run two upstream musl functions through Hydir's Linux launch path.

The sources are unmodified musl 1.2.5 files from commit
0784374d561435f7c787a555aeab8ede699ed298. The two small main programs
only supply fixed inputs and an observable native result. This gate compares
one bounded input per function; it makes no whole-program equivalence claim.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "tests/holdout/musl"
HYDIRCTL = Path(os.environ.get("HYDIRCTL") or shutil.which("hydirctl") or
                ROOT / "target/debug/hydirctl").resolve()
STACK_BASE = 0x6FFE00
STACK_LENGTH = 0x208
STACK_POINTER = 0x700000
RETURN_ADDRESS = 0xDEADBEEF
CASES = (
    {"name": "span", "function": "strspn", "main": "span_main.c",
     "sources": ("strspn.c",), "arguments": ("hydir_span_word", "hydir_span_accept"),
     "native_stdout": "6\n", "expected": 6},
    {"name": "reverse", "function": "strrchr", "main": "reverse_main.c",
     "sources": ("strrchr.c", "memrchr.c"),
     "arguments": ("hydir_reverse_word", 97),
     "native_stdout": "5\n", "expected_offset": 5},
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timed(command, directory, name, timeout=300):
    metrics = directory / f"{name}.metrics"
    result = subprocess.run(
        ["/usr/bin/time", "-f", "%e %M", "-o", str(metrics),
         *[str(value) for value in command]],
        cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False,
    )
    elapsed, rss = metrics.read_text(encoding="utf-8").split()[-2:]
    measure = {"elapsed_ms": round(float(elapsed) * 1000),
               "peak_rss_kib": int(rss)}
    if result.returncode:
        raise RuntimeError(
            f"{name} failed ({result.returncode}): "
            f"{result.stdout[-1500:]} {result.stderr[-3000:]}")
    return result.stdout, measure


def symbols(binary):
    output = subprocess.check_output(["nm", "-n", str(binary)], text=True)
    return {parts[2]: int(parts[0], 16) for line in output.splitlines()
            if len(parts := line.split()) == 3}


def build(case, directory):
    binary = directory / f"{case['name']}.elf"
    command = ["gcc", "-O0", "-g", "-fno-pie", "-no-pie", "-fno-builtin",
               "-fno-stack-protector", "-Wl,--build-id=none", "-include",
               SOURCES / "compat.h", SOURCES / case["main"],
               *(SOURCES / name for name in case["sources"]), "-o", binary]
    _, measure = timed(command, directory, f"{case['name']}-build")
    binary.chmod(0o500)
    return binary, measure


def write_seed(case, binary, snapshot, addresses, directory):
    layout = {row["name"]: row for row in snapshot["register_layout"]}
    registers = []
    for register, argument in zip(("RDI", "RSI"), case["arguments"]):
        value = addresses[argument] if isinstance(argument, str) else argument
        registers.append({"offset": layout[register]["storage"]["offset"],
                          "size": 8, "value": hex(value)})
    registers.append({"offset": layout["RSP"]["storage"]["offset"],
                      "size": 8, "value": hex(STACK_POINTER)})
    # A native caller supplies concrete callee-saved registers. Use a stated
    # synthetic value for bytes that an O0 prologue saves before overwriting.
    for name in ("RBP", "RBX", "R12", "R13", "R14", "R15"):
        if name in layout:
            registers.append({"offset": layout[name]["storage"]["offset"],
                              "size": 8, "value": "0x0"})
    seeded = {(int(row["offset"], 16) + byte)
              for row in registers for byte in range(row["size"])}
    for instruction in snapshot["selected_function"]["instructions"]:
        for operation in instruction["pcode"]:
            inputs = operation["inputs"]
            if (operation["mnemonic"] != "INT_XOR" or len(inputs) != 2
                    or inputs[0] != inputs[1] or inputs[0]["space"] != "register"
                    or inputs[0]["size"] > 16):
                continue
            start = int(inputs[0]["offset"], 16)
            for part in range(0, inputs[0]["size"], 8):
                size = min(8, inputs[0]["size"] - part)
                if any(start + part + byte in seeded for byte in range(size)):
                    continue
                registers.append({"offset": hex(start + part), "size": size,
                                  "value": "0x0"})
                seeded.update(start + part + byte for byte in range(size))
    seed = {"schema_version": 1, "binary_sha256": sha(binary),
            "entry": snapshot["selected_function"]["entry"],
            "registers": registers,
            "memory": [{"space": "ram", "byte_offset": hex(STACK_POINTER),
                        "size": 8, "value": hex(RETURN_ADDRESS)}]}
    path = directory / "seed.json"
    path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
    return path


def source_ids(artifact, trace):
    llvm = artifact["llvm"]
    ids = {(row["instruction_address"]["space"],
            row["instruction_address"]["offset"], row["operation_index"]): index
           for index, row in enumerate(llvm["source_operations"])}
    result = []
    for segment_index, segment in enumerate(trace["segments"]):
        for event in segment["path"]["events"]:
            if event["kind"] == "fallthrough":
                continue
            if event["kind"] == "effect":
                operation = event["operation"]["source"]
            elif event["kind"] == "branch":
                operation = event["source"]
            else:
                raise RuntimeError(f"unknown Rust event {event['kind']}")
            source = operation["source_address"]
            result.append(ids[(source["space"], source["offset"],
                               operation["sequence_index"])])
        if segment_index + 1 < len(trace["segments"]):
            operation = segment["path"]["stop"]["source"]
            source = operation["source_address"]
            result.append(ids[(source["space"], source["offset"],
                               operation["sequence_index"])])
    return result


def llvm_result(artifact, seed, snapshot, directory):
    llvm = artifact["llvm"]
    source = directory / "lifted.ll"
    source.write_text(llvm["llvm_ir"], encoding="utf-8")
    library = directory / "lifted.so"
    _, compile_measure = timed(
        ["clang", "-shared", "-fPIC", "-x", "ir", source, "-o", library],
        directory, "llvm-compile")
    function = ctypes.CDLL(str(library.resolve())).hydir_pcode_cfg
    u8p = ctypes.POINTER(ctypes.c_uint8)
    function.argtypes = [u8p, u8p, ctypes.c_int32, u8p, u8p,
                         ctypes.c_uint64, ctypes.c_uint64, u8p, u8p,
                         ctypes.c_uint64, ctypes.c_uint64,
                         ctypes.POINTER(ctypes.c_uint32),
                         ctypes.POINTER(ctypes.c_uint32), ctypes.c_int32, ctypes.c_int32]
    function.restype = ctypes.c_int32
    byte_map = {(row["space"], int(row["offset"], 16)): row["index"]
                for row in llvm["byte_map"]}
    state = (ctypes.c_uint8 * max(1, llvm["state_bytes"]))()
    known = (ctypes.c_uint8 * max(1, llvm["state_bytes"]))()
    for register in seed["registers"]:
        offset = int(register["offset"], 16)
        value = int(register["value"], 16)
        for index in range(register["size"]):
            mapped = byte_map.get(("register", offset + index))
            if mapped is not None:
                state[mapped] = (value >> (8 * index)) & 0xFF
                known[mapped] = 0xFF
    stack = (ctypes.c_uint8 * STACK_LENGTH)()
    stack_known = (ctypes.c_uint8 * STACK_LENGTH)()
    for memory in seed["memory"]:
        start = int(memory["byte_offset"], 16) - STACK_BASE
        value = int(memory["value"], 16).to_bytes(memory["size"], "little")
        for index, byte in enumerate(value):
            stack[start + index] = byte
            stack_known[start + index] = 0xFF
    heap = (ctypes.c_uint8 * 1)()
    heap_known = (ctypes.c_uint8 * 1)()
    events = (ctypes.c_uint32 * 4096)()
    event_count = ctypes.c_uint32()
    ram_id = next(row["id"] for row in snapshot["address_spaces"]
                  if row["name"] == "ram")
    started = time.perf_counter()
    status = function(state, known, ram_id, stack, stack_known, STACK_BASE,
                      STACK_LENGTH, heap, heap_known, 0, 0, events,
                      ctypes.byref(event_count), 4096, 4096)
    runtime = {"elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
               "process_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}
    rax_offset = int(next(row["storage"]["offset"]
                          for row in snapshot["register_layout"]
                          if row["name"] == "RAX"), 16)
    result = 0
    result_known = True
    for index in range(8):
        mapped = byte_map.get(("register", rax_offset + index))
        if mapped is None or known[mapped] != 0xFF:
            result_known = False
            break
        result |= state[mapped] << (8 * index)
    return {"status": status, "rax": result if result_known else None,
            "events": list(events[:event_count.value]),
            "compile": compile_measure, "runtime": runtime,
            "module_sha256": sha(source)}


def observe(binary, entry, native_stdout, directory):
    observer = Path(os.environ.get("HYDIR_FRIDA_OBSERVER") or
                    HYDIRCTL.parent / "hydir-frida-observer")
    if not observer.is_file():
        raise RuntimeError(f"bundled Frida observer is unavailable: {observer}")
    spec = {"schema_version": 1, "binary_sha256": sha(binary),
            "argv_hex": [], "stdin_hex": "", "files": [], "origins": [],
            "goal": {"exit_code": 0, "stdout_contains_hex": None,
                     "stderr_contains_hex": None},
            "budget": {"timeout_ms": 10000, "memory_bytes": 1073741824,
                       "output_bytes": 4096}}
    spec_path = directory / "observation-input.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n", encoding="utf-8")
    trace_path = directory / "observation.json"
    _, measure = timed([HYDIRCTL, "observe", "frida", binary, spec_path,
                        "--function", hex(entry), "--output", trace_path],
                       directory, "frida-observe", timeout=60)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    if (trace["binary_sha256"] != spec["binary_sha256"]
            or trace["status"] != "completed" or trace["lost_events"]
            or bytes.fromhex(trace["stdout_hex"]).decode() != native_stdout
            or not any(event["kind"] == "entry"
                       and event["source"]["elf_vaddr"] == entry
                       for event in trace["events"])):
        raise RuntimeError("Frida evidence is incomplete or differs from native output")
    linked_blocks = sorted({event["source"]["elf_vaddr"]
                            for event in trace["events"] if event["kind"] == "block"
                            and event["source"]["elf_vaddr"] is not None
                            and event["source"]["original_bytes_hex"]})
    if not linked_blocks:
        raise RuntimeError("Frida found no block with checked ELF source bytes")
    linked_calls = [{"source": event["source"]["elf_vaddr"],
                     "target": (event.get("target") or {}).get("elf_vaddr")}
                    for event in trace["events"] if event["kind"] == "call"
                    and event["source"]["elf_vaddr"] is not None
                    and event["source"]["original_bytes_hex"]]
    unlinked_events = sum((event.get("source") or {}).get("elf_vaddr") is None
                          for event in trace["events"])
    return {"status": trace["status"], "events": len(trace["events"]),
            "lost_events": trace["lost_events"],
            "linked_block_sources": linked_blocks, "linked_calls": linked_calls,
            "unlinked_events": unlinked_events,
            "trace_sha256": sha(trace_path), "metrics": measure}


def run_case(case, directory, full):
    directory.mkdir(parents=True, exist_ok=True)
    result = {"name": case["name"], "upstream_function": case["function"]}
    binary, result["build"] = build(case, directory)
    result["binary_sha256"] = sha(binary)
    addresses = symbols(binary)
    entry = addresses[case["function"]]
    result["entry"] = hex(entry)
    native, result["native"] = timed([binary], directory, "native")
    if native != case["native_stdout"]:
        raise RuntimeError(f"native output differs: {native!r}")
    snapshot_path = directory / "snapshot.json"
    _, result["ghidra"] = timed([HYDIRCTL, "ghidra", "analyze", binary,
                                  "--function", hex(entry), "--output", snapshot_path],
                                 directory, "ghidra-analyze", timeout=600)
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    if (snapshot["binary_sha256"] != result["binary_sha256"]
            or int(snapshot["selected_function"]["entry"]["offset"], 16) != entry):
        raise RuntimeError("Ghidra snapshot has a different binary or entry")
    result["snapshot_sha256"] = sha(snapshot_path)
    result["seed_assumption"] = (
        "callee-saved entry registers and self-XOR source registers are zero "
        "for this bounded input")
    seed_path = write_seed(case, binary, snapshot, addresses, directory)
    allocation_path = directory / "allocations.json"
    allocation_path.write_text(json.dumps({"schema_version": 1, "regions": [
        {"kind": "stack", "space": "ram", "base": STACK_BASE,
         "byte_len": STACK_LENGTH}]}) + "\n", encoding="utf-8")
    trace_path = directory / "rust-trace.json"
    _, result["rust_metrics"] = timed(
        [HYDIRCTL, "ghidra", "trace-calls-imports", binary, seed_path,
         "--function", hex(entry), "--allocations", allocation_path,
         "--max-functions", "8", "--max-ops", "4096", "--max-visits", "1024",
         "--max-depth", "8", "--output", trace_path],
        directory, "rust-trace", timeout=600)
    trace = json.loads(trace_path.read_text(encoding="utf-8"))
    result["rust_stop"] = trace["stop"]
    result["rust_trace_sha256"] = sha(trace_path)
    llvm_path = directory / "llvm-artifact.json"
    _, result["llvm_emit"] = timed(
        [HYDIRCTL, "ghidra", "llvm-cfg-calls-imports", binary, seed_path,
         "--function", hex(entry), "--allocations", allocation_path,
         "--max-functions", "8", "--max-ops", "4096", "--max-visits", "1024",
         "--max-depth", "8", "--output", llvm_path],
        directory, "llvm-emit", timeout=600)
    artifact = json.loads(llvm_path.read_text(encoding="utf-8"))
    result["llvm_artifact_sha256"] = sha(llvm_path)
    result["llvm_stop_sites"] = artifact["llvm"]["stop_sites"]
    llvm = llvm_result(artifact, json.loads(seed_path.read_text()),
                       snapshot, directory)
    result["llvm"] = {key: value for key, value in llvm.items() if key != "events"}
    expected = (case["expected"] if "expected" in case else
                addresses["hydir_reverse_word"] + case["expected_offset"])
    if trace["stop"]["kind"] == "return" and llvm["status"] == 1:
        rust_rax = trace["final_state"]["register_bytes"]
        rust_result = 0
        result_known = True
        for index in range(8):
            value = rust_rax.get(str(index))
            if value is None:
                result_known = False
                break
            rust_result |= value << (8 * index)
        events = source_ids(artifact, trace)
        if not result_known or llvm["rax"] is None:
            result["comparison"] = {
                "verdict": "inconclusive", "reason": "return value bytes are unknown",
                "source": trace["stop"]["source"]["source_address"]}
        elif llvm["events"] != events or rust_result != expected or llvm["rax"] != expected:
            first = next((index for index, (left, right) in
                          enumerate(zip(llvm["events"], events)) if left != right),
                         min(len(llvm["events"]), len(events)))
            source = (artifact["llvm"]["source_operations"][events[first]]["instruction_address"]
                      if first < len(events) else trace["stop"]["source"]["source_address"])
            result["comparison"] = {
                "verdict": "mismatch", "source": source,
                "state_bytes": {"register": "RAX", "rust": rust_result,
                                "llvm": llvm["rax"], "native": expected},
                "first_different_event": first}
        else:
            result["comparison"] = {"verdict": "matched_observed_contract",
                                    "rax": expected, "source_events": len(events),
                                    "return_source": trace["stop"]["source"]["source_address"]}
    else:
        result["comparison"] = {"verdict": "inconclusive",
                                "reason": "Rust or LLVM stopped before the selected function returned",
                                "source": trace["stop"].get("source", {}).get("source_address")}
    if full:
        result["frida"] = observe(binary, entry, native, directory)
        result["observation_alignment"] = {
            "verdict": "inconclusive", "source": hex(entry),
            "reason": "the Frida entry state was not proven identical to the synthetic static seed"}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "target/demo-heldout-musl")
    parser.add_argument("--static-only", action="store_true",
                        help="diagnose the static chain without the Frida bundle")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("the demo requires Linux x86-64")
    if not HYDIRCTL.is_file():
        parser.error(f"build or set HYDIRCTL: {HYDIRCTL}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="run.", dir=args.output_dir))
    report = {"schema_version": 1, "upstream": "musl v1.2.5",
              "upstream_commit": "0784374d561435f7c787a555aeab8ede699ed298",
              "source_sha256": {name: sha(SOURCES / name)
                                for name in ("strspn.c", "strrchr.c", "memrchr.c")},
              "cases": [], "full_observation": not args.static_only}
    for case in CASES:
        try:
            row = run_case(case, directory / case["name"], not args.static_only)
        except Exception as error:
            row = {"name": case["name"], "verdict": "failed",
                   "reason": str(error), "artifact_dir": str(directory / case["name"])}
        report["cases"].append(row)
        (directory / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(directory / "report.json"),
                      "cases": [{"name": row["name"],
                                 "verdict": row.get("verdict", row.get("comparison", {}).get("verdict"))}
                                for row in report["cases"]]}, sort_keys=True))
    if any(row.get("verdict", row.get("comparison", {}).get("verdict")) != "matched_observed_contract"
           for row in report["cases"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
