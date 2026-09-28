#!/usr/bin/env python3
"""Fresh Ghidra lifts of one ELF at O0/O2, with and without DWARF.

The scalar add function must execute exactly in Rust, LLVM, and (on Linux)
the CPU. The password comparison is also checked where the current P-code
subset can execute it. Unsupported optimized SIMD effects stay explicit.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tests/fixtures/hydir_password_demo.c"
GDB_SCRIPT = ROOT / "tests/fixtures/ghidra_matrix_native.gdb"
MASK64 = (1 << 64) - 1
CASES = {
    "add2": (("small", 7, 11, 18), ("wrap", MASK64, 2, 1)),
    "equals": (
        ("match", b"HYDIR-ACCESS", 12, 1),
        ("mismatch", b"hYDIR-ACCESS", 12, 0),
        ("wrong-length", b"HYDIR-ACCESS", 11, 0),
    ),
}


def run(command, *, env=None, timeout=120):
    result = subprocess.run(
        [str(arg) for arg in command], cwd=ROOT, env=env,
        capture_output=True, text=True, timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(
            f"{' '.join(map(str, command))} failed ({result.returncode}):\n"
            f"{result.stdout[-3000:]}\n{result.stderr[-3000:]}"
        )
    return result.stdout


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def build_variants(directory):
    clang = shutil.which("clang")
    strip = shutil.which("llvm-strip") or shutil.which("strip")
    nm = shutil.which("llvm-nm") or shutil.which("nm")
    if not all((clang, strip, nm)):
        raise RuntimeError("clang, strip, and nm are required")
    variants = {}
    for level in ("o0", "o2"):
        dwarf = directory / f"password-{level}-dwarf.elf"
        flags = (["--target=x86_64-unknown-linux-gnu", "-fuse-ld=lld"]
                 if sys.platform == "win32" else [])
        run([clang, *flags, f"-{level.upper()}", "-g", "-fno-stack-protector",
             "-fno-builtin", "-nostdlib", "-static", "-no-pie", "-Wl,--build-id=none",
             "-Wl,-e,_start", SOURCE, "-o", dwarf])
        elf = dwarf.read_bytes()
        program_offset = struct.unpack_from("<Q", elf, 32)[0]
        program_size, program_count = struct.unpack_from("<HH", elf, 54)
        if any(struct.unpack_from("<I", elf, program_offset + index * program_size)[0] == 3
               for index in range(program_count)):
            raise AssertionError(f"matrix ELF still has a program interpreter: {dwarf}")
        symbols = {}
        for row in run([nm, dwarf]).splitlines():
            match = re.fullmatch(r"\s*([0-9a-fA-F]+)\s+[Tt]\s+(hydir_triton_add2|hydir_secure_equals)", row)
            if match:
                symbols[match.group(2)] = int(match.group(1), 16)
        if set(symbols) != {"hydir_triton_add2", "hydir_secure_equals"}:
            raise AssertionError(f"missing matrix symbols in {dwarf}: {symbols}")
        stripped = directory / f"password-{level}-stripped.elf"
        shutil.copy2(dwarf, stripped)
        run([strip, "--strip-all", stripped])
        variants[level] = (dwarf, stripped, symbols)
    return variants


def seed_for(binary, entry, kind, case):
    return_address = struct.unpack_from("<Q", binary.read_bytes(), 24)[0]
    if kind == "add2":
        _, rdi, rsi, _ = case
        candidate = None
    else:
        _, candidate, rsi, _ = case
        rdi = 0x700100
    registers = [(0x38, rdi), (0x30, rsi), (0x20, 0x700000),
                 (0x28, 0x700200), (0, 0), (8, 0)]
    memory = [(0x700000, 8, return_address)]
    if candidate is not None:
        memory.extend([
            (0x700100, 8, int.from_bytes(candidate[:8], "little")),
            (0x700108, 4, int.from_bytes(candidate[8:], "little")),
        ])
    return {
        "schema_version": 1,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "entry": entry,
        "registers": [
            {"offset": hex(offset), "size": 8, "value": hex(value)}
            for offset, value in registers
        ],
        "memory": [
            {"space": "ram", "byte_offset": hex(address), "size": size,
             "value": hex(value)}
            for address, size, value in memory
        ],
    }


def native_result(binary, snapshot_path, kind, case):
    if sys.platform != "linux" or platform.machine() != "x86_64":
        return None
    if not shutil.which("gdb"):
        raise RuntimeError("GDB is required for the Linux native matrix")
    env = {**os.environ,
           "HYDIR_NATIVE_SNAPSHOT": str(snapshot_path),
           "HYDIR_MATRIX_KIND": kind}
    if kind == "add2":
        _, rdi, rsi, _ = case
        env.update(HYDIR_MATRIX_ARG0=hex(rdi), HYDIR_MATRIX_ARG1=hex(rsi))
    else:
        _, candidate, length, _ = case
        env.update(HYDIR_MATRIX_INPUT_HEX=candidate.hex(),
                   HYDIR_MATRIX_ARG1=hex(length))
    try:
        output = run(["gdb", "-nx", "-q", "--batch", "-x", GDB_SCRIPT, binary],
                     env=env, timeout=90)
    except RuntimeError as error:
        raise RuntimeError(f"native {binary.stem}/{kind}/{case[0]}: {error}") from error
    results = [json.loads(line.removeprefix("HYDIR_NATIVE_RESULT="))
               for line in output.splitlines()
               if line.startswith("HYDIR_NATIVE_RESULT=")]
    if len(results) != 1:
        raise AssertionError(f"missing native result: {output[-2000:]}")
    return results[0]


def seed_llvm_register(byte_map, state, known, offset, value):
    indexes = [byte_map.get(("register", offset + byte)) for byte in range(8)]
    if all(index is None for index in indexes):
        return
    if any(index is None for index in indexes):
        raise AssertionError(f"incomplete LLVM register map at {hex(offset)}")
    for byte, index in enumerate(indexes):
        state[index] = (value >> (8 * byte)) & 0xff
        known[index] = 0xff


def read_llvm_register(byte_map, state, known, offset, size):
    indexes = [byte_map[("register", offset + byte)] for byte in range(size)]
    if any(known[index] != 0xff for index in indexes):
        raise AssertionError(f"LLVM register {hex(offset)} has unknown bytes")
    return int.from_bytes(bytes(state[index] for index in indexes), "little")


def llvm_cases(artifact, module_path, kind, cases, seeds, rust_traces):
    library = module_path.with_suffix(".dll" if sys.platform == "win32" else ".so")
    flags = (["-Wl,/export:hydir_pcode_cfg"] if sys.platform == "win32"
             else ["-fPIC"])
    run(["clang", "-shared", *flags, module_path, "-o", library], timeout=120)
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
                for row in artifact["byte_map"]}
    results = {}
    try:
        for case in cases:
            name, *_, expected = case
            seed = seeds[name]
            state = (ctypes.c_uint8 * artifact["state_bytes"])()
            known = (ctypes.c_uint8 * artifact["state_bytes"])()
            for row in seed["registers"]:
                seed_llvm_register(byte_map, state, known,
                                   int(row["offset"], 16), int(row["value"], 16))
            guest = (ctypes.c_uint8 * 0x300)()
            guest_known = (ctypes.c_uint8 * 0x300)()
            for row in seed["memory"]:
                start = int(row["byte_offset"], 16) - 0x6fff00
                value = int(row["value"], 16).to_bytes(row["size"], "little")
                for byte, item in enumerate(value):
                    guest[start + byte] = item
                    guest_known[start + byte] = 0xff
            events = (ctypes.c_uint32 * 8192)()
            event_count = ctypes.c_uint32(0)
            status = lifted(state, known, 433,  # Ghidra's RAM address-space ID.
                            guest, guest_known, 0x6fff00, len(guest), events,
                            ctypes.byref(event_count), 8192, 8192)
            visits = []
            for operation_id in events[:event_count.value]:
                address = artifact["source_operations"][operation_id][
                    "instruction_address"]["offset"]
                if not visits or visits[-1] != address:
                    visits.append(address)
            rust_visits = [row["offset"] for row in rust_traces[name]["instruction_visits"]]
            if status != 1:
                if rust_traces[name]["stop"]["kind"] == "return":
                    raise AssertionError(f"LLVM stopped ({status}) but Rust returned: {kind}/{name}")
                if status not in (3, 4, 14, 20) or visits != rust_visits[:len(visits)]:
                    raise AssertionError(f"LLVM partial path differs from Rust: {kind}/{name}, {status}, {visits}")
                results[name] = {"status": status, "claim": "partial",
                                 "completed_visits": len(visits)}
                continue
            if rust_traces[name]["stop"]["kind"] != "return":
                raise AssertionError(f"LLVM returned through an unsupported Rust path: {kind}/{name}")
            width = 8 if kind == "add2" else 4
            value = read_llvm_register(byte_map, state, known, 0, width)
            if value != expected:
                raise AssertionError(f"LLVM {kind}/{name}: {value} != {expected}")
            if visits != rust_visits:
                raise AssertionError(f"LLVM/Rust visits differ: {kind}/{name}")
            results[name] = {"status": status, "claim": "exact_path",
                             "result": value, "visits": len(visits)}
    finally:
        if sys.platform == "win32":
            del lifted
            free_library = ctypes.windll.kernel32.FreeLibrary
            free_library.argtypes = [ctypes.c_void_p]
            free_library.restype = ctypes.c_int
            if not free_library(loaded._handle):
                raise RuntimeError("FreeLibrary failed for LLVM matrix module")
            loaded._handle = 0
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "target/ghidra-opt-matrix")
    args = parser.parse_args()
    directory = args.output_dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    client = Path(os.environ.get(
        "HYDIRCTL_BIN", ROOT / "target/debug" /
        ("hydirctl.exe" if sys.platform == "win32" else "hydirctl")))
    if not client.is_file():
        raise RuntimeError(f"build hydirctl first: {client}")
    variants = build_variants(directory)
    report = {"schema_version": 1, "compiler": run(["clang", "--version"]).splitlines()[0],
              "variants": {}}
    for level, (dwarf, stripped, symbols) in variants.items():
        pair = {}
        for binary, debug in ((dwarf, "dwarf"), (stripped, "stripped")):
            label = f"{level}-{debug}"
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            pair[debug] = {}
            for kind, symbol in (("add2", "hydir_triton_add2"),
                                 ("equals", "hydir_secure_equals")):
                entry = hex(symbols[symbol])
                snapshot_path = directory / f"{label}-{kind}-snapshot.json"
                run([client, "ghidra", "analyze", binary, "--function", entry,
                     "--output", snapshot_path], timeout=180)
                snapshot = load(snapshot_path)
                selected = snapshot["selected_function"]
                if snapshot["binary_sha256"] != digest or selected["entry"]["offset"] != entry:
                    raise AssertionError(f"snapshot binding failed: {label}/{kind}")
                artifact_path = directory / f"{label}-{kind}-llvm.json"
                run([client, "ghidra-snapshot", "llvm-cfg-image", binary,
                     snapshot_path, "--output", artifact_path])
                artifact = load(artifact_path)
                if artifact["schema_version"] != 3 or artifact["binary_sha256"] != digest:
                    raise AssertionError(f"LLVM binding failed: {label}/{kind}")
                module_path = artifact_path.with_suffix(".ll")
                module_path.write_text(artifact["llvm_ir"], encoding="utf-8")
                seeds = {}
                traces = {}
                native = {}
                for case in CASES[kind]:
                    name, *_, expected = case
                    seed = seed_for(binary, selected["entry"], kind, case)
                    seeds[name] = seed
                    seed_path = directory / f"{label}-{kind}-{name}-seed.json"
                    seed_path.write_text(json.dumps(seed, indent=2) + "\n", encoding="utf-8")
                    trace_path = directory / f"{label}-{kind}-{name}-trace.json"
                    run([client, "ghidra-snapshot", "trace-path", binary,
                         snapshot_path, seed_path, "--max-ops", "8192",
                         "--max-visits", "512", "--output", trace_path])
                    trace = load(trace_path)
                    traces[name] = trace
                    if kind == "add2" or level == "o0" or name == "wrong-length":
                        if trace["stop"]["kind"] != "return":
                            raise AssertionError(f"Rust stopped unexpectedly: {label}/{kind}/{name}: {trace['stop']}")
                        if trace["final_state"]["register_bytes"]["0"] != expected:
                            raise AssertionError(f"wrong Rust result: {label}/{kind}/{name}")
                        native_result_row = native_result(
                            binary, snapshot_path, kind, case)
                        if native_result_row is not None:
                            if (native_result_row["result"] != expected or
                                    native_result_row["verified_instruction_bytes"] != len(selected["instructions"])):
                                raise AssertionError(f"Rust/native mismatch: {label}/{kind}/{name}")
                            native[name] = "matched_output_and_code_bytes"
                    elif trace["stop"]["kind"] != "return":
                        if trace["stop"]["kind"] != "effect_boundary":
                            raise AssertionError(f"unexpected partial stop: {label}/{kind}/{name}")
                    elif trace["final_state"]["register_bytes"]["0"] != expected:
                        raise AssertionError(f"wrong optimized Rust result: {label}/{kind}/{name}")
                llvm = llvm_cases(artifact, module_path, kind, CASES[kind], seeds, traces)
                pair[debug][kind] = {
                    "entry": entry, "binary_sha256": digest,
                    "instruction_count": len(selected["instructions"]),
                    "pcode_operation_count": sum(len(row["pcode"]) for row in selected["instructions"]),
                    "read_only_image_known_bytes": artifact["read_only_image"]["known_byte_count"],
                    "rust_stops": {name: row["stop"]["kind"] for name, row in traces.items()},
                    "llvm": llvm, "native": native,
                }
                pair[debug][kind]["_instructions"] = selected["instructions"]
                print(f"{label}/{kind}: " + ", ".join(
                    f"{name}={traces[name]['stop']['kind']}/{llvm[name]['status']}"
                    for name, *_ in CASES[kind]), flush=True)
        for kind in CASES:
            if pair["dwarf"][kind]["_instructions"] != pair["stripped"][kind]["_instructions"]:
                raise AssertionError(f"DWARF/stripped raw P-code differs: {level}/{kind}")
            del pair["dwarf"][kind]["_instructions"]
            del pair["stripped"][kind]["_instructions"]
        report["variants"].update({f"{level}-{key}": value for key, value in pair.items()})
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n",
                                               encoding="utf-8")
    print(f"Ghidra optimization matrix passed: {directory / 'report.json'}")


if __name__ == "__main__":
    main()
