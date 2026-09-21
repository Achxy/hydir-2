#!/usr/bin/env python3
"""Reproduce the wiki's VM-handler analysis with HydIR, Triton, and LLVM.

Requires triton-library and pyelftools in this Python interpreter, plus
clang, ld.lld, opt, lli, and a built hydirctl on PATH / target/debug.
The ELF is a trusted, hand-authored fixture; Triton emulates its handler.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys

from elftools.elf.elffile import ELFFile
from triton import ARCH, CPUSIZE, Instruction, MemoryAccess, TritonContext


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "target" / "demo-vm-handler"
SOURCE = ROOT / "tests" / "fixtures" / "vm_vadd.S"
MODEL = ROOT / "tests" / "fixtures" / "vm_vadd.ll"
MASK = (1 << 64) - 1
STATE_BASE = 0x100000
RETURN_STACK = 0x200000


def run(*args: object, check: bool = True) -> subprocess.CompletedProcess[str]:
    command = [str(arg) for arg in args]
    if os.name == "nt" and command[0] == "ld.lld":
        command[0] = "ld.lld.exe"
    return subprocess.run(
        command, cwd=ROOT, text=True,
        capture_output=True, check=check,
    )


def function_bytes(elf_path: Path) -> tuple[int, bytes]:
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        symbols = elf.get_section_by_name(".symtab")
        match = next(symbol for symbol in symbols.iter_symbols() if symbol.name == "vm_vadd")
        section = elf.get_section(match["st_shndx"])
        start = match["st_value"] - section["sh_addr"]
        return match["st_value"], section.data()[start : start + match["st_size"]]


def triton_case(address: int, code: bytes, before: list[int]) -> tuple[list[int], list[dict]]:
    ctx = TritonContext(ARCH.X86_64)
    ctx.setConcreteRegisterValue(ctx.registers.rdi, STATE_BASE)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, RETURN_STACK)
    ctx.setConcreteRegisterValue(ctx.registers.rip, address)
    ctx.setConcreteMemoryAreaValue(STATE_BASE, struct.pack("<22Q", *before))
    ctx.setConcreteMemoryAreaValue(RETURN_STACK, struct.pack("<Q", 0))
    records = []
    offset = 0
    while offset < len(code):
        inst = Instruction(code[offset:offset + 16])
        inst.setAddress(address + offset)
        ctx.processing(inst)
        records.append({"address": hex(address + offset), "bytes": code[offset:offset + inst.getSize()].hex(), "disassembly": inst.getDisassembly()})
        offset += inst.getSize()
        if inst.getDisassembly().lower().startswith("ret"):
            break
    if offset != len(code) or len(records) != 8:
        raise AssertionError("handler decoding or control flow changed")
    after = list(struct.unpack("<22Q", bytes(ctx.getConcreteMemoryAreaValue(STATE_BASE, 176))))
    return after, records


def symbolic_sum_check(address: int, code: bytes, sp: int) -> dict:
    """Check the output word for symbolic top-of-stack inputs at fixed sp."""
    ctx = TritonContext(ARCH.X86_64)
    ctx.setConcreteRegisterValue(ctx.registers.rdi, STATE_BASE)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, RETURN_STACK)
    ctx.setConcreteRegisterValue(ctx.registers.rip, address)
    ctx.setConcreteMemoryAreaValue(STATE_BASE, struct.pack("<22Q", *([0] * 20 + [sp, 12])))
    ctx.setConcreteMemoryAreaValue(RETURN_STACK, struct.pack("<Q", 0))
    low = MemoryAccess(STATE_BASE + 32 + (sp - 2) * 8, CPUSIZE.QWORD)
    high = MemoryAccess(STATE_BASE + 32 + (sp - 1) * 8, CPUSIZE.QWORD)
    ctx.symbolizeMemory(low, "stack_low")
    ctx.symbolizeMemory(high, "stack_high")
    a = ctx.getMemoryAst(low)
    b = ctx.getMemoryAst(high)
    offset = 0
    while offset < len(code):
        inst = Instruction(code[offset:offset + 16])
        inst.setAddress(address + offset)
        ctx.processing(inst)
        offset += inst.getSize()
    result = ctx.getMemoryAst(low)
    unchanged_high = ctx.getMemoryAst(high)
    sum_counterexample = ctx.isSat(result != a + b)
    high_counterexample = ctx.isSat(unchanged_high != b)
    if sum_counterexample or high_counterexample:
        raise AssertionError("symbolic stack effect differs from transfer function")
    return {
        "sp": sp,
        "sum_counterexample_sat": sum_counterexample,
        "old_top_modified_counterexample_sat": high_counterexample,
        "result_ast": str(result),
    }


def expected(before: list[int]) -> list[int]:
    after = before.copy()
    sp = before[20]
    if not 2 <= sp <= 16:
        raise ValueError("handler precondition: 2 <= sp <= 16")
    after[4 + sp - 2] = (before[4 + sp - 2] + before[4 + sp - 1]) & MASK
    after[20] = sp - 1
    after[21] = (before[21] + 1) & MASK
    return after


def llvm_harness(cases: list[tuple[list[int], list[int]]]) -> str:
    parts = [MODEL.read_text(encoding="utf-8"), "\ndefine i32 @main() {\nentry:"]
    checks = []
    for case_index, (before, after) in enumerate(cases):
        state = f"%state{case_index}"
        parts.append(f"  {state} = alloca %VMState, align 8")
        for word_index, value in enumerate(before):
            pointer = f"%in_ptr_{case_index}_{word_index}"
            parts.append(f"  {pointer} = getelementptr i64, ptr {state}, i64 {word_index}")
            parts.append(f"  store i64 {value}, ptr {pointer}, align 8")
        parts.append(f"  call void @vm_vadd_ir(ptr {state})")
        for word_index, value in enumerate(after):
            pointer = f"%out_ptr_{case_index}_{word_index}"
            actual = f"%out_{case_index}_{word_index}"
            match = f"%eq_{case_index}_{word_index}"
            parts.append(f"  {pointer} = getelementptr i64, ptr {state}, i64 {word_index}")
            parts.append(f"  {actual} = load i64, ptr {pointer}, align 8")
            parts.append(f"  {match} = icmp eq i64 {actual}, {value}")
            checks.append(match)
    accumulated = checks[0]
    for index, check in enumerate(checks[1:], 1):
        next_value = f"%all_{index}"
        parts.append(f"  {next_value} = and i1 {accumulated}, {check}")
        accumulated = next_value
    parts.extend([f"  %result = select i1 {accumulated}, i32 0, i32 1", "  ret i32 %result", "}"])
    return "\n".join(parts) + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    obj = OUT / "vm_vadd.o"
    elf = OUT / "vm_vadd.elf"
    run("clang", "-std=c11", "-fsyntax-only", "-x", "c",
        ROOT / "tests" / "fixtures" / "vm_vadd_state.h")
    run("clang", "--target=x86_64-unknown-linux-gnu", "-c", SOURCE, "-o", obj)
    run("ld.lld", "-m", "elf_x86_64", "-e", "_start", "-o", elf, obj)
    address, code = function_bytes(elf)

    cli_name = "hydirctl.exe" if os.name == "nt" else "hydirctl"
    cli = Path(os.environ.get("HYDIRCTL", ROOT / "target" / "debug" / cli_name))
    if not cli.is_file():
        raise SystemExit(f"build HydIR first: cargo build --locked --bin hydirctl (missing {cli})")
    inventory = json.loads(run(cli, "inspect", elf).stdout)
    analysis = json.loads(run(cli, "analyze", elf).stdout)
    digest = hashlib.sha256(elf.read_bytes()).hexdigest()
    if inventory["binary_sha256"] != digest or analysis["binary_sha256"] != digest:
        raise AssertionError("HydIR reports a different ELF identity")
    function = next(item for item in inventory["functions"] if item["name"] == "vm_vadd")
    effects = next(item for item in analysis["functions"] if item["name"] == "vm_vadd")
    if int(function["address"], 16) != address or function["size"] != len(code):
        raise AssertionError("HydIR symbol extent differs from extracted ELF bytes")
    if effects["reachable_instructions"] != 8 or not effects["unknown_global_effects"]:
        raise AssertionError("HydIR native-analysis result changed")
    cfg = run(cli, "cfg", elf, "vm_vadd", check=False)
    lift = run(cli, "lift", elf, "vm_vadd", "--assume-u64x2", check=False)
    if cfg.returncode == 0 or lift.returncode == 0 or "operand kind unsupported" not in cfg.stderr or "operand kind unsupported" not in lift.stderr:
        raise AssertionError("HydIR scalar CFG/lift boundary changed")
    bridge_env = os.environ.copy()
    bridge_env["HYDIR_TRITON_PYTHON"] = sys.executable
    bridge = subprocess.run(
        [str(cli), "triton", str(elf), "vm_vadd"], cwd=ROOT,
        text=True, capture_output=True, check=True, env=bridge_env,
    )
    bridge_report = json.loads(bridge.stdout)
    if bridge_report["binary_sha256"] != digest or len(bridge_report["instructions"]) != 8 or bridge_report["code_size"] != len(code) or len(bridge_report["paths"]) != 1:
        raise AssertionError("HydIR Triton bridge decoded a different handler")

    rng = random.Random(0x56414444)
    cases: list[tuple[list[int], list[int]]] = []
    for sp, lhs, rhs in [(2, 7, 9), (2, MASK, 1), (16, 0, 0), (16, MASK, MASK)]:
        before = [rng.getrandbits(64) for _ in range(20)] + [sp, 12]
        before[4 + sp - 2], before[4 + sp - 1] = lhs, rhs
        after, trace = triton_case(address, code, before)
        if after != expected(before):
            raise AssertionError(f"Triton state mismatch at sp={sp}: {after} != {expected(before)}")
        cases.append((before, after))
    for _ in range(64):
        sp = rng.randrange(2, 17)
        before = [rng.getrandbits(64) for _ in range(20)] + [sp, rng.getrandbits(64)]
        after, _ = triton_case(address, code, before)
        if after != expected(before):
            raise AssertionError(f"Triton state mismatch at sp={sp}")
        cases.append((before, after))

    symbolic = [symbolic_sum_check(address, code, sp) for sp in range(2, 17)]

    harness = OUT / "vm_vadd_check.ll"
    harness.write_text(llvm_harness(cases), encoding="utf-8")
    run("opt", "-passes=verify", "-disable-output", harness)
    run("lli", harness)

    report = {
        "fixture": str(SOURCE.relative_to(ROOT)).replace("\\", "/"),
        "elf_sha256": digest,
        "handler_address": hex(address),
        "handler_size": len(code),
        "handler_bytes": code.hex(),
        "hydir": {"symbol": function, "analysis": effects,
                  "cfg_error": cfg.stderr.strip(), "lift_error": lift.stderr.strip(),
                  "triton_bridge": {"backend": bridge_report["backend"],
                                    "instruction_count": len(bridge_report["instructions"]),
                                    "path_count": len(bridge_report["paths"]),
                                    "state_setup": "generic arg0/arg1; VMState memory not initialized"}},
        "triton": {"tested_states": len(cases), "first_input": cases[0][0],
                   "first_output": cases[0][1], "instructions": trace,
                   "symbolic_checks": symbolic},
        "llvm": {"model": str(MODEL.relative_to(ROOT)).replace("\\", "/"),
                 "verified": True, "full_state_matches_triton": len(cases)},
    }
    (OUT / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"HydIR inventory/analysis: {address:#x}, {len(code)} bytes, {effects['reachable_instructions']} instructions")
    print(f"HydIR scalar CFG/lift: {cfg.stderr.strip()} / {lift.stderr.strip()}")
    print(f"Triton native handler vs LLVM transfer function: {len(cases)} full-state cases PASS")
    print(f"Triton symbolic stack sum counterexamples: none at {len(symbolic)} valid stack depths")
    print(f"Evidence: {OUT / 'report.json'}")


if __name__ == "__main__":
    main()
