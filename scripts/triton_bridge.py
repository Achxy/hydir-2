#!/usr/bin/env python3
"""Bounded, non-executing Triton semantics bridge for HydIR."""

from __future__ import annotations

import json
import sys


MAX_CODE_BYTES = 4096


def fail(message: str) -> None:
    raise ValueError(message)


def main() -> None:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict) or request.get("schema_version") != 1:
            fail("unsupported request schema")
        symbol = request.get("function_symbol")
        digest = request.get("binary_sha256")
        address = request.get("entry_address")
        code_hex = request.get("code_hex")
        if not isinstance(symbol, str) or not symbol:
            fail("function_symbol must be a non-empty string")
        if not isinstance(digest, str) or len(digest) != 64:
            fail("binary_sha256 must be a 64-character hex digest")
        if not isinstance(address, int) or address < 0:
            fail("entry_address must be a non-negative integer")
        if not isinstance(code_hex, str) or len(code_hex) == 0 or len(code_hex) % 2:
            fail("code_hex must contain an even number of hexadecimal characters")
        try:
            code = bytes.fromhex(code_hex)
        except ValueError as error:
            raise ValueError("code_hex is not valid hexadecimal") from error
        if len(code) > MAX_CODE_BYTES:
            fail("function exceeds 4096-byte limit")

        from triton import ARCH, Instruction, TritonContext

        context = TritonContext(ARCH.X86_64)
        context.symbolizeRegister(context.registers.rdi, "arg0")
        context.symbolizeRegister(context.registers.rsi, "arg1")

        instructions = []
        offset = 0
        while offset < len(code):
            instruction = Instruction(code[offset:])
            instruction.setAddress(address + offset)
            if instruction.getSize() <= 0:
                fail("Triton decoded a zero-size instruction")
            context.processing(instruction)
            instructions.append(
                {
                    "address": address + offset,
                    "size": instruction.getSize(),
                    "bytes": code[offset : offset + instruction.getSize()].hex(),
                    "disassembly": instruction.getDisassembly(),
                    "symbolic_expressions": [
                        str(expression)
                        for expression in instruction.getSymbolicExpressions()
                    ],
                }
            )
            offset += instruction.getSize()

        rax = context.getSymbolicRegister(context.registers.rax)
        result = {
            "schema_version": 1,
            "backend": "triton",
            "architecture": "x86_64",
            "binary_sha256": digest,
            "function_symbol": symbol,
            "entry_address": address,
            "code_size": len(code),
            "symbolic_inputs": ["arg0", "arg1"],
            "instructions": instructions,
            "final_registers": {
                "rax": str(rax),
            },
        }
        json.dump(result, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    except Exception as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
