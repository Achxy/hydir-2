#!/usr/bin/env python3
"""Bounded, non-executing Triton semantics bridge for HydIR.

The bridge explores only direct control flow inside one bounded symbol. Each
path gets a fresh Triton context; final register values are merged as textual
ITE expressions so a conditional function is not mistaken for a straight-line
trace.
"""

from __future__ import annotations

import ast
import json
import sys


MAX_REQUEST_BYTES = 128 * 1024
MAX_CODE_BYTES = 4096
MAX_PATHS = 64
MAX_PATH_INSTRUCTIONS = 1024
MAX_CONSOLE_COMMANDS = 64
MAX_CONSOLE_COMMAND_BYTES = 4096


def fail(message: str) -> None:
    raise ValueError(message)


def read_request() -> dict:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        fail("request exceeds 128 KiB limit")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"malformed JSON: {error.msg}") from error
    if not isinstance(request, dict) or request.get("schema_version") != 1:
        fail("unsupported request schema")
    return request


def validate_request(request: dict) -> tuple[str, str, int, bytes]:
    symbol = request.get("function_symbol")
    digest = request.get("binary_sha256")
    address = request.get("entry_address")
    code_hex = request.get("code_hex")
    if not isinstance(symbol, str) or not symbol or len(symbol) > 256:
        fail("function_symbol must be 1-256 characters")
    if not isinstance(digest, str) or len(digest) != 64:
        fail("binary_sha256 must be a 64-character hex digest")
    try:
        bytes.fromhex(digest)
    except ValueError as error:
        raise ValueError("binary_sha256 must be hexadecimal") from error
    if not isinstance(address, int) or isinstance(address, bool) or address < 0:
        fail("entry_address must be a non-negative integer")
    if not isinstance(code_hex, str) or len(code_hex) == 0 or len(code_hex) % 2:
        fail("code_hex must contain an even number of hexadecimal characters")
    try:
        code = bytes.fromhex(code_hex)
    except ValueError as error:
        raise ValueError("code_hex is not valid hexadecimal") from error
    if len(code) > MAX_CODE_BYTES:
        fail("function exceeds 4096-byte limit")
    return symbol, digest.lower(), address, code


def new_context():
    from triton import ARCH, TritonContext

    context = TritonContext(ARCH.X86_64)
    context.symbolizeRegister(context.registers.rdi, "arg0")
    context.symbolizeRegister(context.registers.rsi, "arg1")
    return context


def decode_and_process(context, code: bytes, address: int, offset: int):
    from triton import Instruction

    # Triton accepts at most the x86 architectural maximum of 15 opcode bytes.
    # Supplying the entire remaining function fails for symbols over that size.
    instruction = Instruction(code[offset : offset + 15])
    instruction.setAddress(address + offset)
    context.processing(instruction)
    size = instruction.getSize()
    if size <= 0:
        fail("Triton decoded a zero-size instruction")
    if offset + size > len(code):
        fail(f"instruction at 0x{address + offset:x} exceeds symbol bounds")
    return instruction


def replay(context, code: bytes, address: int, trace: tuple[int, ...]) -> None:
    for offset in trace:
        decode_and_process(context, code, address, offset)


def target_offset(target: int, address: int, code: bytes) -> int:
    offset = target - address
    if offset < 0 or offset >= len(code):
        fail(f"control flow target 0x{target:x} leaves symbol")
    return offset


def direct_target(instruction) -> int | None:
    operands = instruction.getOperands()
    if not operands:
        return None
    token = str(operands[0]).split(":", 1)[0]
    try:
        return int(token, 0)
    except ValueError:
        return None


def merge_paths(path_results: list[dict]) -> str:
    if len(path_results) == 1:
        return path_results[0]["rax"]
    merged = path_results[-1]["rax"]
    for path in reversed(path_results[:-1]):
        merged = f"(ite {path['path_condition']} {path['rax']} {merged})"
    return merged


def register_ast(context, register) -> str:
    expression = context.getSymbolicRegister(register)
    if expression is None:
        return "(_ bv0 64)"
    return str(expression.getAst())


class ConsoleEvaluator:
    """Evaluate a deliberately small, Triton-only Python-shaped language."""

    MUTATING_METHODS = {
        "processing",
        "setConcreteRegisterValue",
        "symbolizeRegister",
    }
    CONTEXT_METHODS = {
        "getModel",
        "getSymbolicRegister",
        *MUTATING_METHODS,
    }

    def __init__(self) -> None:
        from triton import ARCH, Instruction, TritonContext

        self.arch = ARCH
        self.instruction_type = Instruction
        self.context_constructor = TritonContext
        self.context_class = type(TritonContext(ARCH.X86_64))
        self.values: dict[str, object] = {}
        self.output: list[str] = []

    def execute(self, source: str) -> list[str]:
        if not isinstance(source, str) or not source.strip():
            fail("console command must be non-empty")
        if len(source.encode("utf-8")) > MAX_CONSOLE_COMMAND_BYTES:
            fail("console command exceeds 4096-byte limit")
        try:
            module = ast.parse(source, mode="exec")
        except SyntaxError as error:
            raise ValueError(f"invalid console syntax: {error.msg}") from error
        if len(module.body) != 1:
            fail("enter one Triton statement at a time")
        before = len(self.output)
        statement = module.body[0]
        if isinstance(statement, ast.ImportFrom):
            if (
                statement.module != "triton"
                or len(statement.names) != 1
                or statement.names[0].name != "*"
            ):
                fail("only 'from triton import *' is allowed")
        elif isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                fail("console assignments require one variable name")
            name = statement.targets[0].id
            if name.startswith("_") or len(name) > 64 or not name.replace("_", "a").isalnum():
                fail("invalid console variable name")
            self.values[name] = self.evaluate(statement.value)
        elif isinstance(statement, ast.Expr):
            value = self.evaluate(statement.value)
            if value is not None and not self._is_mutating_call(statement.value):
                self.output.append(repr(value) if isinstance(value, str) else str(value))
        else:
            fail("statement type is outside the Triton console subset")
        return self.output[before:]

    def _is_mutating_call(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in self.MUTATING_METHODS
        )

    def evaluate(self, node: ast.AST):
        if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, int, str)):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in self.values:
                return self.values[node.id]
            if node.id == "ARCH":
                return self.arch
            fail(f"unknown console name {node.id!r}")
        if isinstance(node, ast.Attribute):
            base = self.evaluate(node.value)
            if base is self.arch and node.attr == "X86_64":
                return self.arch.X86_64
            if isinstance(base, self.context_class) and node.attr == "registers":
                return base.registers
            if node.attr.startswith("_"):
                fail("private attributes are not allowed")
            try:
                register = getattr(base, node.attr)
            except AttributeError as error:
                raise ValueError(f"unknown Triton attribute {node.attr!r}") from error
            if "register" not in type(register).__name__.lower():
                fail("only Triton register attributes are allowed")
            return register
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            value = self.evaluate(node.operand)
            if not isinstance(value, int):
                fail("unary minus requires an integer")
            return -value
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitXor):
            left = self.evaluate(node.left)
            right = self.evaluate(node.right)
            if not isinstance(left, int) or not isinstance(right, int):
                fail("xor requires integer operands")
            return left ^ right
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq):
            return self.evaluate(node.left) == self.evaluate(node.comparators[0])
        if isinstance(node, ast.Call):
            if node.keywords:
                fail("keyword arguments are not supported")
            arguments = [self.evaluate(argument) for argument in node.args]
            if isinstance(node.func, ast.Name):
                if node.func.id == "TritonContext" and len(arguments) == 1:
                    return self.context_constructor(arguments[0])
                if node.func.id == "Instruction" and len(arguments) == 1 and isinstance(arguments[0], bytes):
                    return self.instruction_type(arguments[0])
                if node.func.id == "print" and len(arguments) == 1:
                    self.output.append(str(arguments[0]))
                    return None
                if node.func.id == "hex" and len(arguments) == 1 and isinstance(arguments[0], int):
                    return hex(arguments[0])
                fail(f"console function {node.func.id!r} is not allowed")
            if isinstance(node.func, ast.Attribute):
                receiver = self.evaluate(node.func.value)
                method = node.func.attr
                if isinstance(receiver, self.context_class) and method in self.CONTEXT_METHODS:
                    return getattr(receiver, method)(*arguments)
                if method == "getAst" and not arguments and hasattr(receiver, "getAst"):
                    return receiver.getAst()
                fail(f"Triton method {method!r} is not allowed")
        fail(f"expression type {type(node).__name__} is outside the Triton console subset")


def run_console(request: dict) -> dict:
    commands = request.get("commands")
    if not isinstance(commands, list) or len(commands) > MAX_CONSOLE_COMMANDS:
        fail("commands must be a list of at most 64 statements")
    evaluator = ConsoleEvaluator()
    entries = []
    for index, command in enumerate(commands):
        try:
            output = evaluator.execute(command)
        except Exception as error:
            raise ValueError(f"command {index + 1} failed: {error}") from error
        entries.append({"command": command, "output": output})
    return {
        "schema_version": 1,
        "backend": "triton",
        "operation": "console",
        "entries": entries,
    }


def main() -> None:
    try:
        request = read_request()
        if request.get("operation") == "console":
            json.dump(run_console(request), sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
            return
        symbol, digest, address, code = validate_request(request)

        instructions: dict[int, dict] = {}
        paths = [(tuple(), 0, tuple(), frozenset())]
        path_results: list[dict] = []

        while paths:
            trace, offset, conditions, visited = paths.pop()
            if len(path_results) >= MAX_PATHS:
                fail("control-flow path count exceeds 64-path limit")
            if offset in visited:
                fail(f"control-flow loop at 0x{address + offset:x} is unsupported")
            if len(trace) >= MAX_PATH_INSTRUCTIONS:
                fail("control-flow path exceeds 1024-instruction limit")

            context = new_context()
            replay(context, code, address, trace)
            instruction = decode_and_process(context, code, address, offset)
            size = instruction.getSize()
            text = instruction.getDisassembly() or ""
            mnemonic = text.split(None, 1)[0].lower() if text else "unknown"
            record = {
                "address": address + offset,
                "size": size,
                "bytes": code[offset : offset + size].hex(),
                "disassembly": text,
                "symbolic_expressions": [
                    str(expression)
                    for expression in instruction.getSymbolicExpressions()
                ],
            }
            instructions.setdefault(address + offset, record)
            next_trace = trace + (offset,)
            next_visited = visited | {offset}

            if mnemonic.startswith("ret"):
                path_results.append(
                    {
                        "path_condition": "(and " + " ".join(conditions) + ")"
                        if conditions
                        else "true",
                        "rax": register_ast(context, context.registers.rax),
                    }
                )
                continue

            if mnemonic.startswith("call"):
                fail(f"call at 0x{address + offset:x} is unsupported")
            if not instruction.isControlFlow():
                next_offset = offset + size
                if next_offset >= len(code):
                    fail(f"non-returning instruction at 0x{address + offset:x} reaches symbol end")
                paths.append((next_trace, next_offset, conditions, next_visited))
                continue

            constraints = context.getPathConstraints()
            if not constraints:
                if mnemonic.startswith("jmp"):
                    target = direct_target(instruction)
                    if target is None:
                        fail(f"unresolved control flow at 0x{address + offset:x}")
                    next_offset = target_offset(target, address, code)
                    if next_offset in next_visited:
                        fail(f"control-flow loop at 0x{target:x} is unsupported")
                    paths.append((next_trace, next_offset, conditions, next_visited))
                    continue
                fail(f"unresolved control flow at 0x{address + offset:x}")
            branches = constraints[-1].getBranchConstraints()
            if not branches:
                fail(f"unresolved control flow at 0x{address + offset:x}")
            for branch in branches:
                target = int(branch["dstAddr"])
                next_offset = target_offset(target, address, code)
                if next_offset in next_visited:
                    fail(f"control-flow loop at 0x{target:x} is unsupported")
                paths.append(
                    (
                        next_trace,
                        next_offset,
                        conditions + (str(branch["constraint"]),),
                        next_visited,
                    )
                )

        if not path_results:
            fail("no return path recovered")
        ordered_instructions = [instructions[key] for key in sorted(instructions)]
        result = {
            "schema_version": 1,
            "backend": "triton",
            "architecture": "x86_64",
            "binary_sha256": digest,
            "function_symbol": symbol,
            "entry_address": address,
            "code_size": len(code),
            "symbolic_inputs": ["arg0", "arg1"],
            "instructions": ordered_instructions,
            "paths": path_results,
            "final_registers": {"rax": merge_paths(path_results)},
        }
        json.dump(result, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
    except Exception as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
