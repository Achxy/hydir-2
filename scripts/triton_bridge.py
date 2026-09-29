#!/usr/bin/env python3
"""Bounded Triton semantics and captured-state bridge for HydIR.

The original operation explores direct flow in one symbol without running the
ELF. The snapshot operation starts from explicitly captured state and returns
only a function witness; original-program validation belongs to native replay.
"""

from __future__ import annotations

import ast
import hashlib
import json
import sys
import time


MAX_REQUEST_BYTES = 128 * 1024
MAX_CODE_BYTES = 4096
MAX_PATHS = 64
MAX_PATH_INSTRUCTIONS = 1024
MAX_CONSOLE_COMMANDS = 64
MAX_CONSOLE_COMMAND_BYTES = 4096
MAX_SLICE_AST_NODES = 65536
MAX_SLICE_DECISIONS = 64
SNAPSHOT_REGISTERS = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9",
    "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags",
)
SNAPSHOT_FLAG_BITS = {
    "cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of", "nt",
    "rf", "vm", "ac", "vif", "vip", "id", "rflags",
}


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


class UnsupportedSnapshot(Exception):
    """A captured state cannot support this bounded symbolic execution."""


class SnapshotBudgetExhausted(Exception):
    """The bounded solver session has reached its declared budget."""


def _u64(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << 64:
        fail(f"{name} must be an unsigned 64-bit integer")
    return value


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        fail(f"{name} must be a 64-character hex digest")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} must be hexadecimal") from error
    return value


def _hex_bytes(value: object, limit: int, name: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 2 or len(value) > limit * 2:
        fail(f"{name} must contain 1..={limit} bytes of even-length hex")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name} is not valid hexadecimal") from error


def validate_snapshot_request(request: dict) -> dict:
    if request.get("operation") != "snapshot_return":
        fail("unsupported snapshot operation")
    for name in ("binary_sha256", "input_sha256", "snapshot_sha256", "probe_sha256"):
        _digest(request.get(name), name)
    code_address = _u64(request.get("code_address"), "code_address")
    code = _hex_bytes(request.get("code_hex"), MAX_CODE_BYTES, "code_hex")
    registers = request.get("registers")
    if not isinstance(registers, dict) or set(registers) != set(SNAPSHOT_REGISTERS):
        fail("snapshot registers must contain the captured integer register set")
    for name, value in registers.items():
        _u64(value, f"register {name}")
    if registers["rip"] != code_address:
        fail("captured RIP differs from code_address")
    pages = request.get("pages")
    if not isinstance(pages, list) or not 1 <= len(pages) <= 8:
        fail("snapshot request must include 1..=8 present pages")
    page_bytes = {}
    writable_pages = set()
    executable_pages = set()
    previous = -1
    for page in pages:
        if not isinstance(page, dict) or set(page) != {
            "address", "bytes_hex", "writable", "executable"
        }:
            fail("snapshot page has invalid fields")
        address = _u64(page["address"], "page address")
        if address % 4096 or address <= previous:
            fail("snapshot pages must be aligned and strictly increasing")
        data = _hex_bytes(page["bytes_hex"], 4096, "page bytes_hex")
        if len(data) != 4096:
            fail("snapshot present page must contain exactly 4096 bytes")
        if not isinstance(page["writable"], bool) or not isinstance(page["executable"], bool):
            fail("snapshot page permissions must be booleans")
        page_bytes[address] = data
        if page["writable"]:
            writable_pages.add(address)
        if page["executable"]:
            executable_pages.add(address)
        previous = address

    def captured_bytes(address: int, length: int) -> bytes:
        result = bytearray()
        for location in range(address, address + length):
            page = page_bytes.get(location & ~4095)
            if page is None:
                fail(f"snapshot did not capture byte 0x{location:x}")
            result.append(page[location & 4095])
        return bytes(result)

    if captured_bytes(code_address, len(code)) != code:
        fail("code_hex disagrees with captured memory")
    if any((location & ~4095) not in executable_pages
           for location in range(code_address, code_address + len(code))):
        fail("captured code is outside executable pages")
    origin = request.get("symbolic_origin")
    if not isinstance(origin, dict) or not isinstance(origin.get("id"), str) or not origin["id"]:
        fail("symbolic_origin must name an input origin")
    origin_address = _u64(request.get("origin_address"), "origin_address")
    seed = _hex_bytes(request.get("seed_hex"), 32, "seed_hex")
    if origin_address < code_address + len(code) and origin_address + len(seed) > code_address:
        fail("symbolic origin overlaps captured code")
    if origin.get("length") != len(seed) or captured_bytes(origin_address, len(seed)) != seed:
        fail("symbolic origin differs from captured seed bytes")
    if request.get("origin_probe_evidence") != "byte_equality_only":
        fail("snapshot origin requires explicit byte-equality evidence")
    assumptions = [
        "analyst_selected_origin_address_has_input_channel_bytes",
        "selected_code_extent_and_captured_pages_cover_this_function_path",
    ]
    if request.get("assumptions") != assumptions:
        fail("snapshot solver assumptions are missing or altered")
    encoding = origin.get("encoding")
    if encoding not in ("raw", "ascii"):
        fail("snapshot solver currently supports raw and ASCII origin encodings")
    alphabet_hex = origin.get("alphabet_hex", "")
    if not isinstance(alphabet_hex, str) or len(alphabet_hex) % 2 or len(alphabet_hex) > 512:
        fail("symbolic origin alphabet is invalid")
    try:
        alphabet = bytes.fromhex(alphabet_hex)
    except ValueError as error:
        raise ValueError("symbolic origin alphabet is not hexadecimal") from error
    if alphabet_hex and not alphabet:
        fail("symbolic origin alphabet is empty")
    channel = origin.get("channel")
    if not isinstance(channel, dict) or channel.get("kind") not in ("stdin", "argv", "file"):
        fail("symbolic origin channel is invalid")
    allowed = set(alphabet) if alphabet else set(range(256))
    if encoding == "ascii":
        allowed.intersection_update(range(128))
    if channel["kind"] == "argv":
        allowed.discard(0)
    if not allowed or any(byte not in allowed for byte in seed):
        fail("captured seed violates symbolic origin constraints")
    expected = _u64(request.get("return_equals"), "return_equals")
    for name, maximum in (("max_seeds", 16), ("max_instructions_per_seed", 1024),
                          ("max_solver_queries", 32), ("wall_timeout_ms", 20000),
                          ("solver_timeout_ms", 2000)):
        value = request.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            fail(f"{name} must be within 1..={maximum}")
    return {
        "binary_sha256": request["binary_sha256"],
        "input_sha256": request["input_sha256"],
        "snapshot_sha256": request["snapshot_sha256"],
        "probe_sha256": request["probe_sha256"],
        "code_address": code_address,
        "code": code,
        "registers": registers,
        "pages": page_bytes,
        "writable_pages": writable_pages,
        "origin": origin,
        "origin_address": origin_address,
        "seed": seed,
        "allowed": allowed,
        "return_equals": expected,
        "max_seeds": request["max_seeds"],
        "max_instructions": request["max_instructions_per_seed"],
        "max_solver_queries": request["max_solver_queries"],
        "wall_timeout_ms": request["wall_timeout_ms"],
        "solver_timeout_ms": request["solver_timeout_ms"],
    }


def _snapshot_context(plan: dict, seed: bytes):
    from triton import ARCH, CALLBACK, CPUSIZE, MemoryAccess, TritonContext

    context = TritonContext(ARCH.X86_64)
    context.setSolverTimeout(plan["solver_timeout_ms"])
    for address, data in plan["pages"].items():
        context.setConcreteMemoryAreaValue(address, data, callbacks=False)
    context.setConcreteMemoryAreaValue(plan["origin_address"], seed, callbacks=False)
    known_registers = set()
    for name, value in plan["registers"].items():
        register = getattr(context.registers, name)
        context.setConcreteRegisterValue(register, value, callbacks=False)
        known_registers.add(context.getParentRegister(register).getName())
    known_registers.update(SNAPSHOT_FLAG_BITS)
    known_pages = set(plan["pages"])
    writable_pages = plan["writable_pages"]
    code_start = plan["code_address"]
    code_end = code_start + len(plan["code"])

    def check_memory(_, memory):
        address = memory.getAddress()
        size = memory.getSize()
        if size <= 0 or any((byte & ~4095) not in known_pages
                            for byte in range(address, address + size)):
            raise UnsupportedSnapshot(f"uncaptured memory at 0x{address:x}")

    def check_write(_, memory, _value):
        check_memory(_, memory)
        address = memory.getAddress()
        if any((byte & ~4095) not in writable_pages
               for byte in range(address, address + memory.getSize())):
            raise UnsupportedSnapshot(f"write to non-writable captured page at 0x{address:x}")
        if address < code_end and address + memory.getSize() > code_start:
            raise UnsupportedSnapshot("self-modifying code is outside snapshot solver scope")

    def check_register(ctx, register):
        parent = ctx.getParentRegister(register).getName()
        if parent not in known_registers:
            raise UnsupportedSnapshot(f"uncaptured register {parent}")

    context.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, check_memory)
    context.addCallback(CALLBACK.SET_CONCRETE_MEMORY_VALUE, check_write)
    context.addCallback(CALLBACK.GET_CONCRETE_REGISTER_VALUE, check_register)
    variables = []
    for index in range(len(seed)):
        variable = context.symbolizeMemory(
            MemoryAccess(plan["origin_address"] + index, CPUSIZE.BYTE), f"origin_{index}"
        )
        variables.append(variable)
    return context, variables


def _allowed_constraints(context, variables, allowed: set[int]):
    ast_context = context.getAstContext()
    if len(allowed) == 256:
        return []
    values = sorted(allowed)
    result = []
    for variable in variables:
        node = ast_context.variable(variable)
        if values == list(range(128)):
            result.append(ast_context.bvult(node, ast_context.bv(128, 8)))
            continue
        if values == list(range(1, 256)):
            result.append(node != ast_context.bv(0, 8))
            continue
        alternatives = [node == ast_context.bv(value, 8) for value in values]
        result.append(alternatives[0] if len(alternatives) == 1
                      else ast_context.lor(alternatives))
    return result


def _solve_snapshot_query(context, clauses, variables, seed, timeout, budget):
    from triton import SOLVER_STATE

    remaining_ms = int((budget["deadline"] - time.monotonic()) * 1000)
    if budget["queries"] >= budget["max_queries"] or remaining_ms <= 0:
        raise SnapshotBudgetExhausted("snapshot solver query or wall budget exhausted")
    budget["queries"] += 1
    predicate = clauses[0] if len(clauses) == 1 else context.getAstContext().land(clauses)
    model, status, _ = context.getModel(
        predicate, status=True, timeout=min(timeout, remaining_ms)
    )
    if status == SOLVER_STATE.UNSAT:
        return None, "unsat"
    if status != SOLVER_STATE.SAT:
        for label in ("TIMEOUT", "UNKNOWN", "OUTOFMEM"):
            if status == getattr(SOLVER_STATE, label, None):
                return None, label.lower()
        return None, "unknown"
    candidate = bytearray(seed)
    for index, variable in enumerate(variables):
        value = model.get(variable.getId())
        if value is not None:
            candidate[index] = int(value.getValue())
    return bytes(candidate), "sat"


def _ast_dependencies(node, variable_offsets: dict[int, int],
                      expression_sources: dict[int, int], slice_budget: dict):
    """Bounded structural dependencies, including referenced expression bodies."""
    from triton import AST_NODE

    pending = [node]
    expanded_expressions = set()
    offsets = set()
    sources = set()
    while pending:
        if slice_budget["remaining"] == 0:
            slice_budget["truncated"] = True
            break
        slice_budget["remaining"] -= 1
        current = pending.pop()
        kind = current.getType()
        if kind == AST_NODE.VARIABLE:
            offset = variable_offsets.get(current.getSymbolicVariable().getId())
            if offset is None:
                slice_budget["unknown_variable"] = True
            else:
                offsets.add(offset)
        elif kind == AST_NODE.REFERENCE:
            expression = current.getSymbolicExpression()
            expression_id = expression.getId()
            source = expression_sources.get(expression_id)
            if source is not None:
                sources.add(source)
            if expression_id not in expanded_expressions:
                expanded_expressions.add(expression_id)
                pending.append(expression.getAst())
        pending.extend(current.getChildren())
    return sorted(offsets), sorted(sources)


def _execute_snapshot_seed(plan: dict, seed: bytes, explore: bool, budget: dict,
                           collect_slice: bool = False):
    from triton import EXCEPTION, Instruction

    context, variables = _snapshot_context(plan, seed)
    allowed = _allowed_constraints(context, variables, plan["allowed"])
    prefix = []
    alternatives = []
    seen_constraints = 0
    instructions = 0
    trace = []
    decisions = []
    expression_sources = {}
    variable_offsets = {variable.getId(): index for index, variable in enumerate(variables)}
    slice_budget = {"remaining": MAX_SLICE_AST_NODES, "truncated": False,
                    "unknown_variable": False}
    while instructions < plan["max_instructions"]:
        if time.monotonic() >= budget["deadline"]:
            raise SnapshotBudgetExhausted("snapshot solver wall budget exhausted")
        pc = context.getConcreteRegisterValue(context.registers.rip, callbacks=False)
        offset = pc - plan["code_address"]
        if offset < 0 or offset >= len(plan["code"]):
            raise UnsupportedSnapshot(f"control flow leaves captured code at 0x{pc:x}")
        instruction = Instruction(plan["code"][offset:offset + 15])
        instruction.setAddress(pc)
        context.disassembly(instruction)
        size = instruction.getSize()
        if size <= 0 or offset + size > len(plan["code"]):
            raise UnsupportedSnapshot(f"instruction at 0x{pc:x} exceeds captured code")
        text = instruction.getDisassembly() or ""
        mnemonic = text.split(None, 1)[0].lower() if text else "unknown"
        if mnemonic.startswith(("call", "syscall", "sysenter", "int", "iret", "hlt", "ud2")):
            raise UnsupportedSnapshot(f"unsupported instruction at 0x{pc:x}: {mnemonic}")
        outcome = context.processing(instruction)
        if outcome != EXCEPTION.NO_FAULT:
            raise UnsupportedSnapshot(f"Triton cannot process 0x{pc:x}: {outcome}")
        instructions += 1
        budget["processed_instructions"] += 1
        if collect_slice:
            occurrence = instructions - 1
            trace.append({"index": occurrence, "address": pc,
                          "code_offset": offset, "disassembly": text})
            for expression in instruction.getSymbolicExpressions():
                expression_sources[expression.getId()] = occurrence
        if explore:
            constraints = context.getPathConstraints()
            for constraint in constraints[seen_constraints:]:
                if not constraint.isMultipleBranches():
                    continue
                options = constraint.getBranchConstraints()
                taken = [branch for branch in options if branch["isTaken"]]
                if len(taken) != 1:
                    raise UnsupportedSnapshot(f"ambiguous branch at 0x{pc:x}")
                if collect_slice:
                    if len(decisions) < MAX_SLICE_DECISIONS:
                        offsets, sources = _ast_dependencies(
                            taken[0]["constraint"], variable_offsets,
                            expression_sources, slice_budget
                        )
                        decisions.append({
                            "kind": "branch", "occurrence": occurrence,
                            "address": pc, "taken_target": taken[0]["dstAddr"],
                            "origin_offsets": offsets, "source_occurrences": sources,
                        })
                    else:
                        slice_budget["truncated"] = True
                for branch in options:
                    if branch["isTaken"]:
                        continue
                    candidate, state = _solve_snapshot_query(
                        context, prefix + [branch["constraint"]] + allowed,
                        variables, seed, plan["solver_timeout_ms"], budget
                    )
                    alternatives.append((candidate, state))
                prefix.append(taken[0]["constraint"])
            seen_constraints = len(constraints)
        if mnemonic.startswith("ret"):
            value = context.getConcreteRegisterValue(context.registers.rax, callbacks=False)
            slice_report = None
            if collect_slice and value != plan["return_equals"]:
                offsets, sources = _ast_dependencies(
                    context.getRegisterAst(context.registers.rax), variable_offsets,
                    expression_sources, slice_budget
                )
                decisions.append({
                    "kind": "return", "occurrence": occurrence,
                    "address": pc, "observed_value": value,
                    "origin_offsets": offsets, "source_occurrences": sources,
                })
                relevant = [decision for decision in decisions
                            if decision["origin_offsets"]]
                source_indices = sorted({index for decision in relevant
                                         for index in decision["source_occurrences"]})
                unresolved = [
                    "origin_channel_provenance_unproven_byte_equality_only",
                    "other_paths_and_environment_not_in_this_trace",
                    "symbolic_memory_address_dependencies_not_analyzed",
                ]
                if slice_budget["truncated"]:
                    unresolved.append("slice_ast_or_decision_budget_exhausted")
                if slice_budget["unknown_variable"]:
                    unresolved.append("unmapped_symbolic_variable")
                slice_report = {
                    "schema_version": 1,
                    "kind": "input_condition_slice",
                    "scope": "captured_seed_trace_structural_dependencies",
                    "binary_sha256": plan["binary_sha256"],
                    "input_sha256": plan["input_sha256"],
                    "snapshot_sha256": plan["snapshot_sha256"],
                    "probe_sha256": plan["probe_sha256"],
                    "code_sha256": hashlib.sha256(plan["code"]).hexdigest(),
                    "code_address": plan["code_address"],
                    "origin_id": plan["origin"]["id"],
                    "channel": plan["origin"]["channel"],
                    "channel_offset": plan["origin"]["offset"],
                    "seed_hex": seed.hex(),
                    "observed_return": value,
                    "return_equals": plan["return_equals"],
                    "ast_walk_complete": not slice_budget["truncated"]
                    and not slice_budget["unknown_variable"],
                    "relevant_origin_offsets": sorted({offset for decision in relevant
                                                       for offset in decision["origin_offsets"]}),
                    "source_occurrences": source_indices,
                    "instructions": trace,
                    "decisions": decisions,
                    "unresolved_dependencies": unresolved,
                }
            if not explore:
                return value, None, "not_run", [], instructions, slice_report
            goal = context.getRegisterAst(context.registers.rax) == context.getAstContext().bv(
                plan["return_equals"], 64
            )
            candidate, state = _solve_snapshot_query(
                context, [context.getPathPredicate(), goal] + allowed,
                variables, seed, plan["solver_timeout_ms"], budget
            )
            return value, candidate, state, alternatives, instructions, slice_report
    raise SnapshotBudgetExhausted("snapshot path exceeds instruction budget")


def run_snapshot_return(request: dict) -> dict:
    from triton import VERSION

    plan = validate_snapshot_request(request)
    budget = {
        "deadline": time.monotonic() + plan["wall_timeout_ms"] / 1000,
        "queries": 0,
        "max_queries": plan["max_solver_queries"],
        "processed_instructions": 0,
    }
    queued = [plan["seed"]]
    seen = set()
    explored = 0
    uncertainty = set()
    unsupported = []
    budget_hit = None
    input_condition_slice = None
    while queued and explored < plan["max_seeds"]:
        seed = queued.pop(0)
        if seed in seen:
            continue
        seen.add(seed)
        explored += 1
        try:
            value, candidate, state, alternatives, _, trace_slice = _execute_snapshot_seed(
                plan, seed, True, budget, collect_slice=seed == plan["seed"]
            )
            if trace_slice is not None:
                input_condition_slice = trace_slice
            if state == "sat" and candidate is not None:
                if any(byte not in plan["allowed"] for byte in candidate):
                    raise UnsupportedSnapshot("solver candidate violates origin constraints")
                checked, _, _, _, _, _ = _execute_snapshot_seed(
                    plan, candidate, False, budget
                )
                if checked != plan["return_equals"]:
                    raise UnsupportedSnapshot("candidate does not satisfy concrete Triton replay")
                status = "function_witness"
                witness = candidate.hex()
                break
            uncertainty.add(state)
            for alternative, alternative_state in alternatives:
                if alternative_state != "sat":
                    uncertainty.add(alternative_state)
                elif alternative is not None and alternative not in seen and alternative not in queued:
                    queued.append(alternative)
        except UnsupportedSnapshot as error:
            unsupported.append(str(error))
        except SnapshotBudgetExhausted as error:
            budget_hit = str(error)
            break
    else:
        witness = None
        if queued or budget_hit:
            status = "budget_exhausted"
        elif unsupported:
            status = "unsupported_effect"
        elif "timeout" in uncertainty:
            status = "solver_timeout"
        elif "unknown" in uncertainty or "outofmem" in uncertainty:
            status = "solver_unknown"
        else:
            status = "search_exhausted"
    if budget_hit:
        witness = None
        status = "budget_exhausted"
    return {
        "schema_version": 1,
        "operation": "snapshot_return",
        "backend": "triton",
        "backend_version": f"{VERSION.MAJOR}.{VERSION.MINOR}.{VERSION.BUILD}",
        "binary_sha256": request["binary_sha256"],
        "input_sha256": request["input_sha256"],
        "snapshot_sha256": request["snapshot_sha256"],
        "probe_sha256": request["probe_sha256"],
        "origin_id": plan["origin"]["id"],
        "origin_probe_evidence": "byte_equality_only",
        "assumptions": request["assumptions"],
        "return_equals": plan["return_equals"],
        "status": status,
        "candidate_hex": witness,
        "explored_seeds": explored,
        "processed_instructions": budget["processed_instructions"],
        "solver_queries": budget["queries"],
        "unsupported_paths": len(unsupported),
        "diagnostic": budget_hit or (unsupported[0] if unsupported else None),
        "input_condition_slice": input_condition_slice,
    }


def new_context():
    from triton import ARCH, TritonContext

    context = TritonContext(ARCH.X86_64)
    context.setSolverTimeout(2000)
    context.symbolizeRegister(context.registers.rdi, "arg0")
    context.symbolizeRegister(context.registers.rsi, "arg1")
    return context


def path_witness(context, choices: tuple[int, ...]) -> list[int] | None:
    """Solve the selected branch at each replayed conditional instruction."""
    from triton import SOLVER_STATE

    branches = [constraint.getBranchConstraints()
                for constraint in context.getPathConstraints()
                if constraint.isMultipleBranches()]
    if len(branches) != len(choices):
        fail("Triton path constraints differ from replayed branch choices")
    selected = []
    for options, choice in zip(branches, choices):
        if choice >= len(options):
            fail("Triton branch choice is outside replayed constraints")
        selected.append(options[choice]["constraint"])
    if not selected:
        return [0, 0]
    predicate = selected[0] if len(selected) == 1 else context.getAstContext().land(selected)
    model, status, _ = context.getModel(predicate, status=True, timeout=2000)
    if status == SOLVER_STATE.UNSAT:
        return None
    if status != SOLVER_STATE.SAT:
        for label in ("TIMEOUT", "UNKNOWN", "OUTOFMEM"):
            if status == getattr(SOLVER_STATE, label):
                fail(f"Triton solver returned {label.lower()} for a path witness")
        fail(f"Triton solver returned unrecognized status {status!r} for a path witness")
    values = []
    for alias in ("arg0", "arg1"):
        variable = context.getSymbolicVariable(alias)
        solution = model.get(variable.getId())
        values.append(int(solution.getValue()) if solution is not None else 0)
    return values


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
    return str(context.getAstContext().unroll(expression.getAst()))


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
        if request.get("operation") == "snapshot_return":
            json.dump(run_snapshot_return(request), sys.stdout, sort_keys=True)
            sys.stdout.write("\n")
            return
        symbol, digest, address, code = validate_request(request)

        instructions: dict[int, dict] = {}
        paths = [(tuple(), 0, tuple(), frozenset(), tuple())]
        path_results: list[dict] = []

        while paths:
            trace, offset, conditions, visited, choices = paths.pop()
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
                witness = path_witness(context, choices)
                if witness is None:
                    continue
                path_results.append(
                    {
                        "path_condition": "(and " + " ".join(conditions) + ")"
                        if conditions
                        else "true",
                        "rax": register_ast(context, context.registers.rax),
                        "input_witness": witness,
                    }
                )
                continue

            if mnemonic.startswith("call"):
                fail(f"call at 0x{address + offset:x} is unsupported")
            if not instruction.isControlFlow():
                next_offset = offset + size
                if next_offset >= len(code):
                    fail(f"non-returning instruction at 0x{address + offset:x} reaches symbol end")
                paths.append((next_trace, next_offset, conditions, next_visited, choices))
                continue

            if mnemonic.startswith("jmp"):
                target = direct_target(instruction)
                if target is None:
                    fail(f"unresolved control flow at 0x{address + offset:x}")
                next_offset = target_offset(target, address, code)
                if next_offset in next_visited:
                    fail(f"control-flow loop at 0x{target:x} is unsupported")
                paths.append((next_trace, next_offset, conditions, next_visited, choices))
                continue

            constraints = context.getPathConstraints()
            if not constraints:
                fail(f"unresolved control flow at 0x{address + offset:x}")
            branches = constraints[-1].getBranchConstraints()
            if not branches:
                fail(f"unresolved control flow at 0x{address + offset:x}")
            for choice, branch in enumerate(branches):
                target = int(branch["dstAddr"])
                next_offset = target_offset(target, address, code)
                if next_offset in next_visited:
                    fail(f"control-flow loop at 0x{target:x} is unsupported")
                paths.append(
                    (
                        next_trace,
                        next_offset,
                        conditions + (str(context.getAstContext().unroll(branch["constraint"])),),
                        next_visited,
                        choices + (choice,),
                    )
                )
                if len(paths) + len(path_results) > MAX_PATHS:
                    fail("control-flow path count exceeds 64-path limit")

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
