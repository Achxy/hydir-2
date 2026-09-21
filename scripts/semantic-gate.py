#!/usr/bin/env python3
"""Native Linux evidence gate for trusted scalar machine-code fixtures.

Unsupported compiler output is recorded, not counted as a semantic mismatch.
All artifacts and the JSON report are written under target/semantic-gate.
"""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONS = ("identity", "add", "max", "xor")
ASSEMBLY_FUNCTIONS = (
    "leaf_add", "call_leaf_add", "mov_imm64", "cmp_imm", "test_imm",
    "identity_a", "identity_b", "zeroextend_a", "zeroextend_imm", "frame_balance",
    "stack_slot_add", "stack_branch", "dword_redzone_add", "dword_redzone_max_s",
    "nop_identity", "lea_scaled", "lea_rip",
    "sub_ab", "sub_ba", "add3", "twice_a",
    "twice_b", "min_u", "min_s", "equal", "not_equal", "less_u",
    "less_s", "bit_overlap", "repeat3", "repeat4",
    "cond_e", "cond_ne", "cond_g", "cond_ge", "cond_l", "cond_le",
    "cond_a", "cond_ae", "cond_b", "cond_be", "cond_s", "cond_ns",
    "cond_o", "cond_no",
)
LEVELS = ("0", "1", "2")
CONDITION_FUNCTIONS = tuple(f"hydir_cond_{suffix}" for suffix in (
    "e", "ne", "g", "ge", "l", "le", "a", "ae", "b", "be", "s", "ns", "o", "no",
))


def source_identity():
    """Hash gate inputs by path and content, including untracked source files."""
    paths = [ROOT / "Cargo.toml", ROOT / "Cargo.lock"]
    for directory in ("crates", "tests/fixtures"):
        paths.extend(path for path in (ROOT / directory).rglob("*") if path.is_file())
    paths.extend((ROOT / "scripts/semantic-gate.py", ROOT / "scripts/triton_bridge.py",
                  ROOT / "tests/instruction_oracle_test.py",
                  ROOT / "tests/semantic_gate_report_test.py"))
    digest = hashlib.sha256()
    for path in sorted(paths):
        relative = path.relative_to(ROOT).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def run(command, *, timeout=120, env=None):
    start = time.perf_counter()
    completed = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, check=False,
        env=env,
    )
    return completed, round(time.perf_counter() - start, 6)


def check_validation_report(report, binary, symbol, backend, expected_cases, external_cases):
    """Reject incomplete validator output before recording a semantic match."""
    if not isinstance(report, dict):
        return "validator report is not an object"
    expected_backend = "raw LLVM" if backend == "llvm" else "HydIR scalar LLVM-to-C"
    if report.get("binary") != str(binary.resolve()) or report.get("function") != symbol:
        return "validator report identifies a different binary or function"
    if report.get("backend") != expected_backend:
        return "validator report identifies a different backend"
    mismatched = report.get("cases_mismatched")
    if type(mismatched) is not int or not 0 <= mismatched <= expected_cases:
        return "validator report has invalid cases_mismatched"
    for name, expected in (("cases_attempted", expected_cases),
                           ("external_cases_attempted", external_cases),
                           ("cases_matched", expected_cases - mismatched)):
        actual = report.get(name)
        if type(actual) is not int or actual != expected:
            return f"validator report has invalid {name}"
    samples = report.get("mismatches")
    if not isinstance(samples, list) or (mismatched > 0 and not samples):
        return "validator report has no mismatch samples"
    if len(samples) > mismatched:
        return "validator report has more mismatch samples than mismatches"
    if report.get("result") != ("fail" if mismatched else "pass"):
        return "validator report result conflicts with case counts"
    return None


def parse_solver_witnesses(output):
    """Use only distinct, bounded two-register models from the bridge."""
    report = json.loads(output)
    paths = report["paths"]
    if not isinstance(paths, list) or not paths:
        raise ValueError("solver returned no paths")
    witnesses = [path["input_witness"] for path in paths]
    if any(not isinstance(witness, list) or len(witness) != 2
           or any(type(value) is not int or not 0 <= value <= 2**64 - 1
                  for value in witness) for witness in witnesses):
        raise ValueError("solver returned an invalid two-u64 witness")
    if len({tuple(witness) for witness in witnesses}) != len(witnesses):
        raise ValueError("solver returned duplicate path witnesses")
    return witnesses


def annotate_failure(message):
    """Expose gate failures in the public Actions job annotations."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::error title=Semantic gate failure::{escaped}", file=sys.stderr)


def main():
    started = time.perf_counter()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--random-cases", type=int, default=64)
    parser.add_argument("--compilers", nargs="+", default=["clang", "gcc"])
    parser.add_argument("--require-triton-witness", action="store_true")
    parser.add_argument("--require-triton-conditions", action="store_true",
                        help="require two Triton return-path witnesses for every condition fixture")
    parser.add_argument("--require-assembly-coverage", action="store_true",
                        help="require every declared hand-assembly fixture to match both backends")
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("semantic gate requires native Linux x86-64")
    import resource
    if not 0 <= args.random_cases <= 10000:
        parser.error("random cases must be 0..=10000")
    for tool in (*args.compilers, "clang", "opt", "cargo"):
        if shutil.which(tool) is None:
            parser.error(f"required tool unavailable: {tool}")

    stamp = time.strftime("%Y%m%d-%H%M%S")
    output = ROOT / "target" / "semantic-gate" / stamp
    output.mkdir(parents=True, exist_ok=False)
    built, _ = run(["cargo", "build", "--locked", "-q", "-p", "hydir-cli"], timeout=600)
    if built.returncode:
        raise RuntimeError(built.stderr)
    hydir = ROOT / "target" / "debug" / "hydirctl"
    triton_python = os.environ.get("HYDIR_TRITON_PYTHON", sys.executable)
    triton_check, _ = run([triton_python, "-c", "from triton import ARCH, TritonContext"])
    triton_available = triton_check.returncode == 0
    if (args.require_triton_witness or args.require_triton_conditions) and not triton_available:
        parser.error("required Triton binary-analysis bindings are unavailable")
    triton_env = {**os.environ, "HYDIR_TRITON_PYTHON": triton_python}
    versions = {}
    for tool in (*args.compilers, "clang", "opt", "rustc"):
        if tool not in versions:
            version, _ = run([tool, "--version"])
            versions[tool] = version.stdout.splitlines()[0] if version.stdout else "unknown"
    if triton_available:
        version, _ = run([triton_python, "-c",
                          "import importlib.metadata as m; print(m.version('triton-library'))"])
        versions["triton-library"] = version.stdout.strip() or "unknown"
        oracle, oracle_seconds = run(
            [triton_python, str(ROOT / "tests/instruction_oracle_test.py"), "-q"], timeout=120)
        oracle_status = "failed" if oracle.returncode else "passed"
        oracle_error = oracle.stderr[-2000:] if oracle.returncode else None
    else:
        oracle_seconds = None
        oracle_status = "unavailable"
        oracle_error = None
    git_revision, _ = run(["git", "rev-parse", "HEAD"])
    tasks = [
        (compiler, level, f"hydir_opt_{function}", "optimized_scalar.c", "compiler_c")
        for compiler in args.compilers for level in LEVELS for function in FUNCTIONS
    ]
    tasks += [
        ("clang", "0", f"hydir_{function}", "scalar_corpus.S", "hand_assembly")
        for function in ASSEMBLY_FUNCTIONS
    ]
    rows = []
    for compiler, level, symbol, source, origin in tasks:
        label = f"{compiler}-O{level}-{symbol}"
        binary = output / label
        row = {"compiler": compiler, "optimization": f"O{level}",
               "function": symbol, "origin": origin, "status": "attempted"}
        rows.append(row)
        build, elapsed = run([
            compiler, f"-O{level}", "-no-pie", f"-DHYDIR_FUNCTION={symbol}",
            str(ROOT / "tests/fixtures" / source),
            str(ROOT / "tests/fixtures/scalar_main.c"), "-o", str(binary),
        ])
        row["build_seconds"] = elapsed
        if build.returncode:
            row.update(status="build_error", reason=build.stderr[-2000:])
            continue
        row["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        inventory, _ = run([str(hydir), "disassemble", str(binary)])
        if inventory.returncode:
            row.update(status="inventory_error", reason=inventory.stderr[-2000:])
            continue
        try:
            decoded = json.loads(inventory.stdout)
            addresses = next(set(function["instruction_addresses"])
                             for function in decoded["functions"]
                             if function["name"] == symbol)
            if not addresses:
                raise ValueError("selected function has no decoded instruction addresses")
            row["instruction_families"] = sorted({
                instruction["mnemonic"] for instruction in decoded["instructions"]
                if instruction["address"] in addresses
            })
        except (ValueError, KeyError, TypeError, StopIteration) as error:
            row.update(status="inventory_error", reason=f"invalid disassembly report: {error}")
            continue
        ir = output / f"{label}.ll"
        lifted, elapsed = run([
            str(hydir), "lift", str(binary), symbol,
            "--assume-u64x2", "--output", str(ir),
        ])
        row["lift_seconds"] = elapsed
        if lifted.returncode:
            row.update(status="rejected", reason=lifted.stderr.strip()[-2000:])
            continue
        row["lift_succeeded"] = True
        verified, _ = run(["opt", "-passes=verify", "-disable-output", str(ir)])
        if verified.returncode:
            row.update(status="invalid_ir", reason=verified.stderr[-2000:])
            continue
        row["ir_verified"] = True
        row["status"] = "supported"
        model_file = None
        if symbol in ("hydir_stack_slot_add", "hydir_stack_branch"):
            inspected, _ = run([str(hydir), "inspect", str(binary)])
            if inspected.returncode:
                row.update(status="validation_error", reason=inspected.stderr[-2000:])
                continue
            try:
                spec = json.loads(inspected.stdout)
                entry = next(function["address"] for function in spec["functions"]
                             if function["name"] == symbol)
                typed_model = spec["typed_model"]
                if not isinstance(typed_model, dict):
                    raise TypeError("typed_model is not an object")
            except (ValueError, KeyError, TypeError, StopIteration) as error:
                row.update(status="validation_error", reason=f"invalid model inspection report: {error}")
                continue
            provenance = {"source": "analyst_assertion",
                          "scope": "trusted hand-assembly stack fixture"}
            typed_model["prototypes"] = [{
                "id": "prototype-stack-fixture", "entry": entry,
                "return_type": "u64", "parameters": ["u64", "u64"],
                "calling_convention": "sysv_amd64", "provenance": provenance,
            }]
            typed_model["stack_facts"] = [{
                "id": "stack-slot-minus-16", "function_entry": entry,
                "entry_rsp_offset": -16, "width_bits": 64,
                "provenance": provenance,
            }]
            model_file = output / f"{label}.model.json"
            model_file.write_text(json.dumps(spec) + "\n", encoding="utf-8")
            row["typed_model_file_sha256"] = hashlib.sha256(model_file.read_bytes()).hexdigest()
        cases_file = None
        if triton_available:
            symbolic, elapsed = run([str(hydir), "triton", str(binary), symbol],
                                    timeout=120, env=triton_env)
            row["triton_seconds"] = elapsed
            if symbolic.returncode == 0:
                try:
                    witnesses = parse_solver_witnesses(symbolic.stdout)
                except (ValueError, KeyError, TypeError) as error:
                    row["triton_status"] = "rejected"
                    row["triton_reason"] = f"invalid solver report: {error}"
                else:
                    cases_file = output / f"{label}.solver-cases.json"
                    cases_file.write_text(json.dumps([[str(a), str(b)] for a, b in witnesses]) + "\n",
                                          encoding="utf-8")
                    row["triton_status"] = "solved"
                    row["solver_cases"] = len(witnesses)
                    row["solver_branch_paths"] = len(witnesses) if len(witnesses) > 1 else 0
                    row["solver_cases_sha256"] = hashlib.sha256(cases_file.read_bytes()).hexdigest()
            else:
                row["triton_status"] = "rejected"
                row["triton_reason"] = symbolic.stderr.strip()[-1000:]
        else:
            row["triton_status"] = "unavailable"
        for backend, command in (("llvm", "validate"), ("c", "validate-c")):
            case_args = ["--cases-file", str(cases_file)] if cases_file else []
            model_args = ["--model", str(model_file)] if model_file else []
            checked, elapsed = run([
                str(hydir), command, str(binary), symbol,
                "--assume-u64x2", "--trusted-fixture",
                "--clang", "clang", "--random-cases", str(args.random_cases),
                *case_args,
                *model_args,
            ], timeout=600)
            row[f"{backend}_seconds"] = elapsed
            try:
                report = json.loads(checked.stdout)
            except ValueError:
                report = None
            report_error = check_validation_report(
                report, binary, symbol, backend,
                8 + args.random_cases + row.get("solver_cases", 0),
                row.get("solver_cases", 0),
            )
            if report_error:
                row.update(status="validation_error", reason=report_error)
                break
            row[f"{backend}_cases_attempted"] = report["cases_attempted"]
            row[f"{backend}_cases_mismatched"] = report["cases_mismatched"]
            if model_file:
                evidence = report.get("typed_model_evidence")
                row[f"{backend}_typed_model_evidence"] = evidence
                if (not isinstance(evidence, dict)
                        or evidence.get("stack_assertions") != ["stack-slot-minus-16"]
                        or evidence.get("prototype_assertion") != "prototype-stack-fixture"
                        or evidence.get("binary_sha256") != row["binary_sha256"]
                        or not isinstance(evidence.get("typed_model_sha256"), str)
                        or len(evidence["typed_model_sha256"]) != 64):
                    row["typed_model_evidence_error"] = "typed validation report omitted or changed an assertion identity"
            if report["cases_mismatched"]:
                row[f"{backend}_mismatches"] = report["mismatches"]
                row["status"] = "mismatch"
                row["reason"] = "validator reported divergent native and lifted results"
                break
            if checked.returncode:
                row["status"] = "validation_error"
                row["reason"] = checked.stderr.strip()[-2000:]
                break
            if row.get("typed_model_evidence_error"):
                row["status"] = "validation_error"
                row["reason"] = row["typed_model_evidence_error"]
                break
        else:
            row["status"] = "matched"

    counts = {status: sum(row["status"] == status for row in rows)
              for status in ("attempted", "rejected", "matched", "mismatch",
                             "build_error", "inventory_error", "invalid_ir", "validation_error")}
    counts["attempted"] = len(rows)
    counts["supported"] = sum(row.get("lift_succeeded", False) for row in rows)
    counts["verified"] = sum(row.get("ir_verified", False) for row in rows)
    counts["triton_solved"] = sum(row.get("triton_status") == "solved" for row in rows)
    counts["triton_rejected"] = sum(row.get("triton_status") == "rejected" for row in rows)
    counts["triton_unavailable"] = sum(row.get("triton_status") == "unavailable" for row in rows)
    counts["solver_branch_functions"] = sum(row.get("solver_branch_paths", 0) > 1 for row in rows)
    counts["hand_assembly_attempted"] = sum(row["origin"] == "hand_assembly" for row in rows)
    counts["hand_assembly_matched"] = sum(row["origin"] == "hand_assembly"
                                          and row["status"] == "matched" for row in rows)
    family_counts = {}
    setting_counts = {}
    for row in rows:
        setting = f"{row['compiler']}-{row['optimization']}"
        buckets = [setting_counts.setdefault(setting, {})]
        buckets.extend(family_counts.setdefault(family, {})
                       for family in row.get("instruction_families", []))
        for bucket in buckets:
            bucket["attempted"] = bucket.get("attempted", 0) + 1
            bucket[row["status"]] = bucket.get(row["status"], 0) + 1
    summary = {
        "schema_version": 1,
        "scope": "trusted native Linux x86-64 compiler-output coverage",
        "random_cases_per_backend": args.random_cases,
        "triton_python": triton_python if triton_available else None,
        "triton_available": triton_available,
        "instruction_oracle": oracle_status,
        "instruction_oracle_error": oracle_error,
        "instruction_oracle_seconds": oracle_seconds,
        "tool_versions": versions,
        "git_revision": git_revision.stdout.strip() if git_revision.returncode == 0 else None,
        "source_tree_sha256": source_identity(),
        "counts": counts,
        "by_compiler_setting": setting_counts,
        "by_instruction_family": family_counts,
        "peak_child_rss_kib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
        "wall_seconds": round(time.perf_counter() - started, 6),
        "rows": rows,
    }
    report = output / "report.json"
    report.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"{report}: {counts}")
    failed = any(row["status"] in ("mismatch", "build_error", "inventory_error", "invalid_ir", "validation_error")
                 for row in rows)
    if args.require_triton_witness and counts["solver_branch_functions"] == 0:
        print("semantic gate lacked a Triton witness for any branched function", file=sys.stderr)
        failed = True
    if args.require_triton_conditions:
        missing_conditions = [row["function"] for row in rows
                              if row["function"] in CONDITION_FUNCTIONS
                              and (row.get("triton_status") != "solved"
                                   or row.get("solver_branch_paths", 0) < 2)]
        if missing_conditions:
            print("semantic gate lacked two Triton paths for: "
                  + ", ".join(missing_conditions), file=sys.stderr)
            failed = True
    if args.require_assembly_coverage and counts["hand_assembly_matched"] != len(ASSEMBLY_FUNCTIONS):
        print("semantic gate failed declared hand-assembly coverage: "
              f"{counts['hand_assembly_matched']}/{len(ASSEMBLY_FUNCTIONS)} matched",
              file=sys.stderr)
        failed = True
    if oracle_status == "failed":
        print("Triton instruction-state oracle failed", file=sys.stderr)
        failed = True
    if failed:
        failing_rows = [row for row in rows if row["status"] in
                        ("mismatch", "build_error", "inventory_error", "invalid_ir", "validation_error")]
        for row in failing_rows[:20]:
            label = f"{row['compiler']}-{row['optimization']}-{row['function']}"
            annotate_failure(f"{label}: {row['status']}: {row.get('reason', 'no reason recorded')[:240]}")
        if len(failing_rows) > 20:
            annotate_failure(f"{len(failing_rows) - 20} additional rows failed; see report artifact")
        if args.require_triton_witness and counts["solver_branch_functions"] == 0:
            annotate_failure("No Triton witness for a branched function")
        if args.require_triton_conditions and missing_conditions:
            annotate_failure("Missing Triton condition paths: " + ", ".join(missing_conditions))
        if args.require_assembly_coverage and counts["hand_assembly_matched"] != len(ASSEMBLY_FUNCTIONS):
            annotate_failure(f"Hand-assembly coverage: {counts['hand_assembly_matched']}/{len(ASSEMBLY_FUNCTIONS)} matched")
        if oracle_status == "failed":
            annotate_failure("Triton instruction-state oracle failed: " + (oracle_error or "unknown error")[:240])
    return int(failed)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(f"semantic gate infrastructure failure: {error}", file=sys.stderr)
        sys.exit(2)
