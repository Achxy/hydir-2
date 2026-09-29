#!/usr/bin/env python3
"""Opt-in comparison of Hydir and Patchestry exports from the same ELF.

Only decompiler high P-code operations are compared. Hydir's raw instruction
P-code is a different representation and is deliberately excluded.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = {
    "add-zero": (
        "tests/fixtures/ghidra_add_zero.elf",
        "tests/fixtures/ghidra_add_zero_v2.json",
        "hydir_add_zero",
    ),
    "choose-branch": (
        "tests/fixtures/ghidra_choose_calls.elf",
        "tests/fixtures/ghidra_choose_root_v2.json",
        "hydir_choose",
    ),
    "prism-branch": (
        "demo/hydir-prism.elf",
        "tests/fixtures/ghidra_prism_bit_gate_oracle_v2.json",
        "hydir_stage_bit_gate",
    ),
    "password-memory": (
        "tests/fixtures/hydir-password-gate-stripped.elf",
        "tests/fixtures/ghidra_password_secure_equals_o1_v2.json",
        "FUN_002016d0",
    ),
}
OP_LABEL = re.compile(r"^([^:]+):([0-9a-fA-F]+):([0-9]+):([0-9]+)$")
COMPAT_LINE = "case PcodeOp.EXTRACT:        case PcodeOp.INSERT:"


def ghidra_version(ghidra_home: Path) -> str:
    properties = ghidra_home / "Ghidra" / "application.properties"
    for line in properties.read_text(encoding="utf-8").splitlines():
        if line.startswith("application.version="):
            return line.partition("=")[2].strip()
    raise ValueError(f"application.version missing in {properties}")


def git_revision(patchestry: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(patchestry), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def prepare_scripts(source: Path, destination: Path) -> None:
    if not (source / "PatchestryDecompileFunctions.java").is_file():
        raise ValueError(f"Patchestry exporter missing in {source}")
    destination.mkdir()
    for java_file in source.glob("*.java"):
        shutil.copy2(java_file, destination / java_file.name)
    for package in ("domain", "util"):
        shutil.copytree(source / package, destination / package)

    # Patchestry references two opcode constants absent from official Ghidra
    # 12.1.4 in a scalar-type classifier. Neither occurs in these fixtures.
    # Patch an ephemeral copy only; leave the comparison checkout untouched.
    serializer = destination / "util" / "PcodeSerializer.java"
    content = serializer.read_text(encoding="utf-8")
    if content.count(COMPAT_LINE) != 1:
        raise ValueError("Unexpected Patchestry serializer; review compatibility shim")
    serializer.write_text(content.replace(COMPAT_LINE, ""), encoding="utf-8")


def hydir_operations(snapshot: dict) -> Counter[tuple[str, int, str]]:
    high = snapshot["selected_function"]["high_pcode"]
    if high["status"] != "complete":
        raise ValueError(f"Hydir high P-code status is {high['status']!r}")
    return Counter(
        (
            op["source_address"]["space"],
            int(op["source_address"]["offset"], 0),
            op["mnemonic"],
        )
        for op in high["operations"]
    )


def patchestry_operations(
    program: dict, entry_space: str, entry_offset: int
) -> tuple[Counter[tuple[str, int, str]], Counter[str], dict]:
    selected = [
        function
        for function in program["functions"].values()
        if function.get("entry_point")
        and parse_entry(function["entry_point"]) == (entry_space, entry_offset)
    ]
    if len(selected) != 1:
        raise ValueError(f"Expected one Patchestry function at {entry_space}:{entry_offset:x}")
    function = selected[0]
    source_ops: Counter[tuple[str, int, str]] = Counter()
    synthetic: Counter[str] = Counter()
    for block in function.get("basic_blocks", {}).values():
        operations = block["operations"]
        order = block["ordered_operations"]
        if len(order) != len(operations) or set(order) != set(operations):
            raise ValueError("Patchestry block operation order does not match its map")
        for label in order:
            op = operations[label]
            match = OP_LABEL.fullmatch(label)
            if match and match[1] == entry_space:
                source_ops[(match[1], int(match[2], 16), op["mnemonic"])] += 1
            else:
                synthetic[op["mnemonic"]] += 1
    return source_ops, synthetic, function


def parse_entry(label: str) -> tuple[str, int]:
    space, offset = label.split(":", 1)
    return space, int(offset, 16)


def expanded(operations: Counter[tuple[str, int, str]]) -> list[dict]:
    return [
        {"space": space, "address": f"0x{address:x}", "mnemonic": mnemonic}
        for (space, address, mnemonic), count in sorted(operations.items())
        for _ in range(count)
    ]


def compare_fixture(
    name: str,
    ghidra_home: Path,
    version: str,
    script_dir: Path,
    scratch: Path,
    output_dir: Path,
) -> dict:
    binary_name, snapshot_name, function_name = FIXTURES[name]
    binary = ROOT / binary_name
    snapshot_path = ROOT / snapshot_name
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if snapshot["binary_sha256"] != digest:
        raise ValueError(f"{snapshot_name} has a stale binary digest")
    if snapshot["program"]["ghidra_version"] != version:
        raise ValueError(
            f"{snapshot_name} uses Ghidra {snapshot['program']['ghidra_version']}; "
            f"installed version is {version}"
        )
    entry = snapshot["selected_function"]["entry"]
    entry_space, entry_offset = entry["space"], int(entry["offset"], 0)
    if not any(
        function["entry"] == entry and function["name"] == function_name
        for function in snapshot["functions"]
    ):
        raise ValueError(f"{snapshot_name} does not identify {function_name} at selected entry")

    analyzer = ghidra_home / "support" / (
        "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    )
    output_path = output_dir / f"{name}.patchestry.json"
    log_path = output_dir / f"{name}.ghidra.log"
    command = [
        str(analyzer),
        str(scratch),
        f"hydir_patchestry_{name.replace('-', '_')}",
        "-readOnly",
        "-deleteProject",
        "-import",
        str(binary),
        "-scriptPath",
        str(script_dir),
        "-postScript",
        "PatchestryDecompileFunctions",
        "single",
        function_name,
        str(output_path),
        "--no-repair-function-boundaries",
    ]
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, errors="replace", timeout=300, check=False,
    )
    log_path.write_text(result.stdout, encoding="utf-8")
    # Ghidra can exit zero after a post-script exception. Check its output too.
    if result.returncode or not output_path.is_file() or not output_path.stat().st_size:
        raise RuntimeError(
            f"Patchestry export failed for {name} (exit {result.returncode}); see {log_path}"
        )
    program = json.loads(output_path.read_text(encoding="utf-8"))
    if program["id"] != snapshot["program"]["language_id"]:
        raise ValueError(f"{name}: Ghidra language differs between exporters")

    hydir = hydir_operations(snapshot)
    if any(mnemonic in {"EXTRACT", "INSERT"} for _, _, mnemonic in hydir):
        raise ValueError(f"{name}: compatibility shim touches a fixture opcode")
    patchestry, synthetic, function = patchestry_operations(
        program, entry_space, entry_offset
    )
    if function["name"] != function_name:
        raise ValueError(f"{name}: Patchestry selected a different function")
    common = hydir & patchestry
    missing = hydir - patchestry
    extra = patchestry - hydir
    return {
        "fixture": name,
        "binary": binary.relative_to(ROOT).as_posix(),
        "binary_sha256": digest,
        "hydir_snapshot": snapshot_path.relative_to(ROOT).as_posix(),
        "function": function_name,
        "entry": f"{entry_space}:0x{entry_offset:x}",
        "hydir_high_ops": sum(hydir.values()),
        "patchestry_source_ops": sum(patchestry.values()),
        "matched_high_ops": sum(common.values()),
        "missing_from_patchestry": expanded(missing),
        "extra_in_patchestry": expanded(extra),
        "patchestry_synthetic_ops": dict(sorted(synthetic.items())),
        "agree": not missing and not extra,
        "patchestry_export": output_path.name,
        "ghidra_log": log_path.name,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--patchestry", type=Path, required=True, help="local Patchestry checkout")
    parser.add_argument(
        "--ghidra-home", type=Path,
        default=os.environ.get("HYDIR_GHIDRA_HOME") or os.environ.get("GHIDRA_HOME"),
        required=not (os.environ.get("HYDIR_GHIDRA_HOME") or os.environ.get("GHIDRA_HOME")),
    )
    parser.add_argument("--fixture", choices=("all", *FIXTURES), default="all")
    parser.add_argument(
        "--require-agreement", action="store_true",
        help="exit nonzero if source-addressed high P-code differs",
    )
    parser.add_argument(
        "--output-dir", type=Path,
        default=ROOT / "target" / "patchestry-comparison",
    )
    args = parser.parse_args()
    patchestry = args.patchestry.resolve(strict=True)
    ghidra_home = args.ghidra_home.resolve(strict=True)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    version = ghidra_version(ghidra_home)
    if version != "12.1.4":
        raise ValueError(f"Comparator fixtures were saved from Ghidra 12.1.4, got {version}")
    names = list(FIXTURES) if args.fixture == "all" else [args.fixture]

    with tempfile.TemporaryDirectory(prefix="hydir_patchestry_") as temporary:
        scratch = Path(temporary)
        if any(part.startswith(".") for part in scratch.parts):
            raise ValueError("Ghidra project path contains a dot-prefixed directory")
        script_dir = scratch / "scripts"
        prepare_scripts(patchestry / "scripts" / "ghidra", script_dir)
        results = [
            compare_fixture(name, ghidra_home, version, script_dir, scratch, output_dir)
            for name in names
        ]

    report = {
        "schema_version": 1,
        "comparison_scope": "source-addressed Ghidra decompiler high P-code mnemonics",
        "not_a_semantic_equivalence_proof": True,
        "all_agree": all(result["agree"] for result in results),
        "ghidra_version": version,
        "patchestry_revision": git_revision(patchestry),
        "compatibility_shim": "removed absent PcodeOp.EXTRACT/INSERT scalar classifier cases from temporary copy",
        "results": results,
    }
    report_path = output_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for result in results:
        print(
            f"{result['fixture']}: {result['matched_high_ops']}/{result['hydir_high_ops']} "
            f"Hydir high ops, {result['matched_high_ops']}/{result['patchestry_source_ops']} "
            f"Patchestry source ops matched; synthetic "
            f"{result['patchestry_synthetic_ops']}"
        )
        for direction in ("missing_from_patchestry", "extra_in_patchestry"):
            for op in result[direction]:
                print(f"  {direction}: {op['space']}:{op['address']} {op['mnemonic']}")
    print(f"Report: {report_path}")
    return 1 if args.require_agreement and not report["all_agree"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"Patchestry comparison failed: {error}", file=sys.stderr)
        sys.exit(2)
