#!/usr/bin/env python3
"""Compare HydIR candidate entries with labelled Ghidra/DDisasm evidence.

This is a read-only comparison. External entries never become HydIR lift bounds.
"""

import argparse
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def address(value):
    if not isinstance(value, str) or not value.startswith("0x"):
        raise ValueError(f"expected hexadecimal address, got {value!r}")
    parsed = int(value, 16)
    if not 0 <= parsed < 1 << 64:
        raise ValueError(f"address exceeds u64: {value}")
    return parsed


def ghidra_entries(path):
    graph = json.loads(path.read_text(encoding="utf-8"))
    if graph.get("schema_version") != 1 or graph.get("source") != "ghidra":
        raise ValueError("expected HydIR Ghidra graph export schema 1")
    functions = graph.get("functions")
    if not isinstance(functions, list):
        raise ValueError("Ghidra export has no functions array")
    entries = {}
    for function in functions:
        entry = address(function["entry"])
        entries.setdefault(entry, []).append(str(function["name"]))
    return entries, {"source": "ghidra", "artifact_sha256": digest(path),
                     "program_label": graph.get("program"),
                     "binary_identity": "unverified_external_label"}


def ddisasm_entries(path):
    try:
        import gtirb
        from gtirb_functions import Function
    except ImportError as error:
        raise ValueError("GTIRB comparison requires matching gtirb and gtirb-functions packages") from error
    ir = gtirb.IR.load_protobuf(str(path))
    entries = {}
    for module in ir.modules:
        for function in Function.build_functions(module):
            for block in function.get_entry_blocks():
                if block.address is None:
                    continue
                entries.setdefault(block.address, []).append(function.get_name())
    return entries, {"source": "ddisasm_gtirb", "artifact_sha256": digest(path),
                     "binary_identity": "unverified_external_artifact"}


def compare(native, external, metadata):
    native_entries = set(native)
    external_entries = set(external)
    return {**metadata,
            "agreement": [f"0x{entry:016x}" for entry in sorted(native_entries & external_entries)],
            "hydir_only": [f"0x{entry:016x}" for entry in sorted(native_entries - external_entries)],
            "external_only": [f"0x{entry:016x}" for entry in sorted(external_entries - native_entries)],
            "external_names": {f"0x{entry:016x}": names
                               for entry, names in sorted(external.items())}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("hydir_disassembly_json", type=Path,
                        help="output of hydirctl disassemble for the same binary")
    parser.add_argument("--ghidra", type=Path, help="HydIRExport.java graph JSON")
    parser.add_argument("--ddisasm-gtirb", type=Path, help="GTIRB produced by DDisasm")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.ghidra and not args.ddisasm_gtirb:
        parser.error("provide --ghidra or --ddisasm-gtirb")
    try:
        native = json.loads(args.hydir_disassembly_json.read_text(encoding="utf-8"))
        binary_sha256 = digest(args.binary)
        if native.get("schema_version") != 2 or native.get("binary_sha256") != binary_sha256:
            raise ValueError("HydIR disassembly schema or binary identity mismatch")
        native_entries = {address(candidate["entry"]): candidate
                          for candidate in native["candidates"]}
        sources = []
        if args.ghidra:
            sources.append(compare(native_entries, *ghidra_entries(args.ghidra)))
        if args.ddisasm_gtirb:
            sources.append(compare(native_entries, *ddisasm_entries(args.ddisasm_gtirb)))
        report = {
            "schema_version": 1,
            "binary_sha256": binary_sha256,
            "hydir_disassembly_sha256": digest(args.hydir_disassembly_json),
            "hydir_candidates": native["candidates"],
            "external_comparisons": sources,
            "trust_boundary": "external entries are comparison evidence only; no candidate extent or lift boundary is established",
        }
        output = json.dumps(report, indent=2) + "\n"
        if args.output:
            if args.output.exists():
                raise ValueError("output already exists")
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
