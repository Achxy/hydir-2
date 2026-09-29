"""Real Linux Frida/Bubblewrap gate for two PIE paths and an indirect call."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
OBSERVER = Path(os.environ["HYDIR_FRIDA_OBSERVER"])


def symbol_addresses(binary):
    output = subprocess.check_output(["nm", "-n", binary], text=True)
    return {
        fields[2]: int(fields[0], 16)
        for line in output.splitlines()
        if len(fields := line.split()) == 3
    }


def run_one(binary, symbols, value, scratch):
    elf = binary.read_bytes()
    spec = {
        "schema_version": 1,
        "binary_sha256": hashlib.sha256(elf).hexdigest(),
        "argv_hex": [value.encode().hex()],
        "stdin_hex": "",
        "files": [],
        "origins": [],
        "goal": {"exit_code": 0, "stdout_contains_hex": None, "stderr_contains_hex": None},
        "budget": {"timeout_ms": 10000, "memory_bytes": 1073741824, "output_bytes": 4096},
    }
    input_file = scratch / f"input-{value}.json"
    input_file.write_text(json.dumps(spec), encoding="utf-8")
    native = subprocess.run([binary, value], capture_output=True, timeout=10, check=False)
    if native.returncode != 0:
        raise AssertionError(f"native fixture failed: {native.returncode} {native.stderr!r}")
    observed = subprocess.run(
        [OBSERVER, binary, input_file, f"{symbols['hydir_select']:x}"],
        capture_output=True, text=True, timeout=20, check=False,
    )
    if observed.returncode != 0:
        raise AssertionError(f"isolated Frida observation failed: {observed.stderr}")
    trace = json.loads(observed.stdout)
    if trace["observer"] != "bubblewrap-frida-rust-message-v2":
        raise AssertionError("observer did not use the Frida message transport")
    if trace["status"] != "completed":
        raise AssertionError(f"trace incomplete: {trace['status']} {trace['diagnostics']}")
    if trace["lost_events"]:
        raise AssertionError(f"Frida lost {trace['lost_events']} events")
    if bytes.fromhex(trace["stdout_hex"]) != native.stdout:
        raise AssertionError("observed output differs from uninstrumented native run")
    if bytes.fromhex(trace["stderr_hex"]) != native.stderr:
        raise AssertionError("observed stderr differs from uninstrumented native run")
    events = trace["events"]
    if not any(event["kind"] == "entry" and
               event["source"]["elf_vaddr"] == symbols["hydir_select"] for event in events):
        raise AssertionError("selected entry was not normalized")
    if not any(event["kind"] == "block" and event["source"]["elf_vaddr"] is not None
               for event in events):
        raise AssertionError("no checked ELF block event")
    expected = symbols["hydir_right" if value == "1" else "hydir_left"]
    if not any(event["kind"] == "call" and event["target"]["elf_vaddr"] == expected
               for event in events):
        raise AssertionError(f"indirect call target {expected:x} was not observed")
    return len(events)


def main():
    with tempfile.TemporaryDirectory(prefix="hydir-frida-gate-") as directory:
        scratch = Path(directory)
        binary = scratch / "frida-branch.elf"
        subprocess.run([
            "clang", "-O0", "-fPIE", "-pie", "-fno-omit-frame-pointer",
            ROOT / "tests/fixtures/frida_branch.c", "-o", binary,
        ], check=True)
        symbols = symbol_addresses(binary)
        counts = {value: run_one(binary, symbols, value, scratch) for value in ("0", "1")}
        print(f"Frida inside Bubblewrap: two completed PIE paths, events={counts}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Frida F0 gate failed: {error}", file=sys.stderr)
        raise
