#!/usr/bin/env python3
"""Real Ghidra EmulatorHelper versus Hydir's Rust P-code path executor.

Set HYDIR_GHIDRA_HOME to an unpacked Ghidra 12.1.4 directory. This test is
skipped when Ghidra is unavailable; no mocked emulator stands in for it.
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "demo" / "hydir-prism.elf"
SNAPSHOT = ROOT / "tests" / "fixtures" / "ghidra_prism_patch_portal_v2.json"
BRANCH_SNAPSHOT = ROOT / "tests" / "fixtures" / "ghidra_prism_bit_gate_oracle_v2.json"
SCRIPT = ROOT / "integrations" / "ghidra" / "HydIROracle.java"
GHIDRA_HOME = Path(os.environ.get("HYDIR_GHIDRA_HOME", "")) if os.environ.get("HYDIR_GHIDRA_HOME") else None
HEADLESS = GHIDRA_HOME / "support" / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless") if GHIDRA_HOME else None


def encoded(text):
    return "h" + text.encode("utf-8").hex()


def state_value(state, space, offset, size):
    if space == "register":
        byte_map = state["register_bytes"]
    else:
        byte_map = state["memory_bytes"][space]
    return sum(byte_map[str(offset + index)] << (8 * index) for index in range(size))


@unittest.skipUnless(HEADLESS and HEADLESS.is_file(), "set HYDIR_GHIDRA_HOME to run the real Ghidra oracle")
class GhidraOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="hydir-ghidra-oracle-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.temp = Path(cls.temporary.name)
        scripts = cls.temp / "scripts"
        scripts.mkdir()
        shutil.copy2(SCRIPT, scripts / SCRIPT.name)
        projects = cls.temp / "projects"
        projects.mkdir()
        cls.cases = [
            ("zero", 0),
            ("high", 0xFEDCBA9876543210),
        ]
        cls.branch_cases = [("taken", 1, 0), ("not_taken", 0, 1)]
        command = [str(HEADLESS), str(projects), "HydirOracleTest", "-import", str(BINARY), "-scriptPath", str(scripts)]
        for label, rdi in cls.cases:
            command.extend([
                "-postScript", SCRIPT.name, str(cls.temp / f"{label}.json"), str(BINARY),
                "0x201388", "8", encoded(f"RDI=0x{rdi:x};RSP=0x700000"),
                encoded("0x700000:8:0xdeadbeef"), encoded("RAX,RDI,RSP,RIP"),
                encoded("0x700000:8"),
            ])
        for label, zf, _ in cls.branch_cases:
            command.extend([
                "-postScript", SCRIPT.name, str(cls.temp / f"branch-{label}.json"), str(BINARY),
                "0x2013cf", "8", encoded(f"ZF=0x{zf:x};RAX=0x0;RSP=0x700000"),
                encoded("0x700000:8:0xdeadbeef"), encoded("RAX,ZF,RSP,RIP"),
                encoded("0x700000:8"), "0x2013d9",
            ])
        command.extend([
            "-postScript", SCRIPT.name, str(cls.temp / "call_boundary.json"), str(BINARY),
            "0x2013a9", "8", encoded("RSP=0x700000"), encoded(""),
            encoded("RSP"), encoded(""), "-deleteProject",
        ])
        result = subprocess.run(command, capture_output=True, text=True, timeout=180)
        output = result.stdout + result.stderr
        if result.returncode != 0 or "ERROR REPORT SCRIPT ERROR" in output:
            raise AssertionError(f"Ghidra oracle failed ({result.returncode}):\n{output[-8000:]}")
        for label, _ in cls.cases:
            if not (cls.temp / f"{label}.json").is_file():
                raise AssertionError(f"Ghidra did not write {label} result:\n{output[-8000:]}")
        for label, _, _ in cls.branch_cases:
            if not (cls.temp / f"branch-{label}.json").is_file():
                raise AssertionError(f"Ghidra did not write branch {label} result:\n{output[-8000:]}")
        if not (cls.temp / "call_boundary.json").is_file():
            raise AssertionError(f"Ghidra did not write call boundary:\n{output[-8000:]}")
        cls.snapshot = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
        cls.branch_snapshot = json.loads(BRANCH_SNAPSHOT.read_text(encoding="utf-8"))
        cls.digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()

    def hydir_trace(self, seed, snapshot, label, start=None):
        seed_path = self.temp / f"seed-{label}.json"
        seed_path.write_text(json.dumps(seed), encoding="utf-8")
        executable = os.environ.get("HYDIRCTL_BIN")
        if executable:
            command = [executable]
        else:
            candidate = ROOT / "target" / "debug" / ("hydirctl.exe" if os.name == "nt" else "hydirctl")
            command = [str(candidate)] if candidate.is_file() else ["cargo", "run", "-q", "-p", "hydir-cli", "--"]
        command += [
            "ghidra-snapshot", "trace-path", str(BINARY), str(snapshot), str(seed_path),
            "--max-ops", "32", "--max-visits", "8",
        ]
        if start is not None:
            command += ["--start", start]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_exact_patch_portal_matches_rust_path_for_two_seeds(self):
        self.assertEqual(self.snapshot["binary_sha256"], self.digest)
        self.assertEqual(self.snapshot["selected_function"]["entry"]["offset"], "0x201388")
        for label, rdi in self.cases:
            with self.subTest(label=label):
                oracle = json.loads((self.temp / f"{label}.json").read_text(encoding="utf-8"))
                seed = {
                    "schema_version": 1,
                    "binary_sha256": self.digest,
                    "entry": {"space": "ram", "offset": "0x201388"},
                    "registers": [
                        {"offset": "0x38", "size": 8, "value": f"0x{rdi:x}"},
                        {"offset": "0x20", "size": 8, "value": "0x700000"},
                    ],
                    "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8, "value": "0xdeadbeef"}],
                }
                trace = self.hydir_trace(seed, SNAPSHOT, label)
                self.assertEqual(oracle["oracle"], "ghidra_emulator_helper")
                self.assertEqual(oracle["binary_sha256"], trace["binary_sha256"])
                self.assertEqual(oracle["stop"]["kind"], "return")
                self.assertEqual(trace["stop"]["kind"], "return")
                self.assertEqual(
                    [step["address"] for step in oracle["steps"]],
                    trace["instruction_visits"],
                )
                by_name = {item["name"]: item for item in oracle["registers"]}
                for name in ("RAX", "RDI", "RSP"):
                    item = by_name[name]
                    self.assertEqual(
                        int(item["value"], 16),
                        state_value(trace["final_state"], "register", int(item["offset"], 16), item["size"]),
                        name,
                    )
                # Hydir stops before the RETURN P-code op, after RET loaded
                # the target into its register-space temporary at RIP's offset.
                self.assertEqual(
                    int(by_name["RIP"]["value"], 16),
                    state_value(trace["final_state"], "register", 0x288, 8),
                )
                item = oracle["memory"][0]
                self.assertEqual(
                    int(item["value"], 16),
                    state_value(trace["final_state"], "ram", int(item["address"]["offset"], 16), item["size"]),
                )

    def test_both_real_conditional_branch_outcomes_match_rust_path(self):
        self.assertEqual(self.branch_snapshot["binary_sha256"], self.digest)
        self.assertEqual(self.branch_snapshot["selected_function"]["entry"]["offset"], "0x2013cf")
        for label, zf, expected_rax in self.branch_cases:
            with self.subTest(label=label):
                oracle = json.loads((self.temp / f"branch-{label}.json").read_text(encoding="utf-8"))
                seed = {
                    "schema_version": 1,
                    "binary_sha256": self.digest,
                    "entry": {"space": "ram", "offset": "0x2013cf"},
                    "registers": [
                        {"offset": "0x206", "size": 1, "value": f"0x{zf:x}"},
                        {"offset": "0x0", "size": 8, "value": "0x0"},
                        {"offset": "0x20", "size": 8, "value": "0x700000"},
                    ],
                    "memory": [{"space": "ram", "byte_offset": "0x700000", "size": 8, "value": "0xdeadbeef"}],
                }
                trace = self.hydir_trace(seed, BRANCH_SNAPSHOT, f"branch-{label}", start="0x2013d9")
                self.assertEqual(oracle["entry"], seed["entry"])
                self.assertEqual(oracle["start"], trace["start"])
                self.assertEqual(oracle["stop"]["kind"], "return")
                self.assertEqual(trace["stop"]["kind"], "return")
                self.assertEqual(
                    [step["address"] for step in oracle["steps"]],
                    trace["instruction_visits"],
                )
                by_name = {item["name"]: item for item in oracle["registers"]}
                self.assertEqual(int(by_name["RAX"]["value"], 16), expected_rax)
                for name in ("RAX", "ZF", "RSP"):
                    item = by_name[name]
                    self.assertEqual(
                        int(item["value"], 16),
                        state_value(trace["final_state"], "register", int(item["offset"], 16), item["size"]),
                        name,
                    )
                self.assertEqual(
                    int(by_name["RIP"]["value"], 16),
                    state_value(trace["final_state"], "register", 0x288, 8),
                )
                item = oracle["memory"][0]
                self.assertEqual(
                    int(item["value"], 16),
                    state_value(trace["final_state"], "ram", int(item["address"]["offset"], 16), item["size"]),
                )

    def test_call_is_an_explicit_boundary(self):
        oracle = json.loads((self.temp / "call_boundary.json").read_text(encoding="utf-8"))
        self.assertEqual(oracle["binary_sha256"], self.digest)
        self.assertEqual(oracle["stop"]["kind"], "unsupported_effect")
        self.assertEqual([step["address"]["offset"] for step in oracle["steps"]], ["0x2013a9"])


if __name__ == "__main__":
    unittest.main()
