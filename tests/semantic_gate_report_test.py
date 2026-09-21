"""The native gate must fail closed on missing or unrelated validator evidence."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/semantic-gate.py"
SPEC = importlib.util.spec_from_file_location("semantic_gate", SCRIPT)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ValidatorReportTests(unittest.TestCase):
    def test_report_identity_and_complete_case_accounting(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fixture"
            report = {
                "binary": str(binary.resolve()),
                "function": "hydir_add",
                "backend": "raw LLVM",
                "cases_attempted": 12,
                "external_cases_attempted": 2,
                "cases_matched": 12,
                "cases_mismatched": 0,
                "mismatches": [],
                "result": "pass",
            }
            check = lambda value: GATE.check_validation_report(
                value, binary, "hydir_add", "llvm", 12, 2)
            self.assertIsNone(check(report))
            self.assertIsNotNone(check(None))
            for change in ({"function": "hydir_other"},
                           {"binary": str(binary) + "-other"},
                           {"backend": "HydIR scalar LLVM-to-C"},
                           {"cases_attempted": 0},
                           {"external_cases_attempted": 0},
                           {"cases_mismatched": "0"},
                           {"cases_matched": 11},
                           {"mismatches": [{}]},
                           {"result": "fail"}):
                with self.subTest(change=change):
                    self.assertIsNotNone(check({**report, **change}))

    def test_solver_witnesses_must_be_distinct_u64_pairs(self):
        make = lambda paths: json.dumps({"paths": paths})
        self.assertEqual(GATE.parse_solver_witnesses(make([
            {"input_witness": [0, 0]},
            {"input_witness": [2**64 - 1, 1]},
        ])), [[0, 0], [2**64 - 1, 1]])
        for paths in ([], [{"input_witness": [0, 0]}, {"input_witness": [0, 0]}],
                      [{"input_witness": [-1, 0]}], [{"input_witness": [0]}]):
            with self.subTest(paths=paths), self.assertRaises(ValueError):
                GATE.parse_solver_witnesses(make(paths))


if __name__ == "__main__":
    unittest.main()
