import io
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from aegis import _print_text_diagnostics
from scanner import engine
from simulation.service import SUPPORTED_CHECKS, run_runtime_validation
from simulation.support import analyze_runtime_eligibility, support_matrix, supported_checks


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


class TestRuntimeSupportRegistry(unittest.TestCase):
    def test_service_supported_checks_match_support_registry(self):
        self.assertEqual(SUPPORTED_CHECKS, supported_checks())
        self.assertEqual(
            supported_checks(),
            {
                "missing-access-control",
                "reentrancy",
                "delegatecall-untrusted-target",
                "integer-overflow",
                "timestamp-dependence",
                "predictable-randomness",
            },
        )

    def test_supported_sample_findings_are_runtime_eligible(self):
        samples = {
            "access.sol": "missing-access-control",
            "reentrancy.sol": "reentrancy",
            "delegatecall.sol": "delegatecall-untrusted-target",
            "overflow.sol": "integer-overflow",
            "timestamp.sol": "timestamp-dependence",
            "weak_randomness_runtime.sol": "predictable-randomness",
        }
        for sample, expected_check in samples.items():
            with self.subTest(sample=sample):
                scan = engine.scan(_read_sample(sample), sample)
                eligibility = analyze_runtime_eligibility(scan["findings"])
                self.assertIn(expected_check, eligibility["found_checks"])
                self.assertGreater(eligibility["eligible_count"], 0)

    def test_unsupported_finding_filter_has_detailed_diagnostics(self):
        result = run_runtime_validation(
            "pragma solidity ^0.8.0; contract X {}",
            [{"id": "x", "check": "tx-origin-auth", "vulnerability": "tx.origin"}],
        )
        self.assertEqual(result["status"], "simulation_unsupported")
        self.assertEqual(result["diagnostics"]["error_phase"], "finding_filter")
        self.assertEqual(result["diagnostics"]["finding_count"], 1)
        self.assertEqual(result["diagnostics"]["finding_checks"], ["tx-origin-auth"])
        self.assertIn("timestamp-dependence", result["diagnostics"]["supported_checks"])
        self.assertIn("predictable-randomness", result["diagnostics"]["supported_checks"])
        self.assertIn("Found checks: tx-origin-auth", result["summary"])
        self.assertNotIn("access-control, reentrancy, and delegatecall findings only", result["summary"])
        self.assertIn("runtime_eligibility", result["metadata"])

    @patch("simulation.service.compile_source_rich", side_effect=RuntimeError("stop before compile"))
    def test_supported_check_is_not_filtered_out_before_compilation(self, _mock_compile):
        result = run_runtime_validation(
            "pragma solidity ^0.8.0; contract X {}",
            [{"id": "x", "check": "timestamp-dependence", "vulnerability": "Timestamp Dependence"}],
        )
        self.assertNotEqual(result["diagnostics"]["error_phase"], "finding_filter")
        self.assertEqual(result["diagnostics"]["runtime_eligible_count"], 1)


class TestRuntimeSupportWorkflow(unittest.TestCase):
    def run_dev(self, *args):
        return subprocess.run(
            [sys.executable, "scripts/dev.py", *args],
            cwd=os.path.dirname(os.path.dirname(__file__)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_support_matrix_command_lists_all_current_runtime_families(self):
        result = self.run_dev("support-matrix")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = result.stdout
        for item in support_matrix():
            self.assertIn(item["check"], output)
            self.assertIn(item["family"], output)

    def test_diagnose_command_reports_reentrancy_eligible(self):
        result = self.run_dev("diagnose", "reentrancy")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Runtime eligible: 1", result.stdout)
        self.assertIn("check=reentrancy eligible=yes", result.stdout)

    def test_check_runtime_support_tier(self):
        result = self.run_dev("check", "runtime-support")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("runtime support matrix", result.stdout.lower())


class TestRuntimeSupportCliDiagnostics(unittest.TestCase):
    def test_cli_diagnostics_prints_finding_filter_details(self):
        diag = {
            "error_phase": "finding_filter",
            "finding_count": 1,
            "finding_checks": ["tx-origin-auth"],
            "supported_checks": ["missing-access-control", "reentrancy", "timestamp-dependence"],
            "runtime_eligible_count": 0,
        }
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            _print_text_diagnostics(diag)
        output = buf.getvalue()
        self.assertIn("Runtime eligibility: 0 eligible / 1 finding(s)", output)
        self.assertIn("Found checks: tx-origin-auth", output)
        self.assertIn("Supported checks:", output)


if __name__ == "__main__":
    unittest.main()
