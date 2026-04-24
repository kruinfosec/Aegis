import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from benchmarks.fixtures import FIXTURES, families, select_fixtures
from benchmarks.runner import run_benchmark, summarize, write_artifact


def fake_full_scan(source, filename, run_runtime=False, backend_name="hardhat"):
    status_by_file = {
        "access.sol": ("missing-access-control", "confirmed_by_runtime"),
        "access_runtime_negative.sol": ("missing-access-control", "not_confirmed_by_runtime"),
        "reentrancy.sol": ("reentrancy", "confirmed_by_runtime"),
        "reentrancy_runtime_safe.sol": ("reentrancy", "not_confirmed_by_runtime"),
        "delegatecall.sol": ("delegatecall-untrusted-target", "confirmed_by_runtime"),
        "delegatecall_runtime_negative.sol": ("delegatecall-untrusted-target", "not_confirmed_by_runtime"),
        "overflow.sol": ("integer-overflow", "confirmed_by_runtime"),
        "overflow_safe.sol": ("integer-overflow", "not_confirmed_by_runtime"),
        "timestamp.sol": ("timestamp-dependence", "confirmed_by_runtime"),
        "timestamp_runtime_negative.sol": ("timestamp-dependence", "not_confirmed_by_runtime"),
        "weak_randomness_runtime.sol": ("predictable-randomness", "confirmed_by_runtime"),
        "weak_randomness_runtime_negative.sol": ("predictable-randomness", "not_confirmed_by_runtime"),
    }
    check, status = status_by_file[filename]
    if not run_runtime:
        status = "NOT_RUN"
    return {
        "success": True,
        "findings": [
            {
                "id": f"{filename}-1",
                "check": check,
                "runtime_validation_status": status,
            }
        ],
        "runtime_correlation": {
            "backend": "hardhat" if run_runtime else None,
            "scenario_families_executed": [check] if run_runtime else [],
        },
        "simulation": {
            "diagnostics": {
                "total_ms": 10,
                "compilation_ms": 2,
                "backend_startup_ms": 3,
                "scenario_execution_ms": 4,
                "error_phase": None,
            }
        },
    }


class TestBenchmarkFixtures(unittest.TestCase):
    def test_fixture_registry_has_supported_runtime_families(self):
        self.assertEqual(
            families(),
            [
                "access-control",
                "delegatecall",
                "integer-overflow",
                "reentrancy",
                "timestamp-dependence",
                "weak-randomness",
            ],
        )
        for fixture in FIXTURES:
            self.assertTrue((ROOT / fixture.sample).exists(), fixture.sample)

    def test_select_fixtures_can_filter_family_and_quick_mode(self):
        weak = select_fixtures("weak-randomness")
        self.assertEqual({fixture.family for fixture in weak}, {"weak-randomness"})
        quick = select_fixtures(quick=True)
        self.assertTrue(quick)
        self.assertTrue(all(fixture.quick for fixture in quick))


class TestBenchmarkRunner(unittest.TestCase):
    @patch("benchmarks.runner.full_scan", side_effect=fake_full_scan)
    def test_run_benchmark_compares_expected_outcomes(self, _mock_scan):
        result = run_benchmark(family="weak-randomness", run_runtime=True)
        self.assertEqual(result["summary"]["total_fixtures"], 2)
        self.assertEqual(result["summary"]["failed"], 0)
        self.assertEqual(result["summary"]["runtime_status_counts"]["confirmed_by_runtime"], 1)
        self.assertEqual(result["summary"]["runtime_status_counts"]["not_confirmed_by_runtime"], 1)

    @patch("benchmarks.runner.full_scan", side_effect=fake_full_scan)
    def test_static_only_benchmark_records_not_run_runtime(self, _mock_scan):
        result = run_benchmark(family="weak-randomness", run_runtime=False)
        self.assertEqual(result["summary"]["runtime_status_counts"]["NOT_RUN"], 2)
        self.assertEqual(result["summary"]["failed"], 0)

    def test_summarize_counts_family_and_statuses(self):
        summary = summarize([
            {
                "family": "example",
                "passed": True,
                "duration_ms": 12,
                "static": {"found": True},
                "runtime": {"observed_status": "confirmed_by_runtime"},
            },
            {
                "family": "example",
                "passed": False,
                "duration_ms": 8,
                "static": {"found": False},
                "runtime": {"observed_status": "simulation_unsupported"},
            },
        ])
        self.assertEqual(summary["total_fixtures"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["runtime_status_counts"]["simulation_unsupported"], 1)
        self.assertEqual(summary["family_summary"]["example"]["fixtures"], 2)

    def test_write_artifact_outputs_json(self):
        output = ROOT / "artifacts" / "benchmarks" / "unit-test-benchmark.json"
        try:
            path = write_artifact({"mode": "unit", "summary": {"failed": 0}}, output)
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["mode"], "unit")
        finally:
            if output.exists():
                output.unlink()


class TestBenchmarkWorkflowCommands(unittest.TestCase):
    def run_dev(self, *args):
        return subprocess.run(
            [sys.executable, "scripts/dev.py", *args],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_benchmark_list_command(self):
        result = self.run_dev("benchmark", "list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("weak-randomness-positive", result.stdout)
        self.assertIn("access-control-positive", result.stdout)

    def test_benchmark_family_validation_rejects_unknown_family(self):
        result = self.run_dev("benchmark", "run", "--family", "unknown-family", "--quick")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown benchmark family", result.stderr)

    def test_check_benchmark_dry_run_outputs_quick_benchmark_command(self):
        result = self.run_dev("check", "benchmark", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("benchmark run --quick", result.stdout)


if __name__ == "__main__":
    unittest.main()
