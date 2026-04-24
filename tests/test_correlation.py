"""
Tests for the reusable static/dynamic correlation layer and unified pipeline.

Covers:
- correlation without runtime (static-only path)
- correlation with confirmed / not-confirmed / mixed results
- scan-level runtime_correlation summary accuracy
- static evidence preservation after merge
- report-format ordering bug regression
- graceful degradation when runtime deps are unavailable
- pipeline full_scan with runtime disabled
- pipeline full_scan with mocked runtime
"""

import os
import sys
import json
import unittest
from copy import deepcopy
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import engine
from scanner.correlation import correlate, build_runtime_summary, count_runtime_statuses
from scanner.pipeline import full_scan
from scanner import report as report_formatter
from simulation.models import RUNTIME_CONFIRMED, RUNTIME_NOT_CONFIRMED


class TestCountRuntimeStatuses(unittest.TestCase):
    """Unit tests for count_runtime_statuses helper."""

    def test_empty_findings(self):
        self.assertEqual(count_runtime_statuses([]), {})

    def test_all_not_run(self):
        findings = [
            {"runtime_validation_status": "NOT_RUN"},
            {"runtime_validation_status": "NOT_RUN"},
        ]
        counts = count_runtime_statuses(findings)
        self.assertEqual(counts, {"NOT_RUN": 2})

    def test_mixed_statuses(self):
        findings = [
            {"runtime_validation_status": "confirmed_by_runtime"},
            {"runtime_validation_status": "not_confirmed_by_runtime"},
            {"runtime_validation_status": "NOT_RUN"},
            {"runtime_validation_status": "confirmed_by_runtime"},
        ]
        counts = count_runtime_statuses(findings)
        self.assertEqual(counts["confirmed_by_runtime"], 2)
        self.assertEqual(counts["not_confirmed_by_runtime"], 1)
        self.assertEqual(counts["NOT_RUN"], 1)

    def test_missing_status_defaults_to_not_run(self):
        findings = [{"vulnerability": "test"}]
        counts = count_runtime_statuses(findings)
        self.assertEqual(counts, {"NOT_RUN": 1})


class TestCorrelateStaticOnly(unittest.TestCase):
    """Tests for correlate() when no runtime result is provided."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_static_only_produces_valid_structure(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        enriched = correlate(scan_result, runtime_result=None, runtime_requested=False)

        self.assertIn("findings", enriched)
        self.assertIn("analysis_summary", enriched)
        self.assertIn("runtime_correlation", enriched)
        self.assertIsNone(enriched["simulation"])

    def test_static_only_runtime_not_requested(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        enriched = correlate(scan_result, runtime_result=None, runtime_requested=False)

        rt = enriched["runtime_correlation"]
        self.assertFalse(rt["runtime_requested"])
        self.assertFalse(rt["runtime_executed"])
        self.assertFalse(rt["enabled"])
        self.assertIsNone(rt["backend"])
        self.assertEqual(rt["not_run_count"], enriched["total_issues"])
        self.assertEqual(rt["confirmed_count"], 0)

    def test_static_only_runtime_requested_but_unavailable(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        enriched = correlate(scan_result, runtime_result=None, runtime_requested=True)

        rt = enriched["runtime_correlation"]
        self.assertTrue(rt["runtime_requested"])
        self.assertFalse(rt["runtime_executed"])
        self.assertFalse(rt["enabled"])

    def test_findings_retain_static_evidence(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        enriched = correlate(scan_result, runtime_result=None)
        for finding in enriched["findings"]:
            self.assertIn("evidence", finding)
            self.assertEqual(finding["verification"]["static"], "FLAGGED")
            self.assertEqual(finding["verification"]["dynamic"], "NOT_RUN")
            self.assertEqual(finding["exploitability"], "UNVERIFIED")

    def test_original_scan_result_not_mutated(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        original_finding_count = len(scan_result["findings"])
        original_first_id = scan_result["findings"][0]["id"]
        _enriched = correlate(scan_result, runtime_result=None)
        # Original must be untouched.
        self.assertEqual(len(scan_result["findings"]), original_finding_count)
        self.assertEqual(scan_result["findings"][0]["id"], original_first_id)
        self.assertNotIn("runtime_correlation", scan_result)


class TestCorrelateWithRuntime(unittest.TestCase):
    """Tests for correlate() with runtime validation results."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def _make_runtime_result(self, findings, status, backend="hardhat"):
        """Build a minimal runtime result with one validation per finding."""
        validations = []
        for f in findings:
            validations.append({
                "finding_id": f["id"],
                "status": status,
                "backend": backend,
                "check": "access_control.unauthorized_privileged_call",
                "scenario": "access_control.unauthorized_privileged_call",
                "contract_name": f.get("contract_name", "Unknown"),
                "function_name": f.get("function", ""),
                "evidence": {"reverted": status != RUNTIME_CONFIRMED},
                "limitations": ["Test limitation"],
                "error": None if status == RUNTIME_CONFIRMED else "Reverted",
            })
        return {
            "backend": backend,
            "status": status,
            "success": True,
            "summary": "Completed",
            "validations": validations,
            "accounts": ["0x001", "0x002"],
            "attacks_run": [],
            "metadata": {},
        }

    def test_confirmed_runtime_enriches_findings(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        runtime_result = self._make_runtime_result(
            scan_result["findings"], RUNTIME_CONFIRMED
        )
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        for finding in enriched["findings"]:
            self.assertEqual(finding["runtime_validation_status"], RUNTIME_CONFIRMED)
            self.assertEqual(finding["verification"]["dynamic"], "CONFIRMED")
            self.assertEqual(finding["exploitability"], "CONFIRMED_BY_RUNTIME")
            self.assertEqual(finding["runtime_backend"], "hardhat")

    def test_not_confirmed_runtime_enriches_findings(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        runtime_result = self._make_runtime_result(
            scan_result["findings"], RUNTIME_NOT_CONFIRMED
        )
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        for finding in enriched["findings"]:
            self.assertEqual(finding["runtime_validation_status"], RUNTIME_NOT_CONFIRMED)
            self.assertEqual(finding["verification"]["dynamic"], "NOT_CONFIRMED")
            self.assertEqual(finding["exploitability"], "NOT_CONFIRMED_BY_RUNTIME")

    def test_mixed_statuses_produce_correct_summary(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        findings = scan_result["findings"]
        self.assertGreaterEqual(len(findings), 2, "Need at least 2 findings for mixed test")

        # First finding confirmed, second not confirmed.
        runtime_result = self._make_runtime_result(findings[:1], RUNTIME_CONFIRMED)
        runtime_result["validations"].extend(
            self._make_runtime_result(findings[1:], RUNTIME_NOT_CONFIRMED)["validations"]
        )
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        rt = enriched["runtime_correlation"]
        self.assertEqual(rt["confirmed_count"], 1)
        self.assertGreaterEqual(rt["not_confirmed_count"], 1)
        self.assertTrue(rt["runtime_executed"])

    def test_static_evidence_preserved_after_runtime_merge(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        # Capture static evidence before merge.
        original_evidence = [deepcopy(f["evidence"]) for f in scan_result["findings"]]

        runtime_result = self._make_runtime_result(
            scan_result["findings"], RUNTIME_CONFIRMED
        )
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        for i, finding in enumerate(enriched["findings"]):
            # Static evidence fields must still be present.
            self.assertIn("evidence", finding)
            self.assertEqual(finding["evidence"]["type"], original_evidence[i]["type"])
            # Static verification must still be FLAGGED.
            self.assertEqual(finding["verification"]["static"], "FLAGGED")

    def test_scan_level_summary_fields_complete(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        runtime_result = self._make_runtime_result(
            scan_result["findings"], RUNTIME_CONFIRMED
        )
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        rt = enriched["runtime_correlation"]
        required_fields = [
            "runtime_requested", "runtime_executed", "enabled", "backend",
            "total_findings", "runtime_validated_count", "confirmed_count",
            "not_confirmed_count", "inconclusive_count", "unsupported_count",
            "failed_count", "not_run_count",
            "findings_without_runtime_validation_count",
            "scenario_families_executed",
        ]
        for field in required_fields:
            self.assertIn(field, rt, f"Missing summary field: {field}")

    def test_scenario_families_captured(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        runtime_result = self._make_runtime_result(
            scan_result["findings"], RUNTIME_CONFIRMED
        )
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        rt = enriched["runtime_correlation"]
        self.assertIn("access_control", rt["scenario_families_executed"])


class TestReportOrderingBugRegression(unittest.TestCase):
    """Regression test for the app.py ordering bug.

    Previously, ``report_formatter.format_report()`` was called *before*
    runtime enrichment ran, so runtime fields (runtime_validation_status,
    exploitability, verification.dynamic) were always defaults in the
    formatted output.  This test proves they now carry enriched values.
    """

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_formatted_report_contains_runtime_enriched_fields(self):
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        # Build a fake runtime result with confirmed status.
        validations = []
        for f in scan_result["findings"]:
            validations.append({
                "finding_id": f["id"],
                "status": RUNTIME_CONFIRMED,
                "backend": "hardhat",
                "check": "access_control.unauthorized_privileged_call",
                "scenario": "access_control.unauthorized_privileged_call",
                "contract_name": f.get("contract_name", "Unknown"),
                "function_name": f.get("function", ""),
                "evidence": {"reverted": False},
                "limitations": [],
                "error": None,
            })
        runtime_result = {
            "backend": "hardhat",
            "status": RUNTIME_CONFIRMED,
            "success": True,
            "summary": "Completed",
            "validations": validations,
            "accounts": [],
            "attacks_run": [],
            "metadata": {},
        }

        # This is the CORRECT order (post-fix): correlate THEN format.
        enriched = correlate(scan_result, runtime_result, runtime_requested=True)
        formatted = report_formatter.format_report(enriched)

        # Formatted findings must carry runtime fields (the bug would have
        # left these as "NOT_RUN" / "UNVERIFIED").
        for finding in formatted["findings"]:
            self.assertEqual(
                finding.get("runtime_validation_status"),
                RUNTIME_CONFIRMED,
                "Runtime status did not reach formatted report — ordering bug still present",
            )
            self.assertEqual(
                finding.get("exploitability"),
                "CONFIRMED_BY_RUNTIME",
                "Exploitability did not reach formatted report — ordering bug still present",
            )
            self.assertEqual(
                finding.get("verification", {}).get("dynamic"),
                "CONFIRMED",
                "Dynamic verification did not reach formatted report — ordering bug still present",
            )

    def test_old_broken_order_would_lose_runtime_fields(self):
        """Proves the OLD (broken) order does NOT propagate runtime fields."""
        scan_result = engine.scan(self.read_sample("access.sol"), "access.sol")
        # Format FIRST (the old broken order).
        formatted_before = report_formatter.format_report(scan_result)
        # All findings must still be un-enriched.
        for finding in formatted_before["findings"]:
            self.assertEqual(finding.get("runtime_validation_status"), "NOT_RUN")
            self.assertEqual(finding.get("exploitability"), "UNVERIFIED")


class TestGracefulDegradation(unittest.TestCase):
    """Tests for graceful degradation when runtime dependencies are unavailable."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    @patch("scanner.pipeline._SIMULATION_IMPORT_OK", False)
    @patch("scanner.pipeline.run_runtime_validation")
    @patch("scanner.pipeline.simulation_available", return_value=False)
    def test_pipeline_degrades_when_simulation_unavailable(self, _mock_avail, mock_sim):
        """When simulation module cannot be imported, pipeline should still
        produce a valid enriched result without crashing."""
        source = self.read_sample("access.sol")
        result = full_scan(source, "access.sol", run_runtime=True)

        self.assertTrue(result["success"])
        self.assertIn("runtime_correlation", result)
        rt = result["runtime_correlation"]
        self.assertTrue(rt["runtime_requested"])
        # The mock replaces the real function, so _try_runtime will be called.
        # MagicMock return value won't have proper dict structure, so _try_runtime
        # catches the exception and produces a simulation_failed fallback.
        # Key assertion: pipeline doesn't crash regardless.
        self.assertIn("findings", result)
        self.assertGreater(result["total_issues"], 0)

    def test_pipeline_handles_runtime_exception_gracefully(self):
        """If runtime validation raises an exception, pipeline should catch it
        and return a valid result with simulation_failed status."""
        source = self.read_sample("access.sol")
        with patch("scanner.pipeline.run_runtime_validation", side_effect=RuntimeError("Hardhat not found")):
            result = full_scan(source, "access.sol", run_runtime=True)

        self.assertTrue(result["success"])
        self.assertIn("runtime_correlation", result)
        # The raw simulation payload should indicate failure.
        sim = result.get("simulation")
        self.assertIsNotNone(sim)
        self.assertEqual(sim["status"], "simulation_failed")
        self.assertIn("Hardhat not found", sim["error"])


class TestPipelineFullScan(unittest.TestCase):
    """Tests for the unified pipeline full_scan() function."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_static_only_scan(self):
        result = full_scan(self.read_sample("safe.sol"), "safe.sol", run_runtime=False)

        self.assertTrue(result["success"])
        self.assertEqual(result["total_issues"], 0)
        self.assertIn("runtime_correlation", result)
        rt = result["runtime_correlation"]
        self.assertFalse(rt["runtime_requested"])
        self.assertFalse(rt["runtime_executed"])

    def test_static_scan_with_issues_no_runtime(self):
        result = full_scan(self.read_sample("access.sol"), "access.sol", run_runtime=False)

        self.assertTrue(result["success"])
        self.assertGreater(result["total_issues"], 0)
        rt = result["runtime_correlation"]
        self.assertFalse(rt["runtime_requested"])
        self.assertEqual(rt["not_run_count"], result["total_issues"])

    def test_pipeline_returns_enriched_structure(self):
        result = full_scan(self.read_sample("selfdestruct.sol"), "selfdestruct.sol", run_runtime=False)

        # Verify all top-level keys exist.
        for key in ["success", "findings", "total_issues", "risk_level",
                     "risk_score", "analysis_summary", "runtime_correlation", "simulation"]:
            self.assertIn(key, result, f"Missing top-level key: {key}")

    def test_pipeline_with_mocked_runtime(self):
        """Pipeline with a mocked runtime that confirms all findings."""
        source = self.read_sample("access.sol")
        scan_result = engine.scan(source, "access.sol")

        def mock_runtime(src, findings, backend_name="hardhat"):
            validations = []
            for f in findings:
                validations.append({
                    "finding_id": f["id"],
                    "status": RUNTIME_CONFIRMED,
                    "backend": backend_name,
                    "check": "access_control.unauthorized_privileged_call",
                    "scenario": "access_control.unauthorized_privileged_call",
                    "contract_name": f.get("contract_name", "Unknown"),
                    "function_name": f.get("function", ""),
                    "evidence": {"reverted": False},
                    "limitations": [],
                    "error": None,
                })
            return {
                "backend": backend_name,
                "status": RUNTIME_CONFIRMED,
                "success": True,
                "summary": "All confirmed",
                "validations": validations,
                "accounts": [],
                "attacks_run": [],
                "metadata": {},
            }

        with patch("scanner.pipeline.run_runtime_validation", side_effect=mock_runtime):
            result = full_scan(source, "access.sol", run_runtime=True)

        self.assertTrue(result["success"])
        rt = result["runtime_correlation"]
        self.assertTrue(rt["runtime_requested"])
        self.assertTrue(rt["runtime_executed"])
        self.assertGreater(rt["confirmed_count"], 0)
        self.assertEqual(rt["not_run_count"], 0)


class TestJSONExportIncludesCorrelation(unittest.TestCase):
    """Verify that the JSON export path carries runtime_correlation."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")
        # Import app for test client.
        from app import app
        app.config["TESTING"] = True
        self.client = app.test_client()

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_json_export_contains_runtime_correlation(self):
        """JSON export endpoint should include runtime_correlation."""
        enriched = full_scan(self.read_sample("selfdestruct.sol"), "selfdestruct.sol", run_runtime=False)
        formatted = report_formatter.format_report(enriched)
        formatted["simulation"] = enriched.get("simulation")
        formatted["runtime_correlation"] = enriched.get("runtime_correlation")

        with self.client.session_transaction() as sess:
            sess["report"] = formatted

        response = self.client.get("/report/export/json")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("runtime_correlation", payload)
        if payload["runtime_correlation"]:
            self.assertIn("runtime_requested", payload["runtime_correlation"])
            self.assertIn("runtime_executed", payload["runtime_correlation"])


if __name__ == "__main__":
    unittest.main()
