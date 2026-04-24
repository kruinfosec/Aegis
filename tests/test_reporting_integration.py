"""
Tests for reporting integration: web UI, CLI text, CLI JSON, diagnostics.

Covers:
  - Report formatter with runtime-enriched findings
  - JSON export shape (runtime_correlation, diagnostics, per-finding fields)
  - CLI text output with runtime status, evidence, diagnostics
  - CLI JSON output structure
  - Correct display for all runtime statuses
  - Regression protection for report ordering
"""

import json
import os
import sys
import unittest
from io import StringIO
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import app
from scanner import engine
from scanner import report as report_formatter
from scanner.pipeline import full_scan
from scanner.finding import merge_runtime_validations, summarize_findings


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


def _make_runtime_result_confirmed(finding_id: str) -> dict:
    """Create a mock runtime result that confirms one finding."""
    return {
        "backend": "hardhat",
        "status": "confirmed_by_runtime",
        "success": True,
        "summary": "Runtime confirmed",
        "validations": [
            {
                "finding_id": finding_id,
                "status": "confirmed_by_runtime",
                "backend": "hardhat",
                "check": "access_control.unauthorized_privileged_call",
                "scenario": "access_control.unauthorized_call",
                "evidence": {
                    "victim_contract": "UnprotectedToken",
                    "tx_hash": "0xabc123",
                    "reverted": False,
                },
                "limitations": ["Test limitation"],
                "error": None,
            }
        ],
        "diagnostics": {
            "error_phase": None,
            "compilation_ms": 5200.5,
            "backend_startup_ms": 3100.2,
            "scenario_execution_ms": 800.0,
            "total_ms": 9200.7,
            "compilation_cache_hit": False,
            "compilation_warnings": [],
            "startup_retries": 0,
            "backend_port": 54321,
            "scenarios_attempted": 1,
            "scenarios_succeeded": 1,
            "scenarios_failed": 0,
        },
        "accounts": ["0x1111", "0x2222"],
        "metadata": {"scenario_count": 1},
    }


def _make_runtime_result_not_confirmed(finding_id: str) -> dict:
    return {
        "backend": "hardhat",
        "status": "not_confirmed_by_runtime",
        "success": True,
        "summary": "Runtime did not confirm",
        "validations": [
            {
                "finding_id": finding_id,
                "status": "not_confirmed_by_runtime",
                "backend": "hardhat",
                "check": "access_control.unauthorized_privileged_call",
                "scenario": "access_control.unauthorized_call",
                "evidence": {"reverted": True},
                "limitations": [],
                "error": "Not owner",
            }
        ],
        "diagnostics": {
            "error_phase": None,
            "compilation_ms": 100.0,
            "backend_startup_ms": 2000.0,
            "scenario_execution_ms": 500.0,
            "total_ms": 2600.0,
            "compilation_cache_hit": True,
            "compilation_warnings": [],
            "startup_retries": 0,
            "backend_port": 54322,
            "scenarios_attempted": 1,
            "scenarios_succeeded": 1,
            "scenarios_failed": 0,
        },
        "accounts": [],
        "metadata": {},
    }


# ═══════════════════════════════════════════════════════════════════════════
# Web Report Formatter Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestReportFormatterRuntime(unittest.TestCase):
    """Test that report formatter preserves runtime fields."""

    def test_confirmed_finding_has_runtime_fields(self):
        scan = engine.scan(_read_sample("access.sol"), "access.sol")
        finding = scan["findings"][0]
        runtime = _make_runtime_result_confirmed(finding["id"])
        enriched = merge_runtime_validations(scan["findings"], runtime)
        scan["findings"] = enriched
        formatted = report_formatter.format_report(scan)

        f0 = formatted["findings"][0]
        self.assertEqual(f0["runtime_validation_status"], "confirmed_by_runtime")
        self.assertEqual(f0["runtime_backend"], "hardhat")
        self.assertIsNotNone(f0["runtime_evidence"])
        self.assertEqual(f0["verification"]["dynamic"], "CONFIRMED")
        self.assertEqual(f0["exploitability"], "CONFIRMED_BY_RUNTIME")
        # UI CSS fields should also exist.
        self.assertIn("severity_css", f0)
        self.assertIn("severity_icon", f0)

    def test_not_confirmed_finding_has_correct_fields(self):
        scan = engine.scan(_read_sample("access.sol"), "access.sol")
        finding = scan["findings"][0]
        runtime = _make_runtime_result_not_confirmed(finding["id"])
        enriched = merge_runtime_validations(scan["findings"], runtime)
        scan["findings"] = enriched
        formatted = report_formatter.format_report(scan)

        f0 = formatted["findings"][0]
        self.assertEqual(f0["runtime_validation_status"], "not_confirmed_by_runtime")
        self.assertEqual(f0["verification"]["dynamic"], "NOT_CONFIRMED")
        self.assertEqual(f0["exploitability"], "NOT_CONFIRMED_BY_RUNTIME")

    def test_unrun_finding_has_default_status(self):
        scan = engine.scan(_read_sample("access.sol"), "access.sol")
        formatted = report_formatter.format_report(scan)
        f0 = formatted["findings"][0]
        self.assertEqual(f0["runtime_validation_status"], "NOT_RUN")
        self.assertIsNone(f0["runtime_backend"])

    def test_verified_findings_count_reflects_runtime(self):
        scan = engine.scan(_read_sample("access.sol"), "access.sol")
        finding = scan["findings"][0]
        runtime = _make_runtime_result_confirmed(finding["id"])
        enriched = merge_runtime_validations(scan["findings"], runtime)
        scan["findings"] = enriched
        scan["analysis_summary"] = summarize_findings(enriched)
        formatted = report_formatter.format_report(scan)
        self.assertGreaterEqual(formatted["verified_findings"], 1)


# ═══════════════════════════════════════════════════════════════════════════
# JSON Export Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestJSONExportRuntime(unittest.TestCase):
    """Test JSON export includes runtime, correlation, and diagnostics."""

    def setUp(self):
        self.client = app.test_client()

    def _setup_session_with_runtime(self):
        """Scan a sample and inject mocked runtime into the session."""
        scan = engine.scan(_read_sample("access.sol"), "access.sol")
        finding = scan["findings"][0]
        runtime = _make_runtime_result_confirmed(finding["id"])
        enriched = merge_runtime_validations(scan["findings"], runtime)
        scan["findings"] = enriched
        scan["analysis_summary"] = summarize_findings(enriched)

        from scanner.correlation import build_runtime_summary
        scan["runtime_correlation"] = build_runtime_summary(
            enriched, runtime_result=runtime, runtime_requested=True,
        )

        formatted = report_formatter.format_report(scan)
        formatted["runtime_correlation"] = scan["runtime_correlation"]
        formatted["simulation"] = runtime
        formatted["simulation_diagnostics"] = runtime.get("diagnostics")
        formatted["simulation_available"] = True
        return formatted

    def test_export_includes_runtime_correlation(self):
        with self.client.session_transaction() as sess:
            sess["report"] = self._setup_session_with_runtime()

        response = self.client.get("/report/export/json")
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("runtime_correlation", payload)
        rc = payload["runtime_correlation"]
        self.assertTrue(rc["runtime_requested"])
        self.assertTrue(rc["runtime_executed"])
        self.assertGreaterEqual(rc["confirmed_count"], 1)

    def test_export_includes_diagnostics(self):
        with self.client.session_transaction() as sess:
            sess["report"] = self._setup_session_with_runtime()

        response = self.client.get("/report/export/json")
        payload = response.get_json()
        self.assertIn("simulation_diagnostics", payload)
        diag = payload["simulation_diagnostics"]
        self.assertIsNotNone(diag)
        self.assertIn("total_ms", diag)
        self.assertIn("compilation_ms", diag)
        self.assertIn("compilation_cache_hit", diag)

    def test_export_includes_simulation_available(self):
        with self.client.session_transaction() as sess:
            sess["report"] = self._setup_session_with_runtime()

        response = self.client.get("/report/export/json")
        payload = response.get_json()
        self.assertIn("simulation_available", payload)
        self.assertTrue(payload["simulation_available"])

    def test_export_per_finding_runtime_fields(self):
        with self.client.session_transaction() as sess:
            sess["report"] = self._setup_session_with_runtime()

        response = self.client.get("/report/export/json")
        payload = response.get_json()
        f0 = payload["findings"][0]
        self.assertEqual(f0["runtime_validation_status"], "confirmed_by_runtime")
        self.assertEqual(f0["runtime_backend"], "hardhat")
        self.assertIsNotNone(f0["runtime_evidence"])
        self.assertIsNotNone(f0["validation_notes"])
        self.assertEqual(f0["verification"]["dynamic"], "CONFIRMED")

    def test_export_without_runtime_still_has_fields(self):
        """Export without runtime should still have null/default runtime fields."""
        scan = engine.scan(_read_sample("access.sol"), "access.sol")
        formatted = report_formatter.format_report(scan)
        formatted["runtime_correlation"] = None
        formatted["simulation_diagnostics"] = None
        formatted["simulation_available"] = False

        with self.client.session_transaction() as sess:
            sess["report"] = formatted

        response = self.client.get("/report/export/json")
        payload = response.get_json()
        self.assertIsNone(payload["runtime_correlation"])
        self.assertIsNone(payload["simulation_diagnostics"])
        self.assertFalse(payload["simulation_available"])
        f0 = payload["findings"][0]
        self.assertEqual(f0["runtime_validation_status"], "NOT_RUN")


# ═══════════════════════════════════════════════════════════════════════════
# CLI Text Output Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCLITextOutput(unittest.TestCase):
    """Test CLI text output includes runtime context."""

    def test_text_finding_with_runtime_confirmed(self):
        from aegis import _print_text_finding
        finding = {
            "vulnerability": "Missing Access Control",
            "severity": "HIGH",
            "line": 10,
            "contract_name": "UnprotectedToken",
            "function": "mint",
            "description": "No access control on mint",
            "fix": "Add onlyOwner modifier",
            "runtime_validation_status": "confirmed_by_runtime",
            "exploitability": "CONFIRMED_BY_RUNTIME",
            "runtime_evidence": {"victim_contract": "UnprotectedToken", "tx_hash": "0xabc"},
            "validation_notes": ["Runtime confirmed the vulnerability."],
        }
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_text_finding(0, finding)
        output = buf.getvalue()
        self.assertIn("Confirmed by Runtime", output)
        self.assertIn("CONFIRMED_BY_RUNTIME", output)
        self.assertIn("UnprotectedToken", output)
        self.assertIn("mint()", output)
        self.assertIn("Evidence:", output)

    def test_text_finding_not_confirmed(self):
        from aegis import _print_text_finding
        finding = {
            "vulnerability": "Missing Access Control",
            "severity": "HIGH",
            "line": 10,
            "description": "Test",
            "fix": "Fix",
            "runtime_validation_status": "not_confirmed_by_runtime",
            "exploitability": "NOT_CONFIRMED_BY_RUNTIME",
            "runtime_evidence": {"reverted": True},
            "validation_notes": ["Attack reverted."],
        }
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_text_finding(0, finding)
        output = buf.getvalue()
        self.assertIn("Not Confirmed by Runtime", output)
        self.assertIn("NOT_CONFIRMED_BY_RUNTIME", output)

    def test_text_finding_not_run(self):
        from aegis import _print_text_finding
        finding = {
            "vulnerability": "Weak Randomness",
            "severity": "MEDIUM",
            "line": 20,
            "description": "Predictable",
            "fix": "Use VRF",
            "runtime_validation_status": "NOT_RUN",
            "exploitability": "UNVERIFIED",
        }
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_text_finding(0, finding)
        output = buf.getvalue()
        # NOT_RUN should NOT print runtime status.
        self.assertNotIn("Runtime:", output)

    def test_text_diagnostics_output(self):
        from aegis import _print_text_diagnostics
        diag = {
            "total_ms": 9200.7,
            "compilation_ms": 5200.5,
            "compilation_cache_hit": False,
            "backend_startup_ms": 3100.2,
            "startup_retries": 0,
            "scenario_execution_ms": 800.0,
            "error_phase": None,
        }
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_text_diagnostics(diag)
        output = buf.getvalue()
        self.assertIn("Diagnostics:", output)
        self.assertIn("total=", output)
        self.assertIn("compile=", output)
        self.assertIn("startup=", output)
        self.assertIn("scenarios=", output)

    def test_text_diagnostics_with_cache_hit(self):
        from aegis import _print_text_diagnostics
        diag = {
            "total_ms": 2000.0,
            "compilation_ms": 0.0,
            "compilation_cache_hit": True,
            "backend_startup_ms": 1500.0,
            "startup_retries": 1,
            "scenario_execution_ms": 400.0,
            "error_phase": None,
        }
        buf = StringIO()
        with patch("sys.stdout", buf):
            _print_text_diagnostics(diag)
        output = buf.getvalue()
        self.assertIn("(cached)", output)
        self.assertIn("(1 retries)", output)


# ═══════════════════════════════════════════════════════════════════════════
# CLI JSON Output Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCLIJSONOutput(unittest.TestCase):
    """Test CLI JSON output includes all enriched fields."""

    def test_json_output_includes_runtime_correlation(self):
        """full_scan JSON output should include runtime_correlation."""
        source = _read_sample("access.sol")
        result = full_scan(source, "access.sol", run_runtime=False)
        # JSON serialization should work.
        json_str = json.dumps([result], indent=2)
        parsed = json.loads(json_str)
        self.assertIn("runtime_correlation", parsed[0])

    def test_json_output_has_simulation_with_diagnostics(self):
        """full_scan with runtime should include simulation + diagnostics."""
        source = _read_sample("access.sol")
        # Mock runtime to avoid needing Hardhat.
        scan = engine.scan(source, "access.sol")
        finding = scan["findings"][0]
        runtime = _make_runtime_result_confirmed(finding["id"])

        from scanner.correlation import correlate
        result = correlate(scan, runtime, runtime_requested=True)

        json_str = json.dumps([result], indent=2)
        parsed = json.loads(json_str)
        r = parsed[0]
        self.assertIn("simulation", r)
        self.assertIn("diagnostics", r["simulation"])
        self.assertIn("runtime_correlation", r)
        self.assertTrue(r["runtime_correlation"]["runtime_requested"])

    def test_json_per_finding_runtime_shape(self):
        """JSON output findings should have stable runtime field shape."""
        source = _read_sample("access.sol")
        scan = engine.scan(source, "access.sol")
        finding = scan["findings"][0]
        runtime = _make_runtime_result_confirmed(finding["id"])

        from scanner.correlation import correlate
        result = correlate(scan, runtime, runtime_requested=True)

        f0 = result["findings"][0]
        # All runtime fields should be present.
        for key in ["runtime_validation_status", "runtime_backend", "runtime_scenario",
                     "runtime_evidence", "validation_notes", "exploitability", "verification"]:
            self.assertIn(key, f0, f"Missing key: {key}")


# ═══════════════════════════════════════════════════════════════════════════
# All Runtime Status Display Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestAllRuntimeStatusDisplay(unittest.TestCase):
    """Test correct wording/label for every runtime status."""

    def test_all_statuses_have_labels(self):
        from aegis import RUNTIME_STATUS_LABELS
        expected_statuses = {
            "confirmed_by_runtime",
            "not_confirmed_by_runtime",
            "inconclusive_runtime",
            "simulation_unsupported",
            "simulation_failed",
            "NOT_RUN",
        }
        self.assertEqual(set(RUNTIME_STATUS_LABELS.keys()), expected_statuses)

    def test_label_wording_is_honest(self):
        from aegis import RUNTIME_STATUS_LABELS
        # Should NOT contain misleading terms.
        for label in RUNTIME_STATUS_LABELS.values():
            self.assertNotIn("passed", label.lower())
            self.assertNotIn("safe", label.lower())
            self.assertNotIn("demo", label.lower())


if __name__ == "__main__":
    unittest.main()
