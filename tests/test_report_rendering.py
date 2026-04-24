import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import REPORT_CACHE, SAMPLE_CATALOG, app
from scanner import engine
from scanner import report as report_formatter
from scanner.correlation import correlate


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


def _format_scan(sample_name: str, runtime_result=None, runtime_requested=False):
    source = _read_sample(sample_name)
    scan = engine.scan(source, sample_name)
    enriched = correlate(scan, runtime_result, runtime_requested=runtime_requested)
    formatted = report_formatter.format_report(enriched)
    formatted["runtime_correlation"] = enriched.get("runtime_correlation")
    formatted["simulation"] = enriched.get("simulation")
    formatted["simulation_diagnostics"] = (enriched.get("simulation") or {}).get("diagnostics")
    formatted["simulation_available"] = runtime_requested
    return formatted


def _runtime_result_for_first_finding(sample_name: str, status="confirmed_by_runtime"):
    scan = engine.scan(_read_sample(sample_name), sample_name)
    finding = scan["findings"][0]
    return {
        "backend": "hardhat",
        "status": status,
        "success": status in {"confirmed_by_runtime", "not_confirmed_by_runtime"},
        "summary": "Runtime smoke result",
        "validations": [
            {
                "finding_id": finding["id"],
                "status": status,
                "backend": "hardhat",
                "check": finding["check"],
                "scenario": "test.render_smoke",
                "contract_name": finding.get("contract_name"),
                "function_name": finding.get("function"),
                "evidence": {
                    "classification_reason": "Render smoke evidence with nested data.",
                    "nested": {"tx": "0xabc", "changed": True},
                    "items": [1, 2, 3],
                },
                "limitations": ["Render smoke limitation."],
                "error": "render smoke error" if status == "simulation_failed" else None,
            }
        ],
        "diagnostics": {
            "error_phase": "scenario_execution" if status == "simulation_failed" else None,
            "compilation_ms": 12.5,
            "backend_startup_ms": 40.0,
            "scenario_execution_ms": 8.0,
            "total_ms": 60.5,
            "compilation_cache_hit": False,
            "compilation_warnings": [],
            "startup_retries": 0,
            "backend_port": 50123,
            "scenarios_attempted": 1,
            "scenarios_succeeded": 1 if status != "simulation_failed" else 0,
            "scenarios_failed": 1 if status == "simulation_failed" else 0,
        },
        "accounts": [],
        "metadata": {"scenario_count": 1},
    }


class TestReportRendering(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def _render_report(self, report):
        with app.test_request_context("/report"):
            return app.jinja_env.get_template("report.html").render(report=report)

    def test_report_template_renders_enriched_runtime_finding(self):
        runtime = _runtime_result_for_first_finding("access.sol")
        report = _format_scan("access.sol", runtime_result=runtime, runtime_requested=True)
        html = self._render_report(report)
        self.assertIn("Runtime validation", html)
        self.assertIn("Runtime confirmed", html)
        self.assertIn("Details and remediation", html)
        self.assertIn("Render smoke evidence", html)

    def test_report_template_renders_empty_static_report(self):
        report = _format_scan("safe.sol")
        html = self._render_report(report)
        self.assertIn("No vulnerabilities detected", html)
        self.assertIn("Static analysis only", html)

    def test_report_template_renders_failed_runtime_state(self):
        runtime = _runtime_result_for_first_finding("access.sol", status="simulation_failed")
        report = _format_scan("access.sol", runtime_result=runtime, runtime_requested=True)
        html = self._render_report(report)
        self.assertIn("Runtime failed", html)
        self.assertIn("Diagnostics", html)
        self.assertIn("scenario_execution", html)

    def test_report_template_renders_when_scan_time_ms_missing(self):
        report = _format_scan("access.sol", runtime_result=_runtime_result_for_first_finding("access.sol"), runtime_requested=True)
        report.pop("scan_time_ms", None)
        html = self._render_report(report)
        self.assertIn("Scan report", html)
        self.assertIn("Runtime validation", html)

    def test_report_template_renders_minimal_stale_session_shape(self):
        stale_report = {
            "filename": "stale.sol",
            "risk_level": "HIGH",
            "risk_score": 8,
            "total_issues": 1,
            "findings": [
                {
                    "vulnerability": "Legacy Finding",
                    "severity": "HIGH",
                    "line": 7,
                    "description": "Old session payload without UI fields.",
                    "fix": "Review manually.",
                }
            ],
        }
        html = self._render_report(stale_report)
        self.assertIn("stale.sol", html)
        self.assertIn("Legacy Finding", html)
        self.assertIn("Static analysis only", html)

    def test_report_template_renders_without_runtime_diagnostics(self):
        report = _format_scan("access.sol", runtime_result=_runtime_result_for_first_finding("access.sol"), runtime_requested=True)
        report["simulation_diagnostics"] = {}
        report["simulation"] = {}
        report.pop("scan_time_ms", None)
        html = self._render_report(report)
        self.assertIn("Runtime validation", html)
        self.assertNotIn("UndefinedError", html)

    def test_report_route_redirects_without_session(self):
        response = self.client.get("/report")
        self.assertEqual(response.status_code, 302)

    def test_report_route_renders_with_session_report(self):
        report = _format_scan("access.sol", runtime_result=_runtime_result_for_first_finding("access.sol"), runtime_requested=True)
        with self.client.session_transaction() as sess:
            sess["report"] = report
        response = self.client.get("/report")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Findings", response.data)
        self.assertIn(b"Runtime validation", response.data)

    def test_report_route_normalizes_stale_session_report(self):
        with self.client.session_transaction() as sess:
            sess["report"] = {
                "filename": "legacy.sol",
                "risk_level": "MEDIUM",
                "risk_score": 5,
                "findings": [
                    {
                        "vulnerability": "Legacy Finding",
                        "severity": "MEDIUM",
                        "line": 3,
                        "description": "Legacy shape.",
                        "fix": "Review.",
                    }
                ],
            }
        response = self.client.get("/report")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"legacy.sol", response.data)
        self.assertIn(b"Legacy Finding", response.data)

    def test_json_export_route_handles_enriched_report(self):
        report = _format_scan("access.sol", runtime_result=_runtime_result_for_first_finding("access.sol"), runtime_requested=True)
        with self.client.session_transaction() as sess:
            sess["report"] = report
        response = self.client.get("/report/export/json")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("runtime_correlation", payload)
        self.assertTrue(payload["findings"])

    def test_json_export_route_handles_stale_session_report(self):
        with self.client.session_transaction() as sess:
            sess["report"] = {
                "filename": "legacy.sol",
                "risk_level": "LOW",
                "findings": [
                    {
                        "vulnerability": "Legacy Finding",
                        "severity": "LOW",
                        "line": 11,
                        "description": "Legacy export shape.",
                        "fix": "Review.",
                    }
                ],
            }
        response = self.client.get("/report/export/json")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["filename"], "legacy.sol")
        self.assertEqual(payload["findings"][0]["vulnerability"], "Legacy Finding")


class TestHomePageSampleFlows(unittest.TestCase):
    SAMPLE_NAMES = [sample["slug"] for sample in SAMPLE_CATALOG]

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_index_contains_expected_quick_test_links(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        for sample in SAMPLE_CATALOG:
            self.assertIn(f"/sample/{sample['slug']}".encode(), response.data)
            self.assertIn(sample["label"].encode("utf-8"), response.data)
            self.assertIn(f'data-sample-file="{sample["file"]}"'.encode(), response.data)

    def test_homepage_sample_routes_render_reports_and_export_json(self):
        with patch("app.is_runtime_available", return_value=False):
            for sample in SAMPLE_CATALOG:
                with self.subTest(sample=sample["slug"]):
                    response = self.client.get(f"/sample/{sample['slug']}", follow_redirects=True)
                    self.assertEqual(response.status_code, 200)
                    self.assertIn(b"Scan report", response.data)
                    self.assertIn(sample["file"].encode(), response.data)

                    export = self.client.get("/report/export/json")
                    self.assertEqual(export.status_code, 200)
                    payload = export.get_json()
                    self.assertEqual(payload["filename"], sample["file"])
                    self.assertIn("findings", payload)
                    checks = {finding.get("check") for finding in payload["findings"]}
                    if sample["expected_check"]:
                        self.assertIn(sample["expected_check"], checks)
                    else:
                        self.assertEqual(payload["total_issues"], 0)

    def test_quick_test_selection_replaces_previous_sample_report(self):
        with patch("app.is_runtime_available", return_value=False):
            first = self.client.get("/sample/timestamp", follow_redirects=True)
            self.assertEqual(first.status_code, 200)
            self.assertIn(b"timestamp.sol", first.data)

            second = self.client.get("/sample/reentrancy", follow_redirects=True)
            self.assertEqual(second.status_code, 200)
            self.assertIn(b"reentrancy.sol", second.data)
            self.assertNotIn(b"timestamp.sol", second.data)

            export = self.client.get("/report/export/json")
            payload = export.get_json()
            self.assertEqual(payload["filename"], "reentrancy.sol")
            self.assertEqual({finding.get("check") for finding in payload["findings"]}, {"reentrancy"})

    def test_quick_test_reports_are_cached_server_side_not_cookie_payloads(self):
        REPORT_CACHE.clear()
        with patch("app.is_runtime_available", return_value=False):
            response = self.client.get("/sample/reentrancy")
        self.assertEqual(response.status_code, 302)
        cookie = response.headers.get("Set-Cookie", "")
        self.assertLess(len(cookie), 1200)
        with self.client.session_transaction() as sess:
            self.assertIn("report_id", sess)
            self.assertNotIn("report", sess)
            self.assertIn(sess["report_id"], REPORT_CACHE)

    def test_unknown_sample_redirects_without_crashing(self):
        response = self.client.get("/sample/not-a-sample")
        self.assertEqual(response.status_code, 302)


if __name__ == "__main__":
    unittest.main()
