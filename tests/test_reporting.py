import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import app
from scanner import engine
from scanner import report as report_formatter


class TestAegisReporting(unittest.TestCase):
    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename: str) -> str:
        path = os.path.join(self.samples_dir, filename)
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()

    def test_engine_returns_structured_finding_fields(self):
        result = engine.scan(self.read_sample("selfdestruct.sol"), "selfdestruct.sol")

        self.assertTrue(result["success"])
        self.assertGreater(result["total_issues"], 0)

        finding = result["findings"][0]
        self.assertIn("confidence", finding)
        self.assertIn("impact", finding)
        self.assertIn("exploit_path", finding)
        self.assertIn("limitations", finding)
        self.assertIn("evidence", finding)
        self.assertIn("verification", finding)
        self.assertEqual(finding["verification"]["static"], "FLAGGED")
        self.assertEqual(finding["verification"]["dynamic"], "NOT_RUN")
        self.assertTrue(str(finding["swc_id"]).startswith("SWC-"))

    def test_report_formatter_preserves_summary_counts(self):
        result = engine.scan(self.read_sample("overflow.sol"), "overflow.sol")
        formatted = report_formatter.format_report(result)

        self.assertIn("confidence_counts", formatted)
        self.assertIn("severity_counts", formatted)
        self.assertGreaterEqual(formatted["unverified_findings"], 1)

    def test_json_export_includes_professional_report_fields(self):
        client = app.test_client()
        result = engine.scan(self.read_sample("delegatecall.sol"), "delegatecall.sol")
        with client.session_transaction() as session:
            session["report"] = report_formatter.format_report(result)

        response = client.get("/report/export/json")
        payload = response.get_json()

        self.assertEqual(response.status_code, 200)
        self.assertIn("analysis_summary", payload)
        self.assertIn("findings", payload)
        self.assertIn("confidence", payload["findings"][0])
        self.assertIn("evidence", payload["findings"][0])
        self.assertIn("limitations", payload["findings"][0])


if __name__ == "__main__":
    unittest.main()
