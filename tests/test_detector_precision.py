import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import engine


class TestDetectorPrecision(unittest.TestCase):
    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def scan_file(self, filename: str) -> dict:
        path = os.path.join(self.samples_dir, filename)
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
        return engine.scan(source, filename)

    def findings_for_check(self, result: dict, check: str) -> list:
        return [finding for finding in result["findings"] if finding.get("check") == check]

    def test_reentrancy_safe_cei_not_flagged(self):
        result = self.scan_file("reentrancy_safe.sol")
        reentrancy_findings = self.findings_for_check(result, "reentrancy")
        self.assertEqual(reentrancy_findings, [])

    def test_reentrancy_vulnerable_has_high_confidence_evidence(self):
        result = self.scan_file("reentrancy.sol")
        reentrancy_findings = self.findings_for_check(result, "reentrancy")
        self.assertTrue(reentrancy_findings)
        finding = reentrancy_findings[0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertIn(finding["confidence"], {"HIGH", "MEDIUM"})
        self.assertEqual(finding["function"], "withdraw")
        self.assertIn("Function 'withdraw'", finding["evidence"]["notes"])

    def test_access_safe_not_flagged(self):
        result = self.scan_file("access_safe.sol")
        access_findings = self.findings_for_check(result, "missing-access-control")
        self.assertEqual(access_findings, [])

    def test_access_vulnerable_finds_unprotected_mint(self):
        result = self.scan_file("access.sol")
        access_findings = self.findings_for_check(result, "missing-access-control")
        vuln_names = {finding["vulnerability"] for finding in access_findings}
        self.assertIn("Missing Access Control in mint()", vuln_names)
        self.assertIn("Missing Access Control in transferOwnership()", vuln_names)
        self.assertTrue(all(finding["function"] for finding in access_findings))

    def test_delegatecall_safe_hardcoded_admin_path_not_flagged(self):
        result = self.scan_file("delegatecall_safe.sol")
        delegate_findings = self.findings_for_check(result, "delegatecall-untrusted-target")
        self.assertEqual(delegate_findings, [])

    def test_delegatecall_storage_backed_admin_path_downgraded_to_review(self):
        result = self.scan_file("delegatecall_review.sol")
        delegate_findings = self.findings_for_check(result, "delegatecall-untrusted-target")
        self.assertEqual(len(delegate_findings), 1)
        finding = delegate_findings[0]
        self.assertEqual(finding["vulnerability"], "Delegatecall Review Required")
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["confidence"], "MEDIUM")

    def test_delegatecall_user_controlled_still_high_risk(self):
        result = self.scan_file("delegatecall.sol")
        delegate_findings = self.findings_for_check(result, "delegatecall-untrusted-target")
        self.assertEqual(len(delegate_findings), 1)
        finding = delegate_findings[0]
        self.assertEqual(finding["vulnerability"], "Delegatecall to Untrusted Contract")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["confidence"], "HIGH")
        self.assertEqual(finding["function"], "executeLogic")

    def test_timestamp_detector_adds_scope_context(self):
        result = self.scan_file("timestamp.sol")
        timestamp_findings = self.findings_for_check(result, "timestamp-dependence")
        self.assertTrue(timestamp_findings)
        spin_finding = next(finding for finding in timestamp_findings if finding.get("function") == "spin")
        self.assertEqual(spin_finding["contract_name"], "RouletteGame")
        self.assertIn(spin_finding["confidence"], {"HIGH", "MEDIUM"})

    def test_weak_randomness_detector_adds_scope_context(self):
        result = self.scan_file("weak_randomness_runtime.sol")
        randomness_findings = self.findings_for_check(result, "predictable-randomness")
        self.assertTrue(randomness_findings)
        draw_finding = next(finding for finding in randomness_findings if finding.get("function") == "draw")
        self.assertEqual(draw_finding["contract_name"], "PredictableLottery")
        self.assertEqual(draw_finding["weak_randomness_source"], "block.timestamp")


if __name__ == "__main__":
    unittest.main()
