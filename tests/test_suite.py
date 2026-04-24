import unittest
import os
import sys

# Add the parent directory to the path so we can import the scanner module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scanner import engine

class TestAegisDetectors(unittest.TestCase):
    """
    Automated test suite for Aegis Vulnerability Scanner.
    Validates that each detector correctly identifies its target vulnerability 
    in the provided sample files.
    """

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), '..', 'samples')

    def scan_file(self, filename: str) -> dict:
        filepath = os.path.join(self.samples_dir, filename)
        with open(filepath, "r", encoding="utf-8") as f:
            source = f.read()
        return engine.scan(source, filename)

    def test_safe_contract(self):
        res = self.scan_file("safe.sol")
        self.assertTrue(res["success"])
        self.assertEqual(res["total_issues"], 0, "safe.sol should have 0 issues")
        self.assertEqual(res["risk_level"], "SAFE")

    def test_reentrancy(self):
        res = self.scan_file("reentrancy.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertIn("Reentrancy Risk: State Update After External Call", vulnerabilities)

    def test_integer_overflow(self):
        res = self.scan_file("overflow.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertIn("Integer Overflow / Underflow", vulnerabilities)

    def test_unprotected_selfdestruct(self):
        res = self.scan_file("selfdestruct.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertIn("Unprotected selfdestruct()", vulnerabilities)
        self.assertEqual(res["risk_level"], "CRITICAL")

    def test_weak_randomness(self):
        res = self.scan_file("randomness.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertTrue(any("Weak Randomness" in v for v in vulnerabilities))

    def test_delegatecall(self):
        res = self.scan_file("delegatecall.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertIn("Delegatecall to Untrusted Contract", vulnerabilities)

    def test_access_control(self):
        res = self.scan_file("access.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertTrue(any("Missing Access Control" in v for v in vulnerabilities))

    def test_timestamp_dependence(self):
        res = self.scan_file("timestamp.sol")
        self.assertTrue(res["total_issues"] >= 1)
        vulnerabilities = [f["vulnerability"] for f in res["findings"]]
        self.assertIn("Timestamp Dependence", vulnerabilities)

if __name__ == "__main__":
    unittest.main()
