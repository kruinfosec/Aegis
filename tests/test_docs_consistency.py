import json
import os
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scripts import dev


README = ROOT / "README.md"
DEV_WORKFLOW = ROOT / "docs" / "dev-workflow.md"
PACKAGE_JSON = ROOT / "package.json"


class TestDocsConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.readme = README.read_text(encoding="utf-8")
        cls.workflow = DEV_WORKFLOW.read_text(encoding="utf-8")
        cls.package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))

    def test_documented_demo_presets_exist_and_samples_exist(self):
        docs = f"{self.readme}\n{self.workflow}"
        for name, preset in dev.DEMO_PRESETS.items():
            self.assertIn(name, docs)
            self.assertTrue((ROOT / preset["sample"]).exists(), preset["sample"])

    def test_documented_verification_tiers_exist(self):
        docs = f"{self.readme}\n{self.workflow}"
        for tier in dev.VERIFY_COMMANDS:
            self.assertIn(f"check {tier}", docs)

    def test_runtime_status_terms_are_documented(self):
        for status in [
            "confirmed_by_runtime",
            "not_confirmed_by_runtime",
            "inconclusive_runtime",
            "simulation_unsupported",
            "simulation_failed",
            "NOT_RUN",
        ]:
            self.assertIn(status, self.readme)
            self.assertIn(status, self.workflow)

    def test_package_aliases_reference_current_workflow_commands(self):
        scripts = self.package["scripts"]
        expected = {
            "demo:list": "python scripts/dev.py demos",
            "demo:scan": "python scripts/dev.py demo weak-randomness",
            "demo:json": "python scripts/dev.py json-smoke weak-randomness",
            "benchmark:list": "python scripts/dev.py benchmark list",
            "benchmark:quick": "python scripts/dev.py benchmark run --quick",
            "benchmark:full": "python scripts/dev.py benchmark run --write",
            "test:fast": "python scripts/dev.py fast",
            "test:report": "python scripts/dev.py report",
            "test:runtime": "python scripts/dev.py runtime",
            "test:full": "python scripts/dev.py check full",
            "verify:demo": "python scripts/dev.py check demo",
            "verify:benchmark": "python scripts/dev.py check benchmark",
            "verify:runtime-support": "python scripts/dev.py check runtime-support",
            "runtime:support": "python scripts/dev.py support-matrix",
            "runtime:diagnose": "python scripts/dev.py diagnose samples/reentrancy.sol",
            "dev:web": "python scripts/dev.py web",
        }
        for name, command in expected.items():
            self.assertEqual(scripts.get(name), command)

    def test_docs_do_not_reference_old_ganache_runtime(self):
        docs = f"{self.readme}\n{self.workflow}"
        self.assertNotIn("Ganache", docs)


if __name__ == "__main__":
    unittest.main()
