import os
import subprocess
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
DEV = [sys.executable, "scripts/dev.py"]


def run_dev(*args):
    return subprocess.run(
        [*DEV, *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class TestDevWorkflow(unittest.TestCase):
    def test_lists_curated_demos(self):
        result = run_dev("demos")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("weak-randomness", result.stdout)
        self.assertIn("access-control", result.stdout)
        self.assertIn("safe-static", result.stdout)

    def test_demo_dry_run_outputs_cli_command(self):
        result = run_dev("demo", "timestamp", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("aegis.py", result.stdout)
        self.assertIn("samples/timestamp.sol", result.stdout)
        self.assertIn("--runtime", result.stdout)

    def test_check_dry_run_outputs_verification_command(self):
        result = run_dev("check", "report", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unittest", result.stdout)
        self.assertIn("tests.test_report_rendering", result.stdout)

    def test_web_dry_run_can_print_sample_hint(self):
        result = run_dev("web", "--sample", "weak-randomness", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("samples/weak_randomness_runtime.sol", result.stdout)
        self.assertIn("app.py", result.stdout)

    def test_scaffold_dry_run_lists_expected_files(self):
        result = run_dev("scaffold", "price-oracle", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("simulation", result.stdout)
        self.assertIn("price_oracle.py", result.stdout)
        self.assertIn("samples", result.stdout)
        self.assertIn("test_price_oracle_runtime.py", result.stdout)

    def test_legacy_fast_alias_still_maps_to_check_fast(self):
        result = run_dev("fast", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tests.test_detector_precision", result.stdout)


if __name__ == "__main__":
    unittest.main()
