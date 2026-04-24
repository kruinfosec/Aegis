"""
Tests for simulation hardening: caching, timeouts, retries, diagnostics.

Covers:
  - Compilation cache hits, misses, clearing
  - Compilation timeout handling
  - Hardhat startup retry logic (mock)
  - Structured diagnostics in simulation results
  - Error phase classification
  - Graceful degradation paths
"""

import hashlib
import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from simulation.compiler import (
    CompilationError,
    CompilationResult,
    CompiledContract,
    clear_compilation_cache,
    compile_source,
    compile_source_rich,
    get_cache_size,
    get_cache_stats,
    _source_hash,
)
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_FAILED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
    RuntimeDiagnostics,
    SimulationRunResult,
    ValidationRecord,
)
from simulation.backends.hardhat import HardhatBackend


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════════════
# Compilation Caching Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCompilationCache(unittest.TestCase):
    """Test in-memory compilation cache behavior."""

    def setUp(self):
        clear_compilation_cache()

    def tearDown(self):
        clear_compilation_cache()

    def test_source_hash_deterministic(self):
        """Same source produces the same hash."""
        source = "pragma solidity ^0.8.0; contract A { }"
        h1 = _source_hash(source)
        h2 = _source_hash(source)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # SHA-256 hex

    def test_different_source_different_hash(self):
        source_a = "pragma solidity ^0.8.0; contract A { }"
        source_b = "pragma solidity ^0.8.0; contract B { }"
        self.assertNotEqual(_source_hash(source_a), _source_hash(source_b))

    def test_cache_miss_then_hit(self):
        """First compilation is a miss, second with same source is a hit."""
        source = _read_sample("safe.sol")

        r1 = compile_source_rich(source)
        self.assertFalse(r1.cache_hit)
        self.assertGreater(r1.duration_ms, 0)
        self.assertGreater(len(r1.contracts), 0)

        r2 = compile_source_rich(source)
        self.assertTrue(r2.cache_hit)
        self.assertEqual(r2.duration_ms, 0.0)
        self.assertEqual(len(r2.contracts), len(r1.contracts))

    def test_cache_stats_tracked(self):
        """Cache hits and misses are counted."""
        source = _read_sample("safe.sol")

        stats_before = get_cache_stats()
        self.assertEqual(stats_before["hits"], 0)
        self.assertEqual(stats_before["misses"], 0)

        compile_source(source)  # miss
        compile_source(source)  # hit

        stats_after = get_cache_stats()
        self.assertEqual(stats_after["misses"], 1)
        self.assertEqual(stats_after["hits"], 1)

    def test_cache_size_grows(self):
        """Cache size increases with distinct sources."""
        s1 = _read_sample("safe.sol")
        s2 = _read_sample("access.sol")

        self.assertEqual(get_cache_size(), 0)
        compile_source(s1)
        self.assertEqual(get_cache_size(), 1)
        compile_source(s2)
        self.assertEqual(get_cache_size(), 2)

    def test_cache_clear(self):
        """Clearing cache resets everything."""
        compile_source(_read_sample("safe.sol"))
        self.assertGreater(get_cache_size(), 0)

        clear_compilation_cache()
        self.assertEqual(get_cache_size(), 0)
        self.assertEqual(get_cache_stats()["hits"], 0)
        self.assertEqual(get_cache_stats()["misses"], 0)

    def test_cache_bypass(self):
        """use_cache=False skips cache entirely."""
        source = _read_sample("safe.sol")
        compile_source(source)  # populate cache

        r = compile_source_rich(source, use_cache=False)
        self.assertFalse(r.cache_hit)
        self.assertGreater(r.duration_ms, 0)

    def test_compile_source_returns_contracts(self):
        """compile_source (non-rich) returns list of CompiledContract."""
        source = _read_sample("safe.sol")
        contracts = compile_source(source)
        self.assertIsInstance(contracts, list)
        self.assertTrue(all(isinstance(c, CompiledContract) for c in contracts))


# ═══════════════════════════════════════════════════════════════════════════
# Compilation Timeout Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCompilationTimeout(unittest.TestCase):
    """Test timeout handling in compilation."""

    def setUp(self):
        clear_compilation_cache()

    def tearDown(self):
        clear_compilation_cache()

    @patch("simulation.compiler.subprocess.run")
    def test_timeout_raises_compilation_error(self, mock_run):
        """TimeoutExpired should become CompilationError with clear message."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="solc", timeout=5)

        with self.assertRaises(CompilationError) as ctx:
            compile_source("pragma solidity ^0.8.0; contract A { }", timeout=5)

        self.assertIn("timed out", str(ctx.exception).lower())
        self.assertIn("5s", str(ctx.exception))

    @patch("simulation.compiler.subprocess.run")
    def test_timeout_not_cached(self, mock_run):
        """Failed compilation should not pollute the cache."""
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="solc", timeout=5)

        try:
            compile_source("pragma solidity ^0.8.0; contract A { }")
        except CompilationError:
            pass

        self.assertEqual(get_cache_size(), 0)


# ═══════════════════════════════════════════════════════════════════════════
# Hardhat Retry Logic Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestHardhatRetryLogic(unittest.TestCase):
    """Test bounded retry behavior for Hardhat startup."""

    @patch("simulation.backends.hardhat.shutil.which", return_value="npx")
    @patch("simulation.backends.hardhat.subprocess.Popen")
    def test_retry_on_immediate_exit(self, mock_popen, mock_which):
        """If process exits immediately, backend should retry up to startup_retries."""
        mock_process = MagicMock()
        mock_process.poll.return_value = 1  # Exited immediately
        mock_process.returncode = 1
        mock_popen.return_value = mock_process

        backend = HardhatBackend(port=9999, startup_timeout=2, startup_retries=3)

        with self.assertRaises(RuntimeError) as ctx:
            backend.start()

        # Should have attempted to spawn the process multiple times.
        self.assertGreaterEqual(mock_popen.call_count, 2)
        self.assertIn("exited before becoming ready", str(ctx.exception))

    @patch("simulation.backends.hardhat.shutil.which", return_value="npx")
    @patch("simulation.backends.hardhat.subprocess.Popen")
    def test_single_retry_succeeds(self, mock_popen, mock_which):
        """If first attempt fails but second succeeds, backend starts."""
        fail_process = MagicMock()
        fail_process.poll.return_value = 1
        fail_process.returncode = 1

        success_process = MagicMock()
        success_process.poll.return_value = None  # Still running

        mock_popen.side_effect = [fail_process, success_process]

        backend = HardhatBackend(port=9999, startup_timeout=2, startup_retries=2)

        # Mock is_ready to return True on second attempt.
        call_count = [0]
        def is_ready_side_effect():
            call_count[0] += 1
            return call_count[0] > 2  # False first 2 calls, True after
        backend.is_ready = is_ready_side_effect

        backend.start()
        self.assertEqual(mock_popen.call_count, 2)

    @patch("simulation.backends.hardhat.shutil.which", return_value=None)
    def test_no_npx_raises_immediately(self, mock_which):
        """If npx is not found, no retries should be attempted."""
        backend = HardhatBackend(port=9999)
        with self.assertRaises(RuntimeError) as ctx:
            backend.start()
        self.assertIn("npx", str(ctx.exception).lower())

    def test_get_diagnostics_structure(self):
        """get_diagnostics returns expected keys."""
        backend = HardhatBackend(port=9999)
        diag = backend.get_diagnostics()
        expected_keys = {"startup_retries_used", "startup_duration_ms", "port", "host", "managed_process", "connected"}
        self.assertEqual(set(diag.keys()), expected_keys)
        self.assertEqual(diag["port"], 9999)


# ═══════════════════════════════════════════════════════════════════════════
# Structured Diagnostics Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestStructuredDiagnostics(unittest.TestCase):
    """Test that RuntimeDiagnostics are produced and serialized correctly."""

    def test_diagnostics_default_values(self):
        d = RuntimeDiagnostics()
        data = d.to_dict()
        self.assertIsNone(data["error_phase"])
        self.assertIsNone(data["compilation_ms"])
        self.assertIsNone(data["backend_startup_ms"])
        self.assertEqual(data["startup_retries"], 0)
        self.assertEqual(data["scenarios_attempted"], 0)

    def test_diagnostics_serialized_in_run_result(self):
        d = RuntimeDiagnostics(
            error_phase="compilation",
            compilation_ms=150.5,
            compilation_cache_hit=False,
            startup_retries=1,
        )
        result = SimulationRunResult(
            backend="hardhat",
            status=RUNTIME_FAILED,
            success=False,
            summary="Test",
            diagnostics=d,
        )
        data = result.to_dict()
        self.assertIn("diagnostics", data)
        self.assertEqual(data["diagnostics"]["error_phase"], "compilation")
        self.assertEqual(data["diagnostics"]["compilation_ms"], 150.5)
        self.assertFalse(data["diagnostics"]["compilation_cache_hit"])
        self.assertEqual(data["diagnostics"]["startup_retries"], 1)

    def test_diagnostics_scenario_counts(self):
        d = RuntimeDiagnostics(
            scenarios_attempted=5,
            scenarios_succeeded=3,
            scenarios_failed=1,
        )
        data = d.to_dict()
        self.assertEqual(data["scenarios_attempted"], 5)
        self.assertEqual(data["scenarios_succeeded"], 3)
        self.assertEqual(data["scenarios_failed"], 1)


# ═══════════════════════════════════════════════════════════════════════════
# Service-Level Diagnostics Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestServiceDiagnostics(unittest.TestCase):
    """Test that run_runtime_validation populates diagnostics."""

    def _read_sample(self, name):
        return _read_sample(name)

    def test_unsupported_backend_has_diagnostics(self):
        from simulation.service import run_runtime_validation
        result = run_runtime_validation("pragma solidity ^0.8.0;", [{"check": "reentrancy"}], backend_name="anvil")
        self.assertIn("diagnostics", result)
        self.assertEqual(result["diagnostics"]["error_phase"], "backend_selection")

    def test_no_findings_has_diagnostics(self):
        from simulation.service import run_runtime_validation
        result = run_runtime_validation("pragma solidity ^0.8.0;", [])
        self.assertIn("diagnostics", result)
        self.assertEqual(result["diagnostics"]["error_phase"], "finding_filter")

    def test_unsupported_checks_has_diagnostics(self):
        from simulation.service import run_runtime_validation
        result = run_runtime_validation("x", [{"check": "some-future-check"}])
        self.assertIn("diagnostics", result)
        self.assertEqual(result["diagnostics"]["error_phase"], "finding_filter")

    @patch("simulation.service.compile_source_rich", side_effect=CompilationError("solc missing"))
    def test_compilation_failure_has_diagnostics(self, _mock):
        from simulation.service import run_runtime_validation
        result = run_runtime_validation(
            "pragma solidity ^0.8.0;",
            [{"check": "missing-access-control"}],
        )
        self.assertIn("diagnostics", result)
        self.assertEqual(result["diagnostics"]["error_phase"], "compilation")
        self.assertEqual(result["status"], RUNTIME_FAILED)
        self.assertIn("compilation", result["summary"].lower())

    def test_real_run_has_timing_diagnostics(self):
        """Real Hardhat run should produce timing diagnostics."""
        from simulation.service import run_runtime_validation
        from scanner import engine

        source = self._read_sample("access.sol")
        scan_result = engine.scan(source, "access.sol")
        result = run_runtime_validation(source, scan_result["findings"])

        d = result.get("diagnostics", {})
        self.assertIsNotNone(d.get("compilation_ms"), "compilation_ms should be set")
        self.assertIsNotNone(d.get("backend_startup_ms"), "backend_startup_ms should be set")
        self.assertIsNotNone(d.get("scenario_execution_ms"), "scenario_execution_ms should be set")
        self.assertIsNotNone(d.get("total_ms"), "total_ms should be set")
        self.assertGreater(d["total_ms"], 0)

    def test_real_run_cache_hit_on_second_call(self):
        """Second call with same source should hit compilation cache."""
        from simulation.service import run_runtime_validation
        from scanner import engine

        clear_compilation_cache()

        source = self._read_sample("access.sol")
        scan_result = engine.scan(source, "access.sol")

        r1 = run_runtime_validation(source, scan_result["findings"])
        d1 = r1.get("diagnostics", {})
        # First call: cache miss.
        self.assertFalse(d1.get("compilation_cache_hit", True))

        r2 = run_runtime_validation(source, scan_result["findings"])
        d2 = r2.get("diagnostics", {})
        # Second call: cache hit.
        self.assertTrue(d2.get("compilation_cache_hit", False))

        clear_compilation_cache()


# ═══════════════════════════════════════════════════════════════════════════
# Error Phase Classification Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestErrorPhaseClassification(unittest.TestCase):
    """Test that different failure modes produce correct error_phase."""

    def test_backend_startup_error_phase(self):
        from simulation.service import run_runtime_validation

        with patch("simulation.service.compile_source_rich") as mock_compile:
            mock_compile.return_value = CompilationResult(
                contracts=[CompiledContract("A", [], "0x00")],
                cache_hit=False, duration_ms=10, warnings=[], source_hash="abc",
            )
            with patch("simulation.service.HardhatBackend") as MockBackend:
                instance = MockBackend.return_value
                instance.start.side_effect = RuntimeError("Hardhat node failed to start")
                instance.stop.return_value = None

                result = run_runtime_validation(
                    "pragma solidity ^0.8.0;",
                    [{"check": "missing-access-control"}],
                )

        self.assertEqual(result["status"], RUNTIME_FAILED)
        self.assertEqual(result["diagnostics"]["error_phase"], "backend_startup")

    def test_generic_error_phase(self):
        from simulation.service import run_runtime_validation

        with patch("simulation.service.compile_source_rich") as mock_compile:
            mock_compile.return_value = CompilationResult(
                contracts=[CompiledContract("A", [], "0x00")],
                cache_hit=False, duration_ms=10, warnings=[], source_hash="abc",
            )
            with patch("simulation.service.HardhatBackend") as MockBackend:
                instance = MockBackend.return_value
                instance.start.side_effect = RuntimeError("Something unexpected happened")
                instance.stop.return_value = None

                result = run_runtime_validation(
                    "pragma solidity ^0.8.0;",
                    [{"check": "missing-access-control"}],
                )

        self.assertEqual(result["status"], RUNTIME_FAILED)
        self.assertEqual(result["diagnostics"]["error_phase"], "scenario_execution")


# ═══════════════════════════════════════════════════════════════════════════
# Graceful Degradation with Diagnostics
# ═══════════════════════════════════════════════════════════════════════════

class TestGracefulDegradationWithDiagnostics(unittest.TestCase):
    """Pipeline graceful degradation should still produce diagnostics."""

    def test_pipeline_passes_diagnostics_through(self):
        """Pipeline fallback results should preserve diagnostics field."""
        from scanner.pipeline import full_scan

        source = _read_sample("safe.sol")

        # Static-only scan (no runtime) — should include runtime_correlation.
        result = full_scan(source, "safe.sol", run_runtime=False)
        self.assertIn("runtime_correlation", result)

    def test_pipeline_exception_fallback_has_structure(self):
        """If runtime raises, fallback result should be well-structured."""
        from scanner.pipeline import _try_runtime

        with patch("scanner.pipeline.run_runtime_validation", side_effect=Exception("boom")):
            result = _try_runtime("source", [], "hardhat")

        self.assertEqual(result["status"], "simulation_failed")
        self.assertIn("error", result)
        self.assertEqual(result["error"], "boom")


# ═══════════════════════════════════════════════════════════════════════════
# Compilation Result Model
# ═══════════════════════════════════════════════════════════════════════════

class TestCompilationResultModel(unittest.TestCase):
    """Test CompilationResult dataclass."""

    def test_default_values(self):
        r = CompilationResult(contracts=[])
        self.assertFalse(r.cache_hit)
        self.assertEqual(r.duration_ms, 0.0)
        self.assertEqual(r.warnings, [])
        self.assertEqual(r.source_hash, "")

    def test_with_values(self):
        c = CompiledContract("X", [{"type": "function"}], "0xaa")
        r = CompilationResult(
            contracts=[c],
            cache_hit=True,
            duration_ms=42.5,
            warnings=["Warning 1"],
            source_hash="abc123",
        )
        self.assertTrue(r.cache_hit)
        self.assertEqual(r.duration_ms, 42.5)
        self.assertEqual(len(r.contracts), 1)
        self.assertEqual(r.source_hash, "abc123")


if __name__ == "__main__":
    unittest.main()
