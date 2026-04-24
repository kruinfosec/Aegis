"""
Tests for integer overflow runtime validation.

Covers:
  - Helper functions (find_target_contract, has_function, build_constructor_args)
  - Scenario unit tests with mocked backend (underflow, overflow, revert)
  - Correlation merge-back tests
  - Pipeline integration tests
  - Real Hardhat integration tests (positive + negative)
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from simulation.compiler import CompiledContract
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_FAILED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
    ValidationRecord,
)
from simulation.scenarios.integer_overflow import (
    INITIAL_SUPPLY,
    UNDERFLOW_TRANSFER_AMOUNT,
    _build_constructor_args,
    _find_target_contract,
    _has_function,
    validate_integer_overflow,
)

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


def _make_overflow_abi():
    """Create a realistic ABI for VulnerableToken."""
    return [
        {"type": "constructor", "inputs": [{"name": "initialSupply", "type": "uint256"}]},
        {"type": "function", "name": "balances", "inputs": [{"name": "", "type": "address"}],
         "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "totalSupply", "inputs": [],
         "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "owner", "inputs": [],
         "outputs": [{"name": "", "type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "transfer", "inputs": [
            {"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}
        ], "outputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "addReward", "inputs": [
            {"name": "user", "type": "address"}, {"name": "reward", "type": "uint256"}
        ], "outputs": [], "stateMutability": "nonpayable"},
        {"type": "function", "name": "bulkTransfer", "inputs": [
            {"name": "to", "type": "address"},
            {"name": "unitAmount", "type": "uint256"},
            {"name": "units", "type": "uint256"},
        ], "outputs": [], "stateMutability": "nonpayable"},
    ]


def _make_compiled_contract(name="VulnerableToken", abi=None):
    return CompiledContract(
        contract_name=name,
        abi=abi or _make_overflow_abi(),
        bytecode="0x6080604052...",
    )


def _make_finding(function="transfer", contract_name="VulnerableToken", finding_id="overflow-1"):
    return {
        "id": finding_id,
        "vulnerability": "Integer Overflow / Underflow",
        "severity": "MEDIUM",
        "line": 31,
        "check": "integer-overflow",
        "contract_name": contract_name,
        "function": function,
        "description": "Arithmetic on uint256 without SafeMath.",
        "fix": "Use SafeMath or Solidity 0.8+.",
    }


def _make_mock_backend():
    backend = MagicMock()
    backend.backend_id = "hardhat"
    backend.get_accounts.return_value = [
        "0x1111111111111111111111111111111111111111",
        "0x2222222222222222222222222222222222222222",
    ]
    return backend


# ═══════════════════════════════════════════════════════════════════════════
# Helper Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestHelpers(unittest.TestCase):
    """Test helper functions for the integer overflow scenario."""

    def test_has_function(self):
        c = _make_compiled_contract()
        self.assertTrue(_has_function(c, "transfer"))
        self.assertTrue(_has_function(c, "balances"))
        self.assertFalse(_has_function(c, "nonexistent"))

    def test_find_target_contract_by_name(self):
        c = _make_compiled_contract("VulnerableToken")
        result = _find_target_contract([c], "VulnerableToken", "transfer")
        self.assertIsNotNone(result)
        self.assertEqual(result.contract_name, "VulnerableToken")

    def test_find_target_contract_by_function_fallback(self):
        c = _make_compiled_contract("SomeOtherName")
        result = _find_target_contract([c], "NonExistent", "transfer")
        self.assertIsNotNone(result)
        self.assertEqual(result.contract_name, "SomeOtherName")

    def test_find_target_contract_none(self):
        c = _make_compiled_contract()
        result = _find_target_contract([c], "VulnerableToken", "nonexistent")
        self.assertIsNone(result)

    def test_build_constructor_args_with_uint(self):
        c = _make_compiled_contract()
        accounts = ["0x1111"]
        args = _build_constructor_args(c, accounts)
        self.assertEqual(len(args), 1)
        self.assertEqual(args[0], INITIAL_SUPPLY)


# ═══════════════════════════════════════════════════════════════════════════
# Scenario Unit Tests (mocked backend)
# ═══════════════════════════════════════════════════════════════════════════

class TestIntegerOverflowScenarioUnit(unittest.TestCase):
    """Test integer overflow validation logic with mocked backend."""

    def test_confirmed_underflow_transfer(self):
        """When transfer from zero-balance wraps around, underflow is confirmed."""
        backend = _make_mock_backend()
        c = _make_compiled_contract()
        finding = _make_finding(function="transfer")

        backend.deploy_contract.return_value = {
            "contract_address": "0xCONTRACT",
            "tx_hash": "0xDEPLOY",
        }
        # balances: deployer has INITIAL_SUPPLY, attacker has 0.
        # After underflow: attacker has huge value.
        MAX_UINT256 = 2**256 - 1
        balance_calls = [INITIAL_SUPPLY, 0, MAX_UINT256]
        backend.call_function.side_effect = balance_calls

        backend.execute_transaction.return_value = {
            "success": True,
            "tx_hash": "0xATTACK",
            "reverted": False,
        }

        results = validate_integer_overflow(
            [finding], [c], backend, "// Source"
        )
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.status, RUNTIME_CONFIRMED)
        self.assertEqual(r.scenario, "integer_overflow.underflow_transfer")
        self.assertIn("underflow", r.evidence.get("classification_reason", "").lower())

    def test_not_confirmed_when_transfer_reverts(self):
        """When transfer reverts (has require guard), underflow not confirmed."""
        backend = _make_mock_backend()
        c = _make_compiled_contract()
        finding = _make_finding(function="transfer")

        backend.deploy_contract.return_value = {
            "contract_address": "0xCONTRACT",
            "tx_hash": "0xDEPLOY",
        }
        backend.call_function.side_effect = [INITIAL_SUPPLY, 0, 0]
        backend.execute_transaction.return_value = {
            "success": False,
            "reverted": True,
            "error": "Insufficient balance",
        }

        results = validate_integer_overflow([finding], [c], backend, "// Source")
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.status, RUNTIME_NOT_CONFIRMED)
        self.assertIn("reverted", r.evidence.get("classification_reason", "").lower())

    def test_unsupported_when_no_function_name(self):
        """Finding without function name should be unsupported."""
        backend = _make_mock_backend()
        c = _make_compiled_contract()
        finding = _make_finding(function=None)

        results = validate_integer_overflow([finding], [c], backend, "// Source")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, RUNTIME_UNSUPPORTED)

    def test_unsupported_when_no_balances_getter(self):
        """Contract without balances getter should be unsupported."""
        backend = _make_mock_backend()
        abi = [
            {"type": "function", "name": "transfer", "inputs": [
                {"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}
            ], "outputs": []},
        ]
        c = _make_compiled_contract(abi=abi)
        finding = _make_finding(function="transfer")

        results = validate_integer_overflow([finding], [c], backend, "// Source")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, RUNTIME_UNSUPPORTED)

    def test_findings_without_overflow_check_are_skipped(self):
        """Only integer-overflow check findings should be processed."""
        backend = _make_mock_backend()
        c = _make_compiled_contract()
        finding = _make_finding()
        finding["check"] = "reentrancy"

        results = validate_integer_overflow([finding], [c], backend, "// Source")
        self.assertEqual(len(results), 0)

    def test_generic_function_is_unsupported(self):
        """Functions without a specific strategy should be unsupported."""
        backend = _make_mock_backend()
        c = _make_compiled_contract()
        abi = _make_overflow_abi() + [
            {"type": "function", "name": "customArithmetic", "inputs": [], "outputs": []},
        ]
        c = _make_compiled_contract(abi=abi)
        finding = _make_finding(function="customArithmetic")

        backend.deploy_contract.return_value = {
            "contract_address": "0xCONTRACT",
            "tx_hash": "0xDEPLOY",
        }
        backend.call_function.side_effect = [INITIAL_SUPPLY, 0]

        results = validate_integer_overflow([finding], [c], backend, "// Source")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, RUNTIME_UNSUPPORTED)

    def test_confirmed_add_reward_overflow(self):
        """addReward with max uint256 should confirm overflow."""
        backend = _make_mock_backend()
        c = _make_compiled_contract()
        finding = _make_finding(function="addReward")

        backend.deploy_contract.return_value = {
            "contract_address": "0xCONTRACT",
            "tx_hash": "0xDEPLOY",
        }
        # deployer balance before = INITIAL_SUPPLY, attacker balance = 0
        # After adding max_uint256 reward: balance wraps to a small value.
        wrapped_value = 999  # Less than INITIAL_SUPPLY → overflow confirmed.
        backend.call_function.side_effect = [INITIAL_SUPPLY, 0, wrapped_value]

        backend.execute_transaction.return_value = {
            "success": True,
            "tx_hash": "0xREWARD",
            "reverted": False,
        }

        results = validate_integer_overflow([finding], [c], backend, "// Source")
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertEqual(r.status, RUNTIME_CONFIRMED)
        self.assertEqual(r.scenario, "integer_overflow.addReward")


# ═══════════════════════════════════════════════════════════════════════════
# Correlation Merge-Back Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestCorrelationMergeBack(unittest.TestCase):
    """Test that integer overflow results merge correctly through correlation."""

    def test_overflow_confirmed_merges_through_correlation(self):
        from scanner import engine
        from scanner.correlation import correlate

        source = _read_sample("overflow.sol")
        scan = engine.scan(source, "overflow.sol")

        # Find an overflow finding.
        overflow_findings = [f for f in scan["findings"] if f.get("check") == "integer-overflow"]
        self.assertGreater(len(overflow_findings), 0, "No overflow findings produced")

        f = overflow_findings[0]

        # Build a mock runtime result that confirms.
        mock_runtime = {
            "backend": "hardhat",
            "status": "confirmed_by_runtime",
            "success": True,
            "summary": "Runtime confirmed overflow.",
            "validations": [{
                "finding_id": f["id"],
                "status": "confirmed_by_runtime",
                "backend": "hardhat",
                "check": "integer-overflow",
                "scenario": "integer_overflow.underflow_transfer",
                "evidence": {"contract_name": "VulnerableToken", "function_tested": "transfer"},
                "limitations": [],
                "error": None,
            }],
            "diagnostics": {
                "total_ms": 5000, "compilation_ms": 2000,
                "backend_startup_ms": 2000, "scenario_execution_ms": 1000,
                "compilation_cache_hit": False, "startup_retries": 0,
                "compilation_warnings": [], "backend_port": 54321,
                "scenarios_attempted": 1, "scenarios_succeeded": 1,
                "scenarios_failed": 0, "error_phase": None,
            },
            "accounts": [],
            "metadata": {},
        }

        result = correlate(scan, mock_runtime, runtime_requested=True)
        enriched = [f for f in result["findings"] if f.get("check") == "integer-overflow"]
        confirmed = [f for f in enriched if f.get("runtime_validation_status") == "confirmed_by_runtime"]
        self.assertGreater(len(confirmed), 0, "No overflow finding was confirmed")

    def test_overflow_not_confirmed_merges_correctly(self):
        from scanner import engine
        from scanner.correlation import correlate

        source = _read_sample("overflow.sol")
        scan = engine.scan(source, "overflow.sol")

        overflow_findings = [f for f in scan["findings"] if f.get("check") == "integer-overflow"]
        self.assertGreater(len(overflow_findings), 0)
        f = overflow_findings[0]

        mock_runtime = {
            "backend": "hardhat",
            "status": "not_confirmed_by_runtime",
            "success": True,
            "summary": "Runtime did not confirm.",
            "validations": [{
                "finding_id": f["id"],
                "status": "not_confirmed_by_runtime",
                "backend": "hardhat",
                "check": "integer-overflow",
                "scenario": "integer_overflow.underflow_transfer",
                "evidence": {"transfer_reverted": True},
                "limitations": [],
                "error": None,
            }],
            "diagnostics": {
                "total_ms": 3000, "compilation_ms": 1000,
                "backend_startup_ms": 1500, "scenario_execution_ms": 500,
                "compilation_cache_hit": True, "startup_retries": 0,
                "compilation_warnings": [], "backend_port": 54322,
                "scenarios_attempted": 1, "scenarios_succeeded": 1,
                "scenarios_failed": 0, "error_phase": None,
            },
            "accounts": [],
            "metadata": {},
        }

        result = correlate(scan, mock_runtime, runtime_requested=True)
        enriched = [f for f in result["findings"] if f.get("check") == "integer-overflow"]
        not_confirmed = [f for f in enriched if f.get("runtime_validation_status") == "not_confirmed_by_runtime"]
        self.assertGreater(len(not_confirmed), 0, "No overflow finding was not-confirmed")


# ═══════════════════════════════════════════════════════════════════════════
# Pipeline Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestPipelineIntegrationOverflow(unittest.TestCase):
    """Test the full pipeline with mocked integer overflow runtime."""

    def test_pipeline_with_mocked_overflow_confirmed(self):
        """full_scan with mocked runtime that confirms integer overflow."""
        from scanner.pipeline import full_scan

        source = _read_sample("overflow.sol")

        def mock_runtime(source_code, findings, backend_name="hardhat"):
            overflow_findings = [f for f in findings if f.get("check") == "integer-overflow"]
            validations = []
            for f in overflow_findings:
                validations.append({
                    "finding_id": f["id"],
                    "status": "confirmed_by_runtime",
                    "backend": "hardhat",
                    "check": "integer-overflow",
                    "scenario": "integer_overflow.underflow_transfer",
                    "evidence": {"contract_name": "VulnerableToken"},
                    "limitations": [],
                    "error": None,
                })
            return {
                "backend": "hardhat",
                "status": "confirmed_by_runtime",
                "success": True,
                "summary": "Confirmed overflow.",
                "validations": validations,
                "diagnostics": {
                    "total_ms": 5000, "compilation_ms": 2000,
                    "backend_startup_ms": 2000, "scenario_execution_ms": 1000,
                    "compilation_cache_hit": False, "startup_retries": 0,
                    "compilation_warnings": [], "backend_port": 54321,
                    "scenarios_attempted": len(validations), "scenarios_succeeded": len(validations),
                    "scenarios_failed": 0, "error_phase": None,
                },
                "accounts": [],
                "metadata": {},
            }

        with patch("scanner.pipeline.run_runtime_validation", side_effect=mock_runtime):
            with patch("scanner.pipeline._SIMULATION_IMPORT_OK", True):
                result = full_scan(source, "overflow.sol", run_runtime=True)

        self.assertTrue(result["success"])
        rc = result.get("runtime_correlation")
        self.assertIsNotNone(rc)
        self.assertTrue(rc["runtime_requested"])
        self.assertTrue(rc["runtime_executed"])
        self.assertGreater(rc["confirmed_count"], 0)


# ═══════════════════════════════════════════════════════════════════════════
# Detector Enhancement Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectorEnhancement(unittest.TestCase):
    """Test that the enhanced overflow detector produces function/contract fields."""

    def test_detector_produces_function_name(self):
        from scanner import engine
        source = _read_sample("overflow.sol")
        scan = engine.scan(source, "overflow.sol")

        overflow_findings = [f for f in scan["findings"] if f.get("check") == "integer-overflow"]
        self.assertGreater(len(overflow_findings), 0)

        # At least one finding should have a function name.
        functions = {f.get("function") for f in overflow_findings}
        self.assertTrue(any(fn is not None for fn in functions),
                        f"No overflow findings have function names: {functions}")

    def test_detector_produces_contract_name(self):
        from scanner import engine
        source = _read_sample("overflow.sol")
        scan = engine.scan(source, "overflow.sol")

        overflow_findings = [f for f in scan["findings"] if f.get("check") == "integer-overflow"]
        self.assertGreater(len(overflow_findings), 0)

        for f in overflow_findings:
            self.assertEqual(f.get("contract_name"), "VulnerableToken",
                             f"Finding missing contract_name: {f}")

    def test_safe_sample_still_flags_arithmetic(self):
        """overflow_safe.sol uses 0.6.0 without SafeMath — detector should flag."""
        from scanner import engine
        source = _read_sample("overflow_safe.sol")
        scan = engine.scan(source, "overflow_safe.sol")

        overflow_findings = [f for f in scan["findings"] if f.get("check") == "integer-overflow"]
        self.assertGreater(len(overflow_findings), 0,
                           "Safe sample should still be flagged by static detector (pre-0.8, no SafeMath)")


# ═══════════════════════════════════════════════════════════════════════════
# Real Hardhat Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

# ── Hardhat-compilable 0.8+ sources for real integration tests ───────────
# npx solc installs the latest compiler (0.8.x), so we need 0.8+ fixtures.
# Vulnerable case: uses unchecked{} to re-enable wraparound.
# Safe case: normal 0.8 checked arithmetic (reverts on overflow).

_VULN_OVERFLOW_08_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableToken08
/// @notice Uses unchecked blocks — arithmetic CAN overflow/underflow.
contract VulnerableToken08 {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) public {
        unchecked {
            balances[msg.sender] -= amount;
            balances[to] += amount;
        }
    }
}
"""

_SAFE_OVERFLOW_08_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title SafeToken08
/// @notice Normal 0.8 checked arithmetic — reverts on overflow.
contract SafeToken08 {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor(uint256 initialSupply) {
        owner = msg.sender;
        totalSupply = initialSupply;
        balances[msg.sender] = initialSupply;
    }

    function transfer(address to, uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
"""


def _make_overflow_finding_for_runtime(finding_id, contract_name, function_name="transfer"):
    """Create a manually crafted finding for runtime testing.

    The static detector skips 0.8+ code, so for real Hardhat tests with 0.8+
    fixtures we craft findings directly.
    """
    return {
        "id": finding_id,
        "vulnerability": "Integer Overflow / Underflow",
        "severity": "MEDIUM",
        "line": 20,
        "check": "integer-overflow",
        "contract_name": contract_name,
        "function": function_name,
        "description": "Unchecked arithmetic in 0.8+ code.",
        "fix": "Remove unchecked block.",
    }


class TestRealHardhatIntegerOverflow(unittest.TestCase):
    """Integration tests that run against a real Hardhat node.

    Uses Solidity 0.8+ fixtures (compilable by npx solc) with:
    - unchecked{} blocks for the vulnerable case (wraparound)
    - normal checked arithmetic for the safe case (revert)

    Findings are crafted manually because the static detector
    skips 0.8+ code (it has built-in overflow protection).
    """

    @classmethod
    def setUpClass(cls):
        try:
            from simulation.service import simulation_available
            if not simulation_available():
                raise unittest.SkipTest("web3.py not available")
        except ImportError:
            raise unittest.SkipTest("simulation module not available")

    def test_real_hardhat_vulnerable_overflow(self):
        """Real Hardhat: VulnerableToken08 (unchecked) should be confirmed.

        The unchecked{} block allows uint256 underflow. Transferring from
        a zero-balance account causes the balance to wrap to max uint256.
        """
        from simulation.service import run_runtime_validation

        finding = _make_overflow_finding_for_runtime(
            "overflow-vuln-08", "VulnerableToken08", "transfer"
        )

        result = run_runtime_validation(
            _VULN_OVERFLOW_08_SOURCE, [finding], backend_name="hardhat"
        )

        self.assertIsNotNone(result)
        self.assertNotEqual(result.get("status"), "simulation_failed",
                            f"Runtime failed: {result.get('error', result.get('summary'))}")

        validations = result.get("validations", [])
        overflow_vals = [v for v in validations
                         if v.get("scenario", "").startswith("integer_overflow")]

        confirmed = [v for v in overflow_vals if v.get("status") == "confirmed_by_runtime"]
        self.assertGreater(len(confirmed), 0,
                           f"Expected confirmed overflow, got: "
                           f"{[(v.get('status'), v.get('error')) for v in overflow_vals]}")

        evidence = confirmed[0].get("evidence", {})
        self.assertIn("attacker_balance_after", evidence)
        self.assertIn("classification_reason", evidence)
        # Balance should have wrapped to a huge number.
        after = int(evidence["attacker_balance_after"])
        self.assertGreater(after, 10**70, f"Expected wraparound, got balance: {after}")

    def test_real_hardhat_safe_overflow(self):
        """Real Hardhat: SafeToken08 (checked) should be not_confirmed.

        Normal 0.8 arithmetic reverts on underflow. The transfer should
        fail and the balance should remain unchanged.
        """
        from simulation.service import run_runtime_validation

        finding = _make_overflow_finding_for_runtime(
            "overflow-safe-08", "SafeToken08", "transfer"
        )

        result = run_runtime_validation(
            _SAFE_OVERFLOW_08_SOURCE, [finding], backend_name="hardhat"
        )

        self.assertIsNotNone(result)
        self.assertNotEqual(result.get("status"), "simulation_failed",
                            f"Runtime failed: {result.get('error', result.get('summary'))}")

        validations = result.get("validations", [])
        overflow_vals = [v for v in validations
                         if v.get("scenario", "").startswith("integer_overflow")]

        # None should be confirmed.
        confirmed = [v for v in overflow_vals if v.get("status") == "confirmed_by_runtime"]
        self.assertEqual(len(confirmed), 0,
                         f"Safe contract should NOT be confirmed: "
                         f"{[(v.get('status'), v.get('error')) for v in overflow_vals]}")

        not_confirmed = [v for v in overflow_vals if v.get("status") == "not_confirmed_by_runtime"]
        self.assertGreater(len(not_confirmed), 0,
                           f"Expected not_confirmed, got: "
                           f"{[(v.get('status'), v.get('error')) for v in overflow_vals]}")


if __name__ == "__main__":
    unittest.main()
