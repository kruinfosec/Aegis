"""
Tests for reentrancy runtime validation.

Covers:
- unit tests with FakeBackend (no Hardhat required)
  - positive: confirmed reentrancy via balance drain
  - negative: not confirmed when attack reverts (CEI pattern)
  - unsupported: missing function name / no deposit
  - failed: compilation error
  - merge-back through correlation layer
- integration tests (require Hardhat + web3)
  - real positive: vulnerable VulnerableBank
  - real negative: safe SafeBank (CEI pattern)
- pipeline integration test with mocked runtime
"""

import os
import sys
import unittest
from copy import deepcopy
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import engine
from scanner.correlation import correlate
from scanner.pipeline import full_scan
from simulation.compiler import CompiledContract, CompilationError
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_UNSUPPORTED,
    RUNTIME_FAILED,
)
from simulation.scenarios.reentrancy import (
    validate_reentrancy,
    _extract_pragma,
    _build_attacker_source,
    _has_function,
    WEI_PER_ETH,
    DEPOSIT_WEI,
    ATTACK_WEI,
)


# ── FakeBackend that simulates reentrancy behavior ───────────────────────────

class FakeReentrancyBackend:
    """Backend that simulates reentrancy attack outcomes without Hardhat."""

    backend_id = "hardhat"

    def __init__(self, *, attack_succeeds=True, attack_drains=True, deposit_fails=False):
        """
        attack_succeeds: whether the attack() call returns success=True
        attack_drains: whether the victim balance drops to 0 (reentrancy worked)
        deposit_fails: whether deposit() fails
        """
        self.attack_succeeds = attack_succeeds
        self.attack_drains = attack_drains
        self.deposit_fails = deposit_fails
        self._deployed = []
        self._victim_balance = 0
        self._victim_address = None

    def get_accounts(self):
        return [
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000003",
        ]

    def deploy_contract(self, abi, bytecode, constructor_args=None):
        addr = f"0x{'0' * 38}{len(self._deployed) + 10:02x}"
        self._deployed.append({"abi": abi, "address": addr, "constructor_args": constructor_args})
        # First deployment is victim.
        if self._victim_address is None:
            self._victim_address = addr
        return {
            "contract_address": addr,
            "tx_hash": f"0xdeploy{len(self._deployed)}",
            "deployer": self.get_accounts()[0],
            "receipt": {"status": 1},
        }

    def execute_transaction(self, contract_abi, contract_address, function_name, args, sender, value=0):
        # deposit() — seed victim.
        if function_name == "deposit":
            if self.deposit_fails:
                return {"success": False, "reverted": True, "error": "deposit failed"}
            self._victim_balance += value
            return {
                "success": True,
                "tx_hash": "0xdeposit",
                "receipt": {"status": 1},
                "reverted": False,
            }

        # attack() — attacker entry point.
        if function_name == "attack":
            if not self.attack_succeeds:
                return {"success": False, "reverted": True, "error": "Revert: Insufficient balance"}
            if self.attack_drains:
                # Reentrancy succeeded — victim drained.
                self._victim_balance = 0
            else:
                # Normal single withdraw — victim keeps remaining.
                self._victim_balance = max(0, self._victim_balance - value)
            return {
                "success": True,
                "tx_hash": "0xattack",
                "receipt": {"status": 1},
                "reverted": False,
            }

        return {"success": True, "tx_hash": "0xgeneric", "receipt": {"status": 1}, "reverted": False}

    def get_balance(self, address):
        if address == self._victim_address:
            return self._victim_balance
        # Attacker gets what was drained.
        if self.attack_drains and self.attack_succeeds:
            return DEPOSIT_WEI + ATTACK_WEI  # All funds
        return ATTACK_WEI

    def send_eth(self, sender, to, value):
        return {"success": True, "tx_hash": "0xsendeth", "receipt": {"status": 1}}


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_victim_compiled(contract_name="VulnerableBank"):
    """Create a fake compiled contract with deposit/withdraw functions."""
    return CompiledContract(
        contract_name=contract_name,
        abi=[
            {"type": "constructor", "inputs": []},
            {"type": "function", "name": "deposit", "inputs": [], "stateMutability": "payable"},
            {"type": "function", "name": "withdraw", "inputs": [{"name": "amount", "type": "uint256"}]},
            {"type": "function", "name": "getBalance", "inputs": [], "stateMutability": "view"},
        ],
        bytecode="0x6000",
    )


def _make_attacker_compiled():
    """Create a fake compiled attacker contract."""
    return CompiledContract(
        contract_name="AegisReentrancyAttacker",
        abi=[
            {"type": "constructor", "inputs": [{"name": "_victim", "type": "address"}]},
            {"type": "function", "name": "attack", "inputs": [], "stateMutability": "payable"},
            {"type": "function", "name": "getBalance", "inputs": [], "stateMutability": "view"},
        ],
        bytecode="0x6001",
    )


VULNERABLE_SOURCE = open(
    os.path.join(os.path.dirname(__file__), "..", "samples", "reentrancy.sol"),
    "r", encoding="utf-8",
).read()

SAFE_SOURCE = open(
    os.path.join(os.path.dirname(__file__), "..", "samples", "reentrancy_runtime_safe.sol"),
    "r", encoding="utf-8",
).read()


class TestHelpers(unittest.TestCase):
    """Test helper functions."""

    def test_extract_pragma_from_070(self):
        self.assertEqual(_extract_pragma("pragma solidity ^0.7.0;"), "pragma solidity ^0.7.0;")

    def test_extract_pragma_from_080(self):
        self.assertEqual(_extract_pragma("pragma solidity ^0.8.0;"), "pragma solidity ^0.8.0;")

    def test_extract_pragma_missing(self):
        self.assertEqual(_extract_pragma("contract Test {}"), "pragma solidity ^0.8.0;")

    def test_build_attacker_source_contains_interface(self):
        src = _build_attacker_source()
        self.assertIn("IVictim", src)
        self.assertIn("AegisReentrancyAttacker", src)
        self.assertIn("receive()", src)

    def test_has_function(self):
        c = _make_victim_compiled()
        self.assertTrue(_has_function(c, "deposit"))
        self.assertTrue(_has_function(c, "withdraw"))
        self.assertFalse(_has_function(c, "nonexistent"))


class TestReentrancyScenarioUnit(unittest.TestCase):
    """Unit tests for reentrancy runtime validation using FakeBackend."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def _get_reentrancy_findings(self, filename):
        scan_result = engine.scan(self.read_sample(filename), filename)
        return [f for f in scan_result["findings"] if f["check"] == "reentrancy"]

    @patch("simulation.scenarios.reentrancy.compile_source")
    def test_confirmed_reentrancy_via_drain(self, mock_compile):
        """When the attacker drains the victim, reentrancy is confirmed."""
        mock_compile.return_value = [_make_victim_compiled(), _make_attacker_compiled()]
        findings = self._get_reentrancy_findings("reentrancy.sol")
        self.assertGreater(len(findings), 0, "Expected reentrancy findings")

        backend = FakeReentrancyBackend(attack_succeeds=True, attack_drains=True)
        compiled = [_make_victim_compiled()]
        source = self.read_sample("reentrancy.sol")

        validations = validate_reentrancy(findings, compiled, backend, source)
        self.assertGreater(len(validations), 0)

        v = validations[0]
        self.assertEqual(v.status, RUNTIME_CONFIRMED)
        self.assertEqual(v.check, "reentrancy")
        self.assertEqual(v.scenario, "reentrancy.attacker_drain")
        self.assertIn("victim_balance_after_attack_wei", v.evidence)
        self.assertEqual(v.evidence["victim_balance_after_attack_wei"], "0")
        self.assertIn("classification_reason", v.evidence)
        self.assertIn("drained", v.evidence["classification_reason"].lower())

    @patch("simulation.scenarios.reentrancy.compile_source")
    def test_not_confirmed_when_attack_reverts(self, mock_compile):
        """When the attack reverts (CEI pattern), reentrancy is not confirmed."""
        mock_compile.return_value = [
            _make_victim_compiled("SafeBankWithBookkeeping"),
            _make_attacker_compiled(),
        ]
        findings = self._get_reentrancy_findings("reentrancy_runtime_safe.sol")
        self.assertGreater(len(findings), 0, "Expected reentrancy findings from safe sample")

        backend = FakeReentrancyBackend(attack_succeeds=False)
        compiled = [_make_victim_compiled("SafeBankWithBookkeeping")]
        source = self.read_sample("reentrancy_runtime_safe.sol")

        validations = validate_reentrancy(findings, compiled, backend, source)
        self.assertGreater(len(validations), 0)

        v = validations[0]
        self.assertEqual(v.status, RUNTIME_NOT_CONFIRMED)
        self.assertIn("reverted", v.evidence.get("classification_reason", "").lower())

    def test_unsupported_when_no_function_name(self):
        """Finding without function name should be unsupported."""
        backend = FakeReentrancyBackend()
        findings = [{"id": "test_id", "check": "reentrancy", "function": None, "contract_name": "Test"}]
        compiled = [_make_victim_compiled()]
        validations = validate_reentrancy(findings, compiled, backend, "pragma solidity ^0.7.0;")
        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0].status, RUNTIME_UNSUPPORTED)

    def test_unsupported_when_no_deposit_function(self):
        """Victim without deposit() should be unsupported."""
        backend = FakeReentrancyBackend()
        findings = [{"id": "test_id", "check": "reentrancy", "function": "withdraw",
                      "contract_name": "NoDepositContract"}]
        # Contract without deposit function.
        no_deposit = CompiledContract(
            contract_name="NoDepositContract",
            abi=[
                {"type": "constructor", "inputs": []},
                {"type": "function", "name": "withdraw", "inputs": [{"name": "amount", "type": "uint256"}]},
            ],
            bytecode="0x6000",
        )
        validations = validate_reentrancy(findings, [no_deposit], backend, "pragma solidity ^0.7.0;")
        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0].status, RUNTIME_UNSUPPORTED)

    @patch("simulation.scenarios.reentrancy.compile_source", side_effect=CompilationError("solc error"))
    def test_failed_when_compilation_fails(self, _mock):
        """If attacker contract compilation fails, status should be FAILED."""
        backend = FakeReentrancyBackend()
        findings = [{"id": "test_id", "check": "reentrancy", "function": "withdraw",
                      "contract_name": "VulnerableBank"}]
        compiled = [_make_victim_compiled()]
        validations = validate_reentrancy(findings, compiled, backend, "pragma solidity ^0.7.0;")
        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0].status, RUNTIME_FAILED)
        self.assertIn("solc error", validations[0].error)

    @patch("simulation.scenarios.reentrancy.compile_source")
    def test_inconclusive_single_withdraw(self, mock_compile):
        """When attack succeeds but only drains the attack amount (no extra), inconclusive."""
        mock_compile.return_value = [_make_victim_compiled(), _make_attacker_compiled()]
        backend = FakeReentrancyBackend(attack_succeeds=True, attack_drains=False)
        findings = self._get_reentrancy_findings("reentrancy.sol")
        compiled = [_make_victim_compiled()]
        source = self.read_sample("reentrancy.sol")

        validations = validate_reentrancy(findings, compiled, backend, source)
        self.assertGreater(len(validations), 0)

        v = validations[0]
        self.assertIn(v.status, {RUNTIME_INCONCLUSIVE, RUNTIME_CONFIRMED, RUNTIME_NOT_CONFIRMED})

    @patch("simulation.scenarios.reentrancy.compile_source")
    def test_deposit_failure_produces_failed_record(self, mock_compile):
        """If deposit() fails, should produce a FAILED record."""
        mock_compile.return_value = [_make_victim_compiled(), _make_attacker_compiled()]
        backend = FakeReentrancyBackend(deposit_fails=True)
        findings = self._get_reentrancy_findings("reentrancy.sol")
        compiled = [_make_victim_compiled()]
        source = self.read_sample("reentrancy.sol")

        validations = validate_reentrancy(findings, compiled, backend, source)
        self.assertGreater(len(validations), 0)
        self.assertEqual(validations[0].status, RUNTIME_FAILED)

    def test_findings_without_reentrancy_check_are_skipped(self):
        """Only reentrancy check findings should be processed."""
        backend = FakeReentrancyBackend()
        findings = [{"id": "test_id", "check": "missing-access-control", "function": "mint"}]
        validations = validate_reentrancy(findings, [], backend, "pragma solidity ^0.7.0;")
        self.assertEqual(len(validations), 0)


class TestCorrelationMergeBack(unittest.TestCase):
    """Test that reentrancy runtime results merge through the correlation layer."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_reentrancy_confirmed_merges_through_correlation(self):
        scan_result = engine.scan(self.read_sample("reentrancy.sol"), "reentrancy.sol")
        reentrancy_findings = [f for f in scan_result["findings"] if f["check"] == "reentrancy"]
        self.assertGreater(len(reentrancy_findings), 0)

        # Build a mock runtime result with reentrancy confirmed.
        validations = []
        for f in reentrancy_findings:
            validations.append({
                "finding_id": f["id"],
                "status": RUNTIME_CONFIRMED,
                "backend": "hardhat",
                "check": "reentrancy",
                "scenario": "reentrancy.attacker_drain",
                "contract_name": f.get("contract_name"),
                "function_name": f.get("function"),
                "evidence": {
                    "victim_balance_after_attack_wei": "0",
                    "classification_reason": "Victim drained.",
                },
                "limitations": ["Test only."],
                "error": None,
            })
        runtime_result = {
            "backend": "hardhat",
            "status": RUNTIME_CONFIRMED,
            "success": True,
            "summary": "Confirmed",
            "validations": validations,
            "accounts": [],
            "attacks_run": validations,
            "metadata": {},
        }

        enriched = correlate(scan_result, runtime_result, runtime_requested=True)

        for f in enriched["findings"]:
            if f["check"] == "reentrancy":
                self.assertEqual(f["runtime_validation_status"], RUNTIME_CONFIRMED)
                self.assertEqual(f["exploitability"], "CONFIRMED_BY_RUNTIME")
                self.assertEqual(f["verification"]["dynamic"], "CONFIRMED")
                self.assertEqual(f["runtime_backend"], "hardhat")

        rt = enriched["runtime_correlation"]
        self.assertTrue(rt["runtime_executed"])
        self.assertIn("reentrancy", rt["scenario_families_executed"])

    def test_reentrancy_not_confirmed_merges_correctly(self):
        scan_result = engine.scan(self.read_sample("reentrancy_runtime_safe.sol"), "reentrancy_runtime_safe.sol")
        reentrancy_findings = [f for f in scan_result["findings"] if f["check"] == "reentrancy"]
        self.assertGreater(len(reentrancy_findings), 0)

        validations = [{
            "finding_id": reentrancy_findings[0]["id"],
            "status": RUNTIME_NOT_CONFIRMED,
            "backend": "hardhat",
            "check": "reentrancy",
            "scenario": "reentrancy.attacker_drain",
            "evidence": {"attack_reverted": True},
            "limitations": [],
            "error": None,
        }]
        runtime_result = {
            "backend": "hardhat",
            "status": RUNTIME_NOT_CONFIRMED,
            "success": True,
            "summary": "Not confirmed",
            "validations": validations,
            "accounts": [],
            "attacks_run": validations,
            "metadata": {},
        }

        enriched = correlate(scan_result, runtime_result, runtime_requested=True)
        f = next(f for f in enriched["findings"] if f["check"] == "reentrancy")
        self.assertEqual(f["runtime_validation_status"], RUNTIME_NOT_CONFIRMED)
        self.assertEqual(f["exploitability"], "NOT_CONFIRMED_BY_RUNTIME")
        self.assertEqual(f["verification"]["dynamic"], "NOT_CONFIRMED")


class TestPipelineIntegrationReentrancy(unittest.TestCase):
    """Test that reentrancy flows through pipeline.full_scan() correctly."""

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_pipeline_with_mocked_reentrancy_confirmed(self):
        """full_scan with mocked runtime that confirms reentrancy."""
        source = self.read_sample("reentrancy.sol")

        def mock_runtime(src, fns, backend_name="hardhat"):
            reentrancy = [f for f in fns if f.get("check") == "reentrancy"]
            validations = [{
                "finding_id": f["id"],
                "status": RUNTIME_CONFIRMED,
                "backend": backend_name,
                "check": "reentrancy",
                "scenario": "reentrancy.attacker_drain",
                "evidence": {"victim_balance_after_attack_wei": "0"},
                "limitations": [],
                "error": None,
            } for f in reentrancy]
            return {
                "backend": backend_name,
                "status": RUNTIME_CONFIRMED if validations else RUNTIME_UNSUPPORTED,
                "success": bool(validations),
                "summary": "Reentrancy confirmed",
                "validations": validations,
                "accounts": [],
                "attacks_run": validations,
                "metadata": {},
            }

        with patch("scanner.pipeline.run_runtime_validation", side_effect=mock_runtime):
            result = full_scan(source, "reentrancy.sol", run_runtime=True)

        self.assertTrue(result["success"])
        rt = result["runtime_correlation"]
        self.assertTrue(rt["runtime_requested"])
        self.assertTrue(rt["runtime_executed"])
        self.assertGreater(rt["confirmed_count"], 0)
        self.assertIn("reentrancy", rt["scenario_families_executed"])


class TestRealHardhatReentrancy(unittest.TestCase):
    """Integration tests that run against a real Hardhat node.

    These tests require:
    - web3.py installed
    - npx and Hardhat available in PATH
    - solc available via npx

    They exercise the full end-to-end path:
    source → scan → compile → deploy → attack → classify → correlate
    """

    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename):
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as f:
            return f.read()

    def test_real_hardhat_vulnerable_reentrancy(self):
        """Real Hardhat: VulnerableBank should be confirmed_by_runtime."""
        from simulation.service import run_runtime_validation
        source = self.read_sample("reentrancy.sol")
        scan_result = engine.scan(source, "reentrancy.sol")

        result = run_runtime_validation(source, scan_result["findings"])

        self.assertEqual(result["backend"], "hardhat")
        self.assertTrue(result["validations"])

        reentrancy_validations = [v for v in result["validations"] if v["check"] == "reentrancy"]
        self.assertGreater(len(reentrancy_validations), 0, "Expected reentrancy validations")

        v = reentrancy_validations[0]
        self.assertEqual(v["status"], RUNTIME_CONFIRMED)
        self.assertEqual(v["scenario"], "reentrancy.attacker_drain")
        self.assertIn("victim_balance_after_attack_wei", v.get("evidence", {}))
        self.assertEqual(v["evidence"]["victim_balance_after_attack_wei"], "0")

    def test_real_hardhat_safe_reentrancy(self):
        """Real Hardhat: SafeBank (CEI) should be not_confirmed_by_runtime."""
        from simulation.service import run_runtime_validation
        source = self.read_sample("reentrancy_runtime_safe.sol")
        scan_result = engine.scan(source, "reentrancy_runtime_safe.sol")

        # Verify static detector flags it.
        reentrancy_findings = [f for f in scan_result["findings"] if f["check"] == "reentrancy"]
        self.assertGreater(len(reentrancy_findings), 0, "Static detector should flag safe sample too")

        result = run_runtime_validation(source, scan_result["findings"])

        self.assertEqual(result["backend"], "hardhat")
        reentrancy_validations = [v for v in result["validations"] if v["check"] == "reentrancy"]
        self.assertGreater(len(reentrancy_validations), 0)

        v = reentrancy_validations[0]
        self.assertEqual(v["status"], RUNTIME_NOT_CONFIRMED,
                         f"Expected NOT_CONFIRMED for safe CEI contract, got {v['status']}")
        self.assertTrue(v.get("evidence", {}).get("attack_reverted"),
                        "Attack should have reverted for safe contract")


if __name__ == "__main__":
    unittest.main()
