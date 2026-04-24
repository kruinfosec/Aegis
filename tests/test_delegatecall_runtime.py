"""
Tests for delegatecall runtime validation.

Covers:
  - Helper functions (contract matching, attack args, etc.)
  - Unit tests with FakeBackend (confirmed, not-confirmed, unsupported, failed)
  - Correlation merge-back via correlate()
  - Pipeline integration with mocked runtime
  - Real Hardhat integration (vulnerable + safe cases)
"""

import os
import sys
import unittest
from copy import deepcopy
from typing import Any, Dict, List, Optional
from unittest.mock import patch

# Ensure project root is on the path.
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner import engine
from scanner.correlation import correlate
from scanner.finding import normalize_finding
from simulation.compiler import CompiledContract
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_FAILED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
    ValidationRecord,
)
from simulation.scenarios.delegatecall import (
    DELEGATECALL_CHECK,
    _build_attack_args,
    _find_proxy_contract,
    _has_function,
    validate_delegatecall,
)


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()


def _make_delegatecall_finding(**overrides) -> dict:
    """Create a synthetic delegatecall finding dict."""
    base = {
        "id": "aegis.delegatecall:test.sol:10:Delegatecall to Untrusted Contract",
        "check": DELEGATECALL_CHECK,
        "vulnerability": "Delegatecall to Untrusted Contract",
        "severity": "HIGH",
        "confidence": "HIGH",
        "function": "executeLogic",
        "contract_name": "ProxyVulnerable",
        "line": 10,
    }
    base.update(overrides)
    return base


def _make_proxy_abi():
    """Mock ABI for a simple proxy with owner() and executeLogic(address, bytes)."""
    return [
        {
            "type": "function",
            "name": "owner",
            "inputs": [],
            "outputs": [{"name": "", "type": "address"}],
            "stateMutability": "view",
        },
        {
            "type": "function",
            "name": "executeLogic",
            "inputs": [
                {"name": "target", "type": "address"},
                {"name": "data", "type": "bytes"},
            ],
            "outputs": [],
            "stateMutability": "payable",
        },
        {
            "type": "constructor",
            "inputs": [],
        },
    ]


# ═══════════════════════════════════════════════════════════════════════════
# FakeBackend for unit tests
# ═══════════════════════════════════════════════════════════════════════════

class FakeBackend:
    backend_id = "fake"

    def __init__(
        self,
        deploy_results=None,
        execute_result=None,
        owner_before="0xDeployer",
        owner_after="0xAttacker",
        accounts=None,
    ):
        self._deploy_results = deploy_results or []
        self._deploy_call_count = 0
        self._execute_result = execute_result or {"success": True, "reverted": False, "tx_hash": "0xabc"}
        self._owner_before = owner_before
        self._owner_after = owner_after
        self._call_count = 0
        self._accounts = accounts or ["0xDeployer", "0xAttacker"]

    def get_accounts(self):
        return self._accounts

    def deploy_contract(self, abi, bytecode, constructor_args=None):
        if self._deploy_call_count < len(self._deploy_results):
            result = self._deploy_results[self._deploy_call_count]
        else:
            result = {"contract_address": f"0xContract{self._deploy_call_count}", "tx_hash": "0xdeploy", "deployer": "0xDeployer"}
        self._deploy_call_count += 1
        return result

    def execute_transaction(self, abi, address, function, args, sender, value=0):
        return self._execute_result

    def call_function(self, abi, address, function_name, args=None):
        self._call_count += 1
        if self._call_count <= 1:
            return self._owner_before
        return self._owner_after

    def get_balance(self, address):
        return 0

    def send_eth(self, sender, to, value):
        return {"success": True}


# ═══════════════════════════════════════════════════════════════════════════
# Test Classes
# ═══════════════════════════════════════════════════════════════════════════

class TestHelpers(unittest.TestCase):
    """Test helper functions in the delegatecall scenario module."""

    def test_has_function(self):
        abi = _make_proxy_abi()
        self.assertTrue(_has_function(abi, "owner"))
        self.assertTrue(_has_function(abi, "executeLogic"))
        self.assertFalse(_has_function(abi, "nonexistent"))

    def test_find_proxy_contract_by_name(self):
        c = CompiledContract(contract_name="ProxyVulnerable", abi=_make_proxy_abi(), bytecode="0x00")
        result = _find_proxy_contract([c], "ProxyVulnerable", "executeLogic")
        self.assertIsNotNone(result)
        self.assertEqual(result.contract_name, "ProxyVulnerable")

    def test_find_proxy_contract_by_function_fallback(self):
        c = CompiledContract(contract_name="SomeProxy", abi=_make_proxy_abi(), bytecode="0x00")
        result = _find_proxy_contract([c], None, "executeLogic")
        self.assertIsNotNone(result)

    def test_build_attack_args_address_and_bytes(self):
        func_abi = {
            "inputs": [
                {"name": "target", "type": "address"},
                {"name": "data", "type": "bytes"},
            ],
        }
        args = _build_attack_args(func_abi, "0xImpl", b"\x01\x02")
        self.assertEqual(args, ["0xImpl", b"\x01\x02"])

    def test_build_attack_args_bytes_only(self):
        func_abi = {
            "inputs": [
                {"name": "data", "type": "bytes"},
            ],
        }
        args = _build_attack_args(func_abi, "0xImpl", b"\x01\x02")
        self.assertEqual(args, [b"\x01\x02"])


class TestDelegatecallScenarioUnit(unittest.TestCase):
    """Unit tests for the delegatecall scenario using FakeBackend."""

    def _run_with_backend(self, backend, finding=None, contracts=None):
        finding = finding or _make_delegatecall_finding()
        contracts = contracts or [
            CompiledContract(
                contract_name="ProxyVulnerable",
                abi=_make_proxy_abi(),
                bytecode="0x6080",
            ),
        ]
        with patch("simulation.scenarios.delegatecall.compile_source") as mock_compile:
            mock_compile.return_value = contracts + [
                CompiledContract(
                    contract_name="AegisMaliciousImpl",
                    abi=[
                        {"type": "function", "name": "takeOwnership", "inputs": [], "outputs": []},
                        {"type": "function", "name": "owner", "inputs": [], "outputs": [{"type": "address"}]},
                    ],
                    bytecode="0x6080",
                ),
            ]
            return validate_delegatecall([finding], contracts, backend, "pragma solidity ^0.8.0;")

    def test_confirmed_storage_takeover(self):
        """When the attacker succeeds and owner changes, delegatecall is confirmed."""
        backend = FakeBackend(
            execute_result={"success": True, "reverted": False, "tx_hash": "0xattack"},
            owner_before="0xDeployer",
            owner_after="0xAttacker",
        )
        records = self._run_with_backend(backend)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_CONFIRMED)
        self.assertIn("owner changed", records[0].evidence.get("classification_reason", ""))

    def test_not_confirmed_when_attack_reverts(self):
        """When the attack reverts (access control), delegatecall is not confirmed."""
        backend = FakeBackend(
            execute_result={"success": False, "reverted": True, "error": "Not owner"},
            owner_before="0xDeployer",
            owner_after="0xDeployer",
        )
        records = self._run_with_backend(backend)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_NOT_CONFIRMED)

    def test_inconclusive_when_owner_unchanged(self):
        """When attack succeeds but owner doesn't change, result is inconclusive."""
        backend = FakeBackend(
            execute_result={"success": True, "reverted": False, "tx_hash": "0xattack"},
            owner_before="0xDeployer",
            owner_after="0xDeployer",  # Same — no change
        )
        records = self._run_with_backend(backend)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_INCONCLUSIVE)

    def test_unsupported_when_no_function_name(self):
        """Finding without function name should be unsupported."""
        finding = _make_delegatecall_finding(function=None)
        backend = FakeBackend()
        records = self._run_with_backend(backend, finding=finding)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_UNSUPPORTED)

    def test_unsupported_when_no_owner_getter(self):
        """Proxy without owner() getter should be unsupported."""
        abi_no_owner = [
            {"type": "function", "name": "executeLogic", "inputs": [
                {"name": "target", "type": "address"}, {"name": "data", "type": "bytes"}
            ], "outputs": [], "stateMutability": "payable"},
            {"type": "constructor", "inputs": []},
        ]
        contracts = [CompiledContract(contract_name="ProxyVulnerable", abi=abi_no_owner, bytecode="0x6080")]
        finding = _make_delegatecall_finding()
        backend = FakeBackend()
        records = self._run_with_backend(backend, finding=finding, contracts=contracts)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_UNSUPPORTED)

    def test_failed_when_compilation_fails(self):
        """If malicious implementation compilation fails, status should be FAILED."""
        finding = _make_delegatecall_finding()
        contracts = [
            CompiledContract(contract_name="ProxyVulnerable", abi=_make_proxy_abi(), bytecode="0x6080"),
        ]
        backend = FakeBackend()
        from simulation.compiler import CompilationError
        with patch("simulation.scenarios.delegatecall.compile_source", side_effect=CompilationError("solc error")):
            records = validate_delegatecall([finding], contracts, backend, "pragma solidity ^0.8.0;")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_FAILED)

    def test_findings_without_delegatecall_check_are_skipped(self):
        """Only delegatecall-untrusted-target findings should be processed."""
        finding = _make_delegatecall_finding(check="reentrancy")
        backend = FakeBackend()
        records = self._run_with_backend(backend, finding=finding)
        self.assertEqual(len(records), 0)


class TestCorrelationMergeBack(unittest.TestCase):
    """Test that delegatecall runtime results merge through correlate()."""

    def test_delegatecall_confirmed_merges_through_correlation(self):
        scan_result = {
            "success": True,
            "filename": "test.sol",
            "findings": [_make_delegatecall_finding()],
            "total_issues": 1,
            "risk_level": "HIGH",
            "risk_score": 20,
            "pragma_version": "^0.8.0",
        }

        runtime_result = {
            "backend": "hardhat",
            "status": "confirmed_by_runtime",
            "success": True,
            "summary": "Confirmed.",
            "validations": [
                ValidationRecord(
                    finding_id=scan_result["findings"][0]["id"],
                    check=DELEGATECALL_CHECK,
                    title="Delegatecall to Untrusted Contract",
                    status=RUNTIME_CONFIRMED,
                    backend="hardhat",
                    scenario="delegatecall.storage_takeover",
                    evidence={"owner_before": "0xDeployer", "owner_after": "0xAttacker"},
                ).to_dict(),
            ],
        }

        enriched = correlate(scan_result, runtime_result, runtime_requested=True)
        f = enriched["findings"][0]
        self.assertEqual(f["runtime_validation_status"], RUNTIME_CONFIRMED)

    def test_delegatecall_not_confirmed_merges_correctly(self):
        scan_result = {
            "success": True,
            "filename": "test.sol",
            "findings": [_make_delegatecall_finding()],
            "total_issues": 1,
            "risk_level": "HIGH",
            "risk_score": 20,
            "pragma_version": "^0.8.0",
        }

        runtime_result = {
            "backend": "hardhat",
            "status": "not_confirmed_by_runtime",
            "success": True,
            "summary": "Not confirmed.",
            "validations": [
                ValidationRecord(
                    finding_id=scan_result["findings"][0]["id"],
                    check=DELEGATECALL_CHECK,
                    title="Delegatecall to Untrusted Contract",
                    status=RUNTIME_NOT_CONFIRMED,
                    backend="hardhat",
                    scenario="delegatecall.storage_takeover",
                    evidence={"attack_reverted": True},
                ).to_dict(),
            ],
        }

        enriched = correlate(scan_result, runtime_result, runtime_requested=True)
        f = enriched["findings"][0]
        self.assertEqual(f["runtime_validation_status"], RUNTIME_NOT_CONFIRMED)


class TestPipelineIntegrationDelegatecall(unittest.TestCase):
    """Test that delegatecall results flow through pipeline.full_scan()."""

    def test_pipeline_with_mocked_delegatecall_confirmed(self):
        """full_scan with mocked runtime that confirms delegatecall."""
        from scanner.pipeline import full_scan

        source = _read_sample("delegatecall.sol")

        fake_runtime = {
            "backend": "hardhat",
            "status": "confirmed_by_runtime",
            "success": True,
            "summary": "Confirmed.",
            "validations": [
                {
                    "finding_id": None,
                    "check": DELEGATECALL_CHECK,
                    "title": "Delegatecall to Untrusted Contract",
                    "status": RUNTIME_CONFIRMED,
                    "backend": "hardhat",
                    "scenario": "delegatecall.storage_takeover",
                    "evidence": {"owner_before": "0xA", "owner_after": "0xB"},
                    "actions": [],
                    "limitations": [],
                },
            ],
        }

        with patch("scanner.pipeline.run_runtime_validation", return_value=fake_runtime):
            with patch("scanner.pipeline._SIMULATION_IMPORT_OK", True):
                with patch("scanner.pipeline.simulation_available", return_value=True):
                    result = full_scan(source, "delegatecall.sol", run_runtime=True)

        self.assertIn("runtime_correlation", result)
        self.assertTrue(result["runtime_correlation"]["runtime_executed"])
        self.assertIn("delegatecall", result["runtime_correlation"]["scenario_families_executed"])


# ═══════════════════════════════════════════════════════════════════════════
# Real Hardhat Integration Tests
# ═══════════════════════════════════════════════════════════════════════════

class TestRealHardhatDelegatecall(unittest.TestCase):
    """Integration tests using a real Hardhat node.

    These tests are slower (compile + deploy + attack) and require:
    - Node.js + npx in PATH
    - web3.py installed
    - A free port for Hardhat
    """

    @classmethod
    def read_sample(cls, name: str) -> str:
        return _read_sample(name)

    def test_real_hardhat_vulnerable_delegatecall(self):
        """Real Hardhat: ProxyVulnerable should be confirmed_by_runtime."""
        from simulation.service import run_runtime_validation

        source = self.read_sample("delegatecall.sol")
        scan_result = engine.scan(source, "delegatecall.sol")

        # Verify static scan found delegatecall findings.
        dc_findings = [f for f in scan_result["findings"] if f["check"] == DELEGATECALL_CHECK]
        self.assertTrue(dc_findings, "Static scan should find delegatecall findings")

        result = run_runtime_validation(source, scan_result["findings"])

        self.assertEqual(result["backend"], "hardhat")
        self.assertTrue(result["validations"], "Expected at least one validation record")

        dc_validations = [v for v in result["validations"] if v["check"] == DELEGATECALL_CHECK]
        self.assertGreater(len(dc_validations), 0, "Expected delegatecall validations")

        v = dc_validations[0]
        self.assertEqual(v["status"], RUNTIME_CONFIRMED,
                         f"Expected CONFIRMED for vulnerable proxy, got {v['status']}. "
                         f"Error: {v.get('error')}")
        self.assertIn("owner_before", v.get("evidence", {}))
        self.assertIn("owner_after", v.get("evidence", {}))

    def test_real_hardhat_safe_delegatecall(self):
        """Real Hardhat: AdminGatedProxy should be not_confirmed_by_runtime."""
        from simulation.service import run_runtime_validation

        source = self.read_sample("delegatecall_runtime_negative.sol")
        scan_result = engine.scan(source, "delegatecall_runtime_negative.sol")

        # Verify static scan found delegatecall findings.
        dc_findings = [f for f in scan_result["findings"] if f["check"] == DELEGATECALL_CHECK]
        self.assertTrue(dc_findings, "Static scan should flag admin-gated proxy")

        result = run_runtime_validation(source, scan_result["findings"])

        dc_validations = [v for v in result["validations"] if v["check"] == DELEGATECALL_CHECK]
        self.assertGreater(len(dc_validations), 0, "Expected delegatecall validations")

        v = dc_validations[0]
        self.assertEqual(v["status"], RUNTIME_NOT_CONFIRMED,
                         f"Expected NOT_CONFIRMED for safe proxy, got {v['status']}. "
                         f"Error: {v.get('error')}")


if __name__ == "__main__":
    unittest.main()
