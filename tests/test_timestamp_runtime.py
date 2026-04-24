"""
Tests for timestamp dependence runtime validation.

Covers:
- detector context enrichment for timestamp findings
- scenario unit tests with a fake backend
- correlation merge-back
- pipeline integration with mocked runtime
- real Hardhat integration for positive and negative fixtures
"""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from scanner import engine
from scanner.correlation import correlate
from scanner.pipeline import full_scan
from simulation.compiler import CompiledContract
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
)
from simulation.scenarios.timestamp_dependence import (
    TIMESTAMP_CHECK,
    VALIDATOR_SKEW_SECONDS,
    validate_timestamp_dependence,
)


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


def _make_timestamp_finding(
    *,
    finding_id="timestamp-1",
    contract_name="RouletteGame",
    function_name="spin",
) -> dict:
    return {
        "id": finding_id,
        "vulnerability": "Timestamp Dependence",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "line": 10,
        "check": TIMESTAMP_CHECK,
        "contract_name": contract_name,
        "function": function_name,
        "description": "Timestamp-based control flow.",
        "fix": "Avoid using block.timestamp for critical decisions.",
    }


class FakeTimestampBackend:
    backend_id = "hardhat"

    def __init__(self, *, payout_on_exact_multiple=True):
        self._timestamp = 100
        self._next_timestamp = None
        self._block_number = 1
        self._deploy_count = 0
        self._balances = {}
        self.payout_on_exact_multiple = payout_on_exact_multiple

    def get_accounts(self):
        return [
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000003",
        ]

    def deploy_contract(self, abi, bytecode, constructor_args=None):
        self._deploy_count += 1
        address = f"0x{'0' * 38}{self._deploy_count:02x}"
        self._balances[address] = 0
        return {
            "contract_address": address,
            "tx_hash": f"0xdeploy{self._deploy_count}",
            "deployer": self.get_accounts()[0],
            "receipt": {"status": 1, "blockNumber": self._block_number},
        }

    def execute_transaction(self, contract_abi, contract_address, function_name, args, sender, value=0):
        self._mine()
        current_balance = self._balances.get(contract_address, 0)
        if function_name == "spin":
            self._balances[contract_address] = current_balance + value
            payout = self._timestamp % 15 == 0 if self.payout_on_exact_multiple else False
            if payout:
                self._balances[contract_address] = 0
            return {
                "success": True,
                "tx_hash": f"0xtx{self._block_number}",
                "receipt": {"status": 1, "blockNumber": self._block_number},
                "reverted": False,
            }

        return {
            "success": True,
            "tx_hash": f"0xtx{self._block_number}",
            "receipt": {"status": 1, "blockNumber": self._block_number},
            "reverted": False,
        }

    def call_function(self, contract_abi, contract_address, function_name, args=None):
        if function_name == "isRefreshWindowOpen":
            return self._timestamp > 100 + 86400
        return None

    def get_balance(self, address):
        return self._balances.get(address, 0)

    def get_block(self, block_identifier="latest"):
        return {"number": self._block_number, "timestamp": self._timestamp, "hash": "0xblock"}

    def set_next_block_timestamp(self, timestamp: int):
        self._next_timestamp = int(timestamp)

    def mine_block(self):
        self._mine()
        return self.get_block("latest")

    def _mine(self):
        if self._next_timestamp is not None:
            self._timestamp = self._next_timestamp
            self._next_timestamp = None
        else:
            self._timestamp += 1
        self._block_number += 1


class TestTimestampDetectorContext(unittest.TestCase):
    def test_detector_adds_function_and_contract_context(self):
        result = engine.scan(_read_sample("timestamp.sol"), "timestamp.sol")
        findings = [f for f in result["findings"] if f.get("check") == TIMESTAMP_CHECK]
        self.assertGreater(len(findings), 0)
        spin_finding = next(f for f in findings if f.get("function") == "spin")
        self.assertEqual(spin_finding["contract_name"], "RouletteGame")
        self.assertIn(spin_finding["severity"], {"LOW", "MEDIUM"})


class TestTimestampScenarioUnit(unittest.TestCase):
    def test_positive_runtime_case_is_confirmed(self):
        backend = FakeTimestampBackend()
        findings = [_make_timestamp_finding()]
        compiled = [
            CompiledContract(
                contract_name="RouletteGame",
                abi=[
                    {"type": "constructor", "inputs": []},
                    {"type": "function", "name": "spin", "inputs": [], "stateMutability": "payable"},
                ],
                bytecode="0x6000",
            )
        ]
        validations = validate_timestamp_dependence(
            findings,
            compiled,
            backend,
            _read_sample("timestamp.sol"),
        )
        self.assertEqual(len(validations), 1)
        record = validations[0]
        self.assertEqual(record.status, RUNTIME_CONFIRMED)
        self.assertEqual(record.scenario, "timestamp_dependence.security_sensitive_modulo")
        self.assertTrue(record.evidence["outcome_changed"])
        self.assertTrue(record.evidence["reachable_only_with_time_shift"])

    def test_negative_runtime_case_is_not_confirmed(self):
        backend = FakeTimestampBackend()
        findings = [_make_timestamp_finding(
            finding_id="timestamp-2",
            contract_name="MetadataWindow",
            function_name="isRefreshWindowOpen",
        )]
        compiled = [
            CompiledContract(
                contract_name="MetadataWindow",
                abi=[
                    {"type": "constructor", "inputs": []},
                    {
                        "type": "function",
                        "name": "isRefreshWindowOpen",
                        "inputs": [],
                        "outputs": [{"name": "", "type": "bool"}],
                        "stateMutability": "view",
                    },
                ],
                bytecode="0x6000",
            )
        ]
        validations = validate_timestamp_dependence(
            findings,
            compiled,
            backend,
            _read_sample("timestamp_runtime_negative.sol"),
        )
        self.assertEqual(len(validations), 1)
        record = validations[0]
        self.assertEqual(record.status, RUNTIME_NOT_CONFIRMED)
        self.assertEqual(record.scenario, "timestamp_dependence.observation_only_window")
        self.assertFalse(record.evidence["security_relevant_difference"])

    def test_missing_function_context_is_unsupported(self):
        backend = FakeTimestampBackend()
        validations = validate_timestamp_dependence(
            [_make_timestamp_finding(function_name=None)],
            [],
            backend,
            _read_sample("timestamp.sol"),
        )
        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0].status, RUNTIME_UNSUPPORTED)


class TestTimestampCorrelation(unittest.TestCase):
    def test_merge_back_marks_timestamp_finding_confirmed(self):
        scan = engine.scan(_read_sample("timestamp.sol"), "timestamp.sol")
        finding = next(f for f in scan["findings"] if f.get("check") == TIMESTAMP_CHECK)
        runtime = {
            "backend": "hardhat",
            "status": RUNTIME_CONFIRMED,
            "success": True,
            "summary": "Timestamp confirmed",
            "validations": [
                {
                    "finding_id": finding["id"],
                    "status": RUNTIME_CONFIRMED,
                    "backend": "hardhat",
                    "check": TIMESTAMP_CHECK,
                    "scenario": "timestamp_dependence.security_sensitive_modulo",
                    "evidence": {"reachable_only_with_time_shift": True},
                    "limitations": [],
                    "error": None,
                }
            ],
        }
        enriched = correlate(scan, runtime, runtime_requested=True)
        merged = next(f for f in enriched["findings"] if f["id"] == finding["id"])
        self.assertEqual(merged["runtime_validation_status"], RUNTIME_CONFIRMED)
        self.assertEqual(merged["verification"]["dynamic"], "CONFIRMED")
        self.assertIn("timestamp_dependence", enriched["runtime_correlation"]["scenario_families_executed"])


class TestTimestampPipelineIntegration(unittest.TestCase):
    def test_pipeline_with_mocked_timestamp_runtime(self):
        source = _read_sample("timestamp.sol")

        def mock_runtime(src, findings, backend_name="hardhat"):
            timestamp_findings = [f for f in findings if f.get("check") == TIMESTAMP_CHECK]
            validations = [
                {
                    "finding_id": f["id"],
                    "status": RUNTIME_CONFIRMED,
                    "backend": backend_name,
                    "check": TIMESTAMP_CHECK,
                    "scenario": "timestamp_dependence.security_sensitive_modulo",
                    "evidence": {"skew_window_seconds": VALIDATOR_SKEW_SECONDS},
                    "limitations": [],
                    "error": None,
                }
                for f in timestamp_findings
            ]
            return {
                "backend": backend_name,
                "status": RUNTIME_CONFIRMED,
                "success": True,
                "summary": "Timestamp confirmed",
                "validations": validations,
                "accounts": [],
                "metadata": {},
            }

        with patch("scanner.pipeline.run_runtime_validation", side_effect=mock_runtime):
            result = full_scan(source, "timestamp.sol", run_runtime=True)

        self.assertTrue(result["runtime_correlation"]["runtime_executed"])
        self.assertIn("timestamp_dependence", result["runtime_correlation"]["scenario_families_executed"])
        self.assertGreater(result["runtime_correlation"]["confirmed_count"], 0)


class TestRealHardhatTimestamp(unittest.TestCase):
    def test_real_hardhat_positive_timestamp_case(self):
        from simulation.service import run_runtime_validation

        source = _read_sample("timestamp.sol")
        scan = engine.scan(source, "timestamp.sol")
        findings = [f for f in scan["findings"] if f.get("check") == TIMESTAMP_CHECK and f.get("function") == "spin"]
        self.assertGreater(len(findings), 0)

        result = run_runtime_validation(source, findings)
        validations = [v for v in result["validations"] if v["check"] == TIMESTAMP_CHECK]
        self.assertGreater(len(validations), 0)
        self.assertEqual(validations[0]["status"], RUNTIME_CONFIRMED)
        self.assertTrue(validations[0]["evidence"]["reachable_only_with_time_shift"])

    def test_real_hardhat_negative_timestamp_case(self):
        from simulation.service import run_runtime_validation

        source = _read_sample("timestamp_runtime_negative.sol")
        scan = engine.scan(source, "timestamp_runtime_negative.sol")
        findings = [f for f in scan["findings"] if f.get("check") == TIMESTAMP_CHECK]
        self.assertGreater(len(findings), 0)

        result = run_runtime_validation(source, findings)
        validations = [v for v in result["validations"] if v["check"] == TIMESTAMP_CHECK]
        self.assertGreater(len(validations), 0)
        self.assertIn(validations[0]["status"], {RUNTIME_NOT_CONFIRMED, RUNTIME_INCONCLUSIVE})


if __name__ == "__main__":
    unittest.main()
