"""
Tests for weak randomness runtime validation.
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
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
)
from simulation.scenarios.weak_randomness import (
    WEAK_RANDOMNESS_CHECK,
    validate_weak_randomness,
)


SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "samples")
WEI = 10 ** 18


def _read_sample(name: str) -> str:
    with open(os.path.join(SAMPLES_DIR, name), "r", encoding="utf-8") as handle:
        return handle.read()


def _make_finding(
    *,
    finding_id="weak-randomness-1",
    contract_name="PredictableLottery",
    function_name="draw",
    source="block.timestamp",
) -> dict:
    return {
        "id": finding_id,
        "vulnerability": f"Weak Randomness Source ({source})",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "line": 15,
        "check": WEAK_RANDOMNESS_CHECK,
        "contract_name": contract_name,
        "function": function_name,
        "weak_randomness_source": source,
        "description": "Block property used as randomness.",
        "fix": "Use VRF or commit-reveal.",
    }


def _lottery_abi():
    return [
        {"type": "constructor", "inputs": []},
        {"type": "function", "name": "ticketPrice", "inputs": [], "outputs": [{"type": "uint256"}], "stateMutability": "view"},
        {"type": "function", "name": "lastWinner", "inputs": [], "outputs": [{"type": "address"}], "stateMutability": "view"},
        {"type": "function", "name": "buyTicket", "inputs": [], "stateMutability": "payable"},
        {"type": "function", "name": "draw", "inputs": [], "stateMutability": "nonpayable"},
    ]


def _preview_abi():
    return [
        {"type": "constructor", "inputs": []},
        {
            "type": "function",
            "name": "previewNonce",
            "inputs": [],
            "outputs": [{"type": "uint256"}],
            "stateMutability": "view",
        },
    ]


class FakeWeakRandomnessBackend:
    backend_id = "hardhat"

    def __init__(self):
        self._timestamp = 100
        self._next_timestamp = None
        self._block_number = 1
        self._deploy_count = 0
        self._contracts = {}

    def get_accounts(self):
        return [
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000003",
        ]

    def deploy_contract(self, abi, bytecode, constructor_args=None):
        self._deploy_count += 1
        address = f"0x{'0' * 38}{self._deploy_count:02x}"
        self._contracts[address] = {
            "abi": abi,
            "balance": 0,
            "players": [],
            "last_winner": "0x0000000000000000000000000000000000000000",
        }
        return {
            "contract_address": address,
            "tx_hash": f"0xdeploy{self._deploy_count}",
            "deployer": self.get_accounts()[0],
            "receipt": {"status": 1, "blockNumber": self._block_number},
        }

    def execute_transaction(self, contract_abi, contract_address, function_name, args, sender, value=0):
        self._mine()
        state = self._contracts[contract_address]
        if function_name == "buyTicket":
            state["players"].append(sender)
            state["balance"] += value
            return {"success": True, "tx_hash": f"0xbuy{self._block_number}", "receipt": {"status": 1, "blockNumber": self._block_number}, "reverted": False}
        if function_name == "draw":
            index = self._timestamp % len(state["players"])
            state["last_winner"] = state["players"][index]
            state["balance"] = 0
            state["players"] = []
            return {"success": True, "tx_hash": f"0xdraw{self._block_number}", "receipt": {"status": 1, "blockNumber": self._block_number}, "reverted": False}
        return {"success": True, "tx_hash": f"0xtx{self._block_number}", "receipt": {"status": 1, "blockNumber": self._block_number}, "reverted": False}

    def call_function(self, contract_abi, contract_address, function_name, args=None):
        if function_name == "ticketPrice":
            return WEI
        if function_name == "lastWinner":
            return self._contracts[contract_address]["last_winner"]
        if function_name == "previewNonce":
            return (self._timestamp + self._block_number) % 100
        return None

    def get_balance(self, address):
        return self._contracts.get(address, {}).get("balance", 0)

    def get_block(self, block_identifier="latest"):
        return {"number": self._block_number, "timestamp": self._timestamp, "hash": f"0xblock{self._block_number}"}

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


class TestWeakRandomnessDetectorContext(unittest.TestCase):
    def test_detector_adds_function_and_contract_context(self):
        result = engine.scan(_read_sample("weak_randomness_runtime.sol"), "weak_randomness_runtime.sol")
        findings = [f for f in result["findings"] if f.get("check") == WEAK_RANDOMNESS_CHECK]
        self.assertGreater(len(findings), 0)
        draw_finding = next(f for f in findings if f.get("function") == "draw")
        self.assertEqual(draw_finding["contract_name"], "PredictableLottery")
        self.assertEqual(draw_finding["weak_randomness_source"], "block.timestamp")


class TestWeakRandomnessScenarioUnit(unittest.TestCase):
    def test_positive_lottery_case_is_confirmed(self):
        backend = FakeWeakRandomnessBackend()
        compiled = [
            CompiledContract(
                contract_name="PredictableLottery",
                abi=_lottery_abi(),
                bytecode="0x6000",
            )
        ]
        records = validate_weak_randomness(
            [_make_finding()],
            compiled,
            backend,
            _read_sample("weak_randomness_runtime.sol"),
        )
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.status, RUNTIME_CONFIRMED)
        self.assertEqual(record.scenario, "weak_randomness.lottery_winner_payout")
        self.assertTrue(record.evidence["winner_changed"])
        self.assertTrue(record.evidence["outcome_steerable_in_local_chain"])

    def test_negative_observation_only_case_is_not_confirmed(self):
        backend = FakeWeakRandomnessBackend()
        compiled = [
            CompiledContract(
                contract_name="RandomnessPreview",
                abi=_preview_abi(),
                bytecode="0x6000",
            )
        ]
        records = validate_weak_randomness(
            [_make_finding(
                finding_id="weak-randomness-2",
                contract_name="RandomnessPreview",
                function_name="previewNonce",
            )],
            compiled,
            backend,
            _read_sample("weak_randomness_runtime_negative.sol"),
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_NOT_CONFIRMED)
        self.assertEqual(records[0].scenario, "weak_randomness.observation_only")
        self.assertFalse(records[0].evidence["security_relevant_difference"])

    def test_missing_function_context_is_unsupported(self):
        backend = FakeWeakRandomnessBackend()
        records = validate_weak_randomness(
            [_make_finding(function_name=None)],
            [],
            backend,
            _read_sample("weak_randomness_runtime.sol"),
        )
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].status, RUNTIME_UNSUPPORTED)


class TestWeakRandomnessCorrelation(unittest.TestCase):
    def test_merge_back_marks_weak_randomness_confirmed(self):
        scan = engine.scan(_read_sample("weak_randomness_runtime.sol"), "weak_randomness_runtime.sol")
        finding = next(f for f in scan["findings"] if f.get("check") == WEAK_RANDOMNESS_CHECK)
        runtime = {
            "backend": "hardhat",
            "status": RUNTIME_CONFIRMED,
            "success": True,
            "summary": "Weak randomness confirmed",
            "validations": [
                {
                    "finding_id": finding["id"],
                    "status": RUNTIME_CONFIRMED,
                    "backend": "hardhat",
                    "check": WEAK_RANDOMNESS_CHECK,
                    "scenario": "weak_randomness.lottery_winner_payout",
                    "evidence": {"outcome_steerable_in_local_chain": True},
                    "limitations": [],
                    "error": None,
                }
            ],
        }
        enriched = correlate(scan, runtime, runtime_requested=True)
        merged = next(f for f in enriched["findings"] if f["id"] == finding["id"])
        self.assertEqual(merged["runtime_validation_status"], RUNTIME_CONFIRMED)
        self.assertEqual(merged["verification"]["dynamic"], "CONFIRMED")
        self.assertIn("weak_randomness", enriched["runtime_correlation"]["scenario_families_executed"])


class TestWeakRandomnessPipelineIntegration(unittest.TestCase):
    def test_pipeline_with_mocked_weak_randomness_runtime(self):
        source = _read_sample("weak_randomness_runtime.sol")

        def mock_runtime(src, findings, backend_name="hardhat"):
            weak_findings = [f for f in findings if f.get("check") == WEAK_RANDOMNESS_CHECK]
            return {
                "backend": backend_name,
                "status": RUNTIME_CONFIRMED,
                "success": True,
                "summary": "Weak randomness confirmed",
                "validations": [
                    {
                        "finding_id": f["id"],
                        "status": RUNTIME_CONFIRMED,
                        "backend": backend_name,
                        "check": WEAK_RANDOMNESS_CHECK,
                        "scenario": "weak_randomness.lottery_winner_payout",
                        "evidence": {"winner_changed": True},
                        "limitations": [],
                        "error": None,
                    }
                    for f in weak_findings
                ],
                "accounts": [],
                "metadata": {},
            }

        with patch("scanner.pipeline.run_runtime_validation", side_effect=mock_runtime):
            result = full_scan(source, "weak_randomness_runtime.sol", run_runtime=True)

        self.assertTrue(result["runtime_correlation"]["runtime_executed"])
        self.assertIn("weak_randomness", result["runtime_correlation"]["scenario_families_executed"])
        self.assertGreater(result["runtime_correlation"]["confirmed_count"], 0)


class TestRealHardhatWeakRandomness(unittest.TestCase):
    def test_real_hardhat_positive_weak_randomness_case(self):
        from simulation.service import run_runtime_validation

        source = _read_sample("weak_randomness_runtime.sol")
        scan = engine.scan(source, "weak_randomness_runtime.sol")
        findings = [f for f in scan["findings"] if f.get("check") == WEAK_RANDOMNESS_CHECK and f.get("function") == "draw"]
        self.assertGreater(len(findings), 0)

        result = run_runtime_validation(source, findings)
        validations = [v for v in result["validations"] if v["check"] == WEAK_RANDOMNESS_CHECK]
        self.assertGreater(len(validations), 0)
        self.assertEqual(validations[0]["status"], RUNTIME_CONFIRMED)
        self.assertTrue(validations[0]["evidence"]["outcome_steerable_in_local_chain"])

    def test_real_hardhat_negative_weak_randomness_case(self):
        from simulation.service import run_runtime_validation

        source = _read_sample("weak_randomness_runtime_negative.sol")
        scan = engine.scan(source, "weak_randomness_runtime_negative.sol")
        findings = [f for f in scan["findings"] if f.get("check") == WEAK_RANDOMNESS_CHECK]
        self.assertGreater(len(findings), 0)

        result = run_runtime_validation(source, findings)
        validations = [v for v in result["validations"] if v["check"] == WEAK_RANDOMNESS_CHECK]
        self.assertGreater(len(validations), 0)
        self.assertEqual(validations[0]["status"], RUNTIME_NOT_CONFIRMED)
        self.assertFalse(validations[0]["evidence"]["security_relevant_difference"])


if __name__ == "__main__":
    unittest.main()
