import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from scanner import engine
from scanner.finding import merge_runtime_validations
from simulation.compiler import CompilationError
from simulation.compiler import CompiledContract
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
)
from simulation.scenarios.access_control import validate_access_control
from simulation.service import run_runtime_validation


class FakeBackend:
    backend_id = "hardhat"

    def __init__(self, tx_result):
        self.tx_result = tx_result

    def get_accounts(self):
        return [
            "0x0000000000000000000000000000000000000001",
            "0x0000000000000000000000000000000000000002",
            "0x0000000000000000000000000000000000000003",
        ]

    def deploy_contract(self, abi, bytecode, constructor_args=None):
        return {
            "contract_address": "0x00000000000000000000000000000000000000AA",
            "tx_hash": "0xdeploy",
            "deployer": self.get_accounts()[0],
            "receipt": {"status": 1},
        }

    def execute_transaction(self, contract_abi, contract_address, function_name, args, sender):
        return self.tx_result


class TestSimulationFoundation(unittest.TestCase):
    def setUp(self):
        self.samples_dir = os.path.join(os.path.dirname(__file__), "..", "samples")

    def read_sample(self, filename: str) -> str:
        with open(os.path.join(self.samples_dir, filename), "r", encoding="utf-8") as handle:
            return handle.read()

    def scan(self, filename: str) -> dict:
        return engine.scan(self.read_sample(filename), filename)

    def test_service_returns_unsupported_without_relevant_findings(self):
        result = run_runtime_validation(self.read_sample("safe.sol"), [], backend_name="hardhat")
        self.assertEqual(result["status"], RUNTIME_UNSUPPORTED)

    def test_access_control_validation_confirms_successful_unauthorized_call(self):
        scan_result = self.scan("access.sol")
        compiled = [
            CompiledContract(
                contract_name="UnprotectedToken",
                abi=[
                    {"type": "constructor", "inputs": []},
                    {"type": "function", "name": "mint", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}]},
                ],
                bytecode="0x6000",
            )
        ]
        backend = FakeBackend(
            {
                "success": True,
                "tx_hash": "0x1234",
                "receipt": {"status": 1},
                "reverted": False,
            }
        )
        finding = next(f for f in scan_result["findings"] if f["function"] == "mint")
        validations = validate_access_control([finding], compiled, backend)
        self.assertEqual(len(validations), 1)
        self.assertEqual(validations[0].status, RUNTIME_CONFIRMED)

    def test_access_control_validation_marks_revert_as_not_confirmed(self):
        scan_result = self.scan("access_runtime_negative.sol")
        compiled = [
            CompiledContract(
                contract_name="HelperProtectedToken",
                abi=[
                    {"type": "constructor", "inputs": []},
                    {"type": "function", "name": "mint", "inputs": [{"name": "to", "type": "address"}, {"name": "amount", "type": "uint256"}]},
                ],
                bytecode="0x6000",
            )
        ]
        backend = FakeBackend(
            {
                "success": False,
                "reverted": True,
                "error": "Not owner",
            }
        )
        finding = next(f for f in scan_result["findings"] if f["function"] == "mint")
        validations = validate_access_control([finding], compiled, backend)
        self.assertEqual(validations[0].status, RUNTIME_NOT_CONFIRMED)
        self.assertEqual(validations[0].contract_name, "HelperProtectedToken")

    @patch("simulation.service.compile_source_rich", side_effect=CompilationError("compiler unavailable"))
    def test_service_handles_missing_compiler(self, _mock_compile):
        scan_result = self.scan("access.sol")
        result = run_runtime_validation(self.read_sample("access.sol"), scan_result["findings"], backend_name="hardhat")
        self.assertEqual(result["status"], "simulation_failed")
        self.assertIn("compilation", result["summary"].lower())

    def test_real_hardhat_access_control_validation(self):
        scan_result = self.scan("access.sol")
        result = run_runtime_validation(self.read_sample("access.sol"), scan_result["findings"], backend_name="hardhat")
        self.assertEqual(result["backend"], "hardhat")
        self.assertTrue(result["validations"])
        self.assertIn(result["status"], {RUNTIME_CONFIRMED, "confirmed_by_runtime"})
        self.assertTrue(any(v["status"] == RUNTIME_CONFIRMED for v in result["validations"]))

    def test_real_hardhat_negative_access_control_validation(self):
        scan_result = self.scan("access_runtime_negative.sol")
        result = run_runtime_validation(self.read_sample("access_runtime_negative.sol"), scan_result["findings"], backend_name="hardhat")
        self.assertEqual(result["backend"], "hardhat")
        self.assertTrue(result["validations"])
        self.assertEqual(result["status"], RUNTIME_NOT_CONFIRMED)
        self.assertTrue(all(v["status"] == RUNTIME_NOT_CONFIRMED for v in result["validations"]))

    def test_contract_matching_uses_static_contract_context(self):
        scan_result = self.scan("access_multi.sol")
        mint_finding = next(f for f in scan_result["findings"] if f["function"] == "mint")
        self.assertEqual(mint_finding["contract_name"], "ExposedMintToken")

        result = run_runtime_validation(self.read_sample("access_multi.sol"), scan_result["findings"], backend_name="hardhat")
        mint_validation = next(v for v in result["validations"] if v["function_name"] == "mint")
        self.assertEqual(mint_validation["contract_name"], "ExposedMintToken")
        self.assertEqual(mint_validation["status"], RUNTIME_CONFIRMED)

    def test_runtime_merge_back_enriches_findings(self):
        scan_result = self.scan("access_runtime_negative.sol")
        runtime_result = {
            "validations": [
                {
                    "finding_id": scan_result["findings"][0]["id"],
                    "status": RUNTIME_NOT_CONFIRMED,
                    "backend": "hardhat",
                    "check": "access_control.unauthorized_privileged_call",
                    "evidence": {"reverted": True},
                    "limitations": ["Test limitation"],
                    "error": "Not owner",
                }
            ]
        }
        merged = merge_runtime_validations(scan_result["findings"], runtime_result)
        finding = next(f for f in merged if f["id"] == scan_result["findings"][0]["id"])
        self.assertEqual(finding["runtime_validation_status"], RUNTIME_NOT_CONFIRMED)
        self.assertEqual(finding["runtime_backend"], "hardhat")
        self.assertEqual(finding["verification"]["dynamic"], "NOT_CONFIRMED")
        self.assertEqual(finding["exploitability"], "NOT_CONFIRMED_BY_RUNTIME")
        self.assertTrue(finding["validation_notes"])


if __name__ == "__main__":
    unittest.main()
