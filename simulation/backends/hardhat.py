"""
Hardhat Network backend for Aegis runtime validation.

Hardening features:
- Configurable startup retries with bounded attempts.
- Optimized is_ready() that reuses the web3 provider.
- Structured error context on failures.
"""

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from simulation.backends.base import SimulationBackend

try:
    from web3 import Web3
    from web3.exceptions import ContractLogicError
except ImportError:  # pragma: no cover - handled by service
    Web3 = None
    ContractLogicError = Exception


def _npx_command() -> str:
    return "npx.cmd" if os.name == "nt" else "npx"


class HardhatBackend(SimulationBackend):
    backend_id = "hardhat"

    def __init__(
        self,
        repo_root: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 8545,
        startup_timeout: int = 15,
        rpc_timeout: int = 10,
        startup_retries: int = 2,
    ):
        self.repo_root = Path(repo_root or os.getcwd())
        self.host = host
        self.port = port
        self.startup_timeout = startup_timeout
        self.rpc_timeout = rpc_timeout
        self.startup_retries = startup_retries
        self.rpc_url = f"http://{self.host}:{self.port}"
        self._process = None
        self._managed_process = False
        self._w3 = None

        # Diagnostic counters.
        self._retry_count = 0
        self._startup_duration_ms = 0.0

    def start(self) -> None:
        if Web3 is None:
            raise RuntimeError("web3.py is not installed.")

        if self.is_ready():
            self._managed_process = False
            return

        executable = _npx_command()
        if shutil.which(executable) is None:
            raise RuntimeError("npx is not available, so Hardhat cannot be started.")

        last_error = None
        for attempt in range(1, self.startup_retries + 1):
            self._retry_count = attempt - 1
            try:
                self._start_once(executable)
                return  # Success
            except RuntimeError as exc:
                last_error = exc
                # Only retry if the process exited prematurely (not timeout).
                if "exited before becoming ready" in str(exc) and attempt < self.startup_retries:
                    self._cleanup_process()
                    time.sleep(0.5)
                    continue
                raise

        # Should not reach here, but safety net.
        raise last_error or RuntimeError("Hardhat node failed to start after retries.")

    def _start_once(self, executable: str) -> None:
        """Single attempt to start and wait for Hardhat to become ready."""
        t0 = time.monotonic()

        self._process = subprocess.Popen(
            [executable, "hardhat", "node", "--hostname", self.host, "--port", str(self.port)],
            cwd=str(self.repo_root),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        self._managed_process = True

        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if self.is_ready():
                self._startup_duration_ms = (time.monotonic() - t0) * 1000
                return
            if self._process.poll() is not None:
                raise RuntimeError(
                    f"Hardhat node exited before becoming ready (exit code: {self._process.returncode})."
                )
            time.sleep(0.5)

        self._startup_duration_ms = (time.monotonic() - t0) * 1000
        raise RuntimeError(
            f"Hardhat node did not become ready within {self.startup_timeout}s timeout."
        )

    def _cleanup_process(self) -> None:
        """Terminate a failed process for retry."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

    def stop(self) -> None:
        if self._process and self._managed_process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
        self._process = None
        self._w3 = None
        self._managed_process = False

    def is_ready(self) -> bool:
        if Web3 is None:
            return False
        try:
            # Reuse existing provider if already connected.
            if self._w3 is not None and self._w3.is_connected():
                return True
            self._w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": self.rpc_timeout}))
            return self._w3.is_connected()
        except Exception:
            return False

    def get_accounts(self) -> List[str]:
        self._require_web3()
        return [str(account) for account in self._w3.eth.accounts]

    def deploy_contract(self, abi: list, bytecode: str, constructor_args: Optional[List[Any]] = None) -> Dict[str, Any]:
        self._require_web3()
        constructor_args = constructor_args or []
        deployer = self.get_accounts()[0]
        contract = self._w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = contract.constructor(*constructor_args).transact({"from": deployer})
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        return {
            "contract_address": receipt.contractAddress,
            "tx_hash": tx_hash.hex(),
            "deployer": deployer,
            "receipt": _receipt_to_dict(receipt),
        }

    def execute_transaction(self, contract_abi: list, contract_address: str, function_name: str, args: List[Any], sender: str, value: int = 0) -> Dict[str, Any]:
        self._require_web3()
        contract = self._w3.eth.contract(address=contract_address, abi=contract_abi)
        function = getattr(contract.functions, function_name)(*args)
        tx_params = {"from": sender}
        if value:
            tx_params["value"] = value
        try:
            tx_hash = function.transact(tx_params)
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
            return {
                "success": True,
                "tx_hash": tx_hash.hex(),
                "receipt": _receipt_to_dict(receipt),
                "reverted": False,
            }
        except ContractLogicError as exc:
            return {
                "success": False,
                "reverted": True,
                "error": str(exc),
            }
        except ValueError as exc:
            message = _extract_rpc_error(exc)
            return {
                "success": False,
                "reverted": True,
                "error": message,
            }
        except Exception as exc:
            return {
                "success": False,
                "reverted": None,
                "error": str(exc),
            }

    def call_function(self, contract_abi: list, contract_address: str, function_name: str, args: Optional[List[Any]] = None) -> Any:
        """Read-only call to a contract function (no transaction created)."""
        self._require_web3()
        contract = self._w3.eth.contract(address=contract_address, abi=contract_abi)
        fn = getattr(contract.functions, function_name)(*(args or []))
        return fn.call()

    def get_block(self, block_identifier: str = "latest") -> Dict[str, Any]:
        self._require_web3()
        block = self._w3.eth.get_block(block_identifier)
        return {
            "number": int(block.number),
            "timestamp": int(block.timestamp),
            "hash": block.hash.hex() if getattr(block, "hash", None) else None,
        }

    def set_next_block_timestamp(self, timestamp: int) -> None:
        self._require_web3()
        response = self._w3.provider.make_request("evm_setNextBlockTimestamp", [int(timestamp)])
        if response.get("error"):
            raise RuntimeError(_extract_rpc_error(ValueError(response["error"])))

    def mine_block(self) -> Dict[str, Any]:
        self._require_web3()
        response = self._w3.provider.make_request("evm_mine", [])
        if response.get("error"):
            raise RuntimeError(_extract_rpc_error(ValueError(response["error"])))
        return self.get_block("latest")

    def get_balance(self, address: str) -> int:
        """Return the ETH balance (in wei) of the given address."""
        self._require_web3()
        return self._w3.eth.get_balance(address)

    def send_eth(self, sender: str, to: str, value: int) -> Dict[str, Any]:
        """Send raw ETH from *sender* to *to*."""
        self._require_web3()
        try:
            tx_hash = self._w3.eth.send_transaction({"from": sender, "to": to, "value": value})
            receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
            return {"success": True, "tx_hash": tx_hash.hex(), "receipt": _receipt_to_dict(receipt)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def get_diagnostics(self) -> dict:
        """Return diagnostic information about this backend instance."""
        return {
            "startup_retries_used": self._retry_count,
            "startup_duration_ms": round(self._startup_duration_ms, 2),
            "port": self.port,
            "host": self.host,
            "managed_process": self._managed_process,
            "connected": self._w3 is not None and self._w3.is_connected() if self._w3 else False,
        }

    def _require_web3(self) -> None:
        if not self._w3 and not self.is_ready():
            raise RuntimeError("Hardhat backend is not connected.")


def _extract_rpc_error(exc: Exception) -> str:
    if not exc.args:
        return str(exc)
    first = exc.args[0]
    if isinstance(first, dict):
        error = first.get("message") or first.get("data") or first
        return json.dumps(error) if isinstance(error, (dict, list)) else str(error)
    return str(first)


def _receipt_to_dict(receipt: Any) -> Dict[str, Any]:
    return {
        "status": getattr(receipt, "status", None),
        "blockNumber": getattr(receipt, "blockNumber", None),
        "gasUsed": getattr(receipt, "gasUsed", None),
        "contractAddress": getattr(receipt, "contractAddress", None),
    }
