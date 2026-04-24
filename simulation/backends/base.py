"""
Backend abstraction for runtime validation chains.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class SimulationBackend(ABC):
    backend_id = "unknown"

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass

    @abstractmethod
    def is_ready(self) -> bool:
        pass

    @abstractmethod
    def get_accounts(self) -> List[str]:
        pass

    @abstractmethod
    def deploy_contract(self, abi: list, bytecode: str, constructor_args: Optional[List[Any]] = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    def execute_transaction(self, contract_abi: list, contract_address: str, function_name: str, args: List[Any], sender: str, value: int = 0) -> Dict[str, Any]:
        pass

    @abstractmethod
    def call_function(self, contract_abi: list, contract_address: str, function_name: str, args: Optional[List[Any]] = None) -> Any:
        """Read-only call to a contract function (no transaction created)."""
        pass

    @abstractmethod
    def get_block(self, block_identifier: str = "latest") -> Dict[str, Any]:
        """Return block metadata for the requested block identifier."""
        pass

    @abstractmethod
    def set_next_block_timestamp(self, timestamp: int) -> None:
        """Set the timestamp for the next mined block."""
        pass

    @abstractmethod
    def mine_block(self) -> Dict[str, Any]:
        """Mine a block and return the latest block metadata."""
        pass
