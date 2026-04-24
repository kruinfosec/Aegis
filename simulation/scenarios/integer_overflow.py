"""
Runtime validation scenario for integer overflow / underflow findings (SWC-101).

Strategy
~~~~~~~~
For each integer-overflow finding, we:

1. Identify the relevant contract and arithmetic function.
2. Deploy the contract on the Hardhat local blockchain.
3. Execute the flagged arithmetic function with boundary inputs
   designed to trigger a uint256 overflow or underflow.
4. Read the resulting state (balances, counters) and compare
   against expected safe values.
5. If the value wraps around (e.g., balance becomes huge after
   subtracting from zero), classify as confirmed.
   If the transaction reverts (SafeMath, Solidity ≥0.8 checked
   arithmetic, or explicit requires), classify as not confirmed.

Honest classification
~~~~~~~~~~~~~~~~~~~~~
- **confirmed_by_runtime**: The arithmetic operation wrapped around
  at runtime — the post-state clearly shows an overflowed / underflowed
  value that is inconsistent with safe arithmetic.
- **not_confirmed_by_runtime**: The arithmetic operation reverted or
  explicitly guarded against overflow/underflow.
- **inconclusive_runtime**: The transaction succeeded but the post-state
  is ambiguous — we cannot definitively prove wraparound or safety.
- **simulation_unsupported**: The finding's contract shape doesn't match
  what this scenario can deploy/test (e.g., no matching function, complex
  constructor, or no balance getter).
"""

import re
from typing import List, Optional

from simulation.compiler import CompiledContract, compile_source, CompilationError
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_FAILED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
    RuntimeActionResult,
    ValidationRecord,
)


# ── Constants ────────────────────────────────────────────────────────────────

# Boundary value for uint256 underflow test: transfer from zero balance.
UNDERFLOW_TRANSFER_AMOUNT = 1
# Initial supply for contract deployment.
INITIAL_SUPPLY = 1000


# ── Public API ───────────────────────────────────────────────────────────────

def validate_integer_overflow(
    findings: list,
    compiled_contracts: List[CompiledContract],
    backend,
    source_code: str,
) -> List[ValidationRecord]:
    """Validate integer overflow findings by deploying and exercising arithmetic.

    Parameters
    ----------
    findings:
        Full findings list from the scanner.
    compiled_contracts:
        Pre-compiled contracts from the source.
    backend:
        Running HardhatBackend instance.
    source_code:
        Raw Solidity source (needed for contract inspection).

    Returns
    -------
    list[ValidationRecord]
        One record per integer-overflow finding that was testable.
    """
    validations = []
    relevant = [f for f in findings if f.get("check") == "integer-overflow"]
    accounts = backend.get_accounts()

    if not relevant:
        return validations

    for finding in relevant:
        record = _validate_one(finding, compiled_contracts, backend, source_code, accounts)
        validations.append(record)

    return validations


# ── Internal logic ───────────────────────────────────────────────────────────

def _validate_one(
    finding: dict,
    compiled_contracts: List[CompiledContract],
    backend,
    source_code: str,
    accounts: list,
) -> ValidationRecord:
    """Attempt integer overflow runtime validation for a single finding."""
    function_name = finding.get("function")
    contract_name = finding.get("contract_name")

    if not function_name:
        return _unsupported_record(
            finding, backend,
            "Function name could not be determined from the static finding.",
            ["Runtime validation requires a callable function name."],
        )

    # Find the contract in the compiled output.
    target_contract = _find_target_contract(compiled_contracts, contract_name, function_name)
    if target_contract is None:
        return _unsupported_record(
            finding, backend,
            f"No deployable contract with function '{function_name}' was found.",
            ["This scenario requires a contract with the flagged arithmetic function."],
        )

    # We need a way to observe state — look for `balances` mapping or similar.
    has_balances = _has_function(target_contract, "balances")
    has_total_supply = _has_function(target_contract, "totalSupply")

    if not has_balances:
        return _unsupported_record(
            finding, backend,
            "Contract does not expose a 'balances' getter for runtime observation.",
            ["This scenario requires a public balances mapping to observe overflow effects."],
        )

    # ── Deploy contract ──────────────────────────────────────────────────
    deployer = accounts[0]
    attacker = accounts[1] if len(accounts) > 1 else deployer
    actions = []

    try:
        constructor_args = _build_constructor_args(target_contract, accounts)
        deployment = backend.deploy_contract(
            target_contract.abi,
            target_contract.bytecode,
            constructor_args,
        )
        contract_address = deployment["contract_address"]
        actions.append(RuntimeActionResult(
            status="setup",
            action="deploy_contract",
            tx_hash=deployment.get("tx_hash"),
            account=deployer,
            function="constructor",
            details={"contract": contract_name, "address": contract_address},
        ))

        # ── Read initial state ───────────────────────────────────────────
        deployer_balance_before = backend.call_function(
            target_contract.abi, contract_address, "balances", [deployer],
        )
        attacker_balance_before = backend.call_function(
            target_contract.abi, contract_address, "balances", [attacker],
        )

        # ── Choose scenario strategy based on function ───────────────────
        if function_name == "transfer":
            return _test_underflow_transfer(
                finding, target_contract, backend, contract_address,
                deployer, attacker, attacker_balance_before, actions,
            )
        elif function_name in ("addReward", "bulkTransfer"):
            return _test_overflow_arithmetic(
                finding, target_contract, backend, contract_address,
                deployer, attacker, deployer_balance_before, actions,
                function_name,
            )
        else:
            # Generic: try calling the function with large values.
            return _test_generic_overflow(
                finding, target_contract, backend, contract_address,
                deployer, attacker, attacker_balance_before, actions,
                function_name,
            )

    except CompilationError as exc:
        return _failed_record(
            finding, backend, contract_name, function_name, actions,
            f"Compilation failed: {exc}",
        )
    except Exception as exc:
        return _failed_record(
            finding, backend, contract_name, function_name, actions,
            f"Unexpected error during integer overflow execution: {exc}",
        )


def _test_underflow_transfer(
    finding: dict,
    contract: CompiledContract,
    backend,
    contract_address: str,
    deployer: str,
    attacker: str,
    attacker_balance_before: int,
    actions: list,
) -> ValidationRecord:
    """Test underflow by transferring from an account with zero balance.

    If the attacker (who has no tokens) can transfer tokens and end up
    with a huge balance (uint256 wraparound), overflow is confirmed.
    If the transaction reverts, overflow is not confirmed.
    """
    contract_name = finding.get("contract_name")
    function_name = "transfer"

    # Attacker tries to transfer 1 token from their zero-balance account.
    transfer_result = backend.execute_transaction(
        contract_abi=contract.abi,
        contract_address=contract_address,
        function_name="transfer",
        args=[deployer, UNDERFLOW_TRANSFER_AMOUNT],
        sender=attacker,
    )
    actions.append(RuntimeActionResult(
        status="attack" if transfer_result.get("success") else "blocked",
        action="underflow_transfer",
        tx_hash=transfer_result.get("tx_hash"),
        reverted=transfer_result.get("reverted"),
        error=transfer_result.get("error"),
        account=attacker,
        function="transfer",
        details={
            "from": attacker,
            "to": deployer,
            "amount": UNDERFLOW_TRANSFER_AMOUNT,
            "balance_before": str(attacker_balance_before),
        },
    ))

    # Read post-state.
    attacker_balance_after = backend.call_function(
        contract.abi, contract_address, "balances", [attacker],
    )

    evidence = {
        "contract_name": contract_name,
        "contract_address": contract_address,
        "function_tested": function_name,
        "attacker_account": attacker,
        "transfer_amount": str(UNDERFLOW_TRANSFER_AMOUNT),
        "attacker_balance_before": str(attacker_balance_before),
        "attacker_balance_after": str(attacker_balance_after),
        "transfer_reverted": transfer_result.get("reverted"),
        "transfer_tx_hash": transfer_result.get("tx_hash"),
    }

    if transfer_result.get("reverted") or not transfer_result.get("success"):
        # Transaction reverted — safe arithmetic or guards prevented underflow.
        status = RUNTIME_NOT_CONFIRMED
        reason = (
            "The transfer transaction reverted when attempting to transfer "
            "from a zero-balance account. This indicates the arithmetic is "
            "guarded (e.g., require check, SafeMath, or Solidity ≥0.8 checked arithmetic)."
        )
        if transfer_result.get("error"):
            reason += f" Revert reason: {transfer_result['error']}"
    elif attacker_balance_after > attacker_balance_before and attacker_balance_after > 10**70:
        # Balance wrapped around to a huge number — underflow confirmed.
        status = RUNTIME_CONFIRMED
        reason = (
            f"The attacker's balance changed from {attacker_balance_before} to "
            f"{attacker_balance_after} after transferring {UNDERFLOW_TRANSFER_AMOUNT} "
            f"from a zero-balance account. This is a uint256 underflow wraparound, "
            f"confirming the arithmetic overflow vulnerability."
        )
    elif attacker_balance_after > attacker_balance_before:
        # Balance increased but not to a clearly wrapped value — still suspicious.
        status = RUNTIME_CONFIRMED
        reason = (
            f"The attacker's balance increased from {attacker_balance_before} to "
            f"{attacker_balance_after} after transferring from a zero-balance account. "
            f"This indicates arithmetic underflow."
        )
    else:
        status = RUNTIME_INCONCLUSIVE
        reason = (
            f"The transfer succeeded but the attacker's balance is {attacker_balance_after}. "
            f"Unable to definitively classify the arithmetic behavior."
        )

    evidence["classification_reason"] = reason

    return ValidationRecord(
        finding_id=finding.get("id"),
        check="integer-overflow",
        title=finding.get("vulnerability", "Integer Overflow / Underflow"),
        status=status,
        backend=backend.backend_id,
        scenario="integer_overflow.underflow_transfer",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            "This scenario tests a transfer-from-zero-balance underflow pattern.",
            "Only contracts with a public balances mapping can be observed.",
            "The test depends on compiler version: Solidity <0.8 may wrap, ≥0.8 will revert.",
        ],
    )


def _test_overflow_arithmetic(
    finding: dict,
    contract: CompiledContract,
    backend,
    contract_address: str,
    deployer: str,
    attacker: str,
    deployer_balance_before: int,
    actions: list,
    function_name: str,
) -> ValidationRecord:
    """Test overflow by calling addReward/bulkTransfer with extreme values."""
    contract_name = finding.get("contract_name")

    # Choose inputs based on function.
    if function_name == "addReward":
        # Try to add a huge reward that would overflow uint256.
        max_uint256 = 2**256 - 1
        reward_amount = max_uint256  # Adding this to any positive balance overflows.
        call_args = [deployer, reward_amount]
        action_name = "overflow_add_reward"
    elif function_name == "bulkTransfer":
        # Multiplication overflow: large unitAmount * large units.
        call_args = [attacker, 2**128, 2**128]
        action_name = "overflow_bulk_transfer"
    else:
        return _unsupported_record(
            finding, backend,
            f"No overflow test strategy for function '{function_name}'.",
            [],
        )

    tx_result = backend.execute_transaction(
        contract_abi=contract.abi,
        contract_address=contract_address,
        function_name=function_name,
        args=call_args,
        sender=deployer,
    )
    actions.append(RuntimeActionResult(
        status="attack" if tx_result.get("success") else "blocked",
        action=action_name,
        tx_hash=tx_result.get("tx_hash"),
        reverted=tx_result.get("reverted"),
        error=tx_result.get("error"),
        account=deployer,
        function=function_name,
        details={"args": [str(a) for a in call_args]},
    ))

    # Read post-state.
    deployer_balance_after = backend.call_function(
        contract.abi, contract_address, "balances", [deployer],
    )

    evidence = {
        "contract_name": contract_name,
        "contract_address": contract_address,
        "function_tested": function_name,
        "caller": deployer,
        "args": [str(a) for a in call_args],
        "balance_before": str(deployer_balance_before),
        "balance_after": str(deployer_balance_after),
        "tx_reverted": tx_result.get("reverted"),
        "tx_hash": tx_result.get("tx_hash"),
    }

    if tx_result.get("reverted") or not tx_result.get("success"):
        status = RUNTIME_NOT_CONFIRMED
        reason = (
            f"The {function_name}() call reverted when given overflow-triggering inputs. "
            f"This indicates the arithmetic is guarded."
        )
        if tx_result.get("error"):
            reason += f" Revert reason: {tx_result['error']}"
    elif function_name == "addReward" and deployer_balance_after < deployer_balance_before:
        # Balance decreased after adding a huge reward — definite overflow wraparound.
        status = RUNTIME_CONFIRMED
        reason = (
            f"After addReward with a near-max uint256 value, the deployer's balance "
            f"changed from {deployer_balance_before} to {deployer_balance_after}. "
            f"The decrease proves arithmetic overflow wraparound."
        )
    elif function_name == "bulkTransfer" and tx_result.get("success"):
        # bulkTransfer succeeded with huge multiplication — overflow let it bypass require.
        status = RUNTIME_CONFIRMED
        reason = (
            f"bulkTransfer succeeded with overflow-triggering multiplication inputs. "
            f"The totalAmount overflowed to a small value, bypassing the balance check."
        )
    else:
        status = RUNTIME_INCONCLUSIVE
        reason = (
            f"Transaction succeeded but post-state is ambiguous. "
            f"Balance before: {deployer_balance_before}, after: {deployer_balance_after}."
        )

    evidence["classification_reason"] = reason

    return ValidationRecord(
        finding_id=finding.get("id"),
        check="integer-overflow",
        title=finding.get("vulnerability", "Integer Overflow / Underflow"),
        status=status,
        backend=backend.backend_id,
        scenario=f"integer_overflow.{function_name}",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            f"This scenario tests {function_name}() with boundary inputs.",
            "Only contracts with a public balances mapping can be observed.",
            "The test depends on compiler version behavior.",
        ],
    )


def _test_generic_overflow(
    finding: dict,
    contract: CompiledContract,
    backend,
    contract_address: str,
    deployer: str,
    attacker: str,
    attacker_balance_before: int,
    actions: list,
    function_name: str,
) -> ValidationRecord:
    """Fallback: try calling the flagged function with boundary inputs."""
    # For generic functions we don't have a specific attack strategy,
    # mark as unsupported rather than pretend.
    return _unsupported_record(
        finding, backend,
        f"No specific overflow test strategy for function '{function_name}'.",
        [
            "This scenario supports transfer, addReward, and bulkTransfer patterns.",
            "Other arithmetic functions require custom scenario development.",
        ],
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_target_contract(
    compiled_contracts: List[CompiledContract],
    contract_name: Optional[str],
    function_name: str,
) -> Optional[CompiledContract]:
    """Find the contract matching the finding's contract_name or function."""
    # Exclude auto-generated Aegis contracts.
    aegis_names = {"AegisReentrancyAttacker", "AegisDelegatecallAttacker"}

    if contract_name:
        for contract in compiled_contracts:
            if contract.contract_name == contract_name and contract.contract_name not in aegis_names:
                if _has_function(contract, function_name):
                    return contract

    for contract in compiled_contracts:
        if contract.contract_name in aegis_names:
            continue
        if _has_function(contract, function_name):
            return contract

    return None


def _has_function(contract: CompiledContract, function_name: str) -> bool:
    return any(
        entry.get("type") == "function" and entry.get("name") == function_name
        for entry in contract.abi
    )


def _build_constructor_args(contract: CompiledContract, accounts: list) -> list:
    """Build constructor args for the target contract."""
    for entry in contract.abi:
        if entry.get("type") == "constructor":
            inputs = entry.get("inputs", [])
            if not inputs:
                return []
            args = []
            for inp in inputs:
                t = inp.get("type", "")
                if t == "address":
                    args.append(accounts[0])
                elif t.startswith("uint") or t.startswith("int"):
                    args.append(INITIAL_SUPPLY)
                elif t == "bool":
                    args.append(False)
                elif t == "string":
                    args.append("")
                elif t.startswith("bytes"):
                    args.append(b"")
                else:
                    return []
            return args
    return []


def _unsupported_record(
    finding: dict,
    backend,
    error_msg: str,
    limitations: list,
) -> ValidationRecord:
    return ValidationRecord(
        finding_id=finding.get("id"),
        check="integer-overflow",
        title=finding.get("vulnerability", "Integer Overflow / Underflow"),
        status=RUNTIME_UNSUPPORTED,
        backend=backend.backend_id,
        scenario="integer_overflow",
        contract_name=finding.get("contract_name"),
        function_name=finding.get("function"),
        error=error_msg,
        limitations=limitations,
    )


def _failed_record(
    finding: dict,
    backend,
    contract_name: Optional[str],
    function_name: Optional[str],
    actions: list,
    error_msg: str,
) -> ValidationRecord:
    return ValidationRecord(
        finding_id=finding.get("id"),
        check="integer-overflow",
        title=finding.get("vulnerability", "Integer Overflow / Underflow"),
        status=RUNTIME_FAILED,
        backend=backend.backend_id,
        scenario="integer_overflow",
        contract_name=contract_name,
        function_name=function_name,
        actions=actions,
        error=error_msg,
        limitations=["The integer overflow scenario failed before producing a classification."],
    )
