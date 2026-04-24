"""
Runtime validation scenario for weak randomness findings (SWC-120).

The scenario is intentionally narrow:
- Confirm lottery-style winner/payout paths when controlled local-chain block
  inputs steer the winner.
- Mark observation-only weak-randomness helpers as not confirmed rather than
  overstating exploitability.
- Classify unsupported contract shapes honestly.
"""

import re
from typing import Any, Dict, List, Optional

from scanner import parser
from simulation.compiler import CompiledContract
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
    RuntimeActionResult,
    ValidationRecord,
)


WEAK_RANDOMNESS_CHECK = "predictable-randomness"
DEFAULT_TICKET_VALUE = 10 ** 18
WEAK_SOURCE_RE = re.compile(
    r"\b(block\.timestamp|block\.number|block\.difficulty|block\.coinbase|blockhash\s*\()"
)
SECURITY_IMPACT_RE = re.compile(
    r"\b(winner|lottery|prize|payout|reward|draw|pick|transfer|call)\b",
    re.IGNORECASE,
)


def validate_weak_randomness(
    findings: list,
    compiled_contracts: List[CompiledContract],
    backend: Any,
    source_code: str,
) -> List[ValidationRecord]:
    validations: List[ValidationRecord] = []
    relevant = [finding for finding in findings if finding.get("check") == WEAK_RANDOMNESS_CHECK]
    if not relevant:
        return validations

    parsed = parser.parse(source_code)
    functions = parsed.get("analysis_context", {}).get("functions", [])
    accounts = backend.get_accounts()

    for finding in relevant:
        validations.append(
            _validate_one(finding, compiled_contracts, backend, functions, accounts)
        )

    return validations


def _validate_one(
    finding: dict,
    compiled_contracts: List[CompiledContract],
    backend: Any,
    functions: list,
    accounts: list,
) -> ValidationRecord:
    function_name = finding.get("function")
    contract_name = finding.get("contract_name")

    if not function_name:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            error="Function name could not be determined from the static finding.",
            limitations=["Runtime validation requires function-level context for weak-randomness findings."],
        )

    function_ctx = _find_function_context(functions, contract_name, function_name)
    if function_ctx is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="No matching function body was available for weak-randomness scenario classification.",
            limitations=["Runtime validation needs source-level function context to understand weak-randomness usage."],
        )

    compiled_contract = _find_target_contract(compiled_contracts, contract_name, function_name)
    if compiled_contract is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="No deployable contract with the flagged weak-randomness function was found.",
            limitations=["This scenario currently supports direct deployment of compiled contracts only."],
        )

    function_abi = _find_function_abi(compiled_contract.abi, function_name)
    if function_abi is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=compiled_contract.contract_name,
            function_name=function_name,
            error="The flagged function is not directly callable in the compiled ABI.",
            limitations=["Runtime validation supports public/external callable weak-randomness paths only."],
        )

    pattern = _classify_pattern(function_ctx, function_abi, compiled_contract)
    if pattern == "lottery_winner_payout":
        return _validate_lottery_winner_payout(
            finding,
            compiled_contract,
            function_abi,
            backend,
            function_ctx,
            accounts,
        )
    if pattern == "observation_only":
        return _validate_observation_only(
            finding,
            compiled_contract,
            function_abi,
            backend,
            function_ctx,
            accounts,
        )

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=WEAK_RANDOMNESS_CHECK,
        title=finding.get("vulnerability", "Weak Randomness"),
        status=RUNTIME_INCONCLUSIVE,
        backend=backend.backend_id,
        scenario="weak_randomness.predictability_probe",
        contract_name=compiled_contract.contract_name,
        function_name=function_name,
        evidence={
            "contract_name": compiled_contract.contract_name,
            "function_tested": function_name,
            "weak_randomness_source": finding.get("weak_randomness_source"),
            "classification_reason": (
                "The function uses weak block-derived randomness, but the contract shape did not "
                "match a scenario that can honestly prove a steerable payout or winner outcome."
            ),
        },
        limitations=[
            "This batch confirms simple lottery winner/payout patterns and observation-only negative cases.",
            "Other weak-randomness uses may need custom scenario logic before runtime confirmation is appropriate.",
        ],
    )


def _validate_lottery_winner_payout(
    finding: dict,
    contract: CompiledContract,
    function_abi: dict,
    backend: Any,
    function_ctx: dict,
    accounts: list,
) -> ValidationRecord:
    contract_name = contract.contract_name
    function_name = function_ctx["name"]
    if len(accounts) < 3:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="Not enough accounts available for lottery steering validation.",
            limitations=["This scenario requires one caller and at least two participant accounts."],
        )

    draw_args = _build_function_args(function_abi.get("inputs", []), accounts)
    if draw_args is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="Draw function arguments are not supported by this scenario.",
            limitations=["Lottery weak-randomness validation currently supports zero-arg or simple scalar draw functions."],
        )

    even_run = _run_lottery_case(
        backend,
        contract,
        function_name,
        draw_args,
        accounts,
        desired_remainder=0,
    )
    odd_run = _run_lottery_case(
        backend,
        contract,
        function_name,
        draw_args,
        accounts,
        desired_remainder=1,
    )

    actions = even_run["actions"] + odd_run["actions"]
    winner_changed = (
        even_run.get("last_winner")
        and odd_run.get("last_winner")
        and even_run["last_winner"].lower() != odd_run["last_winner"].lower()
    )
    both_paid = even_run["payout_triggered"] and odd_run["payout_triggered"]

    status = RUNTIME_INCONCLUSIVE
    reason = (
        "The weak-randomness path executed, but the observed winner or payout evidence was ambiguous."
    )
    if winner_changed and both_paid:
        status = RUNTIME_CONFIRMED
        reason = (
            "Controlled local-chain block timestamps steered the same lottery setup to different "
            "winners while paying out the contract balance. This confirms a predictable, "
            "security-relevant outcome in the tested Hardhat setup."
        )
    elif even_run["tx"].get("success") and odd_run["tx"].get("success"):
        status = RUNTIME_NOT_CONFIRMED
        reason = (
            "The tested block conditions did not produce a materially different winner or payout "
            "in the executed local-chain path."
        )

    evidence = {
        "contract_name": contract_name,
        "contract_address": odd_run["contract_address"],
        "function_tested": function_name,
        "weak_randomness_source": finding.get("weak_randomness_source"),
        "block_properties_used": _block_properties_used(function_ctx),
        "classification_reason": reason,
        "first_case": even_run["evidence"],
        "second_case": odd_run["evidence"],
        "winner_changed": winner_changed,
        "payout_observed": both_paid,
        "outcome_steerable_in_local_chain": winner_changed and both_paid,
    }

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=WEAK_RANDOMNESS_CHECK,
        title=finding.get("vulnerability", "Weak Randomness"),
        status=status,
        backend=backend.backend_id,
        scenario="weak_randomness.lottery_winner_payout",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            "This confirms steerability only for the executed local Hardhat path.",
            "The result does not quantify real-world validator incentives, mempool ordering, or production chain constraints.",
            "The scenario currently targets simple lottery contracts with buyTicket() and lastWinner().",
        ],
    )


def _validate_observation_only(
    finding: dict,
    contract: CompiledContract,
    function_abi: dict,
    backend: Any,
    function_ctx: dict,
    accounts: list,
) -> ValidationRecord:
    contract_name = contract.contract_name
    function_name = function_ctx["name"]
    constructor_args = _build_constructor_args(contract.abi, accounts)
    if constructor_args is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="Constructor arguments for this contract shape are not supported.",
            limitations=["Observation-only weak-randomness validation currently supports simple constructor inputs."],
        )

    function_args = _build_function_args(function_abi.get("inputs", []), accounts)
    if function_args is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="Function arguments for this weak-randomness helper are not supported.",
            limitations=["Observation-only weak-randomness validation currently supports common scalar ABI inputs."],
        )

    deployment = backend.deploy_contract(contract.abi, contract.bytecode, constructor_args)
    contract_address = deployment["contract_address"]
    first = _call_observation(backend, contract, contract_address, function_name, function_args, offset=3)
    second = _call_observation(backend, contract, contract_address, function_name, function_args, offset=5)
    output_changed = first["result"] != second["result"]

    evidence = {
        "contract_name": contract_name,
        "contract_address": contract_address,
        "function_tested": function_name,
        "weak_randomness_source": finding.get("weak_randomness_source"),
        "block_properties_used": _block_properties_used(function_ctx),
        "first_observation": first,
        "second_observation": second,
        "output_changed": output_changed,
        "security_relevant_difference": False,
        "classification_reason": (
            "The helper exposes block-derived pseudo-random output, but the executed path is "
            "view-only and did not transfer value, pick a winner, mint assets, or change privileged state."
        ),
    }

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=WEAK_RANDOMNESS_CHECK,
        title=finding.get("vulnerability", "Weak Randomness"),
        status=RUNTIME_NOT_CONFIRMED,
        backend=backend.backend_id,
        scenario="weak_randomness.observation_only",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=[
            RuntimeActionResult(
                status=RUNTIME_NOT_CONFIRMED,
                action="observation_only_randomness_probe",
                account=accounts[0],
                function=function_name,
                details=evidence,
            )
        ],
        limitations=[
            "A changing view-only pseudo-random value may still be unsafe if another contract consumes it.",
            "This classification applies only to the direct executed path in this contract.",
        ],
    )


def _run_lottery_case(
    backend: Any,
    contract: CompiledContract,
    draw_function: str,
    draw_args: list,
    accounts: list,
    *,
    desired_remainder: int,
) -> dict:
    deployer, player_a, player_b = accounts[0], accounts[1], accounts[2]
    deployment = backend.deploy_contract(contract.abi, contract.bytecode, _build_constructor_args(contract.abi, accounts) or [])
    contract_address = deployment["contract_address"]
    actions = [
        RuntimeActionResult(
            status="setup",
            action="deploy_contract",
            tx_hash=deployment.get("tx_hash"),
            account=deployer,
            function="constructor",
            details={"contract": contract.contract_name, "contract_address": contract_address},
        )
    ]

    ticket_value = _ticket_value(backend, contract, contract_address)
    for player in (player_a, player_b):
        buy_tx = backend.execute_transaction(
            contract_abi=contract.abi,
            contract_address=contract_address,
            function_name="buyTicket",
            args=[],
            sender=player,
            value=ticket_value,
        )
        actions.append(
            RuntimeActionResult(
                status="setup" if buy_tx.get("success") else RUNTIME_INCONCLUSIVE,
                action="buy_ticket",
                tx_hash=buy_tx.get("tx_hash"),
                reverted=buy_tx.get("reverted"),
                error=buy_tx.get("error"),
                account=player,
                function="buyTicket",
                details={"value_wei": str(ticket_value), "contract_address": contract_address},
            )
        )

    balance_before = backend.get_balance(contract_address)
    latest = backend.get_block("latest")
    draw_timestamp = _next_timestamp_with_remainder(int(latest["timestamp"]) + 1, 2, desired_remainder)
    backend.set_next_block_timestamp(draw_timestamp)
    draw_tx = backend.execute_transaction(
        contract_abi=contract.abi,
        contract_address=contract_address,
        function_name=draw_function,
        args=draw_args,
        sender=deployer,
    )
    draw_block = backend.get_block("latest")
    balance_after = backend.get_balance(contract_address)
    last_winner = None
    try:
        last_winner = backend.call_function(contract.abi, contract_address, "lastWinner", [])
    except Exception:
        pass

    payout_triggered = bool(draw_tx.get("success") and balance_before > 0 and balance_after == 0)
    actions.append(
        RuntimeActionResult(
            status=RUNTIME_CONFIRMED if payout_triggered else RUNTIME_INCONCLUSIVE,
            action="draw_with_controlled_block_input",
            tx_hash=draw_tx.get("tx_hash"),
            reverted=draw_tx.get("reverted"),
            error=draw_tx.get("error"),
            account=deployer,
            function=draw_function,
            arguments=draw_args,
            details={
                "timestamp_used": draw_timestamp,
                "block_number": draw_block.get("number"),
                "block_hash": draw_block.get("hash"),
                "last_winner": last_winner,
                "contract_balance_before_wei": str(balance_before),
                "contract_balance_after_wei": str(balance_after),
                "payout_triggered": payout_triggered,
            },
        )
    )

    return {
        "contract_address": contract_address,
        "tx": draw_tx,
        "last_winner": last_winner,
        "payout_triggered": payout_triggered,
        "actions": actions,
        "evidence": {
            "contract_address": contract_address,
            "timestamp": draw_timestamp,
            "block_number": draw_block.get("number"),
            "block_hash": draw_block.get("hash"),
            "players": [player_a, player_b],
            "last_winner": last_winner,
            "contract_balance_before_wei": str(balance_before),
            "contract_balance_after_wei": str(balance_after),
            "draw_tx_hash": draw_tx.get("tx_hash"),
            "draw_reverted": draw_tx.get("reverted"),
            "payout_triggered": payout_triggered,
        },
    }


def _call_observation(
    backend: Any,
    contract: CompiledContract,
    contract_address: str,
    function_name: str,
    function_args: list,
    *,
    offset: int,
) -> dict:
    latest = backend.get_block("latest")
    timestamp = int(latest["timestamp"]) + offset
    backend.set_next_block_timestamp(timestamp)
    mined = backend.mine_block()
    result = backend.call_function(contract.abi, contract_address, function_name, function_args)
    return {
        "timestamp": timestamp,
        "block_number": mined.get("number"),
        "block_hash": mined.get("hash"),
        "result": result,
    }


def _classify_pattern(function_ctx: dict, function_abi: dict, contract: CompiledContract) -> str:
    text = f"{function_ctx.get('header', '')}\n{function_ctx.get('body', '')}"
    if (
        "%" in text
        and WEAK_SOURCE_RE.search(text)
        and SECURITY_IMPACT_RE.search(text)
        and _has_function(contract.abi, "buyTicket")
        and _has_function(contract.abi, "lastWinner")
    ):
        return "lottery_winner_payout"
    if function_abi.get("stateMutability") in {"view", "pure"}:
        return "observation_only"
    return "ambiguous"


def _find_function_context(functions: list, contract_name: Optional[str], function_name: str) -> Optional[dict]:
    for function in functions:
        if function.get("name") != function_name:
            continue
        if contract_name and function.get("contract_name") != contract_name:
            continue
        return function
    for function in functions:
        if function.get("name") == function_name:
            return function
    return None


def _find_target_contract(
    compiled_contracts: List[CompiledContract],
    contract_name: Optional[str],
    function_name: str,
) -> Optional[CompiledContract]:
    if contract_name:
        for contract in compiled_contracts:
            if contract.contract_name == contract_name and _find_function_abi(contract.abi, function_name):
                return contract
    for contract in compiled_contracts:
        if _find_function_abi(contract.abi, function_name):
            return contract
    return None


def _find_function_abi(abi: list, function_name: str) -> Optional[dict]:
    for entry in abi:
        if entry.get("type") == "function" and entry.get("name") == function_name:
            return entry
    return None


def _has_function(abi: list, function_name: str) -> bool:
    return _find_function_abi(abi, function_name) is not None


def _ticket_value(backend: Any, contract: CompiledContract, contract_address: str) -> int:
    if _has_function(contract.abi, "ticketPrice"):
        try:
            return int(backend.call_function(contract.abi, contract_address, "ticketPrice", []))
        except Exception:
            return DEFAULT_TICKET_VALUE
    return DEFAULT_TICKET_VALUE


def _block_properties_used(function_ctx: dict) -> list:
    text = f"{function_ctx.get('header', '')}\n{function_ctx.get('body', '')}"
    properties = []
    for name, pattern in [
        ("block.timestamp", r"\bblock\.timestamp\b"),
        ("block.number", r"\bblock\.number\b"),
        ("blockhash", r"\bblockhash\s*\("),
        ("block.difficulty", r"\bblock\.difficulty\b"),
        ("block.coinbase", r"\bblock\.coinbase\b"),
    ]:
        if re.search(pattern, text):
            properties.append(name)
    return properties


def _build_constructor_args(abi: list, accounts: list) -> Optional[list]:
    for entry in abi:
        if entry.get("type") != "constructor":
            continue
        args = _build_function_args(entry.get("inputs", []), accounts)
        return [] if args is None and not entry.get("inputs") else args
    return []


def _build_function_args(inputs: List[Dict[str, Any]], accounts: list) -> Optional[list]:
    built = []
    for entry in inputs:
        arg = _build_arg(entry.get("type", ""), accounts)
        if arg is None:
            return None
        built.append(arg)
    return built


def _build_arg(arg_type: str, accounts: list) -> Optional[Any]:
    if arg_type.endswith("[]"):
        inner = _build_arg(arg_type[:-2], accounts)
        return None if inner is None else [inner]
    if arg_type == "address":
        return accounts[0]
    if arg_type.startswith("uint") or arg_type.startswith("int"):
        return 1
    if arg_type == "bool":
        return True
    if arg_type == "string":
        return "aegis"
    if arg_type.startswith("bytes"):
        return b""
    return None


def _next_timestamp_with_remainder(value: int, modulus: int, desired_remainder: int) -> int:
    candidate = int(value)
    while candidate % modulus != desired_remainder:
        candidate += 1
    return candidate


def _unsupported_record(
    finding: dict,
    backend: Any,
    *,
    contract_name: Optional[str] = None,
    function_name: Optional[str] = None,
    error: str = "",
    limitations: Optional[list] = None,
) -> ValidationRecord:
    return ValidationRecord(
        finding_id=finding.get("id"),
        check=WEAK_RANDOMNESS_CHECK,
        title=finding.get("vulnerability", "Weak Randomness"),
        status=RUNTIME_UNSUPPORTED,
        backend=backend.backend_id,
        scenario="weak_randomness.predictability_probe",
        contract_name=contract_name,
        function_name=function_name,
        error=error,
        limitations=limitations or ["The contract shape is not supported by this runtime scenario."],
    )
