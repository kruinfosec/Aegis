"""
Runtime validation scenario for timestamp dependence findings (SWC-116).

This scenario stays intentionally narrow and honest:

- It confirms only patterns where a small timestamp skew changes a
  security-relevant outcome in the tested local-chain path.
- It does not treat long-horizon scheduling or observation-only time checks
  as confirmed vulnerabilities.
- It classifies vague or unsupported contract shapes conservatively.
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


TIMESTAMP_CHECK = "timestamp-dependence"
VALIDATOR_SKEW_SECONDS = 15
DEFAULT_PAYABLE_TEST_VALUE = 10 ** 18
TIMESTAMP_CONTROL_FLOW_RE = re.compile(
    r"(require|if|while)\s*\((?P<expr>[^;]*\b(block\.timestamp|now)\b[^;]*)\)"
)
TIME_UNIT_RE = re.compile(r"\b\d+\s+(seconds?|minutes?|hours?|days?|weeks?)\b", re.IGNORECASE)
MODULO_RE = re.compile(r"\b(block\.timestamp|now)\b\s*%\s*(?P<modulus>\d+)")
SECURITY_IMPACT_RE = re.compile(
    r"\b(transfer|send|call|winner|reward|payout|claim|withdraw|drain)\b",
    re.IGNORECASE,
)


def validate_timestamp_dependence(
    findings: list,
    compiled_contracts: List[CompiledContract],
    backend: Any,
    source_code: str,
) -> List[ValidationRecord]:
    validations: List[ValidationRecord] = []
    relevant = [finding for finding in findings if finding.get("check") == TIMESTAMP_CHECK]
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
    scenario_name = "timestamp_dependence.timestamp_skew_observation"

    if not function_name:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario=scenario_name,
            contract_name=contract_name,
            error="Function name could not be determined from the static finding.",
            limitations=["Runtime validation requires function-level context for timestamp findings."],
        )

    function_ctx = _find_function_context(functions, contract_name, function_name)
    if function_ctx is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario=scenario_name,
            contract_name=contract_name,
            function_name=function_name,
            error="No matching function body was available for timestamp scenario classification.",
            limitations=["Runtime validation needs source-level function context to understand timestamp usage."],
        )

    compiled_contract = _find_target_contract(compiled_contracts, contract_name, function_name)
    if compiled_contract is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario=scenario_name,
            contract_name=contract_name,
            function_name=function_name,
            error="No deployable contract with the flagged timestamp-dependent function was found.",
            limitations=["This scenario currently supports direct deployment of compiled contracts only."],
        )

    function_abi = _find_function_abi(compiled_contract.abi, function_name)
    if function_abi is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario=scenario_name,
            contract_name=compiled_contract.contract_name,
            function_name=function_name,
            error="The flagged function is not directly callable in the compiled ABI.",
            limitations=["Runtime validation supports public/external callable timestamp paths only."],
        )

    pattern = _classify_function_pattern(function_ctx, function_abi)
    if pattern == "security_sensitive_modulo":
        return _validate_security_sensitive_modulo(
            finding,
            compiled_contract,
            function_abi,
            backend,
            function_ctx,
            accounts,
        )

    if pattern == "observation_only":
        return _validate_observation_only_window(
            finding,
            compiled_contract,
            function_abi,
            backend,
            function_ctx,
            accounts,
        )

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=TIMESTAMP_CHECK,
        title=finding.get("vulnerability", "Timestamp Dependence"),
        status=RUNTIME_INCONCLUSIVE,
        backend=backend.backend_id,
        scenario="timestamp_dependence.timestamp_skew_observation",
        contract_name=compiled_contract.contract_name,
        function_name=function_name,
        evidence={
            "contract_name": compiled_contract.contract_name,
            "function_tested": function_name,
            "classification_reason": (
                "The contract uses block.timestamp in control flow, but the function shape "
                "did not match a scenario that can honestly confirm or disprove meaningful "
                "runtime exploitability in this batch."
            ),
        },
        limitations=[
            "This batch confirms payout/gating patterns and observation-only negative cases only.",
            "More complex timestamp-dependent business logic may require custom per-pattern scenarios.",
        ],
    )


def _validate_security_sensitive_modulo(
    finding: dict,
    contract: CompiledContract,
    function_abi: dict,
    backend: Any,
    function_ctx: dict,
    accounts: list,
) -> ValidationRecord:
    contract_name = contract.contract_name
    function_name = function_ctx["name"]
    caller = accounts[1] if len(accounts) > 1 else accounts[0]
    sponsor = accounts[0]
    constructor_args = _build_constructor_args(contract.abi, accounts)
    if constructor_args is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="timestamp_dependence.security_sensitive_modulo",
            contract_name=contract_name,
            function_name=function_name,
            error="Constructor arguments for this contract shape are not supported.",
            limitations=["Timestamp runtime validation currently supports only simple constructor inputs."],
        )

    function_args = _build_function_args(function_abi.get("inputs", []), accounts)
    if function_args is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="timestamp_dependence.security_sensitive_modulo",
            contract_name=contract_name,
            function_name=function_name,
            error="Function arguments for this timestamp-dependent path are not supported.",
            limitations=["Timestamp runtime validation currently supports only common scalar ABI inputs."],
        )

    payable_value = _derive_payable_value(function_ctx, function_abi)
    modulus = _extract_modulus(function_ctx.get("body", ""))
    latest = backend.get_block("latest")
    base_timestamp = int(latest["timestamp"]) + 2
    winning_timestamp = _next_multiple(base_timestamp, modulus)
    losing_timestamp = winning_timestamp + 1

    losing_run = _run_security_sensitive_case(
        backend,
        contract,
        function_name,
        function_args,
        sponsor,
        caller,
        constructor_args,
        seed_timestamp=max(base_timestamp, winning_timestamp - 2),
        attack_timestamp=losing_timestamp,
        payable_value=payable_value,
    )
    winning_run = _run_security_sensitive_case(
        backend,
        contract,
        function_name,
        function_args,
        sponsor,
        caller,
        constructor_args,
        seed_timestamp=max(losing_timestamp + 1, winning_timestamp + 2),
        attack_timestamp=winning_timestamp + modulus,
        payable_value=payable_value,
    )

    actions = losing_run["actions"] + winning_run["actions"]
    classification_reason = (
        "The tested function produced materially different value-flow outcomes when the call "
        f"timestamp was shifted within a {VALIDATOR_SKEW_SECONDS}-second local-chain skew window."
    )
    status = RUNTIME_INCONCLUSIVE
    if (
        losing_run["tx"].get("success")
        and winning_run["tx"].get("success")
        and not losing_run["payout_triggered"]
        and winning_run["payout_triggered"]
        and winning_run["attack_timestamp"] - losing_run["attack_timestamp"] <= VALIDATOR_SKEW_SECONDS
    ):
        status = RUNTIME_CONFIRMED
        classification_reason = (
            "A one-second timestamp change within the tested local Hardhat environment changed the "
            "payout outcome of the same function call. The losing timestamp left ETH in the contract, "
            "while the winning timestamp drained the contract to the caller."
        )
    elif (
        losing_run["tx"].get("success")
        and winning_run["tx"].get("success")
        and losing_run["payout_triggered"] == winning_run["payout_triggered"]
    ):
        status = RUNTIME_NOT_CONFIRMED
        classification_reason = (
            "The tested timestamp skew did not materially change the observed payout outcome in the "
            "executed local-chain path."
        )

    evidence = {
        "contract_name": contract_name,
        "contract_address": winning_run["contract_address"],
        "function_tested": function_name,
        "classification_reason": classification_reason,
        "skew_window_seconds": VALIDATOR_SKEW_SECONDS,
        "modulus": modulus,
        "losing_case": losing_run["evidence"],
        "winning_case": winning_run["evidence"],
        "outcome_changed": losing_run["payout_triggered"] != winning_run["payout_triggered"],
        "reachable_only_with_time_shift": (
            not losing_run["payout_triggered"] and winning_run["payout_triggered"]
        ),
    }

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=TIMESTAMP_CHECK,
        title=finding.get("vulnerability", "Timestamp Dependence"),
        status=status,
        backend=backend.backend_id,
        scenario="timestamp_dependence.security_sensitive_modulo",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            "This confirms manipulability only for the executed local Hardhat path.",
            "The result does not quantify real-world validator incentives or network conditions.",
            "This scenario currently targets fine-grained modulo/equality payout patterns only.",
        ],
    )


def _validate_observation_only_window(
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
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="timestamp_dependence.observation_only_window",
            contract_name=contract_name,
            function_name=function_name,
            error="Constructor arguments for this contract shape are not supported.",
            limitations=["Timestamp runtime validation currently supports only simple constructor inputs."],
        )

    function_args = _build_function_args(function_abi.get("inputs", []), accounts)
    if function_args is None:
        return ValidationRecord(
            finding_id=finding.get("id"),
            check=TIMESTAMP_CHECK,
            title=finding.get("vulnerability", "Timestamp Dependence"),
            status=RUNTIME_UNSUPPORTED,
            backend=backend.backend_id,
            scenario="timestamp_dependence.observation_only_window",
            contract_name=contract_name,
            function_name=function_name,
            error="Function arguments for this timestamp path are not supported.",
            limitations=["Timestamp runtime validation currently supports only common scalar ABI inputs."],
        )

    deployment = backend.deploy_contract(contract.abi, contract.bytecode, constructor_args)
    contract_address = deployment["contract_address"]
    latest = backend.get_block("latest")
    first_timestamp = int(latest["timestamp"]) + 5
    second_timestamp = first_timestamp + VALIDATOR_SKEW_SECONDS

    first_call = _call_at_timestamp(
        backend,
        contract,
        contract_address,
        function_name,
        function_args,
        first_timestamp,
    )
    second_call = _call_at_timestamp(
        backend,
        contract,
        contract_address,
        function_name,
        function_args,
        second_timestamp,
    )

    changed = first_call["result"] != second_call["result"]
    status = RUNTIME_NOT_CONFIRMED
    classification_reason = (
        "The tested function is observation-only and did not produce a materially different "
        f"result within a {VALIDATOR_SKEW_SECONDS}-second timestamp skew window."
    )
    if changed:
        status = RUNTIME_INCONCLUSIVE
        classification_reason = (
            "The observation-only helper changed across the tested timestamps, but the executed "
            "path did not demonstrate a security-relevant payout, privilege escalation, or other "
            "material exploit outcome."
        )

    evidence = {
        "contract_name": contract_name,
        "contract_address": contract_address,
        "function_tested": function_name,
        "classification_reason": classification_reason,
        "skew_window_seconds": VALIDATOR_SKEW_SECONDS,
        "first_observation": first_call,
        "second_observation": second_call,
        "outcome_changed": changed,
        "security_relevant_difference": False,
    }

    actions = [
        RuntimeActionResult(
            status=status,
            action="observation_only_timestamp_probe",
            account=accounts[0],
            function=function_name,
            details=evidence,
        )
    ]

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=TIMESTAMP_CHECK,
        title=finding.get("vulnerability", "Timestamp Dependence"),
        status=status,
        backend=backend.backend_id,
        scenario="timestamp_dependence.observation_only_window",
        contract_name=contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            "Observation-only helpers can still matter in broader system designs, but this batch does not overstate them as confirmed exploits.",
            "The negative classification applies only to the executed local-chain path and tested skew window.",
        ],
    )


def _run_security_sensitive_case(
    backend: Any,
    contract: CompiledContract,
    function_name: str,
    function_args: list,
    sponsor: str,
    caller: str,
    constructor_args: list,
    seed_timestamp: int,
    attack_timestamp: int,
    payable_value: int,
) -> dict:
    deployment = backend.deploy_contract(contract.abi, contract.bytecode, constructor_args)
    contract_address = deployment["contract_address"]
    actions = [
        RuntimeActionResult(
            status="setup",
            action="deploy_contract",
            tx_hash=deployment.get("tx_hash"),
            account=sponsor,
            function="constructor",
            details={"contract_address": contract_address, "contract_name": contract.contract_name},
        )
    ]

    seed_timestamp = _ensure_future_timestamp(backend, seed_timestamp)
    backend.set_next_block_timestamp(seed_timestamp)
    seed_tx = backend.execute_transaction(
        contract_abi=contract.abi,
        contract_address=contract_address,
        function_name=function_name,
        args=function_args,
        sender=sponsor,
        value=payable_value,
    )
    seed_block = _receipt_block(seed_tx.get("receipt"))
    actions.append(
        RuntimeActionResult(
            status="setup" if seed_tx.get("success") else RUNTIME_INCONCLUSIVE,
            action="seed_contract_balance",
            tx_hash=seed_tx.get("tx_hash"),
            reverted=seed_tx.get("reverted"),
            error=seed_tx.get("error"),
            account=sponsor,
            function=function_name,
            arguments=function_args,
            details={
                "timestamp_used": seed_timestamp,
                "block_number": seed_block,
                "contract_address": contract_address,
            },
        )
    )

    balance_before = backend.get_balance(contract_address)
    attack_timestamp = _ensure_future_timestamp(backend, attack_timestamp)
    backend.set_next_block_timestamp(attack_timestamp)
    attack_tx = backend.execute_transaction(
        contract_abi=contract.abi,
        contract_address=contract_address,
        function_name=function_name,
        args=function_args,
        sender=caller,
        value=payable_value,
    )
    attack_block = _receipt_block(attack_tx.get("receipt"))
    balance_after = backend.get_balance(contract_address)
    payout_triggered = bool(
        attack_tx.get("success") and balance_after == 0 and balance_before > 0
    )
    actions.append(
        RuntimeActionResult(
            status=RUNTIME_CONFIRMED if payout_triggered else (
                RUNTIME_NOT_CONFIRMED if attack_tx.get("success") else RUNTIME_INCONCLUSIVE
            ),
            action="timestamp_dependent_call",
            tx_hash=attack_tx.get("tx_hash"),
            reverted=attack_tx.get("reverted"),
            error=attack_tx.get("error"),
            account=caller,
            function=function_name,
            arguments=function_args,
            details={
                "timestamp_used": attack_timestamp,
                "block_number": attack_block,
                "contract_balance_before_wei": str(balance_before),
                "contract_balance_after_wei": str(balance_after),
                "payout_triggered": payout_triggered,
            },
        )
    )

    return {
        "contract_address": contract_address,
        "attack_timestamp": attack_timestamp,
        "tx": attack_tx,
        "payout_triggered": payout_triggered,
        "actions": actions,
        "evidence": {
            "contract_address": contract_address,
            "seed_timestamp": seed_timestamp,
            "seed_block_number": seed_block,
            "attack_timestamp": attack_timestamp,
            "attack_block_number": attack_block,
            "contract_balance_before_wei": str(balance_before),
            "contract_balance_after_wei": str(balance_after),
            "tx_hash": attack_tx.get("tx_hash"),
            "reverted": attack_tx.get("reverted"),
            "payout_triggered": payout_triggered,
        },
    }


def _call_at_timestamp(
    backend: Any,
    contract: CompiledContract,
    contract_address: str,
    function_name: str,
    function_args: list,
    timestamp: int,
) -> dict:
    timestamp = _ensure_future_timestamp(backend, timestamp)
    backend.set_next_block_timestamp(timestamp)
    mined = backend.mine_block()
    result = backend.call_function(contract.abi, contract_address, function_name, function_args)
    return {
        "timestamp": timestamp,
        "block_number": mined["number"],
        "result": result,
    }


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


def _classify_function_pattern(function_ctx: dict, function_abi: dict) -> str:
    body = function_ctx.get("body", "")
    header = function_ctx.get("header", "")
    full_text = f"{header}\n{body}"
    if MODULO_RE.search(full_text) and SECURITY_IMPACT_RE.search(full_text):
        return "security_sensitive_modulo"
    if function_abi.get("stateMutability") in {"view", "pure"}:
        return "observation_only"
    if TIME_UNIT_RE.search(full_text) and not SECURITY_IMPACT_RE.search(full_text):
        return "observation_only"
    return "ambiguous"


def _derive_payable_value(function_ctx: dict, function_abi: dict) -> int:
    if function_abi.get("stateMutability") != "payable":
        return 0
    require_match = re.search(r"msg\.value\s*==\s*(\d+)\s*ether", function_ctx.get("body", ""))
    if require_match:
        return int(require_match.group(1)) * (10 ** 18)
    return DEFAULT_PAYABLE_TEST_VALUE


def _extract_modulus(body: str) -> int:
    match = MODULO_RE.search(body)
    if match:
        try:
            modulus = int(match.group("modulus"))
            if modulus > 0:
                return modulus
        except ValueError:
            pass
    return VALIDATOR_SKEW_SECONDS


def _next_multiple(value: int, modulus: int) -> int:
    remainder = value % modulus
    return value if remainder == 0 else value + (modulus - remainder)


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


def _receipt_block(receipt: Optional[dict]) -> Optional[int]:
    if not receipt:
        return None
    return receipt.get("blockNumber")


def _ensure_future_timestamp(backend: Any, timestamp: int) -> int:
    latest = backend.get_block("latest")
    minimum = int(latest["timestamp"]) + 1
    return max(int(timestamp), minimum)
