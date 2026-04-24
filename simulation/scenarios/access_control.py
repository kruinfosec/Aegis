"""
Runtime validation scenario for missing access control findings.
"""

from typing import Any, Dict, List, Optional

from simulation.compiler import CompiledContract
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_FAILED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_NOT_CONFIRMED,
    RUNTIME_UNSUPPORTED,
    RuntimeActionResult,
    ValidationRecord,
)


def validate_access_control(findings: list, compiled_contracts: List[CompiledContract], backend) -> List[ValidationRecord]:
    validations = []
    relevant_findings = [finding for finding in findings if finding.get("check") == "missing-access-control"]
    accounts = backend.get_accounts()
    unauthorized = accounts[1] if len(accounts) > 1 else None

    for finding in relevant_findings:
        function_name = finding.get("function") or _extract_function_from_vulnerability(finding.get("vulnerability", ""))
        if not function_name:
            validations.append(
                ValidationRecord(
                    finding_id=finding.get("id"),
                    check="missing-access-control",
                    title=finding.get("vulnerability", "Missing Access Control"),
                    status=RUNTIME_UNSUPPORTED,
                    backend=backend.backend_id,
                    scenario="access_control.unauthorized_privileged_call",
                    error="Function name could not be determined from the static finding.",
                    limitations=["Runtime validation requires a callable function name."],
                )
            )
            continue

        if unauthorized is None:
            validations.append(
                ValidationRecord(
                    finding_id=finding.get("id"),
                    check="missing-access-control",
                    title=finding.get("vulnerability", "Missing Access Control"),
                    status=RUNTIME_FAILED,
                    backend=backend.backend_id,
                    scenario="access_control.unauthorized_privileged_call",
                    function_name=function_name,
                    error="Not enough accounts available for unauthorized-call testing.",
                )
            )
            continue

        candidates = _find_candidates(compiled_contracts, finding, function_name)
        if not candidates:
            validations.append(
                ValidationRecord(
                    finding_id=finding.get("id"),
                    check="missing-access-control",
                    title=finding.get("vulnerability", "Missing Access Control"),
                    status=RUNTIME_UNSUPPORTED,
                    backend=backend.backend_id,
                    scenario="access_control.unauthorized_privileged_call",
                    contract_name=finding.get("contract_name"),
                    function_name=function_name,
                    error="No deployable contract with a matching callable function was compiled.",
                    limitations=["The runtime validator currently supports only direct public/external functions on compiled contracts."],
                )
            )
            continue

        actions = []
        unsupported_reasons = []
        for contract, function_abi in candidates:
            constructor = _constructor_abi(contract.abi)
            constructor_args = [] if not constructor else _build_args(constructor.get("inputs", []), accounts)
            if constructor and constructor_args is None:
                unsupported_reasons.append("Constructor arguments are not yet supported for this contract shape.")
                continue

            function_args = _build_args(function_abi.get("inputs", []), accounts)
            if function_args is None:
                unsupported_reasons.append("Function arguments are not yet supported for this ABI shape.")
                continue

            deployment = backend.deploy_contract(contract.abi, contract.bytecode, constructor_args)
            tx_result = backend.execute_transaction(
                contract_abi=contract.abi,
                contract_address=deployment["contract_address"],
                function_name=function_name,
                args=function_args,
                sender=unauthorized,
            )

            actions.append(
                RuntimeActionResult(
                    status=RUNTIME_CONFIRMED if tx_result.get("success") else (
                        RUNTIME_NOT_CONFIRMED if tx_result.get("reverted") else RUNTIME_INCONCLUSIVE
                    ),
                    action="unauthorized_privileged_call",
                    tx_hash=tx_result.get("tx_hash"),
                    reverted=tx_result.get("reverted"),
                    error=tx_result.get("error"),
                    account=unauthorized,
                    function=function_name,
                    arguments=function_args,
                    details={
                        "candidate_contract": contract.contract_name,
                        "deployment": deployment,
                        "receipt": tx_result.get("receipt"),
                    },
                )
            )

            if finding.get("contract_name") and contract.contract_name == finding.get("contract_name"):
                break

        if not actions:
            validations.append(
                ValidationRecord(
                    finding_id=finding.get("id"),
                    check="missing-access-control",
                    title=finding.get("vulnerability", "Missing Access Control"),
                    status=RUNTIME_UNSUPPORTED,
                    backend=backend.backend_id,
                    scenario="access_control.unauthorized_privileged_call",
                    contract_name=finding.get("contract_name"),
                    function_name=function_name,
                    error="No runtime-executable candidate could be prepared.",
                    limitations=unsupported_reasons or ["No candidate contract/function pair could be executed."],
                )
            )
            continue

        status = _aggregate_action_status(actions, finding.get("contract_name"))
        primary_action = actions[0]
        evidence = {
            "candidate_contracts": [candidate[0].contract_name for candidate in candidates],
            "matched_contract_hint": finding.get("contract_name"),
            "selected_contract": primary_action.details.get("candidate_contract"),
            "contract_address": primary_action.details.get("deployment", {}).get("contract_address"),
            "unauthorized_account": unauthorized,
            "function": function_name,
            "arguments": primary_action.arguments,
            "tx_hash": primary_action.tx_hash,
            "reverted": primary_action.reverted,
        }

        validations.append(
            ValidationRecord(
                finding_id=finding.get("id"),
                check="missing-access-control",
                title=finding.get("vulnerability", "Missing Access Control"),
                status=status,
                backend=backend.backend_id,
                scenario="access_control.unauthorized_privileged_call",
                contract_name=primary_action.details.get("candidate_contract"),
                function_name=function_name,
                evidence=evidence,
                actions=actions,
                limitations=[
                    "This scenario validates a direct unauthorized call only.",
                    "It does not yet test proxy paths, initializer misuse, or internal authorization helpers.",
                    "A result only disproves or confirms the specific executed path, not every possible authorization path.",
                ],
                error=next((action.error for action in actions if action.error), None),
            )
        )

    return validations


def _find_candidates(compiled_contracts: List[CompiledContract], finding: dict, function_name: str):
    candidates = []
    contract_hint = finding.get("contract_name")
    for contract in compiled_contracts:
        if contract_hint and contract.contract_name != contract_hint:
            continue
        for entry in contract.abi:
            if entry.get("type") == "function" and entry.get("name") == function_name:
                candidates.append((contract, entry))
    if candidates:
        return candidates

    for contract in compiled_contracts:
        for entry in contract.abi:
            if entry.get("type") == "function" and entry.get("name") == function_name:
                candidates.append((contract, entry))
    return candidates


def _constructor_abi(abi: list) -> Optional[Dict[str, Any]]:
    for entry in abi:
        if entry.get("type") == "constructor":
            return entry
    return None


def _build_args(inputs: List[Dict[str, Any]], accounts: List[str]) -> Optional[List[Any]]:
    built = []
    for entry in inputs:
        arg = _build_arg(entry.get("type", ""), accounts)
        if arg is None:
            return None
        built.append(arg)
    return built


def _build_arg(arg_type: str, accounts: List[str]) -> Optional[Any]:
    if arg_type.endswith("[]"):
        inner = _build_arg(arg_type[:-2], accounts)
        return None if inner is None else [inner]
    if arg_type == "address":
        return accounts[2] if len(accounts) > 2 else accounts[0]
    if arg_type.startswith("uint") or arg_type.startswith("int"):
        return 1
    if arg_type == "bool":
        return True
    if arg_type == "string":
        return "aegis"
    if arg_type.startswith("bytes"):
        return b""
    return None


def _extract_function_from_vulnerability(vulnerability: str) -> Optional[str]:
    if " in " in vulnerability and vulnerability.endswith("()"):
        return vulnerability.split(" in ", 1)[1][:-2]
    return None


def _aggregate_action_status(actions: List[RuntimeActionResult], contract_hint: Optional[str]) -> str:
    statuses = [action.status for action in actions]
    if contract_hint:
        hinted = [action for action in actions if action.details.get("candidate_contract") == contract_hint]
        if hinted:
            return hinted[0].status
    if any(status == RUNTIME_CONFIRMED for status in statuses):
        return RUNTIME_CONFIRMED
    if all(status == RUNTIME_NOT_CONFIRMED for status in statuses):
        return RUNTIME_NOT_CONFIRMED
    if any(status == RUNTIME_INCONCLUSIVE for status in statuses):
        return RUNTIME_INCONCLUSIVE
    return RUNTIME_UNSUPPORTED
