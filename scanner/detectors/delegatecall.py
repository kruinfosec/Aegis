"""
Aegis delegatecall detector.

This detector distinguishes between:
  - delegatecall exists,
  - delegatecall target appears user-controlled,
  - delegatecall may be partially constrained by access control.
"""

from scanner.detectors.common import (
    classify_delegatecall_target,
    function_has_auth,
    function_snippet,
)


def detect(parsed: dict) -> list:
    findings = []
    context = parsed.get("analysis_context", {})
    functions = context.get("functions", [])
    lines = parsed["lines"]

    for function in functions:
        if function.get("kind") != "function":
            continue

        delegate_calls = [
            call for call in function.get("external_calls", [])
            if call["kind"] == "delegatecall"
        ]
        if not delegate_calls:
            continue

        has_auth = function_has_auth(function)
        for call in delegate_calls:
            target_info = classify_delegatecall_target(function, call)
            classification = target_info["classification"]

            if classification in {"hardcoded", "self"} and has_auth:
                continue

            severity = target_info["severity"]
            confidence = target_info["confidence"]
            vulnerability = "Delegatecall to Untrusted Contract"
            if classification == "storage-controlled" and has_auth:
                vulnerability = "Delegatecall Review Required"
                severity = "MEDIUM"
                confidence = "MEDIUM"
            elif classification == "unknown":
                vulnerability = "Potentially Risky Delegatecall Usage"
            elif classification == "user-controlled" and not has_auth:
                severity = "HIGH"
                confidence = "HIGH"

            findings.append(
                {
                    "vulnerability": vulnerability,
                    "severity": severity,
                    "confidence": confidence,
                    "function": function["name"],
                    "contract_name": function.get("contract_name"),
                    "line": call["line"],
                    "description": (
                        f"Function '{function['name']}' performs delegatecall and the target "
                        f"appears {classification.replace('-', ' ')}. {target_info['notes']}"
                    ),
                    "impact": (
                        "delegatecall executes foreign code in the storage context of the current "
                        "contract, which can alter ownership, balances, or implementation state."
                    ),
                    "exploit_path": (
                        "An attacker influences the delegatecall target or delegatecall payload so "
                        "malicious code runs with this contract's storage and privileges."
                    ),
                    "fix": (
                        "Use delegatecall only in well-reviewed upgrade/proxy patterns. Restrict "
                        "who can trigger it, constrain the target, and validate upgrade paths."
                    ),
                    "remediation": (
                        "Prefer trusted implementation addresses, explicit admin gating, and separate "
                        "upgrade logic from arbitrary user-triggered delegate execution."
                    ),
                    "limitations": [
                        "Aegis infers target controllability from source structure rather than full data flow.",
                        "Proxy patterns may be intentional, but still require careful review.",
                    ],
                    "evidence_notes": (
                        f"delegatecall target '{call['target']}' in function '{function['name']}' "
                        f"was classified as {classification}."
                        + (" The function appears authorization-gated." if has_auth else " No clear authorization gate was detected.")
                    ),
                    "code_snippet": function_snippet(lines, function),
                }
            )

    return findings
