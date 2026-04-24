"""
Aegis reentrancy detector.

This pass remains source-based, but reasons at function scope using:
  - external call sites,
  - state-update ordering,
  - likely guard modifiers,
  - whether the external interaction appears value-bearing.

The structure is conceptually inspired by the way mature tools separate
"external call exists" from "state changes after external call", but it stays
lightweight and source-centric for Aegis.
"""

from scanner.detectors.common import function_snippet


def detect(parsed: dict) -> list:
    findings = []
    context = parsed.get("analysis_context", {})
    functions = context.get("functions", [])
    lines = parsed["lines"]

    for function in functions:
        if function.get("kind") != "function":
            continue
        if function.get("has_reentrancy_guard"):
            continue

        external_calls = function.get("external_calls", [])
        state_updates = function.get("state_updates", [])
        if not external_calls:
            continue

        risky_calls = [call for call in external_calls if call["kind"] in {"call", "send", "transfer"}]
        if not risky_calls:
            continue

        for call in risky_calls:
            updates_after_call = [
                update for update in state_updates if update["offset"] > call["offset"]
            ]
            updates_before_call = [
                update for update in state_updates if update["offset"] < call["offset"]
            ]
            if updates_after_call:
                severity = "HIGH" if call["sends_value"] else "MEDIUM"
                confidence = "HIGH" if call["target"] in function.get("params", []) or call["sends_value"] else "MEDIUM"
                findings.append(
                    {
                        "vulnerability": "Reentrancy Risk: State Update After External Call",
                        "severity": severity,
                        "confidence": confidence,
                        "function": function["name"],
                        "contract_name": function.get("contract_name"),
                        "line": call["line"],
                        "description": (
                            f"Function '{function['name']}' performs an external {call['kind']} "
                            f"before completing state updates. This violates the usual "
                            "Checks-Effects-Interactions ordering and can expose an intermediate state."
                        ),
                        "impact": (
                            "An attacker may re-enter the function before accounting or state "
                            "changes are finalized, potentially draining value or breaking invariants."
                        ),
                        "exploit_path": (
                            f"Callers reach '{function['name']}', trigger the external {call['kind']}, "
                            "and then re-enter before the later state update executes."
                        ),
                        "fix": (
                            "Move all state updates before the external interaction, and consider "
                            "a reentrancy guard for additional defense."
                        ),
                        "remediation": (
                            "Refactor the function to follow Checks-Effects-Interactions strictly. "
                            "If external calls are unavoidable, update balances and storage first."
                        ),
                        "limitations": [
                            "This is still a source-level heuristic and does not prove a full exploit path.",
                            "Some post-call updates may be harmless bookkeeping depending on surrounding logic.",
                        ],
                        "evidence_notes": (
                            f"Function '{function['name']}' contains an external {call['kind']} on line "
                            f"{call['line']} followed by later state updates on lines "
                            + ", ".join(str(update["line"]) for update in updates_after_call[:3])
                            + "."
                        ),
                        "code_snippet": function_snippet(lines, function),
                    }
                )
                continue

            if not updates_before_call and call["kind"] == "call":
                findings.append(
                    {
                        "vulnerability": "Suspicious External Call With Reentrancy Exposure",
                        "severity": "LOW" if call["unchecked"] else "MEDIUM",
                        "confidence": "LOW",
                        "function": function["name"],
                        "contract_name": function.get("contract_name"),
                        "line": call["line"],
                        "description": (
                            f"Function '{function['name']}' issues an external low-level call "
                            "without clear preceding effects. This is not enough to confirm reentrancy, "
                            "but it deserves review."
                        ),
                        "impact": (
                            "If the function relies on other state not recognized by Aegis, "
                            "re-entry into the same contract could still be unsafe."
                        ),
                        "exploit_path": (
                            "A malicious callee could attempt to call back into the contract while "
                            "execution is still in progress."
                        ),
                        "fix": (
                            "Review whether the call target is trusted, whether state is finalized "
                            "before interaction, and whether a guard is appropriate."
                        ),
                        "remediation": (
                            "Prefer explicit CEI ordering and guard untrusted callbacks with a "
                            "reentrancy lock where the function changes important state."
                        ),
                        "limitations": [
                            "Aegis did not find a clear post-call state update in this function.",
                            "This result is intentionally lower confidence and may be benign.",
                        ],
                        "evidence_notes": (
                            f"Function '{function['name']}' contains a low-level call on line {call['line']} "
                            "but Aegis could not establish sufficient state ordering context."
                        ),
                        "code_snippet": function_snippet(lines, function),
                    }
                )

    return findings
