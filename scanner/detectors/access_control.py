"""
Aegis access control detector.

This detector focuses on privileged functions that appear externally reachable
and lack recognizable authorization checks.
"""

from scanner.detectors.common import (
    function_snippet,
    is_likely_sensitive_function,
)


def detect(parsed: dict) -> list:
    findings = []
    context = parsed.get("analysis_context", {})
    functions = context.get("functions", [])
    lines = parsed["lines"]

    for function in functions:
        if function.get("kind") != "function":
            continue
        if function.get("visibility") not in {"public", "external", ""}:
            continue
        if not is_likely_sensitive_function(function):
            continue
        if function.get("has_auth"):
            continue

        function_name = function["name"]
        severity = "CRITICAL" if function_name.lower() in {"kill", "destroy"} else "HIGH"
        confidence = "HIGH" if function_name.lower() in {"mint", "transferownership", "setowner", "kill", "destroy"} else "MEDIUM"
        findings.append(
            {
                "vulnerability": f"Missing Access Control in {function_name}()",
                "severity": severity,
                "confidence": confidence,
                "function": function_name,
                "contract_name": function.get("contract_name"),
                "line": function["start_line"],
                "description": (
                    f"Function '{function_name}' appears to perform privileged or security-sensitive "
                    "behavior but Aegis did not find a recognized access control modifier or inline "
                    "authorization check."
                ),
                "impact": (
                    "An arbitrary caller may be able to invoke a privileged function and change "
                    "ownership, mint value, upgrade logic, or destroy the contract."
                ),
                "exploit_path": (
                    f"An external user calls '{function_name}()' directly because the function is "
                    "externally reachable and no visible authorization gate was detected."
                ),
                "fix": (
                    "Protect the function with a well-defined authorization mechanism such as "
                    "onlyOwner, onlyRole, or an explicit require(msg.sender == owner) check."
                ),
                "remediation": (
                    "Restrict privileged functions with a standard modifier and keep access checks "
                    "close to the function entry point for easier review."
                ),
                "limitations": [
                    "Aegis recognizes common modifier and require-style authorization patterns only.",
                    "Custom authorization implemented through internal helper calls may not be detected.",
                ],
                "evidence_notes": (
                    f"Sensitive function '{function_name}' is {function.get('visibility') or 'externally'} "
                    "reachable and no recognized access-control pattern was found."
                ),
                "code_snippet": function_snippet(lines, function),
            }
        )

    return findings
