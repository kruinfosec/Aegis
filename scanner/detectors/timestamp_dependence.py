import re

from scanner.detectors.common import function_snippet, get_code_snippet


TIMESTAMP_CONTROL_FLOW_RE = re.compile(
    r"(require|if|while)\s*\([^;]*\b(block\.timestamp|now)\b[^;]*\)"
)
TIMESTAMP_RANDOMNESS_RE = re.compile(
    r"\b(block\.timestamp|now)\b\s*%\s*\d+|\b(block\.timestamp|now)\b\s*(==|!=|<=|>=|<|>)"
)
VALUE_IMPACT_RE = re.compile(
    r"\b(transfer|send|call)\b|\bwinner\b|\bpayout\b|\breward\b",
    re.IGNORECASE,
)


def detect(parsed: dict) -> list:
    findings = []
    lines = parsed["lines"]
    context = parsed.get("analysis_context", {})
    functions = context.get("functions", [])

    if functions:
        for function in functions:
            matches = _find_timestamp_lines(function, lines)
            for line_num, line_content in matches:
                severity, confidence = _classify_timestamp_risk(function, line_content)
                findings.append(
                    {
                        "vulnerability": "Timestamp Dependence",
                        "severity": severity,
                        "confidence": confidence,
                        "function": function["name"],
                        "contract_name": function.get("contract_name"),
                        "line": line_num,
                        "description": (
                            "The contract uses 'block.timestamp' or 'now' in control flow. "
                            "Validators can influence timestamps within a limited skew window, "
                            "which can bias fine-grained gates, payouts, or randomness-like logic."
                        ),
                        "fix": (
                            "Avoid using block.timestamp for fine-grained security decisions or "
                            "randomness. Long scheduling windows may be acceptable, but payouts, "
                            "winner selection, and narrow equality thresholds should not depend on it."
                        ),
                        "limitations": [
                            "Long-duration scheduling checks may be acceptable depending on contract intent.",
                            "This detector is source-based and does not prove that a timestamp-controlled path is exploitable.",
                        ],
                        "evidence_notes": (
                            f"Function '{function['name']}' uses block.timestamp/now in control flow on line "
                            f"{line_num}."
                        ),
                        "code_snippet": function_snippet(lines, function),
                    }
                )
        return findings

    for line_num, line_content in lines:
        stripped = line_content.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if TIMESTAMP_CONTROL_FLOW_RE.search(line_content):
            severity, confidence = _classify_timestamp_risk(None, line_content)
            findings.append(
                {
                    "vulnerability": "Timestamp Dependence",
                    "severity": severity,
                    "confidence": confidence,
                    "line": line_num,
                    "description": (
                        "The contract uses 'block.timestamp' or 'now' in control flow. "
                        "Validators can influence timestamps within a limited skew window, "
                        "which can bias fine-grained gates, payouts, or randomness-like logic."
                    ),
                    "fix": (
                        "Avoid using block.timestamp for fine-grained security decisions or "
                        "randomness. Long scheduling windows may be acceptable, but payouts, "
                        "winner selection, and narrow equality thresholds should not depend on it."
                    ),
                    "code_snippet": get_code_snippet(lines, line_num, context=2),
                }
            )

    return findings


def _find_timestamp_lines(function: dict, lines: list) -> list:
    matches = []
    for line_num, line_content in lines[function["start_line"] - 1:function["end_line"]]:
        stripped = line_content.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if TIMESTAMP_CONTROL_FLOW_RE.search(line_content):
            matches.append((line_num, line_content))
    return matches


def _classify_timestamp_risk(function: dict | None, line_content: str) -> tuple[str, str]:
    candidate_text = line_content
    if function:
        candidate_text = f"{function.get('header', '')}\n{function.get('body', '')}"

    if TIMESTAMP_RANDOMNESS_RE.search(candidate_text) and VALUE_IMPACT_RE.search(candidate_text):
        return "MEDIUM", "HIGH"
    if TIMESTAMP_RANDOMNESS_RE.search(candidate_text):
        return "MEDIUM", "MEDIUM"
    return "LOW", "MEDIUM"
