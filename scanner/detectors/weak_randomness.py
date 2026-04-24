"""
Aegis weak randomness detector.

Flags block-derived values used as randomness-like inputs and, when the
lightweight parser has function context, records contract/function scope so
runtime validation can target the relevant callable path.
"""

import re

from scanner.detectors.common import function_snippet, get_code_snippet


WEAK_SOURCES = [
    (
        r"\bblock\.timestamp\b",
        "block.timestamp",
        "Validators can slightly influence block timestamps. It should never be used as a randomness source.",
    ),
    (
        r"\bblock\.number\b",
        "block.number",
        "Block numbers are predictable and publicly known. Using them as randomness allows attackers to predict outcomes.",
    ),
    (
        r"\bblockhash\s*\(",
        "blockhash()",
        "blockhash() only works for recent blocks and is predictable or known around inclusion time.",
    ),
    (
        r"\bblock\.difficulty\b",
        "block.difficulty",
        "block.difficulty, or block.prevrandao post-Merge, should not be used as a sole randomness source.",
    ),
    (
        r"\bblock\.coinbase\b",
        "block.coinbase",
        "block.coinbase is known before the block is mined and must not be used for randomness.",
    ),
]

RANDOMNESS_CONTEXT_RE = re.compile(
    r"\b(block\.timestamp|block\.number|block\.difficulty|block\.coinbase|blockhash\s*\()"
)
SECURITY_IMPACT_RE = re.compile(
    r"\b(winner|lottery|prize|payout|reward|mint|trait|random|draw|pick|transfer|call)\b",
    re.IGNORECASE,
)


def detect(parsed: dict) -> list:
    findings = []
    lines = parsed["lines"]
    context = parsed.get("analysis_context", {})
    functions = context.get("functions", [])
    seen_lines = set()

    if functions:
        for function in functions:
            for line_num, _line_content, source_name, explanation in _find_weak_source_lines(function, lines):
                if line_num in seen_lines:
                    continue
                seen_lines.add(line_num)
                severity, confidence = _classify_randomness_risk(function, source_name)
                findings.append(
                    _build_finding(
                        parsed,
                        line_num,
                        source_name,
                        explanation,
                        severity,
                        confidence,
                        function=function,
                    )
                )
        return findings

    for line_num, line_content in lines:
        stripped = line_content.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue

        for pattern, source_name, explanation in WEAK_SOURCES:
            if re.search(pattern, line_content):
                if line_num not in seen_lines:
                    seen_lines.add(line_num)
                    findings.append(
                        _build_finding(
                            parsed,
                            line_num,
                            source_name,
                            explanation,
                            "MEDIUM",
                            "MEDIUM",
                        )
                    )
                break

    return findings


def _find_weak_source_lines(function: dict, lines: list) -> list:
    matches = []
    for line_num, line_content in lines[function["start_line"] - 1:function["end_line"]]:
        stripped = line_content.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for pattern, source_name, explanation in WEAK_SOURCES:
            if re.search(pattern, line_content):
                matches.append((line_num, line_content, source_name, explanation))
                break
    return matches


def _classify_randomness_risk(function: dict, source_name: str) -> tuple[str, str]:
    text = f"{function.get('header', '')}\n{function.get('body', '')}"
    if "%" in text and SECURITY_IMPACT_RE.search(text):
        return "MEDIUM", "HIGH"
    if source_name in {"block.timestamp", "block.number", "blockhash()"} and RANDOMNESS_CONTEXT_RE.search(text):
        return "MEDIUM", "MEDIUM"
    return "LOW", "MEDIUM"


def _build_finding(
    parsed: dict,
    line_num: int,
    source_name: str,
    explanation: str,
    severity: str,
    confidence: str,
    *,
    function: dict | None = None,
) -> dict:
    finding = {
        "vulnerability": f"Weak Randomness Source ({source_name})",
        "severity": severity,
        "confidence": confidence,
        "line": line_num,
        "weak_randomness_source": source_name,
        "description": (
            f"{source_name} is used at this line. {explanation} "
            "Contracts using weak randomness for decisions like winner selection, "
            "NFT traits, or game outcomes can be predicted or influenced by validators "
            "or transaction submitters."
        ),
        "fix": (
            "Use a verifiable randomness source such as Chainlink VRF, or use a "
            "commit-reveal scheme when a fully trustless oracle is not available. "
            "Never use block properties as the primary randomness source."
        ),
        "code_snippet": get_code_snippet(parsed["lines"], line_num, context=2),
    }
    if function:
        finding.update(
            {
                "function": function["name"],
                "contract_name": function.get("contract_name"),
                "code_snippet": function_snippet(parsed["lines"], function),
                "evidence_notes": (
                    f"Function '{function['name']}' uses {source_name} in randomness-like logic on line {line_num}."
                ),
            }
        )
    return finding
