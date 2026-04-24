"""
Aegis — Smart Contract Vulnerability Scanner
engine.py: Orchestrates all vulnerability detectors and aggregates findings.
"""

from scanner import parser
from scanner.finding import normalize_finding, summarize_findings
from scanner.detectors import (
    reentrancy, integer_overflow, tx_origin,
    selfdestruct, weak_randomness, unchecked_calls,
    delegatecall, access_control, timestamp_dependence
)


# Severity weights for overall risk score calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 5,
    "INFO": 1,
}

RISK_THRESHOLDS = {
    "CRITICAL": 40,
    "HIGH": 20,
    "MEDIUM": 10,
    "LOW": 1,
}


def scan(source_code: str, filename: str = "contract.sol") -> dict:
    """
    Main entry point. Takes raw Solidity source code, runs all detectors,
    and returns a structured scan result dict.
    """
    # Step 1: Parse the contract
    parsed = parser.parse(source_code)

    if not parsed["is_valid"]:
        return {
            "success": False,
            "error": parsed["error"],
            "filename": filename,
            "findings": [],
            "total_issues": 0,
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "pragma_version": None,
        }

    # Step 2: Run all detectors
    detector_runs = [
        ("reentrancy", reentrancy.detect(parsed)),
        ("integer_overflow", integer_overflow.detect(parsed)),
        ("tx_origin", tx_origin.detect(parsed)),
        ("selfdestruct", selfdestruct.detect(parsed)),
        ("weak_randomness", weak_randomness.detect(parsed)),
        ("unchecked_calls", unchecked_calls.detect(parsed)),
        ("delegatecall", delegatecall.detect(parsed)),
        ("access_control", access_control.detect(parsed)),
        ("timestamp_dependence", timestamp_dependence.detect(parsed)),
    ]

    all_findings = []
    for detector_key, findings in detector_runs:
        all_findings.extend(
            normalize_finding(detector_key, finding, filename)
            for finding in findings
        )

    # Step 3: Sort findings by severity (most critical first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    # Step 4: Calculate overall risk score and level
    risk_score = sum(
        SEVERITY_WEIGHTS.get(f["severity"], 0) for f in all_findings
    )
    risk_level = _calculate_risk_level(risk_score)

    return {
        "success": True,
        "error": None,
        "filename": filename,
        "findings": all_findings,
        "total_issues": len(all_findings),
        "risk_level": risk_level,
        "risk_score": risk_score,
        "pragma_version": parsed.get("pragma_version"),
        "has_overflow_protection": parsed.get("has_overflow_protection", False),
        "line_count": len(parsed["lines"]),
        "analysis_summary": summarize_findings(all_findings),
    }


def _calculate_risk_level(score: int) -> str:
    """Maps numeric score to a risk level label."""
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        return "CRITICAL"
    elif score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"
    elif score >= RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    elif score >= RISK_THRESHOLDS["LOW"]:
        return "LOW"
    else:
        return "SAFE"
