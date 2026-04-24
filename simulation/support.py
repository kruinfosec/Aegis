"""Runtime support registry and eligibility helpers for Aegis."""

from __future__ import annotations

from collections import Counter


RUNTIME_SUPPORT = {
    "missing-access-control": {
        "family": "access-control",
        "label": "Access control",
        "scenario": "access_control",
        "status": "supported",
    },
    "reentrancy": {
        "family": "reentrancy",
        "label": "Reentrancy",
        "scenario": "reentrancy",
        "status": "supported",
    },
    "delegatecall-untrusted-target": {
        "family": "delegatecall",
        "label": "Delegatecall",
        "scenario": "delegatecall",
        "status": "supported",
    },
    "integer-overflow": {
        "family": "integer-overflow",
        "label": "Integer overflow / arithmetic overflow",
        "scenario": "integer_overflow",
        "status": "supported",
        "caveat": "Public Solidity 0.6 fixtures may fail the current local compiler path before scenario execution.",
    },
    "timestamp-dependence": {
        "family": "timestamp-dependence",
        "label": "Timestamp dependence",
        "scenario": "timestamp_dependence",
        "status": "supported",
    },
    "predictable-randomness": {
        "family": "weak-randomness",
        "label": "Weak randomness",
        "scenario": "weak_randomness",
        "status": "supported",
    },
}


def supported_checks() -> set[str]:
    return set(RUNTIME_SUPPORT)


def support_matrix() -> list[dict]:
    return [
        {"check": check, **meta}
        for check, meta in sorted(RUNTIME_SUPPORT.items(), key=lambda item: item[1]["family"])
    ]


def supported_family_labels() -> str:
    labels = [item["label"] for item in support_matrix()]
    return ", ".join(labels)


def analyze_runtime_eligibility(findings: list[dict]) -> dict:
    checks = [finding.get("check") or "missing-check" for finding in findings]
    check_counts = dict(Counter(checks))
    supported = supported_checks()
    eligible = [finding for finding in findings if finding.get("check") in supported]
    unsupported = [finding for finding in findings if finding.get("check") not in supported]
    return {
        "total_findings": len(findings),
        "found_checks": sorted(check_counts),
        "found_check_counts": check_counts,
        "supported_checks": sorted(supported),
        "supported_families": sorted({meta["family"] for meta in RUNTIME_SUPPORT.values()}),
        "eligible_count": len(eligible),
        "unsupported_count": len(unsupported),
        "eligible_findings": [_finding_brief(finding) for finding in eligible],
        "unsupported_findings": [_finding_brief(finding) for finding in unsupported],
    }


def finding_filter_summary(eligibility: dict) -> str:
    if eligibility["total_findings"] == 0:
        return "Runtime validation skipped: no findings were supplied."
    if eligibility["eligible_count"] == 0:
        found = ", ".join(eligibility["found_checks"]) or "none"
        supported = ", ".join(eligibility["supported_checks"])
        return (
            "Runtime validation skipped: none of the static findings are currently "
            f"runtime-supported. Found checks: {found}. Supported checks: {supported}."
        )
    return (
        f"Runtime eligibility: {eligibility['eligible_count']} of "
        f"{eligibility['total_findings']} finding(s) match a runtime-supported check."
    )


def _finding_brief(finding: dict) -> dict:
    return {
        "id": finding.get("id"),
        "check": finding.get("check"),
        "title": finding.get("title") or finding.get("vulnerability"),
        "contract_name": finding.get("contract_name"),
        "function": finding.get("function"),
        "line": finding.get("line"),
    }
