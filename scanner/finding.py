"""
Structured finding helpers for Aegis.

This module normalizes detector output into a richer, explicit schema so that
reports can distinguish:
  - what was observed,
  - how confident the tool is,
  - what the likely impact is,
  - what still remains unverified.

The design is conceptually informed by mature issue/report models used in
open-source tools such as Mythril, but is intentionally much simpler and
tailored to Aegis's current architecture.
"""

from copy import deepcopy


RUNTIME_TO_DYNAMIC_VERIFICATION = {
    "confirmed_by_runtime": "CONFIRMED",
    "not_confirmed_by_runtime": "NOT_CONFIRMED",
    "inconclusive_runtime": "INCONCLUSIVE",
    "simulation_unsupported": "UNSUPPORTED",
    "simulation_failed": "FAILED",
}

RUNTIME_TO_EXPLOITABILITY = {
    "confirmed_by_runtime": "CONFIRMED_BY_RUNTIME",
    "not_confirmed_by_runtime": "NOT_CONFIRMED_BY_RUNTIME",
    "inconclusive_runtime": "INCONCLUSIVE_RUNTIME",
    "simulation_unsupported": "UNVERIFIED",
    "simulation_failed": "UNVERIFIED",
}

RUNTIME_STATUS_NOTES = {
    "confirmed_by_runtime": "Runtime validation executed a supporting scenario and observed behavior consistent with the finding.",
    "not_confirmed_by_runtime": "Runtime validation executed the tested scenario, but the unauthorized or risky action reverted or failed.",
    "inconclusive_runtime": "Runtime validation executed but did not produce a decisive result for the tested scenario.",
    "simulation_unsupported": "Runtime validation could not fully exercise this finding with the currently supported scenario set.",
    "simulation_failed": "Runtime validation attempted to run but failed before producing reliable evidence.",
}


DETECTOR_METADATA = {
    "reentrancy": {
        "detector_id": "aegis.reentrancy",
        "check": "reentrancy",
        "swc_id": "SWC-107",
        "analysis_kind": "static-heuristic",
        "confidence": "medium",
        "impact": (
            "If an attacker can re-enter before state is finalized, contract funds "
            "or accounting invariants may be drained or corrupted."
        ),
        "exploit_path": (
            "Attacker triggers an external call and re-enters the vulnerable "
            "function before balances or state are safely updated."
        ),
        "limitations": [
            "This result is based on source heuristics, not full control-flow analysis.",
            "Reentrancy guards or surrounding logic may reduce exploitability.",
        ],
    },
    "integer_overflow": {
        "detector_id": "aegis.integer_overflow",
        "check": "integer-overflow",
        "swc_id": "SWC-101",
        "analysis_kind": "static-heuristic",
        "confidence": "medium",
        "impact": (
            "Arithmetic wraparound can corrupt balances, counters, or supply values "
            "and may let attackers mint or transfer unintended value."
        ),
        "exploit_path": (
            "An attacker reaches arithmetic on legacy Solidity integer types "
            "without built-in overflow checks or SafeMath protections."
        ),
        "limitations": [
            "The detector does not model full data flow or all safe arithmetic wrappers.",
            "Some flagged arithmetic may be unreachable or otherwise constrained.",
        ],
    },
    "tx_origin": {
        "detector_id": "aegis.tx_origin",
        "check": "tx-origin-auth",
        "swc_id": "SWC-115",
        "analysis_kind": "static-heuristic",
        "confidence": "high",
        "impact": (
            "Authorization based on tx.origin can allow phishing-style call chains "
            "that execute privileged actions through attacker-controlled contracts."
        ),
        "exploit_path": (
            "Attacker tricks a privileged user into calling an intermediary "
            "contract, which then calls the vulnerable contract while tx.origin "
            "still resolves to the victim."
        ),
        "limitations": [
            "The detector does not prove the surrounding authorization path is reachable.",
            "Some tx.origin usage may be intentional for anti-contract gating, though that pattern is discouraged.",
        ],
    },
    "selfdestruct": {
        "detector_id": "aegis.selfdestruct",
        "check": "unprotected-selfdestruct",
        "swc_id": "SWC-106",
        "analysis_kind": "static-heuristic",
        "confidence": "high",
        "impact": (
            "An unprotected selfdestruct path can permanently destroy contract code "
            "and redirect remaining ETH."
        ),
        "exploit_path": (
            "Attacker calls a kill or destroy path that reaches selfdestruct "
            "without effective access control."
        ),
        "limitations": [
            "The detector infers access control from common patterns and may miss custom authorization logic.",
            "It does not prove a caller can satisfy every path condition in production.",
        ],
    },
    "weak_randomness": {
        "detector_id": "aegis.weak_randomness",
        "check": "predictable-randomness",
        "swc_id": "SWC-120",
        "analysis_kind": "static-heuristic",
        "confidence": "medium",
        "impact": (
            "Predictable on-chain values can let validators or users influence "
            "lotteries, game outcomes, or trait assignment."
        ),
        "exploit_path": (
            "Attacker predicts or biases outcomes derived from block metadata "
            "instead of secure randomness."
        ),
        "limitations": [
            "The detector flags weak randomness sources even when the business impact is low.",
            "It does not quantify economic exploitability or market conditions.",
        ],
    },
    "unchecked_calls": {
        "detector_id": "aegis.unchecked_calls",
        "check": "unchecked-low-level-call",
        "swc_id": "SWC-104",
        "analysis_kind": "static-heuristic",
        "confidence": "high",
        "impact": (
            "Ignoring low-level call results can hide transfer failures or failed "
            "external interactions, causing inconsistent state or bypassed logic."
        ),
        "exploit_path": (
            "A low-level call fails, but execution continues because the boolean "
            "success value is never checked."
        ),
        "limitations": [
            "The detector is line-based and may miss multi-line result handling.",
            "Some call patterns are intentionally fire-and-forget, though they should still be reviewed carefully.",
        ],
    },
    "delegatecall": {
        "detector_id": "aegis.delegatecall",
        "check": "delegatecall-untrusted-target",
        "swc_id": "SWC-112",
        "analysis_kind": "static-heuristic",
        "confidence": "medium",
        "impact": (
            "delegatecall into attacker-controlled code can overwrite storage, "
            "change ownership, or execute arbitrary logic in the caller context."
        ),
        "exploit_path": (
            "Attacker influences the delegatecall target or payload so malicious "
            "code executes with the calling contract's storage and privileges."
        ),
        "limitations": [
            "The detector currently flags delegatecall usage conservatively.",
            "It does not yet prove target controllability or storage corruption end-to-end.",
        ],
    },
    "access_control": {
        "detector_id": "aegis.access_control",
        "check": "missing-access-control",
        "swc_id": "SWC-105",
        "analysis_kind": "static-heuristic",
        "confidence": "medium",
        "impact": (
            "Privileged state changes without authorization checks can let any "
            "caller mint, transfer ownership, destroy contracts, or drain funds."
        ),
        "exploit_path": (
            "Attacker directly calls a sensitive function that lacks a recognized "
            "permission check or restrictive visibility."
        ),
        "limitations": [
            "The detector identifies sensitive functions by name-based heuristics.",
            "Custom authorization schemes may exist outside the function signature line.",
        ],
    },
    "timestamp_dependence": {
        "detector_id": "aegis.timestamp_dependence",
        "check": "timestamp-dependence",
        "swc_id": "SWC-116",
        "analysis_kind": "static-heuristic",
        "confidence": "medium",
        "impact": (
            "Time-sensitive control flow can be biased within validator-controlled "
            "timestamp tolerance, affecting gates, rewards, or randomness."
        ),
        "exploit_path": (
            "An attacker or validator benefits when contract control flow depends "
            "on block.timestamp or now at fine-grained thresholds."
        ),
        "limitations": [
            "Long-duration time checks may be acceptable depending on the use case.",
            "The detector does not distinguish harmless scheduling from exploitable edge thresholds.",
        ],
    },
}


def normalize_finding(detector_key: str, raw_finding: dict, filename: str) -> dict:
    """
    Normalize a legacy detector finding into Aegis's richer report schema.
    """
    meta = deepcopy(DETECTOR_METADATA[detector_key])
    line = raw_finding.get("line")
    snippet = raw_finding.get("code_snippet")

    structured = {
        "id": f"{meta['detector_id']}:{filename}:{line}:{raw_finding.get('vulnerability', 'finding')}",
        "title": raw_finding.get("vulnerability", "Security Finding"),
        "vulnerability": raw_finding.get("vulnerability", "Security Finding"),
        "function": raw_finding.get("function"),
        "contract_name": raw_finding.get("contract_name"),
        "severity": raw_finding.get("severity", "INFO"),
        "confidence": raw_finding.get("confidence", meta["confidence"]).upper(),
        "swc_id": raw_finding.get("swc_id", meta["swc_id"]),
        "detector_id": meta["detector_id"],
        "check": meta["check"],
        "analysis_kind": raw_finding.get("analysis_kind", meta["analysis_kind"]),
        "line": line,
        "description": raw_finding.get("description", ""),
        "fix": raw_finding.get("fix", ""),
        "impact": raw_finding.get("impact", meta["impact"]),
        "exploit_path": raw_finding.get("exploit_path", meta["exploit_path"]),
        "remediation": raw_finding.get("remediation", raw_finding.get("fix", "")),
        "limitations": raw_finding.get("limitations", meta["limitations"]),
        "exploitability": raw_finding.get("exploitability", "UNVERIFIED"),
        "evidence": {
            "type": "source-pattern",
            "line": line,
            "function": raw_finding.get("function"),
            "contract_name": raw_finding.get("contract_name"),
            "snippet": snippet,
            "notes": raw_finding.get(
                "evidence_notes",
                "Derived from static source analysis heuristics.",
            ),
        },
        "verification": {
            "static": "FLAGGED",
            "dynamic": "NOT_RUN",
        },
        "code_snippet": snippet,
        "runtime_validation_status": "NOT_RUN",
        "runtime_backend": None,
        "runtime_scenario": None,
        "runtime_evidence": None,
        "validation_notes": [],
    }

    if "references" in raw_finding:
        structured["references"] = raw_finding["references"]
    if "weak_randomness_source" in raw_finding:
        structured["weak_randomness_source"] = raw_finding["weak_randomness_source"]
        structured["evidence"]["weak_randomness_source"] = raw_finding["weak_randomness_source"]

    return structured


def summarize_findings(findings: list) -> dict:
    """
    Build high-level analysis summary metadata for reporting.
    """
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for finding in findings:
        severity = finding.get("severity", "INFO")
        confidence = finding.get("confidence", "LOW")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

    return {
        "severity_counts": severity_counts,
        "confidence_counts": confidence_counts,
        "verified_findings": sum(
            1
            for finding in findings
            if finding.get("verification", {}).get("dynamic") == "CONFIRMED"
        ),
        "unverified_findings": sum(
            1
            for finding in findings
            if finding.get("verification", {}).get("dynamic") != "CONFIRMED"
        ),
    }


def merge_runtime_validations(findings: list, runtime_result: dict) -> list:
    """
    Enrich findings with runtime-validation results without overwriting static context.
    """
    validations = {
        validation.get("finding_id"): validation
        for validation in runtime_result.get("validations", [])
        if validation.get("finding_id")
    }

    merged = []
    for finding in findings:
        enriched = deepcopy(finding)
        validation = validations.get(enriched.get("id"))
        if not validation:
            merged.append(enriched)
            continue

        runtime_status = validation.get("status", "simulation_failed")
        enriched["runtime_validation_status"] = runtime_status
        enriched["runtime_backend"] = validation.get("backend")
        enriched["runtime_scenario"] = validation.get("scenario") or validation.get("check")
        enriched["runtime_evidence"] = validation.get("evidence")
        enriched["verification"] = {
            **enriched.get("verification", {}),
            "dynamic": RUNTIME_TO_DYNAMIC_VERIFICATION.get(runtime_status, "FAILED"),
        }
        enriched["exploitability"] = RUNTIME_TO_EXPLOITABILITY.get(
            runtime_status,
            enriched.get("exploitability", "UNVERIFIED"),
        )

        notes = [RUNTIME_STATUS_NOTES.get(runtime_status, "Runtime validation result recorded.")]
        notes.extend(validation.get("limitations", []))
        if validation.get("error"):
            notes.append(str(validation["error"]))
        enriched["validation_notes"] = notes

        merged.append(enriched)

    return merged
