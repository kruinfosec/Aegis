"""
Aegis — Smart Contract Vulnerability Scanner
report.py: Formats scan engine output for display in templates.
"""

# Maps severity to CSS class names and emoji used in templates
SEVERITY_META = {
    "CRITICAL": {"css": "severity-critical", "icon": "💀", "label": "CRITICAL"},
    "HIGH":     {"css": "severity-high",     "icon": "🔴", "label": "HIGH"},
    "MEDIUM":   {"css": "severity-medium",   "icon": "🟡", "label": "MEDIUM"},
    "LOW":      {"css": "severity-low",      "icon": "🟢", "label": "LOW"},
    "INFO":     {"css": "severity-info",     "icon": "ℹ️", "label": "INFO"},
}

RUNTIME_STATUS_META = {
    "confirmed_by_runtime": {
        "css": "rt-badge-confirmed",
        "label": "Runtime confirmed",
        "short": "Confirmed",
        "tone": "Evidence supports this finding in the tested runtime path.",
    },
    "not_confirmed_by_runtime": {
        "css": "rt-badge-not-confirmed",
        "label": "Runtime not confirmed",
        "short": "Not confirmed",
        "tone": "The tested runtime path did not confirm exploitability.",
    },
    "inconclusive_runtime": {
        "css": "rt-badge-inconclusive",
        "label": "Runtime inconclusive",
        "short": "Inconclusive",
        "tone": "Runtime ran, but the evidence was not decisive.",
    },
    "simulation_unsupported": {
        "css": "rt-badge-unsupported",
        "label": "Runtime unsupported",
        "short": "Unsupported",
        "tone": "Aegis does not yet support this contract shape at runtime.",
    },
    "simulation_failed": {
        "css": "rt-badge-failed",
        "label": "Runtime failed",
        "short": "Failed",
        "tone": "Runtime validation failed before producing reliable evidence.",
    },
    "NOT_RUN": {
        "css": "rt-badge-not-run",
        "label": "Static only",
        "short": "Static only",
        "tone": "Runtime validation was not run for this finding.",
    },
}

RISK_META = {
    "CRITICAL": {"css": "risk-critical", "icon": "💀", "label": "CRITICAL RISK"},
    "HIGH":     {"css": "risk-high",     "icon": "🔴", "label": "HIGH RISK"},
    "MEDIUM":   {"css": "risk-medium",   "icon": "🟡", "label": "MEDIUM RISK"},
    "LOW":      {"css": "risk-low",      "icon": "🟢", "label": "LOW RISK"},
    "SAFE":     {"css": "risk-safe",     "icon": "✅", "label": "SAFE"},
    "UNKNOWN":  {"css": "risk-unknown",  "icon": "❓", "label": "UNKNOWN"},
}


def format_report(scan_result: dict) -> dict:
    """
    Takes the raw scan engine result and enriches it with
    UI-ready metadata (CSS classes, icons) for Jinja2 templates.
    """
    # Enrich each finding with display metadata
    enriched_findings = []
    for finding in scan_result.get("findings", []):
        sev = finding.get("severity", "INFO")
        meta = SEVERITY_META.get(sev, SEVERITY_META["INFO"])
        rt_status = finding.get("runtime_validation_status", "NOT_RUN")
        rt_meta = RUNTIME_STATUS_META.get(rt_status, RUNTIME_STATUS_META["NOT_RUN"])
        enriched_findings.append({
            **finding,
            "severity_css": meta["css"],
            "severity_icon": meta["icon"],
            "severity_label": meta["label"],
            "runtime_status_css": rt_meta["css"],
            "runtime_status_label": rt_meta["label"],
            "runtime_status_short": rt_meta["short"],
            "runtime_status_tone": rt_meta["tone"],
            "scope_label": _scope_label(finding),
            "rationale_preview": _rationale_preview(finding),
            "runtime_evidence_preview": _evidence_preview(finding.get("runtime_evidence")),
            "runtime_evidence_items": _evidence_items(finding.get("runtime_evidence")),
            "static_evidence_preview": _evidence_preview(finding.get("evidence")),
        })

    risk = scan_result.get("risk_level", "UNKNOWN")
    risk_meta = RISK_META.get(risk, RISK_META["UNKNOWN"])
    runtime_correlation = scan_result.get("runtime_correlation") or {}
    simulation = scan_result.get("simulation") or {}
    diagnostics = simulation.get("diagnostics") or scan_result.get("simulation_diagnostics") or {}

    report = {
        **scan_result,
        "findings": enriched_findings,
        "risk_css": risk_meta["css"],
        "risk_icon": risk_meta["icon"],
        "risk_label": risk_meta["label"],
        "severity_counts": scan_result.get("analysis_summary", {}).get("severity_counts", {}),
        "confidence_counts": scan_result.get("analysis_summary", {}).get("confidence_counts", {}),
        "verified_findings": scan_result.get("analysis_summary", {}).get("verified_findings", 0),
        "unverified_findings": scan_result.get("analysis_summary", {}).get("unverified_findings", 0),
        "contract_names": _contract_names(enriched_findings),
        "contracts_count": len(_contract_names(enriched_findings)),
        "runtime_status_counts": _runtime_status_counts(enriched_findings),
        "scan_time_ms": diagnostics.get("total_ms"),
        "runtime_requested": runtime_correlation.get("runtime_requested", False),
        "runtime_executed": runtime_correlation.get("runtime_executed", False),
        "runtime_backend": runtime_correlation.get("backend"),
    }
    return ensure_report_shape(report)


def ensure_report_shape(report: dict | None) -> dict:
    """Return a template-safe report dict.

    ``format_report()`` provides the canonical shape for new scans. This helper
    also protects older/stale session payloads that predate newer UI fields.
    Optional display fields are normalized to safe defaults, while truly absent
    runtime timing remains ``None`` so templates can omit it honestly.
    """
    report = dict(report or {})
    findings = [_ensure_finding_shape(finding) for finding in report.get("findings", [])]
    risk = report.get("risk_level", "UNKNOWN")
    risk_meta = RISK_META.get(risk, RISK_META["UNKNOWN"])
    runtime_correlation = report.get("runtime_correlation") or {}
    simulation = report.get("simulation") or {}
    diagnostics = (
        report.get("simulation_diagnostics")
        or simulation.get("diagnostics")
        or {}
    )
    scan_time_ms = report.get("scan_time_ms")
    if scan_time_ms is None:
        scan_time_ms = diagnostics.get("total_ms")

    contract_names = report.get("contract_names")
    if contract_names is None:
        contract_names = _contract_names(findings)

    report.update({
        "filename": report.get("filename") or "Unknown contract",
        "pragma_version": report.get("pragma_version"),
        "line_count": report.get("line_count") or 0,
        "risk_level": risk,
        "risk_score": report.get("risk_score", 0),
        "total_issues": report.get("total_issues", len(findings)),
        "findings": findings,
        "risk_css": report.get("risk_css") or risk_meta["css"],
        "risk_icon": report.get("risk_icon") or risk_meta["icon"],
        "risk_label": report.get("risk_label") or risk_meta["label"],
        "severity_counts": report.get("severity_counts") or _severity_counts(findings),
        "confidence_counts": report.get("confidence_counts") or {},
        "verified_findings": report.get("verified_findings", 0),
        "unverified_findings": report.get("unverified_findings", len(findings)),
        "contract_names": contract_names,
        "contracts_count": report.get("contracts_count", len(contract_names)),
        "runtime_status_counts": report.get("runtime_status_counts") or _runtime_status_counts(findings),
        "scan_time_ms": scan_time_ms,
        "runtime_requested": report.get("runtime_requested", runtime_correlation.get("runtime_requested", False)),
        "runtime_executed": report.get("runtime_executed", runtime_correlation.get("runtime_executed", False)),
        "runtime_backend": report.get("runtime_backend", runtime_correlation.get("backend")),
        "runtime_correlation": runtime_correlation,
        "simulation": simulation,
        "simulation_diagnostics": diagnostics,
        "simulation_available": report.get("simulation_available", False),
    })
    return report


def _ensure_finding_shape(finding: dict) -> dict:
    finding = dict(finding or {})
    sev = finding.get("severity", "INFO")
    meta = SEVERITY_META.get(sev, SEVERITY_META["INFO"])
    rt_status = finding.get("runtime_validation_status", "NOT_RUN")
    rt_meta = RUNTIME_STATUS_META.get(rt_status, RUNTIME_STATUS_META["NOT_RUN"])
    finding.setdefault("id", None)
    finding.setdefault("vulnerability", "Finding")
    finding.setdefault("line", "unknown")
    finding.setdefault("description", "")
    finding.setdefault("impact", "Impact not recorded.")
    finding.setdefault("exploit_path", "Exploit path not recorded.")
    finding.setdefault("fix", "Review the finding and apply the appropriate mitigation.")
    finding.setdefault("remediation", None)
    finding.setdefault("confidence", "UNKNOWN")
    finding.setdefault("limitations", [])
    finding.setdefault("validation_notes", [])
    finding.setdefault("verification", {})
    if not isinstance(finding["verification"], dict):
        finding["verification"] = {}
    finding["verification"].setdefault("dynamic", "NOT_RUN")
    finding.update({
        "severity_css": finding.get("severity_css") or meta["css"],
        "severity_icon": finding.get("severity_icon") or meta["icon"],
        "severity_label": finding.get("severity_label") or meta["label"],
        "runtime_status_css": finding.get("runtime_status_css") or rt_meta["css"],
        "runtime_status_label": finding.get("runtime_status_label") or rt_meta["label"],
        "runtime_status_short": finding.get("runtime_status_short") or rt_meta["short"],
        "runtime_status_tone": finding.get("runtime_status_tone") or rt_meta["tone"],
        "scope_label": finding.get("scope_label") or _scope_label(finding),
        "rationale_preview": finding.get("rationale_preview") or _rationale_preview(finding),
        "runtime_evidence_preview": finding.get("runtime_evidence_preview") or _evidence_preview(finding.get("runtime_evidence")),
        "runtime_evidence_items": finding.get("runtime_evidence_items") or _evidence_items(finding.get("runtime_evidence")),
        "static_evidence_preview": finding.get("static_evidence_preview") or _evidence_preview(finding.get("evidence")),
    })
    return finding


def _scope_label(finding: dict) -> str:
    parts = []
    if finding.get("contract_name"):
        parts.append(finding["contract_name"])
    if finding.get("function"):
        parts.append(f"{finding['function']}()")
    return " / ".join(parts) if parts else "Contract scope"


def _rationale_preview(finding: dict) -> str:
    for key in ("description", "impact", "exploit_path"):
        value = finding.get(key)
        if value:
            return _truncate(str(value), 220)
    return "Aegis flagged this source pattern for review."


def _evidence_preview(evidence) -> str:
    if not evidence:
        return "No runtime evidence recorded."
    if isinstance(evidence, dict):
        reason = evidence.get("classification_reason") or evidence.get("notes")
        if reason:
            return _truncate(str(reason), 220)
        pairs = _evidence_items(evidence)
        if pairs:
            return "; ".join(f"{item['label']}: {item['value']}" for item in pairs[:3])
    return _truncate(str(evidence), 220)


def _evidence_items(evidence) -> list:
    if not isinstance(evidence, dict):
        return []
    items = []
    for key, value in evidence.items():
        items.append(
            {
                "key": key,
                "label": key.replace("_", " ").title(),
                "value": _display_value(value),
            }
        )
    return items


def _display_value(value) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if value is None:
        return "not recorded"
    if isinstance(value, (dict, list, tuple)):
        return _truncate(str(value), 260)
    return _truncate(str(value), 260)


def _truncate(value: str, limit: int) -> str:
    cleaned = " ".join(value.split())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: max(0, limit - 1)].rstrip() + "..."


def _contract_names(findings: list) -> list:
    names = []
    seen = set()
    for finding in findings:
        name = finding.get("contract_name")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _runtime_status_counts(findings: list) -> dict:
    counts = {status: 0 for status in RUNTIME_STATUS_META}
    for finding in findings:
        status = finding.get("runtime_validation_status", "NOT_RUN")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _severity_counts(findings: list) -> dict:
    counts = {severity: 0 for severity in SEVERITY_META}
    for finding in findings:
        severity = finding.get("severity", "INFO")
        counts[severity] = counts.get(severity, 0) + 1
    return counts
