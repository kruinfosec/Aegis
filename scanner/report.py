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
        enriched_findings.append({
            **finding,
            "severity_css": meta["css"],
            "severity_icon": meta["icon"],
            "severity_label": meta["label"],
        })

    risk = scan_result.get("risk_level", "UNKNOWN")
    risk_meta = RISK_META.get(risk, RISK_META["UNKNOWN"])

    return {
        **scan_result,
        "findings": enriched_findings,
        "risk_css": risk_meta["css"],
        "risk_icon": risk_meta["icon"],
        "risk_label": risk_meta["label"],
    }
