"""
Aegis — Smart Contract Vulnerability Scanner
app.py: Flask web application entry point.
"""

import os
import json
from uuid import uuid4
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.utils import secure_filename

from scanner.pipeline import full_scan, is_runtime_available
from scanner import report as report_formatter

app = Flask(__name__)
app.secret_key = "aegis-kru-infosec-secret-2024"

ALLOWED_EXTENSIONS = {"sol"}
MAX_CONTENT_LENGTH = 512 * 1024  # 500 KB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
REPORT_CACHE = {}
REPORT_CACHE_LIMIT = 25


SAMPLE_CATALOG = [
    {
        "slug": "reentrancy",
        "file": "reentrancy.sol",
        "label": "Reentrancy Attack",
        "badge": "HIGH",
        "icon": "🔴",
        "css": "sample-high",
        "expected_check": "reentrancy",
    },
    {
        "slug": "selfdestruct",
        "file": "selfdestruct.sol",
        "label": "Unprotected Selfdestruct",
        "badge": "CRITICAL",
        "icon": "💀",
        "css": "sample-critical",
        "expected_check": "unprotected-selfdestruct",
    },
    {
        "slug": "delegatecall",
        "file": "delegatecall.sol",
        "label": "Untrusted Delegatecall",
        "badge": "HIGH",
        "icon": "🎭",
        "css": "sample-high",
        "expected_check": "delegatecall-untrusted-target",
    },
    {
        "slug": "access",
        "file": "access.sol",
        "label": "Missing Access Control",
        "badge": "HIGH",
        "icon": "🔓",
        "css": "sample-high",
        "expected_check": "missing-access-control",
    },
    {
        "slug": "overflow",
        "file": "overflow.sol",
        "label": "Integer Overflow",
        "badge": "MEDIUM",
        "icon": "🟡",
        "css": "sample-medium",
        "expected_check": "integer-overflow",
    },
    {
        "slug": "randomness",
        "file": "randomness.sol",
        "label": "Weak Randomness",
        "badge": "MEDIUM",
        "icon": "🎲",
        "css": "sample-medium",
        "expected_check": "predictable-randomness",
    },
    {
        "slug": "timestamp",
        "file": "timestamp.sol",
        "label": "Timestamp Dependence",
        "badge": "LOW",
        "icon": "⏱️",
        "css": "sample-low",
        "expected_check": "timestamp-dependence",
    },
    {
        "slug": "safe",
        "file": "safe.sol",
        "label": "Safe Contract",
        "badge": "SAFE",
        "icon": "✅",
        "css": "sample-safe",
        "expected_check": None,
    },
]
SAMPLES_BY_SLUG = {sample["slug"]: sample for sample in SAMPLE_CATALOG}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", samples=SAMPLE_CATALOG)


@app.route("/scan", methods=["POST"])
def scan():
    """Handle contract upload, run scanner, optionally run simulation."""
    if "contract" not in request.files:
        flash("No file selected. Please upload a .sol file.", "error")
        return redirect(url_for("index"))

    file = request.files["contract"]

    if file.filename == "":
        flash("No file selected. Please upload a .sol file.", "error")
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        flash("Invalid file type. Only .sol (Solidity) files are accepted.", "error")
        return redirect(url_for("index"))

    try:
        source_code = file.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Could not read file. Ensure it is a valid UTF-8 text file.", "error")
        return redirect(url_for("index"))

    if not source_code.strip():
        flash("The uploaded file is empty.", "error")
        return redirect(url_for("index"))

    filename = secure_filename(file.filename)
    return _run_scan_and_redirect(source_code, filename)


@app.route("/sample/<name>", methods=["GET"])
def load_sample(name: str):
    """Load and scan a bundled sample contract."""
    sample = SAMPLES_BY_SLUG.get(name)
    if not sample:
        flash("Unknown sample name.", "error")
        return redirect(url_for("index"))

    sample_path = os.path.join(os.path.dirname(__file__), "samples", sample["file"])
    if not os.path.exists(sample_path):
        flash("Sample file not found.", "error")
        return redirect(url_for("index"))

    with open(sample_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    return _run_scan_and_redirect(source_code, sample["file"])


@app.route("/report", methods=["GET"])
def show_report():
    report_data = _get_current_report()
    if not report_data:
        flash("No scan results found. Please upload a contract first.", "error")
        return redirect(url_for("index"))
    report_data = report_formatter.ensure_report_shape(report_data)
    _refresh_current_report(report_data)
    return render_template("report.html", report=report_data)


@app.route("/report/export/json", methods=["GET"])
def export_json():
    """Download the current scan report as a formatted JSON file."""
    report_data = _get_current_report()
    if not report_data:
        flash("No scan results to export. Please run a scan first.", "error")
        return redirect(url_for("index"))
    report_data = report_formatter.ensure_report_shape(report_data)
    _refresh_current_report(report_data)

    # Build a clean export dict (strip UI-only CSS/icon fields)
    export = {
        "tool": "Aegis by Kru Infosec",
        "filename": report_data.get("filename"),
        "pragma_version": report_data.get("pragma_version"),
        "has_overflow_protection": report_data.get("has_overflow_protection"),
        "line_count": report_data.get("line_count"),
        "risk_level": report_data.get("risk_level"),
        "risk_score": report_data.get("risk_score"),
        "total_issues": report_data.get("total_issues"),
        "analysis_summary": report_data.get("analysis_summary"),
        "runtime_correlation": report_data.get("runtime_correlation") or None,
        "simulation_diagnostics": report_data.get("simulation_diagnostics") or None,
        "simulation_available": report_data.get("simulation_available"),
        "findings": [
            {
                "id":             f.get("id"),
                "vulnerability":  f["vulnerability"],
                "contract_name":  f.get("contract_name"),
                "function":       f.get("function"),
                "severity":       f["severity"],
                "confidence":     f.get("confidence"),
                "swc_id":         f.get("swc_id"),
                "detector_id":    f.get("detector_id"),
                "check":          f.get("check"),
                "analysis_kind":  f.get("analysis_kind"),
                "exploitability": f.get("exploitability"),
                "runtime_validation_status": f.get("runtime_validation_status"),
                "runtime_backend": f.get("runtime_backend"),
                "runtime_scenario": f.get("runtime_scenario"),
                "runtime_evidence": f.get("runtime_evidence"),
                "validation_notes": f.get("validation_notes", []),
                "line":           f["line"],
                "description":    f["description"],
                "impact":         f.get("impact"),
                "exploit_path":   f.get("exploit_path"),
                "fix":            f["fix"],
                "remediation":    f.get("remediation"),
                "limitations":    f.get("limitations", []),
                "evidence":       f.get("evidence"),
                "verification":   f.get("verification"),
            }
            for f in report_data.get("findings", [])
        ],
    }

    filename = report_data.get("filename", "contract").replace(".sol", "")
    json_bytes = json.dumps(export, indent=2).encode("utf-8")
    return Response(
        json_bytes,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="aegis_{filename}_report.json"'},
    )


def _run_scan_and_redirect(source_code: str, filename: str):
    """Shared helper: scan → runtime → correlate → format → session → redirect.

    Uses ``pipeline.full_scan()`` as the single orchestration path so that
    runtime-enriched findings, correlation summaries, and analysis summaries
    are all populated *before* the report formatter runs.  This guarantees
    that per-finding runtime fields (runtime_validation_status, exploitability,
    verification.dynamic) reach the Jinja2 templates correctly.
    """
    runtime_available = is_runtime_available()
    enriched = full_scan(
        source_code,
        filename=filename,
        run_runtime=runtime_available,
    )

    if not enriched["success"]:
        flash(f"Scan error: {enriched['error']}", "error")
        return redirect(url_for("index"))

    # Format for UI *after* correlation so enriched fields are included.
    formatted = report_formatter.format_report(enriched)

    # Attach raw simulation payload for the UI detail panel (not final truth).
    formatted["simulation"] = enriched.get("simulation")
    formatted["simulation_available"] = runtime_available
    formatted["runtime_correlation"] = enriched.get("runtime_correlation")

    # Extract diagnostics from the raw simulation result for the template.
    sim = enriched.get("simulation") or {}
    formatted["simulation_diagnostics"] = sim.get("diagnostics")

    _store_current_report(formatted)
    return redirect(url_for("show_report"))


def _store_current_report(report_data: dict) -> None:
    """Store report data server-side and keep only a small id in the cookie.

    Flask's default session is cookie-backed. Full Aegis reports can exceed the
    browser cookie limit, which can make a newly selected sample appear to show a
    previous report. Keeping the payload server-side avoids stale Quick Test
    reports without changing the scanner/report architecture.
    """
    report_id = uuid4().hex
    REPORT_CACHE[report_id] = report_data
    session.pop("report", None)
    session["report_id"] = report_id
    _trim_report_cache()


def _get_current_report() -> dict | None:
    report_id = session.get("report_id")
    if report_id and report_id in REPORT_CACHE:
        return REPORT_CACHE[report_id]
    # Backward-compatible fallback for tests or old sessions created before the
    # cache existed.
    return session.get("report")


def _refresh_current_report(report_data: dict) -> None:
    report_id = session.get("report_id")
    if report_id and report_id in REPORT_CACHE:
        REPORT_CACHE[report_id] = report_data


def _trim_report_cache() -> None:
    while len(REPORT_CACHE) > REPORT_CACHE_LIMIT:
        oldest_key = next(iter(REPORT_CACHE))
        REPORT_CACHE.pop(oldest_key, None)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
