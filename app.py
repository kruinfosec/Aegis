"""
Aegis — Smart Contract Vulnerability Scanner
app.py: Flask web application entry point.
"""

import os
import json
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response
from werkzeug.utils import secure_filename

from scanner import engine
from scanner import report as report_formatter

# Optional simulation — gracefully skipped if web3 not installed
try:
    from simulation import simulate as simulator
    SIMULATION_AVAILABLE = True
except ImportError:
    SIMULATION_AVAILABLE = False

app = Flask(__name__)
app.secret_key = "aegis-kru-infosec-secret-2024"

ALLOWED_EXTENSIONS = {"sol"}
MAX_CONTENT_LENGTH = 512 * 1024  # 500 KB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


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
    safe_names = {"reentrancy", "overflow", "safe", "randomness", "selfdestruct", "delegatecall", "access", "timestamp"}
    if name not in safe_names:
        flash("Unknown sample name.", "error")
        return redirect(url_for("index"))

    sample_path = os.path.join(os.path.dirname(__file__), "samples", f"{name}.sol")
    if not os.path.exists(sample_path):
        flash("Sample file not found.", "error")
        return redirect(url_for("index"))

    with open(sample_path, "r", encoding="utf-8") as f:
        source_code = f.read()

    return _run_scan_and_redirect(source_code, f"{name}.sol")


@app.route("/report", methods=["GET"])
def show_report():
    report_data = session.get("report")
    if not report_data:
        flash("No scan results found. Please upload a contract first.", "error")
        return redirect(url_for("index"))
    return render_template("report.html", report=report_data)


@app.route("/report/export/json", methods=["GET"])
def export_json():
    """Download the current scan report as a formatted JSON file."""
    report_data = session.get("report")
    if not report_data:
        flash("No scan results to export. Please run a scan first.", "error")
        return redirect(url_for("index"))

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
        "findings": [
            {
                "vulnerability": f["vulnerability"],
                "severity":      f["severity"],
                "line":          f["line"],
                "description":   f["description"],
                "fix":           f["fix"],
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
    """Shared helper: scan code, optionally simulate, store in session, redirect."""
    raw_result = engine.scan(source_code, filename=filename)

    if not raw_result["success"]:
        flash(f"Scan error: {raw_result['error']}", "error")
        return redirect(url_for("index"))

    formatted = report_formatter.format_report(raw_result)

    # Run blockchain simulation if web3 is available
    simulation_result = None
    if SIMULATION_AVAILABLE and raw_result["total_issues"] > 0:
        try:
            simulation_result = simulator.run_simulation(
                source_code, raw_result["findings"]
            )
        except Exception:
            simulation_result = {
                "success": False,
                "error": "Simulation failed unexpectedly.",
                "summary": "Simulation unavailable.",
                "attacks_run": [],
            }

    formatted["simulation"] = simulation_result
    formatted["simulation_available"] = SIMULATION_AVAILABLE
    session["report"] = formatted
    return redirect(url_for("show_report"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
