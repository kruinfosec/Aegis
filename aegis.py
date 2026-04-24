#!/usr/bin/env python3
"""
Aegis — Smart Contract Vulnerability Scanner (CLI)
Command-line interface for the Aegis scanner engine.

Uses ``pipeline.full_scan()`` as the single orchestration path so that
runtime-enriched findings, correlation summaries, and analysis summaries
are identical to what the Flask app produces.
"""

import argparse
import sys
import json
import os
from scanner.pipeline import full_scan, is_runtime_available

# Fix for Windows console emoji encoding
if sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass


RUNTIME_STATUS_LABELS = {
    "confirmed_by_runtime":       "✅ Confirmed by Runtime",
    "not_confirmed_by_runtime":   "🛡️ Not Confirmed by Runtime",
    "inconclusive_runtime":       "❓ Inconclusive",
    "simulation_unsupported":     "⚙️ Unsupported",
    "simulation_failed":          "❌ Failed",
    "NOT_RUN":                    "—  Not Run",
}


def main():
    parser = argparse.ArgumentParser(
        description="Aegis Smart Contract Vulnerability Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        "target",
        help="Path to the Solidity (.sol) file or directory to scan"
    )
    
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)"
    )

    parser.add_argument(
        "--runtime",
        action="store_true",
        default=False,
        help="Enable runtime validation (requires Hardhat + web3.py)"
    )

    parser.add_argument(
        "--runtime-backend",
        default="hardhat",
        help="Runtime validation backend (default: hardhat)"
    )

    args = parser.parse_args()

    target_path = os.path.abspath(args.target)

    if not os.path.exists(target_path):
        print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    files_to_scan = []
    if os.path.isfile(target_path):
        if not target_path.endswith('.sol'):
            print(f"Error: File '{target_path}' is not a .sol file.", file=sys.stderr)
            sys.exit(1)
        files_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.sol'):
                    files_to_scan.append(os.path.join(root, file))
        
        if not files_to_scan:
            print(f"No .sol files found in directory '{target_path}'.", file=sys.stderr)
            sys.exit(0)

    # Warn about runtime availability.
    run_runtime = args.runtime
    if run_runtime and not is_runtime_available():
        print("⚠️  Runtime validation requested but dependencies are not available.", file=sys.stderr)
        print("    Install web3.py and ensure npx/Hardhat are in PATH.", file=sys.stderr)
        print("    Continuing with static analysis only.\n", file=sys.stderr)

    # Scan all files via the unified pipeline.
    results = []
    for filepath in files_to_scan:
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                source_code = f.read()
            
            filename = os.path.basename(filepath)

            if run_runtime and args.format == "text":
                print(f"⏳ Scanning {filename} (runtime validation enabled)...")

            scan_result = full_scan(
                source_code,
                filename=filename,
                run_runtime=run_runtime,
                backend_name=args.runtime_backend,
            )
            results.append(scan_result)
            
        except Exception as e:
            results.append({
                "success": False,
                "error": str(e),
                "filename": os.path.basename(filepath),
                "findings": [],
                "total_issues": 0,
                "runtime_correlation": None,
            })

    # Print output.
    if args.format == "json":
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            _print_text_report(result)
        print(f"\n{'='*60}\n")

def _print_text_report(result: dict) -> None:
    """Print a single scan result in human-readable text format."""
    print(f"\n{'='*60}")
    print(f"📄 Report for: {result.get('filename', 'Unknown')}")
    print(f"{'='*60}")
    
    if not result.get("success"):
        print(f"[!] Scan Error: {result.get('error')}")
        return
        
    print(f"Risk Level : {result.get('risk_level')} (Score: {result.get('risk_score')})")
    print(f"Solidity   : {result.get('pragma_version') or 'Unknown'}")
    print(f"Issues     : {result.get('total_issues')}")

    # Runtime correlation summary.
    rt_corr = result.get("runtime_correlation")
    if rt_corr and rt_corr.get("runtime_requested"):
        print(f"\n--- Runtime Validation ---")
        if rt_corr.get("runtime_executed"):
            print(f"Backend    : {rt_corr.get('backend', 'unknown')}")
            print(f"Confirmed  : {rt_corr.get('confirmed_count', 0)}")
            print(f"Not Conf.  : {rt_corr.get('not_confirmed_count', 0)}")
            print(f"Inconclusive: {rt_corr.get('inconclusive_count', 0)}")
            print(f"Unsupported: {rt_corr.get('unsupported_count', 0)}")
            print(f"Failed     : {rt_corr.get('failed_count', 0)}")
            print(f"Not Run    : {rt_corr.get('not_run_count', 0)}")
            families = rt_corr.get("scenario_families_executed", [])
            if families:
                print(f"Scenarios  : {', '.join(families)}")
        else:
            print(f"Status     : Runtime did not execute")
            sim = result.get("simulation")
            if sim and sim.get("summary"):
                print(f"Reason     : {sim['summary']}")

        # Concise diagnostics in text mode.
        sim = result.get("simulation") or {}
        diag = sim.get("diagnostics")
        if diag:
            _print_text_diagnostics(diag)

    print("-" * 60)
    
    if result.get("total_issues") == 0:
        print("✅ No vulnerabilities detected. Contract appears safe.")
    else:
        for i, finding in enumerate(result.get("findings", [])):
            _print_text_finding(i, finding)


def _print_text_finding(index: int, finding: dict) -> None:
    """Print a single finding in text format with runtime context."""
    print(f"\n[{index+1}] {finding['vulnerability']} ({finding['severity']})")
    print(f"    Line : {finding['line']}")

    # Contract/function context.
    ctx_parts = []
    if finding.get("contract_name"):
        ctx_parts.append(finding["contract_name"])
    if finding.get("function"):
        ctx_parts.append(f"{finding['function']}()")
    if ctx_parts:
        print(f"    Scope: {' → '.join(ctx_parts)}")

    print(f"    Desc : {finding['description']}")
    print(f"    Fix  : {finding['fix']}")

    # Runtime status if not default.
    rt_status = finding.get("runtime_validation_status", "NOT_RUN")
    if rt_status != "NOT_RUN":
        label = RUNTIME_STATUS_LABELS.get(rt_status, rt_status)
        print(f"    Runtime: {label}")

        exploit = finding.get("exploitability", "UNVERIFIED")
        if exploit != "UNVERIFIED":
            print(f"    Exploit: {exploit}")

        # Short evidence summary.
        evidence = finding.get("runtime_evidence")
        if evidence and isinstance(evidence, dict):
            summary_parts = []
            for k, v in evidence.items():
                if isinstance(v, str) and len(v) > 42:
                    v = v[:20] + "…"  # Truncate long addresses
                summary_parts.append(f"{k}={v}")
            if summary_parts:
                print(f"    Evidence: {', '.join(summary_parts[:4])}")

        # Validation notes (first note only for brevity).
        notes = finding.get("validation_notes", [])
        if notes:
            print(f"    Note : {notes[0]}")


def _print_text_diagnostics(diag: dict) -> None:
    """Print concise diagnostics in text mode."""
    parts = []
    if diag.get("total_ms") is not None:
        parts.append(f"total={diag['total_ms']:.0f}ms")
    if diag.get("compilation_ms") is not None:
        cache = " (cached)" if diag.get("compilation_cache_hit") else ""
        parts.append(f"compile={diag['compilation_ms']:.0f}ms{cache}")
    if diag.get("backend_startup_ms") is not None:
        retries = f" ({diag['startup_retries']} retries)" if diag.get("startup_retries") else ""
        parts.append(f"startup={diag['backend_startup_ms']:.0f}ms{retries}")
    if diag.get("scenario_execution_ms") is not None:
        parts.append(f"scenarios={diag['scenario_execution_ms']:.0f}ms")
    if diag.get("error_phase"):
        parts.append(f"error_phase={diag['error_phase']}")

    if parts:
        print(f"Diagnostics: {' | '.join(parts)}")

    if diag.get("error_phase") == "finding_filter":
        found = ", ".join(diag.get("finding_checks") or []) or "none"
        supported = ", ".join(diag.get("supported_checks") or []) or "none"
        print(
            "Runtime eligibility: "
            f"{diag.get('runtime_eligible_count', 0)} eligible / "
            f"{diag.get('finding_count', 0)} finding(s)"
        )
        print(f"Found checks: {found}")
        print(f"Supported checks: {supported}")


if __name__ == "__main__":
    main()
