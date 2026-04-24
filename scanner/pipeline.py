"""
Unified scan pipeline for Aegis.

Every interface — Flask app, CLI, programmatic callers — should use
``full_scan()`` as the single orchestration path.  This guarantees:

* static scan
* optional runtime validation
* deterministic correlation / enrichment
* a single enriched result object

The pipeline imports the simulation subsystem **conditionally** so that
Aegis works in static-only mode when ``web3`` or Node tooling is absent.
"""

import sys
from scanner import engine
from scanner.correlation import correlate

# ── conditional simulation import ────────────────────────────────────────────
try:
    from simulation.service import run_runtime_validation, simulation_available
    _SIMULATION_IMPORT_OK = True
except ImportError:
    _SIMULATION_IMPORT_OK = False

    def run_runtime_validation(*_args, **_kwargs):  # type: ignore[misc]
        return {
            "backend": "hardhat",
            "status": "simulation_unsupported",
            "success": False,
            "summary": "Runtime validation skipped: simulation dependencies are not installed.",
            "error": "simulation module could not be imported.",
            "accounts": [],
            "validations": [],
            "attacks_run": [],
            "metadata": {},
        }

    def simulation_available() -> bool:  # type: ignore[misc]
        return False


# ── public API ───────────────────────────────────────────────────────────────

def full_scan(
    source_code: str,
    filename: str = "contract.sol",
    *,
    run_runtime: bool = False,
    backend_name: str = "hardhat",
) -> dict:
    """End-to-end Aegis scan: static analysis → optional runtime → correlation.

    Parameters
    ----------
    source_code:
        Raw Solidity source as a string.
    filename:
        Display name for the scanned file.
    run_runtime:
        If ``True``, attempt runtime validation after the static scan.
        Gracefully degrades if dependencies are missing.
    backend_name:
        Runtime backend identifier.  Only ``"hardhat"`` is supported today.

    Returns
    -------
    dict
        Enriched scan result with correlation summaries.  This is the single
        authoritative result object for app, CLI, and export.
    """
    # Step 1: Static scan.
    scan_result = engine.scan(source_code, filename=filename)

    if not scan_result["success"]:
        # Return early — correlation still attaches a summary even on failure.
        return correlate(scan_result, runtime_result=None, runtime_requested=run_runtime)

    # Step 2: Optional runtime validation.
    runtime_result = None
    if run_runtime and scan_result["total_issues"] > 0:
        runtime_result = _try_runtime(source_code, scan_result["findings"], backend_name)

    # Step 3: Correlation — merge + summaries.
    return correlate(scan_result, runtime_result, runtime_requested=run_runtime)


def is_runtime_available() -> bool:
    """Check whether the runtime subsystem can be used."""
    if not _SIMULATION_IMPORT_OK:
        return False
    return simulation_available()


# ── internal helpers ─────────────────────────────────────────────────────────

def _try_runtime(
    source_code: str,
    findings: list,
    backend_name: str,
) -> dict:
    """Attempt runtime validation, returning a fallback result on any error."""
    try:
        return run_runtime_validation(
            source_code,
            findings,
            backend_name=backend_name,
        )
    except Exception as exc:
        return {
            "backend": backend_name,
            "status": "simulation_failed",
            "success": False,
            "summary": "Runtime validation failed unexpectedly.",
            "error": str(exc),
            "accounts": [],
            "validations": [],
            "attacks_run": [],
            "metadata": {},
        }
