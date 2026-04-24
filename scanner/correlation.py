"""
Reusable static/dynamic correlation layer for Aegis.

This module is the single authoritative place where static scan findings are
enriched with runtime-validation results.  Every interface — app, CLI, tests,
export — should call ``correlate()`` rather than performing ad-hoc merge logic.

Design rules
~~~~~~~~~~~~
* The *enriched findings list* and the *runtime_correlation summary* returned
  by ``correlate()`` are the authoritative truth about the merged state.
* The raw simulation payload (if any) is preserved verbatim for debug / UI
  detail panels, but it is **not** a competing source of final status.
* Runtime absence is never confused with runtime disproval.
"""

from copy import deepcopy
from typing import Any, Dict, List, Optional

from scanner.finding import merge_runtime_validations, summarize_findings


# ── public API ───────────────────────────────────────────────────────────────

def correlate(
    scan_result: dict,
    runtime_result: Optional[dict] = None,
    *,
    runtime_requested: bool = False,
) -> dict:
    """Merge static scan results with optional runtime-validation results.

    Parameters
    ----------
    scan_result:
        The dict returned by ``engine.scan()``.
    runtime_result:
        The dict returned by ``simulation.service.run_runtime_validation()``
        (or ``simulate.run_simulation()``).  ``None`` if runtime was not run.
    runtime_requested:
        Whether the caller explicitly asked for runtime validation, even if it
        could not execute for dependency or scenario-coverage reasons.

    Returns
    -------
    dict
        A **new** enriched scan-result dict.  Original ``scan_result`` is not
        mutated.  The dict contains:
        - all original engine fields
        - ``findings`` — runtime-enriched copies
        - ``analysis_summary`` — regenerated to reflect runtime verification
        - ``runtime_correlation`` — scan-level correlation summary
        - ``simulation`` — raw runtime payload (for UI detail / debug)
    """
    enriched = deepcopy(scan_result)

    if runtime_result is not None and enriched.get("findings"):
        enriched["findings"] = merge_runtime_validations(
            enriched["findings"],
            runtime_result,
        )

    # Re-generate analysis summary *after* merge so counts are accurate.
    enriched["analysis_summary"] = summarize_findings(enriched["findings"])

    # Attach scan-level correlation summary.
    enriched["runtime_correlation"] = build_runtime_summary(
        enriched["findings"],
        runtime_result=runtime_result,
        runtime_requested=runtime_requested,
    )

    # Preserve raw simulation payload for UI detail panels / debug.
    enriched["simulation"] = runtime_result

    return enriched


# ── helpers ──────────────────────────────────────────────────────────────────

def build_runtime_summary(
    findings: List[dict],
    *,
    runtime_result: Optional[dict] = None,
    runtime_requested: bool = False,
) -> dict:
    """Build a scan-level correlation summary from enriched findings.

    ``runtime_requested`` — whether the user asked for runtime validation.
    ``runtime_executed``  — whether the backend actually ran *any* scenario
    to completion (success or failure), as opposed to being skipped or
    crashing before the first scenario.
    """
    status_counts = count_runtime_statuses(findings)
    total = len(findings)

    # Determine backend used.
    backend = None
    if runtime_result is not None:
        backend = runtime_result.get("backend")

    # Determine whether runtime actually executed (at least one validation
    # record was produced).
    runtime_executed = False
    if runtime_result is not None:
        validations = runtime_result.get("validations", [])
        if validations:
            runtime_executed = True

    # Collect scenario families executed.
    scenario_families: List[str] = []
    if runtime_result is not None:
        seen = set()
        for validation in runtime_result.get("validations", []):
            scenario = validation.get("scenario") or validation.get("check", "")
            family = scenario.split(".")[0] if scenario else ""
            if family and family not in seen:
                seen.add(family)
                scenario_families.append(family)

    validated_count = (
        status_counts.get("confirmed_by_runtime", 0)
        + status_counts.get("not_confirmed_by_runtime", 0)
        + status_counts.get("inconclusive_runtime", 0)
        + status_counts.get("simulation_unsupported", 0)
        + status_counts.get("simulation_failed", 0)
    )

    return {
        "runtime_requested": runtime_requested,
        "runtime_executed": runtime_executed,
        "enabled": runtime_result is not None,
        "backend": backend,
        "total_findings": total,
        "runtime_validated_count": validated_count,
        "confirmed_count": status_counts.get("confirmed_by_runtime", 0),
        "not_confirmed_count": status_counts.get("not_confirmed_by_runtime", 0),
        "inconclusive_count": status_counts.get("inconclusive_runtime", 0),
        "unsupported_count": status_counts.get("simulation_unsupported", 0),
        "failed_count": status_counts.get("simulation_failed", 0),
        "not_run_count": status_counts.get("NOT_RUN", 0),
        "findings_without_runtime_validation_count": status_counts.get("NOT_RUN", 0),
        "scenario_families_executed": scenario_families,
    }


def count_runtime_statuses(findings: List[dict]) -> Dict[str, int]:
    """Tally ``runtime_validation_status`` across all findings."""
    counts: Dict[str, int] = {}
    for finding in findings:
        status = finding.get("runtime_validation_status", "NOT_RUN")
        counts[status] = counts.get(status, 0) + 1
    return counts
