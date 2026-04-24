"""Lightweight validation benchmark runner for Aegis."""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from benchmarks.fixtures import BenchmarkFixture, families, select_fixtures
from scanner.pipeline import full_scan


ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_DIR = ROOT / "artifacts" / "benchmarks"
RUNTIME_STATUSES = [
    "confirmed_by_runtime",
    "not_confirmed_by_runtime",
    "inconclusive_runtime",
    "simulation_unsupported",
    "simulation_failed",
    "NOT_RUN",
]


def list_fixtures() -> list[dict]:
    return [_fixture_to_dict(fixture) for fixture in select_fixtures()]


def run_benchmark(
    *,
    family: str | None = None,
    quick: bool = False,
    run_runtime: bool = True,
) -> dict:
    fixtures = select_fixtures(family, quick=quick)
    started = time.perf_counter()
    results = [run_fixture(fixture, run_runtime=run_runtime) for fixture in fixtures]
    total_ms = round((time.perf_counter() - started) * 1000, 2)
    return {
        "schema_version": 1,
        "mode": "quick" if quick else "full",
        "runtime_requested": run_runtime,
        "family_filter": family,
        "total_ms": total_ms,
        "fixtures": results,
        "summary": summarize(results, total_ms=total_ms),
    }


def run_fixture(fixture: BenchmarkFixture, *, run_runtime: bool = True) -> dict:
    source_path = ROOT / fixture.sample
    started = time.perf_counter()
    source = source_path.read_text(encoding="utf-8")
    result = full_scan(
        source,
        filename=source_path.name,
        run_runtime=run_runtime,
    )
    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    relevant = [finding for finding in result.get("findings", []) if finding.get("check") == fixture.check]
    runtime_statuses = [finding.get("runtime_validation_status", "NOT_RUN") for finding in relevant]
    simulation_status = (result.get("simulation") or {}).get("status")
    observed_runtime_status = _choose_runtime_status(runtime_statuses, simulation_status=simulation_status)
    static_found = bool(relevant)
    static_passed = static_found == fixture.expected_static_found
    runtime_passed = (
        not run_runtime
        or fixture.expected_runtime_status is None
        or observed_runtime_status == fixture.expected_runtime_status
    )
    passed = bool(result.get("success")) and static_passed and runtime_passed
    diagnostics = ((result.get("simulation") or {}).get("diagnostics") or {})
    return {
        **_fixture_to_dict(fixture),
        "passed": passed,
        "success": bool(result.get("success")),
        "duration_ms": duration_ms,
        "static": {
            "expected_found": fixture.expected_static_found,
            "found": static_found,
            "passed": static_passed,
            "relevant_findings": len(relevant),
            "total_findings": len(result.get("findings", [])),
        },
        "runtime": {
            "requested": run_runtime,
            "expected_status": fixture.expected_runtime_status,
            "observed_status": observed_runtime_status,
            "passed": runtime_passed,
            "status_counts": dict(Counter(runtime_statuses)),
            "backend": ((result.get("runtime_correlation") or {}).get("backend")),
            "scenario_families": ((result.get("runtime_correlation") or {}).get("scenario_families_executed") or []),
        },
        "diagnostics": {
            "total_ms": diagnostics.get("total_ms"),
            "compilation_ms": diagnostics.get("compilation_ms"),
            "backend_startup_ms": diagnostics.get("backend_startup_ms"),
            "scenario_execution_ms": diagnostics.get("scenario_execution_ms"),
            "error_phase": diagnostics.get("error_phase"),
        },
    }


def summarize(results: Iterable[dict], *, total_ms: float | None = None) -> dict:
    results = list(results)
    families_summary = defaultdict(lambda: {
        "fixtures": 0,
        "passed": 0,
        "failed": 0,
        "duration_ms": 0.0,
        "static_found": 0,
        "runtime_status_counts": {status: 0 for status in RUNTIME_STATUSES},
    })
    runtime_counts = {status: 0 for status in RUNTIME_STATUSES}
    for item in results:
        fam = families_summary[item["family"]]
        fam["fixtures"] += 1
        fam["passed"] += 1 if item["passed"] else 0
        fam["failed"] += 0 if item["passed"] else 1
        fam["duration_ms"] = round(fam["duration_ms"] + item["duration_ms"], 2)
        fam["static_found"] += 1 if item["static"]["found"] else 0
        status = item["runtime"]["observed_status"]
        if status not in runtime_counts:
            runtime_counts[status] = 0
            fam["runtime_status_counts"][status] = 0
        runtime_counts[status] += 1
        fam["runtime_status_counts"][status] = fam["runtime_status_counts"].get(status, 0) + 1

    total = len(results)
    passed = sum(1 for item in results if item["passed"])
    static_hits = sum(1 for item in results if item["static"]["found"])
    return {
        "total_fixtures": total,
        "passed": passed,
        "failed": total - passed,
        "static_detection_hit_rate": _ratio(static_hits, total),
        "runtime_status_counts": runtime_counts,
        "family_summary": dict(sorted(families_summary.items())),
        "total_ms": total_ms if total_ms is not None else round(sum(item["duration_ms"] for item in results), 2),
        "notes": [
            "Metrics are based on curated fixtures, not broad statistical precision/recall.",
            "Runtime evidence reflects local Hardhat scenarios and should be interpreted conservatively.",
        ],
    }


def write_artifact(result: dict, output: str | Path | None = None) -> Path:
    if output is None:
        mode = result.get("mode", "benchmark")
        family = result.get("family_filter") or "all"
        output = ARTIFACT_DIR / f"{mode}-{family}.json"
    output_path = Path(output)
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return output_path


def print_summary(result: dict) -> None:
    summary = result["summary"]
    print("Aegis benchmark summary")
    print(f"Mode      : {result['mode']}")
    print(f"Runtime   : {'requested' if result['runtime_requested'] else 'static-only'}")
    print(f"Fixtures  : {summary['total_fixtures']} ({summary['passed']} passed, {summary['failed']} failed)")
    print(f"Duration  : {summary['total_ms']:.0f}ms")
    print(f"Static hit: {summary['static_detection_hit_rate']:.2%} on curated fixtures")
    print("\nRuntime statuses:")
    for status, count in summary["runtime_status_counts"].items():
        if count:
            print(f"  {status:<28} {count}")
    print("\nFamilies:")
    for family, data in summary["family_summary"].items():
        print(
            f"  {family:<22} fixtures={data['fixtures']} "
            f"passed={data['passed']} failed={data['failed']} "
            f"duration={data['duration_ms']:.0f}ms"
        )


def known_families() -> list[str]:
    return families()


def _choose_runtime_status(statuses: list[str], *, simulation_status: str | None = None) -> str:
    if simulation_status in {"simulation_failed", "simulation_unsupported", "inconclusive_runtime"}:
        if not statuses or all(status == "NOT_RUN" for status in statuses):
            return simulation_status
    if not statuses:
        return "NOT_RUN"
    priority = {
        "confirmed_by_runtime": 0,
        "not_confirmed_by_runtime": 1,
        "inconclusive_runtime": 2,
        "simulation_unsupported": 3,
        "simulation_failed": 4,
        "NOT_RUN": 5,
    }
    return sorted(statuses, key=lambda status: priority.get(status, 99))[0]


def _fixture_to_dict(fixture: BenchmarkFixture) -> dict:
    return {
        "id": fixture.id,
        "family": fixture.family,
        "check": fixture.check,
        "sample": fixture.sample,
        "expected_static_found": fixture.expected_static_found,
        "expected_runtime_status": fixture.expected_runtime_status,
        "quick": fixture.quick,
        "notes": fixture.notes,
    }


def _ratio(value: int, total: int) -> float:
    return round(value / total, 4) if total else 0.0
