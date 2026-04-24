"""
Simulation orchestration for Aegis.

Hardening features:
- Structured diagnostics (timing, cache, retries, phases).
- Phase-specific error reporting.
- Compilation caching via compile_source_rich().
"""

import socket
import time
from pathlib import Path

from simulation.backends.hardhat import HardhatBackend
from simulation.compiler import CompilationError, compile_source_rich
from simulation.models import (
    RUNTIME_CONFIRMED,
    RUNTIME_FAILED,
    RUNTIME_INCONCLUSIVE,
    RUNTIME_UNSUPPORTED,
    RuntimeDiagnostics,
    SimulationRunResult,
)
from simulation.scenarios.access_control import validate_access_control
from simulation.scenarios.delegatecall import validate_delegatecall
from simulation.scenarios.integer_overflow import validate_integer_overflow
from simulation.scenarios.reentrancy import validate_reentrancy
from simulation.scenarios.timestamp_dependence import validate_timestamp_dependence
from simulation.scenarios.weak_randomness import validate_weak_randomness
from simulation.support import (
    analyze_runtime_eligibility,
    finding_filter_summary,
    supported_checks,
)

try:
    import web3  # noqa: F401
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False


# Scenario families that this service can dispatch to.
SUPPORTED_CHECKS = supported_checks()


def simulation_available() -> bool:
    return WEB3_AVAILABLE


def run_runtime_validation(source_code: str, findings: list, backend_name: str = "hardhat") -> dict:
    diag = RuntimeDiagnostics()
    t_total_start = time.monotonic()
    eligibility = analyze_runtime_eligibility(findings)
    _attach_eligibility_diagnostics(diag, eligibility)

    if not WEB3_AVAILABLE:
        diag.error_phase = "dependency_check"
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_UNSUPPORTED,
            success=False,
            summary="Runtime validation skipped: web3.py is not installed.",
            error="web3.py is required for runtime validation.",
            diagnostics=diag,
        ).to_dict()

    if backend_name != "hardhat":
        diag.error_phase = "backend_selection"
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_UNSUPPORTED,
            success=False,
            summary=f"Runtime validation backend '{backend_name}' is not supported yet.",
            error="Only the Hardhat backend is implemented in this batch.",
            diagnostics=diag,
        ).to_dict()

    if not findings:
        diag.error_phase = "finding_filter"
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_UNSUPPORTED,
            success=False,
            summary=finding_filter_summary(eligibility),
            metadata={"runtime_eligibility": eligibility},
            diagnostics=diag,
        ).to_dict()

    # Check whether ANY finding is covered by a supported scenario.
    if eligibility["eligible_count"] == 0:
        diag.error_phase = "finding_filter"
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_UNSUPPORTED,
            success=False,
            summary=finding_filter_summary(eligibility),
            metadata={"runtime_eligibility": eligibility},
            diagnostics=diag,
        ).to_dict()

    port = _find_free_port()
    diag.backend_port = port
    backend = HardhatBackend(
        repo_root=str(_repo_root()),
        port=port,
        startup_timeout=20,
    )
    try:
        # ── Phase: Compilation ───────────────────────────────────────────
        t_comp_start = time.monotonic()
        comp_result = compile_source_rich(source_code)
        diag.compilation_ms = round((time.monotonic() - t_comp_start) * 1000, 2)
        diag.compilation_cache_hit = comp_result.cache_hit
        diag.compilation_warnings = comp_result.warnings
        compiled_contracts = comp_result.contracts

        # ── Phase: Backend startup ───────────────────────────────────────
        t_start_start = time.monotonic()
        backend.start()
        diag.backend_startup_ms = round((time.monotonic() - t_start_start) * 1000, 2)

        # Collect backend diagnostics.
        backend_diag = backend.get_diagnostics()
        diag.startup_retries = backend_diag.get("startup_retries_used", 0)

        # ── Phase: Scenario execution ────────────────────────────────────
        t_scenario_start = time.monotonic()
        validations = []

        # Dispatch: access-control scenarios.
        if any(f.get("check") == "missing-access-control" for f in findings):
            validations.extend(
                validate_access_control(findings, compiled_contracts, backend)
            )

        # Dispatch: reentrancy scenarios.
        if any(f.get("check") == "reentrancy" for f in findings):
            validations.extend(
                validate_reentrancy(findings, compiled_contracts, backend, source_code)
            )

        # Dispatch: delegatecall scenarios.
        if any(f.get("check") == "delegatecall-untrusted-target" for f in findings):
            validations.extend(
                validate_delegatecall(findings, compiled_contracts, backend, source_code)
            )

        # Dispatch: integer overflow scenarios.
        if any(f.get("check") == "integer-overflow" for f in findings):
            validations.extend(
                validate_integer_overflow(findings, compiled_contracts, backend, source_code)
            )

        # Dispatch: timestamp dependence scenarios.
        if any(f.get("check") == "timestamp-dependence" for f in findings):
            validations.extend(
                validate_timestamp_dependence(findings, compiled_contracts, backend, source_code)
            )

        # Dispatch: weak randomness scenarios.
        if any(f.get("check") == "predictable-randomness" for f in findings):
            validations.extend(
                validate_weak_randomness(findings, compiled_contracts, backend, source_code)
            )

        diag.scenario_execution_ms = round((time.monotonic() - t_scenario_start) * 1000, 2)
        diag.scenarios_attempted = len(validations)
        diag.scenarios_succeeded = sum(
            1 for v in validations if v.status in {RUNTIME_CONFIRMED, "not_confirmed_by_runtime"}
        )
        diag.scenarios_failed = sum(
            1 for v in validations if v.status in {RUNTIME_FAILED}
        )

        accounts = backend.get_accounts()
    except CompilationError as exc:
        diag.error_phase = "compilation"
        diag.total_ms = round((time.monotonic() - t_total_start) * 1000, 2)
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_FAILED,
            success=False,
            summary="Runtime validation failed during compilation.",
            error=str(exc),
            diagnostics=diag,
        ).to_dict()
    except RuntimeError as exc:
        # Distinguish backend startup from general runtime errors.
        error_str = str(exc)
        if "Hardhat" in error_str or "npx" in error_str or "web3" in error_str:
            diag.error_phase = "backend_startup"
        else:
            diag.error_phase = "scenario_execution"
        diag.total_ms = round((time.monotonic() - t_total_start) * 1000, 2)
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_FAILED,
            success=False,
            summary=f"Runtime validation failed during {diag.error_phase.replace('_', ' ')}.",
            error=error_str,
            diagnostics=diag,
        ).to_dict()
    except Exception as exc:
        diag.error_phase = "unknown"
        diag.total_ms = round((time.monotonic() - t_total_start) * 1000, 2)
        return SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_FAILED,
            success=False,
            summary="Runtime validation failed unexpectedly.",
            error=str(exc),
            diagnostics=diag,
        ).to_dict()
    finally:
        try:
            backend.stop()
        except Exception:
            pass

    diag.total_ms = round((time.monotonic() - t_total_start) * 1000, 2)

    if not validations:
        result = SimulationRunResult(
            backend=backend_name,
            status=RUNTIME_UNSUPPORTED,
            success=False,
            summary="Runtime validation produced no executable scenarios.",
            accounts=accounts,
            diagnostics=diag,
        )
        return result.to_dict()

    statuses = {validation.status for validation in validations}
    if "confirmed_by_runtime" in statuses:
        status = "confirmed_by_runtime"
        success = True
        summary = "Hardhat runtime validation confirmed at least one finding through executed scenarios."
    elif "not_confirmed_by_runtime" in statuses:
        status = "not_confirmed_by_runtime"
        success = True
        summary = "Hardhat runtime validation executed, but the tested scenarios did not confirm the findings."
    elif "inconclusive_runtime" in statuses:
        status = RUNTIME_INCONCLUSIVE
        success = False
        summary = "Hardhat runtime validation executed, but at least one scenario was inconclusive."
    elif "simulation_unsupported" in statuses:
        status = RUNTIME_UNSUPPORTED
        success = False
        summary = "Hardhat runtime validation could not execute every scenario because some contract shapes are not supported yet."
    else:
        status = RUNTIME_FAILED
        success = False
        summary = "Hardhat runtime validation failed."

    return SimulationRunResult(
        backend=backend_name,
        status=status,
        success=success,
        summary=summary,
        accounts=accounts,
        validations=validations,
        metadata={
            "scenario_count": len(validations),
            "runtime_eligibility": eligibility,
        },
        diagnostics=diag,
    ).to_dict()


def _attach_eligibility_diagnostics(diag: RuntimeDiagnostics, eligibility: dict) -> None:
    diag.finding_count = eligibility["total_findings"]
    diag.finding_checks = eligibility["found_checks"]
    diag.supported_checks = eligibility["supported_checks"]
    diag.runtime_eligible_count = eligibility["eligible_count"]
    diag.runtime_ineligible_count = eligibility["unsupported_count"]


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        return sock.getsockname()[1]
