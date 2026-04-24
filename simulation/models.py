"""
Structured runtime simulation models for Aegis.

Includes:
- Runtime status constants
- Action/validation records
- Top-level simulation run result with diagnostics
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


RUNTIME_CONFIRMED = "confirmed_by_runtime"
RUNTIME_NOT_CONFIRMED = "not_confirmed_by_runtime"
RUNTIME_INCONCLUSIVE = "inconclusive_runtime"
RUNTIME_UNSUPPORTED = "simulation_unsupported"
RUNTIME_FAILED = "simulation_failed"


@dataclass
class RuntimeActionResult:
    status: str
    action: str
    tx_hash: Optional[str] = None
    reverted: Optional[bool] = None
    error: Optional[str] = None
    account: Optional[str] = None
    function: Optional[str] = None
    arguments: List[Any] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ValidationRecord:
    finding_id: Optional[str]
    check: str
    title: str
    status: str
    backend: str
    scenario: Optional[str] = None
    contract_name: Optional[str] = None
    function_name: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    actions: List[RuntimeActionResult] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["actions"] = [action.to_dict() for action in self.actions]
        return data


@dataclass
class RuntimeDiagnostics:
    """Structured diagnostics for a simulation run.

    These fields enable engineers and future UI/report integration
    to understand exactly what happened during runtime validation.
    """
    # ── Phase that failed (if any) ───────────────────────────────────────
    error_phase: Optional[str] = None  # e.g., "compilation", "backend_startup", "scenario_execution"

    # ── Timing ───────────────────────────────────────────────────────────
    compilation_ms: Optional[float] = None
    backend_startup_ms: Optional[float] = None
    scenario_execution_ms: Optional[float] = None
    total_ms: Optional[float] = None

    # ── Compilation ──────────────────────────────────────────────────────
    compilation_cache_hit: Optional[bool] = None
    compilation_warnings: List[str] = field(default_factory=list)

    # ── Backend ──────────────────────────────────────────────────────────
    startup_retries: int = 0
    backend_port: Optional[int] = None

    # ── Scenario ─────────────────────────────────────────────────────────
    scenarios_attempted: int = 0
    scenarios_succeeded: int = 0
    scenarios_failed: int = 0

    # Runtime finding-filter diagnostics.
    finding_count: int = 0
    finding_checks: List[str] = field(default_factory=list)
    supported_checks: List[str] = field(default_factory=list)
    runtime_eligible_count: int = 0
    runtime_ineligible_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SimulationRunResult:
    backend: str
    status: str
    success: bool
    summary: str
    error: Optional[str] = None
    accounts: List[str] = field(default_factory=list)
    validations: List[ValidationRecord] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    diagnostics: RuntimeDiagnostics = field(default_factory=RuntimeDiagnostics)

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "status": self.status,
            "success": self.success,
            "summary": self.summary,
            "error": self.error,
            "accounts": self.accounts,
            "validations": [validation.to_dict() for validation in self.validations],
            "metadata": self.metadata,
            "diagnostics": self.diagnostics.to_dict(),
            # Backward-compatible fields for the existing UI path.
            "attacks_run": [validation.to_dict() for validation in self.validations],
        }
