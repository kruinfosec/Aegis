"""
Compatibility wrapper for Aegis runtime validation.

The old Ganache demo simulation has been replaced with a pluggable runtime
validation service that starts with a Hardhat backend.
"""

from simulation.service import run_runtime_validation, simulation_available


def run_simulation(source_code: str, findings: list, backend_name: str = "hardhat") -> dict:
    """
    Public entry point used by the Flask app.
    """
    return run_runtime_validation(source_code, findings, backend_name=backend_name)


SIMULATION_AVAILABLE = simulation_available()
