"""Curated benchmark fixtures for runtime-backed Aegis families."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class BenchmarkFixture:
    id: str
    family: str
    check: str
    sample: str
    expected_static_found: bool
    expected_runtime_status: str | None
    quick: bool = False
    notes: str = ""


FIXTURES = [
    BenchmarkFixture(
        id="access-control-positive",
        family="access-control",
        check="missing-access-control",
        sample="samples/access.sol",
        expected_static_found=True,
        expected_runtime_status="confirmed_by_runtime",
        quick=True,
        notes="Missing authorization path should be runtime-confirmable.",
    ),
    BenchmarkFixture(
        id="access-control-negative",
        family="access-control",
        check="missing-access-control",
        sample="samples/access_runtime_negative.sol",
        expected_static_found=True,
        expected_runtime_status="not_confirmed_by_runtime",
        notes="Static suspicion exists, but runtime should not confirm exploit-like behavior.",
    ),
    BenchmarkFixture(
        id="reentrancy-positive",
        family="reentrancy",
        check="reentrancy",
        sample="samples/reentrancy.sol",
        expected_static_found=True,
        expected_runtime_status="confirmed_by_runtime",
        quick=True,
        notes="Externally callable withdrawal path should be runtime-confirmable.",
    ),
    BenchmarkFixture(
        id="reentrancy-negative",
        family="reentrancy",
        check="reentrancy",
        sample="samples/reentrancy_runtime_safe.sol",
        expected_static_found=True,
        expected_runtime_status="not_confirmed_by_runtime",
        notes="Static suspicion exists, but runtime should not confirm a reentrant exploit path.",
    ),
    BenchmarkFixture(
        id="delegatecall-positive",
        family="delegatecall",
        check="delegatecall-untrusted-target",
        sample="samples/delegatecall.sol",
        expected_static_found=True,
        expected_runtime_status="confirmed_by_runtime",
        notes="Delegatecall target should be dynamically demonstrable.",
    ),
    BenchmarkFixture(
        id="delegatecall-negative",
        family="delegatecall",
        check="delegatecall-untrusted-target",
        sample="samples/delegatecall_runtime_negative.sol",
        expected_static_found=True,
        expected_runtime_status="not_confirmed_by_runtime",
        notes="Runtime should avoid over-confirming the safer/non-confirming delegatecall shape.",
    ),
    BenchmarkFixture(
        id="overflow-positive",
        family="integer-overflow",
        check="integer-overflow",
        sample="samples/overflow.sol",
        expected_static_found=True,
        expected_runtime_status="simulation_failed",
        quick=True,
        notes="Current public fixture is Solidity 0.6 and fails the local compiler path before runtime confirmation.",
    ),
    BenchmarkFixture(
        id="overflow-negative",
        family="integer-overflow",
        check="integer-overflow",
        sample="samples/overflow_safe.sol",
        expected_static_found=True,
        expected_runtime_status="simulation_failed",
        notes="Current public negative fixture is Solidity 0.6 and fails the local compiler path before runtime non-confirmation.",
    ),
    BenchmarkFixture(
        id="timestamp-positive",
        family="timestamp-dependence",
        check="timestamp-dependence",
        sample="samples/timestamp.sol",
        expected_static_found=True,
        expected_runtime_status="confirmed_by_runtime",
        quick=True,
        notes="Hardhat timestamp control should change a security-relevant outcome.",
    ),
    BenchmarkFixture(
        id="timestamp-negative",
        family="timestamp-dependence",
        check="timestamp-dependence",
        sample="samples/timestamp_runtime_negative.sol",
        expected_static_found=True,
        expected_runtime_status="not_confirmed_by_runtime",
        notes="Runtime should not confirm harmless or non-exploit-like timestamp usage.",
    ),
    BenchmarkFixture(
        id="weak-randomness-positive",
        family="weak-randomness",
        check="predictable-randomness",
        sample="samples/weak_randomness_runtime.sol",
        expected_static_found=True,
        expected_runtime_status="confirmed_by_runtime",
        quick=True,
        notes="Predictable block-derived lottery outcome should be runtime-confirmable.",
    ),
    BenchmarkFixture(
        id="weak-randomness-negative",
        family="weak-randomness",
        check="predictable-randomness",
        sample="samples/weak_randomness_runtime_negative.sol",
        expected_static_found=True,
        expected_runtime_status="not_confirmed_by_runtime",
        quick=True,
        notes="Observation-only randomness-like usage should not be runtime-confirmed.",
    ),
]


def families() -> list[str]:
    return sorted({fixture.family for fixture in FIXTURES})


def select_fixtures(family: str | None = None, *, quick: bool = False) -> list[BenchmarkFixture]:
    selected = FIXTURES
    if family:
        selected = [fixture for fixture in selected if fixture.family == family]
    if quick:
        selected = [fixture for fixture in selected if fixture.quick]
    return list(selected)
