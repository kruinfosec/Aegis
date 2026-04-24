"""
Compilation helpers for runtime validation.

Features:
- Deterministic in-memory compilation cache (keyed by SHA-256 of source).
- Structured diagnostics on every compilation: cache_hit, duration_ms, warnings.
- Configurable subprocess timeout.
"""

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


class CompilationError(RuntimeError):
    pass


@dataclass
class CompiledContract:
    contract_name: str
    abi: list
    bytecode: str
    source_name: str = "AegisInput.sol"


@dataclass
class CompilationResult:
    """Rich result from compile_source, including diagnostics."""
    contracts: List[CompiledContract]
    cache_hit: bool = False
    duration_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)
    source_hash: str = ""


# ── In-memory compilation cache ─────────────────────────────────────────────
# Keyed by SHA-256 of source code.  Values are (contracts, warnings) tuples.
_compilation_cache: Dict[str, Tuple[List[CompiledContract], List[str]]] = {}

# Cache statistics for diagnostics.
_cache_stats = {"hits": 0, "misses": 0}

# Default compilation subprocess timeout (seconds).
DEFAULT_COMPILE_TIMEOUT = 60


def _npx_command() -> str:
    return "npx.cmd" if os.name == "nt" else "npx"


def _source_hash(source_code: str) -> str:
    return hashlib.sha256(source_code.encode("utf-8")).hexdigest()


def solc_available() -> bool:
    executable = _npx_command()
    try:
        result = subprocess.run(
            [executable, "--yes", "solc", "--version"],
            capture_output=True,
            text=True,
            timeout=DEFAULT_COMPILE_TIMEOUT,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def compile_source(
    source_code: str,
    source_name: str = "AegisInput.sol",
    *,
    timeout: int = DEFAULT_COMPILE_TIMEOUT,
    use_cache: bool = True,
) -> List[CompiledContract]:
    """Compile Solidity source and return deployable contracts.

    Uses an in-memory cache keyed by SHA-256 of the source code.
    Identical source recompiled within the same process is served from cache.
    """
    result = compile_source_rich(
        source_code, source_name, timeout=timeout, use_cache=use_cache,
    )
    return result.contracts


def compile_source_rich(
    source_code: str,
    source_name: str = "AegisInput.sol",
    *,
    timeout: int = DEFAULT_COMPILE_TIMEOUT,
    use_cache: bool = True,
) -> CompilationResult:
    """Compile with full diagnostics (cache_hit, duration, warnings)."""
    global _cache_stats

    src_hash = _source_hash(source_code)

    # ── Cache check ──────────────────────────────────────────────────────
    if use_cache and src_hash in _compilation_cache:
        _cache_stats["hits"] += 1
        contracts, warnings = _compilation_cache[src_hash]
        return CompilationResult(
            contracts=contracts,
            cache_hit=True,
            duration_ms=0.0,
            warnings=warnings,
            source_hash=src_hash,
        )

    _cache_stats["misses"] += 1

    # ── Subprocess compilation ───────────────────────────────────────────
    t0 = time.monotonic()
    executable = _npx_command()
    payload = {
        "language": "Solidity",
        "sources": {source_name: {"content": source_code}},
        "settings": {
            "outputSelection": {
                "*": {"*": ["abi", "evm.bytecode.object"]}
            }
        },
    }

    try:
        result = subprocess.run(
            [executable, "--yes", "solc", "--standard-json"],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise CompilationError(
            f"Solidity compilation timed out after {timeout}s. "
            f"This may indicate an issue with solc or the source file."
        )

    duration_ms = (time.monotonic() - t0) * 1000

    if result.returncode != 0:
        raise CompilationError(result.stderr.strip() or "solc returned a non-zero exit code.")

    output = _parse_solc_output(result.stdout)
    errors = output.get("errors", [])
    fatal_errors = [entry for entry in errors if entry.get("severity") == "error"]
    warnings = [
        entry.get("formattedMessage", entry.get("message", "Warning"))
        for entry in errors
        if entry.get("severity") == "warning"
    ]

    if fatal_errors:
        formatted = "; ".join(
            entry.get("formattedMessage", entry.get("message", "Compilation error"))
            for entry in fatal_errors
        )
        raise CompilationError(formatted)

    contracts: Dict[str, Dict[str, Dict[str, object]]] = output.get("contracts", {})
    compiled = []
    for contract_source, items in contracts.items():
        for contract_name, artifact in items.items():
            bytecode = artifact.get("evm", {}).get("bytecode", {}).get("object", "")
            abi = artifact.get("abi", [])
            if not bytecode or not abi:
                continue
            compiled.append(
                CompiledContract(
                    contract_name=contract_name,
                    abi=abi,
                    bytecode=bytecode,
                    source_name=contract_source,
                )
            )

    if not compiled:
        raise CompilationError("No deployable contracts were produced by the Solidity compiler.")

    # ── Populate cache ───────────────────────────────────────────────────
    if use_cache:
        _compilation_cache[src_hash] = (compiled, warnings)

    return CompilationResult(
        contracts=compiled,
        cache_hit=False,
        duration_ms=round(duration_ms, 2),
        warnings=warnings,
        source_hash=src_hash,
    )


# ── Cache management ─────────────────────────────────────────────────────────

def clear_compilation_cache() -> None:
    """Clear the in-memory compilation cache and reset stats."""
    global _cache_stats
    _compilation_cache.clear()
    _cache_stats = {"hits": 0, "misses": 0}


def get_cache_stats() -> dict:
    """Return current cache hit/miss statistics."""
    return dict(_cache_stats)


def get_cache_size() -> int:
    """Return the number of cached compilations."""
    return len(_compilation_cache)


# ── Internal helpers ─────────────────────────────────────────────────────────

def _parse_solc_output(raw_output: str) -> dict:
    cleaned = raw_output.strip()
    if cleaned.startswith(">>>"):
        cleaned = "\n".join(line for line in cleaned.splitlines() if not line.startswith(">>>"))
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise CompilationError(f"Could not parse solc output: {exc}") from exc
