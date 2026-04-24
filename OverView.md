# Aegis Project Overview

Aegis is a development-stage Solidity security scanner. It combines static
analysis, selected Hardhat-backed runtime validation, correlation, and report
generation across a Flask web UI and CLI.

## Current Purpose

Aegis helps developers and reviewers find common smart contract risk patterns,
then validate selected high-risk findings in a deterministic local Hardhat setup
where a focused runtime scenario exists.

It should be treated as an engineering aid, learning tool, and regression/demo
environment, not as a substitute for a professional audit.

## Main Capabilities

- Static detection for common Solidity risks such as reentrancy, arithmetic
  overflow, weak randomness, timestamp dependence, delegatecall, access control,
  unchecked low-level calls, `tx.origin`, and unprotected `selfdestruct`.
- Runtime validation for selected families using Hardhat Network.
- Correlation that merges runtime results back into static findings.
- Report output through the web UI, CLI text, and CLI/route JSON export.
- Curated demo and verification workflows through `scripts/dev.py`.

## Runtime-Validated Families

Runtime scenarios currently exist for:

- access control
- reentrancy
- delegatecall
- integer overflow / arithmetic overflow
- timestamp dependence
- weak randomness

Runtime evidence is local-chain evidence from the tested scenario. It can support
`confirmed_by_runtime`, `not_confirmed_by_runtime`, `inconclusive_runtime`,
`simulation_unsupported`, or `simulation_failed`, but it should not be overstated
as complete deployment-wide exploit proof.

## Architecture

1. Input enters through the Flask app, CLI, tests, or sample/demo workflow.
2. `scanner.engine` runs static detectors and produces normalized findings.
3. `scanner.pipeline.full_scan()` optionally requests runtime validation.
4. `simulation.service` dispatches supported findings to Hardhat scenarios.
5. `scanner.correlation` merges runtime evidence and statuses into findings.
6. `scanner.report` shapes stable report data for templates and exports.
7. Web, CLI text, and JSON output consume the same enriched result model.

## Developer Workflow

Use the workflow hub for repeatable commands:

```bash
python scripts/dev.py demos
python scripts/dev.py demo weak-randomness
python scripts/dev.py check fast
python scripts/dev.py check runtime
python scripts/dev.py check full
```

See [docs/dev-workflow.md](docs/dev-workflow.md) for the current command guide,
demo matrix, verification tiers, and scaffold flow.
