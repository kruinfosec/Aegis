# Aegis - Smart Contract Security Scanner

Aegis is a development-stage smart contract security tool for Solidity projects.
It combines static vulnerability detection with selected Hardhat-backed runtime
validation so findings can be reported as static-only, runtime-confirmed,
not confirmed, inconclusive, unsupported, or failed.

Aegis is not a replacement for a professional audit. It is intended for learning,
local review, regression testing, and repeatable security demos.

## What Aegis Supports Today

### Static detectors

Aegis currently detects common Solidity risk patterns including:

- reentrancy
- integer overflow / underflow
- `tx.origin` misuse
- unprotected `selfdestruct`
- weak randomness
- unchecked low-level call return values
- risky `delegatecall`
- missing access control
- timestamp dependence

### Runtime validation

Runtime validation is implemented through a local Hardhat backend. When runtime is
enabled and a finding belongs to a supported family, Aegis can compile, deploy,
exercise a focused scenario, and merge runtime evidence back into the same report.

Runtime-backed families currently include:

- access control
- reentrancy
- delegatecall
- integer overflow / arithmetic overflow
- timestamp dependence
- weak randomness

Runtime statuses are intentionally conservative:

- `confirmed_by_runtime`: the tested local scenario produced security-relevant evidence.
- `not_confirmed_by_runtime`: the tested path did not confirm a meaningful exploit behavior.
- `inconclusive_runtime`: the shape or evidence was ambiguous.
- `simulation_unsupported`: no suitable runtime scenario was available.
- `simulation_failed`: runtime validation attempted but failed.
- `NOT_RUN`: runtime validation was not requested or did not apply.

Local-chain evidence proves behavior in the tested Hardhat setup. It should not be
overstated as a complete proof of exploitability in every deployed environment.

## Install

Prerequisites:

- Python 3.11+ recommended
- Node.js and npm for Hardhat runtime validation

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Install Node dependencies:

```bash
npm install
```

Static scanning can still run without the Node/Hardhat path. Runtime validation
requires the Python and Node dependencies to be available.

## Quick Start

Run the web app:

```bash
python app.py
```

Open `http://127.0.0.1:5000`, upload a `.sol` file, and review the report. The
web path requests runtime validation when the runtime subsystem is available.

Run the CLI in static mode:

```bash
python aegis.py samples/safe.sol
```

Run the CLI with runtime validation:

```bash
python aegis.py samples/weak_randomness_runtime.sol --runtime
```

Export CLI JSON:

```bash
python aegis.py samples/weak_randomness_runtime.sol --runtime --format json
```

## Curated Demo Workflow

List available demos:

```bash
python scripts/dev.py demos
```

Run the default high-signal runtime demo:

```bash
python scripts/dev.py demo weak-randomness
```

Generate and validate demo JSON:

```bash
python scripts/dev.py json-smoke weak-randomness
```

Start the web app with a suggested demo sample:

```bash
python scripts/dev.py web --sample weak-randomness
```

### Demo Matrix

| Family | Preset | Sample | Mode | What it demonstrates |
| --- | --- | --- | --- | --- |
| Access control | `access-control` | `samples/access.sol` | Runtime | Dynamically testable missing authorization path |
| Reentrancy | `reentrancy` | `samples/reentrancy.sol` | Runtime | Runtime evidence for an externally callable withdrawal path |
| Delegatecall | `delegatecall` | `samples/delegatecall.sol` | Runtime | Delegatecall behavior against attacker-controlled code |
| Arithmetic overflow | `overflow` | `samples/overflow.sol` | Runtime | Arithmetic behavior validated on a vulnerable sample |
| Timestamp dependence | `timestamp` | `samples/timestamp.sol` | Runtime | Local timestamp control changing a relevant path |
| Weak randomness | `weak-randomness` | `samples/weak_randomness_runtime.sol` | Runtime | Predictable or steerable block-derived randomness |
| Weak randomness negative | `weak-randomness-negative` | `samples/weak_randomness_runtime_negative.sol` | Runtime | Honest non-confirming runtime behavior |
| Safe static smoke | `safe-static` | `samples/safe.sol` | Static | Clean no-finding report path |

## Verification Tiers

Use the workflow hub for repeatable checks:

```bash
python scripts/dev.py check fast
python scripts/dev.py check report
python scripts/dev.py check runtime
python scripts/dev.py check demo
python scripts/dev.py check benchmark
python scripts/dev.py check runtime-support
python scripts/dev.py check full
```

Recommended usage:

- `check fast`: quick static/correlation/reporting integration feedback.
- `check report`: Jinja render, route, JSON/export, and reporting safety.
- `check runtime`: Hardhat/runtime-heavy scenario tests.
- `check demo`: generate and validate a known demo JSON report.
- `check benchmark`: run quick curated benchmark fixtures for current runtime families.
- `check runtime-support`: print the support matrix used by runtime filtering.
- `check full`: full `unittest discover tests` sweep before handoff.

The full and runtime tiers are slower than the fast/report tiers because they may
exercise local-chain validation.

## Development Workflow

Focused workflow documentation lives in [docs/dev-workflow.md](docs/dev-workflow.md).

Useful shortcuts:

```bash
python scripts/dev.py check fast
python scripts/dev.py support-matrix
python scripts/dev.py diagnose samples/reentrancy.sol
python scripts/dev.py benchmark run --quick
python scripts/dev.py demo timestamp --dry-run
python scripts/dev.py scaffold price-oracle --dry-run
python scripts/dev.py web
```

Package script aliases are also available:

```bash
npm run demo:list
npm run demo:scan
npm run demo:json
npm run benchmark:list
npm run benchmark:quick
npm run benchmark:full
npm run test:fast
npm run test:report
npm run test:runtime
npm run test:full
npm run verify:demo
npm run verify:benchmark
npm run dev:web
```

## Benchmark / Validation

Aegis includes a lightweight benchmark layer over curated fixtures for the
runtime-backed families. It is intended to make current behavior easy to compare
over time, not to claim broad statistical precision or recall.

List benchmark fixtures:

```bash
python scripts/dev.py benchmark list
```

Run quick validation:

```bash
python scripts/dev.py benchmark run --quick
```

Run one family:

```bash
python scripts/dev.py benchmark run --family timestamp-dependence
```

Write a JSON artifact:

```bash
python scripts/dev.py benchmark run --quick --write
```

Generated benchmark JSON is written under `artifacts/benchmarks/` and ignored by
Git by default.

## Adding A Future Runtime Family

Preview scaffold files:

```bash
python scripts/dev.py scaffold price-oracle --dry-run
```

Create scaffold files:

```bash
python scripts/dev.py scaffold price-oracle
```

The scaffold creates a scenario module, vulnerable sample, negative sample, and
test skeleton. The generated scenario intentionally returns `simulation_unsupported`
until real deploy, execute, evidence, registration, and positive/negative tests are
implemented.

## Project Layout

```text
Aegis/
|-- aegis.py                  # CLI entry point
|-- app.py                    # Flask web app
|-- scripts/dev.py            # Workflow hub
|-- scanner/                  # Static scan, findings, correlation, reporting
|-- simulation/               # Hardhat runtime backend and scenarios
|-- samples/                  # Vulnerable, safe, positive, and negative fixtures
|-- templates/                # Flask/Jinja report UI
|-- static/                   # CSS and JS
|-- tests/                    # Unit, integration, runtime, and render tests
`-- docs/dev-workflow.md      # Focused developer workflow guide
```

## Current Limitations

- Runtime validation only covers selected vulnerability families.
- Runtime evidence is local Hardhat evidence, not a complete audit proof.
- Static detectors are heuristic and may produce false positives or miss variants.
- Unsupported or ambiguous contract shapes should remain `simulation_unsupported`
  or `inconclusive_runtime`, not be forced into confirmed results.
- The tool is development-stage and should be used alongside manual review and
  established audit tooling.

## Author

Kru Infosec - cybersecurity research and smart contract security analysis.
