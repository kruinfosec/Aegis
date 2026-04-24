# Aegis Developer Workflow

This page is a compact command guide for local development, verification, and demos.
It is intentionally not a full product README.

## Quick Checks

Run a fast static/reporting check while editing detectors or report formatting:

```bash
python scripts/dev.py check fast
```

Run only report and render safety checks:

```bash
python scripts/dev.py check report
```

Run runtime-heavy checks before touching scenario code:

```bash
python scripts/dev.py check runtime
```

Run the full unittest sweep before a handoff or merge:

```bash
python scripts/dev.py check full
```

Legacy aliases still work:

```bash
python scripts/dev.py fast
python scripts/dev.py report
python scripts/dev.py runtime
```

## Curated Demos

List available demos:

```bash
python scripts/dev.py demos
```

Run a runtime-backed weak-randomness demo:

```bash
python scripts/dev.py demo weak-randomness
```

Run any current runtime-backed family:

```bash
python scripts/dev.py demo access-control
python scripts/dev.py demo reentrancy
python scripts/dev.py demo delegatecall
python scripts/dev.py demo overflow
python scripts/dev.py demo timestamp
python scripts/dev.py demo weak-randomness
```

Run a static safe-contract smoke demo:

```bash
python scripts/dev.py demo safe-static
```

Write demo JSON and validate the basic output shape:

```bash
python scripts/dev.py json-smoke weak-randomness
```

Preview a demo command without running it:

```bash
python scripts/dev.py demo timestamp --dry-run
```

## Demo Matrix

| Preset | Sample | Mode | Use it for |
| --- | --- | --- | --- |
| `access-control` | `samples/access.sol` | runtime | Missing authorization runtime validation |
| `reentrancy` | `samples/reentrancy.sol` | runtime | Reentrancy runtime evidence |
| `delegatecall` | `samples/delegatecall.sol` | runtime | Delegatecall runtime behavior |
| `overflow` | `samples/overflow.sol` | runtime | Arithmetic overflow runtime behavior |
| `timestamp` | `samples/timestamp.sol` | runtime | Timestamp dependence validation |
| `weak-randomness` | `samples/weak_randomness_runtime.sol` | runtime | Predictable or steerable randomness |
| `weak-randomness-negative` | `samples/weak_randomness_runtime_negative.sol` | runtime | Non-confirming randomness behavior |
| `safe-static` | `samples/safe.sol` | static | Empty/no-finding report path |

## Web UI

Start the Flask app:

```bash
python scripts/dev.py web
```

Start it with a suggested sample for upload:

```bash
python scripts/dev.py web --sample weak-randomness
```

## Verification Tiers

Use `check fast` for quick iteration.
Use `check report` after changing templates, report shaping, JSON/export handling, or route behavior.
Use `check runtime` after changing Hardhat scenarios, simulation service behavior, or runtime evidence.
Use `check demo` before showing a demo; it generates and validates a known JSON report.
Use `check benchmark` before changing runtime families or trust/status behavior.
Use `check runtime-support` after changing detector check IDs, runtime dispatch, or support messaging.
Use `check full` before a final handoff.

The runtime and full tiers are intentionally slower. Prefer `check fast` or
`check report` while iterating unless you changed scenario execution or backend
behavior.

## Runtime Eligibility Diagnostics

Print the runtime support matrix:

```bash
python scripts/dev.py support-matrix
```

Diagnose a sample or file:

```bash
python scripts/dev.py diagnose samples/reentrancy.sol
python scripts/dev.py diagnose reentrancy
```

The diagnostic output shows static findings, emitted check keys, runtime-eligible
findings, unsupported findings, and the currently supported runtime checks.

## Benchmark Validation

List curated validation fixtures:

```bash
python scripts/dev.py benchmark list
```

Run the quick benchmark set:

```bash
python scripts/dev.py benchmark run --quick
```

Run one family:

```bash
python scripts/dev.py benchmark run --family weak-randomness
```

Write a JSON artifact:

```bash
python scripts/dev.py benchmark run --quick --write
```

Benchmark output summarizes fixture pass/fail, static hit rate on the curated
fixtures, runtime status counts, family-level timing, and fixture-level details.
Generated JSON lives under `artifacts/benchmarks/` and is ignored by Git.

## Runtime Status Wording

Use the same trust language in issues, demos, and pull requests:

- `confirmed_by_runtime`: the local runtime scenario produced relevant evidence.
- `not_confirmed_by_runtime`: the tested path did not confirm exploit-like behavior.
- `inconclusive_runtime`: the evidence was ambiguous.
- `simulation_unsupported`: no suitable scenario exists for the finding shape.
- `simulation_failed`: runtime was attempted but failed.
- `NOT_RUN`: runtime was not requested or did not apply.

Avoid presenting Hardhat-local evidence as a complete deployment-wide exploit proof.

## Scaffolding A Runtime Family

Preview scaffold files for a future runtime family:

```bash
python scripts/dev.py scaffold price-oracle --dry-run
```

Create scaffold files:

```bash
python scripts/dev.py scaffold price-oracle
```

The scaffold creates:

- `simulation/scenarios/<family>.py`
- `samples/<family>_runtime.sol`
- `samples/<family>_runtime_negative.sol`
- `tests/test_<family>_runtime.py`

The generated scenario intentionally returns `simulation_unsupported` until real deploy,
execute, and evidence logic is implemented.

## Package Script Aliases

If using npm scripts:

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
