#!/usr/bin/env python3
"""
Developer workflow shortcuts for Aegis.

The script intentionally stays lightweight: it wraps existing CLI, Flask, and
unittest entry points without changing scanner/runtime architecture.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "artifacts" / "demo_reports"
BENCHMARK_DIR = ROOT / "artifacts" / "benchmarks"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


DEMO_PRESETS = {
    "access-control": {
        "sample": "samples/access.sol",
        "runtime": True,
        "title": "Access control runtime validation",
        "why": "Shows a missing authorization path that can be validated dynamically.",
    },
    "reentrancy": {
        "sample": "samples/reentrancy.sol",
        "runtime": True,
        "title": "Reentrancy runtime validation",
        "why": "Shows runtime evidence for an externally callable withdrawal path.",
    },
    "delegatecall": {
        "sample": "samples/delegatecall.sol",
        "runtime": True,
        "title": "Delegatecall runtime validation",
        "why": "Shows dynamic validation for delegatecall to attacker-controlled code.",
    },
    "overflow": {
        "sample": "samples/overflow.sol",
        "runtime": True,
        "title": "Arithmetic overflow runtime validation",
        "why": "Shows runtime confirmation for arithmetic behavior on a vulnerable sample.",
    },
    "timestamp": {
        "sample": "samples/timestamp.sol",
        "runtime": True,
        "title": "Timestamp dependence runtime validation",
        "why": "Shows local-chain timestamp control changing a security-relevant path.",
    },
    "weak-randomness": {
        "sample": "samples/weak_randomness_runtime.sol",
        "runtime": True,
        "title": "Weak randomness runtime validation",
        "why": "Shows predictable or steerable block-derived randomness in Hardhat.",
    },
    "weak-randomness-negative": {
        "sample": "samples/weak_randomness_runtime_negative.sol",
        "runtime": True,
        "title": "Weak randomness non-confirming runtime case",
        "why": "Shows honest runtime non-confirmation for a non-exploit-like path.",
    },
    "safe-static": {
        "sample": "samples/safe.sol",
        "runtime": False,
        "title": "Static safe-contract smoke demo",
        "why": "Shows the clean no-finding path without starting runtime validation.",
    },
}


VERIFY_COMMANDS = {
    "fast": [
        sys.executable,
        "-m",
        "unittest",
        "tests.test_detector_precision",
        "tests.test_correlation",
        "tests.test_reporting_integration",
    ],
    "report": [
        sys.executable,
        "-m",
        "unittest",
        "tests.test_reporting_integration",
        "tests.test_report_rendering",
    ],
    "runtime": [
        sys.executable,
        "-m",
        "unittest",
        "tests.test_simulation",
        "tests.test_timestamp_runtime",
        "tests.test_weak_randomness_runtime",
    ],
    "full": [
        sys.executable,
        "-m",
        "unittest",
        "discover",
        "tests",
    ],
    "demo": [
        sys.executable,
        "scripts/dev.py",
        "json-smoke",
        "safe-static",
    ],
    "benchmark": [
        sys.executable,
        "scripts/dev.py",
        "benchmark",
        "run",
        "--quick",
    ],
    "runtime-support": [
        sys.executable,
        "scripts/dev.py",
        "support-matrix",
    ],
}


LEGACY_COMMANDS = {
    "fast": ["check", "fast"],
    "report": ["check", "report"],
    "runtime": ["check", "runtime"],
    "demo": ["demo", "weak-randomness"],
    "web": ["web"],
}


SCENARIO_TEMPLATE = '''"""Runtime validation scenario scaffold for {family_title}.

Replace this scaffold with real deploy/execute/evidence logic before enabling
the scenario in simulation.service.
"""

from simulation.models import RuntimeValidation, RuntimeValidationStatus


FAMILY = "{family_slug}"


def supports(finding: dict) -> bool:
    return finding.get("check") == FAMILY


def run(context, finding: dict) -> RuntimeValidation:
    return RuntimeValidation(
        finding_id=finding.get("id"),
        status=RuntimeValidationStatus.SIMULATION_UNSUPPORTED,
        check=finding.get("check", FAMILY),
        scenario=f"{family_slug}.scaffold",
        contract_name=finding.get("contract_name"),
        function_name=finding.get("function"),
        evidence={{
            "classification_reason": (
                "Scaffold only. Add a real runtime scenario before treating this "
                "family as dynamically supported."
            )
        }},
        limitations=["Generated scaffold has no exploit or non-confirming path yet."],
    )
'''


SAMPLE_TEMPLATE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract {contract_name} {{
    // TODO: Replace with a minimal, deterministic sample for {family_title}.
}}
"""


TEST_TEMPLATE = '''import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class Test{class_name}Runtime(unittest.TestCase):
    def test_scaffold_reminder(self):
        self.skipTest("Replace scaffold with runtime-positive and non-confirming tests.")


if __name__ == "__main__":
    unittest.main()
'''


def run_command(command: list[str], *, dry_run: bool = False) -> int:
    if dry_run:
        print(format_command(command))
        return 0
    return subprocess.call(command, cwd=ROOT)


def format_command(command: list[str]) -> str:
    return " ".join(f'"{part}"' if " " in part else part for part in command)


def list_demos(_: argparse.Namespace) -> int:
    print("Available Aegis demos:\n")
    for name, preset in DEMO_PRESETS.items():
        runtime = "runtime" if preset["runtime"] else "static"
        print(f"  {name:<24} {runtime:<7} {preset['sample']}")
        print(f"    {preset['title']} - {preset['why']}")
    print("\nRun one with: python scripts/dev.py demo weak-randomness")
    return 0


def demo_command(args: argparse.Namespace) -> int:
    preset = DEMO_PRESETS[args.name]
    sample = ROOT / preset["sample"]
    command = [
        sys.executable,
        "aegis.py",
        str(sample.relative_to(ROOT)),
        "--format",
        args.format,
    ]
    if preset["runtime"] and not args.static_only:
        command.append("--runtime")

    if args.output:
        output = Path(args.output)
        if not output.is_absolute():
            output = ROOT / output
        command = command + [">", str(output)]
        if args.dry_run:
            print(format_command(command))
            return 0
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8") as handle:
            completed = subprocess.run(command[:-2], cwd=ROOT, text=True, stdout=handle)
        if completed.returncode == 0:
            print(f"Wrote demo output: {output.relative_to(ROOT)}")
        return completed.returncode

    if args.explain:
        print(f"{preset['title']}")
        print(f"Sample : {preset['sample']}")
        print(f"Mode   : {'runtime' if preset['runtime'] and not args.static_only else 'static'}")
        print(f"Why    : {preset['why']}\n")

    return run_command(command, dry_run=args.dry_run)


def check_command(args: argparse.Namespace) -> int:
    return run_command(VERIFY_COMMANDS[args.tier], dry_run=args.dry_run)


def web_command(args: argparse.Namespace) -> int:
    if args.sample:
        preset = DEMO_PRESETS[args.sample]
        print("Suggested demo sample for upload:")
        print(f"  {preset['sample']}")
        print("Then open the generated report in the web UI.\n")
    return run_command([sys.executable, "app.py"], dry_run=args.dry_run)


def json_smoke_command(args: argparse.Namespace) -> int:
    output = REPORT_DIR / f"{args.name}.json"
    demo_args = argparse.Namespace(
        name=args.name,
        format="json",
        output=str(output),
        static_only=args.static_only,
        explain=False,
        dry_run=args.dry_run,
    )
    result = demo_command(demo_args)
    if result != 0 or args.dry_run:
        return result
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"JSON smoke failed: {exc}", file=sys.stderr)
        return 1
    if not isinstance(payload, list) or not payload:
        print("JSON smoke failed: expected a non-empty list of scan results.", file=sys.stderr)
        return 1
    first = payload[0]
    required = {"success", "filename", "findings", "total_issues"}
    missing = sorted(required - set(first))
    if missing:
        print(f"JSON smoke failed: missing keys {missing}", file=sys.stderr)
        return 1
    print(f"JSON smoke passed: {output.relative_to(ROOT)}")
    return 0


def benchmark_list_command(_: argparse.Namespace) -> int:
    from benchmarks.runner import list_fixtures

    print("Aegis benchmark fixtures:\n")
    for fixture in list_fixtures():
        mode = "quick" if fixture["quick"] else "full"
        expected = fixture["expected_runtime_status"] or "static-only"
        print(f"  {fixture['id']:<28} {fixture['family']:<22} {mode:<5} {fixture['sample']}")
        print(f"    static={fixture['expected_static_found']} runtime={expected}")
    return 0


def benchmark_run_command(args: argparse.Namespace) -> int:
    from benchmarks.runner import known_families, print_summary, run_benchmark, write_artifact

    if args.family and args.family not in known_families():
        print(f"Unknown benchmark family: {args.family}", file=sys.stderr)
        print(f"Known families: {', '.join(known_families())}", file=sys.stderr)
        return 2

    result = run_benchmark(
        family=args.family,
        quick=args.quick,
        run_runtime=not args.static_only,
    )
    print_summary(result)
    if args.output or args.write:
        output = args.output
        if output is None:
            mode = "quick" if args.quick else "full"
            family = args.family or "all"
            output = BENCHMARK_DIR / f"{mode}-{family}.json"
        path = write_artifact(result, output)
        print(f"\nWrote benchmark JSON: {path.relative_to(ROOT)}")
    return 0 if result["summary"]["failed"] == 0 else 1


def support_matrix_command(_: argparse.Namespace) -> int:
    from simulation.support import support_matrix

    print("Aegis runtime support matrix:\n")
    for item in support_matrix():
        caveat = f" Caveat: {item['caveat']}" if item.get("caveat") else ""
        print(f"  {item['check']:<30} {item['family']:<22} scenario={item['scenario']}{caveat}")
    return 0


def diagnose_command(args: argparse.Namespace) -> int:
    from scanner import engine
    from simulation.support import analyze_runtime_eligibility, support_matrix

    target = Path(args.target)
    if not target.is_absolute():
        sample_candidate = ROOT / "samples" / f"{args.target}.sol"
        target = sample_candidate if sample_candidate.exists() else ROOT / args.target
    if not target.exists():
        print(f"Target not found: {target}", file=sys.stderr)
        return 1

    source = target.read_text(encoding="utf-8", errors="ignore")
    scan = engine.scan(source, filename=target.name)
    eligibility = analyze_runtime_eligibility(scan.get("findings", []))
    print(f"Runtime diagnosis for: {target.relative_to(ROOT) if target.is_relative_to(ROOT) else target}")
    print(f"Static findings: {eligibility['total_findings']}")
    print(f"Runtime eligible: {eligibility['eligible_count']}")
    print(f"Runtime ineligible: {eligibility['unsupported_count']}")
    print(f"Found checks: {', '.join(eligibility['found_checks']) or 'none'}")
    print(f"Supported checks: {', '.join(eligibility['supported_checks'])}")

    if scan.get("findings"):
        print("\nFindings:")
        for finding in scan["findings"]:
            eligible = "yes" if finding.get("check") in set(eligibility["supported_checks"]) else "no"
            scope = finding.get("contract_name") or "contract"
            if finding.get("function"):
                scope += f".{finding['function']}()"
            print(f"  - check={finding.get('check')} eligible={eligible} scope={scope} line={finding.get('line')}")

    if args.matrix:
        print("\nSupport matrix:")
        for item in support_matrix():
            print(f"  - {item['check']} -> {item['family']} ({item['scenario']})")

    return 0


def scaffold_command(args: argparse.Namespace) -> int:
    slug = args.family.lower().replace("_", "-")
    module_name = slug.replace("-", "_")
    family_title = slug.replace("-", " ").title()
    class_name = "".join(part.title() for part in slug.split("-"))
    contract_name = f"{class_name}Scaffold"
    files = {
        ROOT / "simulation" / "scenarios" / f"{module_name}.py": SCENARIO_TEMPLATE.format(
            family_slug=slug,
            family_title=family_title,
        ),
        ROOT / "samples" / f"{module_name}_runtime.sol": SAMPLE_TEMPLATE.format(
            contract_name=contract_name,
            family_title=family_title,
        ),
        ROOT / "samples" / f"{module_name}_runtime_negative.sol": SAMPLE_TEMPLATE.format(
            contract_name=f"{contract_name}Negative",
            family_title=f"{family_title} negative/non-confirming case",
        ),
        ROOT / "tests" / f"test_{module_name}_runtime.py": TEST_TEMPLATE.format(
            class_name=class_name,
        ),
    }

    for path, content in files.items():
        rel = path.relative_to(ROOT)
        if path.exists() and not args.force:
            print(f"Would skip existing file: {rel}")
            continue
        if args.dry_run:
            action = "Would overwrite" if path.exists() else "Would create"
            print(f"{action}: {rel}")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"Wrote: {rel}")

    if args.dry_run:
        print("\nDry run only. Re-run without --dry-run to create scaffold files.")
    else:
        print("\nNext: replace scaffold logic, register the scenario, and add positive/negative tests.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Aegis developer workflow hub",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    demos = sub.add_parser("demos", help="List curated demo presets")
    demos.set_defaults(func=list_demos)

    demo = sub.add_parser("demo", help="Run a curated CLI demo")
    demo.add_argument("name", choices=sorted(DEMO_PRESETS))
    demo.add_argument("--format", choices=["text", "json"], default="text")
    demo.add_argument("--output", help="Write output to a file instead of stdout")
    demo.add_argument("--static-only", action="store_true", help="Disable runtime for this demo run")
    demo.add_argument("--dry-run", action="store_true", help="Print the command without running it")
    demo.add_argument("--no-explain", dest="explain", action="store_false", help="Only print scanner output")
    demo.set_defaults(func=demo_command, explain=True)

    check = sub.add_parser("check", help="Run a verification tier")
    check.add_argument("tier", choices=sorted(VERIFY_COMMANDS))
    check.add_argument("--dry-run", action="store_true", help="Print the command without running it")
    check.set_defaults(func=check_command)

    support = sub.add_parser("support-matrix", help="Print runtime-supported checks and scenarios")
    support.set_defaults(func=support_matrix_command)

    diagnose = sub.add_parser("diagnose", help="Explain runtime eligibility for a sample or Solidity file")
    diagnose.add_argument("target", help="Sample slug, sample path, or Solidity file path")
    diagnose.add_argument("--matrix", action="store_true", help="Also print the runtime support matrix")
    diagnose.set_defaults(func=diagnose_command)

    benchmark = sub.add_parser("benchmark", help="Run benchmark/validation fixtures")
    benchmark_sub = benchmark.add_subparsers(dest="benchmark_command", required=True)
    benchmark_list = benchmark_sub.add_parser("list", help="List benchmark fixtures")
    benchmark_list.set_defaults(func=benchmark_list_command)
    benchmark_run = benchmark_sub.add_parser("run", help="Run benchmark fixtures")
    benchmark_run.add_argument("--family", help="Limit to one benchmark family")
    benchmark_run.add_argument("--quick", action="store_true", help="Run only quick benchmark fixtures")
    benchmark_run.add_argument("--static-only", action="store_true", help="Skip runtime validation")
    benchmark_run.add_argument("--write", action="store_true", help="Write JSON artifact to artifacts/benchmarks")
    benchmark_run.add_argument("--output", help="Write JSON artifact to a specific path")
    benchmark_run.set_defaults(func=benchmark_run_command)

    web = sub.add_parser("web", help="Run the Flask web UI")
    web.add_argument("--sample", choices=sorted(DEMO_PRESETS), help="Print a suggested sample before launch")
    web.add_argument("--dry-run", action="store_true", help="Print the command without running it")
    web.set_defaults(func=web_command)

    json_smoke = sub.add_parser("json-smoke", help="Generate and validate JSON output for a demo")
    json_smoke.add_argument("name", choices=sorted(DEMO_PRESETS))
    json_smoke.add_argument("--static-only", action="store_true")
    json_smoke.add_argument("--dry-run", action="store_true")
    json_smoke.set_defaults(func=json_smoke_command)

    scaffold = sub.add_parser("scaffold", help="Create scenario/sample/test scaffold files")
    scaffold.add_argument("family", help="New runtime family slug, e.g. price-oracle")
    scaffold.add_argument("--dry-run", action="store_true")
    scaffold.add_argument("--force", action="store_true", help="Overwrite existing scaffold files")
    scaffold.set_defaults(func=scaffold_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "demo" and len(argv) == 1:
        argv = LEGACY_COMMANDS["demo"]
    elif argv and argv[0] in {"fast", "report", "runtime", "web"}:
        argv = LEGACY_COMMANDS[argv[0]] + argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
