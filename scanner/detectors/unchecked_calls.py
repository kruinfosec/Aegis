"""
Aegis — Smart Contract Vulnerability Scanner
detectors/unchecked_calls.py: Detects ignored return values from low-level calls.

When using Solidity's low-level .call(), .send(), or .delegatecall(),
they return a boolean success value that MUST be checked. If ignored,
a failed ETH transfer will pass silently and execution continues —
funds can be lost or logic bypassed without warning.
"""

import re


def detect(parsed: dict) -> list:
    """
    Returns findings for unchecked return values from low-level calls.
    """
    findings = []
    lines = parsed["lines"]

    # Patterns that indicate a low-level call IS present on a line
    call_keywords = [
        (r'\.\s*call\s*(?:\{[^}]*\})?\s*\(', 'call'),
        (r'\.\s*send\s*\(',                   'send'),
        (r'\.\s*delegatecall\s*\(',           'delegatecall'),
    ]

    # Patterns that indicate the return value IS captured (safe)
    safe_capture_patterns = [
        r'\(\s*bool\b',           # (bool success, ...) = ...
        r'bool\s+\w+\s*=',       # bool sent = addr.send(...)
        r'=\s*.*\.(call|send|delegatecall)\s*[\({]',  # any assignment = call
    ]

    seen_lines = set()

    for line_num, line_content in lines:
        stripped = line_content.strip()

        # Skip comments
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        # Skip lines that clearly capture the return value
        if any(re.search(p, line_content) for p in safe_capture_patterns):
            continue

        for pattern, call_type in call_keywords:
            if re.search(pattern, line_content):
                if line_num not in seen_lines:
                    seen_lines.add(line_num)
                    findings.append({
                        "vulnerability": f"Unchecked Return Value ({call_type})",
                        "severity": "LOW",
                        "line": line_num,
                        "description": (
                            f"The return value of a low-level {call_type}() is not checked. "
                            f"If the call fails (e.g. out of gas, reverts), execution continues "
                            f"silently. This can lead to funds being locked or security logic "
                            f"being bypassed without any error thrown."
                        ),
                        "fix": (
                            f"Always capture and check the return value:\n"
                            f"(bool success, ) = addr.{call_type}{{value: amount}}(\"\");\n"
                            f"require(success, 'Transfer failed');"
                        ),
                        "code_snippet": _get_lines_around(lines, line_num, context=2),
                    })
                break

    return findings



def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    return "\n".join(f"{ln}: {content}" for ln, content in lines[start:end])
