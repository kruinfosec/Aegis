"""
Aegis — Smart Contract Vulnerability Scanner
detectors/integer_overflow.py: Detects integer overflow/underflow vulnerabilities.

In Solidity < 0.8.0, arithmetic operations on uint/int types silently wrap around.
For example: uint8 x = 255; x + 1 == 0 (overflow)
Solidity 0.8.0+ has built-in overflow checks, making this less of an issue.
"""

import re


def detect(parsed: dict) -> list:
    """
    Returns a list of findings for integer overflow/underflow vulnerabilities.
    Skips check if contract uses Solidity >= 0.8 (built-in protection).
    """
    findings = []

    # If the contract uses Solidity 0.8+, overflow is handled natively
    if parsed.get("has_overflow_protection"):
        return []

    lines = parsed["lines"]
    source = parsed["source"]

    # Check if SafeMath is imported/used
    uses_safemath = bool(re.search(r'using\s+SafeMath\s+for', source, re.IGNORECASE))
    if uses_safemath:
        return []  # SafeMath protects against overflow

    # Patterns: arithmetic on uint/int without SafeMath
    arithmetic_patterns = [
        (r'\b\w+\s*\+=\s*\w+', '+= (addition assignment)'),
        (r'\b\w+\s*-=\s*\w+', '-= (subtraction assignment)'),
        (r'\b\w+\s*\*=\s*\w+', '*= (multiplication assignment)'),
        (r'\b\w+\s*\+\s*\w+\s*(?:;|,|\))', '+ (addition)'),
        (r'\b\w+\s*-\s*\w+\s*(?:;|,|\))', '- (subtraction)'),
        (r'\b\w+\s*\*\s*\w+\s*(?:;|,|\))', '* (multiplication)'),
    ]

    # Find uint/int variable declarations to know which vars to watch
    uint_vars = set(re.findall(r'\buint\d*\s+(\w+)', source))
    uint_vars |= set(re.findall(r'\bint\d*\s+(\w+)', source))

    flagged_lines = set()

    for line_num, line_content in lines:
        # Skip comments
        stripped = line_content.strip()
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        for pattern, op_name in arithmetic_patterns:
            if re.search(pattern, line_content):
                # Check if any known uint variable is involved
                involved_vars = re.findall(r'\b(\w+)\b', line_content)
                if any(v in uint_vars for v in involved_vars) or uint_vars == set():
                    if line_num not in flagged_lines:
                        flagged_lines.add(line_num)
                        findings.append({
                            "vulnerability": "Integer Overflow / Underflow",
                            "severity": "MEDIUM",
                            "line": line_num,
                            "description": (
                                f"Arithmetic operation ({op_name}) detected on an integer type "
                                f"in a contract using Solidity < 0.8.0 without SafeMath. "
                                f"This may silently overflow or underflow."
                            ),
                            "fix": (
                                "Upgrade to Solidity ^0.8.0 (has built-in overflow checks), "
                                "or use OpenZeppelin's SafeMath library: "
                                "import '@openzeppelin/contracts/utils/math/SafeMath.sol' "
                                "and then 'using SafeMath for uint256;'"
                            ),
                            "code_snippet": _get_lines_around(parsed["lines"], line_num, context=2),
                        })
                        break  # One finding per line

    return findings


def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet_lines = lines[start:end]
    return "\n".join(f"{ln}: {content}" for ln, content in snippet_lines)
