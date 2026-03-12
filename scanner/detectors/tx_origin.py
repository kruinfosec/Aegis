"""
Aegis — Smart Contract Vulnerability Scanner
detectors/tx_origin.py: Detects misuse of tx.origin for authentication.

tx.origin refers to the ORIGINAL sender of the transaction (not the immediate caller).
Using it for authentication allows phishing attacks: a malicious contract can trick
a legitimate user into calling it, and then impersonate them using tx.origin.
"""

import re


def detect(parsed: dict) -> list:
    """
    Returns a list of findings for tx.origin authentication misuse.
    """
    findings = []
    lines = parsed["lines"]

    # Pattern: tx.origin used in require(), if(), or modifier conditions
    tx_origin_patterns = [
        r'require\s*\([^)]*tx\.origin',        # require(tx.origin == ...)
        r'if\s*\([^)]*tx\.origin',             # if(tx.origin == ...)
        r'tx\.origin\s*==',                     # tx.origin == something
        r'==\s*tx\.origin',                     # something == tx.origin
        r'tx\.origin\s*!=',                     # tx.origin != something
        r'modifier\s+\w+[^{]*tx\.origin',       # modifier using tx.origin
    ]

    seen_lines = set()

    for line_num, line_content in lines:
        stripped = line_content.strip()
        # Skip comments
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        for pattern in tx_origin_patterns:
            if re.search(pattern, line_content):
                if line_num not in seen_lines:
                    seen_lines.add(line_num)
                    findings.append({
                        "vulnerability": "tx.origin Authentication Misuse",
                        "severity": "HIGH",
                        "line": line_num,
                        "description": (
                            "tx.origin is used for access control/authentication. "
                            "tx.origin always contains the original EOA (Externally Owned Account) "
                            "that initiated the transaction. A malicious contract can trick a user "
                            "into calling it, and then call your contract — your tx.origin check "
                            "will pass (it'll be the victim's address), allowing unauthorized access."
                        ),
                        "fix": (
                            "Replace tx.origin with msg.sender for authentication checks. "
                            "Example: require(msg.sender == owner, 'Not owner'); "
                            "Only use tx.origin if you specifically need to block contract callers."
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
