"""
Aegis — Smart Contract Vulnerability Scanner
parser.py: Reads and validates uploaded Solidity source files.
"""

import re


def parse(source_code: str) -> dict:
    """
    Parse the raw Solidity source code.
    Returns a dict with:
        - lines: list of (line_number, line_content)
        - source: full raw source string
        - is_valid: bool — whether it looks like valid Solidity
        - error: error message if not valid, else None
        - pragma_version: detected Solidity version string (or None)
        - has_overflow_protection: bool — True if version >= 0.8.x
    """
    lines = source_code.splitlines()
    numbered_lines = [(i + 1, line) for i, line in enumerate(lines)]

    # Basic validity check: must contain 'pragma solidity' or 'contract '
    if not source_code.strip():
        return _error_result("File is empty.")

    has_pragma = bool(re.search(r'pragma\s+solidity', source_code, re.IGNORECASE))
    has_contract = bool(re.search(r'\bcontract\s+\w+', source_code))

    if not has_pragma and not has_contract:
        return _error_result(
            "This does not appear to be a valid Solidity file. "
            "Missing 'pragma solidity' and 'contract' keyword."
        )

    # Detect pragma version
    pragma_version = None
    has_overflow_protection = False
    pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', source_code)
    if pragma_match:
        pragma_version = pragma_match.group(1).strip()
        # Solidity 0.8.x+ has built-in overflow/underflow protection
        version_numbers = re.findall(r'(\d+)\.(\d+)', pragma_version)
        if version_numbers:
            major, minor = int(version_numbers[-1][0]), int(version_numbers[-1][1])
            if major > 0 or minor >= 8:
                has_overflow_protection = True

    return {
        "lines": numbered_lines,
        "source": source_code,
        "is_valid": True,
        "error": None,
        "pragma_version": pragma_version,
        "has_overflow_protection": has_overflow_protection,
    }


def _error_result(message: str) -> dict:
    return {
        "lines": [],
        "source": "",
        "is_valid": False,
        "error": message,
        "pragma_version": None,
        "has_overflow_protection": False,
    }
