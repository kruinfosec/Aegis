"""
Aegis — Smart Contract Vulnerability Scanner
detectors/selfdestruct.py: Detects unprotected selfdestruct() calls.

selfdestruct(address) destroys the contract and sends all ETH to the given address.
If this is callable by anyone (not guarded by onlyOwner or similar), it's catastrophic.
"""

import re


def detect(parsed: dict) -> list:
    """
    Returns a list of findings for unprotected selfdestruct vulnerabilities.
    """
    findings = []
    source = parsed["source"]
    lines = parsed["lines"]

    # Find all selfdestruct/suicide (old alias) calls
    # Then check if the containing function has access control
    sd_pattern = re.compile(r'\bselfdestruct\s*\(|\bsuicide\s*\(')

    # Common access control patterns
    access_control_patterns = [
        r'\bonlyOwner\b',
        r'\bonlyAdmin\b',
        r'\brequire\s*\(\s*msg\.sender\s*==',
        r'\brequire\s*\(\s*owner\s*==\s*msg\.sender',
        r'\bmodifier\b.*\bonlyOwner\b',
        r'\bisOwner\b',
        r'\bonlyRole\b',
    ]

    # Extract function blocks using a simple heuristic
    # Split source into function-level chunks
    func_pattern = re.compile(
        r'(function\s+\w+[^{]*)(\{)',
        re.DOTALL
    )

    # Track positions of all selfdestruct calls
    for sd_match in sd_pattern.finditer(source):
        sd_pos = sd_match.start()
        line_num = source[:sd_pos].count('\n') + 1

        # Find the enclosing function by looking backwards
        func_start = _find_enclosing_function_start(source, sd_pos)
        func_end = _find_matching_brace(source, func_start) if func_start != -1 else sd_pos

        if func_start != -1:
            func_body = source[func_start:func_end + 1]
            # Check if any access control pattern is present in this function
            has_access_control = any(
                re.search(p, func_body) for p in access_control_patterns
            )
        else:
            func_body = ""
            has_access_control = False

        if not has_access_control:
            call_keyword = sd_match.group(0).strip().rstrip('(')
            findings.append({
                "vulnerability": f"Unprotected {call_keyword}()",
                "severity": "CRITICAL",
                "line": line_num,
                "description": (
                    f"A '{call_keyword}()' call was found that does not appear to be "
                    f"protected by an access control modifier (e.g., onlyOwner) or a "
                    f"require(msg.sender == owner) check. Any external attacker could "
                    f"trigger this to permanently destroy the contract and steal all ETH."
                ),
                "fix": (
                    f"Restrict the function containing '{call_keyword}()' to the contract "
                    f"owner using the onlyOwner modifier from OpenZeppelin's Ownable, "
                    f"or add: require(msg.sender == owner, 'Not authorized');"
                ),
                "code_snippet": _get_lines_around(lines, line_num, context=3),
            })

    return findings


def _find_enclosing_function_start(source: str, pos: int) -> int:
    """Find the start position of the enclosing function body (the opening brace)."""
    # Search backwards from pos for 'function' keyword
    substr = source[:pos]
    func_matches = list(re.finditer(r'\bfunction\b', substr))
    if not func_matches:
        return -1
    # Take the last (nearest) function keyword
    last_func = func_matches[-1]
    # Find the opening brace after this function keyword
    brace_pos = source.find('{', last_func.end())
    return brace_pos if brace_pos != -1 and brace_pos < pos else -1


def _find_matching_brace(source: str, open_brace_pos: int) -> int:
    """Find the position of the closing brace matching the opening brace at open_brace_pos."""
    depth = 0
    for i in range(open_brace_pos, len(source)):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return i
    return len(source) - 1


def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet_lines = lines[start:end]
    return "\n".join(f"{ln}: {content}" for ln, content in snippet_lines)
