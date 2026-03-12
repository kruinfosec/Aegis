"""
Aegis — Smart Contract Vulnerability Scanner
detectors/reentrancy.py: Detects reentrancy vulnerability patterns.

A reentrancy attack occurs when an external call is made BEFORE updating
the contract's internal state (e.g., balance). The attacker's fallback
function can re-enter the contract and drain funds.
"""

import re


def detect(parsed: dict) -> list:
    """
    Returns a list of findings (dicts) for reentrancy vulnerabilities.
    """
    findings = []
    source = parsed["source"]
    lines = parsed["lines"]

    # Pattern 1: .call{value:...}() or .call.value() before a state update
    # Look for external call patterns followed by state variable assignments
    call_patterns = [
        r'\.\s*call\s*\{[^}]*value\s*:',   # .call{value: ...}
        r'\.\s*call\s*\.\s*value\s*\(',     # .call.value( (older style)
        r'\.\s*transfer\s*\(',              # .transfer(
        r'\.\s*send\s*\(',                  # .send(
    ]

    # Known reentrancy guard modifier names (used in both Pattern 1 & 3)
    GUARD_PATTERNS = [
        r'\bnonReentrant\b',
        r'\bnoReentrant\b',
        r'\breentrantGuard\b',
        r'\bReentrancyGuard\b',
        r'\bmutexGuard\b',
    ]

    # Pattern 2: Look for withdraw-like functions where external call
    # happens before balance/mapping update
    withdraw_pattern = re.compile(
        r'(function\s+\w*[Ww]ithdraw\w*\s*\([^)]*\)[^{]*)\{',
        re.DOTALL
    )

    for match in withdraw_pattern.finditer(source):
        func_sig = match.group(1)  # function signature (before the brace)
        func_start_pos = match.start()
        open_brace_pos = match.end() - 1

        # Extract the full function body using brace matching
        func_body = _extract_body(source, open_brace_pos)

        # Check if function is protected by a reentrancy guard in its signature
        full_func_text = func_sig + func_body
        has_guard = any(re.search(gp, full_func_text) for gp in GUARD_PATTERNS)
        if has_guard:
            continue  # This function is protected — skip

        # Check if external call appears before balance reset
        has_external_call = any(
            re.search(p, func_body) for p in call_patterns
        )
        has_balance_reset = bool(
            re.search(r'balances?\s*\[.*\]\s*=\s*0|balances?\s*\[.*\]\s*-=', func_body)
        )

        if has_external_call and has_balance_reset:
            # Find the approximate line number
            line_num = source[:func_start_pos].count('\n') + 1

            # Check ordering: call before reset is dangerous
            call_pos = min(
                (func_body.find(p_str) for p_str in ['.call', '.transfer', '.send']
                 if p_str in func_body),
                default=-1
            )
            reset_match = re.search(
                r'balances?\s*\[.*\]\s*=\s*0|balances?\s*\[.*\]\s*-=', func_body
            )
            reset_pos = reset_match.start() if reset_match else -1

            if call_pos != -1 and reset_pos != -1 and call_pos < reset_pos:
                findings.append({
                    "vulnerability": "Reentrancy Attack",
                    "severity": "HIGH",
                    "line": line_num,
                    "description": (
                        "A withdraw-like function makes an external call (e.g., .call, "
                        ".transfer) BEFORE updating the sender's balance. An attacker can "
                        "recursively call this function to drain contract funds."
                    ),
                    "fix": (
                        "Apply the Checks-Effects-Interactions pattern: update the internal "
                        "state (balance = 0) BEFORE making any external calls. Alternatively, "
                        "use OpenZeppelin's ReentrancyGuard modifier."
                    ),
                    "code_snippet": _get_lines_around(lines, line_num, context=3),
                })



    # Pattern 3: Generic external call without reentrancy guard
    # Catch other patterns that don't match withdraw naming
    # Known reentrancy guard modifier names (custom + OpenZeppelin)
    guard_patterns = [
        r'\bnonReentrant\b',
        r'\bnoReentrant\b',
        r'\breentrantGuard\b',
        r'\bReentrancyGuard\b',
        r'\bmutexGuard\b',
        r'\blocked\b',           # custom bool lock modifiers
    ]

    for line_num, line_content in lines:
        for pattern in call_patterns:
            if re.search(pattern, line_content):
                # Skip if already caught by withdraw pattern
                already_found = any(
                    abs(f["line"] - line_num) < 5 for f in findings
                )
                if already_found:
                    break

                # Find enclosing function and check for reentrancy guards
                enclosing_func = _get_enclosing_function(source, lines, line_num)
                if enclosing_func:
                    has_guard = any(
                        re.search(gp, enclosing_func) for gp in guard_patterns
                    )
                    if has_guard:
                        break  # Protected — skip this call

                    # Check Checks-Effects-Interactions: state update BEFORE call
                    call_pos_in_func = enclosing_func.find(line_content.strip())
                    state_update = re.search(
                        r'balances?\s*\[|=\s*0\b|\-=\s*|mappings?\s*\[', enclosing_func
                    )
                    if state_update and state_update.start() < call_pos_in_func:
                        break  # CEI pattern followed — skip

                findings.append({
                    "vulnerability": "Potential Reentrancy (External Call Detected)",
                    "severity": "MEDIUM",
                    "line": line_num,
                    "description": (
                        "An external call was detected. If state variables are updated "
                        "after this call, it may be vulnerable to reentrancy attacks."
                    ),
                    "fix": (
                        "Ensure all state changes happen BEFORE external calls (CEI pattern). "
                        "Use OpenZeppelin's ReentrancyGuard nonReentrant modifier as a safety net."
                    ),
                    "code_snippet": _get_lines_around(lines, line_num, context=2),
                })

    return findings


def _extract_body(source: str, open_brace_pos: int) -> str:
    """Extract function body from open_brace_pos using brace matching. Handles nesting."""
    depth = 0
    for i in range(open_brace_pos, len(source)):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[open_brace_pos:i + 1]
    return source[open_brace_pos:]


def _get_enclosing_function(source: str, lines: list, line_num: int) -> str:
    """Returns the source text of the function enclosing the given line number."""
    # Convert line_num to character position
    source_lines = source.splitlines()
    if line_num - 1 >= len(source_lines):
        return ""
    char_pos = sum(len(l) + 1 for l in source_lines[:line_num - 1])

    # Find nearest function keyword before this position
    func_matches = list(re.finditer(r'\bfunction\b', source[:char_pos]))
    if not func_matches:
        return ""
    last_func_pos = func_matches[-1].start()

    # Find opening brace of that function
    open_brace = source.find('{', last_func_pos)
    if open_brace == -1 or open_brace > char_pos:
        return ""

    return source[last_func_pos:] if open_brace >= char_pos else \
        source[last_func_pos:last_func_pos + len(_extract_body(source, open_brace))]




def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    """Returns a small snippet of code around the target line."""
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet_lines = lines[start:end]
    return "\n".join(f"{ln}: {content}" for ln, content in snippet_lines)
