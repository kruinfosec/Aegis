import re

def detect(parsed: dict) -> list:
    findings = []
    lines = parsed["lines"]
    
    # Pattern: \w+\.delegatecall\(.*\)
    delegatecall_pattern = r'\b\w+\.delegatecall\b'

    for line_num, line_content in lines:
        stripped = line_content.strip()

        # Skip comments
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        if re.search(delegatecall_pattern, line_content):
            findings.append({
                "vulnerability": "Delegatecall to Untrusted Contract",
                "severity": "HIGH",
                "line": line_num,
                "description": (
                    "The contract uses 'delegatecall', which executes code "
                    "from another contract in the context of this contract. "
                    "If the target address is user-controlled, an attacker "
                    "can execute malicious code to drain funds or destroy the contract."
                ),
                "fix": "Avoid using delegatecall unless absolutely necessary. Ensure the target address is hardcoded, trusted, and cannot be changed by unauthorized users.",
                "code_snippet": _get_lines_around(lines, line_num, context=2),
            })
            
    return findings

def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet = "\n".join(f"{line_num}: {content}" for line_num, content in lines[start:end])
    return snippet
