import re

def detect(parsed: dict) -> list:
    findings = []
    lines = parsed["lines"]
    
    # Sensitive function names that typically require access control
    sensitive_functions = [r'transferOwnership', r'withdrawAll', r'emergencyWithdraw', r'mint', r'burn', r'setOwner', r'kill', r'destroy']
    pattern = r'function\s+(' + '|'.join(sensitive_functions) + r')\s*\('
    
    for line_num, line_content in lines:
        stripped = line_content.strip()

        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        match = re.search(pattern, line_content, re.IGNORECASE)
        if match:
            # Check if it lacks common access control modifiers
            if not re.search(r'\b(onlyOwner|onlyAdmin|onlyRole|internal|private)\b', line_content):
                fn_name = match.group(1)
                findings.append({
                    "vulnerability": f"Missing Access Control in {fn_name}()",
                    "severity": "HIGH",
                    "line": line_num,
                    "description": (
                        f"The '{fn_name}' function appears to modify critical state but "
                        f"lacks an access control modifier (like 'onlyOwner'). "
                        f"This could allow any user to execute this privileged action."
                    ),
                    "fix": "Add a modifier such as 'onlyOwner' (e.g. from OpenZeppelin's Ownable module) or an explicit 'require(msg.sender == owner)' check.",
                    "code_snippet": _get_lines_around(lines, line_num, context=2),
                })
            
    return findings

def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet = "\n".join(f"{line_num}: {content}" for line_num, content in lines[start:end])
    return snippet
