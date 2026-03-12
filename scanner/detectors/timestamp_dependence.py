import re

def detect(parsed: dict) -> list:
    findings = []
    lines = parsed["lines"]
    
    # Looking for block.timestamp or now inside require(), if(), or while() statements
    timestamp_pattern = r'(require|if|while)\s*\([^;]*\b(block\.timestamp|now)\b[^;]*\)'
    
    for line_num, line_content in lines:
        stripped = line_content.strip()

        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        if re.search(timestamp_pattern, line_content):
            findings.append({
                "vulnerability": "Timestamp Dependence",
                "severity": "LOW",
                "line": line_num,
                "description": (
                    "The contract uses 'block.timestamp' or 'now' in a control flow statement. "
                    "Miners can manipulate the timestamp slightly (e.g. up to 15 seconds) "
                    "to bypass checks or influence random outcomes."
                ),
                "fix": "Do not use block.timestamp for critical logic. If used for long intervals (e.g. days/weeks), it is acceptable. Never use it for randomness.",
                "code_snippet": _get_lines_around(lines, line_num, context=2),
            })
            
    return findings

def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    snippet = "\n".join(f"{line_num}: {content}" for line_num, content in lines[start:end])
    return snippet
