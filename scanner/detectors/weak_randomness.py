"""
Aegis — Smart Contract Vulnerability Scanner
detectors/weak_randomness.py: Detects use of weak on-chain randomness.

Using block.timestamp, block.number, blockhash, or block.difficulty
as a source of randomness is dangerous because miners/validators can
manipulate these values. Attackers can predict or influence outcomes.

This is commonly exploited in lottery, gambling, or NFT mint contracts.
"""

import re


def detect(parsed: dict) -> list:
    """
    Returns findings for weak randomness sources used in contracts.
    """
    findings = []
    lines = parsed["lines"]

    # Sources that are NOT genuinely random (manipulable by validators)
    weak_sources = [
        (r'\bblock\.timestamp\b',  "block.timestamp",  "Miners can slightly manipulate the block timestamp (±15 seconds). It should never be used as a randomness source."),
        (r'\bblock\.number\b',     "block.number",     "Block numbers are predictable and publicly known. Using them as randomness allows attackers to predict outcomes."),
        (r'\bblockhash\s*\(',      "blockhash()",      "blockhash() only works for the last 256 blocks and is predictable/known to miners before inclusion."),
        (r'\bblock\.difficulty\b', "block.difficulty", "block.difficulty (or block.prevrandao post-Merge) should not be used as a sole randomness source — it can be influenced by validators."),
        (r'\bblock\.coinbase\b',   "block.coinbase",   "block.coinbase (the miner's address) is known before the block is mined and must not be used for randomness."),
    ]

    # Contexts where randomness is actually being USED (not just read)
    # Look for these sources used inside assignments, conditions, or modulo ops
    randomness_context_pattern = re.compile(
        r'(%s)\s*(?:%|==|!=|<|>|\)|,|\s*\+|\s*\-)',  # used in an expression
    )

    seen_lines = set()

    for line_num, line_content in lines:
        stripped = line_content.strip()

        # Skip pure comments
        if stripped.startswith('//') or stripped.startswith('*'):
            continue

        for pattern, source_name, explanation in weak_sources:
            if re.search(pattern, line_content):
                if line_num not in seen_lines:
                    seen_lines.add(line_num)
                    findings.append({
                        "vulnerability": f"Weak Randomness Source ({source_name})",
                        "severity": "MEDIUM",
                        "line": line_num,
                        "description": (
                            f"{source_name} is used at this line. {explanation} "
                            f"Contracts using weak randomness for decisions like winner selection, "
                            f"NFT traits, or game outcomes can be predicted or manipulated by "
                            f"miners/validators and front-running bots."
                        ),
                        "fix": (
                            "Use a verifiable, off-chain randomness oracle such as "
                            "Chainlink VRF (Verifiable Random Function). Alternatively, "
                            "use a commit-reveal scheme for trustless on-chain randomness. "
                            "Never use block properties as a primary randomness source."
                        ),
                        "code_snippet": _get_lines_around(parsed["lines"], line_num, context=2),
                    })
                break  # One finding per line

    return findings


def _get_lines_around(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    return "\n".join(f"{ln}: {content}" for ln, content in lines[start:end])
