"""
Shared detector utilities for Aegis.

These helpers provide a lightweight function/modifier context model so
detectors can reason about Solidity source at function scope without pulling in
heavy parsing dependencies.
"""

import re


COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.DOTALL | re.MULTILINE)
IDENT_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b")

EXTERNAL_VALUE_CALL_RE = re.compile(
    r"(?P<target>[a-zA-Z0-9_\.\(\)\[\]\"'\s]+?)\s*\.\s*call\s*\{[^}]*value\s*:[^}]*\}\s*\(",
    re.DOTALL,
)
EXTERNAL_CALL_RE = re.compile(
    r"(?P<target>[a-zA-Z0-9_\.\(\)\[\]\"'\s]+?)\s*\.\s*(?P<kind>call|delegatecall|send|transfer)\s*(?:\{[^}]*\})?\s*\(",
    re.DOTALL,
)
STATE_UPDATE_RE = re.compile(
    r"""
    (?:
        \b[a-zA-Z_][a-zA-Z0-9_]*\s*(?:\[[^\]]+\])?\s*(?:\+=|-=|\*=|/=|=) |
        \+\+[a-zA-Z_][a-zA-Z0-9_]* |
        [a-zA-Z_][a-zA-Z0-9_]*\+\+ |
        --[a-zA-Z_][a-zA-Z0-9_]* |
        [a-zA-Z_][a-zA-Z0-9_]*-- |
        \bdelete\s+[a-zA-Z_][a-zA-Z0-9_\.\[\]]+ |
        \b[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*(?:push|pop)\s*\(
    )
    """,
    re.VERBOSE,
)
MSG_SENDER_AUTH_RE = re.compile(
    r"require\s*\(\s*[^;]*msg\.sender\s*(?:==|!=)\s*[a-zA-Z_][a-zA-Z0-9_\.]*",
    re.DOTALL,
)
ROLE_AUTH_RE = re.compile(
    r"require\s*\(\s*[^;]*(?:hasRole|isOwner|isAdmin|onlyRole|authorized|owner\s*==\s*msg\.sender)",
    re.DOTALL | re.IGNORECASE,
)
SENSITIVE_NAME_RE = re.compile(
    r"(?:mint|burn|transferOwnership|setOwner|upgrade|setImplementation|withdrawAll|"
    r"emergencyWithdraw|kill|destroy|sweep|pause|unpause|rescue|initialize)",
    re.IGNORECASE,
)
DELEGATECALL_RE = re.compile(
    r"(?P<target>[a-zA-Z_][a-zA-Z0-9_\.]*)\s*\.\s*delegatecall\s*\(",
    re.DOTALL,
)

COMMON_AUTH_MODIFIERS = {
    "onlyowner",
    "onlyadmin",
    "onlyrole",
    "auth",
    "authorized",
    "adminonly",
    "owneronly",
    "governanceonly",
}
REENTRANCY_GUARD_MODIFIERS = {
    "nonreentrant",
    "noreentrant",
    "reentrancyguard",
    "mutexguard",
    "lock",
    "locked",
}
VISIBILITY_KEYWORDS = {"public", "external", "internal", "private"}
MUTABILITY_KEYWORDS = {"payable", "view", "pure", "virtual", "override"}
IGNORED_MODIFIER_TOKENS = VISIBILITY_KEYWORDS | MUTABILITY_KEYWORDS | {"returns"}


def strip_comments(source: str) -> str:
    def _repl(match):
        return "".join("\n" if ch == "\n" else " " for ch in match.group(0))

    return COMMENT_RE.sub(_repl, source)


def build_analysis_context(source: str, lines: list) -> dict:
    sanitized = strip_comments(source)
    contracts = _extract_contracts(sanitized, source)
    modifiers = _extract_named_blocks(sanitized, source, "modifier")
    functions = _extract_functions(sanitized, source, contracts)
    modifier_map = {modifier["name"]: modifier for modifier in modifiers}

    for function in functions:
        function["modifier_defs"] = [
            modifier_map[name]
            for name in function["modifiers"]
            if name in modifier_map
        ]
        function["has_auth"] = function_has_auth(function)
        function["has_reentrancy_guard"] = function_has_reentrancy_guard(function)
        function["external_calls"] = find_external_calls(function)
        function["state_updates"] = find_state_updates(function)

    return {
        "sanitized_source": sanitized,
        "contracts": contracts,
        "functions": functions,
        "modifiers": modifiers,
        "modifier_map": modifier_map,
        "lines": lines,
    }


def _extract_contracts(sanitized: str, source: str) -> list:
    contracts = []
    pattern = re.compile(r"\b(?:abstract\s+)?contract\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")
    for match in pattern.finditer(sanitized):
        start = match.start()
        open_brace = sanitized.find("{", match.end())
        if open_brace == -1:
            continue
        close_brace = _find_matching_brace(sanitized, open_brace)
        if close_brace == -1:
            continue
        contracts.append(
            {
                "name": match.group("name"),
                "start": start,
                "end": close_brace,
                "start_line": line_number_from_offset(source, start),
                "end_line": line_number_from_offset(source, close_brace),
            }
        )
    return contracts


def _extract_functions(sanitized: str, source: str, contracts: list) -> list:
    functions = []
    patterns = [
        ("function", re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>.*?)\)", re.DOTALL)),
        ("constructor", re.compile(r"\bconstructor\s*\((?P<params>.*?)\)", re.DOTALL)),
        ("fallback", re.compile(r"\bfallback\s*\((?P<params>.*?)\)", re.DOTALL)),
        ("receive", re.compile(r"\breceive\s*\((?P<params>.*?)\)", re.DOTALL)),
    ]
    for kind, pattern in patterns:
        for match in pattern.finditer(sanitized):
            start = match.start()
            open_brace = sanitized.find("{", match.end())
            if open_brace == -1:
                continue
            close_brace = _find_matching_brace(sanitized, open_brace)
            if close_brace == -1:
                continue

            header = source[start:open_brace].strip()
            body = source[open_brace + 1:close_brace]
            full_text = source[start:close_brace + 1]
            name = match.groupdict().get("name") or kind
            params = _extract_param_names(match.group("params") or "")

            functions.append(
                {
                    "kind": kind,
                    "name": name,
                    "contract_name": _find_enclosing_contract_name(contracts, start, close_brace),
                    "header": header,
                    "body": body,
                    "full_text": full_text,
                    "start": start,
                    "end": close_brace,
                    "start_line": line_number_from_offset(source, start),
                    "end_line": line_number_from_offset(source, close_brace),
                    "params": params,
                    "visibility": _extract_visibility(header),
                    "modifiers": _extract_modifier_names(header),
                }
            )

    functions.sort(key=lambda item: item["start"])
    return functions


def _find_enclosing_contract_name(contracts: list, start: int, end: int) -> str:
    for contract in contracts:
        if contract["start"] <= start and end <= contract["end"]:
            return contract["name"]
    return ""


def _extract_named_blocks(sanitized: str, source: str, keyword: str) -> list:
    pattern = re.compile(rf"\b{keyword}\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<params>.*?)\)", re.DOTALL)
    blocks = []
    for match in pattern.finditer(sanitized):
        start = match.start()
        open_brace = sanitized.find("{", match.end())
        if open_brace == -1:
            continue
        close_brace = _find_matching_brace(sanitized, open_brace)
        if close_brace == -1:
            continue

        blocks.append(
            {
                "name": match.group("name"),
                "header": source[start:open_brace].strip(),
                "body": source[open_brace + 1:close_brace],
                "full_text": source[start:close_brace + 1],
                "start": start,
                "end": close_brace,
                "start_line": line_number_from_offset(source, start),
                "end_line": line_number_from_offset(source, close_brace),
            }
        )
    return blocks


def _find_matching_brace(source: str, open_brace: int) -> int:
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _extract_param_names(params: str) -> list:
    names = []
    for chunk in params.split(","):
        tokens = [token for token in chunk.strip().split() if token]
        if not tokens:
            continue
        candidate = tokens[-1]
        candidate = candidate.replace("memory", "").replace("calldata", "").strip()
        if IDENT_RE.fullmatch(candidate):
            names.append(candidate)
    return names


def _extract_visibility(header: str) -> str:
    lowered = header.lower()
    for keyword in VISIBILITY_KEYWORDS:
        if re.search(rf"\b{keyword}\b", lowered):
            return keyword
    return ""


def _extract_modifier_names(header: str) -> list:
    tail = header[header.rfind(")") + 1:]
    tokens = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", tail)
    modifiers = []
    for token in tokens:
        lowered = token.lower()
        if lowered in IGNORED_MODIFIER_TOKENS:
            continue
        modifiers.append(token)
    return modifiers


def line_number_from_offset(source: str, offset: int) -> int:
    return source[:offset].count("\n") + 1


def function_has_auth(function: dict) -> bool:
    if function.get("visibility") in {"internal", "private"}:
        return True

    modifier_names = {modifier.lower() for modifier in function.get("modifiers", [])}
    if modifier_names & COMMON_AUTH_MODIFIERS:
        return True

    body = function.get("body", "")
    if MSG_SENDER_AUTH_RE.search(body) or ROLE_AUTH_RE.search(body):
        return True

    for modifier in function.get("modifier_defs", []):
        modifier_body = modifier.get("body", "")
        if MSG_SENDER_AUTH_RE.search(modifier_body) or ROLE_AUTH_RE.search(modifier_body):
            return True
        lowered_name = modifier.get("name", "").lower()
        if lowered_name in COMMON_AUTH_MODIFIERS:
            return True

    return False


def function_has_reentrancy_guard(function: dict) -> bool:
    modifier_names = {modifier.lower() for modifier in function.get("modifiers", [])}
    if modifier_names & REENTRANCY_GUARD_MODIFIERS:
        return True

    body = function.get("body", "")
    if re.search(r"require\s*\(\s*!\s*\w+\s*,", body) and re.search(r"\b\w+\s*=\s*true\s*;", body):
        return True

    for modifier in function.get("modifier_defs", []):
        lowered_name = modifier.get("name", "").lower()
        modifier_body = modifier.get("body", "")
        if lowered_name in REENTRANCY_GUARD_MODIFIERS:
            return True
        if re.search(r"require\s*\(\s*!\s*\w+\s*,", modifier_body) and re.search(r"\b\w+\s*=\s*true\s*;", modifier_body):
            return True

    return False


def find_external_calls(function: dict) -> list:
    body = function.get("body", "")
    calls = []
    for match in EXTERNAL_CALL_RE.finditer(body):
        start = match.start()
        line = function["start_line"] + body[:start].count("\n")
        target = " ".join(match.group("target").split())
        kind = match.group("kind")
        calls.append(
            {
                "kind": kind,
                "target": target,
                "line": line,
                "offset": start,
                "sends_value": bool(EXTERNAL_VALUE_CALL_RE.search(match.group(0))) or kind in {"send", "transfer"},
                "unchecked": not _is_checked_call(body, start),
            }
        )
    return calls


def _is_checked_call(body: str, offset: int) -> bool:
    window_start = max(0, offset - 80)
    window_end = min(len(body), offset + 160)
    window = body[window_start:window_end]
    return bool(
        re.search(r"\(\s*bool\b", window)
        or re.search(r"bool\s+[A-Za-z_][A-Za-z0-9_]*\s*=", window)
        or re.search(r"require\s*\(\s*[A-Za-z_][A-Za-z0-9_]*", window)
    )


def find_state_updates(function: dict) -> list:
    body = function.get("body", "")
    updates = []
    for match in STATE_UPDATE_RE.finditer(body):
        text = " ".join(match.group(0).split())
        if text.startswith("require"):
            continue
        start = match.start()
        updates.append(
            {
                "line": function["start_line"] + body[:start].count("\n"),
                "offset": start,
                "text": text,
            }
        )
    return updates


def is_likely_sensitive_function(function: dict) -> bool:
    header = function.get("header", "")
    body = function.get("body", "")
    name = function.get("name", "")
    if function.get("kind") != "function":
        return False
    if SENSITIVE_NAME_RE.search(name):
        return True
    if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", body):
        return True
    if re.search(r"\bdelegatecall\s*\(", body):
        return True
    if re.search(r"\bowner\s*=", body) and re.search(r"\bnewOwner\b", body):
        return True
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*\s*\+=\s*[A-Za-z_][A-Za-z0-9_]*", body) and "mint" in header.lower():
        return True
    return False


def get_code_snippet(lines: list, target_line: int, context: int = 2) -> str:
    start = max(0, target_line - context - 1)
    end = min(len(lines), target_line + context)
    return "\n".join(f"{line_num}: {content}" for line_num, content in lines[start:end])


def function_snippet(lines: list, function: dict, max_lines: int = 8) -> str:
    start = function["start_line"]
    end = min(function["end_line"], start + max_lines - 1)
    subset = lines[start - 1:end]
    return "\n".join(f"{line_num}: {content}" for line_num, content in subset)


def classify_delegatecall_target(function: dict, call: dict) -> dict:
    target = call["target"]
    lowered_target = target.lower()
    params = set(function.get("params", []))
    if target in params:
        return {
            "classification": "user-controlled",
            "confidence": "HIGH",
            "severity": "HIGH",
            "notes": "delegatecall target is supplied directly as a function parameter.",
        }
    if lowered_target in {"implementation", "logic", "target", "impl"}:
        return {
            "classification": "storage-controlled",
            "confidence": "MEDIUM",
            "severity": "MEDIUM" if function_has_auth(function) else "HIGH",
            "notes": "delegatecall target is read from a mutable-looking storage variable.",
        }
    if re.search(r"address\s*\(\s*0x[a-fA-F0-9]{40}\s*\)", target) or re.search(r"0x[a-fA-F0-9]{40}", target):
        return {
            "classification": "hardcoded",
            "confidence": "LOW",
            "severity": "LOW",
            "notes": "delegatecall target appears hardcoded in source.",
        }
    if lowered_target in {"address(this)", "this"}:
        return {
            "classification": "self",
            "confidence": "LOW",
            "severity": "LOW",
            "notes": "delegatecall target appears to be the current contract.",
        }
    return {
        "classification": "unknown",
        "confidence": "MEDIUM",
        "severity": "MEDIUM",
        "notes": "delegatecall target could not be classified confidently from source heuristics.",
    }
