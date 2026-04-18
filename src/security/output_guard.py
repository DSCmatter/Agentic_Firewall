import re
from typing import Any, List, Tuple

INJECTION_PATTERNS = [
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        "OUT_INJECTION_OVERRIDE",
    ),
    (
        re.compile(r"ignore\s+system\s+prompt", re.IGNORECASE),
        "OUT_INJECTION_SYSTEM_PROMPT",
    ),
    (re.compile(r"read\s+/etc/passwd", re.IGNORECASE), "OUT_INJECTION_SENSITIVE_READ"),
    (re.compile(r"exfiltrat(e|ion)|send\s+secrets", re.IGNORECASE), "OUT_EXFIL_INTENT"),
]

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "OUT_SECRET_AWS_KEY"),
    (
        re.compile(r"-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----"),
        "OUT_SECRET_PRIVATE_KEY",
    ),
]


def scan_output_text(text: str) -> Tuple[List[str], List[str]]:
    reason_codes: List[str] = []
    snippets: List[str] = []
    for pattern, code in INJECTION_PATTERNS + SECRET_PATTERNS:
        m = pattern.search(text or "")
        if m:
            reason_codes.append(code)
            snippets.append(m.group(0)[:120])
    return reason_codes, snippets


def extract_text_from_result(result_obj: Any) -> str:
    chunks: List[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            chunks.append(value)
        elif isinstance(value, dict):
            txt = value.get("text")
            if isinstance(txt, str):
                chunks.append(txt)
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(result_obj)
    return "\n".join(chunks)
