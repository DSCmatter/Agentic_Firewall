import re
from typing import Any, List, Tuple

INJECTION_PATTERNS = [
    # OUT_INJECTION_OVERRIDE: Detects prompt override instructions attempting to ignore previous guidelines.
    (
        re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
        "OUT_INJECTION_OVERRIDE",
    ),
    # OUT_INJECTION_SYSTEM_PROMPT: Detects instructions seeking to bypass the system prompt specifically.
    (
        re.compile(r"ignore\s+system\s+prompt", re.IGNORECASE),
        "OUT_INJECTION_SYSTEM_PROMPT",
    ),
    # OUT_INJECTION_CANARY_PASSWD: Detects reading of local Linux system user accounts using /etc/passwd path canary.
    (
        re.compile(r"(read|cat|get|type)\s+/etc/passwd", re.IGNORECASE),
        "OUT_INJECTION_CANARY_PASSWD",
    ),
    # OUT_INJECTION_CANARY_SHADOW: Detects reading of Linux password hashes using /etc/shadow path canary.
    (
        re.compile(r"(read|cat|get|type)\s+/etc/shadow", re.IGNORECASE),
        "OUT_INJECTION_CANARY_SHADOW",
    ),
    # OUT_INJECTION_CANARY_SSH: Detects reading of SSH private keys using ~/.ssh path canary.
    (
        re.compile(r"(read|cat|get|type)\s+~/\.ssh/id_(rsa|dsa|ed25519|ecdsa)", re.IGNORECASE),
        "OUT_INJECTION_CANARY_SSH",
    ),
    # OUT_INJECTION_CANARY_WIN_INI: Detects reading of standard Windows configuration files using win.ini path canary.
    (
        re.compile(r"(read|cat|get|type)\s+.*[/\\]win\.ini", re.IGNORECASE),
        "OUT_INJECTION_CANARY_WIN_INI",
    ),
    # OUT_EXFIL_INTENT: Detects instructions trying to exfiltrate data or send secrets out of the system.
    (
        re.compile(r"exfiltrat(e|ion)|send\s+secrets", re.IGNORECASE),
        "OUT_EXFIL_INTENT",
    ),
]

SECRET_PATTERNS = [
    # OUT_SECRET_AWS_KEY: Detects raw AWS access keys in tool outputs to prevent cloud credential leaks.
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "OUT_SECRET_AWS_KEY"
    ),
    # OUT_SECRET_PRIVATE_KEY: Detects raw SSH/SSL private keys in tool outputs to prevent secret leakage.
    (
        re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
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
