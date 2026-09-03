"""Static remediation metadata for the 17-attack benchmark.

Remediation guidance is kept here, separate from the normalizer, so that the
normalizer remains a pure observation-to-result mapping and so that attack
metadata can evolve independently of normalization logic.

Each entry targets the Agentic Firewall policy model as the primary remediation
lever, with a secondary note for target/application-level hardening where the
firewall alone is insufficient.

Usage:
    meta = ATTACK_METADATA.get(attack_id)
    remediation = meta.remediation if meta else None
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


# Attacks covered by this benchmark - used for completeness validation.
BENCHMARK_ATTACK_IDS = frozenset(range(1, 18))  # 1..17


@dataclass(frozen=True)
class AttackMetadata:
    attack_id: int
    remediation: str


ATTACK_METADATA: dict[int, AttackMetadata] = {
    1: AttackMetadata(
        attack_id=1,
        remediation=(
            "Configure sandbox root boundaries (SANDBOX:<path>) in policy_v2.json "
            "to confine file access to an approved directory. The gateway will then "
            "reject any path that resolves outside the sandbox."
        ),
    ),
    2: AttackMetadata(
        attack_id=2,
        remediation=(
            "Configure sandbox root boundaries (SANDBOX:<path>) in policy_v2.json. "
            "The gateway resolves relative paths before enforcement so that traversal "
            "sequences (../) cannot escape the sandbox."
        ),
    ),
    3: AttackMetadata(
        attack_id=3,
        remediation=(
            "Remove write_file from allowed_tools for untrusted identities in "
            "policy_v2.json. Apply the principle of least privilege: grant only the "
            "tools each identity actually requires."
        ),
    ),
    4: AttackMetadata(
        attack_id=4,
        remediation=(
            "Remove query_database from allowed_tools for untrusted identities in "
            "policy_v2.json. For target-level hardening, the underlying data layer "
            "should use parameterized queries rather than string interpolation."
        ),
    ),
    5: AttackMetadata(
        attack_id=5,
        remediation=(
            "Revoke execute_command from identities that do not require shell access "
            "in policy_v2.json. Apply least-privilege tool grants so untrusted roles "
            "cannot invoke execution tools at all."
        ),
    ),
    6: AttackMetadata(
        attack_id=6,
        remediation=(
            "Enforce strict identity registration in the gateway. Reject sessions from "
            "identities not listed in policy_v2.json at connection time rather than at "
            "individual tool-call time."
        ),
    ),
    7: AttackMetadata(
        attack_id=7,
        remediation=(
            "Remove fetch_url from allowed_tools for untrusted identities, or configure "
            "an egress domain allowlist in policy_v2.json. This prevents SSRF and blocks "
            "access to cloud metadata endpoints (e.g. 169.254.169.254)."
        ),
    ),
    8: AttackMetadata(
        attack_id=8,
        remediation=(
            "Remove fetch_url from allowed_tools for untrusted identities, or restrict "
            "egress to an approved domain allowlist in policy_v2.json to prevent "
            "outbound data exfiltration."
        ),
    ),
    9: AttackMetadata(
        attack_id=9,
        remediation=(
            "Revoke execute_command from untrusted identities in policy_v2.json. "
            "If shell access is legitimately required, use an allowlisted command "
            "interface rather than passing arbitrary shell strings to the target."
        ),
    ),
    10: AttackMetadata(
        attack_id=10,
        remediation=(
            "Revoke execute_command from untrusted identities in policy_v2.json. "
            "If shell access is legitimately required, use an allowlisted command "
            "interface rather than passing arbitrary shell strings to the target."
        ),
    ),
    11: AttackMetadata(
        attack_id=11,
        remediation=(
            "Revoke execute_command from untrusted identities in policy_v2.json. "
            "If shell access is legitimately required, use an allowlisted command "
            "interface rather than passing arbitrary shell strings to the target."
        ),
    ),
    12: AttackMetadata(
        attack_id=12,
        remediation=(
            "Enable Output Guard in policy_v2.json to inspect tool responses and block "
            "canary strings or injected instructions before they reach the agent context."
        ),
    ),
    13: AttackMetadata(
        attack_id=13,
        remediation=(
            "Remove fetch_url from allowed_tools, or enable Output Guard in policy_v2.json "
            "to detect and block injected content returned from fetched URLs."
        ),
    ),
    14: AttackMetadata(
        attack_id=14,
        remediation=(
            "Remove query_database from allowed_tools, or enable Output Guard in "
            "policy_v2.json to detect and block injected content returned from database "
            "queries."
        ),
    ),
    15: AttackMetadata(
        attack_id=15,
        remediation=(
            "Configure circuit breaker thresholds in policy_v2.json. The gateway will "
            "automatically suspend sessions that accumulate repeated security flag "
            "violations, limiting the blast radius of persistent attacks."
        ),
    ),
    16: AttackMetadata(
        attack_id=16,
        remediation=(
            "Enforce tool-level authorization in policy_v2.json so that each unauthorized "
            "tool call is rejected immediately. This prevents flood-based probing of the "
            "policy boundary."
        ),
    ),
    17: AttackMetadata(
        attack_id=17,
        remediation=(
            "The gateway pins session tokens to the authenticated identity at connection "
            "time. Ensure identity verification is enabled in policy_v2.json so that "
            "requests with a mismatched session identity are rejected."
        ),
    ),
}

# Validate completeness at import time so a forgotten entry surfaces immediately.
_missing = BENCHMARK_ATTACK_IDS - set(ATTACK_METADATA)
if _missing:
    raise RuntimeError(  # pragma: no cover
        f"attack_metadata.py is incomplete: missing entries for attack IDs {sorted(_missing)}"
    )
