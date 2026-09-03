"""Convert benchmark observations into stable, presentation-independent results."""

from __future__ import annotations

from benchmarking.models import AttackObservation, NormalizedAttackResult


_SEVERITY_BY_ATTACK_ID = {
    1: "high", 2: "high", 3: "high", 4: "high",
    5: "critical", 6: "high", 7: "high", 8: "critical",
    9: "critical", 10: "critical", 11: "critical",
    12: "high", 13: "high", 14: "high",
    15: "high", 16: "medium", 17: "critical",
}


ATTACK_REQUIRED_TOOLS: dict[int, str] = {
    1: "read_file",
    2: "read_file",
    3: "write_file",
    4: "query_database",
    5: "execute_command",
    6: "read_file",
    7: "fetch_url",
    8: "fetch_url",
    9: "execute_command",
    10: "execute_command",
    11: "execute_command",
    12: "read_file",
    13: "fetch_url",
    14: "query_database",
    15: "read_file",
    16: "execute_command",
    17: "read_file",
}

FIREWALL_INDICATORS = (
    "Security Policy Violation",
    "IDENTITY_NOT_FOUND",
    "SESSION_SUSPENDED",
    "Suspicious tool output blocked",
)


def _detect_block_sources(messages: list[dict[str, Any]]) -> tuple[bool, bool, str | None]:
    """Detect whether firewall or target generated block/rejection messages based on explicit evidence."""
    firewall_blocked = False
    target_blocked = False
    block_reason = None

    for msg in messages:
        if "error" in msg:
            err_msg = str(msg["error"].get("message", ""))
            if any(ind in err_msg for ind in FIREWALL_INDICATORS):
                firewall_blocked = True
                if not block_reason:
                    block_reason = err_msg
            else:
                target_blocked = True
                if not block_reason:
                    block_reason = err_msg

    return firewall_blocked, target_blocked, block_reason


def normalize_protected_result(
    protected: AttackObservation,
    baseline: AttackObservation | None = None,
    available_tools: set[str] | None = None,
) -> NormalizedAttackResult:
    """Normalize a gateway observation with evidence-based attribution and tool applicability."""
    required_tool = ATTACK_REQUIRED_TOOLS.get(protected.attack_id)

    firewall_blocked, target_blocked, block_reason = _detect_block_sources(protected.messages)

    evidence: dict[str, Any] = {
        "protected_outcome": protected.outcome_label,
        "request_accepted": protected.request_accepted,
        "response_count": len(protected.messages),
        "firewall_blocked": firewall_blocked,
        "target_blocked": target_blocked,
    }
    if block_reason:
        evidence["block_reason"] = block_reason
    if baseline is not None:
        evidence["baseline_outcome"] = baseline.outcome_label
        evidence["baseline_expectation_met"] = baseline.expectation_met

    # 1. Tool Applicability Check
    if available_tools is not None and required_tool and required_tool not in available_tools:
        return NormalizedAttackResult(
            attack_id=protected.attack_id,
            attack_name=protected.attack_name,
            category=protected.category,
            severity=_SEVERITY_BY_ATTACK_ID[protected.attack_id],
            status="NOT_APPLICABLE",
            explanation=f"Target MCP server does not expose required tool '{required_tool}'.",
            evidence=evidence,
            duration_ms=protected.duration_ms,
            protection_source="NONE",
        )

    # 2. Infrastructure Error Check
    if protected.error is not None:
        evidence["infrastructure_error"] = protected.error.to_dict()
        return NormalizedAttackResult(
            attack_id=protected.attack_id,
            attack_name=protected.attack_name,
            category=protected.category,
            severity=_SEVERITY_BY_ATTACK_ID[protected.attack_id],
            status="ERROR",
            explanation=(
                "The attack could not be evaluated because the local target or "
                "transport failed; this is not reported as a vulnerability."
            ),
            evidence=evidence,
            duration_ms=protected.duration_ms,
            protection_source="NONE",
        )

    # 3. Successful Protection (PASS)
    if protected.expectation_met:
        # Determine evidence-based protection source
        if baseline is not None and baseline.error is None:
            if baseline.expectation_met:  # Baseline was exploited (vulnerable)
                protection_source = "FIREWALL" if firewall_blocked else ("TARGET" if target_blocked else "UNKNOWN")
            else:  # Baseline was already blocked (resistant)
                if firewall_blocked and target_blocked:
                    protection_source = "BOTH"
                elif firewall_blocked:
                    protection_source = "BOTH"
                elif target_blocked:
                    protection_source = "TARGET"
                else:
                    protection_source = "TARGET"
        else:
            # Baseline not run or had infrastructure failure
            if firewall_blocked and target_blocked:
                protection_source = "BOTH"
            elif firewall_blocked:
                protection_source = "FIREWALL"
            elif target_blocked:
                protection_source = "TARGET"
            else:
                protection_source = "UNKNOWN"

        explanation = (
            "The attack was successfully blocked by the firewall."
            if protection_source == "FIREWALL"
            else "The attack was resisted with layered protection from both firewall and target."
            if protection_source == "BOTH"
            else "The attack was blocked by the underlying target."
            if protection_source == "TARGET"
            else "The attack was blocked according to benchmark criteria."
        )

        return NormalizedAttackResult(
            attack_id=protected.attack_id,
            attack_name=protected.attack_name,
            category=protected.category,
            severity=_SEVERITY_BY_ATTACK_ID[protected.attack_id],
            status="PASS",
            explanation=explanation,
            evidence=evidence,
            duration_ms=protected.duration_ms,
            protection_source=protection_source,
        )

    # 4. Demonstrated Vulnerability (VULNERABLE)
    return NormalizedAttackResult(
        attack_id=protected.attack_id,
        attack_name=protected.attack_name,
        category=protected.category,
        severity=_SEVERITY_BY_ATTACK_ID[protected.attack_id],
        status="VULNERABLE",
        explanation="The attack was not blocked and demonstrated a security vulnerability.",
        evidence=evidence,
        duration_ms=protected.duration_ms,
        protection_source="NONE",
    )

