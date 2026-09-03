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


def normalize_protected_result(
    protected: AttackObservation,
    baseline: AttackObservation | None = None,
) -> NormalizedAttackResult:
    """Normalize a gateway observation without reinterpreting attack behavior."""
    evidence = {
        "protected_outcome": protected.outcome_label,
        "request_accepted": protected.request_accepted,
        "response_count": len(protected.messages),
    }
    if baseline is not None:
        evidence["baseline_outcome"] = baseline.outcome_label
        evidence["baseline_expectation_met"] = baseline.expectation_met

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
        )

    if protected.expectation_met:
        return NormalizedAttackResult(
            attack_id=protected.attack_id,
            attack_name=protected.attack_name,
            category=protected.category,
            severity=_SEVERITY_BY_ATTACK_ID[protected.attack_id],
            status="PASS",
            explanation="The gateway blocked the attack according to the existing harness criteria.",
            evidence=evidence,
            duration_ms=protected.duration_ms,
        )

    return NormalizedAttackResult(
        attack_id=protected.attack_id,
        attack_name=protected.attack_name,
        category=protected.category,
        severity=_SEVERITY_BY_ATTACK_ID[protected.attack_id],
        status="FAIL",
        explanation="The attack was not blocked according to the existing harness criteria.",
        evidence=evidence,
        duration_ms=protected.duration_ms,
    )
