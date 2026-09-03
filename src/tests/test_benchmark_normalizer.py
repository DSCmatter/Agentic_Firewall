from benchmarking.models import AttackObservation, InfrastructureError
from benchmarking.normalizer import normalize_protected_result
from agentic_firewall.scoring import calculate_security_score


def make_observation(**overrides):
    values = {
        "attack_id": 1,
        "category": "ASI02: Tool Misuse",
        "attack_name": "Absolute Path Traversal via read_file",
        "mode": "protected",
        "request_accepted": True,
        "messages": [{"id": 1, "error": {"message": "Security Policy Violation"}}],
        "expectation_met": True,
        "outcome_label": "Blocked",
        "duration_ms": 25.0,
        "error": None,
    }
    values.update(overrides)
    return AttackObservation(**values)


def test_normalizer_keeps_blocked_attack_as_pass():
    result = normalize_protected_result(make_observation())

    assert result.status == "PASS"
    assert result.evidence["protected_outcome"] == "Blocked"


def test_infrastructure_failure_is_not_a_security_failure():
    result = normalize_protected_result(
        make_observation(
            expectation_met=False,
            outcome_label="Error",
            error=InfrastructureError("connection_dropped", "connection reset", retryable=True),
        )
    )

    assert result.status == "ERROR"
    assert calculate_security_score([result]).score == 100
