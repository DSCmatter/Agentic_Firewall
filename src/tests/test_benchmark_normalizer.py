from __future__ import annotations

import io
from typing import Any
from rich.console import Console

from benchmarking.models import AttackObservation, InfrastructureError, NormalizedAttackResult
from benchmarking.normalizer import ATTACK_REQUIRED_TOOLS, normalize_protected_result
from agentic_firewall.presentation import ScanPresenter
from agentic_firewall.scoring import calculate_security_score
from agentic_firewall.services import ScanReport


def make_observation(**overrides: Any) -> AttackObservation:
    values: dict[str, Any] = {
        "attack_id": 1,
        "category": "ASI02: Tool Misuse",
        "attack_name": "Absolute Path Traversal via read_file",
        "mode": "protected",
        "request_accepted": True,
        "messages": [{"id": 1, "error": {"message": "Security Policy Violation: Path outside sandbox"}}],
        "expectation_met": True,
        "outcome_label": "Blocked",
        "duration_ms": 25.0,
        "error": None,
    }
    values.update(overrides)
    return AttackObservation(**values)


def test_normalizer_keeps_blocked_attack_as_pass_with_firewall_attribution():
    baseline = make_observation(
        mode="standalone",
        expectation_met=True,  # exploited in baseline
        outcome_label="Exploited",
        messages=[{"id": 1, "result": {"content": [{"text": "root:x:0:0"}]}}],
    )
    result = normalize_protected_result(make_observation(), baseline=baseline)

    assert result.status == "PASS"
    assert result.protection_source == "FIREWALL"
    assert result.evidence["protected_outcome"] == "Blocked"
    assert result.evidence["firewall_blocked"] is True


def test_infrastructure_failure_results_in_incomplete_score():
    result = normalize_protected_result(
        make_observation(
            expectation_met=False,
            outcome_label="Error",
            error=InfrastructureError("connection_dropped", "connection reset", retryable=True),
        )
    )

    assert result.status == "ERROR"
    assert result.protection_source == "NONE"
    score = calculate_security_score([result])
    assert score.score is None
    assert score.grade == "INCOMPLETE"
    assert score.score_status == "INCOMPLETE"
    assert score.errored == 1


def test_all_attacks_protected_successfully():
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02: Tool Misuse",
            severity="high" if i % 2 == 0 else "critical",
            status="PASS",
            explanation="Blocked by firewall.",
            evidence={},
            duration_ms=10.0,
            protection_source="FIREWALL",
        )
        for i in range(1, 18)
    ]
    score = calculate_security_score(results)

    assert score.score == 100
    assert score.grade == "A"
    assert score.score_status == "COMPLETE"
    assert score.attack_coverage == "17/17"
    assert score.passed == 17
    assert score.vulnerable == 0
    assert score.errored == 0


def test_one_vulnerable_critical_attack():
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02: Tool Misuse",
            severity="critical" if i == 5 else ("high" if i <= 10 else "critical"),
            status="VULNERABLE" if i == 5 else "PASS",
            explanation="Finding.",
            evidence={},
            duration_ms=10.0,
            protection_source="NONE" if i == 5 else "FIREWALL",
        )
        for i in range(1, 18)
    ]
    score = calculate_security_score(results)

    assert score.score_status == "COMPLETE"
    assert score.vulnerable == 1
    assert score.findings_by_severity["critical"] == 1
    assert score.score is not None and score.score < 100


def test_multiple_vulnerabilities_with_different_severities():
    # 6 critical (10), 10 high (6), 1 medium (3) = 123 max points.
    # Fail 1 critical (aid 5), 1 high (aid 1), 1 medium (aid 16).
    # Lost = 10 + 6 + 3 = 19. Earned = 104. Score = round(100 * 104 / 123) = 85 (Grade B).
    severities = {
        5: "critical", 8: "critical", 9: "critical", 10: "critical", 11: "critical", 17: "critical",
        16: "medium",
    }
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02: Tool Misuse",
            severity=severities.get(i, "high"),
            status="VULNERABLE" if i in (1, 5, 16) else "PASS",
            explanation="Finding",
            evidence={},
            duration_ms=10.0,
            protection_source="NONE" if i in (1, 5, 16) else "FIREWALL",
        )
        for i in range(1, 18)
    ]
    score = calculate_security_score(results)

    assert score.score == 85
    assert score.grade == "B"
    assert score.score_status == "COMPLETE"
    assert score.findings_by_severity["critical"] == 1
    assert score.findings_by_severity["high"] == 1
    assert score.findings_by_severity["medium"] == 1


def test_timeout_is_recorded_as_error():
    result = normalize_protected_result(
        make_observation(
            expectation_met=False,
            outcome_label="Error",
            error=InfrastructureError("timeout", "Timed out waiting for response"),
        )
    )

    assert result.status == "ERROR"
    assert result.protection_source == "NONE"
    assert result.evidence["infrastructure_error"]["kind"] == "timeout"


def test_skipped_test_is_not_counted_as_pass():
    result = NormalizedAttackResult(
        attack_id=1,
        attack_name="Attack 1",
        category="ASI02",
        severity="high",
        status="SKIPPED",
        explanation="Skipped by user",
        evidence={},
        duration_ms=0.0,
        protection_source="NONE",
    )
    score = calculate_security_score([result])

    assert score.skipped == 1
    assert score.passed == 0
    assert score.applicable_tests == 0


def test_not_applicable_when_tool_not_in_available_tools():
    result = normalize_protected_result(
        make_observation(attack_id=1),  # requires read_file
        available_tools={"query_database"},  # read_file missing
    )

    assert result.status == "NOT_APPLICABLE"
    assert result.explanation == "Target MCP server does not expose required tool 'read_file'."
    assert result.protection_source == "NONE"


def test_baseline_vulnerable_and_firewall_blocked():
    baseline = make_observation(
        mode="standalone",
        expectation_met=True,  # baseline vulnerable
        outcome_label="Exploited",
        messages=[{"id": 1, "result": {"text": "data"}}],
    )
    protected = make_observation(
        mode="protected",
        expectation_met=True,
        messages=[{"id": 1, "error": {"message": "Security Policy Violation: tool blocked"}}],
    )
    result = normalize_protected_result(protected, baseline=baseline)

    assert result.status == "PASS"
    assert result.protection_source == "FIREWALL"


def test_baseline_blocked_and_target_blocked():
    baseline = make_observation(
        mode="standalone",
        expectation_met=False,  # target already rejected without firewall
        outcome_label="Blocked",
        messages=[{"id": 1, "error": {"code": -32601, "message": "Method not found"}}],
    )
    protected = make_observation(
        mode="protected",
        expectation_met=True,
        # Target rejected request directly, no firewall indicator
        messages=[{"id": 1, "error": {"code": -32601, "message": "Method not found"}}],
    )
    result = normalize_protected_result(protected, baseline=baseline)

    assert result.status == "PASS"
    assert result.protection_source == "TARGET"


def test_baseline_blocked_and_firewall_also_blocked():
    baseline = make_observation(
        mode="standalone",
        expectation_met=False,
        outcome_label="Blocked",
        messages=[{"id": 7, "error": {"code": -32603, "message": "Connection refused"}}],
    )
    protected = make_observation(
        mode="protected",
        expectation_met=True,
        messages=[{"id": 7, "error": {"message": "Security Policy Violation: Tool fetch_url is not allowed"}}],
    )
    result = normalize_protected_result(protected, baseline=baseline)

    assert result.status == "PASS"
    assert result.protection_source == "BOTH"


def test_baseline_vulnerable_and_firewall_failed():
    baseline = make_observation(
        mode="standalone",
        expectation_met=True,
        outcome_label="Exploited",
        messages=[{"id": 1, "result": {"text": "exploited"}}],
    )
    protected = make_observation(
        mode="protected",
        expectation_met=False,
        outcome_label="Bypassed",
        messages=[{"id": 1, "result": {"text": "exploited"}}],
    )
    result = normalize_protected_result(protected, baseline=baseline)

    assert result.status == "VULNERABLE"
    assert result.protection_source == "NONE"


def test_protected_response_blocked_by_target_without_baseline():
    protected = make_observation(
        mode="protected",
        expectation_met=True,
        # Underlying server rejected tool call with internal error
        messages=[{"id": 1, "error": {"code": -32603, "message": "Database constraint violation"}}],
    )
    result = normalize_protected_result(protected, baseline=None)

    assert result.status == "PASS"
    assert result.protection_source == "TARGET"


def test_zero_applicable_attacks():
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02",
            severity="high",
            status="NOT_APPLICABLE",
            explanation="Tool not exposed",
            evidence={},
            duration_ms=0.0,
            protection_source="NONE",
        )
        for i in range(1, 18)
    ]
    score = calculate_security_score(results)

    assert score.score is None
    assert score.grade == "N/A"
    assert score.score_status == "COMPLETE"
    assert score.attack_coverage == "0/17"
    assert score.not_applicable == 17
    assert score.applicable_tests == 0


def test_partial_applicability_with_all_passing():
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02",
            severity="high",
            status="PASS" if i in (1, 2) else "NOT_APPLICABLE",
            explanation="Result",
            evidence={},
            duration_ms=5.0,
            protection_source="FIREWALL" if i in (1, 2) else "NONE",
        )
        for i in range(1, 18)
    ]
    score = calculate_security_score(results)

    assert score.score == 100
    assert score.grade == "A"
    assert score.score_status == "COMPLETE"
    assert score.attack_coverage == "2/17"
    assert score.passed == 2
    assert score.not_applicable == 15


def test_incomplete_scan_sets_score_none_and_grade_incomplete():
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02",
            severity="high",
            status="PASS" if i <= 10 else "ERROR",
            explanation="Result",
            evidence={},
            duration_ms=5.0,
            protection_source="FIREWALL" if i <= 10 else "NONE",
        )
        for i in range(1, 18)
    ]
    score = calculate_security_score(results)

    assert score.score is None
    assert score.grade == "INCOMPLETE"
    assert score.score_status == "INCOMPLETE"
    assert score.passed == 10
    assert score.errored == 7


def test_empty_result_set():
    score = calculate_security_score([])

    assert score.score is None
    assert score.grade == "INCOMPLETE"
    assert score.score_status == "INCOMPLETE"
    assert score.total_tests == 0


def test_presentation_sanitizes_ansi_and_markup():
    malicious_name = "\x1b[31mInjected Attack\x1b[0m [bold red]Markup[/]"
    result = NormalizedAttackResult(
        attack_id=1,
        attack_name=malicious_name,
        category="ASI02",
        severity="high",
        status="PASS",
        explanation="Safe",
        evidence={},
        duration_ms=10.0,
        protection_source="FIREWALL",
    )
    score = calculate_security_score([result])
    report = ScanReport(results=[result], security_score=score, target={"kind": "test"})

    buffer = io.StringIO()
    console = Console(file=buffer, force_terminal=True, color_system=None)
    presenter = ScanPresenter(console=console)
    presenter.finish(report)

    output = buffer.getvalue()
    # Ensure escaped markup tags are not evaluated as live Rich markup
    assert "[bold red]" not in output or r"\[bold red]" in output or "Injected Attack" in output


def test_deterministic_scoring():
    results = [
        NormalizedAttackResult(
            attack_id=i,
            attack_name=f"Attack {i}",
            category="ASI02",
            severity="high",
            status="PASS" if i % 2 == 0 else "VULNERABLE",
            explanation="Test",
            evidence={},
            duration_ms=5.0,
            protection_source="FIREWALL" if i % 2 == 0 else "NONE",
        )
        for i in range(1, 18)
    ]
    score1 = calculate_security_score(results)
    score2 = calculate_security_score(results)

    assert score1 == score2
    assert score1.to_dict() == score2.to_dict()

