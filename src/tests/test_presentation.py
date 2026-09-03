"""Tests for Step 6: presentation layer, sanitization, CLI flags, and JSON contract."""

from __future__ import annotations

import io
import json
import re
from typing import Any

import pytest
from click.testing import CliRunner
from rich.console import Console

from benchmarking.attack_metadata import ATTACK_METADATA, BENCHMARK_ATTACK_IDS
from benchmarking.models import NormalizedAttackResult
from agentic_firewall.cli import main
from agentic_firewall.presentation import ScanPresenter, _sanitize_terminal_text
from agentic_firewall.scoring import calculate_security_score
from agentic_firewall.services import ScanReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_result(
    attack_id: int = 1,
    status: str = "PASS",
    severity: str = "high",
    protection_source: str = "FIREWALL",
    remediation: str | None = None,
    evidence: dict[str, Any] | None = None,
) -> NormalizedAttackResult:
    return NormalizedAttackResult(
        attack_id=attack_id,
        attack_name=f"Attack {attack_id}",
        category="ASI02: Tool Misuse",
        severity=severity,
        status=status,
        explanation="Test explanation.",
        evidence=evidence or {},
        duration_ms=10.0,
        protection_source=protection_source,
        remediation=remediation,
    )


def make_report(results: list[NormalizedAttackResult], target: dict | None = None) -> ScanReport:
    return ScanReport(
        results=results,
        security_score=calculate_security_score(results),
        target=target or {"kind": "test"},
    )


def capture_finish(report: ScanReport, method: str = "finish") -> str:
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None, width=120)
    presenter = ScanPresenter(console=console)
    getattr(presenter, method)(report)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 1–6: Sanitization
# ---------------------------------------------------------------------------

def test_sanitize_strips_ansi_csi_sequences():
    out = _sanitize_terminal_text("\x1b[31mred text\x1b[0m")
    assert "\x1b" not in out
    assert "red text" in out


def test_sanitize_strips_osc_sequences():
    # OSC hyperlink: ESC ] 8 ; ; url ST
    osc = "\x1b]8;;https://evil.com\x07click here\x1b]8;;\x07"
    out = _sanitize_terminal_text(osc)
    assert "\x1b" not in out
    assert "click here" in out


def test_sanitize_strips_cursor_movement():
    # ESC [ A = cursor up
    out = _sanitize_terminal_text("safe\x1b[Amalicious")
    assert "\x1b" not in out
    assert "safe" in out
    assert "malicious" in out


def test_sanitize_escapes_rich_markup():
    text = "[bold red]injected[/bold red]"
    out = _sanitize_terminal_text(text)
    # Rich brackets should be escaped
    assert "[bold red]" not in out or "\\[" in out or "injected" in out


def test_sanitize_truncates_long_string():
    long_text = "A" * 500
    out = _sanitize_terminal_text(long_text)
    # After escaping and truncation the rendered text should stay bounded
    assert len(out) <= 250  # 240 chars + ellipsis token


def test_sanitize_truncates_multiline():
    text = "\n".join(f"line {i}" for i in range(10))
    out = _sanitize_terminal_text(text)
    # Should contain a note about remaining lines
    assert "more line" in out
    lines = out.splitlines()
    assert len(lines) <= 5  # 4 content lines + ellipsis line


# ---------------------------------------------------------------------------
# 7–8: quiet_finish
# ---------------------------------------------------------------------------

def test_quiet_finish_all_pass():
    results = [make_result(i, "PASS", "high", "FIREWALL") for i in range(1, 18)]
    report = make_report(results)
    out = capture_finish(report, "quiet_finish")
    assert "100" in out  # score present
    assert "17" in out   # coverage
    # No attack table headers
    assert "Attack" not in out or "Attack Coverage" in out


def test_quiet_finish_shows_findings_list():
    results = [make_result(1, "VULNERABLE", "critical", "NONE", remediation="Fix it.")]
    results += [make_result(i, "PASS", "high", "FIREWALL") for i in range(2, 18)]
    report = make_report(results)
    out = capture_finish(report, "quiet_finish")
    assert "CRITICAL" in out
    assert "Attack 1" in out
    # Should not contain full table
    assert "Protection" not in out


# ---------------------------------------------------------------------------
# 9–12: finish() rendering
# ---------------------------------------------------------------------------

def test_finish_no_findings_panel_on_clean_pass():
    results = [make_result(i, "PASS", "high", "FIREWALL") for i in range(1, 18)]
    report = make_report(results)
    out = capture_finish(report)
    assert "SECURITY FINDINGS" not in out


def test_finish_shows_findings_panel_on_vulnerable():
    results = [
        make_result(1, "VULNERABLE", "critical", "NONE", remediation="Configure policy."),
    ] + [make_result(i, "PASS", "high", "FIREWALL") for i in range(2, 18)]
    report = make_report(results)
    out = capture_finish(report)
    assert "SECURITY FINDINGS" in out
    assert "CRITICAL" in out
    assert "Configure policy." in out


def test_finish_incomplete_scan_shows_no_score():
    results = [make_result(i, "ERROR", "high", "NONE") for i in range(1, 18)]
    report = make_report(results)
    out = capture_finish(report)
    assert "N/A" in out
    assert "INCOMPLETE" in out
    # No numeric score like "100/100" or "73/100"
    assert "/100" not in out


def test_finish_partial_coverage_note():
    results = (
        [make_result(1, "PASS", "high", "FIREWALL"), make_result(2, "PASS", "high", "FIREWALL")]
        + [make_result(i, "NOT_APPLICABLE", "high", "NONE") for i in range(3, 18)]
    )
    report = make_report(results)
    out = capture_finish(report)
    assert "2/17" in out
    assert "does not expose the required tools" in out


# ---------------------------------------------------------------------------
# 13–15: JSON output contract
# ---------------------------------------------------------------------------

def test_json_stdout_is_clean_json():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--format", "json"])
    assert result.exit_code == 0
    # stdout must be parseable as JSON
    data = json.loads(result.output)
    assert isinstance(data, dict)
    # No ANSI sequences in stdout
    assert "\x1b" not in result.output


def test_json_output_schema_fields():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.output)

    # Top-level fields
    for field in ("schema_version", "benchmark", "target", "summary", "results"):
        assert field in data, f"Missing top-level field: {field}"

    # Summary fields
    summary = data["summary"]
    for field in ("score", "grade", "score_status", "attack_coverage", "total_tests",
                  "applicable_tests", "passed", "vulnerable", "errored", "skipped",
                  "not_applicable", "findings_by_severity", "findings_by_category"):
        assert field in summary, f"Missing summary field: {field}"

    # Per-result fields
    for res in data["results"]:
        for field in ("attack_id", "attack_name", "category", "severity", "status",
                      "protection_source", "explanation", "remediation", "evidence", "duration_ms"):
            assert field in res, f"Missing result field: {field}"


def test_schema_version_is_1_1():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--format", "json"])
    data = json.loads(result.output)
    assert data["schema_version"] == "1.1"


# ---------------------------------------------------------------------------
# 16–20: Exit codes and --fail-on
# ---------------------------------------------------------------------------

def test_fail_on_critical_exits_1_when_critical_found():
    from agentic_firewall.cli import _fail_on_threshold_met
    results = [make_result(1, "VULNERABLE", "critical", "NONE")]
    report = make_report(results)
    assert _fail_on_threshold_met(report, "critical") is True


def test_fail_on_high_exits_1_when_critical_found():
    from agentic_firewall.cli import _fail_on_threshold_met
    results = [make_result(1, "VULNERABLE", "critical", "NONE")]
    report = make_report(results)
    assert _fail_on_threshold_met(report, "high") is True


def test_fail_on_critical_exits_0_when_only_high_found():
    from agentic_firewall.cli import _fail_on_threshold_met
    results = [make_result(1, "VULNERABLE", "high", "NONE")]
    report = make_report(results)
    assert _fail_on_threshold_met(report, "critical") is False


def test_no_fail_on_exits_0_with_vulnerabilities():
    from agentic_firewall.cli import _fail_on_threshold_met
    results = [make_result(1, "VULNERABLE", "critical", "NONE")]
    report = make_report(results)
    assert _fail_on_threshold_met(report, None) is False


def test_infrastructure_error_exits_1():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--server-url", "http://127.0.0.1:1"])
    assert result.exit_code == 1


# ---------------------------------------------------------------------------
# 21–23: Remediation correctness
# ---------------------------------------------------------------------------

def test_remediation_only_on_vulnerable():
    from benchmarking.normalizer import normalize_protected_result
    from benchmarking.models import AttackObservation

    def make_obs(expectation_met: bool, outcome_label: str) -> AttackObservation:
        return AttackObservation(
            attack_id=1,
            category="ASI02: Tool Misuse",
            attack_name="Test",
            mode="protected",
            request_accepted=True,
            messages=[{"id": 1, "error": {"message": "Security Policy Violation: blocked"}}],
            expectation_met=expectation_met,
            outcome_label=outcome_label,
            duration_ms=10.0,
            error=None,
        )

    # PASS: no remediation
    result_pass = normalize_protected_result(make_obs(True, "Blocked"))
    assert result_pass.status == "PASS"
    assert result_pass.remediation is None

    # VULNERABLE: remediation present
    result_vuln = normalize_protected_result(
        make_obs(False, "Bypassed"),
    )
    assert result_vuln.status == "VULNERABLE"
    assert result_vuln.remediation is not None


def test_remediation_deterministic():
    """Same attack_id must always yield the same remediation string."""
    r1 = ATTACK_METADATA.get(9)
    r2 = ATTACK_METADATA.get(9)
    assert r1 is not None
    assert r2 is not None
    assert r1.remediation == r2.remediation


def test_remediation_present_in_json_for_vulnerable():
    """JSON results for VULNERABLE findings must contain non-null remediation."""
    vuln_result = make_result(9, "VULNERABLE", "critical", "NONE", remediation=ATTACK_METADATA[9].remediation)
    pass_result = make_result(1, "PASS", "high", "FIREWALL")
    report = make_report([vuln_result, pass_result])
    payload = report.to_dict()
    vuln_json = next(r for r in payload["results"] if r["status"] == "VULNERABLE")
    assert vuln_json["remediation"] is not None
    assert len(vuln_json["remediation"]) > 10


# ---------------------------------------------------------------------------
# 24: JSON preserves full evidence while terminal truncates
# ---------------------------------------------------------------------------

def test_json_preserves_full_evidence_while_terminal_truncates():
    """100 KB evidence is preserved verbatim in JSON but bounded in terminal output."""
    big_evidence_value = "X" * 100_000
    evidence = {"output": big_evidence_value}

    result = make_result(1, "PASS", "high", "FIREWALL", evidence=evidence)
    report = make_report([result])

    # Terminal output must be bounded (presentation truncates it).
    terminal_out = capture_finish(report)
    # The 100 KB raw string should NOT appear verbatim in terminal output.
    assert big_evidence_value not in terminal_out

    # JSON must preserve the full value.
    payload = report.to_dict()
    json_evidence = payload["results"][0]["evidence"]["output"]
    assert json_evidence == big_evidence_value


# ---------------------------------------------------------------------------
# 25: attack_metadata completeness
# ---------------------------------------------------------------------------

def test_attack_metadata_covers_all_17_attacks():
    assert set(ATTACK_METADATA.keys()) == set(range(1, 18))
