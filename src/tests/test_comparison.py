from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agentic_firewall.cli import main
from agentic_firewall.comparison import ComparisonInputError, compare_report_files


def make_report(
    statuses: dict[int, str] | None = None,
    severities: dict[int, str] | None = None,
    *,
    score: int | None = 100,
    grade: str = "A",
    coverage: str = "3/3",
    score_status: str = "COMPLETE",
) -> dict:
    statuses = statuses or {1: "PASS", 2: "PASS", 3: "PASS"}
    severities = severities or {attack_id: "high" for attack_id in statuses}
    results = [
        {
            "attack_id": attack_id,
            "attack_name": f"Display name changed {attack_id}",
            "category": "ASI02: Tool Misuse",
            "severity": severities[attack_id],
            "status": status,
            "protection_source": "FIREWALL" if status == "PASS" else "NONE",
            "explanation": "test",
            "remediation": None,
            "evidence": {},
            "duration_ms": 1.0,
        }
        for attack_id, status in sorted(statuses.items())
    ]
    return {
        "schema_version": "1.1",
        "scanner": {"name": "agentic-firewall", "version": "0.1.0"},
        "benchmark": "owasp-asi-17",
        "target": {"kind": "test"},
        "summary": {
            "score": score,
            "grade": grade,
            "score_status": score_status,
            "attack_coverage": coverage,
            "errored": sum(status == "ERROR" for status in statuses.values()),
            "skipped": sum(status == "SKIPPED" for status in statuses.values()),
            "not_applicable": sum(status == "NOT_APPLICABLE" for status in statuses.values()),
        },
        "results": results,
    }


def write_report(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report), encoding="utf-8")


def compare(tmp_path: Path, before: dict, after: dict):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    write_report(before_path, before)
    write_report(after_path, after)
    return compare_report_files(before_path, after_path)


def test_identical_scans_are_unchanged(tmp_path):
    result = compare(tmp_path, make_report(), make_report())
    assert result.overall_result == "UNCHANGED"
    assert result.score_delta == 0
    assert not result.status_changes


def test_score_improvement_and_resolved_vulnerability(tmp_path):
    before = make_report({1: "VULNERABLE", 2: "PASS", 3: "PASS"}, score=70, grade="C")
    after = make_report({1: "PASS", 2: "PASS", 3: "PASS"}, score=100)
    result = compare(tmp_path, before, after)
    assert result.overall_result == "IMPROVED"
    assert result.score_delta == 30
    assert [item["attack_id"] for item in result.resolved_vulnerabilities] == [1]


def test_score_regression_and_new_vulnerability(tmp_path):
    before = make_report()
    after = make_report({1: "VULNERABLE", 2: "PASS", 3: "PASS"}, score=70, grade="C")
    result = compare(tmp_path, before, after)
    assert result.overall_result == "REGRESSED"
    assert result.score_delta == -30
    assert [item["attack_id"] for item in result.new_vulnerabilities] == [1]


def test_score_delta_alone_classifies_complete_reports(tmp_path):
    improved = compare(tmp_path, make_report(score=80, grade="B"), make_report(score=90, grade="A"))
    regressed = compare(tmp_path, make_report(score=90, grade="A"), make_report(score=80, grade="B"))
    assert improved.overall_result == "IMPROVED"
    assert regressed.overall_result == "REGRESSED"


def test_unchanged_vulnerability(tmp_path):
    reports = make_report({1: "VULNERABLE", 2: "PASS", 3: "PASS"}, score=70, grade="C")
    result = compare(tmp_path, reports, reports)
    assert [item["attack_id"] for item in result.unchanged_vulnerabilities] == [1]


def test_severity_increase_and_decrease(tmp_path):
    before = make_report({1: "VULNERABLE", 2: "PASS", 3: "PASS"}, {1: "high", 2: "high", 3: "high"}, score=80, grade="B")
    after = make_report({1: "VULNERABLE", 2: "PASS", 3: "PASS"}, {1: "critical", 2: "low", 3: "high"}, score=70, grade="C")
    result = compare(tmp_path, before, after)
    assert result.overall_result == "REGRESSED"
    assert {(item["attack_id"], item["direction"]) for item in result.severity_changes} == {(1, "increase"), (2, "decrease")}


def test_status_changes_are_matched_by_attack_id(tmp_path):
    before = make_report({1: "PASS", 2: "VULNERABLE", 3: "PASS"})
    after = make_report({1: "VULNERABLE", 2: "PASS", 3: "ERROR"}, score=None, grade="INCOMPLETE", coverage="2/3", score_status="INCOMPLETE")
    result = compare(tmp_path, before, after)
    changes = {(item["attack_id"], item["before"], item["after"]) for item in result.status_changes}
    assert changes == {(1, "PASS", "VULNERABLE"), (2, "VULNERABLE", "PASS"), (3, "PASS", "ERROR")}
    assert result.overall_result == "INCOMPLETE"


def test_coverage_increase_and_decrease(tmp_path):
    before = make_report({1: "PASS", 2: "NOT_APPLICABLE", 3: "NOT_APPLICABLE"}, score=100, coverage="1/3")
    after = make_report({1: "PASS", 2: "PASS", 3: "NOT_APPLICABLE"}, score=100, coverage="2/3")
    result = compare(tmp_path, before, after)
    assert result.overall_result == "IMPROVED"
    assert result.coverage_delta == 1

    reverse = compare(tmp_path, after, before)
    assert reverse.overall_result == "REGRESSED"
    assert reverse.coverage_delta == -1


def test_special_statuses_are_reported(tmp_path):
    before = make_report({1: "ERROR", 2: "SKIPPED", 3: "NOT_APPLICABLE"}, score=None, grade="INCOMPLETE", coverage="0/3", score_status="INCOMPLETE")
    after = make_report({1: "PASS", 2: "PASS", 3: "PASS"})
    output = compare(tmp_path, before, after).to_dict()
    assert output["special_statuses"]["errors"]["before"] == [1]
    assert output["special_statuses"]["skipped"]["before"] == [2]
    assert output["special_statuses"]["not_applicable"]["before"] == [3]


def test_incomplete_before_and_after_are_incomplete(tmp_path):
    complete = make_report()
    incomplete = make_report({1: "ERROR", 2: "PASS", 3: "PASS"}, score=None, grade="INCOMPLETE", coverage="2/3", score_status="INCOMPLETE")
    assert compare(tmp_path, incomplete, complete).overall_result == "INCOMPLETE"
    assert compare(tmp_path, complete, incomplete).overall_result == "INCOMPLETE"


@pytest.mark.parametrize(
    "before,after,message",
    [
        (make_report({1: "PASS"}), make_report({1: "PASS", 2: "PASS"}), "different attack sets"),
        ({"schema_version": "1.0"}, make_report(), "Unsupported scan schema"),
    ],
)
def test_invalid_report_shapes_are_rejected(tmp_path, before, after, message):
    with pytest.raises(ComparisonInputError, match=message):
        compare(tmp_path, before, after)


def test_duplicate_attack_ids_are_rejected(tmp_path):
    report = make_report()
    report["results"].append(dict(report["results"][0]))
    with pytest.raises(ComparisonInputError, match="Duplicate attack_id"):
        compare(tmp_path, report, make_report())


def test_missing_attack_id_is_rejected(tmp_path):
    report = make_report()
    del report["results"][0]["attack_id"]
    with pytest.raises(ComparisonInputError, match="missing fields"):
        compare(tmp_path, report, make_report())


def test_malformed_json_is_rejected(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text("not json", encoding="utf-8")
    write_report(after, make_report())
    with pytest.raises(ComparisonInputError, match="invalid JSON"):
        compare_report_files(before, after)


def test_missing_file_is_rejected(tmp_path):
    with pytest.raises(ComparisonInputError, match="not found"):
        compare_report_files(tmp_path / "missing.json", tmp_path / "also-missing.json")


def test_json_comparison_output_is_machine_readable(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    write_report(before, make_report())
    write_report(after, make_report({1: "VULNERABLE", 2: "PASS", 3: "PASS"}, score=70, grade="C"))
    runner = CliRunner()
    result = runner.invoke(main, ["compare", str(before), str(after), "--format", "json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["schema_version"] == "1.0"
    assert payload["overall_result"] == "REGRESSED"
    assert payload["new_vulnerabilities"][0]["attack_id"] == 1


def test_compare_rich_output_and_usage_error(tmp_path):
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    write_report(before, make_report())
    write_report(after, make_report())
    runner = CliRunner()
    rich_result = runner.invoke(main, ["compare", str(before), str(after)])
    assert rich_result.exit_code == 0
    assert "Security Regression Report" in rich_result.output
    assert "Delta:  +0 applicable tests" in rich_result.output
    assert "Result: UNCHANGED" in rich_result.output

    missing_result = runner.invoke(main, ["compare", str(before), str(tmp_path / "missing.json")])
    assert missing_result.exit_code == 2
    assert "Report file not found" in missing_result.output
