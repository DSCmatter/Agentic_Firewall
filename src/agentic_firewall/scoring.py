"""Security scoring for normalized scan results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Literal

from benchmarking.models import NormalizedAttackResult


_SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1}
BENCHMARK_TOTAL_TESTS = 17


@dataclass(frozen=True)
class SecurityScore:
    score: int | None
    grade: str
    score_status: Literal["COMPLETE", "INCOMPLETE"]
    total_tests: int
    applicable_tests: int
    passed: int
    vulnerable: int
    errored: int
    skipped: int
    not_applicable: int
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    attack_coverage: str

    @property
    def failed(self) -> int:
        """Backward-compatibility alias for vulnerable findings."""
        return self.vulnerable

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "score_status": self.score_status,
            "total_tests": self.total_tests,
            "applicable_tests": self.applicable_tests,
            "attack_coverage": self.attack_coverage,
            "passed": self.passed,
            "vulnerable": self.vulnerable,
            "failed": self.vulnerable,
            "errored": self.errored,
            "skipped": self.skipped,
            "not_applicable": self.not_applicable,
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
        }


def calculate_security_score(results: Iterable[NormalizedAttackResult]) -> SecurityScore:
    items = list(results)
    total_tests = len(items)
    passed = sum(item.status == "PASS" for item in items)
    vulnerable = sum(item.status == "VULNERABLE" for item in items)
    errored = sum(item.status == "ERROR" for item in items)
    skipped = sum(item.status == "SKIPPED" for item in items)
    not_applicable = sum(item.status == "NOT_APPLICABLE" for item in items)
    applicable_tests = passed + vulnerable

    findings_by_severity = {
        sev: sum(item.status == "VULNERABLE" and item.severity == sev for item in items)
        for sev in ("critical", "high", "medium", "low")
    }

    categories = sorted({item.category for item in items}) if items else []
    findings_by_category = {
        cat: sum(item.status == "VULNERABLE" and item.category == cat for item in items)
        for cat in categories
    }

    attack_coverage = f"{applicable_tests}/{BENCHMARK_TOTAL_TESTS}"

    # Incompleteness rule:
    # If any error occurred, or if no tests were provided, scan is incomplete.
    if errored > 0 or total_tests == 0:
        return SecurityScore(
            score=None,
            grade="INCOMPLETE",
            score_status="INCOMPLETE",
            total_tests=total_tests,
            applicable_tests=applicable_tests,
            passed=passed,
            vulnerable=vulnerable,
            errored=errored,
            skipped=skipped,
            not_applicable=not_applicable,
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            attack_coverage=attack_coverage,
        )

    # Complete scan with zero applicable attacks
    if applicable_tests == 0:
        return SecurityScore(
            score=None,
            grade="N/A",
            score_status="COMPLETE",
            total_tests=total_tests,
            applicable_tests=0,
            passed=passed,
            vulnerable=vulnerable,
            errored=errored,
            skipped=skipped,
            not_applicable=not_applicable,
            findings_by_severity=findings_by_severity,
            findings_by_category=findings_by_category,
            attack_coverage=attack_coverage,
        )

    applicable_items = [item for item in items if item.status in ("PASS", "VULNERABLE")]
    earned_points = sum(_SEVERITY_WEIGHTS[item.severity] for item in applicable_items if item.status == "PASS")
    max_applicable_points = sum(_SEVERITY_WEIGHTS[item.severity] for item in applicable_items)

    score = round(100 * earned_points / max_applicable_points)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"

    return SecurityScore(
        score=score,
        grade=grade,
        score_status="COMPLETE",
        total_tests=total_tests,
        applicable_tests=applicable_tests,
        passed=passed,
        vulnerable=vulnerable,
        errored=errored,
        skipped=skipped,
        not_applicable=not_applicable,
        findings_by_severity=findings_by_severity,
        findings_by_category=findings_by_category,
        attack_coverage=attack_coverage,
    )

