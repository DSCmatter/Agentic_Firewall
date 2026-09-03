"""Security scoring for normalized scan results."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from benchmarking.models import NormalizedAttackResult


@dataclass(frozen=True)
class SecurityScore:
    score: int
    grade: str
    passed: int
    failed: int
    errored: int
    skipped: int

    def to_dict(self) -> dict[str, int | str]:
        return {
            "score": self.score,
            "grade": self.grade,
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "skipped": self.skipped,
        }


_DEDUCTIONS = {"critical": 20, "high": 12, "medium": 7, "low": 3}


def calculate_security_score(results: Iterable[NormalizedAttackResult]) -> SecurityScore:
    items = list(results)
    passed = sum(item.status == "PASS" for item in items)
    failed = sum(item.status == "FAIL" for item in items)
    errored = sum(item.status == "ERROR" for item in items)
    skipped = sum(item.status == "SKIPPED" for item in items)
    score = max(0, 100 - sum(_DEDUCTIONS[item.severity] for item in items if item.status == "FAIL"))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return SecurityScore(score, grade, passed, failed, errored, skipped)
