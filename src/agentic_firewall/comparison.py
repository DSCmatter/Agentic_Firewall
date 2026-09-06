"""Offline comparison of saved Agentic Firewall scan reports."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCAN_SCHEMA_VERSION = "1.1"
COMPARISON_SCHEMA_VERSION = "1.0"
_STATUS_VALUES = {"PASS", "VULNERABLE", "ERROR", "SKIPPED", "NOT_APPLICABLE"}
_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_COVERAGE_PATTERN = re.compile(r"^(\d+)/(\d+)$")


class ComparisonInputError(ValueError):
    """A saved report cannot be safely compared."""


@dataclass(frozen=True)
class AttackSnapshot:
    attack_id: int
    attack_name: str
    severity: str
    status: str
    protection_source: str


@dataclass(frozen=True)
class ScanSnapshot:
    path: Path
    summary: dict[str, Any]
    attacks: dict[int, AttackSnapshot]

    @property
    def incomplete(self) -> bool:
        return self.summary["score_status"] == "INCOMPLETE" or self.summary["errored"] > 0

    @property
    def coverage(self) -> tuple[int, int]:
        match = _COVERAGE_PATTERN.fullmatch(self.summary["attack_coverage"])
        assert match is not None
        return int(match.group(1)), int(match.group(2))


@dataclass(frozen=True)
class ComparisonResult:
    before: ScanSnapshot
    after: ScanSnapshot
    new_vulnerabilities: tuple[dict[str, Any], ...]
    resolved_vulnerabilities: tuple[dict[str, Any], ...]
    unchanged_vulnerabilities: tuple[dict[str, Any], ...]
    severity_changes: tuple[dict[str, Any], ...]
    status_changes: tuple[dict[str, Any], ...]
    protection_source_changes: tuple[dict[str, Any], ...]
    overall_result: str

    @property
    def score_delta(self) -> float | None:
        before_score = self.before.summary["score"]
        after_score = self.after.summary["score"]
        if before_score is None or after_score is None:
            return None
        return round(after_score - before_score, 2)

    @property
    def coverage_delta(self) -> int:
        return self.after.coverage[0] - self.before.coverage[0]

    def to_dict(self) -> dict[str, Any]:
        before_coverage = self.before.coverage
        after_coverage = self.after.coverage
        return {
            "schema_version": COMPARISON_SCHEMA_VERSION,
            "comparison": "agentic-firewall-scan",
            "before": {
                "path": str(self.before.path),
                "summary": self.before.summary,
            },
            "after": {
                "path": str(self.after.path),
                "summary": self.after.summary,
            },
            "score_delta": self.score_delta,
            "coverage_delta": {
                "before": self.before.summary["attack_coverage"],
                "after": self.after.summary["attack_coverage"],
                "applicable_tests_delta": self.coverage_delta,
            },
            "new_vulnerabilities": list(self.new_vulnerabilities),
            "resolved_vulnerabilities": list(self.resolved_vulnerabilities),
            "unchanged_vulnerabilities": list(self.unchanged_vulnerabilities),
            "severity_changes": list(self.severity_changes),
            "status_changes": list(self.status_changes),
            "protection_source_changes": list(self.protection_source_changes),
            "status_counts": {
                "before": _status_counts(self.before.attacks.values()),
                "after": _status_counts(self.after.attacks.values()),
            },
            "special_statuses": {
                "errors": {
                    "before": _ids_with_status(self.before.attacks, "ERROR"),
                    "after": _ids_with_status(self.after.attacks, "ERROR"),
                },
                "skipped": {
                    "before": _ids_with_status(self.before.attacks, "SKIPPED"),
                    "after": _ids_with_status(self.after.attacks, "SKIPPED"),
                },
                "not_applicable": {
                    "before": _ids_with_status(self.before.attacks, "NOT_APPLICABLE"),
                    "after": _ids_with_status(self.after.attacks, "NOT_APPLICABLE"),
                },
            },
            "incomplete": self.before.incomplete or self.after.incomplete,
            "overall_result": self.overall_result,
        }


def load_scan_report(path: Path) -> ScanSnapshot:
    """Load and validate one schema-1.1 scan report."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ComparisonInputError(f"Report file not found: {path}") from exc
    except OSError as exc:
        raise ComparisonInputError(f"Could not read report file '{path}': {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ComparisonInputError(f"Report is not valid UTF-8 JSON: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ComparisonInputError(f"Report contains invalid JSON: {path} ({exc.msg})") from exc

    if not isinstance(raw, dict):
        raise ComparisonInputError(f"Report must contain a JSON object: {path}")
    if raw.get("schema_version") != SCAN_SCHEMA_VERSION:
        raise ComparisonInputError(
            f"Unsupported scan schema in '{path}'; expected {SCAN_SCHEMA_VERSION!r}."
        )
    summary = raw.get("summary")
    results = raw.get("results")
    if not isinstance(summary, dict):
        raise ComparisonInputError(f"Report summary must be an object: {path}")
    if not isinstance(results, list):
        raise ComparisonInputError(f"Report results must be an array: {path}")

    required_summary = {
        "score",
        "grade",
        "score_status",
        "attack_coverage",
        "errored",
        "skipped",
        "not_applicable",
    }
    missing_summary = sorted(required_summary - summary.keys())
    if missing_summary:
        raise ComparisonInputError(
            f"Report summary is missing fields {missing_summary}: {path}"
        )
    if summary["score_status"] not in {"COMPLETE", "INCOMPLETE"}:
        raise ComparisonInputError(f"Invalid summary score_status in report: {path}")
    if not isinstance(summary["errored"], int) or summary["errored"] < 0:
        raise ComparisonInputError(f"Invalid summary errored count in report: {path}")
    for field in ("skipped", "not_applicable"):
        if not isinstance(summary[field], int) or summary[field] < 0:
            raise ComparisonInputError(f"Invalid summary {field} count in report: {path}")
    if summary["score"] is not None and not isinstance(summary["score"], (int, float)):
        raise ComparisonInputError(f"Invalid summary score in report: {path}")
    coverage = summary["attack_coverage"]
    match = _COVERAGE_PATTERN.fullmatch(coverage) if isinstance(coverage, str) else None
    if match is None or int(match.group(1)) > int(match.group(2)):
        raise ComparisonInputError(f"Invalid attack coverage in report: {path}")

    attacks: dict[int, AttackSnapshot] = {}
    required_result = {"attack_id", "attack_name", "severity", "status", "protection_source"}
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise ComparisonInputError(f"Result {index} is not an object: {path}")
        missing_result = sorted(required_result - result.keys())
        if missing_result:
            raise ComparisonInputError(
                f"Result {index} is missing fields {missing_result}: {path}"
            )
        attack_id = result["attack_id"]
        if isinstance(attack_id, bool) or not isinstance(attack_id, int) or attack_id < 0:
            raise ComparisonInputError(f"Invalid attack_id in result {index}: {path}")
        if attack_id in attacks:
            raise ComparisonInputError(f"Duplicate attack_id {attack_id} in report: {path}")
        if not isinstance(result["attack_name"], str):
            raise ComparisonInputError(f"Invalid attack_name for attack {attack_id}: {path}")
        if result["status"] not in _STATUS_VALUES:
            raise ComparisonInputError(f"Invalid status for attack {attack_id}: {path}")
        if result["severity"] not in _SEVERITY_ORDER:
            raise ComparisonInputError(f"Invalid severity for attack {attack_id}: {path}")
        if not isinstance(result["protection_source"], str):
            raise ComparisonInputError(f"Invalid protection_source for attack {attack_id}: {path}")
        attacks[attack_id] = AttackSnapshot(
            attack_id=attack_id,
            attack_name=result["attack_name"],
            severity=result["severity"],
            status=result["status"],
            protection_source=result["protection_source"],
        )

    return ScanSnapshot(path=path, summary=summary, attacks=attacks)


def compare_report_files(before_path: Path, after_path: Path) -> ComparisonResult:
    before = load_scan_report(before_path)
    after = load_scan_report(after_path)
    if set(before.attacks) != set(after.attacks):
        missing_after = sorted(set(before.attacks) - set(after.attacks))
        missing_before = sorted(set(after.attacks) - set(before.attacks))
        raise ComparisonInputError(
            f"Reports contain different attack sets; missing after={missing_after}, "
            f"missing before={missing_before}."
        )

    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    severity_changes: list[dict[str, Any]] = []
    status_changes: list[dict[str, Any]] = []
    protection_changes: list[dict[str, Any]] = []

    for attack_id in sorted(before.attacks):
        old = before.attacks[attack_id]
        current = after.attacks[attack_id]
        detail = _attack_detail(current)
        if old.status != "VULNERABLE" and current.status == "VULNERABLE":
            new.append(detail)
        elif old.status == "VULNERABLE" and current.status != "VULNERABLE":
            resolved.append(detail | {"before_status": old.status})
        elif old.status == "VULNERABLE" and current.status == "VULNERABLE":
            unchanged.append(detail)

        if old.severity != current.severity:
            severity_changes.append({
                "attack_id": attack_id,
                "attack_name": current.attack_name,
                "before": old.severity,
                "after": current.severity,
                "direction": "increase" if _SEVERITY_ORDER[current.severity] > _SEVERITY_ORDER[old.severity] else "decrease",
            })
        if old.status != current.status:
            status_changes.append({
                "attack_id": attack_id,
                "attack_name": current.attack_name,
                "before": old.status,
                "after": current.status,
            })
        if old.protection_source != current.protection_source:
            protection_changes.append({
                "attack_id": attack_id,
                "attack_name": current.attack_name,
                "before": old.protection_source,
                "after": current.protection_source,
            })

    regression = bool(new) or any(change["direction"] == "increase" for change in severity_changes)
    improvement = bool(resolved) or any(change["direction"] == "decrease" for change in severity_changes)
    before_score = before.summary["score"]
    after_score = after.summary["score"]
    if before_score is not None and after_score is not None:
        regression = regression or after_score < before_score
        improvement = improvement or after_score > before_score
    for change in status_changes:
        if change["after"] == "VULNERABLE" and change["before"] != "VULNERABLE":
            regression = True
        if change["before"] == "VULNERABLE" and change["after"] != "VULNERABLE":
            improvement = True
    if after.coverage[0] < before.coverage[0]:
        regression = True
    elif after.coverage[0] > before.coverage[0]:
        improvement = True

    if before.incomplete or after.incomplete:
        overall = "INCOMPLETE"
    elif regression:
        overall = "REGRESSED"
    elif improvement:
        overall = "IMPROVED"
    else:
        overall = "UNCHANGED"

    return ComparisonResult(
        before=before,
        after=after,
        new_vulnerabilities=tuple(new),
        resolved_vulnerabilities=tuple(resolved),
        unchanged_vulnerabilities=tuple(unchanged),
        severity_changes=tuple(severity_changes),
        status_changes=tuple(status_changes),
        protection_source_changes=tuple(protection_changes),
        overall_result=overall,
    )


def _attack_detail(attack: AttackSnapshot) -> dict[str, Any]:
    return {
        "attack_id": attack.attack_id,
        "attack_name": attack.attack_name,
        "severity": attack.severity,
        "status": attack.status,
        "protection_source": attack.protection_source,
    }


def _status_counts(attacks: Any) -> dict[str, int]:
    counts = {status: 0 for status in sorted(_STATUS_VALUES)}
    for attack in attacks:
        counts[attack.status] += 1
    return counts


def _ids_with_status(attacks: dict[int, AttackSnapshot], status: str) -> list[int]:
    return sorted(attack_id for attack_id, attack in attacks.items() if attack.status == status)
