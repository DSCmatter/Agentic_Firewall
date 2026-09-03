"""Structured data exchanged between the benchmark harness and its callers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class InfrastructureError:
    """A transport or protocol failure, distinct from a security finding."""

    kind: str
    message: str
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "message": self.message,
            "retryable": self.retryable,
            "details": self.details,
        }


@dataclass
class AttackObservation:
    """Raw outcome of one unchanged attack function running against one target."""

    attack_id: int
    category: str
    attack_name: str
    mode: Literal["standalone", "protected"]
    request_accepted: bool | None
    messages: list[dict[str, Any]]
    expectation_met: bool
    outcome_label: str
    duration_ms: float
    error: InfrastructureError | None = None


@dataclass
class BenchmarkRun:
    """The baseline and protected runs produced by the existing 17-attack suite."""

    baseline: dict[int, AttackObservation]
    protected: dict[int, AttackObservation]


@dataclass
class NormalizedAttackResult:
    """Stable security result intended for consumers such as the Stage 1 CLI."""

    attack_id: int
    attack_name: str
    category: str
    severity: str
    status: Literal["PASS", "FAIL", "ERROR", "SKIPPED"]
    explanation: str
    evidence: dict[str, Any]
    duration_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "category": self.category,
            "severity": self.severity,
            "status": self.status,
            "explanation": self.explanation,
            "evidence": self.evidence,
            "duration_ms": round(self.duration_ms, 2),
        }
