"""CLI-facing service layer for executing the existing benchmark harness."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from benchmarking.attack_harness import run_benchmark
from benchmarking.models import AttackObservation, NormalizedAttackResult
from benchmarking.normalizer import normalize_protected_result
from agentic_firewall.scoring import SecurityScore, calculate_security_score


ResultCallback = Callable[[NormalizedAttackResult], Awaitable[None] | None]


@dataclass
class ScanReport:
    results: list[NormalizedAttackResult]
    security_score: SecurityScore

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "benchmark": "owasp-asi-17",
            "target": {"kind": "local-toy-server", "transport": "MCP SSE via gateway"},
            "summary": self.security_score.to_dict(),
            "results": [result.to_dict() for result in self.results],
        }


async def run_local_scan(on_result: ResultCallback | None = None) -> ScanReport:
    """Run the existing baseline/protected benchmark and expose protected results."""
    async def on_protected_observation(observation: AttackObservation) -> None:
        result = normalize_protected_result(observation)
        if on_result is not None:
            callback_result = on_result(result)
            if hasattr(callback_result, "__await__"):
                await callback_result

    benchmark = await run_benchmark(
        on_protected_result=on_protected_observation,
        emit_output=False,
    )
    baseline_by_id = benchmark.baseline
    results = [
        normalize_protected_result(protected, baseline_by_id.get(attack_id))
        for attack_id, protected in sorted(benchmark.protected.items())
    ]
    return ScanReport(results=results, security_score=calculate_security_score(results))
