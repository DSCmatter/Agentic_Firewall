"""CLI-facing service layer for executing the existing benchmark harness."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from benchmarking.attack_harness import ATTACKS, run_benchmark, run_protected_benchmark
from benchmarking.models import AttackObservation, InfrastructureError, NormalizedAttackResult
from benchmarking.normalizer import normalize_protected_result
from agentic_firewall.mcp_target import McpTargetAdapter, McpTargetConfig, TargetPreflightError
from agentic_firewall.scoring import SecurityScore, calculate_security_score


ResultCallback = Callable[[NormalizedAttackResult], Awaitable[None] | None]


@dataclass
class ScanReport:
    results: list[NormalizedAttackResult]
    security_score: SecurityScore
    target: dict[str, str]

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.1",
            "benchmark": "owasp-asi-17",
            "target": self.target,
            "summary": self.security_score.to_dict(),
            "results": [result.to_dict() for result in self.results],
        }


DEFAULT_BENCHMARK_TOOLS = {
    "read_file",
    "write_file",
    "execute_command",
    "fetch_url",
    "query_database",
}


async def run_local_scan(on_result: ResultCallback | None = None) -> ScanReport:
    """Run the existing baseline/protected benchmark and expose protected results."""
    async def on_protected_observation(observation: AttackObservation) -> None:
        result = normalize_protected_result(observation, available_tools=DEFAULT_BENCHMARK_TOOLS)
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
        normalize_protected_result(
            protected,
            baseline_by_id.get(attack_id),
            available_tools=DEFAULT_BENCHMARK_TOOLS,
        )
        for attack_id, protected in sorted(benchmark.protected.items())
    ]
    return ScanReport(
        results=results,
        security_score=calculate_security_score(results),
        target={"kind": "local-toy-server", "transport": "MCP SSE via gateway"},
    )


async def run_mcp_target_scan(
    config: McpTargetConfig,
    on_result: ResultCallback | None = None,
) -> ScanReport:
    """Preflight an MCP server and run existing attacks through the gateway proxy."""
    available_tools: set[str] = set()

    async def on_protected_observation(observation: AttackObservation) -> None:
        result = normalize_protected_result(observation, available_tools=available_tools)
        if on_result is not None:
            callback_result = on_result(result)
            if hasattr(callback_result, "__await__"):
                await callback_result

    try:
        async with McpTargetAdapter(config) as target:
            await target.preflight()
            available_tools = target.available_tools
            protected = await run_protected_benchmark(
                target.gateway_url or "", on_protected_observation
            )
    except TargetPreflightError as exc:
        return _infrastructure_report(config, exc)

    results = [
        normalize_protected_result(observation, available_tools=available_tools)
        for _, observation in sorted(protected.items())
    ]
    return ScanReport(results, calculate_security_score(results), config.public_description())


def _infrastructure_report(config: McpTargetConfig, error: TargetPreflightError) -> ScanReport:
    """Represent preflight failure as incomplete infrastructure, never a PASS."""
    results = [
        NormalizedAttackResult(
            attack_id=attack_id,
            attack_name=name,
            category=category,
            severity="high",
            status="ERROR",
            explanation="Benchmark not executed because MCP target preflight failed.",
            evidence={"infrastructure_error": InfrastructureError(error.kind, error.message).to_dict()},
            duration_ms=0.0,
            protection_source="NONE",
        )
        for category, attack_id, identity, runner, name in ATTACKS
    ]
    return ScanReport(results, calculate_security_score(results), config.public_description())

