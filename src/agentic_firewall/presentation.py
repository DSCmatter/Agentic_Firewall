"""Rich-only rendering for scan results; no benchmark behavior lives here."""

from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from benchmarking.models import NormalizedAttackResult
from agentic_firewall.services import ScanReport


_STATUS_STYLE = {"PASS": "green", "FAIL": "bold red", "ERROR": "yellow", "SKIPPED": "dim"}


class ScanPresenter:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self.progress = Progress(
            TextColumn("[bold cyan]Running OWASP attacks"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=self.console,
        )
        self.task_id: int | None = None

    def start(self) -> None:
        self.console.print("[bold cyan]Agentic Firewall[/] [dim]• Local OWASP security scan[/]")
        self.progress.start()
        self.task_id = self.progress.add_task("scan", total=17)

    async def on_result(self, result: NormalizedAttackResult) -> None:
        if self.task_id is not None:
            self.progress.advance(self.task_id)

    def finish(self, report: ScanReport) -> None:
        self.progress.stop()
        table = Table(title="OWASP ASI Scan Results")
        table.add_column("ID", justify="right")
        table.add_column("Attack")
        table.add_column("Severity")
        table.add_column("Status")
        table.add_column("Duration", justify="right")
        for result in report.results:
            table.add_row(
                str(result.attack_id), result.attack_name, result.severity.upper(),
                f"[{_STATUS_STYLE[result.status]}]{result.status}[/]",
                f"{result.duration_ms:.0f} ms",
            )
        self.console.print(table)
        score = report.security_score
        score_style = "green" if score.score >= 80 else "red"
        self.console.print(
            f"[bold]Security Score:[/] [{score_style}]"
            f"{score.score}/100 ({score.grade})[/]  "
            f"[green]{score.passed} passed[/], [red]{score.failed} failed[/], "
            f"[yellow]{score.errored} infrastructure errors[/]"
        )
        errors = [result for result in report.results if result.status == "ERROR"]
        if errors:
            kind = errors[0].evidence.get("infrastructure_error", {}).get("kind", "benchmark_execution_error")
            self.console.print(f"[yellow]Scan incomplete:[/] {kind.replace('_', ' ')}")
