"""Rich-only rendering for scan results; no benchmark behavior lives here."""

from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn
from rich.table import Table

from benchmarking.models import NormalizedAttackResult
from agentic_firewall.services import ScanReport


from rich.markup import escape

_STATUS_STYLE = {
    "PASS": "green",
    "VULNERABLE": "bold red",
    "ERROR": "yellow",
    "SKIPPED": "dim",
    "NOT_APPLICABLE": "cyan",
}
_SOURCE_STYLE = {
    "FIREWALL": "bold green",
    "TARGET": "blue",
    "BOTH": "bold cyan",
    "NONE": "dim",
    "UNKNOWN": "yellow",
}


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
        table.add_column("Protection")
        table.add_column("Duration", justify="right")
        for result in report.results:
            status_style = _STATUS_STYLE.get(result.status, "white")
            source_style = _SOURCE_STYLE.get(result.protection_source, "white")
            table.add_row(
                str(result.attack_id),
                escape(result.attack_name),
                escape(result.severity.upper()),
                f"[{status_style}]{escape(result.status)}[/]",
                f"[{source_style}]{escape(result.protection_source)}[/]",
                f"{result.duration_ms:.0f} ms",
            )
        self.console.print(table)
        score = report.security_score
        if score.score_status == "INCOMPLETE":
            self.console.print(
                f"[bold]Security Score:[/] [yellow]N/A ({score.grade})[/]  "
                f"[bold]Attack Coverage:[/] {score.attack_coverage}  "
                f"[green]{score.passed} passed[/], [red]{score.vulnerable} vulnerable[/], "
                f"[yellow]{score.errored} errors[/]"
            )
            errors = [result for result in report.results if result.status == "ERROR"]
            if errors:
                kind = errors[0].evidence.get("infrastructure_error", {}).get("kind", "benchmark_execution_error")
                self.console.print(f"[bold yellow]Scan Status: INCOMPLETE[/] ({kind.replace('_', ' ')})")
        elif score.applicable_tests == 0:
            self.console.print(
                f"[bold]Security Score:[/] [dim]N/A[/]  "
                f"[bold]Attack Coverage:[/] {score.attack_coverage}  "
                f"[cyan]{score.not_applicable} not applicable[/]"
            )
        else:
            score_val = score.score if score.score is not None else 0
            score_style = "green" if score_val >= 80 else "red"
            self.console.print(
                f"[bold]Security Score:[/] [{score_style}]{score_val}/100 ({score.grade})[/]  "
                f"[bold]Attack Coverage:[/] {score.attack_coverage}  "
                f"[green]{score.passed} passed[/], [red]{score.vulnerable} vulnerable[/]"
                + (f", [cyan]{score.not_applicable} not applicable[/]" if score.not_applicable else "")
            )

