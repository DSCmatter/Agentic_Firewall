"""Rich-only rendering for scan results; no benchmark behavior lives here.

Architectural invariant
-----------------------
All target-controlled text passes through `_sanitize_terminal_text()` before
Rich renders it. That function strips ANSI control sequences, escapes Rich
markup, and bounds length so untrusted MCP responses cannot manipulate the
user's terminal.

JSON serialization paths never call this function; raw evidence is preserved.
"""

from __future__ import annotations

import re
import sys
from typing import TYPE_CHECKING

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from benchmarking.models import NormalizedAttackResult
from agentic_firewall.services import ScanReport

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# ANSI / terminal control-sequence sanitizer
# ---------------------------------------------------------------------------

# Covers:
#   ESC [ ... m     – SGR (colour, bold, etc.)
#   ESC [ ... A-Z   – cursor movement, erase
#   ESC ] ... BEL   – OSC (title, hyperlinks, etc.)
#   ESC ] ... ESC \ – OSC with string-terminator
#   ESC @-Z \ _ ~   – Fe two-character sequences
_ANSI_ESCAPE = re.compile(
    r"\x1b(?:"
    r"\[[0-9;?]*[ -/]*[@-~]"        # CSI sequences
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC sequences
    r"|[@-Z\\-_]"                    # Fe sequences
    r")"
)

_MAX_TERMINAL_CHARS = 240
_MAX_TERMINAL_LINES = 4


def _sanitize_terminal_text(text: str, *, max_chars: int = _MAX_TERMINAL_CHARS, max_lines: int = _MAX_TERMINAL_LINES) -> str:
    """Strip ANSI control sequences, escape Rich markup, and bound length.

    This function is **only** for terminal rendering. JSON serialization paths
    must never call it; raw evidence is always preserved in full for JSON.
    """
    # 1. Strip all ANSI / terminal control sequences.
    text = _ANSI_ESCAPE.sub("", text)
    # 2. Escape Rich markup so brackets are displayed literally.
    text = escape(text)
    # 3. Bound line count.
    lines = text.splitlines()
    if len(lines) > max_lines:
        remaining = len(lines) - max_lines
        lines = lines[:max_lines] + [f"[dim]… ({remaining} more line{'s' if remaining > 1 else ''})[/]"]
    text = "\n".join(lines)
    # 4. Bound character count (applied after line truncation).
    if len(text) > max_chars:
        text = text[:max_chars] + "[dim]…[/]"
    return text


# ---------------------------------------------------------------------------
# Style maps
# ---------------------------------------------------------------------------

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
_SEV_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "dim",
}
_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


# ---------------------------------------------------------------------------
# ScanPresenter
# ---------------------------------------------------------------------------

class ScanPresenter:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._progress: Progress | None = None
        self._task_id: int | None = None

    # ------------------------------------------------------------------
    # Progress lifecycle
    # ------------------------------------------------------------------

    def start(self, target_label: str = "Local Toy Benchmark", attack_count: int = 17, *, show_progress: bool = True) -> None:
        self.console.print()
        self.console.print("[bold cyan]Agentic Firewall[/]  [dim]Security Scan[/]")
        self.console.print(f"  [dim]Target:[/]   {_sanitize_terminal_text(target_label)}")
        self.console.print(f"  [dim]Attacks:[/]  {attack_count} scenarios across OWASP ASI02–ASI10")
        self.console.print()
        if show_progress:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]Running attacks"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                console=self.console,
                transient=False,
            )
            self._progress.start()
            self._task_id = self._progress.add_task("scan", total=attack_count)

    async def on_result(self, result: NormalizedAttackResult) -> None:
        if self._progress is not None and self._task_id is not None:
            self._progress.advance(self._task_id)

    def _stop_progress(self) -> None:
        if self._progress is not None:
            self._progress.stop()
            self._progress = None

    # ------------------------------------------------------------------
    # Full interactive finish
    # ------------------------------------------------------------------

    def finish(self, report: ScanReport) -> None:
        self._stop_progress()
        self._render_attack_table(report)
        self._render_findings(report)
        self._render_summary(report)
        self._render_next_steps(report)

    # ------------------------------------------------------------------
    # Quiet finish (no header, no table; score + findings list only)
    # ------------------------------------------------------------------

    def quiet_finish(self, report: ScanReport) -> None:
        self._stop_progress()
        self._render_summary(report)
        score = report.security_score
        if score.vulnerable > 0:
            self.console.print()
            for result in sorted(
                (r for r in report.results if r.status == "VULNERABLE"),
                key=lambda r: (_SEVERITY_ORDER.index(r.severity) if r.severity in _SEVERITY_ORDER else 99),
            ):
                sev_style = _SEV_STYLE.get(result.severity, "white")
                self.console.print(
                    f"  [{sev_style}]{escape(result.severity.upper())}[/]  "
                    f"{_sanitize_terminal_text(result.attack_name)}"
                )

    # ------------------------------------------------------------------
    # Internal rendering helpers
    # ------------------------------------------------------------------

    def _render_attack_table(self, report: ScanReport) -> None:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False, show_edge=False)
        table.add_column("", width=3)       # status icon
        table.add_column("Attack", min_width=28, max_width=42)
        table.add_column("Severity", width=8)
        table.add_column("Status", width=14)
        table.add_column("Protection", width=12)
        table.add_column("Duration", justify="right", width=9)

        ICONS = {
            "PASS": "✓",
            "VULNERABLE": "✗",
            "ERROR": "!",
            "SKIPPED": "-",
            "NOT_APPLICABLE": "~",
        }

        for result in report.results:
            status_style = _STATUS_STYLE.get(result.status, "white")
            source_style = _SOURCE_STYLE.get(result.protection_source, "white")
            sev_style = _SEV_STYLE.get(result.severity, "white")
            icon = ICONS.get(result.status, "?")

            table.add_row(
                f"[{status_style}]{icon}[/]",
                _sanitize_terminal_text(result.attack_name, max_chars=44, max_lines=1),
                f"[{sev_style}]{escape(result.severity.upper())}[/]",
                f"[{status_style}]{escape(result.status)}[/]",
                f"[{source_style}]{escape(result.protection_source)}[/]",
                f"[dim]{result.duration_ms:.0f} ms[/]",
            )

        self.console.print()
        self.console.print(table)

    def _render_findings(self, report: ScanReport) -> None:
        vulnerable = [r for r in report.results if r.status == "VULNERABLE"]
        if not vulnerable:
            return

        self.console.print()
        self.console.print(Rule("[bold red]SECURITY FINDINGS[/]", style="red"))
        self.console.print()

        # Sort by severity descending.
        sorted_findings = sorted(
            vulnerable,
            key=lambda r: (_SEVERITY_ORDER.index(r.severity) if r.severity in _SEVERITY_ORDER else 99),
        )

        for result in sorted_findings:
            sev_style = _SEV_STYLE.get(result.severity, "white")
            self.console.print(
                f"  [{sev_style}]{escape(result.severity.upper())}[/]  "
                f"[bold]{_sanitize_terminal_text(result.attack_name)}[/]"
                f"  [dim]Attack #{result.attack_id}[/]"
            )
            self.console.print(f"  [dim]OWASP:[/]       {_sanitize_terminal_text(result.category)}")
            self.console.print(f"  [dim]Protection:[/]  {escape(result.protection_source)}")

            # Show block reason / evidence if available.
            block_reason = result.evidence.get("block_reason")
            if block_reason:
                self.console.print(f"  [dim]Evidence:[/]    {_sanitize_terminal_text(str(block_reason))}")

            if result.remediation:
                self.console.print(
                    f"  [dim]Remediation:[/] {_sanitize_terminal_text(result.remediation, max_chars=200, max_lines=3)}"
                )
            self.console.print()

    def _render_summary(self, report: ScanReport) -> None:
        score = report.security_score
        self.console.print()

        if score.score_status == "INCOMPLETE":
            self.console.print(f"  [bold]Security Score[/]   [yellow]N/A[/]")
            self.console.print(f"  [bold]Scan Status[/]      [yellow]INCOMPLETE[/]")
            self.console.print(f"  [bold]Attack Coverage[/]  {score.attack_coverage}")
            self.console.print(f"  [bold]Errors[/]           [yellow]{score.errored}[/]", end="")
            errors = [r for r in report.results if r.status == "ERROR"]
            if errors:
                kind = errors[0].evidence.get("infrastructure_error", {}).get("kind", "benchmark_execution_error")
                self.console.print(f" [dim]({kind.replace('_', ' ')})[/]")
            else:
                self.console.print()
        elif score.applicable_tests == 0:
            grade_display = f"  [bold]Security Score[/]   [dim]N/A[/]"
            self.console.print(grade_display)
            self.console.print(f"  [bold]Attack Coverage[/]  {score.attack_coverage}")
            self.console.print(f"  [bold]Vulnerabilities[/]  [green]0[/]")
            self.console.print(
                f"  [bold]Not Applicable[/]   [cyan]{score.not_applicable}[/]  "
                f"[dim](target does not expose the required tools)[/]"
            )
        else:
            score_val = score.score if score.score is not None else 0
            score_style = "bold green" if score_val >= 90 else "green" if score_val >= 70 else "yellow" if score_val >= 60 else "bold red"
            grade_style = score_style
            self.console.print(
                f"  [bold]Security Score[/]   [{score_style}]{score_val}/100[/]  [{grade_style}]({score.grade})[/]"
            )
            self.console.print(f"  [bold]Attack Coverage[/]  {score.attack_coverage}")
            vuln_color = "bold red" if score.vulnerable > 0 else "green"
            self.console.print(f"  [bold]Vulnerabilities[/]  [{vuln_color}]{score.vulnerable}[/]")
            if score.not_applicable:
                self.console.print(
                    f"  [bold]Not Applicable[/]   [cyan]{score.not_applicable}[/]  "
                    f"[dim](target does not expose the required tools)[/]"
                )

        self.console.print()

    def _render_next_steps(self, report: ScanReport) -> None:
        score = report.security_score
        if score.vulnerable > 0:
            self.console.print(
                "  [dim]Save full findings:[/] "
                "[cyan]agentic-firewall scan --format json --output report.json[/]"
            )
        elif score.score_status == "INCOMPLETE":
            self.console.print(
                "  [dim]Tip:[/] Verify the target is reachable and retry. "
                "Use [cyan]--format json[/] for machine-readable diagnostics."
            )
        self.console.print()
