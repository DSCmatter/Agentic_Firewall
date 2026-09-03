"""Click entry point for Agentic Firewall.

Exit-code semantics
-------------------
0  Scan completed (even if vulnerabilities were found) and --fail-on threshold not met.
1  Infrastructure error (errored > 0), OR --fail-on threshold was met.
2  Usage / configuration error.

--fail-on semantics
-------------------
Cumulative severity ladder evaluated against VULNERABLE results directly:
  --fail-on critical  → exit 1 if any CRITICAL vulnerability found
  --fail-on high      → exit 1 if HIGH or CRITICAL found
  --fail-on medium    → exit 1 if MEDIUM / HIGH / CRITICAL found
  --fail-on low       → exit 1 if any vulnerability found

--fail-on never alters score, findings, coverage, or JSON output.

JSON stdout invariant
---------------------
When --format json is active, stdout contains exactly one JSON document and
nothing else. All operational output (progress, warnings) goes to stderr.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import click
from rich.console import Console

from agentic_firewall.mcp_target import McpTargetConfig, TargetConfigurationError
from agentic_firewall.presentation import ScanPresenter
from agentic_firewall.services import run_local_scan, run_mcp_target_scan


_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _fail_on_threshold_met(report, fail_on: str | None) -> bool:
    """Evaluate --fail-on directly against VULNERABLE results, not score dicts."""
    if fail_on is None:
        return False
    threshold_idx = _SEVERITY_ORDER.index(fail_on)
    covered_severities = set(_SEVERITY_ORDER[: threshold_idx + 1])
    return any(
        r.status == "VULNERABLE" and r.severity in covered_severities
        for r in report.results
    )


def _target_label(config: McpTargetConfig | None) -> str:
    if config is None:
        return "Local Toy Benchmark (MCP SSE via gateway)"
    if config.kind == "http_sse":
        return f"HTTP/SSE MCP server  {config.server_url}"
    return "Local stdio MCP server"


@click.group(invoke_without_command=True)
@click.version_option(package_name="agentic-firewall", prog_name="agentic-firewall")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Agentic Firewall — MCP security scanner."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@main.command()
@click.option(
    "--output",
    type=click.Path(path_type=Path, dir_okay=False, writable=True),
    help="Write JSON report to this file.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["rich", "json"]),
    default="rich",
    show_default=True,
    help="Output format. 'json' emits pure JSON to stdout.",
)
@click.option("--server-url", help="HTTP(S) MCP SSE server base URL (must expose <URL>/sse).")
@click.option("--server-cmd", help="JSON argv array for a local stdio MCP server.")
@click.option(
    "--no-progress",
    is_flag=True,
    default=False,
    help="Suppress animated progress bar (useful for non-interactive / CI environments).",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress header, progress, and per-attack table. Show score and findings only.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Exit 1 if any vulnerability at or above this severity level is found (CI gate).",
)
def scan(
    output: Path | None,
    output_format: str,
    server_url: str | None,
    server_cmd: str | None,
    no_progress: bool,
    quiet: bool,
    fail_on: str | None,
) -> None:
    """Execute the 17 OWASP ASI attacks against the built-in benchmark or an MCP target."""
    try:
        target_config = McpTargetConfig.from_options(server_url, server_cmd)
    except TargetConfigurationError as exc:
        raise click.UsageError(str(exc)) from exc

    # For JSON mode: Rich console goes to stderr so stdout is JSON-only.
    json_mode = output_format == "json"
    rich_console = Console(stderr=json_mode)
    presenter = ScanPresenter(rich_console)

    show_progress = not no_progress and not quiet and not json_mode
    show_header = not quiet and not json_mode

    if show_header:
        presenter.start(
            target_label=_target_label(target_config),
            attack_count=17,
            show_progress=show_progress,
        )
    elif show_progress:
        # no_progress=False but quiet=False - start with progress only if header shown
        pass

    on_result_cb = presenter.on_result if (show_header and show_progress) else None

    try:
        report = asyncio.run(
            run_local_scan(on_result_cb)
            if target_config is None
            else run_mcp_target_scan(target_config, on_result_cb)
        )
    except Exception as exc:
        presenter._stop_progress()
        raise click.ClickException(f"Infrastructure failure: {exc}") from exc

    # --- Output -----------------------------------------------------------
    payload = report.to_dict()

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    if json_mode:
        # Architectural invariant: one JSON document, nothing else to stdout.
        click.echo(json.dumps(payload, indent=2))
    elif quiet:
        presenter.quiet_finish(report)
    else:
        presenter.finish(report)
        if output is not None:
            rich_console.print(f"  [dim]Report saved:[/] [cyan]{output}[/]")

    # --- Exit codes -------------------------------------------------------
    if report.security_score.errored:
        raise click.exceptions.Exit(1)

    if _fail_on_threshold_met(report, fail_on):
        raise click.exceptions.Exit(1)
