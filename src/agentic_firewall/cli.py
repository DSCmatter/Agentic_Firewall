"""Click entry point for Agentic Firewall."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console

from agentic_firewall.presentation import ScanPresenter
from agentic_firewall.mcp_target import McpTargetConfig, TargetConfigurationError
from agentic_firewall.services import run_local_scan, run_mcp_target_scan


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Run local Agentic Firewall benchmark tools."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@main.command()
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False, writable=True))
@click.option("--format", "output_format", type=click.Choice(["rich", "json"]), default="rich", show_default=True)
@click.option("--server-url", help="HTTP(S) MCP SSE server base URL (gateway uses <URL>/sse).")
@click.option("--server-cmd", help="JSON argv array for a local stdio MCP server; shell syntax is not accepted.")
def scan(output: Path | None, output_format: str, server_url: str | None, server_cmd: str | None) -> None:
    """Execute the existing 17 attacks against the demo or an MCP target."""
    try:
        target_config = McpTargetConfig.from_options(server_url, server_cmd)
    except TargetConfigurationError as exc:
        raise click.UsageError(str(exc)) from exc
    console = Console()
    presenter = ScanPresenter(console)
    if output_format == "rich":
        presenter.start()
    try:
        callback = presenter.on_result if output_format == "rich" else None
        report = asyncio.run(
            run_local_scan(callback) if target_config is None else run_mcp_target_scan(target_config, callback)
        )
    except Exception as exc:
        if output_format == "rich":
            presenter.progress.stop()
        raise click.ClickException(f"Infrastructure failure: {exc}") from exc

    payload = report.to_dict()
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if output_format == "json":
        click.echo(json.dumps(payload, indent=2))
    else:
        presenter.finish(report)
        if output is not None:
            console.print(f"Report saved: [cyan]{output}[/]")

    if report.security_score.errored:
        raise click.exceptions.Exit(1)

