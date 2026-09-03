"""Click entry point for Agentic Firewall."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from rich.console import Console

from agentic_firewall.presentation import ScanPresenter
from agentic_firewall.services import run_local_scan


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Run local Agentic Firewall benchmark tools."""
    if ctx.invoked_subcommand is None:
        ctx.invoke(scan)


@main.command()
@click.option("--output", type=click.Path(path_type=Path, dir_okay=False, writable=True))
@click.option("--format", "output_format", type=click.Choice(["rich", "json"]), default="rich", show_default=True)
def scan(output: Path | None, output_format: str) -> None:
    """Execute the existing 17-attack OWASP harness against the local toy target."""
    console = Console()
    presenter = ScanPresenter(console)
    if output_format == "rich":
        presenter.start()
    try:
        report = asyncio.run(run_local_scan(presenter.on_result if output_format == "rich" else None))
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

    if report.security_score.failed:
        raise click.exceptions.Exit(1)
    if report.security_score.errored:
        raise click.exceptions.Exit(2)
