"""Main CLI entry point for nhi-recon."""

from __future__ import annotations

import click

from nhi_recon import __version__
from nhi_recon.discover import discover
from nhi_recon.enumerate import enumerate_group
from nhi_recon.chain import chain
from nhi_recon.report import report


@click.group()
@click.version_option(version=__version__, prog_name="nhi-recon")
@click.option(
    "--target",
    "-t",
    envvar="NHI_TARGET",
    default=None,
    help="Default target host (overridden by sub-command --target).",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Global output format.",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output.")
@click.option(
    "--dashboard-url",
    envvar="NHI_DASHBOARD_URL",
    default=None,
    help="Dashboard API URL for live event streaming.",
)
@click.pass_context
def cli(
    ctx: click.Context,
    target: str | None,
    output: str,
    verbose: bool,
    dashboard_url: str | None,
) -> None:
    """nhi-recon -- Non-Human Identity reconnaissance and attack chain tool.

    Discover, enumerate, and demonstrate attack chains against Non-Human
    Identities (service accounts, cloud IAM roles, CI/CD tokens, SPIFFE SVIDs).

    Designed as the offensive companion to the NHI Security Testbed detection
    rules.
    """
    ctx.ensure_object(dict)
    ctx.obj["target"] = target
    ctx.obj["output"] = output
    ctx.obj["verbose"] = verbose
    ctx.obj["dashboard_url"] = dashboard_url


cli.add_command(discover)
cli.add_command(enumerate_group, name="enumerate")
cli.add_command(chain)
cli.add_command(report)


if __name__ == "__main__":
    cli()
