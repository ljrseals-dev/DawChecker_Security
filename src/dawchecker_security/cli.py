"""
Command-line interface for DawChecker Security.

All operations are local. No account, no cloud, no subscription checks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from dawchecker_security.core import SecurityEngine, ActionContext, Decision
from dawchecker_security import __version__

console = Console()


def _engine(policy: str | None, data_dir: str | None) -> SecurityEngine:
    receipt_dir = Path(data_dir) / "receipts" if data_dir else None
    approval_dir = Path(data_dir) / "approvals" if data_dir else None
    return SecurityEngine(
        policy_path=policy,
        receipt_dir=receipt_dir,
        approval_dir=approval_dir,
    )


@click.group()
@click.version_option(__version__, prog_name="dawchecker-sec")
def main() -> None:
    """DawChecker Security — local-first AI / DAW action review.

    No cloud. No paywalls. No subscriptions.
    """


@main.command()
@click.option("--policy", type=click.Path(exists=True), help="Path to policy YAML/JSON")
@click.option("--data-dir", type=click.Path(), help="Override local data directory")
def status(policy: str | None, data_dir: str | None) -> None:
    """Show local engine status."""
    eng = _engine(policy, data_dir)
    s = eng.status()
    table = Table(title="DawChecker Security Status")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")
    for k, v in s.items():
        table.add_row(k, str(v))
    console.print(table)
    console.print(
        Panel(
            "[bold green]Local-first[/] · No cloud required · No paywall · No subscription",
            title="Mode",
        )
    )


@main.command()
@click.argument("action_type", type=click.Choice(["shell", "file", "package", "mcp", "daw"]))
@click.option("--command", "-c", default=None, help="Shell command")
@click.option("--path", "-p", default=None, help="File path")
@click.option("--package", default=None, help="Package name")
@click.option("--tool", default=None, help="MCP tool name")
@click.option("--args", "tool_args", default=None, help="MCP arguments as JSON")
@click.option("--agent", default=None, help="Agent identifier")
@click.option("--policy", type=click.Path(exists=True))
@click.option("--data-dir", type=click.Path())
@click.option("--json-out", is_flag=True, help="Emit JSON result")
def evaluate(
    action_type: str,
    command: str | None,
    path: str | None,
    package: str | None,
    tool: str | None,
    tool_args: str | None,
    agent: str | None,
    policy: str | None,
    data_dir: str | None,
    json_out: bool,
) -> None:
    """Evaluate a single action and print the decision."""
    eng = _engine(policy, data_dir)
    arguments = json.loads(tool_args) if tool_args else {}
    ctx = ActionContext(
        action_type=action_type,
        command=command,
        path=path,
        package=package,
        tool_name=tool,
        arguments=arguments,
        agent=agent,
    )
    result = eng.evaluate(ctx)

    if json_out:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    colour = {
        Decision.ALLOW: "green",
        Decision.BLOCK: "red",
        Decision.ASK: "yellow",
    }[result.decision]

    console.print(
        Panel(
            f"[bold {colour}]{result.decision.value.upper()}[/]\n\n"
            f"{result.reason}\n\n"
            f"Risk: {result.risk_score:.2f}\n"
            f"Labels: {', '.join(result.classifications) or 'none'}\n"
            f"Rule: {result.policy_rule or 'default'}\n"
            f"Receipt: {result.receipt_id or 'n/a'}",
            title="Decision",
        )
    )
    if result.decision == Decision.BLOCK:
        sys.exit(2)
    if result.decision == Decision.ASK:
        sys.exit(1)


@main.command("remember")
@click.argument("action_type", type=click.Choice(["shell", "file", "package", "mcp", "daw"]))
@click.option("--command", "-c", default=None)
@click.option("--path", "-p", default=None)
@click.option("--package", default=None)
@click.option("--tool", default=None)
@click.option("--decision", type=click.Choice(["allow", "block"]), required=True)
@click.option("--reason", default="User decision")
@click.option("--policy", type=click.Path(exists=True))
@click.option("--data-dir", type=click.Path())
def remember_cmd(
    action_type: str,
    command: str | None,
    path: str | None,
    package: str | None,
    tool: str | None,
    decision: str,
    reason: str,
    policy: str | None,
    data_dir: str | None,
) -> None:
    """Store a local remembered decision for an action fingerprint."""
    eng = _engine(policy, data_dir)
    ctx = ActionContext(
        action_type=action_type,
        command=command,
        path=path,
        package=package,
        tool_name=tool,
    )
    eng.remember(ctx, Decision(decision), reason=reason)
    console.print(f"[green]Remembered[/] {decision} for fingerprint {ctx.fingerprint()}")


@main.command()
@click.option("--limit", default=20, show_default=True)
@click.option("--data-dir", type=click.Path())
def receipts(limit: int, data_dir: str | None) -> None:
    """Show recent local receipts."""
    eng = _engine(None, data_dir)
    table = Table(title=f"Recent receipts (last {limit})")
    table.add_column("Time")
    table.add_column("Decision")
    table.add_column("Type")
    table.add_column("Risk")
    table.add_column("Reason")
    for r in eng.receipts.iter_recent(limit):
        from datetime import datetime

        ts = datetime.fromtimestamp(r.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(ts, r.decision, r.action_type, f"{r.risk_score:.2f}", r.reason[:60])
    console.print(table)


@main.command()
@click.option("--policy", type=click.Path(exists=True))
@click.option("--data-dir", type=click.Path())
def init(policy: str | None, data_dir: str | None) -> None:
    """Initialise local directories and write a default policy if missing."""
    eng = _engine(policy, data_dir)
    # Touch the stores
    _ = eng.receipts.count()
    _ = eng.approvals.count()
    console.print("[green]Local data directories ready.[/]")
    console.print(eng.status())


if __name__ == "__main__":
    main()