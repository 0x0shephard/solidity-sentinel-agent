import typer

from sentinel.graphs.parent import run_audit

app = typer.Typer(help="Solidity Sentinel CLI")


@app.callback()
def main() -> None:
    """Solidity Sentinel command group."""


@app.command()
def audit(
    repo: str = typer.Option(..., "--repo", help="Local Solidity repository path."),
    objective: str = typer.Option(..., "--objective", help="Audit objective."),
    mock_llm: bool = typer.Option(True, "--mock-llm/--real-llm", help="Phase 5 uses deterministic graph routing."),
) -> None:
    """Run the parent LangGraph audit path."""

    state = run_audit(repo=repo, objective=objective, mock_llm=mock_llm)
    typer.echo(f"Run ID: {state['run_id']}")
    typer.echo("Status: completed")
    typer.echo(f"Tool calls: {state['tool_call_count']}")
    typer.echo(f"Current focus: {state['current_focus']}")
    typer.echo(f"State: {state['run_dir']}/state.json")
