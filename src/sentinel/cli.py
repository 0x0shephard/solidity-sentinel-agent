import typer

from sentinel.evals.runner import FIXTURES, run_all, run_fixture, write_eval_summary
from sentinel.graphs.parent import run_audit

app = typer.Typer(help="Solidity Sentinel CLI")
eval_app = typer.Typer(help="Run fixture evaluations")
app.add_typer(eval_app, name="eval")


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
    typer.echo(f"Report: {state['run_dir']}/report.md")


@eval_app.callback(invoke_without_command=True)
def eval_main(
    all_fixtures: bool = typer.Option(False, "--all", help="Run all fixtures."),
    fixture: str | None = typer.Option(None, "--fixture", help="Run one fixture."),
    mock_llm: bool = typer.Option(True, "--mock-llm/--real-llm", help="Use deterministic graph routing by default."),
) -> None:
    """Run fixture-based evaluations."""

    if not all_fixtures and fixture is None:
        typer.echo(f"Choose --all or --fixture. Available: {', '.join(FIXTURES)}")
        raise typer.Exit(1)
    scores = run_all(mock_llm=mock_llm) if all_fixtures else [run_fixture(fixture or "", mock_llm=mock_llm)]
    out_dir = write_eval_summary(scores)
    for score in scores:
        typer.echo(f"{score.fixture}: {score.score:.0f}/100")
    typer.echo(f"Summary: {out_dir}")
