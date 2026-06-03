import typer

from sentinel.evals.runner import FIXTURES, run_all, run_fixture, write_eval_summary
from sentinel.graphs.parent import run_audit
from sentinel.rag.sync import sync_solodit
from sentinel.tools import build_default_registry

app = typer.Typer(help="Solidity Sentinel CLI")
eval_app = typer.Typer(help="Run fixture evaluations")
tools_app = typer.Typer(help="Inspect registered tools")
rag_app = typer.Typer(help="Manage Solodit RAG cache")
app.add_typer(eval_app, name="eval")
app.add_typer(tools_app, name="tools")
app.add_typer(rag_app, name="rag")


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


@rag_app.command("sync")
def rag_sync(stale_ok: bool = typer.Option(True, "--stale-ok/--strict", help="Use stale cache if live Solodit sync fails.")) -> None:
    """Synchronize Solodit findings into the local RAG cache."""

    result = sync_solodit(stale_ok=stale_ok)
    typer.echo(f"Status: {result.status.value}")
    typer.echo(f"Findings: {result.finding_count}")
    typer.echo(f"Pages: {result.page_count}")
    if result.message:
        typer.echo(f"Message: {result.message}")
    if result.chroma_path:
        typer.echo(f"Chroma: {result.chroma_path}")


@tools_app.command("list")
def tools_list(json_output: bool = typer.Option(False, "--json", help="Emit JSON metadata.")) -> None:
    """List registered Sentinel tools."""

    import json

    tools = [tool.public_dict() for tool in build_default_registry().list()]
    if json_output:
        typer.echo(json.dumps(tools, indent=2))
        return
    for tool in tools:
        typer.echo(f"{tool['name']}: {tool['description']}")


@tools_app.command("show")
def tools_show(tool_name: str) -> None:
    """Show metadata for one registered tool."""

    import json

    typer.echo(json.dumps(build_default_registry().get(tool_name).public_dict(), indent=2))


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


if __name__ == "__main__":
    app()
