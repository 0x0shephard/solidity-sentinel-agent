import typer

from sentinel.evals.runner import FIXTURES, run_all, run_fixture, write_eval_summary
from sentinel.evals.rag_embeddings import DEFAULT_MODELS, evaluate_embedding_models, generate_eval_queries, list_rag_fixtures, load_rag_fixture
from sentinel.graphs.parent import run_audit
from sentinel.config import get_settings
from sentinel.rag.store import HistoricalFindingStore, load_findings
from sentinel.rag.sync import sync_solodit
from sentinel.rag.targeted import build_targeted_rag, repo_id_for_path, repo_profile_root
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


@rag_app.command("rebuild")
def rag_rebuild(
    scope: str = typer.Option("global", "--scope", help="Rebuild scope: global, repo, or all."),
    repo: str | None = typer.Option(None, "--repo", help="Repository path for --scope repo."),
) -> None:
    """Rebuild Chroma indexes with the active embedding model."""

    settings = get_settings()

    def echo_metadata(label: str, store: HistoricalFindingStore) -> None:
        metadata = store.load_metadata()
        typer.echo(f"{label}: rebuilt")
        if metadata:
            typer.echo(f"  embedding_model: {metadata.embedding_model}")
            typer.echo(f"  embedding_dim: {metadata.embedding_dim}")
            typer.echo(f"  corpus_hash: {metadata.source_cache_hash}")
            typer.echo(f"  findings: {metadata.finding_count}")
            typer.echo(f"  documents: {metadata.document_count}")
            typer.echo(f"  collection: {metadata.chroma_collection_name}")

    if scope not in {"global", "repo", "all"}:
        typer.echo("Invalid --scope. Use global, repo, or all.")
        raise typer.Exit(1)

    if scope in {"global", "all"}:
        if not load_findings(settings):
            typer.echo("Global normalized cache is empty; run `sentinel rag sync` first.")
            raise typer.Exit(1)
        global_store = HistoricalFindingStore(settings)
        global_store.rebuild()
        echo_metadata("global", global_store)

    if scope in {"repo", "all"}:
        if not repo:
            typer.echo("--repo is required for --scope repo or --scope all.")
            raise typer.Exit(1)
        repo_id = repo_id_for_path(repo)
        root = repo_profile_root(settings, repo_id)
        repo_store = HistoricalFindingStore(settings, root=root)
        if load_findings(settings, root=root):
            repo_store.rebuild()
            echo_metadata("repo", repo_store)
        else:
            state = build_targeted_rag(repo, {}, settings=settings)
            typer.echo(f"repo: {state.status.value}")
            typer.echo(f"  repo_id: {state.repo_id}")
            typer.echo(f"  findings: {state.finding_count}")
            typer.echo(f"  fetched: {state.fetched_count}")
            typer.echo(f"  selected_from_global: {state.selected_from_global_count}")
            if state.chroma_path:
                typer.echo(f"  chroma: {state.chroma_path}")


@rag_app.command("eval-embeddings", context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def rag_eval_embeddings(
    ctx: typer.Context,
    fixture: str | None = typer.Option(None, "--fixture", help="RAG eval fixture name."),
    all_fixtures: bool = typer.Option(False, "--all", help="Run all RAG eval fixtures."),
    models: list[str] | None = typer.Option(None, "--models", help="Embedding models to compare."),
    rebuild: bool = typer.Option(False, "--rebuild", help="Rebuild per-model indexes before evaluation."),
) -> None:
    """Evaluate retrieval quality across local embedding models."""

    fixture_names = list_rag_fixtures() if all_fixtures else ([fixture] if fixture else [])
    if not fixture_names:
        typer.echo("Choose --fixture or --all. Generate fixtures with `sentinel rag generate-eval-queries --fixture hawk-high`.")
        raise typer.Exit(1)
    chosen_models = [*(models or []), *ctx.args] or DEFAULT_MODELS
    for fixture_name in fixture_names:
        report = evaluate_embedding_models(load_rag_fixture(fixture_name), chosen_models, rebuild=rebuild)
        typer.echo(f"{fixture_name}: {report.output_dir}")
        typer.echo(f"  best_model_by_recall: {report.best_model_by_recall}")
        typer.echo(f"  best_balanced_model: {report.best_balanced_model}")


@rag_app.command("generate-eval-queries")
def rag_generate_eval_queries(
    fixture: str = typer.Option(..., "--fixture", help="Fixture family, e.g. hawk-high."),
) -> None:
    """Generate a RAG retrieval-eval query fixture."""

    path = generate_eval_queries(fixture)
    typer.echo(f"Wrote {path}")


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
