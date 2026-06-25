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
    stream: bool = typer.Option(True, "--stream/--quiet", help="Stream live progress (stages, tools, LLM steps) to stderr."),
) -> None:
    """Run the parent LangGraph audit path."""

    state = run_audit(repo=repo, objective=objective, mock_llm=mock_llm, stream=stream)
    typer.echo(f"Run ID: {state['run_id']}")
    typer.echo(f"Mode: {'deterministic graph (mock LLM)' if mock_llm else 'real LLM (model-driven)'}")
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


@rag_app.command("ingest-auditvault")
def rag_ingest_auditvault(
    path: str | None = typer.Option(None, "--path", help="Local AuditVault clone (defaults to SENTINEL_AUDITVAULT_DIR)."),
    limit: int | None = typer.Option(None, "--limit", help="Cap the number of notes ingested (for a quick run)."),
) -> None:
    """Ingest an AuditVault knowledge base into the historical-findings corpus."""

    from sentinel.rag.auditvault import ingest_auditvault

    vault_dir = path or get_settings().auditvault_dir
    if not vault_dir:
        typer.echo("Provide --path or set SENTINEL_AUDITVAULT_DIR to a local AuditVault clone.")
        raise typer.Exit(1)
    result = ingest_auditvault(vault_dir, limit=limit)
    typer.echo(f"AuditVault notes parsed: {result['source_files']}")
    typer.echo(f"Added to corpus: {result['added']} (total findings: {result['total']})")
    if result.get("chroma"):
        typer.echo(f"Index: {result['chroma']}")
    typer.echo("Both surfaces updated: historical-finding retrieval + stage-7 sector checklist.")


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


@app.command()
def benchmark(
    ground_truth: str = typer.Option(..., "--ground-truth", help="Path to a ground-truth JSON (e.g. evals/ground_truth/hawk-high.json)."),
    run_dir: str | None = typer.Option(None, "--run-dir", help="Existing run directory to score. If omitted, an audit is run first."),
    repo: str | None = typer.Option(None, "--repo", help="Repo to audit when --run-dir is not given (defaults to the ground-truth repo_path)."),
    real_llm: bool = typer.Option(False, "--real-llm/--mock-llm", help="Run the audit with the real LLM (needed for proposer recall)."),
    include_low: bool = typer.Option(False, "--include-low", help="Also score low-severity findings."),
) -> None:
    """Score an audit run against a contest's published findings (recall benchmark)."""

    import json as _json

    from sentinel.evals.recall import (
        candidates_from_run,
        load_ground_truth,
        render_recall_markdown,
        score_recall,
    )

    gt, contest = load_ground_truth(ground_truth, include_low=include_low)
    if run_dir is None:
        import os as _os
        from pathlib import Path as _Path

        gt_data = _json.loads(_Path(ground_truth).read_text(encoding="utf-8"))
        # Blind eval: the ground-truth file declares which project's own findings to
        # hide from RAG, so a benchmark run can't retrieve its own answers. Applied
        # unless the operator already set it explicitly.
        exclude = gt_data.get("rag_exclude_terms")
        if exclude and not _os.getenv("SENTINEL_RAG_EXCLUDE_TERMS"):
            _os.environ["SENTINEL_RAG_EXCLUDE_TERMS"] = ",".join(exclude)
            typer.echo(f"[blind eval] excluding own findings from RAG: {exclude}")
        gt_repo = gt_data.get("repo_path")
        target = repo or gt_repo
        if not target:
            typer.echo("Provide --run-dir or --repo (or repo_path in the ground-truth file).")
            raise typer.Exit(1)
        objective = "Find bugs in this Foundry smart contract repo; produce evidence-grounded findings."
        state = run_audit(repo=target, objective=objective, mock_llm=not real_llm, stream=real_llm)
        run_dir = state["run_dir"]
    report = score_recall(gt, candidates_from_run(run_dir), contest=contest)
    typer.echo(render_recall_markdown(report))
    typer.echo(f"Run scored: {run_dir}")


@app.command("exploit-replay")
def exploit_replay(
    run: str = typer.Option(..., "--run", help="Prior run dir containing candidate_rank_trace.json (+ state.json)."),
    hyp_id: str | None = typer.Option(None, "--hyp", help="Hypothesis id to replay (default: the first 3)."),
    repo: str | None = typer.Option(None, "--repo", help="Repo path (default: repo_path from the prior run's state.json)."),
    iterations: int = typer.Option(3, "--iterations", help="Exploit-loop max iterations."),
) -> None:
    """Fast-iterate the execution-grounded exploit loop on a saved hypothesis.

    Loads a hypothesis from a prior run and runs ONLY dynamic.author_and_run_exploit
    (author -> validate -> render -> compile -> run), so plan/render/compile bugs can
    be debugged in minutes instead of re-running the full ~2h audit pipeline.
    """
    import json as _json
    import os as _os
    from pathlib import Path as _Path

    from sentinel.schemas.research import VulnerabilityHypothesis
    from sentinel.state import initial_audit_state
    from sentinel.tools import build_default_registry
    from sentinel.tools.executor import ToolExecutor

    run_path = _Path(run)
    trace_path = run_path / "candidate_rank_trace.json"
    if not trace_path.exists():
        typer.echo(f"No candidate_rank_trace.json in {run}")
        raise typer.Exit(1)
    hyps = _json.loads(trace_path.read_text(encoding="utf-8")).get("hypotheses") or []
    if not hyps:
        typer.echo("No hypotheses found in the prior run.")
        raise typer.Exit(1)

    target_repo = repo
    if not target_repo and (run_path / "state.json").exists():
        target_repo = _json.loads((run_path / "state.json").read_text(encoding="utf-8")).get("repo_path")
    if not target_repo:
        typer.echo("Provide --repo (no repo_path in the prior run's state.json).")
        raise typer.Exit(1)

    if hyp_id:
        selected = [h for h in hyps if h.get("id") == hyp_id]
        if not selected:
            typer.echo(f"Hypothesis {hyp_id} not found. Available: {[h.get('id') for h in hyps][:25]}")
            raise typer.Exit(1)
    else:
        selected = hyps[:3]

    _os.environ["SENTINEL_EXPLOIT_LOOP_MAX_ITERATIONS"] = str(iterations)
    from datetime import datetime, timezone

    from sentinel.config import get_settings
    from sentinel.reliability.subprocess import run_command as _run_command

    def _repo_commit(path: str) -> str:
        res = _run_command(["git", "rev-parse", "HEAD"], cwd=path, timeout=15)
        return res.stdout.strip() if res.return_code == 0 else "unknown"

    settings = get_settings()
    model = settings.model
    commit = _repo_commit(target_repo)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    state = initial_audit_state("exploit-replay", target_repo, "Replay exploit loop", str(run_path / "exploit-replay"))
    state["use_llm_refiner"] = True

    executor = ToolExecutor(build_default_registry())
    # Rebuild only function_ranges (fast, no slither) so the DSL knows the whole
    # protocol's function names for cross-contract call validation.
    executor.execute("static.map_function_ranges", {"repo_path": target_repo}, state)
    state["static_facts"]["function_ranges"] = state["last_outputs"].get("static.map_function_ranges", {}).get("ranges", [])

    for raw in selected:
        hyp = VulnerabilityHypothesis.model_validate(raw)
        # Immutable, independently-auditable artifact dir per attempt — earlier
        # reproductions are never overwritten by a later replay of the same hypothesis.
        attempt_dir = run_path / "exploit-replay" / f"{ts}-{hyp.id}"
        attempt_dir.mkdir(parents=True, exist_ok=True)
        state["run_dir"] = str(attempt_dir)
        typer.echo(f"\n=== {hyp.id}: {hyp.title[:80]} ({hyp.vulnerability_class}) ===")
        out = executor.execute(
            "dynamic.author_and_run_exploit",
            {"repo_path": target_repo, "hypothesis": hyp.model_dump(mode="json")},
            state,
        )
        data = out.data or {}
        # Persist full provenance so a verdict can be adjudicated later, not just trusted.
        (attempt_dir / "replay-meta.json").write_text(
            _json.dumps(
                {
                    "hypothesis_id": hyp.id,
                    "title": hyp.title,
                    "vulnerability_class": hyp.vulnerability_class,
                    "model": model,
                    "provider": settings.llm_provider,
                    "repo": target_repo,
                    "repo_commit": commit,
                    "iterations": iterations,
                    "timestamp": ts,
                    "verdict": data.get("verdict"),
                    "classification": data.get("classification"),
                    "result_summary": data.get("result_summary"),
                    "history": data.get("history", []),
                    "hypothesis": hyp.model_dump(mode="json"),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        typer.echo(f"verdict: {data.get('verdict')} | classification: {data.get('classification')}")
        for line in data.get("history", []):
            typer.echo(f"  {line}")
        typer.echo(f"  artifacts: {attempt_dir}")


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
