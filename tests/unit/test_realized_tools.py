from pathlib import Path

from sentinel.schemas.common import ToolStatus
from sentinel.schemas.research import VulnerabilityHypothesis
from sentinel.reliability.subprocess import CommandResult
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor


def test_repo_git_status_is_real_command(tmp_path):
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    output = executor.execute("repo.git_status", {"repo_path": str(tmp_path)}, state)

    assert output.status in {ToolStatus.OK, ToolStatus.ERROR, ToolStatus.UNAVAILABLE}
    if output.status != ToolStatus.UNAVAILABLE:
        assert output.data["command"] == ["git", "status", "--short"]


def test_dynamic_create_and_patch_poc_test(tmp_path):
    (tmp_path / "test").mkdir()
    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks guard",
            confidence=0.7,
        )
    ]
    executor = ToolExecutor(build_default_registry())

    created = executor.execute("dynamic.create_poc_test", {"repo_path": str(tmp_path)}, state)
    patched = executor.execute("dynamic.patch_poc_test", {"repo_path": str(tmp_path)}, state)

    assert created.status == ToolStatus.OK
    assert created.data["target_function"] == "emergencyWithdraw"
    assert patched.status == ToolStatus.OK
    assert Path(patched.data["path"]).exists()


def test_dynamic_generate_validation_artifact_plan_only_when_setup_unknown(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "runs" / "run-1"
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Unchecked transfer",
            vulnerability_class="unchecked_transfer",
            affected_files=["src/UnsafeTokenVault.sol"],
            affected_functions=["withdraw"],
            evidence_summary="Ignored ERC20 transfer return value",
            confidence=0.7,
        )
    ]
    executor = ToolExecutor(build_default_registry())

    generated = executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)

    plan_path = Path(generated.data["plan_path"])
    assert generated.status == ToolStatus.OK
    assert generated.data["path"] is None
    assert generated.data["generated_test"] is False
    assert plan_path.exists()
    assert "mock ERC20 that returns false" in plan_path.read_text(encoding="utf-8")
    assert state["artifacts"][0].kind == "validation_plan"


def test_dynamic_compile_validation_artifact_uses_temporary_worktree(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "run-1"
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]
    captured = {}

    def fake_which(name):
        return "/fake/forge" if name == "forge" else None

    def fake_run(command, cwd, timeout=60, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="compiled", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", fake_which)
    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)
    executor = ToolExecutor(build_default_registry())

    generated = executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    compiled = executor.execute("dynamic.compile_validation_artifacts", {"repo_path": str(repo)}, state)

    manifest = run_dir / "artifacts" / "validation-compile-result.json"
    assert generated.status == ToolStatus.OK
    assert compiled.status == ToolStatus.OK
    assert captured["command"] == ["forge", "build", "--offline"]
    assert captured["cwd"].endswith("artifacts/validation-worktree")
    assert manifest.exists()
    assert not (repo / "test").exists()
    assert any(artifact.kind == "validation_compile_result" for artifact in state["artifacts"])


def test_dynamic_run_validation_artifact_classifies_failure(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "run-1"
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]

    def fake_which(name):
        return "/fake/forge" if name == "forge" else None

    def fake_run(command, cwd, timeout=60, env=None):
        # A genuine ASSERTION failure (not a bare revert) is what counts as a violation.
        return CommandResult(command=command, cwd=str(cwd), return_code=1, stdout="[FAIL: assertion failed: 2 != 1] test_check()\n0 passed; 1 failed; 0 skipped", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", fake_which)
    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)
    executor = ToolExecutor(build_default_registry())

    executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    executed = executor.execute("dynamic.run_validation_artifacts", {"repo_path": str(repo)}, state)

    manifest = run_dir / "artifacts" / "validation-run-result.json"
    assert executed.status == ToolStatus.OK
    assert executed.data["command"] == ["forge", "test", "--offline", "--match-contract", "Sentinel"]
    assert executed.data["classification"] == "security_invariant_violation_or_test_needs_review"
    assert executed.data["test_names"] == ["SentinelMissingAccessControlemergencyWithdrawTest"]
    assert manifest.exists()
    assert not (repo / "test").exists()
    assert any(artifact.kind == "validation_run_result" for artifact in state["artifacts"])


def test_dynamic_run_validation_artifact_classifies_runtime_error(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(tmp_path / "runs" / "run-1"))
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", lambda name: "/fake/forge")
    monkeypatch.setattr(
        "sentinel.tools.dynamic.run_command",
        lambda command, cwd, timeout=60, env=None: CommandResult(command=command, cwd=str(cwd), return_code=-1, stdout="", stderr="The application panicked (crashed). Attempted to create a NULL object."),
    )
    executor = ToolExecutor(build_default_registry())

    executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    executed = executor.execute("dynamic.run_validation_artifacts", {"repo_path": str(repo)}, state)

    # A runtime crash is a tool failure, not a successful validation run.
    assert executed.status == ToolStatus.ERROR
    assert executed.data["classification"] == "validation_runtime_error"


def test_dynamic_repair_validation_artifacts_fixes_then_compiles(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}\n", encoding="utf-8")
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(tmp_path / "runs" / "run-1"))
    state["use_llm_refiner"] = True
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks auth",
            confidence=0.7,
        )
    ]

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", lambda name: "/fake/forge")

    # First compile fails (hallucinated member); after a repair is written, it compiles.
    calls = {"n": 0}

    def fake_run(command, cwd, timeout=60, env=None):
        calls["n"] += 1
        if calls["n"] == 1:
            return CommandResult(command=command, cwd=str(cwd), return_code=1, stdout="", stderr='Error (9582): Member "deposit" not found')
        return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="Compiling 1 files", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)

    class _StubRepairer:
        def repair(self, prompt: str) -> str:
            return "pragma solidity ^0.8.20;\ncontract SentinelFixed { function test_ok() public {} }\n"

    monkeypatch.setattr("sentinel.llm.provider.get_poc_repairer", lambda mock=False: _StubRepairer())

    executor = ToolExecutor(build_default_registry())
    executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo)}, state)
    repaired = executor.execute("dynamic.repair_validation_artifacts", {"repo_path": str(repo)}, state)

    assert repaired.status == ToolStatus.OK
    assert repaired.data["repaired"] is True
    assert repaired.data["repaired_files"]


def test_dynamic_repair_validation_artifacts_skips_without_llm(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(tmp_path / "runs" / "run-1"))
    # use_llm_refiner defaults to False -> repair is a no-op skip.
    executor = ToolExecutor(build_default_registry())
    out = executor.execute("dynamic.repair_validation_artifacts", {"repo_path": str(repo)}, state)
    assert out.status == ToolStatus.SKIPPED


def test_detect_test_fixture_picks_deploy_harness(tmp_path):
    from sentinel.tools.dynamic import _detect_test_fixture

    repo = tmp_path / "repo"
    (repo / "test").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    (repo / "test" / "Fixture.t.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Fixture {\n"
        "    function setUp() public {}\n"
        "    function createVault() public { new Vault(1); }\n"
        "    function deploy() public { thing.initialize(abi.encode(1)); new Consensus(2); new Oracle(3); }\n"
        "}\n",
        encoding="utf-8",
    )
    (repo / "test" / "Vault.t.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract VaultTest is Fixture { function test_x() public {} }\n", encoding="utf-8"
    )
    fixture = _detect_test_fixture(str(repo))
    assert fixture is not None
    assert fixture["name"] == "Fixture"
    assert fixture["import_path"] == "./Fixture.t.sol"


def test_generate_validation_artifacts_authors_when_plan_only(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "test").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    # Constructor args -> templates decline -> plan-only path.
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault { constructor(address a) {} function emergencyWithdraw(address to) external {} }\n",
        encoding="utf-8",
    )
    (repo / "test" / "Fixture.t.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Fixture { function setUp() public {} function createVault() public { new Vault(address(1)); thing.initialize(x); new Oracle(); } }\n",
        encoding="utf-8",
    )
    state = initial_audit_state("run-1", str(repo), "Find bugs", str(tmp_path / "runs" / "run-1"))
    state["use_llm_refiner"] = True
    hyp = VulnerabilityHypothesis(
        id="hyp-1",
        title="Missing access control",
        vulnerability_class="missing_access_control",
        affected_files=["src/Vault.sol"],
        affected_functions=["emergencyWithdraw"],
        evidence_summary="no auth",
        confidence=0.7,
    )

    class _StubAuthor:
        def author(self, prompt: str) -> str:
            assert "Fixture" in prompt  # grounded in the detected fixture
            return "pragma solidity ^0.8.20;\nimport {Fixture} from \"./Fixture.t.sol\";\ncontract SentinelPoC is Fixture { function test_poc() public {} }\n"

    monkeypatch.setattr("sentinel.llm.provider.get_poc_author", lambda mock=False: _StubAuthor())

    executor = ToolExecutor(build_default_registry())
    out = executor.execute("dynamic.generate_validation_artifacts", {"repo_path": str(repo), "hypothesis": hyp.model_dump(mode="json")}, state)
    assert out.data["generated_test"] is True
    assert out.data["authored_by_llm"] is True


def test_dynamic_parse_and_classify_test_output():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    parsed = executor.execute("dynamic.parse_test_output", {"status": "ok", "data": {"stdout": "1 passed; 0 failed"}}, state)
    classified = executor.execute("dynamic.classify_test_result", parsed.model_dump(mode="json"), state)

    assert parsed.status == ToolStatus.OK
    assert parsed.data["passed"] is True
    assert classified.data["classification"] == "poc_passed"


def test_report_add_evidence_and_rank_severity():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    state["hypotheses"] = [
        VulnerabilityHypothesis(
            id="hyp-1",
            title="Missing access control",
            vulnerability_class="missing_access_control",
            affected_files=["src/Vault.sol"],
            affected_functions=["emergencyWithdraw"],
            evidence_summary="Sensitive function lacks guard",
            confidence=0.7,
        )
    ]
    executor = ToolExecutor(build_default_registry())

    executor.execute("report.create_finding", {"data": {}}, state)
    evidence = executor.execute("report.add_evidence", {"data": {"kind": "test", "message": "extra evidence"}}, state)
    severity = executor.execute("report.rank_severity", {"data": {}}, state)

    assert evidence.status == ToolStatus.OK
    assert state["findings"][0].evidence[-1].message == "extra evidence"
    assert severity.data["severity"] == "high"


def test_memory_artifact_and_plan_tools():
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    executor = ToolExecutor(build_default_registry())

    artifact = executor.execute("memory.store_artifact_ref", {"data": {"kind": "report", "path": "runs/run-1/report.md"}}, state)
    plan = executor.execute("memory.get_plan_state", {"data": {}}, state)

    assert artifact.status == ToolStatus.OK
    assert artifact.data["artifact_count"] == 1
    assert plan.status == ToolStatus.OK


def test_author_and_run_exploit_confirms_when_invariant_breaks(monkeypatch, tmp_path):
    # Repo with a foundry fixture so the loop has something to inherit.
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "test").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault { function withdraw() external {} }\n", encoding="utf-8")
    (repo / "test" / "Base.t.sol").write_text("pragma solidity ^0.8.20;\nimport {Test} from \"forge-std/Test.sol\";\ncontract BaseTest is Test { function setUp() public {} }\n", encoding="utf-8")

    state = initial_audit_state("ex", str(repo), "Find bugs", str(tmp_path / "runs" / "ex"))
    state["use_llm_refiner"] = True
    hyp = VulnerabilityHypothesis(
        id="hyp-1", title="Withdraw breaks solvency", vulnerability_class="accounting",
        affected_files=["src/Vault.sol"], affected_functions=["withdraw"],
        evidence_summary="x", confidence=0.6, required_proof="total assets >= total debt",
    )
    state["hypotheses"] = [hyp]

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", lambda name: "/fake/forge")
    monkeypatch.setattr("sentinel.tools.dynamic._detect_test_fixture", lambda repo_path, **k: {"name": "BaseTest", "import_path": "./Base.t.sol", "source": "contract BaseTest {}"})
    monkeypatch.setattr("sentinel.tools.dynamic._copy_repo_for_validation", lambda repo_path, worktree: (worktree / "test").mkdir(parents=True, exist_ok=True))

    class _Author:
        def author(self, prompt):
            return "```solidity\npragma solidity ^0.8.20;\ncontract SentinelwithdrawExploit { function test_x() public {} }\n```"

    monkeypatch.setattr("sentinel.llm.provider.get_poc_author", lambda mock=False: _Author())

    calls = {"n": 0}

    def fake_run(command, cwd, timeout=60, env=None):
        calls["n"] += 1
        if command[:2] == ["forge", "build"]:
            return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="Compiling", stderr="")
        # forge test -> a failing assertion (free-form path; no differential control)
        return CommandResult(command=command, cwd=str(cwd), return_code=1, stdout="[FAIL: assertion failed] test_x()\n1 failed", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)

    out = ToolExecutor(build_default_registry()).execute("dynamic.author_and_run_exploit", {"repo_path": str(repo), "hypothesis": hyp.model_dump(mode="json")}, state)
    # Free-form has no control, so a failing assertion is a LEAD, not a confirmed proof.
    assert out.data["verdict"] == "needs_review"
    assert out.data["classification"] == "security_invariant_violation_or_test_needs_review"


def test_author_and_run_exploit_skips_without_llm(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    state = initial_audit_state("ex2", str(repo), "x", str(tmp_path / "runs" / "ex2"))
    out = ToolExecutor(build_default_registry()).execute("dynamic.author_and_run_exploit", {"repo_path": str(repo)}, state)
    assert out.status == ToolStatus.SKIPPED


def test_author_and_run_exploit_uses_dsl_plan_when_available(monkeypatch, tmp_path):
    # Regression for the smoke-run finding: the DSL path was never taken because
    # the PoC author emitted Solidity (its system prompt) instead of a plan, so
    # parse_plan always failed. With an author that implements author_plan and
    # returns valid plan JSON, the loop must confirm THROUGH the DSL.
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "test").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault { function withdraw() external {} }\n", encoding="utf-8")
    (repo / "test" / "Base.t.sol").write_text(
        "pragma solidity ^0.8.20;\nimport {Test} from \"forge-std/Test.sol\";\ncontract BaseTest is Test { function setUp() public {} }\n", encoding="utf-8")

    state = initial_audit_state("exd", str(repo), "Find bugs", str(tmp_path / "runs" / "exd"))
    state["use_llm_refiner"] = True
    hyp = VulnerabilityHypothesis(
        id="hyp-1", title="Withdraw breaks solvency", vulnerability_class="accounting",
        affected_files=["src/Vault.sol"], affected_functions=["withdraw"],
        evidence_summary="x", confidence=0.6, required_proof="total assets >= total debt",
    )
    state["hypotheses"] = [hyp]

    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", lambda name: "/fake/forge")
    monkeypatch.setattr("sentinel.tools.dynamic._detect_test_fixture", lambda repo_path, **k: {"name": "BaseTest", "import_path": "./Base.t.sol", "surface": "", "source": "contract BaseTest {}"})
    monkeypatch.setattr("sentinel.tools.dynamic._copy_repo_for_validation", lambda repo_path, worktree: (worktree / "test").mkdir(parents=True, exist_ok=True))

    plan_json = (
        '{"actors":[{"name":"attacker","funds_wei":1000000000000000000}],'
        '"attack_calls":[{"actor":"attacker","target":"","function":"withdraw","args":[]}],'
        '"before":[{"name":"bal","expr":"address(this).balance"}],'
        '"after":[{"name":"bal","expr":"address(this).balance"}],'
        '"invariant":{"description":"solvency","assertion":"after_bal >= before_bal"}}'
    )

    class _PlanAuthor:
        def author(self, prompt):  # free-form path must NOT be used
            raise AssertionError("free-form author should not be called when the DSL plan is valid")

        def author_plan(self, prompt):
            return plan_json

    monkeypatch.setattr("sentinel.llm.provider.get_poc_author", lambda mock=False: _PlanAuthor())

    def fake_run(command, cwd, timeout=60, env=None):
        if command[:2] == ["forge", "build"]:
            return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="Compiling", stderr="")
        joined = " ".join(command)
        # Differential control: the CONTROL run (attack removed) holds; the treatment
        # run (attack present) breaks the invariant -> the break is caused by the attack.
        if "Control" in joined:
            return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="1 passed; 0 failed; 0 skipped", stderr="")
        return CommandResult(command=command, cwd=str(cwd), return_code=1, stdout="[FAIL: assertion failed] test_exploit()\n0 passed; 1 failed; 0 skipped", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)

    out = ToolExecutor(build_default_registry()).execute("dynamic.author_and_run_exploit", {"repo_path": str(repo), "hypothesis": hyp.model_dump(mode="json")}, state)
    # Confirmed ONLY because the differential control passed (causal proof).
    assert out.data["verdict"] == "confirmed"
    assert out.data["classification"] == "security_invariant_violation_or_test_needs_review"
    assert any("dsl iter 1: ran ->" in h for h in out.data["history"])
    assert any("control (attack removed) -> security_invariant_held_or_test_passed" in h for h in out.data["history"])
    assert not any("unparseable" in h for h in out.data["history"])


def test_author_and_run_exploit_rejects_vacuous_break(monkeypatch, tmp_path):
    # A DSL plan whose assertion fails EVEN WITHOUT the attack (control also fails)
    # is vacuous and must NOT confirm.
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "test").mkdir(parents=True)
    (repo / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault { function withdraw() external {} }\n", encoding="utf-8")
    (repo / "test" / "Base.t.sol").write_text(
        "pragma solidity ^0.8.20;\nimport {Test} from \"forge-std/Test.sol\";\ncontract BaseTest is Test { function setUp() public {} }\n", encoding="utf-8")

    state = initial_audit_state("exv", str(repo), "Find bugs", str(tmp_path / "runs" / "exv"))
    state["use_llm_refiner"] = True
    hyp = VulnerabilityHypothesis(
        id="hyp-1", title="Withdraw breaks solvency", vulnerability_class="accounting",
        affected_files=["src/Vault.sol"], affected_functions=["withdraw"],
        evidence_summary="x", confidence=0.6,
    )
    state["hypotheses"] = [hyp]
    monkeypatch.setattr("sentinel.tools.dynamic.shutil.which", lambda name: "/fake/forge")
    monkeypatch.setattr("sentinel.tools.dynamic._detect_test_fixture", lambda repo_path, **k: {"name": "BaseTest", "import_path": "./Base.t.sol", "surface": "", "source": "contract BaseTest {}"})
    monkeypatch.setattr("sentinel.tools.dynamic._copy_repo_for_validation", lambda repo_path, worktree: (worktree / "test").mkdir(parents=True, exist_ok=True))

    plan_json = (
        '{"actors":[{"name":"attacker","funds_wei":1}],'
        '"attack_calls":[{"actor":"attacker","target":"","function":"withdraw","args":[]}],'
        '"before":[{"name":"bal","expr":"address(this).balance"}],'
        '"after":[{"name":"bal","expr":"address(this).balance"}],'
        '"invariant":{"description":"d","assertion":"after_bal >= before_bal"}}'
    )

    class _PlanAuthor:
        def author(self, prompt):
            return "```solidity\npragma solidity ^0.8.20;\ncontract SentinelwithdrawExploit { function test_x() public {} }\n```"

        def author_plan(self, prompt):
            return plan_json

    monkeypatch.setattr("sentinel.llm.provider.get_poc_author", lambda mock=False: _PlanAuthor())

    def fake_run(command, cwd, timeout=60, env=None):
        if command[:2] == ["forge", "build"]:
            return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="Compiling", stderr="")
        # BOTH treatment and control fail -> vacuous (failure not caused by the attack)
        return CommandResult(command=command, cwd=str(cwd), return_code=1, stdout="[FAIL: assertion failed] t()\n0 passed; 1 failed; 0 skipped", stderr="")

    monkeypatch.setattr("sentinel.tools.dynamic.run_command", fake_run)

    out = ToolExecutor(build_default_registry()).execute("dynamic.author_and_run_exploit", {"repo_path": str(repo), "hypothesis": hyp.model_dump(mode="json")}, state)
    assert out.data["verdict"] != "confirmed"
    assert any("vacuous" in h.lower() or "control" in h.lower() for h in out.data["history"])


def test_build_receiver_typing_resolves_instances_chains_and_arity(tmp_path):
    from sentinel.tools.dynamic import _build_receiver_typing, _contract_signatures

    (tmp_path / "src").mkdir()
    # Orchestrator exposes Pool via a public getter; Pool has deposit(uint256,address).
    (tmp_path / "src" / "Deploy.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Deploy { Pool public pool; }\n", encoding="utf-8")
    (tmp_path / "src" / "Pool.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Pool {\n"
        "  function deposit(uint256 a, address r) external returns (uint256) {}\n"
        "  function totalAssets() external view returns (uint256) {}\n}\n",
        encoding="utf-8")

    fixture = {
        "surface": "State variables available:\n  Deploy protocol\n",
        "source": "contract BaseTest { Deploy protocol; }",
    }
    receiver_types, type_signatures = _build_receiver_typing(str(tmp_path), fixture)
    # bare instance + getter chain both resolve to their concrete types
    assert receiver_types.get("protocol") == "Deploy"
    assert receiver_types.get("protocol.pool()") == "Pool"
    # precise signatures (arity) extracted for the chain's type
    assert type_signatures["Pool"]["deposit"] == {2}
    assert type_signatures["Pool"]["totalAssets"] == {0}


def test_build_receiver_typing_uses_artifact_abi_for_inherited_functions(tmp_path):
    from sentinel.tools.dynamic import _build_receiver_typing

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract BaseVault { function deposit(uint256 assets, address receiver) public returns (uint256) {} }\n"
        "contract Vault is BaseVault { function withdraw(uint256 assets) external {} }\n",
        encoding="utf-8",
    )
    artifact_dir = tmp_path / "out" / "src" / "Vault.sol"
    artifact_dir.mkdir(parents=True)
    (artifact_dir / "Vault.json").write_text(
        '{"abi":['
        '{"type":"function","name":"deposit","inputs":[{"type":"uint256"},{"type":"address"}]},'
        '{"type":"function","name":"withdraw","inputs":[{"type":"uint256"}]}'
        ']}',
        encoding="utf-8",
    )

    fixture = {
        "surface": "State variables available:\n  Vault vault\n",
        "source": "contract BaseTest { Vault vault; }",
    }
    receiver_types, type_signatures = _build_receiver_typing(str(tmp_path), fixture)

    assert receiver_types["vault"] == "Vault"
    assert type_signatures["Vault"]["deposit"] == {2}
    assert type_signatures["Vault"]["withdraw"] == {1}


def test_contract_signatures_extracts_public_external_only():
    from sentinel.tools.dynamic import _contract_signatures

    body = (
        "contract C {\n"
        "  function a(uint256 x) public {}\n"
        "  function b() external view returns (uint256) {}\n"
        "  function _hidden(uint256 x) internal {}\n"
        "  uint256 public count;\n}\n"
    )
    sigs = _contract_signatures(body)
    assert sigs["a"] == {1}
    assert sigs["b"] == {0}
    assert sigs["count"] == {0}  # public state-var getter
    assert "_hidden" not in sigs  # internal excluded
