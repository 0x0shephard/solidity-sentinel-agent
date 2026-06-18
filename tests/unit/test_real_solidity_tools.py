import json

from sentinel.schemas.common import ToolStatus
from sentinel.state import initial_audit_state
from sentinel.tools import build_default_registry
from sentinel.tools.executor import ToolExecutor
from sentinel.reliability.subprocess import CommandResult


def test_foundry_build_uses_safe_command(monkeypatch, tmp_path):
    captured = {}

    def fake_which(name):
        return "/fake/forge" if name == "forge" else None

    def fake_run(command, cwd, timeout=60, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="ok", stderr="")

    monkeypatch.setattr("sentinel.tools.build.shutil.which", fake_which)
    monkeypatch.setattr("sentinel.tools.build.run_command", fake_run)

    state = initial_audit_state("run-1", str(tmp_path), "Find bugs", "runs/run-1")
    output = ToolExecutor(build_default_registry()).execute("build.foundry_build", {"repo_path": str(tmp_path)}, state)

    assert output.status == ToolStatus.OK
    assert captured["command"] == ["forge", "build"]
    assert captured["cwd"] == str(tmp_path)
    # Cold real-protocol builds need a generous, configurable timeout (was 120s,
    # which was silently timing out and reporting a blank build error).
    from sentinel.config import get_settings
    assert captured["timeout"] == get_settings().forge_command_timeout


def test_run_slither_uses_workspace_local_home(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_dir = tmp_path / "runs" / "run-1"
    captured = {}

    def fake_which(name):
        return "/fake/slither" if name == "slither" else None

    def fake_run(command, cwd, timeout=60, env=None):
        captured["command"] = command
        captured["cwd"] = cwd
        captured["timeout"] = timeout
        captured["home"] = env["HOME"]
        json_path = command[-1]
        with open(json_path, "w", encoding="utf-8") as handle:
            json.dump({"success": True, "results": {"detectors": []}}, handle)
        return CommandResult(command=command, cwd=str(cwd), return_code=0, stdout="", stderr="")

    monkeypatch.setattr("sentinel.tools.static.shutil.which", fake_which)
    monkeypatch.setattr("sentinel.tools.static.run_command", fake_run)

    state = initial_audit_state("run-1", str(repo), "Find bugs", str(run_dir))
    output = ToolExecutor(build_default_registry()).execute("static.run_slither", {"repo_path": str(repo)}, state)

    assert output.status == ToolStatus.OK
    assert output.raw_json_path.endswith("artifacts/slither.json")
    assert captured["command"][:2] == ["slither", str(repo)]
    assert captured["home"].endswith("artifacts/slither-home")


def test_parse_slither_json(tmp_path):
    slither_json = tmp_path / "slither.json"
    slither_json.write_text(
        json.dumps(
            {
                "success": True,
                "results": {
                    "detectors": [
                        {
                            "check": "reentrancy-eth",
                            "impact": "High",
                            "confidence": "Medium",
                            "description": "Possible reentrancy",
                            "elements": [
                                {
                                    "name": "withdraw",
                                    "type": "function",
                                    "source_mapping": {"filename_relative": "src/Vault.sol"},
                                }
                            ],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    state = initial_audit_state("run-1", ".", "Find bugs", "runs/run-1")
    output = ToolExecutor(build_default_registry()).execute("static.parse_slither", {"raw_json_path": str(slither_json)}, state)

    assert output.status == ToolStatus.OK
    assert output.finding_count == 1
    assert output.findings[0].check == "reentrancy-eth"
    assert output.findings[0].source_files == ["src/Vault.sol"]
    assert output.findings[0].functions == ["withdraw"]


def test_extract_storage_writes_ignores_mapping_type_arrow(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "Vault.sol").write_text(
        """
pragma solidity ^0.8.20;

contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }
}
""",
        encoding="utf-8",
    )
    state = initial_audit_state("run-1", str(repo), "Find bugs", "runs/run-1")
    output = ToolExecutor(build_default_registry()).execute("static.extract_storage_writes", {"repo_path": str(repo)}, state)

    assert output.status == ToolStatus.OK
    assert [fact["text"] for fact in output.facts] == ["balances[msg.sender] += msg.value;"]
