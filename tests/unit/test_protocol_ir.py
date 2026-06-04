from pathlib import Path

from sentinel.analysis.protocol_ir import build_protocol_graph, build_protocol_ir, protocol_ir_summary
from sentinel.tools.repo import RepoPathInput
from sentinel.tools.static import map_function_ranges


def test_protocol_ir_extracts_graph_facts_from_production_sources(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Game.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "interface IERC721 { function transferFrom(address from, address to, uint256 id) external; }",
                "contract EggVault {",
                "    IERC721 public nft;",
                "    mapping(uint256 => address) public depositedBy;",
                "    address public owner;",
                "    constructor() { owner = msg.sender; }",
                "    modifier onlyOwner() { require(msg.sender == owner, \"owner\"); _; }",
                "    function deposit(uint256 tokenId, address creditedTo) external {",
                "        nft.transferFrom(msg.sender, address(this), tokenId);",
                "        depositedBy[tokenId] = creditedTo;",
                "    }",
                "    function configure(address next) external onlyOwner {",
                "        owner = next;",
                "    }",
                "}",
                "contract EggGame {",
                "    EggVault public vault;",
                "    function hunt(uint256 tokenId) external {",
                "        if (uint256(blockhash(block.number - 1)) % 2 == 0) {",
                "            vault.deposit(tokenId, msg.sender);",
                "        }",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]

    ir = build_protocol_ir(
        str(tmp_path),
        {
            "function_ranges": ranges,
            "token_types": [{"symbol": "nft", "kind": "erc721", "source": "state_variable"}],
        },
    )
    summary = protocol_ir_summary(ir)

    assert set(ir.contract_names()) >= {"EggVault", "EggGame"}
    assert {"deposit", "configure", "hunt"}.issubset(set(ir.function_names()))
    assert any(flow.asset_kind == "erc721" and flow.function_name == "deposit" for flow in ir.asset_flows)
    assert any(access.variable_name == "depositedBy" and access.access == "write" for access in ir.storage_accesses)
    assert any(auth.role == "owner" and auth.function_name == "configure" for auth in ir.auth_constraints)
    assert any(edge.receiver_symbol == "vault" and edge.to_contract == "EggVault" and edge.to_function == "deposit" for edge in ir.call_edges)
    assert summary["trust_boundaries"] >= 1
    assert ir.completeness_gaps


def test_protocol_ir_keeps_state_variables_contract_scoped(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Multi.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract A {",
                "    uint256 public aBalance;",
                "    function setA(uint256 value) external { aBalance = value; }",
                "}",
                "contract B {",
                "    uint256 public bBalance;",
                "    function setB(uint256 value) external { bBalance = value; }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]

    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges})

    assert any(item.contract_name == "A" and item.variable_name == "aBalance" for item in ir.storage_accesses)
    assert not any(item.contract_name == "A" and item.variable_name == "bBalance" for item in ir.storage_accesses)
    assert any(item.contract_name == "B" and item.variable_name == "bBalance" for item in ir.storage_accesses)
    assert not any(item.contract_name == "B" and item.variable_name == "aBalance" for item in ir.storage_accesses)


def test_protocol_ir_does_not_treat_array_push_as_external_call(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "List.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract List {",
                "    address[] public teachers;",
                "    function add(address teacher) external {",
                "        teachers.push(teacher);",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]

    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges})

    assert not any(edge.receiver_symbol == "teachers" and edge.to_function == "push" for edge in ir.call_edges)
    assert not any(boundary.function_name == "add" and boundary.boundary_kind == "external_call" for boundary in ir.trust_boundaries)


def test_protocol_graph_builds_attack_path_slices(tmp_path: Path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "interface IERC721 { function transferFrom(address from, address to, uint256 id) external; }",
                "contract Vault {",
                "    IERC721 public nft;",
                "    mapping(uint256 => address) public depositedBy;",
                "    function deposit(uint256 tokenId, address creditedTo) external {",
                "        nft.transferFrom(msg.sender, address(this), tokenId);",
                "        depositedBy[tokenId] = creditedTo;",
                "    }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    ranges = map_function_ranges(RepoPathInput(repo_path=str(tmp_path)), {}).model_dump(mode="json")["ranges"]
    ir = build_protocol_ir(str(tmp_path), {"function_ranges": ranges, "token_types": [{"symbol": "nft", "kind": "erc721", "source": "state_variable"}]})

    graph = build_protocol_graph(ir)

    assert graph.slices
    deposit_slice = next(item for item in graph.slices if item.entry_function == "deposit")
    assert deposit_slice.asset_flows
    assert any(access.variable_name == "depositedBy" for access in deposit_slice.storage_accesses)
    assert deposit_slice.proof_status in {"strong_local_path", "missing_counterevidence"}
    assert any(path.graph_slice_id == deposit_slice.slice_id for path in graph.attack_paths)
