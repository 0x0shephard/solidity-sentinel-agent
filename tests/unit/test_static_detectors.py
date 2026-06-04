from pathlib import Path

from sentinel.schemas.common import ToolStatus
from sentinel.tools.static import (
    detect_dangerous_delegatecall,
    detect_external_call_before_accounting,
    detect_oracle_staleness_logic,
    detect_public_vault_accounting_spoof,
    detect_strategy_accounting_trust,
    detect_tx_origin_auth,
    detect_unguarded_initializer,
    detect_unchecked_erc20_returns,
    detect_unsafe_or_guards,
    detect_weak_randomness,
)
from sentinel.tools.repo import RepoPathInput


def _repo(tmp_path: Path, source: str) -> Path:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Target.sol").write_text(source, encoding="utf-8")
    return repo


def _classes(output):
    assert output.status == ToolStatus.OK
    assert output.detections
    assert output.detections[0].evidence
    assert output.detections[0].checklist_refs
    return {detection.vulnerability_class for detection in output.detections}


def test_detect_tx_origin_auth(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ncontract Target {\naddress owner;\nfunction x() external {\nrequire(tx.origin == owner, 'auth');\n}\n}",
    )

    assert "tx_origin_authorization" in _classes(detect_tx_origin_auth(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_unguarded_initializer(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ncontract Target {\naddress owner;\nbool initialized;\nfunction initialize(address o) external {\nowner = o;\ninitialized = true;\n}\n}",
    )

    assert "unguarded_initializer" in _classes(detect_unguarded_initializer(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_oracle_staleness_logic(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ninterface O { function price() external returns(uint,uint); }\ncontract Target {\nO oracle;\nfunction x() external {\n(uint p,uint updatedAt)=oracle.price();\nrequire(p > 0 || block.timestamp - updatedAt < 1 hours, 'oracle');\n}\n}",
    )

    assert "oracle_staleness_logic" in _classes(detect_oracle_staleness_logic(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_unchecked_erc20_returns(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ninterface T { function transfer(address,uint) external returns(bool); }\ncontract Target {\nT token;\nfunction x(address to) external {\ntoken.transfer(to, 1);\n}\n}",
    )

    assert "unchecked_erc20_return" in _classes(detect_unchecked_erc20_returns(RepoPathInput(repo_path=str(repo)), {}))


def test_unchecked_erc20_detector_ignores_erc721_transfer_from(tmp_path):
    repo = _repo(
        tmp_path,
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "import '@openzeppelin/contracts/token/ERC721/ERC721.sol';",
                "contract Egg is ERC721 { constructor() ERC721('E','E') {} }",
                "contract Target {",
                "Egg eggNFT;",
                "function x(uint256 tokenId) external {",
                "eggNFT.transferFrom(msg.sender, address(this), tokenId);",
                "}",
                "}",
            ]
        ),
    )

    output = detect_unchecked_erc20_returns(RepoPathInput(repo_path=str(repo)), {})

    assert output.status == ToolStatus.OK
    assert output.detections == []


def test_unchecked_erc20_detector_ignores_cross_file_custom_erc721(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Egg.sol").write_text(
        "pragma solidity ^0.8.20;\nimport '@openzeppelin/contracts/token/ERC721/ERC721.sol';\ncontract EggToken is ERC721 { constructor() ERC721('E','E') {} }",
        encoding="utf-8",
    )
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\nimport './Egg.sol';\ncontract Vault { EggToken public eggNFT; function x(uint256 tokenId) external { eggNFT.transferFrom(msg.sender, address(this), tokenId); } }",
        encoding="utf-8",
    )

    output = detect_unchecked_erc20_returns(RepoPathInput(repo_path=str(repo)), {})

    assert output.status == ToolStatus.OK
    assert output.detections == []


def test_detect_weak_randomness(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ncontract Target {\nuint eggCounter;\nfunction searchForEgg() external {\nuint r = uint(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, msg.sender, eggCounter))) % 100;\nif (r < 20) { eggCounter++; }\n}\n}",
    )

    assert "weak_randomness" in _classes(detect_weak_randomness(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_public_vault_accounting_spoof(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ninterface N { function ownerOf(uint256) external view returns(address); }\ncontract Target {\nN nft;\nmapping(uint256 => address) depositors;\nmapping(uint256 => bool) stored;\nfunction deposit(uint256 id, address depositor) public {\nrequire(nft.ownerOf(id) == address(this));\nstored[id] = true;\ndepositors[id] = depositor;\n}\n}",
    )

    assert "vault_accounting_spoof" in _classes(detect_public_vault_accounting_spoof(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_dangerous_delegatecall(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ncontract Target {\nfunction x(address target, bytes calldata data) external {\ntarget.delegatecall(data);\n}\n}",
    )

    assert "dangerous_delegatecall" in _classes(detect_dangerous_delegatecall(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_unsafe_or_guards(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ncontract Target {\nfunction x(uint fee, uint limit) external {\nrequire(fee < 10 || limit < 100, 'guard');\n}\n}",
    )

    assert "unsafe_or_guard" in _classes(detect_unsafe_or_guards(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_external_call_before_accounting(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ncontract Target {\nmapping(address=>uint) balanceOf;\nfunction x(address a) external {\na.call('');\nbalanceOf[msg.sender] = 0;\n}\n}",
    )

    assert "external_call_before_accounting" in _classes(detect_external_call_before_accounting(RepoPathInput(repo_path=str(repo)), {}))


def test_detect_strategy_accounting_trust(tmp_path):
    repo = _repo(
        tmp_path,
        "pragma solidity ^0.8.20;\ninterface S { function estimatedTotalAssets() external returns(uint); }\ncontract Target {\nmapping(address=>uint) debt;\nuint totalManagedDebt;\nfunction x(address strategy) external {\nuint reported = S(strategy).estimatedTotalAssets();\ndebt[strategy] = reported;\ntotalManagedDebt += reported;\n}\n}",
    )

    assert "strategy_accounting_trust" in _classes(detect_strategy_accounting_trust(RepoPathInput(repo_path=str(repo)), {}))
