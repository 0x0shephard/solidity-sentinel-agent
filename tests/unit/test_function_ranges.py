from pathlib import Path

from sentinel.solidity.ranges import build_function_ranges, containing_function


def test_function_range_mapper_maps_multiline_function(tmp_path):
    repo = tmp_path / "repo"
    src = repo / "src"
    src.mkdir(parents=True)
    (src / "Vault.sol").write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.20;",
                "contract Vault {",
                "    function initialize(",
                "        address owner_",
                "    ) external {",
                "        owner = owner_;",
                "    }",
                "    receive() external payable {}",
                "}",
            ]
        ),
        encoding="utf-8",
    )

    ranges = build_function_ranges(repo)
    initialize = containing_function(ranges, "src/Vault.sol", 6)
    receive_fn = containing_function(ranges, "src/Vault.sol", 8)

    assert initialize is not None
    assert initialize.contract_name == "Vault"
    assert initialize.function_name == "initialize"
    assert initialize.start_line == 3
    assert initialize.end_line == 7
    assert receive_fn is not None
    assert receive_fn.function_name == "receive"

