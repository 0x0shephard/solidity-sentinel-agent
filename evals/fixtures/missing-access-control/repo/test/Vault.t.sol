// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../src/Vault.sol";

contract VaultTest {
    Vault vault;

    function setUp() public {
        vault = new Vault();
    }
}

