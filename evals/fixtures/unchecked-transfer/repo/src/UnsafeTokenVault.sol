// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract UnsafeTokenVault {
    IERC20 public token;
    mapping(address => uint256) public balances;

    constructor(IERC20 _token) {
        token = _token;
    }

    function deposit(uint256 amount) external {
        require(token.transferFrom(msg.sender, address(this), amount));
        balances[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        token.transfer(msg.sender, amount);
    }
}
