// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20SafeLike {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IOracleSafeLike {
    function price(address token) external view returns (uint256 value, uint256 updatedAt);
}

contract SafeVault {
    IERC20SafeLike public asset;
    IOracleSafeLike public oracle;
    address public owner;
    bool public initialized;
    bool private locked;
    mapping(address => uint256) public balanceOf;

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "LOCKED");
        locked = true;
        _;
        locked = false;
    }

    function initialize(address asset_, address oracle_) external {
        require(!initialized, "INITIALIZED");
        initialized = true;
        owner = msg.sender;
        asset = IERC20SafeLike(asset_);
        oracle = IOracleSafeLike(oracle_);
    }

    function deposit(uint256 amount) external {
        require(asset.transferFrom(msg.sender, address(this), amount), "TRANSFER_FROM");
        balanceOf[msg.sender] += amount;
    }

    function withdraw(uint256 amount) external nonReentrant {
        balanceOf[msg.sender] -= amount;
        require(asset.transfer(msg.sender, amount), "TRANSFER");
    }

    function depositWithOracle(uint256 amount) external {
        (uint256 p, uint256 updatedAt) = oracle.price(address(asset));
        require(p > 0 && updatedAt != 0 && block.timestamp - updatedAt < 2 hours, "ORACLE");
        require(asset.transferFrom(msg.sender, address(this), amount), "TRANSFER_FROM");
        balanceOf[msg.sender] += amount;
    }

    function sweep(address token, address to, uint256 amount) external onlyOwner {
        require(token != address(asset), "ASSET");
        require(IERC20SafeLike(token).transfer(to, amount), "TRANSFER");
    }
}

