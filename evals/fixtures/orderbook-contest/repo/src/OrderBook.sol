// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract OrderBook {
    struct SellOrder {
        address seller;
        uint256 amountToSell;
        uint256 priceInUSDC;
        uint256 deadlineTimestamp;
        bool isActive;
    }

    IERC20 public immutable asset;
    IERC20 public immutable usdc;
    uint256 public feeBps = 3;
    uint256 public totalFees;
    uint256 public nextOrderId;
    mapping(uint256 => SellOrder) public orders;

    constructor(IERC20 _asset, IERC20 _usdc) {
        asset = _asset;
        usdc = _usdc;
    }

    function createSellOrder(uint256 amountToSell, uint256 priceInUSDC, uint256 deadlineTimestamp) external returns (uint256 orderId) {
        require(deadlineTimestamp > block.timestamp, "expired");
        orderId = nextOrderId++;
        orders[orderId] = SellOrder({
            seller: msg.sender,
            amountToSell: amountToSell,
            priceInUSDC: priceInUSDC,
            deadlineTimestamp: deadlineTimestamp,
            isActive: true
        });
        require(asset.transferFrom(msg.sender, address(this), amountToSell), "asset transfer failed");
    }

    function amendSellOrder(uint256 orderId, uint256 amountToSell, uint256 priceInUSDC, uint256 deadlineTimestamp) external {
        SellOrder storage order = orders[orderId];
        require(order.seller == msg.sender, "not seller");
        require(order.isActive, "inactive");
        require(deadlineTimestamp > block.timestamp, "expired");
        order.amountToSell = amountToSell;
        order.priceInUSDC = priceInUSDC;
        order.deadlineTimestamp = deadlineTimestamp;
    }

    function cancelSellOrder(uint256 orderId) external {
        SellOrder storage order = orders[orderId];
        require(order.seller == msg.sender, "not seller");
        require(order.isActive, "inactive");
        order.isActive = false;
        require(asset.transfer(order.seller, order.amountToSell), "asset transfer failed");
    }

    function buyOrder(uint256 orderId) external {
        SellOrder storage order = orders[orderId];
        require(order.isActive, "inactive");
        require(block.timestamp <= order.deadlineTimestamp, "expired");
        uint256 usdcAmount = order.amountToSell * order.priceInUSDC;
        uint256 fee = (usdcAmount * feeBps) / 10_000;
        order.isActive = false;
        totalFees += fee;
        require(usdc.transferFrom(msg.sender, order.seller, usdcAmount - fee), "pay seller failed");
        require(usdc.transferFrom(msg.sender, address(this), fee), "pay fee failed");
        require(asset.transfer(msg.sender, order.amountToSell), "send asset failed");
    }
}
