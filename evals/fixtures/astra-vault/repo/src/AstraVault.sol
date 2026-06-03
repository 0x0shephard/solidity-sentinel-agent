// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20Like {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function decimals() external view returns (uint8);
}

interface IFlashBorrower {
    function onFlashLoan(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32);
}

interface IStrategyLike {
    function deposit(uint256 amount) external returns (uint256 accepted);
    function withdraw(uint256 amount, address receiver) external returns (uint256 returnedAmount);
    function estimatedTotalAssets() external returns (uint256);
}

interface IPriceOracleLike {
    function price(address token) external view returns (uint256 value, uint256 updatedAt);
}

interface IWithdrawHook {
    function beforeWithdraw(
        address caller,
        address owner,
        uint256 assets,
        uint256 shares,
        bytes calldata data
    ) external;
}

contract AstraVault {
    struct StrategyData {
        bool active;
        bool trusted;
        uint16 targetBps;
        uint64 lastReport;
        uint256 debt;
        uint256 idleLimit;
    }

    string public name;
    string public symbol;
    uint8 public decimals;

    IERC20Like public asset;
    address public owner;
    address public pendingOwner;
    address public keeper;
    address public treasury;
    address public oracle;
    address public withdrawHook;

    uint256 public totalSupply;
    uint256 public totalManagedDebt;
    uint256 public highWaterMark;
    uint256 public lastAccountingUpdate;
    uint256 public withdrawDelay;
    uint256 public epochLength;
    uint256 public flashFeeBps;
    uint256 public managementFeeBps;
    uint256 public performanceFeeBps;
    uint256 public maxTotalAssets;
    uint256 public creditScalar;

    bool public paused;
    bool public initialized;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;
    mapping(address => uint256) public lastDepositAt;
    mapping(address => uint256) public rewardDebt;
    mapping(address => uint256) public accountCredit;
    mapping(address => StrategyData) public strategies;
    address[] public strategyList;

    bytes32 private constant FLASH_CALLBACK_SUCCESS = keccak256("ERC3156FlashBorrower.onFlashLoan");

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    event StrategyAdded(address indexed strategy, uint16 targetBps, bool trusted);
    event StrategyReported(address indexed strategy, uint256 oldDebt, uint256 newDebt, uint256 keeperRewardShares);
    event FlashLoan(address indexed borrower, uint256 amount, uint256 fee);
    event Rebalanced(address indexed strategy, int256 amountDelta);
    event Paused(bool status);

    modifier onlyOwner() {
        require(msg.sender == owner || tx.origin == owner, "NOT_OWNER");
        _;
    }

    modifier onlyKeeper() {
        require(msg.sender == keeper || msg.sender == owner || tx.origin == keeper, "NOT_KEEPER");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "PAUSED");
        _;
    }

    function initialize(
        address asset_,
        address treasury_,
        string memory name_,
        string memory symbol_
    ) external {
        asset = IERC20Like(asset_);
        treasury = treasury_;
        owner = msg.sender;
        keeper = msg.sender;
        name = name_;
        symbol = symbol_;
        withdrawDelay = 1 days;
        epochLength = 6 hours;
        flashFeeBps = 8;
        managementFeeBps = 50;
        performanceFeeBps = 1_500;
        maxTotalAssets = type(uint256).max;
        creditScalar = 1e18;
        lastAccountingUpdate = block.timestamp;
        highWaterMark = 1e18;

        try IERC20Like(asset_).decimals() returns (uint8 d) {
            decimals = d;
        } catch {
            decimals = 18;
        }

        initialized = true;
    }

    receive() external payable {}

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            allowance[from][msg.sender] = allowed - amount;
            emit Approval(from, msg.sender, allowance[from][msg.sender]);
        }
        _transfer(from, to, amount);
        return true;
    }

    function permit(
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        require(block.timestamp <= deadline, "EXPIRED");
        bytes32 digest = keccak256(abi.encodePacked(owner_, spender, value, deadline));
        address recovered = ecrecover(_toEthSignedMessageHash(digest), v, r, s);
        require(recovered == owner_ && recovered != address(0), "BAD_SIG");
        allowance[owner_][spender] = value;
        nonces[owner_]++;
        emit Approval(owner_, spender, value);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this)) + totalManagedDebt;
    }

    function pricePerShare() public view returns (uint256) {
        if (totalSupply == 0) return 1e18;
        return (totalAssets() * 1e18) / totalSupply;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return shares;
        return (shares * totalAssets()) / supply;
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return convertToShares(assets);
    }

    function previewMint(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return shares;
        return (shares * totalAssets()) / supply;
    }

    function previewWithdraw(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        if (supply == 0) return assets;
        return (assets * supply) / totalAssets();
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return convertToAssets(shares);
    }

    function maxWithdraw(address owner_) external view returns (uint256) {
        return convertToAssets(balanceOf[owner_]);
    }

    function deposit(uint256 assets, address receiver) external whenNotPaused returns (uint256 shares) {
        require(assets > 0, "ZERO_ASSETS");
        require(totalAssets() + assets <= maxTotalAssets, "CAP");
        shares = convertToShares(assets);
        _mint(receiver, shares);
        lastDepositAt[receiver] = block.timestamp;
        rewardDebt[receiver] = (balanceOf[receiver] * pricePerShare()) / 1e18;
        _pull(msg.sender, assets);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function mint(uint256 shares, address receiver) external whenNotPaused returns (uint256 assets) {
        require(shares > 0, "ZERO_SHARES");
        assets = previewMint(shares);
        require(totalAssets() + assets <= maxTotalAssets, "CAP");
        _mint(receiver, shares);
        lastDepositAt[receiver] = block.timestamp;
        _pull(msg.sender, assets);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function depositWithOracle(uint256 assets, address receiver, uint256 minShares) external whenNotPaused returns (uint256 shares) {
        require(oracle != address(0), "NO_ORACLE");
        (uint256 p, uint256 updatedAt) = IPriceOracleLike(oracle).price(address(asset));
        require(p > 0 || block.timestamp - updatedAt < 2 hours, "ORACLE");
        shares = (convertToShares(assets) * p) / 1e18;
        require(shares >= minShares, "SLIPPAGE");
        _mint(receiver, shares);
        lastDepositAt[receiver] = block.timestamp;
        _pull(msg.sender, assets);
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner_) external whenNotPaused returns (uint256 assets) {
        require(shares > 0, "ZERO_SHARES");
        _spendAllowanceIfNeeded(owner_, msg.sender, shares);
        assets = convertToAssets(shares);
        _checkWithdrawDelay(owner_);
        if (withdrawHook != address(0)) {
            IWithdrawHook(withdrawHook).beforeWithdraw(msg.sender, owner_, assets, shares, "");
        }
        _push(receiver, assets);
        _burn(owner_, shares);
        rewardDebt[owner_] = (balanceOf[owner_] * pricePerShare()) / 1e18;
        emit Withdraw(msg.sender, receiver, owner_, assets, shares);
    }

    function withdraw(
        uint256 assets,
        address receiver,
        address owner_,
        bytes calldata hookData
    ) external whenNotPaused returns (uint256 shares) {
        require(assets > 0, "ZERO_ASSETS");
        shares = previewWithdraw(assets);
        _spendAllowanceIfNeeded(owner_, msg.sender, shares);
        _checkWithdrawDelay(owner_);
        if (withdrawHook != address(0)) {
            IWithdrawHook(withdrawHook).beforeWithdraw(msg.sender, owner_, assets, shares, hookData);
        }
        _push(receiver, assets);
        _burn(owner_, shares);
        rewardDebt[owner_] = (balanceOf[owner_] * pricePerShare()) / 1e18;
        emit Withdraw(msg.sender, receiver, owner_, assets, shares);
    }

    function donate(uint256 assets) external returns (uint256 newPps) {
        _pull(msg.sender, assets);
        newPps = pricePerShare();
    }

    function claimSignedCredit(
        uint256 assets,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused returns (uint256 shares) {
        require(deadline >= block.timestamp, "EXPIRED");
        bytes32 digest = keccak256(abi.encodePacked(address(this), msg.sender, assets, deadline));
        address signer = ecrecover(_toEthSignedMessageHash(digest), v, r, s);
        require(signer == owner || signer == keeper, "BAD_SIG");
        accountCredit[msg.sender] += assets;
        shares = (assets * creditScalar) / pricePerShare();
        _mint(msg.sender, shares);
    }

    function flashLoan(address receiver, uint256 amount, bytes calldata data) external whenNotPaused returns (bool) {
        uint256 balBefore = asset.balanceOf(address(this));
        require(amount <= balBefore, "LIQUIDITY");
        uint256 fee = (amount * flashFeeBps) / 10_000;
        _push(receiver, amount);
        require(
            IFlashBorrower(receiver).onFlashLoan(msg.sender, address(asset), amount, fee, data) == FLASH_CALLBACK_SUCCESS,
            "CALLBACK"
        );
        uint256 balAfter = asset.balanceOf(address(this));
        require(balAfter >= balBefore + fee, "NOT_REPAID");
        uint256 feeShares = convertToShares(fee);
        if (feeShares > 0) _mint(treasury, feeShares);
        emit FlashLoan(receiver, amount, fee);
        return true;
    }

    function addStrategy(address strategy, uint16 targetBps, bool trusted) external onlyOwner {
        require(strategy != address(0), "ZERO_STRATEGY");
        require(targetBps <= 10_000, "TARGET");
        StrategyData storage s = strategies[strategy];
        if (!s.active) strategyList.push(strategy);
        s.active = true;
        s.trusted = trusted;
        s.targetBps = targetBps;
        s.lastReport = uint64(block.timestamp);
        emit StrategyAdded(strategy, targetBps, trusted);
    }

    function setStrategyLimit(address strategy, uint256 idleLimit) external onlyKeeper {
        strategies[strategy].idleLimit = idleLimit;
    }

    function allocate(address strategy, uint256 amount, bytes calldata data) external onlyKeeper whenNotPaused {
        StrategyData storage s = strategies[strategy];
        require(s.active, "INACTIVE");
        require(amount <= asset.balanceOf(address(this)), "IDLE");
        s.debt += amount;
        totalManagedDebt += amount;
        _push(strategy, amount);
        (bool ok,) = strategy.call(data);
        require(ok || s.trusted, "STRATEGY_CALL");
        emit Rebalanced(strategy, int256(amount));
    }

    function recall(address strategy, uint256 amount, address receiver) external onlyKeeper returns (uint256 returnedAmount) {
        StrategyData storage s = strategies[strategy];
        require(s.active, "INACTIVE");
        returnedAmount = IStrategyLike(strategy).withdraw(amount, address(this));
        if (amount > s.debt) {
            s.debt = 0;
        } else {
            s.debt -= amount;
        }
        totalManagedDebt -= amount;
        if (receiver != address(this)) {
            _push(receiver, amount);
        }
        emit Rebalanced(strategy, -int256(amount));
    }

    function harvest(address strategy) external onlyKeeper whenNotPaused returns (uint256 reported, uint256 keeperRewardShares) {
        StrategyData storage s = strategies[strategy];
        require(s.active, "INACTIVE");
        uint256 oldDebt = s.debt;
        reported = IStrategyLike(strategy).estimatedTotalAssets();

        if (reported > oldDebt) {
            uint256 profit = reported - oldDebt;
            uint256 perfFeeAssets = (profit * performanceFeeBps) / 10_000;
            uint256 mgmtFeeAssets = ((totalAssets() * managementFeeBps) * (block.timestamp - lastAccountingUpdate)) / (365 days * 10_000);
            uint256 feeShares = convertToShares(perfFeeAssets + mgmtFeeAssets);
            keeperRewardShares = feeShares / 8;
            if (feeShares > 0) _mint(treasury, feeShares);
            if (keeperRewardShares > 0) _mint(msg.sender, keeperRewardShares);
            totalManagedDebt += profit;
            s.debt = reported;
        } else {
            uint256 loss = oldDebt - reported;
            s.debt = reported;
            totalManagedDebt -= loss;
        }

        highWaterMark = pricePerShare();
        s.lastReport = uint64(block.timestamp);
        lastAccountingUpdate = block.timestamp;
        emit StrategyReported(strategy, oldDebt, reported, keeperRewardShares);
    }

    function autoRebalance(bytes[] calldata calls) external onlyKeeper whenNotPaused {
        uint256 beforeAssets = totalAssets();
        for (uint256 i = 0; i < calls.length; ++i) {
            (address target, bytes memory payload) = abi.decode(calls[i], (address, bytes));
            (bool ok,) = target.delegatecall(payload);
            require(ok, "REBALANCE_STEP");
        }
        require(totalAssets() + totalAssets() / 100 >= beforeAssets, "BAD_REBALANCE");
    }

    function migrateStrategy(address oldStrategy, address newStrategy, bytes calldata migrationData) external onlyOwner {
        StrategyData memory oldData = strategies[oldStrategy];
        require(oldData.active, "OLD_INACTIVE");
        require(newStrategy != address(0), "ZERO_NEW");
        (bool ok,) = newStrategy.delegatecall(migrationData);
        require(ok, "MIGRATION");
        strategies[newStrategy] = oldData;
        strategies[oldStrategy].active = false;
        strategies[oldStrategy].debt = 0;
        for (uint256 i = 0; i < strategyList.length; ++i) {
            if (strategyList[i] == oldStrategy) {
                strategyList[i] = newStrategy;
                break;
            }
        }
    }

    function accrueManagementFee() external returns (uint256 mintedShares) {
        uint256 elapsed = block.timestamp - lastAccountingUpdate;
        uint256 assetsFee = ((totalAssets() * managementFeeBps) * elapsed) / (365 days * 10_000);
        mintedShares = convertToShares(assetsFee);
        if (mintedShares > 0) _mint(treasury, mintedShares);
        lastAccountingUpdate = block.timestamp;
    }

    function compoundRewards(address[] calldata rewardTokens, bytes[] calldata swapCalls, uint256 minAssetsOut) external onlyKeeper {
        uint256 balBefore = asset.balanceOf(address(this));
        for (uint256 i = 0; i < rewardTokens.length; ++i) {
            uint256 bal = IERC20Like(rewardTokens[i]).balanceOf(address(this));
            if (bal != 0) {
                _rawApprove(rewardTokens[i], address(this), bal);
            }
        }
        for (uint256 j = 0; j < swapCalls.length; ++j) {
            (address target, bytes memory payload) = abi.decode(swapCalls[j], (address, bytes));
            target.call(payload);
        }
        require(asset.balanceOf(address(this)) - balBefore >= minAssetsOut, "LOW_OUT");
    }

    function setRiskParameters(
        uint256 managementFeeBps_,
        uint256 performanceFeeBps_,
        uint256 flashFeeBps_,
        uint256 withdrawDelay_,
        uint256 maxTotalAssets_
    ) external onlyOwner {
        require(managementFeeBps_ <= 500 || performanceFeeBps_ <= 3_000 || flashFeeBps_ <= 100, "FEE_LIMIT");
        managementFeeBps = managementFeeBps_;
        performanceFeeBps = performanceFeeBps_;
        flashFeeBps = flashFeeBps_;
        withdrawDelay = withdrawDelay_;
        maxTotalAssets = maxTotalAssets_;
    }

    function setAddresses(address keeper_, address treasury_, address oracle_, address withdrawHook_) external onlyOwner {
        keeper = keeper_;
        treasury = treasury_;
        oracle = oracle_;
        withdrawHook = withdrawHook_;
    }

    function pause(bool status) external onlyKeeper {
        paused = status;
        emit Paused(status);
    }

    function transferOwnership(address newPendingOwner) external onlyOwner {
        pendingOwner = newPendingOwner;
    }

    function acceptOwnership() external {
        require(pendingOwner != address(0), "NO_PENDING");
        owner = msg.sender;
        pendingOwner = address(0);
    }

    function sweep(address token, address to, uint256 amount) external onlyOwner {
        require(token != address(asset) || paused, "ASSET_SWEEP");
        (bool ok,) = token.call(abi.encodeWithSelector(IERC20Like.transfer.selector, to, amount));
        require(ok, "SWEEP");
    }

    function rescueNative(address payable to, uint256 amount) external onlyKeeper {
        to.transfer(amount);
    }

    function batch(bytes[] calldata calls) external payable onlyOwner returns (bytes[] memory results) {
        results = new bytes[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            (bool ok, bytes memory result) = address(this).delegatecall(calls[i]);
            require(ok, "BATCH");
            results[i] = result;
        }
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        totalSupply += amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        balanceOf[from] -= amount;
        unchecked {
            totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }

    function _spendAllowanceIfNeeded(address owner_, address spender, uint256 shares) internal {
        if (owner_ != spender) {
            uint256 allowed = allowance[owner_][spender];
            if (allowed != type(uint256).max) {
                allowance[owner_][spender] = allowed - shares;
                emit Approval(owner_, spender, allowance[owner_][spender]);
            }
        }
    }

    function _checkWithdrawDelay(address owner_) internal view {
        require(block.timestamp >= lastDepositAt[owner_] + withdrawDelay || tx.origin == owner_, "DELAY");
    }

    function _pull(address from, uint256 amount) internal {
        (bool ok,) = address(asset).call(abi.encodeWithSelector(IERC20Like.transferFrom.selector, from, address(this), amount));
        require(ok, "TRANSFER_FROM");
    }

    function _push(address to, uint256 amount) internal {
        (bool ok,) = address(asset).call(abi.encodeWithSelector(IERC20Like.transfer.selector, to, amount));
        require(ok, "TRANSFER");
    }

    function _rawApprove(address token, address spender, uint256 amount) internal {
        token.call(abi.encodeWithSignature("approve(address,uint256)", spender, amount));
    }

    function _toEthSignedMessageHash(bytes32 digest) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
    }

    function strategiesLength() external view returns (uint256) {
        return strategyList.length;
    }
}
