// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {AccessControlEnumerable} from
    "lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol";
import {ReentrancyGuard} from "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";
import {Pausable} from "lib/openzeppelin-contracts/contracts/utils/Pausable.sol";
import {Initializable} from "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";

import {FlowHandler} from "src/FlowHandler.sol";

/// @title IFlowStrategyKeeper
/// @notice Interface for the FlowStrategyKeeper contract
interface IFlowStrategyKeeper {
    /// @notice Configuration for the flow keeper
    struct FlowKeeperConfig {
        address vault; // Vault to monitor for excess baseAsset
        address targetStrategy; // FlexStrategy to allocate funds to
        address safe; // Gnosis Safe holding the funds (for balance checks)
        address baseAsset; // The base asset (e.g., USDC)
        address flowHandler; // FlowHandler module that handles all Safe operations
        uint256 minThreshold; // Minimum vault balance to trigger allocation
        uint256 minResidual; // Minimum to keep in Safe after disbursement
        uint256 minProcessingPercent; // Min % of vault total for time-based fallback (1e18 = 100%)
    }

    error ZeroAddress();
    error InsufficientSafeBalance(uint256 balance, uint256 required);
    error InvalidConfiguration();
    error NoFundsToProcess();

    event KeeperExecuted(
        uint256 indexed timestamp,
        uint256 vaultAllocation,
        uint256 safeBalance,
        uint256 minResidual,
        uint256 available,
        uint256 interest,
        uint256 apr,
        uint256 holdingPeriod,
        uint256 principal,
        uint256 fee,
        uint128 newRatePerSecond
    );
    event ConfigUpdated(address indexed vault, address indexed safe);
}

/// @title FlowStrategyKeeper
/// @notice Keeper contract that monitors vault balances, allocates to strategy,
///         and disburses funds from the Safe with yield holdback via a Sablier Flow stream.
/// @dev Deployed directly (no proxy). NOT a Safe module — all Safe interactions go through FlowHandler.
///      Delegates all fund disbursement to FlowHandler.disburse() which handles interest computation,
///      stream deposit, rate adjustment, and principal/fee transfers.
contract FlowStrategyKeeper is
    IFlowStrategyKeeper,
    AccessControlEnumerable,
    ReentrancyGuard,
    Pausable,
    Initializable
{
    /// @notice Role required to call the keeper function (on-chain computed parameters)
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    /// @notice Role required to call the keeper function with manual parameters
    bytes32 public constant POWER_KEEPER_ROLE = keccak256("POWER_KEEPER_ROLE");

    /// @notice Role required to update configuration
    bytes32 public constant CONFIG_MANAGER_ROLE = keccak256("CONFIG_MANAGER_ROLE");

    /// @notice Role required to pause/unpause the contract
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice Role granted to the initializer (deployer) to call initialize() once
    bytes32 public constant INITIALIZER_ROLE = keccak256("INITIALIZER_ROLE");

    /// @notice Contract version
    string public constant VERSION = "0.1.0";

    /// @notice Precision for percentage calculations (1e18 = 100%)
    uint256 public constant PRECISION = 1e18;

    /// @notice Time interval for fallback processing (24 hours)
    uint256 public constant FALLBACK_INTERVAL = 24 hours;

    /// @notice Keeper configuration
    FlowKeeperConfig private _config;

    /// @notice Timestamp of last processing
    uint256 private _lastProcessedTimestamp;

    /// @notice Creates a new FlowStrategyKeeper
    /// @param _admin Admin address that receives DEFAULT_ADMIN_ROLE, CONFIG_MANAGER_ROLE, and PAUSER_ROLE
    /// @param _initializer Address that can call initialize() once to set the config
    /// @param _pauser Additional address that receives PAUSER_ROLE (e.g. YnDev)
    /// @param _processor Address that receives KEEPER_ROLE and POWER_KEEPER_ROLE
    constructor(address _admin, address _initializer, address _pauser, address _processor) {
        if (_admin == address(0)) revert ZeroAddress();
        if (_initializer == address(0)) revert ZeroAddress();
        if (_pauser == address(0)) revert ZeroAddress();
        if (_processor == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(CONFIG_MANAGER_ROLE, _admin);
        _grantRole(PAUSER_ROLE, _admin);

        _grantRole(INITIALIZER_ROLE, _initializer);

        _grantRole(PAUSER_ROLE, _pauser);

        _grantRole(KEEPER_ROLE, _processor);
        _grantRole(POWER_KEEPER_ROLE, _processor);
    }

    /// @notice Initialize the keeper with configuration
    /// @dev Can only be called once by the INITIALIZER_ROLE holder. The role is revoked after.
    /// @param config_ Initial keeper configuration
    function initialize(FlowKeeperConfig calldata config_) external onlyRole(INITIALIZER_ROLE) initializer {
        _revokeRole(INITIALIZER_ROLE, msg.sender);
        _setConfig(config_);
    }

    /// @notice Execute the keeper logic to process inflows (on-chain computed parameters)
    /// @dev Requires KEEPER_ROLE. Computes vaultAllocation and available from on-chain state.
    function processInflows() external onlyRole(KEEPER_ROLE) nonReentrant whenNotPaused {
        FlowKeeperConfig memory cfg = _config;

        // 1. Check if processing should occur and get vault allocation amount
        (bool shouldExecute, uint256 vaultAllocation) = _shouldProcess(cfg);
        if (!shouldExecute) revert NoFundsToProcess();

        // 2. Allocate vault funds if needed (sends funds to safe via strategy)
        if (vaultAllocation > 0) {
            _allocateToStrategy(cfg, vaultAllocation);
        }

        // 3. Calculate available funds in Safe AFTER allocation (above minResidual)
        uint256 safeBalance = IERC20(cfg.baseAsset).balanceOf(cfg.safe);
        if (safeBalance <= cfg.minResidual) revert NoFundsToProcess();
        uint256 available = safeBalance - cfg.minResidual;

        _executeInflows(cfg, vaultAllocation, available, safeBalance);
    }

    /// @notice Execute the keeper logic to process inflows with manual parameters
    /// @dev Requires POWER_KEEPER_ROLE. Caller provides vaultAllocation and available amounts.
    /// @param vaultAllocation Amount to allocate from vault (0 to skip allocation)
    /// @param available Amount of safe funds to disburse (must leave minResidual in safe)
    function processInflows(uint256 vaultAllocation, uint256 available)
        external
        onlyRole(POWER_KEEPER_ROLE)
        nonReentrant
        whenNotPaused
    {
        if (available == 0) revert NoFundsToProcess();

        FlowKeeperConfig memory cfg = _config;

        // Allocate vault funds if needed
        if (vaultAllocation > 0) {
            _allocateToStrategy(cfg, vaultAllocation);
        }

        // Validate safe has enough funds to cover available + minResidual
        uint256 safeBalance = IERC20(cfg.baseAsset).balanceOf(cfg.safe);
        if (safeBalance < available + cfg.minResidual) {
            revert InsufficientSafeBalance(safeBalance, available + cfg.minResidual);
        }

        _executeInflows(cfg, vaultAllocation, available, safeBalance);
    }

    /// @notice Common inflow execution logic shared by both processInflows variants
    /// @dev FlowHandler computes interest and deposits it into the stream in a single call.
    ///      Fee is computed on top of the interest returned by FlowHandler.
    /// @param cfg Keeper configuration
    /// @param vaultAllocation Amount allocated from vault (for event)
    /// @param available Amount of safe funds to disburse (loanAmount passed to FlowHandler)
    /// @param safeBalance Safe balance after allocation (for event)
    function _executeInflows(
        FlowKeeperConfig memory cfg,
        uint256 vaultAllocation,
        uint256 available,
        uint256 safeBalance
    ) internal {
        FlowHandler flowHandler = FlowHandler(cfg.flowHandler);

        // Single call: deposits interest to stream, adjusts rate, transfers principal and fee
        FlowHandler.DisburseResult memory result = flowHandler.disburse(available);

        // Record last processed timestamp
        _lastProcessedTimestamp = block.timestamp;

        _emitKeeperExecuted(
            vaultAllocation,
            safeBalance,
            cfg.minResidual,
            available,
            uint256(result.interest),
            flowHandler.apr(),
            flowHandler.holdingPeriod(),
            result.principal,
            result.fee,
            result.newRate
        );
    }

    /// @notice Emit the KeeperExecuted event (extracted to avoid stack-too-deep)
    function _emitKeeperExecuted(
        uint256 vaultAllocation,
        uint256 safeBalance,
        uint256 minResidual,
        uint256 available,
        uint256 interest,
        uint256 apr,
        uint256 holdingPeriod,
        uint256 principal,
        uint256 fee,
        uint128 newRatePerSecond
    ) internal {
        emit KeeperExecuted(
            block.timestamp,
            vaultAllocation,
            safeBalance,
            minResidual,
            available,
            interest,
            apr,
            holdingPeriod,
            principal,
            fee,
            newRatePerSecond
        );
    }

    /// @notice Check if processing should occur (for off-chain keepers)
    /// @dev Returns true if:
    ///      1. Vault balance >= minThreshold, OR
    ///      2. 24h passed since last processing AND safe balance >= minProcessingPercent of vault total assets
    /// @return shouldExecute True if processInflows() should be called
    function shouldProcess() external view returns (bool shouldExecute) {
        (shouldExecute,) = _shouldProcess(_config);
    }

    /// @notice Internal check for processing conditions
    /// @param cfg Keeper configuration
    /// @return shouldExecute True if processing should occur
    /// @return vaultAllocation Amount to allocate from vault (0 if none)
    function _shouldProcess(FlowKeeperConfig memory cfg)
        internal
        view
        returns (bool shouldExecute, uint256 vaultAllocation)
    {
        // Condition 1: Vault balance above threshold triggers immediate processing
        uint256 vaultBalance = IERC20(cfg.baseAsset).balanceOf(cfg.vault);
        if (vaultBalance >= cfg.minThreshold) {
            return (true, vaultBalance);
        }

        // Condition 2: Time-based fallback with percentage check
        if (block.timestamp >= _lastProcessedTimestamp + FALLBACK_INTERVAL) {
            uint256 vaultTotalAssets = IERC4626(cfg.vault).totalAssets();
            uint256 minAmount = (vaultTotalAssets * cfg.minProcessingPercent) / PRECISION;
            if (vaultBalance >= minAmount) {
                return (true, vaultBalance);
            }
        }

        return (false, 0);
    }

    /// @notice Get the last processed timestamp
    /// @return timestamp Unix timestamp of last processing
    function lastProcessedTimestamp() external view returns (uint256 timestamp) {
        return _lastProcessedTimestamp;
    }

    /// @notice Allocate funds from vault to strategy via processor
    /// @param cfg Keeper configuration
    /// @param amount Amount to allocate
    function _allocateToStrategy(FlowKeeperConfig memory cfg, uint256 amount) internal {
        // Build processor calls: approve + deposit
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        // Approve strategy to spend vault's baseAsset
        targets[0] = cfg.baseAsset;
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (cfg.targetStrategy, amount));

        // Deposit into strategy
        targets[1] = cfg.targetStrategy;
        values[1] = 0;
        data[1] = abi.encodeCall(IERC4626.deposit, (amount, cfg.vault));

        // Execute via vault processor
        IVaultProcessor(cfg.vault).processor(targets, values, data);
    }

    /// @notice Update the keeper configuration
    /// @param config_ New configuration
    function setConfig(FlowKeeperConfig calldata config_) external onlyRole(CONFIG_MANAGER_ROLE) {
        _setConfig(config_);
    }

    /// @notice Internal function to set configuration
    /// @param config_ New configuration
    function _setConfig(FlowKeeperConfig calldata config_) internal {
        if (config_.vault == address(0)) revert ZeroAddress();
        if (config_.targetStrategy == address(0)) revert ZeroAddress();
        if (config_.safe == address(0)) revert ZeroAddress();
        if (config_.baseAsset == address(0)) revert ZeroAddress();
        if (config_.flowHandler == address(0)) revert ZeroAddress();
        if (config_.minProcessingPercent > PRECISION) revert InvalidConfiguration();

        _config = config_;
        emit ConfigUpdated(config_.vault, config_.safe);
    }

    /// @notice Get the current configuration
    /// @return config The current keeper configuration
    function getConfig() external view returns (FlowKeeperConfig memory config) {
        return _config;
    }

    /// @notice Pause the keeper
    /// @dev Only callable by PAUSER_ROLE
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpause the keeper
    /// @dev Only callable by PAUSER_ROLE
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}

/// @notice Minimal interface for vault processor function
interface IVaultProcessor {
    function processor(address[] calldata targets, uint256[] calldata values, bytes[] calldata data)
        external
        returns (bytes[] memory);
}
