// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {AccessControlEnumerableUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC1271} from "lib/openzeppelin-contracts/contracts/interfaces/IERC1271.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {SafeERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol";

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";
import {IKeeperCompanion} from "src/KeeperCompanion.sol";
import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";

/// @title IStrategyKeeper
/// @notice Interface for the StrategyKeeper contract
interface IStrategyKeeper {
    /// @notice Configuration for the keeper
    struct KeeperConfig {
        address vault; // Vault to monitor for excess baseAsset
        address targetStrategy; // FlexStrategy to allocate funds to
        address safe; // Gnosis Safe holding the funds
        address companion; // KeeperCompanion contract for co-signing
        address baseAsset; // The base asset (e.g., USDC)
        address borrower; // Address to receive principal
        address feeWallet; // Address to receive 1/11 of interest
        address streamReceiver; // Address to receive 10/11 of interest via stream
        address sablier; // Sablier LockupLinear contract
        uint256 minThreshold; // Minimum vault balance to trigger allocation
        uint256 minResidual; // Minimum to keep in Safe after disbursement
        uint256 apr; // APR where 1e18 = 100%
        uint256 holdingDays; // Days of yield to hold in advance (e.g., 28)
        uint256 minProcessingPercent; // Min % of vault total for time-based fallback (1e18 = 100%)
    }

    error ZeroAddress();
    error BelowThreshold(uint256 balance, uint256 threshold);
    error InsufficientSafeBalance(uint256 balance, uint256 required);
    error SafeExecutionFailed();
    error InvalidConfiguration();
    error InvalidCompanionOwner();
    error NoFundsToProcess();

    event KeeperExecuted(
        uint256 indexed timestamp, uint256 vaultAllocation, uint256 principal, uint256 fee, uint256 streamAmount
    );
    event ConfigUpdated();
}

/// @title StrategyKeeper
/// @notice Upgradeable keeper contract that monitors vault balances, allocates to strategy,
///         and disburses funds from the Safe with yield holdback via Sablier streams.
/// @dev Uses TransparentUpgradeableProxy pattern. Requires PROCESSOR_ROLE on the vault and Safe ownership.
contract StrategyKeeper is
    IStrategyKeeper,
    IERC1271,
    Initializable,
    AccessControlEnumerableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    /// @notice Role required to call the keeper function
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    /// @notice Role required to update configuration
    bytes32 public constant CONFIG_MANAGER_ROLE = keccak256("CONFIG_MANAGER_ROLE");

    /// @notice ERC-1271 magic value for isValidSignature(bytes32,bytes)
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @notice Legacy magic value for isValidSignature(bytes,bytes) - Safe 1.4.1 compatibility
    bytes4 internal constant LEGACY_MAGIC_VALUE = 0x20c13b0b;

    /// @notice Invalid signature value
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    /// @notice Precision for percentage calculations (1e18 = 100%)
    uint256 public constant PRECISION = 1e18;

    /// @notice Days per year for APR calculation
    uint256 public constant DAYS_PER_YEAR = 365;

    /// @notice Time interval for fallback processing (24 hours)
    uint256 public constant FALLBACK_INTERVAL = 24 hours;

    /// @notice Storage slot for keeper data
    bytes32 private constant KEEPER_STORAGE_SLOT = keccak256("yieldnest.storage.strategyKeeper");

    /// @notice Storage struct for the keeper
    struct KeeperStorage {
        KeeperConfig config;
        mapping(bytes32 => bool) approvedHashes;
        uint256 lastProcessedTimestamp;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Get the storage struct
    function _getKeeperStorage() internal pure returns (KeeperStorage storage s) {
        bytes32 slot = KEEPER_STORAGE_SLOT;
        assembly {
            s.slot := slot
        }
    }

    /// @notice Initialize the keeper contract
    /// @param admin Admin address with DEFAULT_ADMIN_ROLE
    /// @param config_ Initial keeper configuration
    function initialize(address admin, KeeperConfig calldata config_) external initializer {
        if (admin == address(0)) revert ZeroAddress();

        __AccessControlEnumerable_init();
        __ReentrancyGuard_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(CONFIG_MANAGER_ROLE, admin);

        _setConfig(config_);
    }

    /// @notice Execute the keeper logic to process inflows
    /// @dev Requires KEEPER_ROLE. All-or-nothing execution.
    function processInflows() external onlyRole(KEEPER_ROLE) nonReentrant {
        KeeperStorage storage s = _getKeeperStorage();
        KeeperConfig memory cfg = s.config;

        // 1. Check if processing should occur and get vault allocation amount
        (bool shouldExecute, uint256 vaultAllocation) = _shouldProcess(s, cfg);
        if (!shouldExecute) revert NoFundsToProcess();

        // 2. Allocate vault funds if needed (sends funds to safe via strategy)
        if (vaultAllocation > 0) {
            _allocateToStrategy(cfg, vaultAllocation);
        }

        // 3. Calculate available funds in Safe AFTER allocation (above minResidual)
        uint256 safeBalance = IERC20(cfg.baseAsset).balanceOf(cfg.safe);
        if (safeBalance <= cfg.minResidual) revert NoFundsToProcess();
        uint256 available = safeBalance - cfg.minResidual;

        // 4. Calculate yield holdback
        // interest = available * apr * holdingDays / 365 / PRECISION
        uint256 interest = (available * cfg.apr * cfg.holdingDays) / DAYS_PER_YEAR / PRECISION;
        uint256 principal = available - interest;

        // 5. Calculate fee split: 1/11 to fee wallet, 10/11 to stream
        uint256 fee = interest / 11;
        uint256 streamAmount = interest - fee;

        // 5. Execute Safe transactions
        // Transfer principal to borrower
        _executeSafeTransfer(cfg, cfg.borrower, principal);

        // Transfer fee to fee wallet
        _executeSafeTransfer(cfg, cfg.feeWallet, fee);

        // Create Sablier stream for remaining interest
        _createSablierStream(cfg, streamAmount);

        // Record last processed timestamp
        s.lastProcessedTimestamp = block.timestamp;

        emit KeeperExecuted(block.timestamp, vaultAllocation, principal, fee, streamAmount);
    }

    /// @notice Check if processing should occur (for off-chain keepers)
    /// @dev Returns true if:
    ///      1. Vault balance >= minThreshold, OR
    ///      2. 24h passed since last processing AND safe balance >= minProcessingPercent of vault total assets
    /// @return shouldExecute True if processInflows() should be called
    function shouldProcess() external view returns (bool shouldExecute) {
        KeeperStorage storage s = _getKeeperStorage();
        KeeperConfig memory cfg = s.config;
        (shouldExecute,) = _shouldProcess(s, cfg);
    }

    /// @notice Internal check for processing conditions
    /// @dev Checks if vault needs allocation OR if time-based fallback triggers
    /// @param s Storage reference
    /// @param cfg Keeper configuration
    /// @return shouldExecute True if processing should occur
    /// @return vaultAllocation Amount to allocate from vault (0 if none)
    function _shouldProcess(KeeperStorage storage s, KeeperConfig memory cfg)
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
        // If 24 hours have passed since the last processing AND the vault balance is at least minProcessingPercent of total assets
        if (block.timestamp >= s.lastProcessedTimestamp + FALLBACK_INTERVAL) {
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
        return _getKeeperStorage().lastProcessedTimestamp;
    }

    /// @notice Allocate funds from vault to strategy via processor
    /// @param cfg Keeper configuration
    /// @param amount Amount to allocate
    function _allocateToStrategy(KeeperConfig memory cfg, uint256 amount) internal {
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

    /// @notice Execute a transfer from the Safe
    /// @param cfg Keeper configuration
    /// @param to Recipient address
    /// @param amount Amount to transfer
    function _executeSafeTransfer(KeeperConfig memory cfg, address to, uint256 amount) internal {
        bytes memory txData = abi.encodeCall(IERC20.transfer, (to, amount));
        _executeSafeTransaction(cfg, cfg.baseAsset, 0, txData);
    }

    /// @notice Create a Sablier stream from the Safe
    /// @param cfg Keeper configuration
    /// @param amount Amount to stream
    function _createSablierStream(KeeperConfig memory cfg, uint256 amount) internal {
        // First approve Sablier to spend the stream amount
        bytes memory approveData = abi.encodeCall(IERC20.approve, (cfg.sablier, amount));
        _executeSafeTransaction(cfg, cfg.baseAsset, 0, approveData);

        // Build stream parameters
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: cfg.safe,
            recipient: cfg.streamReceiver,
            depositAmount: uint128(amount),
            token: IERC20(cfg.baseAsset),
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + cfg.holdingDays * 1 days)
            }),
            shape: ""
        });

        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});

        // Create stream via Safe
        bytes memory createData =
            abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));
        _executeSafeTransaction(cfg, cfg.sablier, 0, createData);
    }

    /// @notice Execute a transaction from the Gnosis Safe with contract signatures
    /// @param cfg Keeper configuration
    /// @param to Target address
    /// @param value ETH value
    /// @param data Call data
    /// @return returnData Return data from the call
    function _executeSafeTransaction(KeeperConfig memory cfg, address to, uint256 value, bytes memory data)
        internal
        returns (bytes memory returnData)
    {
        IGnosisSafe safe = IGnosisSafe(cfg.safe);
        uint256 nonce = safe.nonce();

        // Get transaction hash
        bytes32 txHash = safe.getTransactionHash(
            to,
            value,
            data,
            IGnosisSafe.Operation.Call,
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            address(0), // refundReceiver
            nonce
        );

        // Approve hash on this contract (for ERC-1271)
        KeeperStorage storage s = _getKeeperStorage();
        s.approvedHashes[txHash] = true;

        // Approve hash on companion
        IKeeperCompanion(cfg.companion).approveHash(txHash);

        // Build contract signatures
        bytes memory signatures = _buildContractSignatures(address(this), cfg.companion);

        // Execute transaction
        bool success = safe.execTransaction(
            to,
            value,
            data,
            IGnosisSafe.Operation.Call,
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            payable(0), // refundReceiver
            signatures
        );

        if (!success) revert SafeExecutionFailed();

        // Clean up approved hashes
        s.approvedHashes[txHash] = false;
        IKeeperCompanion(cfg.companion).revokeHash(txHash);

        // For calls that return data, we need to handle it separately
        // The Safe's execTransaction returns bool, not the call's return data
        // For createWithTimestampsLL, we need to make a static call to get the expected stream ID
        // However, since Safe doesn't return call data, we'll use events or other mechanisms
        // For now, return empty - stream ID can be retrieved from events
        return "";
    }

    /// @notice Build contract signatures for two signers
    /// @dev Signers must be sorted in ascending order by address
    /// @param signer1 First signer address
    /// @param signer2 Second signer address
    /// @return signatures Packed signatures for Safe
    function _buildContractSignatures(address signer1, address signer2)
        internal
        pure
        returns (bytes memory signatures)
    {
        // Sort signers - Safe requires signatures in ascending order by signer address
        address lower;
        address higher;
        if (uint160(signer1) < uint160(signer2)) {
            lower = signer1;
            higher = signer2;
        } else {
            lower = signer2;
            higher = signer1;
        }

        // Contract signature format:
        // For each signer: r (32 bytes) = address, s (32 bytes) = data offset, v (1 byte) = 0
        // Data section: length (32 bytes) + signature data

        // Static part: 2 signatures * 65 bytes = 130 bytes
        // Dynamic part: 2 * (32 bytes length + 0 bytes data) = 64 bytes
        // Total: 194 bytes

        // Offsets are relative to the start of the signatures data
        // First signer's data starts at offset 130 (after both static parts)
        // Second signer's data starts at offset 130 + 32 = 162 (after first length)

        uint256 offset1 = 130; // Offset to first signature data
        uint256 offset2 = 162; // Offset to second signature data

        signatures = abi.encodePacked(
            // First signer (lower address)
            bytes32(uint256(uint160(lower))), // r = signer address
            bytes32(offset1), // s = offset to data
            uint8(0), // v = 0 for contract signature
            // Second signer (higher address)
            bytes32(uint256(uint160(higher))), // r = signer address
            bytes32(offset2), // s = offset to data
            uint8(0), // v = 0 for contract signature
            // Dynamic data for first signer (empty signature)
            bytes32(0), // length = 0
            // Dynamic data for second signer (empty signature)
            bytes32(0) // length = 0
        );
    }

    /// @notice ERC-1271 signature validation for this contract
    /// @param hash The hash to validate
    /// @param signature The signature (unused)
    /// @return magicValue ERC1271_MAGIC_VALUE if approved, INVALID_SIGNATURE otherwise
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        signature; // Silence unused variable warning

        if (_getKeeperStorage().approvedHashes[hash]) {
            return ERC1271_MAGIC_VALUE;
        }
        return INVALID_SIGNATURE;
    }

    /// @notice Legacy signature validation (Safe 1.4.1 compatibility)
    /// @dev Safe 1.4.1 uses isValidSignature(bytes,bytes) with selector 0x20c13b0b
    /// @param data The EIP-712 encoded message data
    /// @param signature The signature (unused)
    /// @return magicValue LEGACY_MAGIC_VALUE if approved, INVALID_SIGNATURE otherwise
    function isValidSignature(bytes calldata data, bytes calldata signature)
        external
        view
        returns (bytes4 magicValue)
    {
        signature; // Silence unused variable warning

        bytes32 hash = keccak256(data);
        if (_getKeeperStorage().approvedHashes[hash]) {
            return LEGACY_MAGIC_VALUE;
        }
        return INVALID_SIGNATURE;
    }

    /// @notice Update the keeper configuration
    /// @param config_ New configuration
    function setConfig(KeeperConfig calldata config_) external onlyRole(CONFIG_MANAGER_ROLE) {
        _setConfig(config_);
    }

    /// @notice Internal function to set configuration
    /// @param config_ New configuration
    function _setConfig(KeeperConfig calldata config_) internal {
        if (config_.vault == address(0)) revert ZeroAddress();
        if (config_.targetStrategy == address(0)) revert ZeroAddress();
        if (config_.safe == address(0)) revert ZeroAddress();
        if (config_.companion == address(0)) revert ZeroAddress();
        if (config_.baseAsset == address(0)) revert ZeroAddress();
        if (config_.borrower == address(0)) revert ZeroAddress();
        if (config_.feeWallet == address(0)) revert ZeroAddress();
        if (config_.streamReceiver == address(0)) revert ZeroAddress();
        if (config_.sablier == address(0)) revert ZeroAddress();
        if (config_.apr == 0 || config_.apr > PRECISION) revert InvalidConfiguration();
        if (config_.holdingDays == 0) revert InvalidConfiguration();
        if (config_.minProcessingPercent > PRECISION) revert InvalidConfiguration();
        if (config_.companion.code.length > 0 && Ownable(config_.companion).owner() != address(this)) {
            revert InvalidCompanionOwner();
        }

        _getKeeperStorage().config = config_;
        emit ConfigUpdated();
    }

    /// @notice Get the current configuration
    /// @return config The current keeper configuration
    function getConfig() external view returns (KeeperConfig memory config) {
        return _getKeeperStorage().config;
    }
}

/// @notice Minimal interface for vault processor function
interface IVaultProcessor {
    function processor(address[] calldata targets, uint256[] calldata values, bytes[] calldata data)
        external
        returns (bytes[] memory);
}
