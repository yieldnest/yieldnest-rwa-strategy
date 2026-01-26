// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {KeeperCompanion} from "src/KeeperCompanion.sol";

interface IVaultRoles is IAccessControl {
    function PROCESSOR_ROLE() external view returns (bytes32);
}

interface ISablierLockup {
    function nextStreamId() external view returns (uint256);
    function getSender(uint256 streamId) external view returns (address);
    function getRecipient(uint256 streamId) external view returns (address);
    function getDepositedAmount(uint256 streamId) external view returns (uint128);
    function getStartTime(uint256 streamId) external view returns (uint40);
    function getEndTime(uint256 streamId) external view returns (uint40);
    function isCancelable(uint256 streamId) external view returns (bool);
    function isTransferable(uint256 streamId) external view returns (bool);
    function ownerOf(uint256 streamId) external view returns (address); // ERC-721 NFT owner
}

/// @title StrategyKeeperMainnetTest
/// @notice Integration tests for StrategyKeeper with mainnet fork
/// @dev Run with: forge test --match-path "test/mainnet/strategykeeper/*.sol" --fork-url <RPC_URL>
contract StrategyKeeperMainnetTest is Test {
    /// @notice ERC-1271 magic value for isValidSignature(bytes32,bytes)
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @notice Invalid signature value
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    // Mainnet addresses
    address constant VAULT = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8; // ynRWAx
    address constant TARGET_STRATEGY = 0xF6e1443e3F70724cec8C0a779C7C35A8DcDA928B;
    address constant FEE_WALLET = 0xC92Dd1837EBcb0365eB0a8795f9c8E474f8B6183;
    address constant BORROWER = 0xaa7f79Bb105833D655D1C13C175142c44e209912;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant SABLIER = 0xcF8ce57fa442ba50aCbC57147a62aD03873FfA73;

    // Mainnet Safe infrastructure
    address constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    // USDC whale for funding
    address constant USDC_WHALE = 0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341;

    // Test accounts
    address public admin;
    address public keeperBot;
    address public streamReceiver;

    // Contracts
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;
    KeeperCompanion public companion;
    Safe public safe;

    function setUp() public {
        admin = makeAddr("admin");
        keeperBot = makeAddr("keeperBot");
        streamReceiver = makeAddr("streamReceiver");

        // Deploy keeper implementation
        keeperImpl = new StrategyKeeper();

        // Deploy proxy with placeholder safe/companion
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                admin,
                IStrategyKeeper.KeeperConfig({
                    vault: VAULT,
                    targetStrategy: TARGET_STRATEGY,
                    safe: address(1), // placeholder
                    companion: address(0xBEEF), // placeholder
                    baseAsset: USDC,
                    borrower: BORROWER,
                    feeWallet: FEE_WALLET,
                    streamReceiver: streamReceiver,
                    sablier: SABLIER,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18,
                    holdingDays: 28,
                    minProcessingPercent: 0.01e18, // 1%
                    feeFraction: 11
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Deploy companion
        companion = new KeeperCompanion(address(keeper));

        // Deploy real Safe with keeper + companion as owners
        safe = _deploySafe();

        // Update keeper config with real addresses
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18, // 1%
                feeFraction: 11
            })
        );
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund safe with USDC from whale
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(address(safe), 100_000e6);

        // Grant PROCESSOR_ROLE to keeper on the vault
        bytes32 processorRole = IVaultRoles(VAULT).PROCESSOR_ROLE();
        vm.prank(0xfcad670592a3b24869C0b51a6c6FDED4F95D6975);
        IVaultRoles(VAULT).grantRole(processorRole, address(keeper));
    }

    function _deploySafe() internal returns (Safe) {
        address[] memory owners = new address[](2);
        owners[0] = address(keeper);
        owners[1] = address(companion);

        // Sort owners (Safe requires ascending order)
        if (uint160(owners[0]) > uint160(owners[1])) {
            (owners[0], owners[1]) = (owners[1], owners[0]);
        }

        bytes memory setupData = abi.encodeCall(
            Safe.setup,
            (
                owners,
                2, // threshold
                address(0),
                "",
                address(0),
                address(0),
                0,
                payable(address(0))
            )
        );

        SafeProxyFactory factory = SafeProxyFactory(SAFE_PROXY_FACTORY);
        SafeProxy safeProxy = factory.createProxyWithNonce(SAFE_SINGLETON, setupData, block.timestamp);
        return Safe(payable(address(safeProxy)));
    }

    function test_initialization() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();

        assertEq(cfg.vault, VAULT, "vault mismatch");
        assertEq(cfg.targetStrategy, TARGET_STRATEGY, "targetStrategy mismatch");
        assertEq(cfg.safe, address(safe), "safe mismatch");
        assertEq(cfg.companion, address(companion), "companion mismatch");
        assertEq(cfg.baseAsset, USDC, "baseAsset mismatch");
        assertEq(cfg.borrower, BORROWER, "borrower mismatch");
        assertEq(cfg.feeWallet, FEE_WALLET, "feeWallet mismatch");
        assertEq(cfg.streamReceiver, streamReceiver, "streamReceiver mismatch");
        assertEq(cfg.sablier, SABLIER, "sablier mismatch");
        assertEq(cfg.minThreshold, 10_000e6, "minThreshold mismatch");
        assertEq(cfg.minResidual, 1_000e6, "minResidual mismatch");
        assertEq(cfg.apr, 0.121e18, "apr mismatch");
        assertEq(cfg.holdingDays, 28, "holdingDays mismatch");
        assertEq(cfg.minProcessingPercent, 0.01e18, "minProcessingPercent mismatch");
    }

    function test_safeSetup() public view {
        assertTrue(safe.isOwner(address(keeper)), "keeper should be safe owner");
        assertTrue(safe.isOwner(address(companion)), "companion should be safe owner");
        assertEq(safe.getThreshold(), 2, "safe threshold should be 2");
        assertEq(safe.getOwners().length, 2, "safe should have 2 owners");
    }

    function test_safeBalance() public view {
        assertEq(IERC20(USDC).balanceOf(address(safe)), 100_000e6, "safe should have 100k USDC");
    }

    function test_roles() public view {
        assertTrue(keeper.hasRole(keeper.DEFAULT_ADMIN_ROLE(), admin), "admin should have DEFAULT_ADMIN_ROLE");
        assertTrue(keeper.hasRole(keeper.CONFIG_MANAGER_ROLE(), admin), "admin should have CONFIG_MANAGER_ROLE");
        assertTrue(keeper.hasRole(keeper.KEEPER_ROLE(), keeperBot), "keeperBot should have KEEPER_ROLE");
    }

    function test_companionOwnership() public view {
        assertEq(companion.owner(), address(keeper), "keeper should own companion");
    }

    function test_vaultExists() public view {
        assertTrue(VAULT.code.length > 0, "vault should have code");
    }

    function test_targetStrategyExists() public view {
        assertTrue(TARGET_STRATEGY.code.length > 0, "targetStrategy should have code");
    }

    function test_sablierExists() public view {
        assertTrue(SABLIER.code.length > 0, "sablier should have code");
    }

    function test_usdcDecimals() public view {
        (bool success, bytes memory data) = USDC.staticcall(abi.encodeWithSignature("decimals()"));
        assertTrue(success, "decimals() call should succeed");
        assertEq(abi.decode(data, (uint8)), 6, "USDC should have 6 decimals");
    }

    function test_yieldCalculation() public pure {
        // 100,000 USDC at 12.1% APR for 28 days
        // 100000 * 0.121 * 28 / 365 = 928.22
        uint256 available = 100_000e6;
        uint256 apr = 0.121e18;
        uint256 holdingDays = 28;

        uint256 interest = (available * apr * holdingDays) / 365 / 1e18;

        assertApproxEqAbs(interest, 928_219_178, 1e3, "interest calculation mismatch");

        uint256 fee = interest / 11;
        uint256 streamAmount = interest - fee;
        assertEq(fee + streamAmount, interest, "fee + streamAmount should equal interest");
    }

    function test_revertOnUnauthorizedKeeper() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_revertOnUnauthorizedConfigUpdate() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.setConfig(cfg);
    }

    function test_companionHashApproval() public {
        bytes32 testHash = keccak256("test");

        assertFalse(companion.isHashApproved(testHash), "hash should not be approved initially");

        vm.prank(address(keeper));
        companion.approveHash(testHash);
        assertTrue(companion.isHashApproved(testHash), "hash should be approved after approveHash");

        vm.prank(address(keeper));
        companion.revokeHash(testHash);
        assertFalse(companion.isHashApproved(testHash), "hash should not be approved after revokeHash");
    }

    function test_companionIsValidSignature() public {
        bytes32 testHash = keccak256("test");

        assertEq(companion.isValidSignature(testHash, ""), INVALID_SIGNATURE, "unapproved hash should return invalid");

        vm.prank(address(keeper));
        companion.approveHash(testHash);

        assertEq(
            companion.isValidSignature(testHash, ""), ERC1271_MAGIC_VALUE, "approved hash should return magic value"
        );
    }

    function test_configValidation_zeroVault() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.vault = address(0);

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.ZeroAddress.selector);
        keeper.setConfig(cfg);
    }

    function test_configValidation_zeroApr() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.apr = 0;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_configValidation_aprTooHigh() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.apr = 2e18;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_configValidation_zeroHoldingDays() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.holdingDays = 0;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_processInflows_success() public {
        // Get initial balances
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));
        uint256 borrowerBalanceBefore = IERC20(USDC).balanceOf(BORROWER);
        uint256 feeWalletBalanceBefore = IERC20(USDC).balanceOf(FEE_WALLET);
        uint256 sablierBalanceBefore = IERC20(USDC).balanceOf(SABLIER);

        // Get expected stream ID before execution
        ISablierLockup sablier = ISablierLockup(SABLIER);
        uint256 expectedStreamId = sablier.nextStreamId();

        // Calculate expected amounts
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = safeBalanceBefore - cfg.minResidual;
        uint256 interest = (available * cfg.apr * cfg.holdingDays) / 365 / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        // Record timestamp for stream verification
        uint256 expectedStartTime = block.timestamp;
        uint256 expectedEndTime = block.timestamp + cfg.holdingDays * 1 days;

        // Execute processInflows
        vm.prank(keeperBot);
        keeper.processInflows();

        // Assert borrower received principal
        assertEq(
            IERC20(USDC).balanceOf(BORROWER), borrowerBalanceBefore + principal, "Borrower should receive principal"
        );

        // Assert fee wallet received fee
        assertEq(IERC20(USDC).balanceOf(FEE_WALLET), feeWalletBalanceBefore + fee, "Fee wallet should receive fee");

        // Assert safe balance decreased correctly (principal + fee + streamAmount)
        assertEq(IERC20(USDC).balanceOf(address(safe)), cfg.minResidual, "Safe should only have minResidual left");

        // Assert stream was created (Sablier balance increased by streamAmount)
        assertEq(
            IERC20(USDC).balanceOf(SABLIER), sablierBalanceBefore + streamAmount, "Sablier should hold stream amount"
        );

        // Assert next stream ID incremented
        assertEq(sablier.nextStreamId(), expectedStreamId + 1, "Stream ID should increment");

        // Assert stream fields are correct
        assertEq(sablier.getSender(expectedStreamId), address(safe), "Stream sender should be safe");
        assertEq(sablier.getRecipient(expectedStreamId), streamReceiver, "Stream recipient should be streamReceiver");
        assertEq(sablier.ownerOf(expectedStreamId), streamReceiver, "Stream NFT owner should be streamReceiver");
        assertEq(sablier.getDepositedAmount(expectedStreamId), uint128(streamAmount), "Stream deposit should match");
        assertEq(sablier.getStartTime(expectedStreamId), uint40(expectedStartTime), "Stream start time should match");
        assertEq(sablier.getEndTime(expectedStreamId), uint40(expectedEndTime), "Stream end time should match");
        assertTrue(sablier.isCancelable(expectedStreamId), "Stream should be cancelable");
        assertTrue(sablier.isTransferable(expectedStreamId), "Stream should be transferable");
    }

    function test_processInflows_noFundsToProcess() public {
        // Update config to set minThreshold very high so vault allocation is skipped
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max, // Skip vault allocation
                minResidual: 100_000e6, // Set minResidual equal to safe balance
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
        vm.stopPrank();

        // Now safe balance (100_000e6) equals minResidual, so no funds to process
        vm.prank(keeperBot);
        vm.expectRevert(IStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows();
    }

    function test_shouldProcess_noFundsAvailable() public {
        // Set minResidual equal to safe balance AND minThreshold very high
        // AND minProcessingPercent high enough that vault balance is below minAmount
        // so neither condition triggers
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max, // Skip vault threshold condition
                minResidual: 100_000e6, // Equal to safe balance
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.5e18, // 50% - vault balance (77K) < 50% of totalAssets (~1.77M) = ~885K
                feeFraction: 11
            })
        );

        // Even with 24h passed, vault balance is below minProcessingPercent of totalAssets
        vm.warp(block.timestamp + 24 hours);
        assertFalse(
            keeper.shouldProcess(), "shouldProcess should be false when vault balance below minProcessingPercent"
        );
    }

    function test_shouldProcess_vaultAboveThreshold() public {
        // Fund vault with USDC above threshold
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(VAULT, 20_000e6);

        // minThreshold is 10_000e6, vault now has > 10k USDC
        assertTrue(keeper.shouldProcess(), "shouldProcess should be true when vault above threshold");
    }

    function test_shouldProcess_timeBasedFallback() public {
        // Set minThreshold very high so condition 1 won't trigger
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18, // 1%
                feeFraction: 11
            })
        );

        // Let's first do a process to set lastProcessedTimestamp
        vm.prank(keeperBot);
        keeper.processInflows();

        // Now lastProcessedTimestamp is set to current block.timestamp
        assertEq(keeper.lastProcessedTimestamp(), block.timestamp, "lastProcessedTimestamp should be set");

        // Reset vault balance to 2% of vault totalAssets by transferring from USDC_WHALE to the vault
        (bool success, bytes memory data) = VAULT.call(abi.encodeWithSignature("totalAssets()"));
        require(success, "totalAssets() call failed");
        uint256 totalAssets = abi.decode(data, (uint256));
        uint256 twoPercent = totalAssets * 2 / 100;
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(VAULT, twoPercent);

        // Should be false immediately after processing (24h hasn't passed)
        assertFalse(keeper.shouldProcess(), "shouldProcess should be false before 24h");

        // Warp 24 hours
        vm.warp(block.timestamp + 24 hours);

        // Now should be true (24h passed and available >= 1% of vault total)
        assertTrue(keeper.shouldProcess(), "shouldProcess should be true after 24h");
    }

    function test_shouldProcess_timeBasedFallback_belowMinPercent() public {
        // Set minThreshold very high so condition 1 won't trigger
        // Set minProcessingPercent very high so time-based fallback fails
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max,
                minResidual: 99_999e6, // Only 1e6 available
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.5e18, // 50% - way higher than available
                feeFraction: 11
            })
        );

        // Warp 24 hours from now
        vm.warp(block.timestamp + 24 hours);

        // Should be false (24h passed but available < 50% of vault total)
        assertFalse(keeper.shouldProcess(), "shouldProcess should be false when below minProcessingPercent");
    }

    function test_lastProcessedTimestamp_initiallyZero() public view {
        // New keeper should have 0 timestamp
        assertEq(keeper.lastProcessedTimestamp(), 0, "lastProcessedTimestamp should be 0 initially");
    }

    function test_lastProcessedTimestamp_updatedAfterProcess() public {
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );

        uint256 expectedTimestamp = block.timestamp;
        vm.prank(keeperBot);
        keeper.processInflows();

        assertEq(
            keeper.lastProcessedTimestamp(), expectedTimestamp, "lastProcessedTimestamp should be updated after process"
        );
    }

    function test_configValidation_minProcessingPercentTooHigh() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.minProcessingPercent = 2e18; // 200%, invalid

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }
}
