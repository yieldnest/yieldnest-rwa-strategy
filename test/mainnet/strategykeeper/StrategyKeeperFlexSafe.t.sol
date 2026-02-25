// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";
import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";
import {IAccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";
import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";
import {ISablierBatchLockup} from "src/interfaces/sablier/ISablierBatchLockup.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";

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
    function ownerOf(uint256 streamId) external view returns (address);
}

/// @title StrategyKeeperFlexSafeTest
/// @notice Mainnet fork test that uses the REAL Safe from the FlexStrategy's accountingModule.
///         Unlike StrategyKeeperMainnetTest which deploys a fresh Safe, this test verifies
///         the keeper works with the actual deployed Safe that holds strategy funds.
/// @dev Run with: forge test --match-path "test/mainnet/strategykeeper/StrategyKeeperFlexSafe*" --fork-url <RPC_URL>
contract StrategyKeeperFlexSafeTest is Test {
    // USDC whale for funding
    address constant USDC_WHALE = 0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341;

    // Test accounts
    address public admin;
    address public keeperBot;
    address public powerKeeperBot;
    address public streamReceiver;

    // Contracts
    StrategyKeeper public keeper;

    // Real Safe obtained from the FlexStrategy's accountingModule
    address public realSafe;
    FlexStrategy public flexStrategy;
    IAccountingModule public accountingModule;

    function setUp() public {
        admin = makeAddr("admin");
        keeperBot = makeAddr("keeperBot");
        powerKeeperBot = makeAddr("powerKeeperBot");
        streamReceiver = makeAddr("streamReceiver");

        // Get the REAL Safe from the FlexStrategy's accountingModule
        flexStrategy = FlexStrategy(payable(MainnetKeeperContracts.FLEX_STRATEGY));
        accountingModule = flexStrategy.accountingModule();
        realSafe = accountingModule.safe();

        // Deploy keeper: admin gets admin roles, address(this) is initializer,
        // admin is pauser, keeperBot is processor (gets both keeper roles)
        keeper = new StrategyKeeper(admin, address(this), admin, keeperBot);
        keeper.initialize(
            IStrategyKeeper.KeeperConfig({
                vault: MainnetKeeperContracts.YNRWAX,
                targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
                safe: realSafe,
                baseAsset: MainnetKeeperContracts.USDC,
                borrower: MainnetKeeperContracts.BORROWER,
                feeWallet: MainnetKeeperContracts.FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );

        // Enable keeper as a module on the REAL Safe.
        // The Safe's enableModule is `authorized` (requires msg.sender == address(this)),
        // so we prank as the Safe itself to add the keeper module.
        vm.prank(realSafe);
        IGnosisSafe(realSafe).enableModule(address(keeper));

        // For testing: separate KEEPER_ROLE and POWER_KEEPER_ROLE onto different addresses
        vm.startPrank(admin);
        keeper.grantRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot);
        keeper.revokeRole(keeper.POWER_KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund the real safe with USDC from whale
        vm.prank(USDC_WHALE);
        IERC20(MainnetKeeperContracts.USDC).transfer(realSafe, 100_000e6);

        // Grant PROCESSOR_ROLE to keeper on the vault
        MainnetStrategyActors actors = new MainnetStrategyActors();
        bytes32 processorRole = IVaultRoles(MainnetKeeperContracts.YNRWAX).PROCESSOR_ROLE();
        vm.prank(actors.ADMIN());
        IVaultRoles(MainnetKeeperContracts.YNRWAX).grantRole(processorRole, address(keeper));
    }

    // ======== Setup verification ========

    function test_realSafeMatchesActors() public {
        // Verify the safe address matches the known deployed Safe from Actors
        MainnetStrategyActors actors = new MainnetStrategyActors();
        assertEq(realSafe, actors.SAFE(), "Real safe should match the known deployed Safe address");
    }

    function test_safeObtainedFromAccountingModule() public view {
        // Verify we can chain calls: strategy -> accountingModule -> safe
        address safe = FlexStrategy(payable(MainnetKeeperContracts.FLEX_STRATEGY)).accountingModule().safe();
        assertEq(safe, realSafe, "Safe from accountingModule should match");
        assertTrue(safe != address(0), "Safe should not be zero address");
    }

    function test_keeperEnabledAsModule() public view {
        assertTrue(
            IGnosisSafe(realSafe).isModuleEnabled(address(keeper)), "Keeper should be enabled as module on real safe"
        );
    }

    function test_realSafeHasCode() public view {
        assertTrue(realSafe.code.length > 0, "Real safe should be a deployed contract");
    }

    function test_realSafeHasUSDC() public view {
        assertGe(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe),
            100_000e6,
            "Real safe should have at least 100k USDC"
        );
    }

    function test_configPointsToRealSafe() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.safe, realSafe, "Config safe should be the real safe from accountingModule");
        assertEq(
            cfg.targetStrategy, MainnetKeeperContracts.FLEX_STRATEGY, "Config targetStrategy should be FlexStrategy"
        );
    }

    function test_roles() public view {
        assertTrue(keeper.hasRole(keeper.DEFAULT_ADMIN_ROLE(), admin), "admin should have DEFAULT_ADMIN_ROLE");
        assertTrue(keeper.hasRole(keeper.CONFIG_MANAGER_ROLE(), admin), "admin should have CONFIG_MANAGER_ROLE");
        assertTrue(keeper.hasRole(keeper.KEEPER_ROLE(), keeperBot), "keeperBot should have KEEPER_ROLE");
        assertTrue(
            keeper.hasRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot), "powerKeeperBot should have POWER_KEEPER_ROLE"
        );
        assertTrue(keeper.hasRole(keeper.PAUSER_ROLE(), admin), "admin should have PAUSER_ROLE");
    }

    // ======== processInflows with real Safe ========

    /// @notice Compute the available amount the auto processInflows will use.
    ///         Accounts for vault USDC being allocated to the safe via the strategy.
    function _expectedAutoAvailable() internal view returns (uint256 available) {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 vaultUsdcBalance = IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.YNRWAX);
        uint256 vaultAllocation = vaultUsdcBalance >= cfg.minThreshold ? vaultUsdcBalance : 0;
        uint256 safeBalanceAfterAllocation = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe) + vaultAllocation;
        available = safeBalanceAfterAllocation - cfg.minResidual;
    }

    function test_processInflows_withRealSafe() public {
        // Seed the vault with enough USDC to exceed minThreshold and trigger auto processing
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 vaultSeed = cfg.minThreshold + 50_000e6;
        vm.startPrank(USDC_WHALE);
        IERC20(MainnetKeeperContracts.USDC).approve(MainnetKeeperContracts.YNRWAX, vaultSeed);
        IERC4626(MainnetKeeperContracts.YNRWAX).deposit(vaultSeed, USDC_WHALE);
        vm.stopPrank();

        uint256 borrowerBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.BORROWER);
        uint256 feeWalletBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.FEE_WALLET);
        uint256 sablierBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);

        ISablierLockup sablier = ISablierLockup(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        uint256 expectedStreamId = sablier.nextStreamId();

        // The auto processInflows allocates vault USDC to the safe via the strategy.
        uint256 available = _expectedAutoAvailable();
        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        uint256 expectedStartTime = block.timestamp;

        // Execute processInflows via keeper bot
        vm.prank(keeperBot);
        keeper.processInflows();

        // Verify borrower received principal
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.BORROWER),
            borrowerBalanceBefore + principal,
            "Borrower should receive principal"
        );

        // Verify fee wallet received fee
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.FEE_WALLET),
            feeWalletBalanceBefore + fee,
            "Fee wallet should receive fee"
        );

        // Verify safe only has minResidual left
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe),
            cfg.minResidual,
            "Real safe should only have minResidual left"
        );

        // Verify Sablier stream created
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR),
            sablierBalanceBefore + streamAmount,
            "Sablier should hold stream amount"
        );

        // Verify stream details
        assertEq(sablier.nextStreamId(), expectedStreamId + 1, "Stream ID should increment");
        assertEq(sablier.getSender(expectedStreamId), realSafe, "Stream sender should be real safe");
        assertEq(sablier.getRecipient(expectedStreamId), streamReceiver, "Stream recipient should be streamReceiver");
        assertEq(sablier.ownerOf(expectedStreamId), streamReceiver, "Stream NFT owner should be streamReceiver");
        assertEq(sablier.getDepositedAmount(expectedStreamId), uint128(streamAmount), "Stream deposit should match");
        assertEq(sablier.getStartTime(expectedStreamId), uint40(expectedStartTime), "Stream start time should match");
        assertEq(
            sablier.getEndTime(expectedStreamId),
            uint40(expectedStartTime + cfg.holdingPeriod),
            "Stream end time should match"
        );
        assertTrue(sablier.isCancelable(expectedStreamId), "Stream should be cancelable");
        assertTrue(sablier.isTransferable(expectedStreamId), "Stream should be transferable");
    }

    function test_processInflowsManual_withRealSafe() public {
        uint256 safeBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        uint256 borrowerBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.BORROWER);
        uint256 feeWalletBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.FEE_WALLET);
        uint256 sablierBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);

        ISablierLockup sablier = ISablierLockup(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        uint256 expectedStreamId = sablier.nextStreamId();

        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = safeBalanceBefore - cfg.minResidual;
        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        uint256 expectedStartTime = block.timestamp;
        uint256 expectedEndTime = block.timestamp + cfg.holdingPeriod;

        // Execute processInflows via power keeper with manual params
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // Verify borrower received principal
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.BORROWER),
            borrowerBalanceBefore + principal,
            "Borrower should receive principal"
        );

        // Verify fee wallet received fee
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.FEE_WALLET),
            feeWalletBalanceBefore + fee,
            "Fee wallet should receive fee"
        );

        // Verify safe only has minResidual left
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe),
            cfg.minResidual,
            "Real safe should only have minResidual left"
        );

        // Verify stream details
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR),
            sablierBalanceBefore + streamAmount,
            "Sablier should hold stream amount"
        );
        assertEq(sablier.nextStreamId(), expectedStreamId + 1, "Stream ID should increment");
        assertEq(sablier.getSender(expectedStreamId), realSafe, "Stream sender should be real safe");
        assertEq(sablier.getRecipient(expectedStreamId), streamReceiver, "Stream recipient should be streamReceiver");
        assertEq(sablier.getDepositedAmount(expectedStreamId), uint128(streamAmount), "Stream deposit should match");
        assertEq(sablier.getStartTime(expectedStreamId), uint40(expectedStartTime), "Stream start time should match");
        assertEq(sablier.getEndTime(expectedStreamId), uint40(expectedEndTime), "Stream end time should match");
    }

    function test_processInflowsManual_partialAvailable_withRealSafe() public {
        uint256 safeBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        uint256 borrowerBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.BORROWER);
        uint256 feeWalletBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.FEE_WALLET);
        uint256 sablierBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);

        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 fullAvailable = safeBalanceBefore - cfg.minResidual;
        uint256 partialAvailable = fullAvailable / 2;

        uint256 interest = (partialAvailable * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = partialAvailable - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, partialAvailable);

        // Verify borrower received principal
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.BORROWER),
            borrowerBalanceBefore + principal,
            "Borrower should receive principal"
        );

        // Verify fee wallet received fee
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.FEE_WALLET),
            feeWalletBalanceBefore + fee,
            "Fee wallet should receive fee"
        );

        // Verify safe retained more than minResidual
        uint256 expectedSafeBalance = safeBalanceBefore - partialAvailable;
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe),
            expectedSafeBalance,
            "Safe should retain extra funds"
        );
        assertTrue(expectedSafeBalance > cfg.minResidual, "Safe should have more than minResidual");

        // Verify stream
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR),
            sablierBalanceBefore + streamAmount,
            "Sablier should hold stream amount"
        );
    }

    // ======== Event emission ========

    function test_processInflows_emitsEvent_withRealSafe() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 safeBalance = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        uint256 available = safeBalance - cfg.minResidual;

        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        vm.expectEmit(true, false, false, false);
        emit IStrategyKeeper.KeeperExecuted(
            block.timestamp,
            0,
            safeBalance,
            cfg.minResidual,
            available,
            interest,
            cfg.apr,
            cfg.holdingPeriod,
            principal,
            fee,
            streamAmount,
            0
        );

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);
    }

    // ======== Timestamp tracking ========

    function test_lastProcessedTimestamp_updatedAfterProcess_withRealSafe() public {
        assertEq(keeper.lastProcessedTimestamp(), 0, "Should start at 0");

        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe) - cfg.minResidual;

        uint256 expectedTimestamp = block.timestamp;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        assertEq(keeper.lastProcessedTimestamp(), expectedTimestamp, "Timestamp should be updated");
    }

    // ======== Revert cases ========

    function test_revertOnUnauthorizedKeeper_withRealSafe() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_revertOnUnauthorizedPowerKeeper_withRealSafe() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.processInflows(0, 50_000e6);
    }

    function test_revertWhenPaused_withRealSafe() public {
        vm.prank(admin);
        keeper.pause();

        vm.prank(keeperBot);
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_processInflowsManual_revertOnZeroAvailable() public {
        vm.prank(powerKeeperBot);
        vm.expectRevert(IStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows(0, 0);
    }

    function test_processInflowsManual_revertOnInsufficientBalance() public {
        uint256 safeBalance = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();

        // Try to disburse more than safe has
        uint256 tooMuch = safeBalance;

        vm.prank(powerKeeperBot);
        vm.expectRevert(
            abi.encodeWithSelector(
                IStrategyKeeper.InsufficientSafeBalance.selector, safeBalance, tooMuch + cfg.minResidual
            )
        );
        keeper.processInflows(0, tooMuch);
    }

    // ======== Module-specific tests on real Safe ========

    function test_moduleCanExecuteTransfers_onRealSafe() public {
        // Verify the keeper (as a module) can execute transfers from the real Safe
        uint256 safeBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        assertTrue(safeBalanceBefore > 0, "Safe should have USDC");

        // processInflows executes multiple Safe transactions (transfer principal, transfer fee, create stream)
        // If module execution works, the entire flow succeeds
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = safeBalanceBefore - cfg.minResidual;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // If we get here without revert, module execution worked on the real Safe
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe),
            cfg.minResidual,
            "Module execution should have moved funds"
        );
    }

    function test_nonModuleCannotExecuteOnRealSafe() public {
        // Deploy a second keeper that is NOT enabled as a module
        StrategyKeeper unauthorizedKeeper = new StrategyKeeper(admin, address(this), admin, powerKeeperBot);
        unauthorizedKeeper.initialize(
            IStrategyKeeper.KeeperConfig({
                vault: MainnetKeeperContracts.YNRWAX,
                targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
                safe: realSafe,
                baseAsset: MainnetKeeperContracts.USDC,
                borrower: MainnetKeeperContracts.BORROWER,
                feeWallet: MainnetKeeperContracts.FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );

        // Verify it is NOT a module
        assertFalse(
            IGnosisSafe(realSafe).isModuleEnabled(address(unauthorizedKeeper)),
            "Unauthorized keeper should not be a module"
        );

        // Attempt to process should revert because the keeper is not a module on the Safe.
        // The Safe itself reverts with GS104 ("only whitelisted modules") before
        // execTransactionFromModule can return false.
        vm.prank(powerKeeperBot);
        vm.expectRevert();
        unauthorizedKeeper.processInflows(0, 50_000e6);
    }

    // ======== Strategy-Safe relationship verification ========

    function test_strategyAccountingModuleSafeRelationship() public view {
        // Verify the full chain: FlexStrategy -> AccountingModule -> Safe
        FlexStrategy strat = FlexStrategy(payable(MainnetKeeperContracts.FLEX_STRATEGY));
        IAccountingModule am = strat.accountingModule();

        assertEq(address(am), address(accountingModule), "AccountingModule should match");
        assertEq(am.safe(), realSafe, "Safe from accountingModule should match realSafe");
        assertEq(
            am.strategy(),
            MainnetKeeperContracts.FLEX_STRATEGY,
            "AccountingModule strategy should point back to FlexStrategy"
        );
        assertEq(am.baseAsset(), MainnetKeeperContracts.USDC, "AccountingModule baseAsset should be USDC");
    }

    function test_safeIsWhereStrategyFundsReside() public view {
        // The real safe's USDC balance counts as the strategy's available assets
        uint256 safeBalance = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        assertTrue(safeBalance > 0, "Real safe should hold strategy funds");
    }

    // ======== Batch Lockup tests on real Safe ========

    function test_batchLockupExists() public view {
        assertTrue(
            MainnetKeeperContracts.SABLIER_BATCH_LOCKUP.code.length > 0, "Batch lockup should be a deployed contract"
        );
    }

    function test_batchCreateStreams_onRealSafe() public {
        uint256 streamAmount1 = 500e6;
        uint256 streamAmount2 = 800e6;
        uint256 totalAmount = streamAmount1 + streamAmount2;

        ISablierLockup sablier = ISablierLockup(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        uint256 nextStreamIdBefore = sablier.nextStreamId();
        uint256 safeBalanceBefore = IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe);
        uint256 sablierBalanceBefore =
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);

        // Execute module calls as the keeper (which is an enabled module on the real Safe)
        vm.startPrank(address(keeper));

        // Step 1: Approve BatchLockup to spend USDC from the real Safe (via keeper module)
        bytes memory approveData =
            abi.encodeCall(IERC20.approve, (MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, totalAmount));
        bool success = IGnosisSafe(realSafe).execTransactionFromModule(
            MainnetKeeperContracts.USDC, 0, approveData, IGnosisSafe.Operation.Call
        );
        assertTrue(success, "Approve should succeed");

        // Step 2: Build batch params
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](2);

        batch[0] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: realSafe,
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount1),
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        batch[1] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: realSafe,
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount2),
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 56 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        // Step 3: Call batch createWithTimestampsLL from the real Safe via keeper module
        bytes memory batchData = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL,
            (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, IERC20(MainnetKeeperContracts.USDC), batch)
        );
        success = IGnosisSafe(realSafe).execTransactionFromModule(
            MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, 0, batchData, IGnosisSafe.Operation.Call
        );
        assertTrue(success, "Batch create should succeed");

        vm.stopPrank();

        // Verify 2 streams were created
        assertEq(sablier.nextStreamId(), nextStreamIdBefore + 2, "2 streams should be created");

        // Verify stream details
        assertEq(sablier.getSender(nextStreamIdBefore), realSafe, "Stream 1 sender should be real safe");
        assertEq(sablier.getRecipient(nextStreamIdBefore), streamReceiver, "Stream 1 recipient should match");
        assertEq(sablier.getDepositedAmount(nextStreamIdBefore), uint128(streamAmount1), "Stream 1 amount should match");
        assertTrue(sablier.isCancelable(nextStreamIdBefore), "Stream 1 should be cancelable");
        assertTrue(sablier.isTransferable(nextStreamIdBefore), "Stream 1 should be transferable");

        assertEq(sablier.getSender(nextStreamIdBefore + 1), realSafe, "Stream 2 sender should be real safe");
        assertEq(sablier.getRecipient(nextStreamIdBefore + 1), streamReceiver, "Stream 2 recipient should match");
        assertEq(
            sablier.getDepositedAmount(nextStreamIdBefore + 1), uint128(streamAmount2), "Stream 2 amount should match"
        );

        // Verify USDC balances
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(realSafe),
            safeBalanceBefore - totalAmount,
            "Safe balance should decrease by total amount"
        );
        assertEq(
            IERC20(MainnetKeeperContracts.USDC).balanceOf(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR),
            sablierBalanceBefore + totalAmount,
            "Sablier should hold the total stream amount"
        );
    }
}
