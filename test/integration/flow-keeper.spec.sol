// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {Enum} from "lib/safe-smart-account/contracts/libraries/Enum.sol";

import {FlowStrategyKeeper, IFlowStrategyKeeper} from "src/FlowStrategyKeeper.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

/// @title FlowStrategyKeeperIntegrationTest
/// @notice Full integration test for FlowStrategyKeeper using a real Gnosis Safe and
///         mainnet Sablier Flow contract (fork test).
///         Tests: basic processInflows, multiple deposits within same epoch, deposits across epochs,
///         different deposit sizes, late top-up (insolvency recovery), and withdrawal verification.
contract FlowStrategyKeeperIntegrationTest is Test {
    FlowStrategyKeeper public keeper;
    ISablierFlow public sablierFlow;
    IERC20 public usdc;
    Safe public safe;

    address public admin = address(0x1111);
    address public keeperBot = address(0x2222);
    address public powerKeeperBot = address(0x3333);
    address public vault = address(0x4444);
    address public targetStrategy = address(0x5555);
    address public borrower = address(0x6666);
    address public feeWallet = address(0x7777);
    address public streamReceiver = address(0x8888);

    // EOA owner for the Safe
    uint256 public eoaOwnerPk = 0xA11CE;
    address public eoaOwner;

    uint256 public streamId;

    // Config constants
    uint256 constant APR = 0.11e18; // 11%
    uint256 constant HOLDING_PERIOD = 28 days;
    uint256 constant MIN_THRESHOLD = 200_000e6;
    uint256 constant MIN_RESIDUAL = 1_000e6;
    uint256 constant FEE_FRACTION = 11;
    uint8 constant TOKEN_DECIMALS = 6;

    // UD21x18 scaling factor for USDC (6 decimals): 1e18 / 1e6 = 1e12
    uint256 constant SCALING_FACTOR = 1e12;

    function setUp() public {
        eoaOwner = vm.addr(eoaOwnerPk);

        // Real mainnet contracts
        sablierFlow = ISablierFlow(MainnetKeeperContracts.SABLIER_FLOW);
        usdc = IERC20(MainnetKeeperContracts.USDC);

        // Deploy a new Safe using mainnet factory
        Safe safeSingleton = Safe(payable(MainnetKeeperContracts.SAFE_SINGLETON));
        SafeProxyFactory safeFactory = SafeProxyFactory(MainnetKeeperContracts.SAFE_PROXY_FACTORY);

        address[] memory owners = new address[](1);
        owners[0] = eoaOwner;

        bytes memory safeSetupData = abi.encodeCall(
            Safe.setup,
            (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
        );

        SafeProxy safeProxy = safeFactory.createProxyWithNonce(address(safeSingleton), safeSetupData, 0);
        safe = Safe(payable(address(safeProxy)));

        // Create a Sablier Flow stream with Safe as sender
        // Initial rate is very small (essentially 0), the keeper will adjust it
        uint128 initialRate = 1; // smallest non-zero UD21x18 value
        streamId = sablierFlow.create(
            address(safe), streamReceiver, UD21x18.wrap(initialRate), uint40(block.timestamp), usdc, true
        );

        // Deploy FlowStrategyKeeper
        keeper = new FlowStrategyKeeper(address(this), address(this), admin, keeperBot);

        // Initialize with config
        keeper.initialize(
            IFlowStrategyKeeper.FlowKeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: address(safe),
                baseAsset: address(usdc),
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablierFlow: address(sablierFlow),
                streamId: streamId,
                tokenDecimals: TOKEN_DECIMALS,
                minThreshold: MIN_THRESHOLD,
                minResidual: MIN_RESIDUAL,
                apr: APR,
                holdingPeriod: HOLDING_PERIOD,
                minProcessingPercent: 0.01e18,
                feeFraction: FEE_FRACTION
            })
        );

        // Separate KEEPER_ROLE and POWER_KEEPER_ROLE onto different addresses
        keeper.grantRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot);
        keeper.revokeRole(keeper.POWER_KEEPER_ROLE(), keeperBot);

        // Enable keeper as a module on the Safe
        _enableModuleOnSafe(address(keeper));

        // Transfer admin roles
        keeper.grantRole(keeper.DEFAULT_ADMIN_ROLE(), admin);
        keeper.grantRole(keeper.CONFIG_MANAGER_ROLE(), admin);
        keeper.grantRole(keeper.PAUSER_ROLE(), admin);

        // Renounce test contract's roles
        keeper.renounceRole(keeper.PAUSER_ROLE(), address(this));
        keeper.renounceRole(keeper.CONFIG_MANAGER_ROLE(), address(this));
        keeper.renounceRole(keeper.DEFAULT_ADMIN_ROLE(), address(this));

        // Fund the Safe with USDC
        deal(address(usdc), address(safe), 10_000_000e6);
    }

    function _enableModuleOnSafe(address module) internal {
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", module);
        bytes32 txHash = safe.getTransactionHash(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPk, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        safe.execTransaction(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signature
        );
    }

    /*//////////////////////////////////////////////////////////////
                            SETUP VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_keeperIsModule() public view {
        assertTrue(safe.isModuleEnabled(address(keeper)), "Keeper should be enabled as module");
    }

    function test_streamExists() public view {
        assertTrue(sablierFlow.isStream(streamId), "Stream should exist");
        assertEq(sablierFlow.getSender(streamId), address(safe), "Stream sender should be Safe");
        assertEq(sablierFlow.getRecipient(streamId), streamReceiver, "Stream recipient should match");
    }

    function test_configIsCorrect() public view {
        IFlowStrategyKeeper.FlowKeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.vault, vault);
        assertEq(cfg.safe, address(safe));
        assertEq(cfg.borrower, borrower);
        assertEq(cfg.feeWallet, feeWallet);
        assertEq(cfg.streamReceiver, streamReceiver);
        assertEq(cfg.sablierFlow, address(sablierFlow));
        assertEq(cfg.streamId, streamId);
        assertEq(cfg.tokenDecimals, TOKEN_DECIMALS);
        assertEq(cfg.apr, APR);
        assertEq(cfg.holdingPeriod, HOLDING_PERIOD);
        assertEq(cfg.feeFraction, FEE_FRACTION);
    }

    /*//////////////////////////////////////////////////////////////
                       BASIC PROCESS INFLOWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test basic processInflows: principal -> borrower, fee -> feeWallet, yield -> flow stream
    function test_processInflows_basic() public {
        uint256 available = 100_000e6; // 100,000 USDC

        // Calculate expected values
        // interest = 100,000 * 0.11 * 28days / 365days = ~843.835 USDC
        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedFee = expectedInterest / FEE_FRACTION;
        uint256 expectedStreamAmount = expectedInterest - expectedFee;
        uint256 expectedPrincipal = available - expectedInterest;

        uint256 borrowerBalBefore = usdc.balanceOf(borrower);
        uint256 feeWalletBalBefore = usdc.balanceOf(feeWallet);
        uint256 safeBalBefore = usdc.balanceOf(address(safe));
        uint128 streamBalBefore = sablierFlow.getBalance(streamId);

        // Execute processInflows via POWER_KEEPER (skip vault allocation)
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // Verify principal went to borrower
        assertEq(usdc.balanceOf(borrower) - borrowerBalBefore, expectedPrincipal, "Principal to borrower");

        // Verify fee went to feeWallet
        assertEq(usdc.balanceOf(feeWallet) - feeWalletBalBefore, expectedFee, "Fee to feeWallet");

        // Verify stream was deposited
        uint128 streamBalAfter = sablierFlow.getBalance(streamId);
        assertEq(uint256(streamBalAfter) - uint256(streamBalBefore), expectedStreamAmount, "Stream deposit");

        // Verify total deducted from Safe
        uint256 safeBalAfter = usdc.balanceOf(address(safe));
        assertEq(safeBalBefore - safeBalAfter, available, "Total deducted from Safe");

        // Verify rate was adjusted
        uint128 rate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate > 1, "Rate should be increased from initial value");

        // Verify checkpoint was set
        assertEq(keeper.nextCheckpoint(), block.timestamp + HOLDING_PERIOD, "Checkpoint should be set");
    }

    /*//////////////////////////////////////////////////////////////
                        YIELD CALCULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify the exact yield calculation matches expected values
    function test_processInflows_yieldCalculation() public {
        uint256 available = 34_500e6; // 34,500 USDC (same as in StrategyKeeper test)

        uint256 borrowerBalBefore = usdc.balanceOf(borrower);
        uint256 feeWalletBalBefore = usdc.balanceOf(feeWallet);

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // interest = 34,500 * 0.11 * 28/365 = ~291.12..
        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 actualPrincipal = usdc.balanceOf(borrower) - borrowerBalBefore;
        uint256 actualFee = usdc.balanceOf(feeWallet) - feeWalletBalBefore;
        uint256 actualInterest = (available - actualPrincipal);

        assertEq(actualInterest, expectedInterest, "Interest calculation");
        assertEq(actualFee, expectedInterest / FEE_FRACTION, "Fee calculation");
        assertEq(actualPrincipal, available - expectedInterest, "Principal calculation");
    }

    /*//////////////////////////////////////////////////////////////
                       RATE CALCULATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify the UD21x18 rate calculation is correct
    function test_processInflows_rateCalculation() public {
        uint256 available = 100_000e6;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedStreamAmount = expectedInterest - expectedInterest / FEE_FRACTION;

        // Rate should drain streamAmount over HOLDING_PERIOD
        // UD21x18 rate = (streamAmount * 1e18) / (HOLDING_PERIOD * 10^6)
        uint128 expectedRate = uint128((expectedStreamAmount * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));

        uint128 actualRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertEq(actualRate, expectedRate, "Rate should match calculated value");

        // Verify the stream will be approximately drained by the checkpoint
        // At this rate, over HOLDING_PERIOD, streamed amount should ≈ streamAmount
        // streamed = rate * HOLDING_PERIOD * 10^6 / 1e18
        uint256 streamedOverPeriod = (uint256(actualRate) * HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)) / 1e18;
        assertApproxEqAbs(streamedOverPeriod, expectedStreamAmount, 1e3, "Should drain stream over holding period");
    }

    /*//////////////////////////////////////////////////////////////
                    MULTIPLE DEPOSITS SAME EPOCH
    //////////////////////////////////////////////////////////////*/

    /// @notice Test two processInflows within the same 28-day checkpoint period
    function test_processInflows_multipleSameEpoch() public {
        // First deposit: 100,000 USDC
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint256 checkpoint1 = keeper.nextCheckpoint();
        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        // Warp 7 days into the epoch
        vm.warp(block.timestamp + 7 days);

        // Second deposit: 50,000 USDC
        uint256 available2 = 50_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint256 checkpoint2 = keeper.nextCheckpoint();
        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        // Checkpoint should NOT advance (still within the same epoch)
        assertEq(checkpoint2, checkpoint1, "Checkpoint should stay the same within epoch");

        // Rate should be higher (more balance to drain over less time)
        assertTrue(rate2 > rate1, "Rate should increase with additional deposit in same epoch");

        // The stream should have a positive balance (both deposits minus accrued debt)
        assertTrue(sablierFlow.getBalance(streamId) > 0, "Stream should have positive balance");
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS ACROSS EPOCHS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test processInflows across checkpoint boundaries
    function test_processInflows_acrossEpochs() public {
        // Epoch 1: deposit
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint256 checkpoint1 = keeper.nextCheckpoint();

        // Warp past the checkpoint (28 days + 1 day)
        vm.warp(checkpoint1 + 1 days);

        // Epoch 2: new deposit
        uint256 available2 = 80_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint256 checkpoint2 = keeper.nextCheckpoint();

        // Checkpoint should advance to a new period
        assertTrue(checkpoint2 > checkpoint1, "Checkpoint should advance");
        assertEq(checkpoint2, block.timestamp + HOLDING_PERIOD, "New checkpoint = now + holdingPeriod");

        // Rate should be recalculated for the new epoch
        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate2 > 0, "Rate should be positive");
    }

    /*//////////////////////////////////////////////////////////////
                     DIFFERENT DEPOSIT SIZES
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify behavior with various deposit sizes
    function test_processInflows_differentSizes() public {
        // Small deposit: 10,000 USDC
        uint256 small = 10_000e6;
        uint256 borrowerBal0 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, small);
        uint256 principal1 = usdc.balanceOf(borrower) - borrowerBal0;

        // Reset checkpoint for clean test
        vm.warp(keeper.nextCheckpoint() + 1);

        // Medium deposit: 500,000 USDC
        uint256 medium = 500_000e6;
        uint256 borrowerBal1 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, medium);
        uint256 principal2 = usdc.balanceOf(borrower) - borrowerBal1;

        // Reset checkpoint
        vm.warp(keeper.nextCheckpoint() + 1);

        // Large deposit: 5,000,000 USDC
        uint256 large = 5_000_000e6;
        uint256 borrowerBal2 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, large);
        uint256 principal3 = usdc.balanceOf(borrower) - borrowerBal2;

        // Principal should scale proportionally
        assertApproxEqRel(principal2 * 1e18 / principal1, (medium * 1e18) / small, 0.001e18, "Medium/Small ratio");
        assertApproxEqRel(principal3 * 1e18 / principal1, (large * 1e18) / small, 0.001e18, "Large/Small ratio");
    }

    /*//////////////////////////////////////////////////////////////
                    LATE TOP-UP (INSOLVENCY)
    //////////////////////////////////////////////////////////////*/

    /// @notice Test what happens when the top-up doesn't come in time
    function test_processInflows_lateTopUp_insolvency() public {
        // Initial deposit
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        // Check depletion time
        uint256 depletionTime = sablierFlow.depletionTimeOf(streamId);
        assertTrue(depletionTime > block.timestamp, "Depletion should be in the future");

        // Warp well past depletion (checkpoint + 14 days extra)
        vm.warp(keeper.nextCheckpoint() + 14 days);

        // Stream should be insolvent
        uint256 uncoveredDebt = sablierFlow.uncoveredDebtOf(streamId);
        assertTrue(uncoveredDebt > 0, "Stream should be insolvent");

        // Process new inflows - this should recover the stream
        uint256 available2 = 200_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        // After recovery, the stream should have a new rate and checkpoint
        uint128 newRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(newRate > 0, "Rate should be positive after recovery");

        uint256 newCheckpoint = keeper.nextCheckpoint();
        assertEq(newCheckpoint, block.timestamp + HOLDING_PERIOD, "Checkpoint should reset after late top-up");
    }

    /*//////////////////////////////////////////////////////////////
                     STREAM RECEIVER WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify the stream receiver can withdraw accumulated funds
    function test_streamReceiver_canWithdraw() public {
        // Process inflows
        uint256 available = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // Warp 14 days (half the holding period)
        vm.warp(block.timestamp + 14 days);

        // Stream receiver should be able to withdraw accumulated funds
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertTrue(withdrawable > 0, "Should have withdrawable amount after 14 days");

        uint256 receiverBalBefore = usdc.balanceOf(streamReceiver);

        // Withdraw as stream receiver
        vm.prank(streamReceiver);
        sablierFlow.withdrawMax(streamId, streamReceiver);

        uint256 received = usdc.balanceOf(streamReceiver) - receiverBalBefore;
        assertApproxEqAbs(received, withdrawable, 1e3, "Receiver should get the withdrawable amount");

        // Warp to end of holding period
        vm.warp(keeper.nextCheckpoint());

        // Withdraw remaining
        uint128 remainingWithdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertTrue(remainingWithdrawable > 0, "Should have more to withdraw");
    }

    /*//////////////////////////////////////////////////////////////
                      STREAMING OVER FULL PERIOD
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify the total streamed over a full holding period matches the deposited amount
    function test_totalStreamedOverFullPeriod() public {
        uint256 available = 100_000e6;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedStreamAmount = expectedInterest - expectedInterest / FEE_FRACTION;

        // Warp to the checkpoint (full holding period)
        vm.warp(keeper.nextCheckpoint());

        // The total withdrawable should be approximately the stream amount
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        // Allow 0.1% tolerance for rounding
        assertApproxEqRel(
            uint256(withdrawable), expectedStreamAmount, 0.001e18, "Total streamed should match deposited yield"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL & PAUSE
    //////////////////////////////////////////////////////////////*/

    function test_revertOnUnauthorizedKeeper() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        keeper.processInflows(0, 100_000e6);
    }

    function test_revertOnKeeperCallingPowerKeeperFunction() public {
        vm.prank(keeperBot);
        vm.expectRevert();
        keeper.processInflows(0, 100_000e6);
    }

    function test_revertOnPowerKeeperZeroAvailable() public {
        vm.prank(powerKeeperBot);
        vm.expectRevert(IFlowStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows(0, 0);
    }

    function test_revertOnInsufficientSafeBalance() public {
        // Try to process more than the Safe has
        vm.prank(powerKeeperBot);
        vm.expectRevert();
        keeper.processInflows(0, 100_000_000e6);
    }

    function test_pauseBlocksProcessing() public {
        vm.prank(admin);
        keeper.pause();

        vm.prank(powerKeeperBot);
        vm.expectRevert();
        keeper.processInflows(0, 100_000e6);
    }

    function test_unpauseAllowsProcessing() public {
        vm.prank(admin);
        keeper.pause();

        vm.prank(admin);
        keeper.unpause();

        // Should succeed now
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, 100_000e6);
    }

    /*//////////////////////////////////////////////////////////////
                   EVENT EMISSION
    //////////////////////////////////////////////////////////////*/

    /// @notice Verify KeeperExecuted event is emitted with correct data
    function test_emitsKeeperExecutedEvent() public {
        uint256 available = 100_000e6;

        // We just check that the event is emitted (checking all params is brittle due to rate computation)
        vm.expectEmit(true, false, false, false);
        emit IFlowStrategyKeeper.KeeperExecuted(
            block.timestamp, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        );

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);
    }

    /*//////////////////////////////////////////////////////////////
                 MULTI-EPOCH LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    /// @notice Full lifecycle across multiple epochs with withdrawals
    function test_multiEpochLifecycle() public {
        // === Epoch 1 ===
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate1 > 0, "Rate should be set in epoch 1");

        // Recipient withdraws halfway through epoch 1
        vm.warp(block.timestamp + 14 days);
        vm.prank(streamReceiver);
        sablierFlow.withdrawMax(streamId, streamReceiver);

        // Another deposit within epoch 1
        uint256 available1b = 50_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1b);

        uint128 rate1b = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate1b > rate1, "Rate should increase with additional deposit");

        // === Epoch 2 ===
        vm.warp(keeper.nextCheckpoint() + 1);

        uint256 available2 = 200_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate2 > 0, "Rate should be set in epoch 2");

        // Let epoch 2 complete
        vm.warp(keeper.nextCheckpoint());

        // Recipient withdraws everything
        vm.prank(streamReceiver);
        uint128 withdrawn = sablierFlow.withdrawMax(streamId, streamReceiver);
        assertTrue(withdrawn > 0, "Should withdraw accumulated yield");

        // === Epoch 3 (late - past checkpoint) ===
        vm.warp(block.timestamp + 7 days); // 7 days past epoch 2's checkpoint

        uint256 available3 = 150_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available3);

        // Verify recovery
        uint128 rate3 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate3 > 0, "Rate should be positive after late epoch 3");
        assertEq(keeper.nextCheckpoint(), block.timestamp + HOLDING_PERIOD, "New checkpoint after late recovery");
    }
}
