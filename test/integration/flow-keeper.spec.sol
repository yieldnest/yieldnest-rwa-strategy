// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {Enum} from "lib/safe-smart-account/contracts/libraries/Enum.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {FlowStrategyKeeper, IFlowStrategyKeeper} from "src/FlowStrategyKeeper.sol";
import {FlowHandler} from "src/FlowHandler.sol";
import {FlowValidator} from "src/validators/FlowValidator.sol";
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
    FlowHandler public flowHandler;
    FlowValidator public flowValidator;
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
    address public proxyAdmin = address(0x9999);

    // EOA owner for the Safe
    uint256 public eoaOwnerPk = 0xA11CE;
    address public eoaOwner;

    uint256 public streamId;

    // Config constants
    uint256 constant APR = 0.11e18; // 11%
    uint256 constant MAX_APR = 0.115e18; // 11.5% validator cap
    uint256 constant HOLDING_PERIOD = 28 days;
    uint256 constant MIN_THRESHOLD = 200_000e6;
    uint256 constant MIN_RESIDUAL = 1_000e6;
    uint256 constant FEE_FRACTION = 10; // fee = interest / 10 = 1.1% (on top of 11% interest)
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

        bytes memory safeSetupData =
            abi.encodeCall(Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0))));

        SafeProxy safeProxy = safeFactory.createProxyWithNonce(address(safeSingleton), safeSetupData, 0);
        safe = Safe(payable(address(safeProxy)));

        // Create a Sablier Flow stream with Safe as sender
        // Initial rate is very small (essentially 0), the keeper will adjust it
        uint128 initialRate = 1; // smallest non-zero UD21x18 value
        streamId = sablierFlow.create(
            address(safe), streamReceiver, UD21x18.wrap(initialRate), uint40(block.timestamp), usdc, true
        );

        // Deploy FlowHandler behind TransparentUpgradeableProxy
        FlowHandler flowHandlerImpl = new FlowHandler();
        bytes memory initData = abi.encodeCall(
            FlowHandler.initialize,
            (
                FlowHandler.InitParams({
                    admin: address(this),
                    safe: address(safe),
                    flow: address(sablierFlow),
                    streamId: streamId,
                    token: address(usdc),
                    streamRecipient: streamReceiver,
                    apr: APR,
                    holdingPeriod: HOLDING_PERIOD,
                    maxRateDelta: 0, // unlimited
                    maxRate: 0, // unlimited
                    borrower: borrower,
                    feeWallet: feeWallet,
                    feeFraction: FEE_FRACTION
                })
            )
        );
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(flowHandlerImpl), proxyAdmin, initData);
        flowHandler = FlowHandler(address(proxy));

        // Deploy FlowValidator with the stream's 11.5% APR cap
        FlowValidator.StreamLimit[] memory limits = new FlowValidator.StreamLimit[](1);
        limits[0] = FlowValidator.StreamLimit({streamId: streamId, maxApr: MAX_APR});
        flowValidator = new FlowValidator(address(sablierFlow), vault, TOKEN_DECIMALS, limits, admin);

        // Enable FlowHandler proxy as a module on the Safe (it executes stream ops through Safe)
        _enableModuleOnSafe(address(flowHandler));

        // Deploy FlowStrategyKeeper
        keeper = new FlowStrategyKeeper(address(this), address(this), admin, keeperBot);

        // Initialize with config (borrower/feeWallet/feeFraction are in FlowHandler)
        keeper.initialize(
            IFlowStrategyKeeper.FlowKeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: address(safe),
                baseAsset: address(usdc),
                flowHandler: address(flowHandler),
                minThreshold: MIN_THRESHOLD,
                minResidual: MIN_RESIDUAL,
                minProcessingPercent: 0.01e18
            })
        );

        // Grant keeper OPERATOR_ROLE on FlowHandler
        flowHandler.grantRole(flowHandler.OPERATOR_ROLE(), address(keeper));

        // Separate KEEPER_ROLE and POWER_KEEPER_ROLE onto different addresses
        keeper.grantRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot);
        keeper.revokeRole(keeper.POWER_KEEPER_ROLE(), keeperBot);

        // Keeper is NOT a module — it uses FlowHandler.transferAsset() instead

        // Transfer admin roles
        keeper.grantRole(keeper.DEFAULT_ADMIN_ROLE(), admin);
        keeper.grantRole(keeper.CONFIG_MANAGER_ROLE(), admin);
        keeper.grantRole(keeper.PAUSER_ROLE(), admin);

        // Transfer FlowHandler roles to admin
        flowHandler.grantRole(flowHandler.DEFAULT_ADMIN_ROLE(), admin);
        flowHandler.grantRole(flowHandler.MANAGER_ROLE(), admin);
        flowHandler.renounceRole(flowHandler.DEFAULT_ADMIN_ROLE(), address(this));

        // Renounce test contract's roles
        keeper.renounceRole(keeper.PAUSER_ROLE(), address(this));
        keeper.renounceRole(keeper.CONFIG_MANAGER_ROLE(), address(this));
        keeper.renounceRole(keeper.DEFAULT_ADMIN_ROLE(), address(this));

        // Mock vault.totalAssets() for FlowValidator APR checks
        vm.mockCall(vault, abi.encodeWithSignature("totalAssets()"), abi.encode(uint256(100_000_000e6)));

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

    function test_keeperIsNotModule() public view {
        assertFalse(safe.isModuleEnabled(address(keeper)), "Keeper should NOT be enabled as module");
    }

    function test_flowHandlerIsProxy() public view {
        assertTrue(safe.isModuleEnabled(address(flowHandler)), "FlowHandler proxy should be enabled as module");
    }

    function test_streamExists() public view {
        assertTrue(sablierFlow.isStream(streamId), "Stream should exist");
        assertEq(sablierFlow.getSender(streamId), address(safe), "Stream sender should be Safe");
        assertEq(sablierFlow.getRecipient(streamId), streamReceiver, "Stream recipient should match");
    }

    function test_validatorTracksStream() public view {
        FlowValidator.StreamLimit[] memory limits = flowValidator.getLimits();
        assertEq(limits.length, 1, "Should track one stream");
        assertEq(limits[0].streamId, streamId, "Should track the created stream");
        assertEq(limits[0].maxApr, MAX_APR, "Max APR should be 11.5%");
    }

    function test_validatorAllowsNormalDisburse() public {
        // A normal disburse at 11% APR should pass the 11.5% validator cap
        uint256 available = 100_000e6;

        // Compute what rate this disburse will produce
        uint256 interest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 rateDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        uint128 newRate = 1 + rateDelta; // 1 = initial rate

        // Validator should allow this rate
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(newRate)));
        flowValidator.validate(address(sablierFlow), 0, data);
    }

    function test_validatorBlocksExcessiveRate() public {
        // A rate implying > 11.5% APR relative to vault totalAssets should be blocked
        uint256 totalAssets = 100_000_000e6;
        // Compute max allowed rate at 11.5%
        uint128 maxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * uint256(365 days)));

        // One above max should revert
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(maxRate + 1)));

        vm.expectRevert();
        flowValidator.validate(address(sablierFlow), 0, data);
    }

    function test_configIsCorrect() public view {
        IFlowStrategyKeeper.FlowKeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.vault, vault);
        assertEq(cfg.safe, address(safe));
        assertEq(cfg.flowHandler, address(flowHandler));

        // borrower, feeWallet, feeFraction are on FlowHandler
        assertEq(flowHandler.borrower(), borrower);
        assertEq(flowHandler.feeWallet(), feeWallet);
        assertEq(flowHandler.feeFraction(), FEE_FRACTION);
        assertEq(flowHandler.tokenDecimals(), TOKEN_DECIMALS);
        assertEq(flowHandler.apr(), APR);
        assertEq(flowHandler.holdingPeriod(), HOLDING_PERIOD);
    }

    /*//////////////////////////////////////////////////////////////
                       BASIC PROCESS INFLOWS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test basic processInflows: principal -> borrower, fee -> feeWallet, yield -> flow stream
    /// @dev With FlowHandler architecture:
    ///      - interest = available * APR * holdingPeriod / year (FlowHandler computes)
    ///      - fee = interest / feeFraction (on top of interest)
    ///      - principal = available - interest - fee
    ///      - stream receives full interest amount
    function test_processInflows_basic() public {
        uint256 available = 100_000e6; // 100,000 USDC

        // Calculate expected values
        // interest = 100,000 * 0.11 * 28days / 365days = ~843.835 USDC
        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        // fee = interest / 10 (on top of interest)
        uint256 expectedFee = expectedInterest / FEE_FRACTION;
        // stream receives full interest
        uint256 expectedStreamAmount = expectedInterest;
        // principal = available - interest - fee
        uint256 expectedPrincipal = available - expectedInterest - expectedFee;

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

        // Verify stream was deposited with full interest
        uint128 streamBalAfter = sablierFlow.getBalance(streamId);
        assertEq(uint256(streamBalAfter) - uint256(streamBalBefore), expectedStreamAmount, "Stream deposit");

        // Verify total deducted from Safe
        uint256 safeBalAfter = usdc.balanceOf(address(safe));
        assertEq(safeBalBefore - safeBalAfter, available, "Total deducted from Safe");

        // Verify rate was adjusted: newRate = initialRate(1) + interest / holdingPeriod
        uint128 expectedRate = 1 + uint128((expectedStreamAmount * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        uint128 rate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertEq(rate, expectedRate, "Rate should equal initial + additional");
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
        // principal = available - interest - fee
        uint256 actualInterest = available - actualPrincipal - actualFee;

        assertEq(actualInterest, expectedInterest, "Interest calculation");
        assertEq(actualFee, expectedInterest / FEE_FRACTION, "Fee calculation");
        assertEq(actualPrincipal, available - expectedInterest - actualFee, "Principal calculation");
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
        // Stream receives full interest (no fee deduction from stream)
        uint256 expectedStreamAmount = expectedInterest;

        // Rate = initialRate(1) + interest / holdingPeriod
        uint128 additionalRate = uint128((expectedStreamAmount * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        uint128 expectedRate = 1 + additionalRate;

        uint128 actualRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertEq(actualRate, expectedRate, "Rate should match calculated value");
    }

    /*//////////////////////////////////////////////////////////////
                    MULTIPLE DEPOSITS SAME EPOCH
    //////////////////////////////////////////////////////////////*/

    /// @notice Test two processInflows: rate should be additive
    function test_processInflows_multipleSameEpoch() public {
        // First deposit: 100,000 USDC
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        // Warp 7 days
        vm.warp(block.timestamp + 7 days);

        // Second deposit: 50,000 USDC
        uint256 available2 = 50_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        // Rate should be additive: rate1 + additionalRate from second deposit's interest
        uint256 interest2 = (available2 * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 additionalRate = uint128((interest2 * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        assertEq(rate2, rate1 + additionalRate, "Rate should be additive");

        // The stream should have a positive balance (both deposits minus accrued debt)
        assertTrue(sablierFlow.getBalance(streamId) > 0, "Stream should have positive balance");
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS ACROSS EPOCHS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test processInflows after a long gap: rate keeps accumulating
    function test_processInflows_acrossEpochs() public {
        // First deposit
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        // Warp 29 days (past one holding period)
        vm.warp(block.timestamp + 29 days);

        // Second deposit
        uint256 available2 = 80_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        // Rate should be additive regardless of time elapsed
        uint256 interest2 = (available2 * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 additionalRate = uint128((interest2 * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        assertEq(rate2, rate1 + additionalRate, "Rate should be additive across epochs");
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

        // Warp past holding period
        vm.warp(block.timestamp + HOLDING_PERIOD + 1);

        // Medium deposit: 500,000 USDC
        uint256 medium = 500_000e6;
        uint256 borrowerBal1 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, medium);
        uint256 principal2 = usdc.balanceOf(borrower) - borrowerBal1;

        // Warp past holding period
        vm.warp(block.timestamp + HOLDING_PERIOD + 1);

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

        // Warp well past depletion
        vm.warp(depletionTime + 14 days);

        // Stream should be insolvent
        uint256 uncoveredDebt = sablierFlow.uncoveredDebtOf(streamId);
        assertTrue(uncoveredDebt > 0, "Stream should be insolvent");

        // Process new inflows - this should recover the stream
        uint256 available2 = 200_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        // After recovery, the rate should have increased additively
        uint128 newRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(newRate > 0, "Rate should be positive after recovery");

        // Stream should be solvent again
        assertEq(sablierFlow.uncoveredDebtOf(streamId), 0, "Should be solvent after top-up");
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
        assertEq(received, withdrawable, "Receiver should get the withdrawable amount");

        // Warp 14 more days
        vm.warp(block.timestamp + 14 days);

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

        // Stream receives full interest (no fee deduction from stream)
        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedStreamAmount = expectedInterest;

        // Warp a full holding period
        vm.warp(block.timestamp + HOLDING_PERIOD);

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
        emit IFlowStrategyKeeper.KeeperExecuted(block.timestamp, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

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

        // === Period 2 ===
        vm.warp(block.timestamp + HOLDING_PERIOD + 1);

        uint256 available2 = 200_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate2 > rate1b, "Rate should increase with third deposit");

        // Let it stream for another holding period
        vm.warp(block.timestamp + HOLDING_PERIOD);

        // Recipient withdraws everything
        vm.prank(streamReceiver);
        uint128 withdrawn = sablierFlow.withdrawMax(streamId, streamReceiver);
        assertTrue(withdrawn > 0, "Should withdraw accumulated yield");

        // === Period 3 ===
        vm.warp(block.timestamp + 7 days);

        uint256 available3 = 150_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available3);

        // Rate should keep accumulating
        uint128 rate3 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate3 > rate2, "Rate should increase with fourth deposit");
    }
}
