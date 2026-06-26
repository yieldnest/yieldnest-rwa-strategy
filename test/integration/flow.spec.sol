// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

/// @title SablierFlowTest
/// @notice Standalone tests verifying Sablier Flow stream behavior on a mainnet fork.
///         Tests the core Flow operations: create, deposit, adjustRatePerSecond, withdraw,
///         stream depletion (insolvency), and top-up recovery.
///
/// Rate $/s
///   ^
///   |         ┌──────────┐
///   |         │          │         ┌──────┐
///   |  ┌──────┤          │         │      │
///   |  │      │          │         │      │
///   |  │      │          └─────────┤      └────┐
///   |  │      │                    │           │
///   ──┴──────┴──────────┴─────────┴───────────┴──> time
///      S0     S1        TOP-UP 0   S2   TOP-UP 1  (decrease)
contract SablierFlowTest is Test {
    ISablierFlow public sablierFlow;
    IERC20 public usdc;

    address public sender;
    address public recipient;

    uint256 public streamId;

    // USDC has 6 decimals. UD21x18: 1e18 = 1 token/sec.
    // To stream 1 USDC/sec: UD21x18.wrap(1e18)
    // To stream 0.001 USDC/sec = 1000 base units/sec: UD21x18.wrap(1000 * 1e12) = UD21x18.wrap(1e15)
    uint256 constant USDC_DECIMALS = 6;
    uint256 constant SCALING_FACTOR = 1e12; // 1e18 / 1e6

    function setUp() public {
        sablierFlow = ISablierFlow(MainnetKeeperContracts.SABLIER_FLOW);
        usdc = IERC20(MainnetKeeperContracts.USDC);

        sender = makeAddr("sender");
        recipient = makeAddr("recipient");

        // Fund the sender with USDC
        deal(address(usdc), sender, 10_000_000e6);
    }

    /*//////////////////////////////////////////////////////////////
                            STREAM CREATION
    //////////////////////////////////////////////////////////////*/

    /// @notice Test creating a Flow stream
    function test_createFlowStream() public {
        // Rate: 0.01 USDC/sec = 10,000 base units/sec
        // UD21x18: 10_000 * 1e12 = 1e16
        uint128 ratePerSecond = uint128(10_000 * SCALING_FACTOR);

        uint256 id =
            sablierFlow.create(sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true);

        assertTrue(sablierFlow.isStream(id), "Stream should exist");
        assertEq(sablierFlow.getSender(id), sender, "Sender should match");
        assertEq(sablierFlow.getRecipient(id), recipient, "Recipient should match");
        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(id)), ratePerSecond, "Rate should match");
        assertEq(sablierFlow.getBalance(id), 0, "Balance should be 0 (no deposit yet)");
    }

    /// @notice Test creating a stream and depositing in one call
    function test_createAndDeposit() public {
        uint128 ratePerSecond = uint128(10_000 * SCALING_FACTOR);
        uint128 depositAmount = 1_000e6; // 1,000 USDC

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        uint256 id = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        assertTrue(sablierFlow.isStream(id), "Stream should exist");
        assertEq(sablierFlow.getBalance(id), depositAmount, "Balance should equal deposit");
    }

    /*//////////////////////////////////////////////////////////////
                         STREAMING AT EXPECTED RATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that the stream emits tokens at the expected rate over time
    function test_streamEmitsAtExpectedRate() public {
        // Rate: 1 USDC/sec = 1e6 base units/sec
        // UD21x18: 1e6 * 1e12 = 1e18
        uint128 ratePerSecond = uint128(1e18);
        uint128 depositAmount = 100_000e6; // 100,000 USDC

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // After 100 seconds, 100 USDC should be withdrawable
        vm.warp(block.timestamp + 100);
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 100e6, "100 USDC should be withdrawable after 100s");

        // After 1 hour = 3600 seconds, 3600 USDC should be withdrawable
        vm.warp(block.timestamp + 3500); // 100 + 3500 = 3600 total
        withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 3_600e6, "3600 USDC should be withdrawable after 1 hour");

        // After 1 day = 86400 seconds, 86400 USDC should be withdrawable
        vm.warp(block.timestamp + 82800); // 3600 + 82800 = 86400 total
        withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 86_400e6, "86400 USDC should be withdrawable after 1 day");
    }

    /*//////////////////////////////////////////////////////////////
                        ADJUST RATE PER SECOND
    //////////////////////////////////////////////////////////////*/

    /// @notice Test increasing the rate per second (S0 -> S1 in diagram)
    function test_adjustRatePerSecond_increase() public {
        // Start with rate: 0.001 USDC/sec
        uint128 initialRate = uint128(1e15); // 0.001 * 1e18
        uint128 depositAmount = 100_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(initialRate), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp 1000 seconds, should have streamed ~1 USDC
        vm.warp(block.timestamp + 1000);
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 1e6, "1 USDC after 1000s at 0.001/s");

        // Increase rate to 0.01 USDC/sec (10x)
        uint128 newRate = uint128(1e16); // 0.01 * 1e18
        vm.prank(sender);
        sablierFlow.adjustRatePerSecond(streamId, UD21x18.wrap(newRate));

        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), newRate, "Rate should be updated");

        // Warp 1000 more seconds at new rate: should have ~10 more USDC (plus previous ~1)
        vm.warp(block.timestamp + 1000);
        withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 11e6, "~11 USDC total (1 + 10 at new rate)");
    }

    /// @notice Test decreasing the rate per second
    function test_adjustRatePerSecond_decrease() public {
        // Start with high rate: 0.01 USDC/sec
        uint128 initialRate = uint128(1e16);
        uint128 depositAmount = 100_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(initialRate), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp 1000 seconds, ~10 USDC streamed
        vm.warp(block.timestamp + 1000);

        // Decrease rate to 0.001 USDC/sec (1/10th)
        uint128 newRate = uint128(1e15);
        vm.prank(sender);
        sablierFlow.adjustRatePerSecond(streamId, UD21x18.wrap(newRate));

        // Warp 10000 more seconds at low rate: ~10 more USDC
        vm.warp(block.timestamp + 10000);
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 20e6, "20 USDC total (10 + 10 at lower rate)");
    }

    /*//////////////////////////////////////////////////////////////
                              TOP-UP / DEPOSIT
    //////////////////////////////////////////////////////////////*/

    /// @notice Test topping up a stream with additional funds
    function test_topUpDeposit() public {
        uint128 ratePerSecond = uint128(1e16); // 0.01 USDC/sec
        uint128 initialDeposit = 1_000e6; // 1,000 USDC

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), initialDeposit);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, initialDeposit
        );
        vm.stopPrank();

        assertEq(sablierFlow.getBalance(streamId), initialDeposit, "Initial balance");

        // Top up with 2,000 more USDC
        uint128 topUpAmount = 2_000e6;
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), topUpAmount);
        sablierFlow.deposit(streamId, topUpAmount, sender, recipient);
        vm.stopPrank();

        assertEq(sablierFlow.getBalance(streamId), initialDeposit + topUpAmount, "Balance after top-up");

        // Verify depletion time extended
        uint256 depletionTime = sablierFlow.depletionTimeOf(streamId);
        assertTrue(depletionTime > block.timestamp, "Depletion should be in the future");
    }

    /// @notice Test multiple top-ups at different intervals
    function test_multipleTopUps() public {
        uint128 ratePerSecond = uint128(1e16); // 0.01 USDC/sec = 864 USDC/day
        uint128 initialDeposit = 10_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), initialDeposit);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, initialDeposit
        );
        vm.stopPrank();

        // Warp 5 days, ~4320 USDC streamed
        vm.warp(block.timestamp + 5 days);
        uint128 withdrawable1 = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable1, 4_320e6, "4320 USDC after 5 days");

        // Top up with 5,000 USDC
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), 5_000e6);
        sablierFlow.deposit(streamId, 5_000e6, sender, recipient);
        vm.stopPrank();

        // Warp 5 more days, ~8640 USDC total streamed
        vm.warp(block.timestamp + 5 days);
        uint128 withdrawable2 = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable2, 8_640e6, "8640 USDC after 10 days total");

        // Top up with 20,000 USDC
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), 20_000e6);
        sablierFlow.deposit(streamId, 20_000e6, sender, recipient);
        vm.stopPrank();

        // Warp 10 more days, ~17280 USDC total streamed
        vm.warp(block.timestamp + 10 days);
        uint128 withdrawable3 = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable3, 17_280e6, "17280 USDC after 20 days total");
    }

    /*//////////////////////////////////////////////////////////////
                        STREAM DEPLETION (INSOLVENCY)
    //////////////////////////////////////////////////////////////*/

    /// @notice Test what happens when the stream balance runs out
    function test_streamDepletion_goesInsolvent() public {
        // Rate: 1 USDC/sec, deposit only 100 USDC -> depletes after 100 seconds
        uint128 ratePerSecond = uint128(1e18);
        uint128 depositAmount = 100e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Check depletion time
        uint256 depletionTime = sablierFlow.depletionTimeOf(streamId);
        // +1 because Sablier rounds the depletion timestamp up
        assertEq(depletionTime, block.timestamp + 100 + 1, "Depletion should be ~100s from now");

        // Warp to just before depletion
        vm.warp(block.timestamp + 99);
        assertEq(sablierFlow.uncoveredDebtOf(streamId), 0, "Should still be solvent at 99s");

        // Warp past depletion
        vm.warp(block.timestamp + 10); // now at 109s total
        uint256 uncoveredDebt = sablierFlow.uncoveredDebtOf(streamId);
        assertTrue(uncoveredDebt > 0, "Should have uncovered debt (insolvent)");

        // Withdrawable should be capped at the deposit amount
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, depositAmount, "Withdrawable capped at balance");

        // Refundable should be 0 (all funds consumed)
        uint128 refundable = sablierFlow.refundableAmountOf(streamId);
        assertEq(refundable, 0, "No refundable amount when insolvent");
    }

    /// @notice Test depositing after the stream goes insolvent
    function test_depositAfterDepletion() public {
        // Rate: 1 USDC/sec, deposit 100 USDC
        uint128 ratePerSecond = uint128(1e18);
        uint128 depositAmount = 100e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp well past depletion (200 seconds -> 100s uncovered)
        vm.warp(block.timestamp + 200);

        uint256 uncoveredDebtBefore = sablierFlow.uncoveredDebtOf(streamId);
        assertTrue(uncoveredDebtBefore > 0, "Should be insolvent");

        // Deposit 500 USDC to cover the gap and continue streaming
        uint128 topUpAmount = 500e6;
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), topUpAmount);
        sablierFlow.deposit(streamId, topUpAmount, sender, recipient);
        vm.stopPrank();

        // After deposit, the covered debt should increase (new funds cover old debt)
        // Balance = 100 (initial) + 500 (top-up) = 600 USDC
        // Total debt = 200 USDC (100 covered + 100 uncovered before deposit)
        // Now covered debt = min(200, 600) = 200 USDC
        // Withdrawable = 200 - 0 (nothing withdrawn yet) = 200 USDC
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 200e6, "Should be able to withdraw 200 USDC (all accrued debt)");

        // Refundable = balance - covered debt = 600 - 200 = 400
        uint128 refundable = sablierFlow.refundableAmountOf(streamId);
        assertEq(refundable, 400e6, "400 USDC refundable (600 balance - 200 covered debt)");

        // Stream should no longer be insolvent
        uint256 uncoveredDebtAfter = sablierFlow.uncoveredDebtOf(streamId);
        assertEq(uncoveredDebtAfter, 0, "Should be solvent again after top-up");
    }

    /*//////////////////////////////////////////////////////////////
                    WITHDRAWAL OF COMMITTED FUNDS
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that the recipient can withdraw accumulated streamed funds
    function test_withdrawCommittedFunds() public {
        uint128 ratePerSecond = uint128(1e18); // 1 USDC/sec
        uint128 depositAmount = 10_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp 1000 seconds -> 1000 USDC withdrawable
        vm.warp(block.timestamp + 1000);

        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);

        // Fund recipient with ETH for protocol fee and withdraw 500 USDC
        vm.deal(recipient, 1 ether);
        vm.prank(recipient);
        sablierFlow.withdraw{value: 0.01 ether}(streamId, recipient, 500e6);

        assertEq(usdc.balanceOf(recipient), recipientBalanceBefore + 500e6, "Recipient should receive 500 USDC");

        // Remaining withdrawable should be ~500 USDC
        uint128 remainingWithdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(remainingWithdrawable, 500e6, "500 USDC remaining withdrawable");
    }

    /// @notice Test withdrawMax to drain all available funds
    function test_withdrawMax() public {
        uint128 ratePerSecond = uint128(1e18); // 1 USDC/sec
        uint128 depositAmount = 10_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp 500 seconds -> 500 USDC withdrawable
        vm.warp(block.timestamp + 500);

        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);

        // Fund recipient with ETH for protocol fee and withdraw max
        vm.deal(recipient, 1 ether);
        vm.prank(recipient);
        uint128 withdrawn = sablierFlow.withdrawMax{value: 0.01 ether}(streamId, recipient);

        assertEq(withdrawn, 500e6, "Should withdraw 500 USDC");
        assertEq(usdc.balanceOf(recipient), recipientBalanceBefore + 500e6, "Recipient balance should increase");

        // Nothing left to withdraw
        assertEq(sablierFlow.withdrawableAmountOf(streamId), 0, "No more withdrawable");
    }

    /*//////////////////////////////////////////////////////////////
                          FULL LIFECYCLE TEST
    //////////////////////////////////////////////////////////////*/

    /// @notice Full lifecycle: create -> deposit -> stream -> rate increase -> top-up -> rate decrease -> deplete -> top-up
    function test_fullLifecycle() public {
        // --- Phase 1: Create with initial rate (S0) ---
        // Rate: 0.001 USDC/sec = ~86.4 USDC/day
        uint128 rate0 = uint128(1e15);
        uint128 initialDeposit = 5_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), initialDeposit);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(rate0), uint40(block.timestamp), usdc, true, initialDeposit
        );
        vm.stopPrank();

        // Stream for 1 day at rate0
        vm.warp(block.timestamp + 1 days);
        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertEq(withdrawable, 86_400_000, "86.4 USDC after 1 day at S0");

        // --- Phase 2: Increase rate (S0 -> S1) ---
        uint128 rate1 = uint128(5e15); // 0.005 USDC/sec = ~432 USDC/day
        vm.prank(sender);
        sablierFlow.adjustRatePerSecond(streamId, UD21x18.wrap(rate1));

        // Stream for 1 day at rate1
        vm.warp(block.timestamp + 1 days);
        withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        // Expected: 86.4 (day 1) + 432 (day 2) = ~518.4 USDC
        assertEq(withdrawable, 518_400_000, "518.4 USDC total after 2 days");

        // --- Phase 3: Top-up 0 ---
        uint128 topUp0 = 10_000e6;
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), topUp0);
        sablierFlow.deposit(streamId, topUp0, sender, recipient);
        vm.stopPrank();

        // Balance should be: 5000 + 10000 - 518.4 (withdrawn by stream but not yet by recipient) = ~14481.6
        // Actually, balance = deposits - withdrawals. No one has withdrawn yet.
        // balance = 5000 + 10000 = 15000
        assertEq(sablierFlow.getBalance(streamId), initialDeposit + topUp0, "Balance after top-up 0");

        // --- Phase 4: Stream continues, then rate decrease ---
        vm.warp(block.timestamp + 2 days); // 2 more days at rate1

        // Decrease rate (S1 -> lower)
        uint128 rate2 = uint128(2e15); // 0.002 USDC/sec = ~172.8 USDC/day
        vm.prank(sender);
        sablierFlow.adjustRatePerSecond(streamId, UD21x18.wrap(rate2));

        // Stream for 1 day at rate2
        vm.warp(block.timestamp + 1 days);

        // Recipient withdraws accumulated funds
        vm.prank(recipient);
        uint128 withdrawn = sablierFlow.withdrawMax(streamId, recipient);
        // Total streamed: 86.4 + 432 + (432*2) + 172.8 = 86.4 + 432 + 864 + 172.8 = 1555.2 USDC
        assertEq(withdrawn, 1_555_200_000, "1555.2 USDC total withdrawn");

        // --- Phase 5: Let it deplete ---
        // Remaining balance: 15000 - 1555.2 = 13444.8 USDC
        // At rate2 (0.002 USDC/sec), depletion in: 13444.8 / 0.002 = ~6,722,400 seconds = ~77.8 days
        uint256 depletionTime = sablierFlow.depletionTimeOf(streamId);
        assertTrue(depletionTime > block.timestamp, "Should have future depletion");

        // Warp to depletion + 1 day
        vm.warp(depletionTime + 1 days);
        assertTrue(sablierFlow.uncoveredDebtOf(streamId) > 0, "Should be insolvent");

        // --- Phase 6: Top-up 1 after depletion ---
        uint128 topUp1 = 20_000e6;
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), topUp1);
        sablierFlow.deposit(streamId, topUp1, sender, recipient);
        vm.stopPrank();

        // Should be solvent again
        assertEq(sablierFlow.uncoveredDebtOf(streamId), 0, "Should be solvent after top-up 1");

        // Verify stream is still active (rate > 0 means streaming)
        assertTrue(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)) > 0, "Stream should still be active");
    }

    /// @notice Test that rate per second is unchanged after a top-up is fully depleted
    function test_ratePerSecondUnchangedAfterTopUpDepleted() public {
        // Rate: 1 USDC/sec, deposit 100 USDC -> depletes after ~100s
        uint128 ratePerSecond = uint128(1e18);
        uint128 depositAmount = 100e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp past depletion
        vm.warp(block.timestamp + 200);
        assertTrue(sablierFlow.uncoveredDebtOf(streamId) > 0, "Should be insolvent");
        assertEq(
            UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), ratePerSecond, "Rate unchanged while insolvent"
        );

        // Top up with 500 USDC
        uint128 topUpAmount = 500e6;
        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), topUpAmount);
        sablierFlow.deposit(streamId, topUpAmount, sender, recipient);
        vm.stopPrank();

        assertEq(sablierFlow.uncoveredDebtOf(streamId), 0, "Should be solvent after top-up");
        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), ratePerSecond, "Rate unchanged after top-up");

        // Warp until the top-up is fully depleted
        // Balance = 600, total debt at t=200 was 200, so remaining = 400 USDC at 1/s = 400s more
        uint256 depletionTime = sablierFlow.depletionTimeOf(streamId);
        vm.warp(depletionTime + 100);

        assertTrue(sablierFlow.uncoveredDebtOf(streamId) > 0, "Should be insolvent again");
        assertEq(
            UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)),
            ratePerSecond,
            "Rate unchanged after top-up depleted"
        );
    }

    /*//////////////////////////////////////////////////////////////
                          PAUSE AND RESTART
    //////////////////////////////////////////////////////////////*/

    /// @notice Test pausing and restarting a stream
    function test_pauseAndRestart() public {
        uint128 ratePerSecond = uint128(1e18); // 1 USDC/sec
        uint128 depositAmount = 10_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Stream for 100 seconds
        vm.warp(block.timestamp + 100);
        assertEq(sablierFlow.withdrawableAmountOf(streamId), 100e6, "100 USDC after 100s");

        // Pause the stream
        vm.prank(sender);
        sablierFlow.pause(streamId);
        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), 0, "Rate should be 0 when paused");

        // Warp 100 more seconds - no additional streaming
        vm.warp(block.timestamp + 100);
        assertEq(sablierFlow.withdrawableAmountOf(streamId), 100e6, "Still 100 USDC (paused)");

        // Restart with a new rate
        uint128 newRate = uint128(2e18); // 2 USDC/sec
        vm.prank(sender);
        sablierFlow.restart(streamId, UD21x18.wrap(newRate));
        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), newRate, "New rate after restart");

        // Stream for 100 more seconds at 2 USDC/sec
        vm.warp(block.timestamp + 100);
        assertEq(sablierFlow.withdrawableAmountOf(streamId), 300e6, "300 USDC total (100 + 200)");
    }

    /// @notice Test restartAndDeposit combines both operations
    function test_restartAndDeposit() public {
        uint128 ratePerSecond = uint128(1e18); // 1 USDC/sec
        uint128 initialDeposit = 100e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), initialDeposit);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, initialDeposit
        );
        vm.stopPrank();

        // Let it stream briefly then pause
        vm.warp(block.timestamp + 50);
        vm.prank(sender);
        sablierFlow.pause(streamId);

        // Restart with new rate and additional deposit
        uint128 newRate = uint128(5e17); // 0.5 USDC/sec
        uint128 additionalDeposit = 500e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), additionalDeposit);
        sablierFlow.restartAndDeposit(streamId, UD21x18.wrap(newRate), additionalDeposit);
        vm.stopPrank();

        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), newRate, "Rate should be updated");
        // Balance = 100 + 500 = 600 USDC (but 50 was streamed before pause)
        assertEq(
            sablierFlow.getBalance(streamId), initialDeposit + additionalDeposit, "Balance after restartAndDeposit"
        );
    }

    /// @notice Test prefunding a paused stream, then restarting it later.
    function test_depositAtZeroRateThenRestart() public {
        uint128 zeroRate = 0;
        uint128 depositAmount = 10_000e6; // 10,000 USDC

        vm.prank(sender);
        streamId = sablierFlow.create(sender, recipient, UD21x18.wrap(zeroRate), uint40(block.timestamp), usdc, true);

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        sablierFlow.deposit(streamId, depositAmount, sender, recipient);
        vm.stopPrank();

        assertEq(UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)), 0, "Rate should start at 0");
        assertEq(sablierFlow.getBalance(streamId), depositAmount, "Balance should equal prefunded amount");

        // One week passes while paused - no funds should stream.
        vm.warp(block.timestamp + 7 days);
        assertEq(sablierFlow.withdrawableAmountOf(streamId), 0, "Nothing should stream while rate is 0");

        // Restart at 1000 base units/sec = 0.001 USDC/sec.
        uint128 restartedRate = uint128(1e15);
        vm.prank(sender);
        sablierFlow.restart(streamId, UD21x18.wrap(restartedRate));

        // Ten days at 0.001 USDC/sec = 864 USDC.
        vm.warp(block.timestamp + 10 days);
        assertEq(sablierFlow.withdrawableAmountOf(streamId), 864e6, "864 USDC should stream over 10 days");
    }

    /*//////////////////////////////////////////////////////////////
                       REFUND BY SENDER
    //////////////////////////////////////////////////////////////*/

    /// @notice Test that the sender can refund unstreamed funds
    function test_senderRefund() public {
        uint128 ratePerSecond = uint128(1e16); // 0.01 USDC/sec
        uint128 depositAmount = 10_000e6;

        vm.startPrank(sender);
        usdc.approve(address(sablierFlow), depositAmount);
        streamId = sablierFlow.createAndDeposit(
            sender, recipient, UD21x18.wrap(ratePerSecond), uint40(block.timestamp), usdc, true, depositAmount
        );
        vm.stopPrank();

        // Warp 1 day - ~864 USDC streamed
        vm.warp(block.timestamp + 1 days);

        uint128 refundable = sablierFlow.refundableAmountOf(streamId);
        assertTrue(refundable > 0, "Should have refundable amount");

        uint256 senderBalanceBefore = usdc.balanceOf(sender);

        // Sender refunds 5,000 USDC
        vm.prank(sender);
        sablierFlow.refund(streamId, 5_000e6);

        assertEq(usdc.balanceOf(sender), senderBalanceBefore + 5_000e6, "Sender should receive refund");
    }
}
