// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {FlowMath} from "src/FlowMath.sol";

/// @notice Thin harness to expose FlowMath internal functions for testing
contract FlowMathHarness {
    function computeInterest(uint256 loanAmount, uint256 apr, uint256 holdingPeriod) external pure returns (uint256) {
        return FlowMath.computeInterest(loanAmount, apr, holdingPeriod);
    }

    function calculateRateIncrease(
        uint256 loanAmount,
        uint128 currentRate,
        uint256 apr,
        uint256 holdingPeriod,
        uint8 tokenDecimals,
        uint128 maxRateDelta,
        uint128 maxRate
    ) external pure returns (uint128 depositAmount, uint128 rateDelta, uint128 newRate) {
        return FlowMath.calculateRateIncrease(
            loanAmount, currentRate, apr, holdingPeriod, tokenDecimals, maxRateDelta, maxRate
        );
    }

    function calculateRateDecrease(
        uint256 loanAmount,
        uint128 currentRate,
        uint256 apr,
        uint256 holdingPeriod,
        uint8 tokenDecimals,
        uint128 maxRateDelta
    ) external pure returns (uint128 interest, uint128 rateDelta, uint128 newRate) {
        return FlowMath.calculateRateDecrease(loanAmount, currentRate, apr, holdingPeriod, tokenDecimals, maxRateDelta);
    }
}

/// @title FlowMathTest
/// @notice Unit tests for the FlowMath library — no fork needed.
///         Uses production values (11% APR, 28-day holding, USDC 6 decimals) for concrete tests,
///         and fuzz tests for invariant verification across the full input space.
contract FlowMathTest is Test {
    FlowMathHarness public math;

    // Production constants
    uint256 constant APR = 0.11e18; // 11%
    uint256 constant HOLDING_PERIOD = 28 days;
    uint8 constant USDC_DECIMALS = 6;
    uint256 constant SECONDS_PER_YEAR = 365 days;
    uint256 constant PRECISION = 1e18;

    function setUp() public {
        math = new FlowMathHarness();
    }

    /*//////////////////////////////////////////////////////////////
                      computeInterest — CONCRETE
    //////////////////////////////////////////////////////////////*/

    /// @notice 100,000 USDC at 11% APR for 28 days
    function test_computeInterest_100k() public view {
        uint256 loan = 100_000e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);

        // Manual: 100_000e6 * 0.11e18 * 2_419_200 / 31_536_000 / 1e18
        //       = 100_000_000_000 * 0.11 * 28/365
        //       = 843_835_616 (truncated)
        uint256 expected = (loan * APR * HOLDING_PERIOD) / SECONDS_PER_YEAR / PRECISION;
        assertEq(interest, expected);
        assertEq(interest, 843835616);
    }

    /// @notice 34,500 USDC (same value used in integration tests)
    function test_computeInterest_34500() public view {
        uint256 loan = 34_500e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint256 expected = (loan * APR * HOLDING_PERIOD) / SECONDS_PER_YEAR / PRECISION;
        assertEq(interest, expected);
    }

    /// @notice 10,000 USDC — small deposit
    function test_computeInterest_10k() public view {
        uint256 loan = 10_000e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint256 expected = (loan * APR * HOLDING_PERIOD) / SECONDS_PER_YEAR / PRECISION;
        assertEq(interest, expected);
        assertTrue(interest > 0, "Interest should be non-zero for 10k");
    }

    /// @notice 5,000,000 USDC — large deposit
    function test_computeInterest_5m() public view {
        uint256 loan = 5_000_000e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint256 expected = (loan * APR * HOLDING_PERIOD) / SECONDS_PER_YEAR / PRECISION;
        assertEq(interest, expected);
    }

    /// @notice Zero loan produces zero interest
    function test_computeInterest_zeroLoan() public view {
        assertEq(math.computeInterest(0, APR, HOLDING_PERIOD), 0);
    }

    /// @notice 100% APR for a full year should equal the loan amount
    function test_computeInterest_fullYear100pct() public view {
        uint256 loan = 1_000_000e6;
        uint256 interest = math.computeInterest(loan, 1e18, 365 days);
        assertEq(interest, loan, "100% APR for full year = loan amount");
    }

    /// @notice Interest scales linearly with loan amount
    function test_computeInterest_linearScaling() public view {
        uint256 interest1 = math.computeInterest(100_000e6, APR, HOLDING_PERIOD);
        uint256 interest2 = math.computeInterest(200_000e6, APR, HOLDING_PERIOD);
        assertEq(interest2, interest1 * 2, "Interest should scale linearly");
    }

    /// @notice Very small loan may truncate to zero interest
    function test_computeInterest_dustAmount() public view {
        // 1 wei USDC at 11% for 28 days → rounds to 0
        uint256 interest = math.computeInterest(1, APR, HOLDING_PERIOD);
        assertEq(interest, 0, "Dust amounts truncate to zero");
    }

    /*//////////////////////////////////////////////////////////////
                      computeInterest — FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Interest is always <= loanAmount (APR <= 100%, holdingPeriod <= 1 year)
    function testFuzz_computeInterest_neverExceedsLoan(uint256 loanAmount, uint256 apr, uint256 holdingPeriod)
        public
        view
    {
        // Bound to avoid overflow: loanAmount * apr * holdingPeriod must fit in uint256
        loanAmount = bound(loanAmount, 0, 1e30); // up to 1 trillion tokens with 18 decimals
        apr = bound(apr, 0, PRECISION); // 0-100%
        holdingPeriod = bound(holdingPeriod, 0, 365 days);

        uint256 interest = math.computeInterest(loanAmount, apr, holdingPeriod);
        assertLe(interest, loanAmount, "Interest should never exceed loan for APR<=100% and period<=1yr");
    }

    /// @notice Interest is monotonically increasing with loan amount
    function testFuzz_computeInterest_monotonic(uint256 loanA, uint256 loanB) public view {
        loanA = bound(loanA, 0, 1e30);
        loanB = bound(loanB, loanA, 1e30);

        uint256 interestA = math.computeInterest(loanA, APR, HOLDING_PERIOD);
        uint256 interestB = math.computeInterest(loanB, APR, HOLDING_PERIOD);
        assertLe(interestA, interestB, "Larger loan should yield >= interest");
    }

    /// @notice Interest scales linearly: interest(a+b) == interest(a) + interest(b) (within truncation)
    function testFuzz_computeInterest_additive(uint256 loanA, uint256 loanB) public view {
        loanA = bound(loanA, 1e6, 1e24);
        loanB = bound(loanB, 1e6, 1e24);

        uint256 interestA = math.computeInterest(loanA, APR, HOLDING_PERIOD);
        uint256 interestB = math.computeInterest(loanB, APR, HOLDING_PERIOD);
        uint256 interestSum = math.computeInterest(loanA + loanB, APR, HOLDING_PERIOD);

        // Truncation can lose at most 1 unit per computation, so combined can differ by at most 1
        assertApproxEqAbs(interestSum, interestA + interestB, 1, "Interest should be additive within rounding");
    }

    /*//////////////////////////////////////////////////////////////
                   calculateRateIncrease — CONCRETE
    //////////////////////////////////////////////////////////////*/

    /// @notice 100,000 USDC production scenario
    function test_calculateRateIncrease_100k() public view {
        uint128 initialRate = 1; // smallest non-zero rate
        uint256 loan = 100_000e6;

        (uint128 deposit, uint128 rateDelta, uint128 newRate) =
            math.calculateRateIncrease(loan, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        // deposit == interest
        uint256 expectedInterest = (loan * APR * HOLDING_PERIOD) / SECONDS_PER_YEAR / PRECISION;
        assertEq(deposit, expectedInterest, "Deposit should equal computed interest");

        // rateDelta = interest * 1e18 / (holdingPeriod * 10^6)
        uint128 expectedDelta = uint128((expectedInterest * 1e18) / (HOLDING_PERIOD * 1e6));
        assertEq(rateDelta, expectedDelta, "Rate delta should match formula");

        // newRate = initialRate + rateDelta
        assertEq(newRate, initialRate + expectedDelta, "New rate should be initial + delta");
    }

    /// @notice Two sequential deposits: verify additive rate behavior
    function test_calculateRateIncrease_twoDeposits() public view {
        uint128 initialRate = 1;

        // First deposit: 100k
        (, uint128 delta1, uint128 rate1) =
            math.calculateRateIncrease(100_000e6, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        // Second deposit: 50k on top of rate1
        (, uint128 delta2, uint128 rate2) =
            math.calculateRateIncrease(50_000e6, rate1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        // rate2 = rate1 + delta2 = initialRate + delta1 + delta2
        assertEq(rate2, initialRate + delta1 + delta2, "Rates should be additive");

        // delta2 should be exactly half of delta1 (50k is half of 100k)
        assertEq(delta2, delta1 / 2, "Delta should scale linearly with loan");
    }

    /// @notice Verify rate delta reconstructs to the right token flow
    ///         rateDelta * holdingPeriod * 10^decimals / 1e18 should approximate interest
    function test_calculateRateIncrease_rateDeltaReconstructsInterest() public view {
        uint256 loan = 100_000e6;

        (uint128 deposit, uint128 rateDelta,) =
            math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        // Reconstruct: how many tokens stream at rateDelta for the full holdingPeriod
        uint256 reconstructed = (uint256(rateDelta) * HOLDING_PERIOD * 1e6) / 1e18;

        // Should match deposit within rounding (truncation in both directions)
        assertApproxEqAbs(reconstructed, deposit, 1, "Streamed amount should reconstruct to deposit");
    }

    /// @notice 18-decimal token (e.g. DAI) — rate delta scaling
    function test_calculateRateIncrease_18decimals() public view {
        uint256 loan = 100_000e18; // 100k DAI
        uint8 decimals = 18;

        (uint128 deposit, uint128 rateDelta, uint128 newRate) =
            math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, decimals, 0, 0);

        uint256 expectedInterest = (loan * APR * HOLDING_PERIOD) / SECONDS_PER_YEAR / PRECISION;
        assertEq(deposit, expectedInterest);

        // For 18 decimals: rateDelta = interest * 1e18 / (holdingPeriod * 1e18) = interest / holdingPeriod
        uint128 expectedDelta = uint128(expectedInterest / HOLDING_PERIOD);
        assertEq(rateDelta, expectedDelta);
        assertEq(newRate, 1 + expectedDelta);
    }

    /*//////////////////////////////////////////////////////////////
                calculateRateIncrease — REVERT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_revert_zeroLoanAmount() public {
        vm.expectRevert(FlowMath.ZeroLoanAmount.selector);
        math.calculateRateIncrease(0, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);
    }

    function test_revert_zeroInterest() public {
        // 1 wei USDC at 11% for 28 days → interest truncates to 0
        vm.expectRevert(FlowMath.ZeroInterest.selector);
        math.calculateRateIncrease(1, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);
    }

    function test_revert_streamIsPaused() public {
        vm.expectRevert(FlowMath.StreamIsPaused.selector);
        math.calculateRateIncrease(100_000e6, 0, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);
    }

    function test_revert_rateDeltaExceedsMax() public {
        uint256 loan = 100_000e6;
        // Set maxRateDelta to 1 (extremely low) — should revert
        vm.expectRevert();
        math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 1, 0);
    }

    function test_revert_rateExceedsMax() public {
        uint256 loan = 100_000e6;
        // Set maxRate to 1 — any increase will exceed it
        vm.expectRevert();
        math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 1);
    }

    /*//////////////////////////////////////////////////////////////
                   calculateRateIncrease — LIMIT TESTS
    //////////////////////////////////////////////////////////////*/

    /// @notice maxRateDelta exactly at the boundary — should pass
    function test_maxRateDelta_exactBoundary() public view {
        uint256 loan = 100_000e6;
        // Compute what the delta will be, then set maxRateDelta to exactly that
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint128 expectedDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));

        (, uint128 rateDelta,) =
            math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, expectedDelta, 0);
        assertEq(rateDelta, expectedDelta);
    }

    /// @notice maxRate exactly at the boundary — should pass
    function test_maxRate_exactBoundary() public view {
        uint256 loan = 100_000e6;
        uint128 initialRate = 1;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint128 expectedDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));
        uint128 expectedNewRate = initialRate + expectedDelta;

        (,, uint128 newRate) =
            math.calculateRateIncrease(loan, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, expectedNewRate);
        assertEq(newRate, expectedNewRate);
    }

    /// @notice maxRateDelta one below the delta — should revert
    function test_revert_maxRateDelta_oneBelowBoundary() public {
        uint256 loan = 100_000e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint128 expectedDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));

        vm.expectRevert();
        math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, expectedDelta - 1, 0);
    }

    /// @notice maxRate one below the new rate — should revert
    function test_revert_maxRate_oneBelowBoundary() public {
        uint256 loan = 100_000e6;
        uint128 initialRate = 1;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint128 expectedDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));
        uint128 expectedNewRate = initialRate + expectedDelta;

        vm.expectRevert();
        math.calculateRateIncrease(loan, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, expectedNewRate - 1);
    }

    /*//////////////////////////////////////////////////////////////
                   calculateRateIncrease — FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice depositAmount always equals computeInterest result
    function testFuzz_depositEqualsInterest(uint256 loanAmount) public view {
        // Bound to values that produce non-zero interest and don't overflow
        loanAmount = bound(loanAmount, 1e6, 1e24);

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        // Also ensure rateDelta is non-zero
        uint256 rateDelta = (interest * 1e18) / (HOLDING_PERIOD * 1e6);
        vm.assume(rateDelta > 0);

        (uint128 deposit,,) = math.calculateRateIncrease(loanAmount, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);
        assertEq(deposit, interest, "Deposit should always equal computed interest");
    }

    /// @notice newRate = currentRate + rateDelta (always additive)
    function testFuzz_rateIsAdditive(uint256 loanAmount, uint128 currentRate) public view {
        loanAmount = bound(loanAmount, 1e6, 1e24);
        currentRate = uint128(bound(currentRate, 1, type(uint128).max / 2));

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint128 expectedDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));
        vm.assume(expectedDelta > 0);
        vm.assume(uint256(currentRate) + uint256(expectedDelta) <= type(uint128).max);

        (, uint128 rateDelta, uint128 newRate) =
            math.calculateRateIncrease(loanAmount, currentRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        assertEq(newRate, currentRate + rateDelta, "newRate must be currentRate + rateDelta");
    }

    /// @notice rateDelta * holdingPeriod * 10^decimals / 1e18 approximates depositAmount
    function testFuzz_rateDeltaReconstructsDeposit(uint256 loanAmount) public view {
        loanAmount = bound(loanAmount, 1e8, 1e24); // need enough to avoid dust

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint256 rawDelta = (interest * 1e18) / (HOLDING_PERIOD * 1e6);
        vm.assume(rawDelta > 0);

        (uint128 deposit, uint128 rateDelta,) =
            math.calculateRateIncrease(loanAmount, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        uint256 reconstructed = (uint256(rateDelta) * HOLDING_PERIOD * 1e6) / 1e18;
        assertApproxEqAbs(reconstructed, deposit, 1, "Rate delta should reconstruct deposit within 1 unit");
    }

    /// @notice Fuzz across different APRs and holding periods
    function testFuzz_calculateRateIncrease_varyParams(uint256 loanAmount, uint256 apr, uint256 holdingPeriod)
        public
        view
    {
        loanAmount = bound(loanAmount, 1e8, 1e24);
        apr = bound(apr, 0.01e18, 1e18); // 1% to 100%
        holdingPeriod = bound(holdingPeriod, 1 days, 365 days);

        uint256 interest = math.computeInterest(loanAmount, apr, holdingPeriod);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint256 rawDelta = (interest * 1e18) / (holdingPeriod * 1e6);
        vm.assume(rawDelta > 0 && rawDelta <= type(uint128).max);

        (uint128 deposit, uint128 rateDelta, uint128 newRate) =
            math.calculateRateIncrease(loanAmount, 1, apr, holdingPeriod, USDC_DECIMALS, 0, 0);

        assertEq(deposit, uint128(interest));
        assertEq(newRate, 1 + rateDelta);
        assertTrue(rateDelta > 0);
    }

    /// @notice Fuzz with different token decimals (6, 8, 18)
    function testFuzz_calculateRateIncrease_varyDecimals(uint256 loanAmount, uint8 decimals) public view {
        decimals = uint8(bound(decimals, 6, 18));
        // Scale loan to match decimals — cap at 1 billion tokens to avoid overflow
        loanAmount = bound(loanAmount, 10 ** decimals, 1e9 * (10 ** decimals));

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint256 rawDelta = (interest * 1e18) / (HOLDING_PERIOD * (10 ** decimals));
        vm.assume(rawDelta > 0 && rawDelta <= type(uint128).max);

        (uint128 deposit, uint128 rateDelta, uint128 newRate) =
            math.calculateRateIncrease(loanAmount, 1, APR, HOLDING_PERIOD, decimals, 0, 0);

        assertEq(deposit, uint128(interest));
        assertEq(newRate, 1 + rateDelta);

        // Reconstruct — rounding tolerance scales with how large the numbers are.
        // The UD21x18 conversion truncates, so error can be up to (10^decimals / 1e18) base units.
        // For 6 decimals this is <=1, for 18 decimals it can be larger.
        uint256 reconstructed = (uint256(rateDelta) * HOLDING_PERIOD * (10 ** decimals)) / 1e18;
        uint256 tolerance = decimals <= 6 ? 1 : (10 ** decimals) / 1e6;
        assertApproxEqAbs(reconstructed, deposit, tolerance, "Reconstruction within rounding tolerance");
    }

    /// @notice maxRateDelta=0 and maxRate=0 should never revert (unlimited)
    function testFuzz_unlimitedNeverReverts(uint256 loanAmount, uint128 currentRate) public view {
        loanAmount = bound(loanAmount, 1e6, 1e24);
        currentRate = uint128(bound(currentRate, 1, type(uint64).max)); // keep small enough to not overflow

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint256 rawDelta = (interest * 1e18) / (HOLDING_PERIOD * 1e6);
        vm.assume(rawDelta > 0 && rawDelta <= type(uint128).max);
        vm.assume(uint256(currentRate) + rawDelta <= type(uint128).max);

        // Should not revert with 0 limits
        math.calculateRateIncrease(loanAmount, currentRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);
    }

    /*//////////////////////////////////////////////////////////////
                   calculateRateDecrease — CONCRETE
    //////////////////////////////////////////////////////////////*/

    /// @notice Increase then decrease by the same loan amount: rate returns to initial
    function test_decreaseRate_fullRoundTrip() public view {
        uint128 initialRate = 1000; // non-trivial starting rate
        uint256 loan = 100_000e6;

        // Increase
        (, uint128 increaseDelta, uint128 rateAfterIncrease) =
            math.calculateRateIncrease(loan, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        // Decrease by same loan
        (, uint128 decreaseDelta, uint128 rateAfterDecrease) =
            math.calculateRateDecrease(loan, rateAfterIncrease, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);

        assertEq(increaseDelta, decreaseDelta, "Deltas should be symmetric");
        assertEq(rateAfterDecrease, initialRate, "Rate should return to initial");
    }

    /// @notice Partial repayment: decrease by half the original loan
    function test_decreaseRate_partialRepayment() public view {
        uint128 initialRate = 1;
        uint256 loan = 100_000e6;

        (, uint128 fullDelta, uint128 rateAfterIncrease) =
            math.calculateRateIncrease(loan, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        // Repay half
        (, uint128 halfDelta, uint128 rateAfterDecrease) =
            math.calculateRateDecrease(loan / 2, rateAfterIncrease, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);

        assertEq(halfDelta, fullDelta / 2, "Half loan should produce half delta");
        assertEq(rateAfterDecrease, initialRate + fullDelta - halfDelta, "Rate after partial repayment");
    }

    /// @notice Interest returned by decrease matches computeInterest
    function test_decreaseRate_interestMatchesCompute() public view {
        uint256 loan = 100_000e6;
        // First increase to get a realistic rate, then decrease
        (,, uint128 currentRate) = math.calculateRateIncrease(loan, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        (uint128 interest,,) = math.calculateRateDecrease(loan / 2, currentRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);

        uint256 expectedInterest = math.computeInterest(loan / 2, APR, HOLDING_PERIOD);
        assertEq(interest, expectedInterest, "Decrease interest should match computeInterest");
    }

    /*//////////////////////////////////////////////////////////////
                   calculateRateDecrease — REVERT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_decreaseRate_revert_zeroLoan() public {
        vm.expectRevert(FlowMath.ZeroLoanAmount.selector);
        math.calculateRateDecrease(0, 1000, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);
    }

    function test_decreaseRate_revert_streamPaused() public {
        vm.expectRevert(FlowMath.StreamIsPaused.selector);
        math.calculateRateDecrease(100_000e6, 0, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);
    }

    function test_decreaseRate_revert_rateUnderflow() public {
        // Rate is 1, decrease would produce a delta >> 1
        vm.expectRevert();
        math.calculateRateDecrease(100_000e6, 1, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);
    }

    function test_decreaseRate_revert_rateDeltaExceedsMax() public {
        uint256 loan = 100_000e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint128 delta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));

        // currentRate high enough to not underflow, but maxRateDelta too low
        vm.expectRevert();
        math.calculateRateDecrease(loan, delta + 1000, APR, HOLDING_PERIOD, USDC_DECIMALS, delta - 1);
    }

    /// @notice Decrease delta == currentRate should revert (would set rate to 0, use pause instead)
    function test_decreaseRate_revert_exactlyEqualsCurrentRate() public {
        uint256 loan = 100_000e6;
        uint256 interest = math.computeInterest(loan, APR, HOLDING_PERIOD);
        uint128 delta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));

        // Set currentRate = delta exactly → should revert with RateUnderflow
        vm.expectRevert(abi.encodeWithSelector(FlowMath.RateUnderflow.selector, delta, delta));
        math.calculateRateDecrease(loan, delta, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);
    }

    /*//////////////////////////////////////////////////////////////
                   calculateRateDecrease — FUZZ
    //////////////////////////////////////////////////////////////*/

    /// @notice Increase then decrease by same amount always returns to initial rate
    function testFuzz_decreaseRate_roundTrip(uint256 loanAmount, uint128 initialRate) public view {
        loanAmount = bound(loanAmount, 1e6, 1e24);
        initialRate = uint128(bound(initialRate, 1, type(uint64).max));

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint128 delta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));
        vm.assume(delta > 0);
        vm.assume(uint256(initialRate) + uint256(delta) <= type(uint128).max);

        (, uint128 increaseDelta, uint128 rateUp) =
            math.calculateRateIncrease(loanAmount, initialRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0, 0);

        (, uint128 decreaseDelta, uint128 rateDown) =
            math.calculateRateDecrease(loanAmount, rateUp, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);

        assertEq(increaseDelta, decreaseDelta, "Deltas must be symmetric");
        assertEq(rateDown, initialRate, "Rate must return to initial");
    }

    /// @notice newRate is always strictly less than currentRate after decrease
    function testFuzz_decreaseRate_rateAlwaysLower(uint256 loanAmount, uint128 currentRate) public view {
        loanAmount = bound(loanAmount, 1e6, 1e24);

        uint256 interest = math.computeInterest(loanAmount, APR, HOLDING_PERIOD);
        vm.assume(interest > 0 && interest <= type(uint128).max);

        uint128 delta = uint128((interest * 1e18) / (HOLDING_PERIOD * 1e6));
        vm.assume(delta > 0);

        // currentRate must be > delta to not underflow
        currentRate = uint128(bound(currentRate, delta + 1, type(uint128).max));

        (,, uint128 newRate) =
            math.calculateRateDecrease(loanAmount, currentRate, APR, HOLDING_PERIOD, USDC_DECIMALS, 0);

        assertLt(newRate, currentRate, "Rate must decrease");
        assertGt(newRate, 0, "Rate must stay positive");
    }
}
