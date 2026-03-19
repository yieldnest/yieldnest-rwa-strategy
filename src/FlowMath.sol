// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

/// @title FlowMath
/// @notice Pure math library for Sablier Flow stream rate calculations.
///         Computes interest from loan parameters and derives UD21x18 rate deltas.
library FlowMath {
    /// @notice Precision for percentage calculations (1e18 = 100%)
    uint256 internal constant PRECISION = 1e18;

    /// @notice Seconds per year for APR calculation (365 days)
    uint256 internal constant SECONDS_PER_YEAR = 365 days;

    error ZeroLoanAmount();
    error ZeroInterest();
    error InterestExceedsUint128(uint256 interest);
    error ZeroRateDelta();
    error RateDeltaExceedsMax(uint128 delta, uint128 max);
    error RateExceedsMax(uint128 newRate, uint128 max);
    error RateUnderflow(uint128 currentRate, uint128 rateDelta);
    error StreamIsPaused();

    /// @notice Compute interest for a given loan amount
    /// @param loanAmount The total loan amount
    /// @param apr APR (1e18 = 100%)
    /// @param holdingPeriod Duration in seconds over which interest accrues
    /// @return interest The interest amount
    function computeInterest(uint256 loanAmount, uint256 apr, uint256 holdingPeriod) internal pure returns (uint256) {
        return (loanAmount * apr * holdingPeriod) / SECONDS_PER_YEAR / PRECISION;
    }

    /// @notice Compute interest, rate delta, and new rate from all inputs
    /// @dev Validates all invariants. Reverts on zero amounts, overflow, or limit breaches.
    /// @param loanAmount The total loan amount from which interest is derived
    /// @param currentRate The current stream rate (UD21x18 unwrapped)
    /// @param apr APR (1e18 = 100%)
    /// @param holdingPeriod Duration in seconds over which interest is spread
    /// @param tokenDecimals Token decimals for UD21x18 conversion
    /// @param maxRateDelta Maximum allowed rate increase per call (0 = unlimited)
    /// @param maxRate Maximum allowed absolute rate (0 = unlimited)
    /// @return depositAmount The interest amount to deposit into the stream
    /// @return rateDelta The rate increase (UD21x18 unwrapped)
    /// @return newRate The resulting rate after the increase
    function calculateRateIncrease(
        uint256 loanAmount,
        uint128 currentRate,
        uint256 apr,
        uint256 holdingPeriod,
        uint8 tokenDecimals,
        uint128 maxRateDelta,
        uint128 maxRate
    ) internal pure returns (uint128 depositAmount, uint128 rateDelta, uint128 newRate) {
        if (loanAmount == 0) revert ZeroLoanAmount();

        uint256 interest = computeInterest(loanAmount, apr, holdingPeriod);
        if (interest == 0) revert ZeroInterest();
        if (interest > type(uint128).max) revert InterestExceedsUint128(interest);

        depositAmount = uint128(interest);

        rateDelta = uint128((interest * 1e18) / (holdingPeriod * (10 ** tokenDecimals)));
        if (rateDelta == 0) revert ZeroRateDelta();

        if (maxRateDelta > 0 && rateDelta > maxRateDelta) {
            revert RateDeltaExceedsMax(rateDelta, maxRateDelta);
        }

        if (currentRate == 0) revert StreamIsPaused();

        newRate = currentRate + rateDelta;

        if (maxRate > 0 && newRate > maxRate) {
            revert RateExceedsMax(newRate, maxRate);
        }
    }

    /// @notice Compute interest, rate delta, and new rate for a loan repayment (rate decrease)
    /// @dev Validates all invariants. Reverts if decrease would bring rate to zero (use pause instead).
    /// @param loanAmount The repaid loan amount from which the rate reduction is derived
    /// @param currentRate The current stream rate (UD21x18 unwrapped)
    /// @param apr APR (1e18 = 100%)
    /// @param holdingPeriod Duration in seconds over which the rate was originally spread
    /// @param tokenDecimals Token decimals for UD21x18 conversion
    /// @param maxRateDelta Maximum allowed rate change per call (0 = unlimited)
    /// @return interest The interest amount corresponding to the repaid loan
    /// @return rateDelta The rate decrease (UD21x18 unwrapped)
    /// @return newRate The resulting rate after the decrease
    function calculateRateDecrease(
        uint256 loanAmount,
        uint128 currentRate,
        uint256 apr,
        uint256 holdingPeriod,
        uint8 tokenDecimals,
        uint128 maxRateDelta
    ) internal pure returns (uint128 interest, uint128 rateDelta, uint128 newRate) {
        if (loanAmount == 0) revert ZeroLoanAmount();

        uint256 _interest = computeInterest(loanAmount, apr, holdingPeriod);
        if (_interest == 0) revert ZeroInterest();
        if (_interest > type(uint128).max) revert InterestExceedsUint128(_interest);

        interest = uint128(_interest);

        rateDelta = uint128((_interest * 1e18) / (holdingPeriod * (10 ** tokenDecimals)));
        if (rateDelta == 0) revert ZeroRateDelta();

        if (maxRateDelta > 0 && rateDelta > maxRateDelta) {
            revert RateDeltaExceedsMax(rateDelta, maxRateDelta);
        }

        if (currentRate == 0) revert StreamIsPaused();
        if (rateDelta >= currentRate) revert RateUnderflow(currentRate, rateDelta);

        newRate = currentRate - rateDelta;
    }
}
