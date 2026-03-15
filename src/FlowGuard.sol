// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {AccessControlEnumerable} from
    "lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";

/// @title FlowGuard
/// @notice Safe module that wraps Sablier Flow stream operations with guard rails.
///         The Safe remains the stream sender; this module controls what callers can do:
///         - `increaseRate`: given a loanAmount, computes interest, deposits it, and increases the rate
///         - Rate increases are bounded by a max delta and max absolute rate
///         - Pause, decrease, refund, and void are blocked for OPERATOR_ROLE callers
///         - ADMIN_ROLE can pause the stream in emergencies
contract FlowGuard is AccessControlEnumerable {
    /// @notice Role that can call increaseRate (e.g. the FlowStrategyKeeper)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Precision for percentage calculations (1e18 = 100%)
    uint256 public constant PRECISION = 1e18;

    /// @notice Seconds per year for APR calculation (365 days)
    uint256 public constant SECONDS_PER_YEAR = 365 days;

    /// @notice Gnosis Safe that owns the stream
    address public immutable SAFE;

    /// @notice Sablier Flow contract
    ISablierFlow public immutable FLOW;

    /// @notice The stream ID this guard controls
    uint256 public immutable STREAM_ID;

    /// @notice The token being streamed
    IERC20 public immutable TOKEN;

    /// @notice The stream recipient
    address public immutable STREAM_RECIPIENT;

    /// @notice Token decimals, read from Sablier Flow at construction
    uint8 public immutable TOKEN_DECIMALS;

    /// @notice APR for interest calculation (1e18 = 100%)
    uint256 public apr;

    /// @notice Duration over which each deposit's rate is spread (e.g., 28 days)
    uint256 public holdingPeriod;

    /// @notice Maximum rate increase (UD21x18) allowed per call. 0 = no limit.
    uint128 public maxRateDelta;

    /// @notice Maximum absolute rate (UD21x18) the stream can reach. 0 = no limit.
    uint128 public maxRate;

    error SafeExecutionFailed();
    error RateDeltaExceedsMax(uint128 delta, uint128 max);
    error RateExceedsMax(uint128 newRate, uint128 max);
    error ZeroLoanAmount();
    error ZeroInterest();
    error InterestExceedsUint128(uint256 interest);
    error ZeroRateDelta();
    error StreamIsPaused();
    error InvalidHoldingPeriod();
    error InvalidApr();

    event RateIncreased(uint128 previousRate, uint128 newRate, uint128 depositAmount, uint256 loanAmount);
    event LimitsUpdated(uint128 maxRateDelta, uint128 maxRate);
    event StreamPaused();
    event HoldingPeriodUpdated(uint256 holdingPeriod);
    event AprUpdated(uint256 apr);

    /// @param _admin Admin address (DEFAULT_ADMIN_ROLE)
    /// @param _safe Gnosis Safe that is the stream sender
    /// @param _flow Sablier Flow contract address
    /// @param _streamId Pre-existing stream ID owned by the Safe
    /// @param _token The ERC-20 token being streamed
    /// @param _streamRecipient The stream recipient address
    /// @param _apr APR for interest calculation (1e18 = 100%)
    /// @param _holdingPeriod Duration in seconds over which each deposit's rate is spread
    /// @param _maxRateDelta Maximum rate delta per call (0 = unlimited)
    /// @param _maxRate Maximum absolute rate (0 = unlimited)
    constructor(
        address _admin,
        address _safe,
        address _flow,
        uint256 _streamId,
        address _token,
        address _streamRecipient,
        uint256 _apr,
        uint256 _holdingPeriod,
        uint128 _maxRateDelta,
        uint128 _maxRate
    ) {
        if (_apr == 0 || _apr > PRECISION) revert InvalidApr();
        if (_holdingPeriod == 0) revert InvalidHoldingPeriod();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        SAFE = _safe;
        FLOW = ISablierFlow(_flow);
        STREAM_ID = _streamId;
        TOKEN = IERC20(_token);
        STREAM_RECIPIENT = _streamRecipient;
        TOKEN_DECIMALS = ISablierFlow(_flow).getTokenDecimals(_streamId);
        apr = _apr;
        holdingPeriod = _holdingPeriod;
        maxRateDelta = _maxRateDelta;
        maxRate = _maxRate;
    }

    /// @notice Compute the interest for a given loan amount
    /// @param loanAmount The total loan amount
    /// @return interest The interest amount (without fees)
    function computeInterest(uint256 loanAmount) public view returns (uint256) {
        return (loanAmount * apr * holdingPeriod) / SECONDS_PER_YEAR / PRECISION;
    }

    /// @notice Given a loanAmount, compute interest, deposit it into the stream, and increase the rate
    /// @dev Caller must have OPERATOR_ROLE. The rate can only go up, never down.
    ///      Interest is computed as: loanAmount * apr * holdingPeriod / SECONDS_PER_YEAR / PRECISION.
    ///      Rate delta is computed from the interest amount spread over the holding period.
    /// @param loanAmount The total loan amount from which interest is derived
    function increaseRate(uint256 loanAmount) external onlyRole(OPERATOR_ROLE) {
        if (loanAmount == 0) revert ZeroLoanAmount();

        uint256 interest = computeInterest(loanAmount);
        if (interest == 0) revert ZeroInterest();
        if (interest > type(uint128).max) revert InterestExceedsUint128(interest);

        uint128 depositAmount = uint128(interest);

        // Compute rate delta: UD21x18 rate = (interest * 1e18) / (holdingPeriod * 10^decimals)
        uint128 rateDelta =
            uint128((interest * 1e18) / (holdingPeriod * (10 ** TOKEN_DECIMALS)));
        if (rateDelta == 0) revert ZeroRateDelta();

        // Enforce max delta
        if (maxRateDelta > 0 && rateDelta > maxRateDelta) {
            revert RateDeltaExceedsMax(rateDelta, maxRateDelta);
        }

        uint128 currentRate = uint128(UD21x18.unwrap(FLOW.getRatePerSecond(STREAM_ID)));
        if (currentRate == 0) revert StreamIsPaused();

        uint128 newRate = currentRate + rateDelta;

        // Enforce max absolute rate
        if (maxRate > 0 && newRate > maxRate) {
            revert RateExceedsMax(newRate, maxRate);
        }

        // Approve Sablier Flow to spend token from Safe
        _executeSafe(address(TOKEN), abi.encodeCall(IERC20.approve, (address(FLOW), depositAmount)));

        // Deposit first, then adjust rate
        _executeSafe(
            address(FLOW),
            abi.encodeCall(ISablierFlow.deposit, (STREAM_ID, depositAmount, SAFE, STREAM_RECIPIENT))
        );
        _executeSafe(
            address(FLOW), abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(newRate)))
        );

        emit RateIncreased(currentRate, newRate, depositAmount, loanAmount);
    }

    /// @notice Pause the stream in an emergency
    /// @dev Only callable by DEFAULT_ADMIN_ROLE
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _executeSafe(address(FLOW), abi.encodeCall(ISablierFlow.pause, (STREAM_ID)));
        emit StreamPaused();
    }

    /// @notice Update rate limits
    /// @param _maxRateDelta New max rate delta per call (0 = unlimited)
    /// @param _maxRate New max absolute rate (0 = unlimited)
    function setLimits(uint128 _maxRateDelta, uint128 _maxRate) external onlyRole(DEFAULT_ADMIN_ROLE) {
        maxRateDelta = _maxRateDelta;
        maxRate = _maxRate;
        emit LimitsUpdated(_maxRateDelta, _maxRate);
    }

    /// @notice Update the holding period
    /// @param _holdingPeriod New duration in seconds
    function setHoldingPeriod(uint256 _holdingPeriod) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_holdingPeriod == 0) revert InvalidHoldingPeriod();
        holdingPeriod = _holdingPeriod;
        emit HoldingPeriodUpdated(_holdingPeriod);
    }

    /// @notice Update the APR
    /// @param _apr New APR (1e18 = 100%)
    function setApr(uint256 _apr) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_apr == 0 || _apr > PRECISION) revert InvalidApr();
        apr = _apr;
        emit AprUpdated(_apr);
    }

    /// @notice Execute a call through the Safe as a module
    function _executeSafe(address to, bytes memory data) internal {
        bool success =
            IGnosisSafe(SAFE).execTransactionFromModule(to, 0, data, IGnosisSafe.Operation.Call);
        if (!success) revert SafeExecutionFailed();
    }
}
