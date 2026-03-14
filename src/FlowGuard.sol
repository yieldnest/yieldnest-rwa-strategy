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
///         - `increaseRate`: deposit + increase the rate (never decrease)
///         - Rate increases are bounded by a max delta and max absolute rate
///         - Pause, decrease, refund, and void are blocked for OPERATOR_ROLE callers
///         - ADMIN_ROLE can pause the stream in emergencies
contract FlowGuard is AccessControlEnumerable {
    /// @notice Role that can call increaseRate (e.g. the FlowStrategyKeeper)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

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

    /// @notice Duration over which each deposit's rate is spread (e.g., 28 days)
    uint256 public holdingPeriod;

    /// @notice Maximum rate increase (UD21x18) allowed per call. 0 = no limit.
    uint128 public maxRateDelta;

    /// @notice Maximum absolute rate (UD21x18) the stream can reach. 0 = no limit.
    uint128 public maxRate;

    error SafeExecutionFailed();
    error RateDeltaExceedsMax(uint128 delta, uint128 max);
    error RateExceedsMax(uint128 newRate, uint128 max);
    error ZeroDeposit();
    error ZeroRateDelta();
    error StreamIsPaused();

    event RateIncreased(uint128 previousRate, uint128 newRate, uint128 depositAmount);
    event LimitsUpdated(uint128 maxRateDelta, uint128 maxRate);
    event StreamPaused();

    error InvalidHoldingPeriod();

    event HoldingPeriodUpdated(uint256 holdingPeriod);

    /// @param _admin Admin address (DEFAULT_ADMIN_ROLE)
    /// @param _safe Gnosis Safe that is the stream sender
    /// @param _flow Sablier Flow contract address
    /// @param _streamId Pre-existing stream ID owned by the Safe
    /// @param _token The ERC-20 token being streamed
    /// @param _streamRecipient The stream recipient address
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
        uint256 _holdingPeriod,
        uint128 _maxRateDelta,
        uint128 _maxRate
    ) {
        if (_holdingPeriod == 0) revert InvalidHoldingPeriod();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);

        SAFE = _safe;
        FLOW = ISablierFlow(_flow);
        STREAM_ID = _streamId;
        TOKEN = IERC20(_token);
        STREAM_RECIPIENT = _streamRecipient;
        TOKEN_DECIMALS = ISablierFlow(_flow).getTokenDecimals(_streamId);
        holdingPeriod = _holdingPeriod;
        maxRateDelta = _maxRateDelta;
        maxRate = _maxRate;
    }

    /// @notice Deposit tokens into the stream and increase the rate
    /// @dev Caller must have OPERATOR_ROLE. The rate can only go up, never down.
    ///      Rate delta is computed as: depositAmount / HOLDING_PERIOD (scaled to UD21x18).
    /// @param depositAmount Amount of tokens to deposit into the stream
    function increaseRate(uint128 depositAmount) external onlyRole(OPERATOR_ROLE) {
        if (depositAmount == 0) revert ZeroDeposit();


        // BUG: the rateDelta is calculated incorrectly. The rate is calculated assuming the depositAmount is the loan amount
        // therefore the rate is the extrapolation of how much per second should be paid given that there's a certain 
        // amount of interest to be paid for the loan.

        // the deposit amount should then be calculated based on the interest to be paid for holdingPeriod

        // Compute rate delta: UD21x18 rate = (depositAmount * 1e18) / (holdingPeriod * 10^decimals)
        uint128 rateDelta =
            uint128((uint256(depositAmount) * 1e18) / (holdingPeriod * (10 ** TOKEN_DECIMALS)));
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

        emit RateIncreased(currentRate, newRate, depositAmount);
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

    /// @notice Execute a call through the Safe as a module
    function _executeSafe(address to, bytes memory data) internal {
        bool success =
            IGnosisSafe(SAFE).execTransactionFromModule(to, 0, data, IGnosisSafe.Operation.Call);
        if (!success) revert SafeExecutionFailed();
    }
}
