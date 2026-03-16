// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {AccessControlEnumerableUpgradeable} from
    "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlEnumerableUpgradeable.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";
import {FlowMath} from "src/FlowMath.sol";

/// @title FlowHandler
/// @notice Upgradeable Safe module that wraps Sablier Flow stream operations with guard rails.
///         The Safe remains the stream sender; this module controls what callers can do:
///         - `increaseRate`: given a loanAmount, computes interest, deposits it, and increases the rate
///         - Rate increases are bounded by a max delta and max absolute rate
///         - Pause, decrease, refund, and void are blocked for OPERATOR_ROLE callers
///         - ADMIN_ROLE can pause the stream in emergencies
/// @dev Deployed behind a TransparentUpgradeableProxy.
contract FlowHandler is AccessControlEnumerableUpgradeable {
    /// @notice Role that can call increaseRate (e.g. the FlowStrategyKeeper)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Gnosis Safe that owns the stream
    address public safe;

    /// @notice Sablier Flow contract
    address public flow;

    /// @notice The stream ID this guard controls
    uint256 public streamId;

    /// @notice The token being streamed
    address public token;

    /// @notice The stream recipient
    address public streamRecipient;

    /// @notice Token decimals, read from Sablier Flow at initialization
    uint8 public tokenDecimals;

    /// @notice APR for interest calculation (1e18 = 100%)
    uint256 public apr;

    /// @notice Duration over which each deposit's rate is spread (e.g., 28 days)
    uint256 public holdingPeriod;

    /// @notice Maximum rate increase (UD21x18) allowed per call. 0 = no limit.
    uint128 public maxRateDelta;

    /// @notice Maximum absolute rate (UD21x18) the stream can reach. 0 = no limit.
    uint128 public maxRate;

    error SafeExecutionFailed();
    error InvalidHoldingPeriod();
    error InvalidApr();

    event RateIncreased(uint128 previousRate, uint128 newRate, uint128 depositAmount, uint256 loanAmount);
    event LimitsUpdated(uint128 maxRateDelta, uint128 maxRate);
    event StreamPaused();
    event HoldingPeriodUpdated(uint256 holdingPeriod);
    event AprUpdated(uint256 apr);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialization parameters for the FlowHandler
    struct InitParams {
        address admin; // Admin address (DEFAULT_ADMIN_ROLE)
        address safe; // Gnosis Safe that is the stream sender
        address flow; // Sablier Flow contract address
        uint256 streamId; // Pre-existing stream ID owned by the Safe
        address token; // The ERC-20 token being streamed
        address streamRecipient; // The stream recipient address
        uint256 apr; // APR for interest calculation (1e18 = 100%)
        uint256 holdingPeriod; // Duration in seconds over which each deposit's rate is spread
        uint128 maxRateDelta; // Maximum rate delta per call (0 = unlimited)
        uint128 maxRate; // Maximum absolute rate (0 = unlimited)
    }

    /// @notice Initialize the FlowHandler
    /// @param params Initialization parameters
    function initialize(InitParams calldata params) external initializer {
        if (params.apr == 0 || params.apr > FlowMath.PRECISION) revert InvalidApr();
        if (params.holdingPeriod == 0) revert InvalidHoldingPeriod();

        __AccessControlEnumerable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, params.admin);

        safe = params.safe;
        flow = params.flow;
        streamId = params.streamId;
        token = params.token;
        streamRecipient = params.streamRecipient;
        tokenDecimals = ISablierFlow(params.flow).getTokenDecimals(params.streamId);
        apr = params.apr;
        holdingPeriod = params.holdingPeriod;
        maxRateDelta = params.maxRateDelta;
        maxRate = params.maxRate;
    }

    /// @notice Compute the interest for a given loan amount
    /// @param loanAmount The total loan amount
    /// @return interest The interest amount (without fees)
    function computeInterest(uint256 loanAmount) public view returns (uint256) {
        return FlowMath.computeInterest(loanAmount, apr, holdingPeriod);
    }

    /// @notice Given a loanAmount, compute interest, deposit it into the stream, and increase the rate
    /// @dev Caller must have OPERATOR_ROLE. The rate can only go up, never down.
    /// @param loanAmount The total loan amount from which interest is derived
    /// @return depositAmount The interest amount deposited into the stream
    /// @return newRate The new rate per second after the increase
    function increaseRate(uint256 loanAmount)
        external
        onlyRole(OPERATOR_ROLE)
        returns (uint128 depositAmount, uint128 newRate)
    {
        uint128 currentRate = uint128(UD21x18.unwrap(ISablierFlow(flow).getRatePerSecond(streamId)));

        uint128 rateDelta;
        (depositAmount, rateDelta, newRate) = FlowMath.calculateRateIncrease(
            loanAmount, currentRate, apr, holdingPeriod, tokenDecimals, maxRateDelta, maxRate
        );

        // Approve Sablier Flow to spend token from Safe
        _executeSafe(token, abi.encodeCall(IERC20.approve, (flow, depositAmount)));

        // Deposit first, then adjust rate
        _executeSafe(
            flow,
            abi.encodeCall(ISablierFlow.deposit, (streamId, depositAmount, safe, streamRecipient))
        );
        _executeSafe(
            flow, abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(newRate)))
        );

        emit RateIncreased(currentRate, newRate, depositAmount, loanAmount);
    }

    /// @notice Pause the stream in an emergency
    /// @dev Only callable by DEFAULT_ADMIN_ROLE
    function pause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _executeSafe(flow, abi.encodeCall(ISablierFlow.pause, (streamId)));
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
        if (_apr == 0 || _apr > FlowMath.PRECISION) revert InvalidApr();
        apr = _apr;
        emit AprUpdated(_apr);
    }

    /// @notice Execute a call through the Safe as a module
    function _executeSafe(address to, bytes memory data) internal {
        bool success =
            IGnosisSafe(safe).execTransactionFromModule(to, 0, data, IGnosisSafe.Operation.Call);
        if (!success) revert SafeExecutionFailed();
    }
}
