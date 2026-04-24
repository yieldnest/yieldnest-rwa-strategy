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
///         - Stream pause/void/refund are handled directly by the multisig
/// @dev Deployed behind a TransparentUpgradeableProxy.
contract FlowHandler is AccessControlEnumerableUpgradeable {
    /// @notice Role that can call disburse / decreaseRate (e.g. the FlowStrategyKeeper)
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    /// @notice Role that can update configuration (APR, holding period, limits, borrower, feeWallet, feeFraction)
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    /// @custom:storage-location erc7201:yieldnest.storage.flow_handler
    struct FlowHandlerStorage {
        address safe;
        address flow;
        uint256 streamId;
        address token;
        address streamRecipient;
        uint8 tokenDecimals;
        uint256 apr;
        uint256 holdingPeriod;
        uint128 maxRateDelta;
        uint128 maxRate;
        address borrower;
        address feeWallet;
        uint256 feeFraction;
    }

    error SafeExecutionFailed();
    error InvalidHoldingPeriod();
    error InvalidApr();
    error InvalidFeeFraction();
    error ZeroAddress();

    event RateDecreased(uint128 previousRate, uint128 newRate, uint128 interest, uint256 loanAmount);
    event Disbursed(uint256 loanAmount, uint128 interest, uint128 newRate, uint256 principal, uint256 fee);
    event LimitsUpdated(uint128 maxRateDelta, uint128 maxRate);
    event HoldingPeriodUpdated(uint256 holdingPeriod);
    event AprUpdated(uint256 apr);
    event BorrowerUpdated(address borrower);
    event FeeWalletUpdated(address feeWallet);
    event FeeFractionUpdated(uint256 feeFraction);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Result of a disburse operation
    struct DisburseResult {
        uint128 interest; // Interest deposited into the stream
        uint128 newRate; // New stream rate per second after the increase
        uint256 principal; // Amount transferred to borrower
        uint256 fee; // Amount transferred to feeWallet
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
        address borrower; // Address to receive principal
        address feeWallet; // Address to receive fee
        uint256 feeFraction; // Fee denominator (>= 2)
    }

    /// @notice Initialize the FlowHandler
    /// @param params Initialization parameters
    function initialize(InitParams calldata params) external initializer {
        if (params.apr == 0 || params.apr > FlowMath.PRECISION) revert InvalidApr();
        if (params.holdingPeriod == 0) revert InvalidHoldingPeriod();
        if (params.borrower == address(0)) revert ZeroAddress();
        if (params.feeWallet == address(0)) revert ZeroAddress();
        if (params.feeFraction < 2) revert InvalidFeeFraction();

        __AccessControlEnumerable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, params.admin);

        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        $.safe = params.safe;
        $.flow = params.flow;
        $.streamId = params.streamId;
        $.token = params.token;
        $.streamRecipient = params.streamRecipient;
        $.tokenDecimals = ISablierFlow(params.flow).getTokenDecimals(params.streamId);
        $.apr = params.apr;
        $.holdingPeriod = params.holdingPeriod;
        $.maxRateDelta = params.maxRateDelta;
        $.maxRate = params.maxRate;
        $.borrower = params.borrower;
        $.feeWallet = params.feeWallet;
        $.feeFraction = params.feeFraction;
    }

    /// @notice Compute the interest for a given loan amount
    /// @param loanAmount The total loan amount
    /// @return interest The interest amount (without fees)
    function computeInterest(uint256 loanAmount) public view returns (uint256) {
        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        return FlowMath.computeInterest(loanAmount, $.apr, $.holdingPeriod);
    }

    /// @notice Disburse a loan amount: deposit interest into the stream, adjust rate up,
    ///         transfer principal to borrower, and transfer fee to feeWallet.
    /// @dev Caller must have OPERATOR_ROLE. Performs up to 5 Safe transactions.
    /// @param loanAmount The total available amount to disburse
    /// @return result The disbursement result
    function disburse(uint256 loanAmount) external onlyRole(OPERATOR_ROLE) returns (DisburseResult memory result) {
        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        uint128 currentRate;
        (currentRate, result.interest, result.newRate) = _increaseStreamRate(loanAmount);

        result.fee = uint256(result.interest) / $.feeFraction;
        result.principal = loanAmount - uint256(result.interest) - result.fee;

        // Transfer principal to borrower
        _executeSafe($.token, abi.encodeCall(IERC20.transfer, ($.borrower, result.principal)));

        // Transfer fee to feeWallet (skip if zero)
        if (result.fee > 0) {
            _executeSafe($.token, abi.encodeCall(IERC20.transfer, ($.feeWallet, result.fee)));
        }

        emit Disbursed(loanAmount, result.interest, result.newRate, result.principal, result.fee);
    }

    /// @notice Given a repaid loanAmount, compute the rate reduction and adjust the stream down
    /// @dev Caller must have OPERATOR_ROLE. Only adjusts the rate — does not refund deposited funds.
    /// @param loanAmount The repaid loan amount from which the rate reduction is derived
    /// @return interest The interest amount corresponding to the repaid loan
    /// @return newRate The new rate per second after the decrease
    function decreaseRate(uint256 loanAmount)
        external
        onlyRole(OPERATOR_ROLE)
        returns (uint128 interest, uint128 newRate)
    {
        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        uint128 currentRate = uint128(UD21x18.unwrap(ISablierFlow($.flow).getRatePerSecond($.streamId)));

        uint128 rateDelta;
        (interest, rateDelta, newRate) = FlowMath.calculateRateDecrease(
            loanAmount, currentRate, $.apr, $.holdingPeriod, $.tokenDecimals, $.maxRateDelta
        );

        _executeSafe($.flow, abi.encodeCall(ISablierFlow.adjustRatePerSecond, ($.streamId, UD21x18.wrap(newRate))));

        emit RateDecreased(currentRate, newRate, interest, loanAmount);
    }

    /// @notice Update rate limits
    /// @param _maxRateDelta New max rate delta per call (0 = unlimited)
    /// @param _maxRate New max absolute rate (0 = unlimited)
    function setLimits(uint128 _maxRateDelta, uint128 _maxRate) external onlyRole(MANAGER_ROLE) {
        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        $.maxRateDelta = _maxRateDelta;
        $.maxRate = _maxRate;
        emit LimitsUpdated(_maxRateDelta, _maxRate);
    }

    /// @notice Update the holding period
    /// @param _holdingPeriod New duration in seconds
    function setHoldingPeriod(uint256 _holdingPeriod) external onlyRole(MANAGER_ROLE) {
        if (_holdingPeriod == 0 || _holdingPeriod > 365 days) revert InvalidHoldingPeriod();
        _getFlowHandlerStorage().holdingPeriod = _holdingPeriod;
        emit HoldingPeriodUpdated(_holdingPeriod);
    }

    /// @notice Update the APR
    /// @param _apr New APR (1e18 = 100%)
    function setApr(uint256 _apr) external onlyRole(MANAGER_ROLE) {
        if (_apr == 0 || _apr > FlowMath.PRECISION) revert InvalidApr();
        _getFlowHandlerStorage().apr = _apr;
        emit AprUpdated(_apr);
    }

    /// @notice Update the borrower address
    /// @param _borrower New borrower address
    function setBorrower(address _borrower) external onlyRole(MANAGER_ROLE) {
        if (_borrower == address(0)) revert ZeroAddress();
        _getFlowHandlerStorage().borrower = _borrower;
        emit BorrowerUpdated(_borrower);
    }

    /// @notice Update the fee wallet address
    /// @param _feeWallet New fee wallet address
    function setFeeWallet(address _feeWallet) external onlyRole(MANAGER_ROLE) {
        if (_feeWallet == address(0)) revert ZeroAddress();
        _getFlowHandlerStorage().feeWallet = _feeWallet;
        emit FeeWalletUpdated(_feeWallet);
    }

    /// @notice Update the fee fraction
    /// @param _feeFraction New fee denominator (>= 2)
    function setFeeFraction(uint256 _feeFraction) external onlyRole(MANAGER_ROLE) {
        if (_feeFraction < 2) revert InvalidFeeFraction();
        _getFlowHandlerStorage().feeFraction = _feeFraction;
        emit FeeFractionUpdated(_feeFraction);
    }

    /// @notice Internal: read current rate, compute increase, execute 3 Safe txs (approve, deposit, adjustRate)
    function _increaseStreamRate(uint256 loanAmount)
        internal
        returns (uint128 currentRate, uint128 depositAmount, uint128 newRate)
    {
        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        currentRate = uint128(UD21x18.unwrap(ISablierFlow($.flow).getRatePerSecond($.streamId)));

        uint128 rateDelta;
        (depositAmount, rateDelta, newRate) = FlowMath.calculateRateIncrease(
            loanAmount, currentRate, $.apr, $.holdingPeriod, $.tokenDecimals, $.maxRateDelta, $.maxRate
        );

        _executeSafe($.token, abi.encodeCall(IERC20.approve, ($.flow, depositAmount)));
        _executeSafe(
            $.flow, abi.encodeCall(ISablierFlow.deposit, ($.streamId, depositAmount, $.safe, $.streamRecipient))
        );
        _executeSafe($.flow, abi.encodeCall(ISablierFlow.adjustRatePerSecond, ($.streamId, UD21x18.wrap(newRate))));
    }

    /// @notice Execute a call through the Safe as a module
    function _executeSafe(address to, bytes memory data) internal {
        bool success = IGnosisSafe(_getFlowHandlerStorage().safe).execTransactionFromModule(
            to, 0, data, IGnosisSafe.Operation.Call
        );
        if (!success) revert SafeExecutionFailed();
    }

    /*//////////////////////////////////////////////////////////////
                                GETTERS
    //////////////////////////////////////////////////////////////*/

    function safe() public view returns (address) {
        return _getFlowHandlerStorage().safe;
    }

    function flow() public view returns (address) {
        return _getFlowHandlerStorage().flow;
    }

    function streamId() public view returns (uint256) {
        return _getFlowHandlerStorage().streamId;
    }

    function token() public view returns (address) {
        return _getFlowHandlerStorage().token;
    }

    function streamRecipient() public view returns (address) {
        return _getFlowHandlerStorage().streamRecipient;
    }

    function tokenDecimals() public view returns (uint8) {
        return _getFlowHandlerStorage().tokenDecimals;
    }

    function apr() public view returns (uint256) {
        return _getFlowHandlerStorage().apr;
    }

    function holdingPeriod() public view returns (uint256) {
        return _getFlowHandlerStorage().holdingPeriod;
    }

    function maxRateDelta() public view returns (uint128) {
        return _getFlowHandlerStorage().maxRateDelta;
    }

    function maxRate() public view returns (uint128) {
        return _getFlowHandlerStorage().maxRate;
    }

    function borrower() public view returns (address) {
        return _getFlowHandlerStorage().borrower;
    }

    function feeWallet() public view returns (address) {
        return _getFlowHandlerStorage().feeWallet;
    }

    function feeFraction() public view returns (uint256) {
        return _getFlowHandlerStorage().feeFraction;
    }

    function _getFlowHandlerStorage() internal pure returns (FlowHandlerStorage storage $) {
        assembly {
            $.slot := 0x896881cf334f778fa94c6a17861664c516faa92b454f0a85365fe8bc17a4fc7b
        }
    }
}
