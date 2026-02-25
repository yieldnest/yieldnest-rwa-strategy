// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";
import {ISablierBatchLockup} from "src/interfaces/sablier/ISablierBatchLockup.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title StrategyKeeperSablierValidator
/// @notice Validates Sablier stream creation parameters for the strategy keeper
/// @dev Ensures that streams created via the processor meet security requirements:
///      - sender must be the configured safe
///      - recipient must be in the allowed recipients list
///      - token must be the configured token
///      - stream must be cancelable
///      - stream must be transferable
///      Supports both single stream (ISablierLockupLinear) and batch stream (ISablierBatchLockup) creation.
contract StrategyKeeperSablierValidator is IValidator {
    string public constant VERSION = "0.2.0";

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the function selector doesn't match a supported function
    error InvalidFunctionSelector(bytes4 selector);

    /// @notice Thrown when the sender is not the configured safe
    error InvalidSender(address sender, address expectedSafe);

    /// @notice Thrown when the recipient is not in the allowed list
    error InvalidRecipient(address recipient);

    /// @notice Thrown when the token is not the configured token
    error InvalidToken(address token, address expectedToken);

    /// @notice Thrown when the stream is not cancelable
    error StreamMustBeCancelable();

    /// @notice Thrown when the stream is not transferable
    error StreamMustBeTransferable();

    /// @notice Thrown when an address is zero
    error ZeroAddress();

    /// @notice Thrown when the allowed recipients array is empty
    error EmptyAllowedRecipients();

    /// @notice Thrown when the lockup address doesn't match the configured lockup
    error InvalidLockupAddress(address lockup, address expectedLockup);

    /// @notice Thrown when the batch array is empty
    error EmptyBatch();

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when the validator is configured
    event ValidatorConfigured(address indexed safe, address indexed token, address[] allowedRecipients);

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice The safe address that must be the sender of the stream
    address public immutable safe;

    /// @notice The Sablier LockupLinear contract address (validated in batch calls)
    address public immutable lockup;

    /// @notice The token that must be used for the stream
    address public immutable token;

    /// @notice Mapping of allowed recipients
    mapping(address => bool) public isAllowedRecipient;

    /// @notice Array of allowed recipients (for enumeration)
    address[] public allowedRecipients;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// @notice Creates a new StrategyKeeperSablierValidator
    /// @param _safe The safe address that must be the sender of streams
    /// @param _lockup The Sablier LockupLinear contract address
    /// @param _token The token address that must be used for streams
    /// @param _allowedRecipients Array of addresses that can receive streams
    constructor(address _safe, address _lockup, address _token, address[] memory _allowedRecipients) {
        if (_safe == address(0)) revert ZeroAddress();
        if (_lockup == address(0)) revert ZeroAddress();
        if (_token == address(0)) revert ZeroAddress();
        if (_allowedRecipients.length == 0) revert EmptyAllowedRecipients();

        safe = _safe;
        lockup = _lockup;
        token = _token;

        for (uint256 i = 0; i < _allowedRecipients.length; i++) {
            if (_allowedRecipients[i] == address(0)) revert ZeroAddress();
            isAllowedRecipient[_allowedRecipients[i]] = true;
            allowedRecipients.push(_allowedRecipients[i]);
        }

        emit ValidatorConfigured(_safe, _token, _allowedRecipients);
    }

    /*//////////////////////////////////////////////////////////////
                            EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a Sablier stream creation call (single or batch)
    /// @param target The Sablier contract address (not validated here, should be validated by the rule)
    /// @param value The ETH value (should be 0 for this call)
    /// @param data The calldata containing the function selector and parameters
    /// @dev Reverts if any validation check fails
    function validate(address target, uint256 value, bytes calldata data) external view override {
        // Suppress unused variable warning
        target;
        value;

        // Check minimum data length (4 bytes selector + params)
        if (data.length < 4) revert InvalidFunctionSelector(bytes4(0));

        // Extract and verify function selector
        bytes4 selector = bytes4(data[:4]);

        if (selector == ISablierLockupLinear.createWithTimestampsLL.selector) {
            _validateSingle(data[4:]);
        } else if (selector == ISablierBatchLockup.createWithTimestampsLL.selector) {
            _validateBatch(data[4:]);
        } else {
            revert InvalidFunctionSelector(selector);
        }
    }

    /*//////////////////////////////////////////////////////////////
                            INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Validates a single createWithTimestampsLL call
    /// @param params The calldata after the selector
    function _validateSingle(bytes calldata params) internal view {
        (ISablierLockupLinear.CreateWithTimestamps memory createParams,,) =
            abi.decode(params, (ISablierLockupLinear.CreateWithTimestamps, ISablierLockupLinear.UnlockAmounts, uint40));

        _validateStreamParams(
            createParams.sender, createParams.recipient, createParams.cancelable, createParams.transferable
        );

        // Validate token is the configured token
        if (address(createParams.token) != token) {
            revert InvalidToken(address(createParams.token), token);
        }
    }

    /// @notice Validates a batch createWithTimestampsLL call
    /// @param params The calldata after the selector
    function _validateBatch(bytes calldata params) internal view {
        (address batchLockup, IERC20 batchToken, ISablierBatchLockup.CreateWithTimestampsLL[] memory batch) =
            abi.decode(params, (address, IERC20, ISablierBatchLockup.CreateWithTimestampsLL[]));

        // Validate lockup address
        if (batchLockup != lockup) {
            revert InvalidLockupAddress(batchLockup, lockup);
        }

        // Validate token
        if (address(batchToken) != token) {
            revert InvalidToken(address(batchToken), token);
        }

        // Validate batch is not empty
        if (batch.length == 0) revert EmptyBatch();

        // Validate each item in the batch
        for (uint256 i = 0; i < batch.length; i++) {
            _validateStreamParams(batch[i].sender, batch[i].recipient, batch[i].cancelable, batch[i].transferable);
        }
    }

    /// @notice Validates common stream parameters
    /// @param sender The stream sender (must be the safe)
    /// @param recipient The stream recipient (must be in allowed list)
    /// @param cancelable Whether the stream is cancelable (must be true)
    /// @param transferable Whether the stream is transferable (must be true)
    function _validateStreamParams(address sender, address recipient, bool cancelable, bool transferable)
        internal
        view
    {
        if (sender != safe) {
            revert InvalidSender(sender, safe);
        }

        if (!isAllowedRecipient[recipient]) {
            revert InvalidRecipient(recipient);
        }

        if (!cancelable) {
            revert StreamMustBeCancelable();
        }

        if (!transferable) {
            revert StreamMustBeTransferable();
        }
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Returns the number of allowed recipients
    /// @return The count of allowed recipients
    function getAllowedRecipientsCount() external view returns (uint256) {
        return allowedRecipients.length;
    }

    /// @notice Returns all allowed recipients
    /// @return Array of allowed recipient addresses
    function getAllowedRecipients() external view returns (address[] memory) {
        return allowedRecipients;
    }
}
