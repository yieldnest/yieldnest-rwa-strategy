// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title StrategyKeeperSablierValidator
/// @notice Validates Sablier stream creation parameters for the strategy keeper
/// @dev Ensures that streams created via the processor meet security requirements:
///      - sender must be the configured safe
///      - recipient must be in the allowed recipients list
///      - token must be the configured token
///      - stream must be cancelable
///      - stream must be transferable
contract StrategyKeeperSablierValidator is IValidator {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown when the function selector doesn't match createWithTimestampsLL
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
    /// @param _token The token address that must be used for streams
    /// @param _allowedRecipients Array of addresses that can receive streams
    constructor(address _safe, address _token, address[] memory _allowedRecipients) {
        if (_safe == address(0)) revert ZeroAddress();
        if (_token == address(0)) revert ZeroAddress();
        if (_allowedRecipients.length == 0) revert EmptyAllowedRecipients();

        safe = _safe;
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

    /// @notice Validates a Sablier createWithTimestampsLL call
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
        if (selector != ISablierLockupLinear.createWithTimestampsLL.selector) {
            revert InvalidFunctionSelector(selector);
        }

        // Decode the CreateWithTimestamps struct from calldata
        // The struct is ABI-encoded as follows:
        // - sender (address, 32 bytes)
        // - recipient (address, 32 bytes)
        // - depositAmount (uint128, 32 bytes)
        // - token (address, 32 bytes)
        // - cancelable (bool, 32 bytes)
        // - transferable (bool, 32 bytes)
        // - timestamps.start (uint40, packed with timestamps.end)
        // - timestamps.end (uint40)
        // - shape (string, dynamic - offset pointer followed by length and data)
        //
        // Note: For structs passed as calldata, the encoding is different from memory encoding
        // The params struct is passed as a pointer to the actual data location

        // Skip the 4-byte selector
        bytes calldata params = data[4:];

        // Decode the parameters
        // The first param (CreateWithTimestamps) is a struct, which is encoded as a tuple
        // followed by UnlockAmounts struct and uint40 cliffTime
        (
            ISablierLockupLinear.CreateWithTimestamps memory createParams,
            , // UnlockAmounts - not validated
                // cliffTime - not validated
        ) = abi.decode(params, (ISablierLockupLinear.CreateWithTimestamps, ISablierLockupLinear.UnlockAmounts, uint40));

        // Validate sender is the safe
        if (createParams.sender != safe) {
            revert InvalidSender(createParams.sender, safe);
        }

        // Validate recipient is in the allowed list
        if (!isAllowedRecipient[createParams.recipient]) {
            revert InvalidRecipient(createParams.recipient);
        }

        // Validate token is the configured token
        if (address(createParams.token) != token) {
            revert InvalidToken(address(createParams.token), token);
        }

        // Validate stream is cancelable
        if (!createParams.cancelable) {
            revert StreamMustBeCancelable();
        }

        // Validate stream is transferable
        if (!createParams.transferable) {
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
