// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Initializable} from "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol";
import {
    AccessControlEnumerableUpgradeable
} from "lib/openzeppelin-contracts-upgradeable/contracts/access/extensions/AccessControlEnumerableUpgradeable.sol";

import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";

/// @title BaseSafeModule
/// @notice Shared Safe module base with ERC-7201 storage and optional pre-execution validation.
abstract contract BaseSafeModule is Initializable, AccessControlEnumerableUpgradeable {
    /// @notice ERC-7201 storage container for shared Safe module configuration.
    /// @custom:storage-location erc7201:yieldnest.storage.base_safe_module
    struct BaseSafeModuleStorage {
        /// @notice Safe that executes module calls.
        address safe;
        /// @notice Optional validator invoked before each Safe module transaction.
        address validator;
    }

    error SafeExecutionFailed();

    event ValidatorUpdated(address validator);

    /// @notice Initialize the base Safe module storage.
    /// @param safe_ Safe that will execute module transactions.
    /// @param validator_ Optional validator called before Safe execution.
    function __BaseSafeModule_init(address safe_, address validator_) internal onlyInitializing {
        BaseSafeModuleStorage storage $ = _getBaseSafeModuleStorage();
        $.safe = safe_;
        $.validator = validator_;
    }

    /// @notice Update the optional pre-execution validator.
    /// @dev Setting the validator to the zero address disables validation.
    /// @param validator_ New validator address.
    function setValidator(address validator_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _getBaseSafeModuleStorage().validator = validator_;
        emit ValidatorUpdated(validator_);
    }

    /// @notice Return the Safe that executes module transactions.
    function safe() public view returns (address) {
        return _getBaseSafeModuleStorage().safe;
    }

    /// @notice Return the optional validator invoked before Safe execution.
    function validator() public view returns (address) {
        return _getBaseSafeModuleStorage().validator;
    }

    /// @notice Execute a call through the configured Safe as a module transaction.
    /// @dev If a validator is configured, it must accept the call before execution proceeds.
    /// @param to Destination address for the Safe module transaction.
    /// @param data Calldata for the Safe module transaction.
    function _executeSafe(address to, bytes memory data) internal {
        BaseSafeModuleStorage storage $ = _getBaseSafeModuleStorage();
        address validator_ = $.validator;
        if (validator_ != address(0)) {
            IValidator(validator_).validate(to, 0, data);
        }

        bool success = IGnosisSafe($.safe).execTransactionFromModule(to, 0, data, IGnosisSafe.Operation.Call);
        if (!success) revert SafeExecutionFailed();
    }

    /// @notice Return the storage pointer for the shared Safe module namespace.
    function _getBaseSafeModuleStorage() internal pure returns (BaseSafeModuleStorage storage $) {
        assembly {
            $.slot := 0x7d86c2f2eb2cb4c0d5f54168f6e699c3b5eaf3d0b60cf66d968ee01a2d332f90
        }
    }
}
