// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";

/// @notice Minimal interface for the deployed YieldNest SafeGuard used in integration tests.
/// @dev Derived from https://github.com/yieldnest/safeguard/blob/main/src/SafeGuard.sol
interface ISafeGuard {
    function name() external view returns (string memory);
    function checkTransactionEnabled() external view returns (bool);
    function checkModuleTransactionEnabled() external view returns (bool);
    function PROCESSOR_MANAGER_ROLE() external view returns (bytes32);
    function GUARD_ADMIN_ROLE() external view returns (bytes32);
    function hasRole(bytes32 role, address account) external view returns (bool);

    function setProcessorRules(
        address[] calldata target,
        bytes4[] calldata functionSig,
        IVault.FunctionRule[] calldata rule
    ) external;

    function getProcessorRule(address contractAddress, bytes4 funcSig)
        external
        view
        returns (IVault.FunctionRule memory);

    function validateCall(address target, uint256 value, bytes calldata data) external view;

    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address executor
    ) external view;
}
