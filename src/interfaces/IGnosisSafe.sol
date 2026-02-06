// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

/// @title IGnosisSafe
/// @notice Interface for Gnosis Safe transaction execution and signature validation
interface IGnosisSafe {
    enum Operation {
        Call,
        DelegateCall
    }

    /// @notice Execute a transaction from the Safe
    /// @param to Destination address
    /// @param value Ether value
    /// @param data Data payload
    /// @param operation Operation type (Call or DelegateCall)
    /// @param safeTxGas Gas for the safe transaction
    /// @param baseGas Gas for data and base transaction
    /// @param gasPrice Gas price for refund calculation
    /// @param gasToken Token address for gas payment (0 for ETH)
    /// @param refundReceiver Address to receive gas refund
    /// @param signatures Packed signature data
    /// @return success Whether the transaction succeeded
    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success);

    /// @notice Get the transaction hash for a Safe transaction
    /// @param to Destination address
    /// @param value Ether value
    /// @param data Data payload
    /// @param operation Operation type
    /// @param safeTxGas Gas for the safe transaction
    /// @param baseGas Gas for data and base transaction
    /// @param gasPrice Gas price for refund calculation
    /// @param gasToken Token address for gas payment
    /// @param refundReceiver Address to receive gas refund
    /// @param _nonce Transaction nonce
    /// @return Transaction hash
    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    /// @notice Get the current nonce of the Safe
    /// @return Current nonce
    function nonce() external view returns (uint256);

    /// @notice Get the threshold of required signatures
    /// @return Threshold number
    function getThreshold() external view returns (uint256);

    /// @notice Check if an address is an owner of the Safe
    /// @param owner Address to check
    /// @return Whether the address is an owner
    function isOwner(address owner) external view returns (bool);

    /// @notice Get the list of Safe owners
    /// @return Array of owner addresses
    function getOwners() external view returns (address[] memory);

    /// @notice Approve a hash on-chain (alternative to off-chain signatures)
    /// @param hashToApprove Hash to approve
    function approveHash(bytes32 hashToApprove) external;

    /// @notice Check if a hash has been approved by an owner
    /// @param owner Owner address
    /// @param hash Hash to check
    /// @return 1 if approved, 0 otherwise
    function approvedHashes(address owner, bytes32 hash) external view returns (uint256);

    /// @notice Execute a transaction as a module
    /// @dev Modules are allowed to execute transactions without signatures
    /// @param to Destination address
    /// @param value Ether value
    /// @param data Data payload
    /// @param operation Operation type (Call or DelegateCall)
    /// @return success Whether the transaction succeeded
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, Operation operation)
        external
        returns (bool success);

    /// @notice Execute a transaction as a module and return data
    /// @dev Modules are allowed to execute transactions without signatures
    /// @param to Destination address
    /// @param value Ether value
    /// @param data Data payload
    /// @param operation Operation type (Call or DelegateCall)
    /// @return success Whether the transaction succeeded
    /// @return returnData Data returned from the call
    function execTransactionFromModuleReturnData(address to, uint256 value, bytes calldata data, Operation operation)
        external
        returns (bool success, bytes memory returnData);

    /// @notice Check if an address is an enabled module
    /// @param module Module address
    /// @return Whether the address is an enabled module
    function isModuleEnabled(address module) external view returns (bool);

    /// @notice Enable a module for this Safe
    /// @param module Module to enable
    function enableModule(address module) external;
}
