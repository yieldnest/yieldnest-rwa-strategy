// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @title IKeeperCompanion
/// @notice Interface for the KeeperCompanion contract
interface IKeeperCompanion is IERC1271 {
    /// @notice Approve a hash for ERC-1271 signature validation
    /// @param hash The hash to approve
    function approveHash(bytes32 hash) external;

    /// @notice Revoke approval for a hash
    /// @param hash The hash to revoke
    function revokeHash(bytes32 hash) external;

    /// @notice Check if a hash is approved
    /// @param hash The hash to check
    /// @return Whether the hash is approved
    function isHashApproved(bytes32 hash) external view returns (bool);
}

/// @title KeeperCompanion
/// @notice A companion contract that acts as an ERC-1271 signer for Gnosis Safe transactions.
///         This contract is owned by the StrategyKeeper and approves transaction hashes
///         on demand, allowing the StrategyKeeper to execute Safe transactions with
///         two contract signatures (StrategyKeeper + KeeperCompanion).
/// @dev This contract must be added as an owner on the Gnosis Safe.
contract KeeperCompanion is IKeeperCompanion, Ownable {
    /// @notice ERC-1271 magic value returned on successful signature validation
    bytes4 internal constant MAGIC_VALUE = 0x1626ba7e;

    /// @notice ERC-1271 failure value
    bytes4 internal constant INVALID_SIGNATURE = 0xffffffff;

    /// @notice Mapping of approved hashes
    mapping(bytes32 => bool) private _approvedHashes;

    /// @notice Emitted when a hash is approved
    /// @param hash The approved hash
    event HashApproved(bytes32 indexed hash);

    /// @notice Emitted when a hash is revoked
    /// @param hash The revoked hash
    event HashRevoked(bytes32 indexed hash);

    /// @notice Creates a new KeeperCompanion
    /// @param keeper The address of the StrategyKeeper that will own this contract
    constructor(address keeper) Ownable(keeper) {}

    /// @notice Approve a hash for ERC-1271 signature validation
    /// @param hash The hash to approve
    /// @dev Only callable by the owner (StrategyKeeper)
    function approveHash(bytes32 hash) external onlyOwner {
        _approvedHashes[hash] = true;
        emit HashApproved(hash);
    }

    /// @notice Revoke approval for a hash
    /// @param hash The hash to revoke
    /// @dev Only callable by the owner (StrategyKeeper)
    function revokeHash(bytes32 hash) external onlyOwner {
        _approvedHashes[hash] = false;
        emit HashRevoked(hash);
    }

    /// @notice Check if a hash is approved
    /// @param hash The hash to check
    /// @return Whether the hash is approved
    function isHashApproved(bytes32 hash) external view returns (bool) {
        return _approvedHashes[hash];
    }

    /// @notice ERC-1271 signature validation
    /// @param hash The hash to validate
    /// @param signature The signature (unused, validation is based on approved hashes)
    /// @return magicValue MAGIC_VALUE if the hash is approved, INVALID_SIGNATURE otherwise
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external
        view
        override
        returns (bytes4 magicValue)
    {
        // Silence unused variable warning
        signature;

        if (_approvedHashes[hash]) {
            return MAGIC_VALUE;
        }
        return INVALID_SIGNATURE;
    }
}
