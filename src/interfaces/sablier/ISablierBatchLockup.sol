// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.8.22;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISablierLockupLinear} from "./ISablierLockupLinear.sol";

/// @title ISablierBatchLockup
/// @notice Helper to batch create Lockup streams.
interface ISablierBatchLockup {
    /// @notice A struct encapsulating all parameters of {SablierLockupLinear.createWithTimestampsLL} except for the
    /// token.
    struct CreateWithTimestampsLL {
        address sender;
        address recipient;
        uint128 depositAmount;
        bool cancelable;
        bool transferable;
        ISablierLockupLinear.Timestamps timestamps;
        uint40 cliffTime;
        ISablierLockupLinear.UnlockAmounts unlockAmounts;
        string shape;
    }

    /// @notice Creates a batch of LL streams using `createWithTimestampsLL`.
    ///
    /// @dev Requirements:
    /// - There must be at least one element in `batch`.
    /// - All requirements from {ISablierLockupLinear.createWithTimestampsLL} must be met for each stream.
    ///
    /// @param lockup The address of the {SablierLockup} contract.
    /// @param token The contract address of the ERC-20 token to be distributed.
    /// @param batch An array of structs, each encapsulating a subset of the parameters of
    /// {ISablierLockupLinear.createWithTimestampsLL}.
    /// @return streamIds The ids of the newly created streams.
    function createWithTimestampsLL(address lockup, IERC20 token, CreateWithTimestampsLL[] calldata batch)
        external
        returns (uint256[] memory streamIds);
}
