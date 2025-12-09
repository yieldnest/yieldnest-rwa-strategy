// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.8.22;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title ISablierLockupLinear
/// @notice Creates Lockup streams with linear distribution model.
interface ISablierLockupLinear {
    /// @notice Struct encapsulating the Lockup timestamps.
    /// @param start The Unix timestamp for the stream's start.
    /// @param end The Unix timestamp for the stream's end.
    struct Timestamps {
        uint40 start;
        uint40 end;
    }

    /// @notice Struct encapsulating the parameters of the `createWithDurations` functions.
    /// @param sender The address distributing the tokens, with the ability to cancel the stream. It doesn't have to be
    /// the same as `msg.sender`.
    /// @param recipient The address receiving the tokens, as well as the NFT owner.
    /// @param depositAmount The deposit amount, denoted in units of the token's decimals.
    /// @param token The contract address of the ERC-20 token to be distributed.
    /// @param cancelable Indicates if the stream is cancelable.
    /// @param transferable Indicates if the stream NFT is transferable.
    /// @param shape An optional parameter to specify the shape of the distribution function. This helps differentiate
    /// streams in the UI.
    struct CreateWithDurations {
        address sender;
        address recipient;
        uint128 depositAmount;
        IERC20 token;
        bool cancelable;
        bool transferable;
        string shape;
    }

    /// @notice Struct encapsulating the parameters of the `createWithTimestamps` functions.
    /// @param sender The address distributing the tokens, with the ability to cancel the stream. It doesn't have to be
    /// the same as `msg.sender`.
    /// @param recipient The address receiving the tokens, as well as the NFT owner.
    /// @param depositAmount The deposit amount, denoted in units of the token's decimals.
    /// @param token The contract address of the ERC-20 token to be distributed.
    /// @param cancelable Indicates if the stream is cancelable.
    /// @param transferable Indicates if the stream NFT is transferable.
    /// @param timestamps Struct encapsulating (i) the stream's start time and (ii) end time, both as Unix timestamps.
    /// @param shape An optional parameter to specify the shape of the distribution function. This helps differentiate
    /// streams in the UI.
    struct CreateWithTimestamps {
        address sender;
        address recipient;
        uint128 depositAmount;
        IERC20 token;
        bool cancelable;
        bool transferable;
        Timestamps timestamps;
        string shape;
    }

    /// @notice Struct encapsulating the unlock amounts for the stream.
    /// @dev The sum of `start` and `cliff` must be less than or equal to deposit amount. Both amounts can be zero.
    /// @param start The amount to be unlocked at the start time.
    /// @param cliff The amount to be unlocked at the cliff time.
    struct UnlockAmounts {
        // slot 0
        uint128 start;
        uint128 cliff;
    }

    /// @notice Struct encapsulating the cliff duration and the total duration used at runtime in
    /// {SablierLockupLinear.createWithDurationsLL} function.
    /// @param cliff The cliff duration in seconds.
    /// @param total The total duration in seconds.
    struct Durations {
        uint40 cliff;
        uint40 total;
    }

    /*//////////////////////////////////////////////////////////////////////////
                        USER-FACING STATE-CHANGING FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Creates a stream by setting the start time to `block.timestamp`, and the end time to
    /// the sum of `block.timestamp` and `durations.total`. The stream is funded by `msg.sender` and is wrapped in an
    /// ERC-721 NFT.
    ///
    /// @dev Emits a {Transfer}, {CreateLockupLinearStream} and {MetadataUpdate} event.
    ///
    /// Requirements:
    /// - All requirements in {createWithTimestampsLL} must be met for the calculated parameters.
    ///
    /// @param params Struct encapsulating the function parameters, which are documented in {Lockup} type.
    /// @param durations Struct encapsulating (i) cliff period duration and (ii) total stream duration, both in seconds.
    /// @param unlockAmounts Struct encapsulating (i) the amount to unlock at the start time and (ii) the amount to
    /// unlock at the cliff time.
    /// @return streamId The ID of the newly created stream.
    function createWithDurationsLL(
        CreateWithDurations calldata params,
        UnlockAmounts calldata unlockAmounts,
        Durations calldata durations
    ) external payable returns (uint256 streamId);

    /// @notice Creates a stream with the provided start time and end time. The stream is funded by `msg.sender` and is
    /// wrapped in an ERC-721 NFT.
    ///
    /// @dev Emits a {Transfer}, {CreateLockupLinearStream} and {MetadataUpdate} event.
    ///
    /// Notes:
    /// - A cliff time of zero means there is no cliff.
    /// - As long as the times are ordered, it is not an error for the start or the cliff time to be in the past.
    ///
    /// Requirements:
    /// - Must not be delegate called.
    /// - `params.depositAmount` must be greater than zero.
    /// - `params.timestamps.start` must be greater than zero and less than `params.timestamps.end`.
    /// - If set, `cliffTime` must be greater than `params.timestamps.start` and less than
    /// `params.timestamps.end`.
    /// - `params.recipient` must not be the zero address.
    /// - `params.sender` must not be the zero address.
    /// - The sum of `params.unlockAmounts.start` and `params.unlockAmounts.cliff` must be less than or equal to
    /// deposit amount.
    /// - If `params.timestamps.cliff` not set, the `params.unlockAmounts.cliff` must be zero.
    /// - `msg.sender` must have allowed this contract to spend at least `params.depositAmount` tokens.
    /// - `params.token` must not be the native token.
    /// - `params.shape.length` must not be greater than 32 characters.
    ///
    /// @param params Struct encapsulating the function parameters, which are documented in {Lockup} type.
    /// @param cliffTime The Unix timestamp for the cliff period's end. A value of zero means there is no cliff.
    /// @param unlockAmounts Struct encapsulating (i) the amount to unlock at the start time and (ii) the amount to
    /// unlock at the cliff time.
    /// @return streamId The ID of the newly created stream.
    function createWithTimestampsLL(
        CreateWithTimestamps calldata params,
        UnlockAmounts calldata unlockAmounts,
        uint40 cliffTime
    ) external payable returns (uint256 streamId);
}
