// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity >=0.8.22;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @notice UD21x18 is a fixed-point number type where 1e18 represents 1.0 tokens per second.
type UD21x18 is uint128;

/// @title ISablierFlow
/// @notice Interface for the Sablier Flow streaming protocol.
/// @dev Flow streams allow continuous token streaming at a configurable rate per second.
///      Unlike Lockup streams, Flow streams have no fixed end time - they stream until
///      the deposited balance is depleted or the stream is paused/voided.
interface ISablierFlow {
    /*//////////////////////////////////////////////////////////////////////////
                            STATE-CHANGING FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Creates a new Flow stream.
    /// @param sender The address that controls the stream (can adjust rate, pause, refund).
    /// @param recipient The address receiving the streamed tokens.
    /// @param ratePerSecond The initial rate per second in UD21x18 format.
    /// @param startTime The Unix timestamp when the stream starts.
    /// @param token The ERC-20 token to stream.
    /// @param transferable Whether the stream NFT is transferable.
    /// @return streamId The ID of the newly created stream.
    function create(
        address sender,
        address recipient,
        UD21x18 ratePerSecond,
        uint40 startTime,
        IERC20 token,
        bool transferable
    ) external returns (uint256 streamId);

    /// @notice Creates a new Flow stream and deposits tokens into it.
    /// @param sender The address that controls the stream.
    /// @param recipient The address receiving the streamed tokens.
    /// @param ratePerSecond The initial rate per second in UD21x18 format.
    /// @param startTime The Unix timestamp when the stream starts.
    /// @param token The ERC-20 token to stream.
    /// @param transferable Whether the stream NFT is transferable.
    /// @param amount The amount of tokens to deposit.
    /// @return streamId The ID of the newly created stream.
    function createAndDeposit(
        address sender,
        address recipient,
        UD21x18 ratePerSecond,
        uint40 startTime,
        IERC20 token,
        bool transferable,
        uint128 amount
    ) external returns (uint256 streamId);

    /// @notice Adjusts the rate per second of an active (non-paused) stream.
    /// @dev Only callable by the stream's sender. Reverts if the stream is paused.
    /// @param streamId The ID of the stream.
    /// @param newRatePerSecond The new rate per second in UD21x18 format.
    function adjustRatePerSecond(uint256 streamId, UD21x18 newRatePerSecond) external payable;

    /// @notice Deposits tokens into an existing stream.
    /// @dev The caller (msg.sender) must have approved this contract to spend the tokens.
    /// @param streamId The ID of the stream.
    /// @param amount The amount of tokens to deposit.
    /// @param sender The stream's sender address (for validation).
    /// @param recipient The stream's recipient address (for validation).
    function deposit(uint256 streamId, uint128 amount, address sender, address recipient) external payable;

    /// @notice Deposits tokens and pauses the stream.
    /// @param streamId The ID of the stream.
    /// @param amount The amount of tokens to deposit.
    function depositAndPause(uint256 streamId, uint128 amount) external payable;

    /// @notice Pauses an active stream (sets rate to 0).
    /// @param streamId The ID of the stream.
    function pause(uint256 streamId) external payable;

    /// @notice Restarts a paused stream with a new rate.
    /// @param streamId The ID of the stream.
    /// @param ratePerSecond The new rate per second in UD21x18 format.
    function restart(uint256 streamId, UD21x18 ratePerSecond) external payable;

    /// @notice Restarts a paused stream and deposits tokens.
    /// @param streamId The ID of the stream.
    /// @param ratePerSecond The new rate per second in UD21x18 format.
    /// @param amount The amount of tokens to deposit.
    function restartAndDeposit(uint256 streamId, UD21x18 ratePerSecond, uint128 amount) external payable;

    /// @notice Refunds tokens from the stream back to the sender.
    /// @param streamId The ID of the stream.
    /// @param amount The amount of tokens to refund.
    function refund(uint256 streamId, uint128 amount) external payable;

    /// @notice Voids the stream permanently. Cannot be restarted.
    /// @param streamId The ID of the stream.
    function void(uint256 streamId) external payable;

    /// @notice Withdraws tokens from the stream to a specified address.
    /// @param streamId The ID of the stream.
    /// @param to The address to receive the withdrawn tokens.
    /// @param amount The amount of tokens to withdraw.
    function withdraw(uint256 streamId, address to, uint128 amount) external payable;

    /// @notice Withdraws the maximum withdrawable amount from the stream.
    /// @param streamId The ID of the stream.
    /// @param to The address to receive the withdrawn tokens.
    /// @return withdrawnAmount The amount of tokens withdrawn.
    function withdrawMax(uint256 streamId, address to) external payable returns (uint128 withdrawnAmount);

    /*//////////////////////////////////////////////////////////////////////////
                                VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    /// @notice Returns the stream's token balance (deposits - withdrawals).
    function getBalance(uint256 streamId) external view returns (uint128 balance);

    /// @notice Returns the current rate per second.
    function getRatePerSecond(uint256 streamId) external view returns (UD21x18 ratePerSecond);

    /// @notice Returns the stream's recipient address.
    function getRecipient(uint256 streamId) external view returns (address recipient);

    /// @notice Returns the stream's sender address.
    function getSender(uint256 streamId) external view returns (address sender);

    /// @notice Returns the snapshot time used for debt calculations.
    function getSnapshotTime(uint256 streamId) external view returns (uint40 snapshotTime);

    /// @notice Returns the token being streamed.
    function getToken(uint256 streamId) external view returns (IERC20 token);

    /// @notice Returns the token's decimals.
    function getTokenDecimals(uint256 streamId) external view returns (uint8 tokenDecimals);

    /// @notice Returns whether the stream is paused (rate == 0 and not voided).
    function isPaused(uint256 streamId) external view returns (bool result);

    /// @notice Returns whether the stream ID corresponds to an existing stream.
    function isStream(uint256 streamId) external view returns (bool result);

    /// @notice Returns whether the stream NFT is transferable.
    function isTransferable(uint256 streamId) external view returns (bool result);

    /// @notice Returns whether the stream has been permanently voided.
    function isVoided(uint256 streamId) external view returns (bool result);

    /// @notice Returns the covered debt (min of total debt and balance).
    function coveredDebtOf(uint256 streamId) external view returns (uint128 coveredDebt);

    /// @notice Returns the Unix timestamp when the stream's balance will be depleted.
    function depletionTimeOf(uint256 streamId) external view returns (uint256 depletionTime);

    /// @notice Returns the ongoing debt scaled to 18 decimals.
    function ongoingDebtScaledOf(uint256 streamId) external view returns (uint256 ongoingDebtScaled);

    /// @notice Returns the refundable amount (balance - covered debt).
    function refundableAmountOf(uint256 streamId) external view returns (uint128 refundableAmount);

    /// @notice Returns the total accrued debt.
    function totalDebtOf(uint256 streamId) external view returns (uint256 totalDebt);

    /// @notice Returns the uncovered debt (total debt - balance, or 0 if solvent).
    function uncoveredDebtOf(uint256 streamId) external view returns (uint256 uncoveredDebt);

    /// @notice Returns the amount the recipient can withdraw.
    function withdrawableAmountOf(uint256 streamId) external view returns (uint128 withdrawableAmount);

    /// @notice Returns the next stream ID to be assigned.
    function nextStreamId() external view returns (uint256);
}
