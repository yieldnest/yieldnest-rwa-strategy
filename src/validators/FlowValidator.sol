// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";

import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";

/// @title FlowValidator
/// @notice Transaction validator for the Safe Guard that checks adjustRatePerSecond calls
///         don't push the effective APR (relative to vault totalAssets) above a per-stream cap.
///         Passes through all other transactions without validation.
contract FlowValidator is IValidator, Ownable {
    /// @notice A stream ID paired with its maximum allowed APR
    struct StreamLimit {
        uint256 streamId;
        uint256 maxApr; // 1e18 = 100%
    }

    uint256 internal constant SECONDS_PER_YEAR = 365 days;

    /// @notice Sablier Flow contract — only calls to this target are validated
    address public immutable flow;

    /// @notice Vault used to read totalAssets for APR calculation
    IERC4626 public immutable vault;

    /// @notice Token decimals for UD21x18 → base-unit conversion
    uint8 public immutable tokenDecimals;

    /// @notice Array of stream limits (small set, iterated linearly)
    StreamLimit[] private _limits;

    error StreamNotFound(uint256 streamId);
    error RateExceedsMaxApr(uint256 streamId, uint128 rate, uint256 effectiveApr, uint256 maxApr);

    event LimitsUpdated();

    constructor(address _flow, address _vault, uint8 _tokenDecimals, StreamLimit[] memory limits_, address owner_)
        Ownable(owner_)
    {
        flow = _flow;
        vault = IERC4626(_vault);
        tokenDecimals = _tokenDecimals;
        for (uint256 i = 0; i < limits_.length; i++) {
            _limits.push(limits_[i]);
        }
    }

    /// @notice Validate a module transaction. Only checks adjustRatePerSecond calls to the flow contract.
    /// @dev Reverts with RateExceedsMaxApr if the new rate implies an APR above the stream's cap.
    ///      All other transactions pass through.
    /// @param target The address the transaction is sent to
    /// @param data The calldata of the transaction
    function validate(address target, uint256, bytes calldata data) external view override {
        if (target != flow) return;
        if (data.length < 4) return;

        bytes4 selector = bytes4(data[:4]);
        if (selector != ISablierFlow.adjustRatePerSecond.selector) return;

        // Decode: adjustRatePerSecond(uint256 streamId, UD21x18 newRate)
        (uint256 streamId, UD21x18 newRate) = abi.decode(data[4:], (uint256, UD21x18));
        uint128 rate = uint128(UD21x18.unwrap(newRate));

        uint256 maxApr = _getMaxApr(streamId);
        uint256 totalAssets = vault.totalAssets();

        // APR check (no division, no precision loss):
        //   rate * 10^decimals * SECONDS_PER_YEAR <= maxApr * totalAssets
        uint256 lhs = uint256(rate) * (10 ** tokenDecimals) * SECONDS_PER_YEAR;
        uint256 rhs = maxApr * totalAssets;

        if (lhs > rhs) {
            uint256 effective = totalAssets > 0 ? lhs / totalAssets : type(uint256).max;
            revert RateExceedsMaxApr(streamId, rate, effective, maxApr);
        }
    }

    /// @notice Compute the effective APR for a given rate against current totalAssets
    /// @param rate The rate per second (UD21x18 unwrapped)
    /// @return apr The effective APR (1e18 = 100%)
    function effectiveApr(uint128 rate) external view returns (uint256 apr) {
        uint256 totalAssets = vault.totalAssets();
        if (totalAssets == 0) return type(uint256).max;
        return uint256(rate) * (10 ** tokenDecimals) * SECONDS_PER_YEAR / totalAssets;
    }

    /// @notice Get the full list of stream limits
    function getLimits() external view returns (StreamLimit[] memory) {
        return _limits;
    }

    /// @notice Get the max APR for a specific stream
    /// @param streamId The stream ID to look up
    /// @return maxApr The max APR (1e18 = 100%)
    function getMaxApr(uint256 streamId) external view returns (uint256 maxApr) {
        return _getMaxApr(streamId);
    }

    /// @notice Replace the entire limits array
    /// @param limits_ New set of stream limits
    function setLimits(StreamLimit[] calldata limits_) external onlyOwner {
        delete _limits;
        for (uint256 i = 0; i < limits_.length; i++) {
            _limits.push(limits_[i]);
        }
        emit LimitsUpdated();
    }

    /// @dev Linear scan — array is expected to be small (< 10 entries)
    function _getMaxApr(uint256 streamId) internal view returns (uint256) {
        StreamLimit[] memory limits = _limits;
        for (uint256 i = 0; i < limits.length; i++) {
            if (limits[i].streamId == streamId) return limits[i].maxApr;
        }
        revert StreamNotFound(streamId);
    }
}
