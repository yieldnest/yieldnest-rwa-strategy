// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {AccessControlEnumerable} from
    "lib/openzeppelin-contracts/contracts/access/extensions/AccessControlEnumerable.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";

import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";

/// @title FlowValidator
/// @notice Transaction validator for the Safe Guard that checks adjustRatePerSecond calls
///         don't push the effective APR (relative to vault totalAssets) above a per-stream cap.
///         Passes through all other transactions without validation.
contract FlowValidator is IValidator, AccessControlEnumerable {
    /// @notice A stream ID paired with its maximum allowed APR
    struct StreamLimit {
        uint256 streamId;
        uint256 maxApr; // 1e18 = 100%
    }

    uint256 internal constant SECONDS_PER_YEAR = 365 days;

    uint256 internal constant APR_DENOMINATOR = 1e18;

    uint256 internal constant UD21x18_DENOMINATOR = 1e18;

    /// @notice Sablier Flow contract — only calls to this target are validated
    address public immutable flow;

    /// @notice Vault used to read totalAssets for APR calculation
    IERC4626 public immutable vault;

    /// @notice Token decimals for UD21x18 → base-unit conversion
    uint8 public immutable tokenDecimals;

    /// @notice Array of stream limits (small set, iterated linearly)
    StreamLimit[] private _limits;

    error InvalidFunctionSelector(bytes4 selector);
    error StreamNotFound(uint256 streamId);
    error RateExceedsMaxApr(uint256 streamId, uint128 rate, uint256 effectiveApr, uint256 maxApr);

    event LimitsUpdated(StreamLimit[] limits);

    /// @notice Role required to call setLimits
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");

    constructor(address _flow, address _vault, uint8 _tokenDecimals, StreamLimit[] memory limits_, address admin_) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(MANAGER_ROLE, admin_);
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

        bytes4 selector = bytes4(data[:4]);
        if (selector != ISablierFlow.adjustRatePerSecond.selector) {
            revert InvalidFunctionSelector(selector);
        }

        // Decode: adjustRatePerSecond(uint256 streamId, UD21x18 newRate)
        (uint256 streamId, UD21x18 newRate) = abi.decode(data[4:], (uint256, UD21x18));
        uint128 rate = uint128(UD21x18.unwrap(newRate));

        uint256 maxApr = _getMaxApr(streamId);
        uint256 totalAssets = vault.totalAssets();

        if (totalAssets == 0) {
            revert RateExceedsMaxApr(streamId, rate, type(uint256).max, maxApr);
        }

        // The maximum APR amount earned scaled by APR_DENOMINATOR
        uint256 scaledMaxAprAmount = maxApr * totalAssets;

        uint256 scaledAprAmount = effectiveAprScaled(rate);

        if (scaledAprAmount > scaledMaxAprAmount) {
            // simply divide by totalAssets to get the actual APR, since the scaling is already done
            uint256 actualApr = effectiveApr(rate, totalAssets);
            revert RateExceedsMaxApr(streamId, rate, actualApr, maxApr);
        }
    }

    /// @notice Compute the effective APR for a given rate against current totalAssets
    /// @param rate The rate per second (UD21x18 unwrapped)
    /// @return apr The effective APR (1e18 = 100%)
    function effectiveApr(uint128 rate) public view returns (uint256 apr) {
        uint256 totalAssets = vault.totalAssets();

        return effectiveApr(rate, totalAssets);
    }

    /**
     * @notice Calculates the effective APR amount, scaled by APR_DENOMINATOR, for a given Flow rate.
     * @dev
     * The Sablier Flow rate is already expressed in 18 decimals (UD21x18), i.e., multiplied by (1e18 / 10^tokenDecimals).
     * To further scale the value to match APR_DENOMINATOR, this function multiplies the rate by:
     *     APR_DENOMINATOR / (UD21x18_DENOMINATOR / (10 ** tokenDecimals))
     * If both APR_DENOMINATOR and UD21x18_DENOMINATOR are 1e18, this is equivalent to multiplying by 10 ** tokenDecimals.
     * For rate calculation reference, see:
     * https://docs.sablier.com/guides/flow/examples/flow-calculate-rps
     * @param rate The Flow stream rate per second (unwrapped UD21x18 value).
     * @return scaledAprAmount The APR numerator, scaled by APR_DENOMINATOR for comparison.
     */
    function effectiveAprScaled(uint128 rate) public view returns (uint256 scaledAprAmount) {
        return uint256(rate) * SECONDS_PER_YEAR * (APR_DENOMINATOR / (UD21x18_DENOMINATOR / (10 ** tokenDecimals)));
    }

    function effectiveApr(uint128 rate, uint256 totalAssets) internal view returns (uint256 apr) {
        if (totalAssets == 0) {
            return type(uint256).max;
        }
        return effectiveAprScaled(rate) / totalAssets;
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
    function setLimits(StreamLimit[] calldata limits_) external onlyRole(MANAGER_ROLE) {
        delete _limits;
        for (uint256 i = 0; i < limits_.length; i++) {
            _limits.push(limits_[i]);
        }
        emit LimitsUpdated(limits_);
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
