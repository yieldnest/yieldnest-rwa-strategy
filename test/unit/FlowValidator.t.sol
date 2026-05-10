// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {FlowValidator} from "src/validators/FlowValidator.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";

/// @title FlowValidatorTest
/// @notice Unit tests for FlowValidator — no fork needed, uses mock vault.
contract FlowValidatorTest is Test {
    FlowValidator public validator;

    address public owner = address(0xAA);
    address public flow = address(0xBB);
    address public vaultAddr = address(0xCC);

    uint256 constant STREAM_ID = 42;
    uint256 constant MAX_APR = 0.115e18; // 11.5%
    uint8 constant TOKEN_DECIMALS = 6; // USDC
    uint256 constant SECONDS_PER_YEAR = 365 days;

    function setUp() public {
        FlowValidator.StreamLimit[] memory limits = new FlowValidator.StreamLimit[](1);
        limits[0] = FlowValidator.StreamLimit({streamId: STREAM_ID, maxApr: MAX_APR});

        validator = new FlowValidator(flow, vaultAddr, TOKEN_DECIMALS, limits, owner);
    }

    /*//////////////////////////////////////////////////////////////
                          CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    function test_constructorSetsImmutables() public view {
        assertEq(validator.flow(), flow);
        assertEq(address(validator.vault()), vaultAddr);
        assertEq(validator.tokenDecimals(), TOKEN_DECIMALS);
        assertTrue(validator.hasRole(validator.DEFAULT_ADMIN_ROLE(), owner));
        assertTrue(validator.hasRole(validator.MANAGER_ROLE(), owner));
    }

    function test_constructorSetsLimits() public view {
        FlowValidator.StreamLimit[] memory limits = validator.getLimits();
        assertEq(limits.length, 1);
        assertEq(limits[0].streamId, STREAM_ID);
        assertEq(limits[0].maxApr, MAX_APR);
    }

    function test_constructorMultipleStreams() public {
        FlowValidator.StreamLimit[] memory limits = new FlowValidator.StreamLimit[](3);
        limits[0] = FlowValidator.StreamLimit({streamId: 1, maxApr: 0.1e18});
        limits[1] = FlowValidator.StreamLimit({streamId: 2, maxApr: 0.115e18});
        limits[2] = FlowValidator.StreamLimit({streamId: 3, maxApr: 0.2e18});

        FlowValidator v = new FlowValidator(flow, vaultAddr, TOKEN_DECIMALS, limits, owner);

        assertEq(v.getMaxApr(1), 0.1e18);
        assertEq(v.getMaxApr(2), 0.115e18);
        assertEq(v.getMaxApr(3), 0.2e18);
    }

    /*//////////////////////////////////////////////////////////////
                          VALIDATE — PASS THROUGH
    //////////////////////////////////////////////////////////////*/

    function test_passesThrough_wrongTarget() public view {
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(1e18)));
        // Different target — should not revert
        validator.validate(address(0xDD), 0, data);
    }

    function test_revertsOnShortData() public {
        vm.expectRevert();
        validator.validate(flow, 0, hex"aabbcc");
    }

    function test_revertsOnDifferentSelector() public {
        bytes memory data = abi.encodeCall(ISablierFlow.deposit, (STREAM_ID, 1000, address(0), address(0)));
        bytes4 depositSelector = ISablierFlow.deposit.selector;

        vm.expectRevert(abi.encodeWithSelector(FlowValidator.InvalidFunctionSelector.selector, depositSelector));
        validator.validate(flow, 0, data);
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATE — RATE CHECK
    //////////////////////////////////////////////////////////////*/

    function test_allowsRateBelowMaxApr() public {
        // totalAssets = 10,000,000 USDC (10M)
        uint256 totalAssets = 10_000_000e6;
        _mockTotalAssets(totalAssets);

        // Max annual yield at 11.5% = 1,150,000 USDC = 1.15e12 base units
        // Max rate = 1.15e12 / SECONDS_PER_YEAR = ~36,465 base units/sec
        // In UD21x18: 36,465 * 1e12 = ~3.6465e16
        // Use a rate well below the max
        uint128 safeRate = 3e16; // below max

        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(safeRate)));
        validator.validate(flow, 0, data);
    }

    function test_allowsRateAtExactMaxApr() public {
        uint256 totalAssets = 10_000_000e6;
        _mockTotalAssets(totalAssets);

        // Compute exact max rate: maxApr * totalAssets / (10^decimals * SECONDS_PER_YEAR)
        // = 0.115e18 * 10_000_000e6 / (1e6 * 31536000)
        // = 1.15e23 * 1e7 / (1e6 * 3.1536e7) = 1.15e30 / 3.1536e13 = ~3.6465e16
        uint128 exactMaxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * SECONDS_PER_YEAR));

        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(exactMaxRate)));
        // Should not revert — exactly at the boundary
        validator.validate(flow, 0, data);
    }

    function test_revertsRateAboveMaxApr() public {
        uint256 totalAssets = 10_000_000e6;
        _mockTotalAssets(totalAssets);

        // Compute exact max rate and add 1
        uint128 exactMaxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * SECONDS_PER_YEAR));
        uint128 tooHighRate = exactMaxRate + 1;

        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(tooHighRate)));

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                STREAM_ID,
                tooHighRate,
                validator.effectiveApr(tooHighRate),
                MAX_APR
            )
        );
        validator.validate(flow, 0, data);
    }

    function test_revertIncludesCorrectErrorData() public {
        uint256 totalAssets = 10_000_000e6;
        _mockTotalAssets(totalAssets);

        uint128 tooHighRate = 1e18; // way too high — 1 USDC/sec = 31.5M USDC/year on 10M = 315% APR

        uint256 effectiveApr = uint256(tooHighRate) * (10 ** TOKEN_DECIMALS) * SECONDS_PER_YEAR / totalAssets;

        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(tooHighRate)));

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector, STREAM_ID, tooHighRate, effectiveApr, MAX_APR
            )
        );
        validator.validate(flow, 0, data);
    }

    function test_revertsForUnknownStreamId() public {
        uint256 totalAssets = 10_000_000e6;
        _mockTotalAssets(totalAssets);

        uint256 unknownStreamId = 999;
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (unknownStreamId, UD21x18.wrap(1)));

        vm.expectRevert(abi.encodeWithSelector(FlowValidator.StreamNotFound.selector, unknownStreamId));
        validator.validate(flow, 0, data);
    }

    /*//////////////////////////////////////////////////////////////
                    VALIDATE — TOTAL ASSETS EDGE CASES
    //////////////////////////////////////////////////////////////*/

    function test_revertsWhenTotalAssetsZero() public {
        _mockTotalAssets(0);

        // Any non-zero rate should revert when totalAssets is 0
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(1)));

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector, STREAM_ID, uint128(1), type(uint256).max, MAX_APR
            )
        );
        validator.validate(flow, 0, data);
    }

    function test_smallTotalAssetsStrictlyBoundsRate() public {
        // With tiny totalAssets, even a tiny rate can exceed max APR
        uint256 totalAssets = 100e6; // 100 USDC
        _mockTotalAssets(totalAssets);

        // Max rate for 100 USDC at 11.5%: 11.5 USDC/year ≈ 0.000000365 USDC/sec
        // In UD21x18: ~365 (very small)
        uint128 maxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * SECONDS_PER_YEAR));

        // At boundary — should pass
        bytes memory dataOk = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(maxRate)));
        validator.validate(flow, 0, dataOk);

        // One above — should revert
        bytes memory dataBad = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(maxRate + 1)));
        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                STREAM_ID,
                maxRate + 1,
                validator.effectiveApr(maxRate + 1),
                MAX_APR
            )
        );
        validator.validate(flow, 0, dataBad);
    }

    function test_largeTotalAssetsAllowsHighRate() public {
        // With large totalAssets, higher rates are acceptable
        uint256 totalAssets = 1_000_000_000e6; // 1 billion USDC
        _mockTotalAssets(totalAssets);

        uint128 maxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * SECONDS_PER_YEAR));

        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (STREAM_ID, UD21x18.wrap(maxRate)));
        validator.validate(flow, 0, data);
    }

    /*//////////////////////////////////////////////////////////////
                       EFFECTIVE APR VIEW
    //////////////////////////////////////////////////////////////*/

    function test_effectiveAprCalculation() public {
        uint256 totalAssets = 10_000_000e6;
        _mockTotalAssets(totalAssets);

        // Rate that would give exactly 11.5% APR
        uint128 rate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * SECONDS_PER_YEAR));

        uint256 apr = validator.effectiveApr(rate);
        // Should be very close to MAX_APR (may differ by a few wei due to rounding)
        assertApproxEqAbs(apr, MAX_APR, 2, "Effective APR should match max APR");
    }

    function test_effectiveAprZeroTotalAssets() public {
        _mockTotalAssets(0);
        assertEq(validator.effectiveApr(1), type(uint256).max, "Should return max uint when totalAssets is 0");
    }

    function test_effectiveAprZeroRate() public {
        _mockTotalAssets(10_000_000e6);
        assertEq(validator.effectiveApr(0), 0, "Zero rate should give zero APR");
    }

    /*//////////////////////////////////////////////////////////////
                          GET MAX APR
    //////////////////////////////////////////////////////////////*/

    function test_getMaxAprReturnsCorrectValue() public view {
        assertEq(validator.getMaxApr(STREAM_ID), MAX_APR);
    }

    function test_getMaxAprRevertsForUnknown() public {
        vm.expectRevert(abi.encodeWithSelector(FlowValidator.StreamNotFound.selector, 999));
        validator.getMaxApr(999);
    }

    /*//////////////////////////////////////////////////////////////
                          SET LIMITS
    //////////////////////////////////////////////////////////////*/

    function test_setLimitsReplacesArray() public {
        FlowValidator.StreamLimit[] memory newLimits = new FlowValidator.StreamLimit[](2);
        newLimits[0] = FlowValidator.StreamLimit({streamId: 100, maxApr: 0.05e18});
        newLimits[1] = FlowValidator.StreamLimit({streamId: 200, maxApr: 0.2e18});

        vm.prank(owner);
        validator.setLimits(newLimits);

        FlowValidator.StreamLimit[] memory limits = validator.getLimits();
        assertEq(limits.length, 2);
        assertEq(limits[0].streamId, 100);
        assertEq(limits[0].maxApr, 0.05e18);
        assertEq(limits[1].streamId, 200);
        assertEq(limits[1].maxApr, 0.2e18);

        // Old stream ID should now revert
        vm.expectRevert(abi.encodeWithSelector(FlowValidator.StreamNotFound.selector, STREAM_ID));
        validator.getMaxApr(STREAM_ID);
    }

    function test_setLimitsEmitsEvent() public {
        FlowValidator.StreamLimit[] memory newLimits = new FlowValidator.StreamLimit[](1);
        newLimits[0] = FlowValidator.StreamLimit({streamId: 1, maxApr: 0.1e18});

        vm.expectEmit();
        emit FlowValidator.LimitsUpdated(newLimits);

        vm.prank(owner);
        validator.setLimits(newLimits);
    }

    function test_setLimitsRevertsForNonManager() public {
        FlowValidator.StreamLimit[] memory newLimits = new FlowValidator.StreamLimit[](1);
        newLimits[0] = FlowValidator.StreamLimit({streamId: 1, maxApr: 0.1e18});

        bytes32 managerRole = validator.MANAGER_ROLE();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(0xDEAD), managerRole
            )
        );
        vm.prank(address(0xDEAD));
        validator.setLimits(newLimits);
    }

    /*//////////////////////////////////////////////////////////////
                          HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mockTotalAssets(uint256 amount) internal {
        vm.mockCall(vaultAddr, abi.encodeCall(IERC4626.totalAssets, ()), abi.encode(amount));
    }
}
