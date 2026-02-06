// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";

contract StrategyKeeperTest is Test {
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;

    address public admin = address(0x1);
    address public keeperBot = address(0x2);
    address public vault = address(0x3);
    address public targetStrategy = address(0x4);
    address public safe = address(0x5);
    address public baseAsset = address(0x6);
    address public borrower = address(0x7);
    address public feeWallet = address(0x8);
    address public streamReceiver = address(0x9);
    address public sablier = address(0xA);

    // 28 days in seconds
    uint256 constant TWENTY_EIGHT_DAYS = 28 days;

    function setUp() public {
        // Deploy implementation
        keeperImpl = new StrategyKeeper();

        // Deploy proxy - use this contract (the test) as the initial deployer so we can grant roles
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                address(this), // Use test contract as initial admin
                IStrategyKeeper.KeeperConfig({
                    vault: vault,
                    targetStrategy: targetStrategy,
                    safe: safe,
                    baseAsset: baseAsset,
                    borrower: borrower,
                    feeWallet: feeWallet,
                    streamReceiver: streamReceiver,
                    sablier: sablier,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18,
                    holdingPeriod: TWENTY_EIGHT_DAYS,
                    minProcessingPercent: 0.01e18,
                    feeFraction: 11
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Grant roles to admin and keeper bot
        keeper.grantRole(keeper.DEFAULT_ADMIN_ROLE(), admin);
        keeper.grantRole(keeper.CONFIG_MANAGER_ROLE(), admin);
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        keeper.grantRole(keeper.PAUSER_ROLE(), admin);

        // Renounce the test contract's roles
        keeper.renounceRole(keeper.PAUSER_ROLE(), address(this));
        keeper.renounceRole(keeper.CONFIG_MANAGER_ROLE(), address(this));
        keeper.renounceRole(keeper.DEFAULT_ADMIN_ROLE(), address(this));
    }

    function test_initialization() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.vault, vault);
        assertEq(cfg.targetStrategy, targetStrategy);
        assertEq(cfg.safe, safe);
        assertEq(cfg.baseAsset, baseAsset);
        assertEq(cfg.borrower, borrower);
        assertEq(cfg.feeWallet, feeWallet);
        assertEq(cfg.streamReceiver, streamReceiver);
        assertEq(cfg.sablier, sablier);
        assertEq(cfg.minThreshold, 10_000e6);
        assertEq(cfg.minResidual, 1_000e6);
        assertEq(cfg.apr, 0.121e18);
        assertEq(cfg.holdingPeriod, TWENTY_EIGHT_DAYS);
    }

    function test_roles() public view {
        assertTrue(keeper.hasRole(keeper.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(keeper.hasRole(keeper.CONFIG_MANAGER_ROLE(), admin));
        assertTrue(keeper.hasRole(keeper.KEEPER_ROLE(), keeperBot));
        assertTrue(keeper.hasRole(keeper.PAUSER_ROLE(), admin));
    }

    function test_revertOnUnauthorizedKeeper() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_revertOnUnauthorizedConfigUpdate() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: TWENTY_EIGHT_DAYS,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_revertOnZeroAddressConfig() public {
        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.ZeroAddress.selector);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: address(0), // Zero address should revert
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: TWENTY_EIGHT_DAYS,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_revertOnInvalidApr() public {
        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0, // Zero APR should revert
                holdingPeriod: TWENTY_EIGHT_DAYS,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_revertOnAprExceedingMax() public {
        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 2e18, // 200% APR exceeds max (100%)
                holdingPeriod: TWENTY_EIGHT_DAYS,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_revertOnZeroHoldingPeriod() public {
        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 0, // Zero should revert
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_revertOnHoldingPeriodExceedsMaximum() public {
        uint256 tooLong = 366 days; // Exceeds max of 365 days
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IStrategyKeeper.HoldingPeriodExceedsMaximum.selector, tooLong, 365 days));
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: tooLong,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_holdingPeriodAtMaximum() public {
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 365 days, // Max allowed
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
        assertEq(keeper.getConfig().holdingPeriod, 365 days);
    }

    function test_pauseAndUnpause() public {
        // Should not be paused initially
        assertFalse(keeper.paused());

        // Pause
        vm.prank(admin);
        keeper.pause();
        assertTrue(keeper.paused());

        // Unpause
        vm.prank(admin);
        keeper.unpause();
        assertFalse(keeper.paused());
    }

    function test_revertOnProcessInflowsWhenPaused() public {
        // Pause the keeper
        vm.prank(admin);
        keeper.pause();

        // Try to process inflows - should revert
        vm.prank(keeperBot);
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_revertOnUnauthorizedPause() public {
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        keeper.pause();
    }

    function test_revertOnUnauthorizedUnpause() public {
        // First pause it
        vm.prank(admin);
        keeper.pause();

        // Try to unpause without permission
        vm.prank(address(0xBEEF));
        vm.expectRevert();
        keeper.unpause();
    }

    function test_configUpdatedEventEmitsDetails() public {
        uint256 newHoldingPeriod = 30 days;
        vm.prank(admin);
        vm.expectEmit(true, true, false, true);
        emit IStrategyKeeper.ConfigUpdated(vault, safe, 0.15e18, newHoldingPeriod, 11);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.15e18,
                holdingPeriod: newHoldingPeriod,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
    }

    function test_yieldCalculation() public pure {
        // Test the yield calculation formula:
        // interest = available * apr * holdingPeriod / SECONDS_PER_YEAR / PRECISION
        //
        // Example from spec:
        // Amount: 34,500 USDC
        // APR: 12.1%
        // Holding 28 days yield in advance
        // 34500 * 12.1 / 100 * 28 / 365 = 320.23561643835615

        uint256 available = 34_500e6; // 34,500 USDC (6 decimals)
        uint256 apr = 0.121e18; // 12.1%
        uint256 holdingPeriod = 28 days; // 28 days in seconds
        uint256 PRECISION = 1e18;
        uint256 SECONDS_PER_YEAR = 365 days;

        uint256 interest = (available * apr * holdingPeriod) / SECONDS_PER_YEAR / PRECISION;

        // Expected: ~320.24 USDC = 320_235_616 (6 decimals)
        // Allow for small rounding difference
        assertApproxEqAbs(interest, 320_235_616, 1e3); // Within 0.001 USDC

        // Test fee split
        uint256 fee = interest / 11; // 1/11 of interest
        uint256 streamAmount = interest - fee; // 10/11 of interest

        assertEq(fee + streamAmount, interest);
        assertApproxEqRel(fee, interest / 11, 0.01e18); // Within 1%
        assertApproxEqRel(streamAmount, (interest * 10) / 11, 0.01e18); // Within 1%
    }
}
