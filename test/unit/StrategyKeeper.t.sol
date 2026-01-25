// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {KeeperCompanion, IKeeperCompanion} from "src/KeeperCompanion.sol";

contract StrategyKeeperTest is Test {
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;
    KeeperCompanion public companion;

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

    function setUp() public {
        // Deploy implementation
        keeperImpl = new StrategyKeeper();

        // Pre-compute the proxy address to deploy companion first
        // We'll use a temporary companion address during init, then update
        address tempCompanion = address(0xBEEF);

        // Deploy proxy with temporary companion address (non-zero)
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                admin,
                IStrategyKeeper.KeeperConfig({
                    vault: vault,
                    targetStrategy: targetStrategy,
                    safe: safe,
                    companion: tempCompanion, // Temporary non-zero address
                    baseAsset: baseAsset,
                    borrower: borrower,
                    feeWallet: feeWallet,
                    streamReceiver: streamReceiver,
                    sablier: sablier,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18,
                    holdingDays: 28,
                    minProcessingPercent: 0.01e18
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Deploy companion with keeper as owner
        companion = new KeeperCompanion(address(keeper));

        // Update config with correct companion and grant roles
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                companion: address(companion),
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18
            })
        );

        // Grant KEEPER_ROLE to bot
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        vm.stopPrank();
    }

    function test_initialization() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.vault, vault);
        assertEq(cfg.targetStrategy, targetStrategy);
        assertEq(cfg.safe, safe);
        assertEq(cfg.companion, address(companion));
        assertEq(cfg.baseAsset, baseAsset);
        assertEq(cfg.borrower, borrower);
        assertEq(cfg.feeWallet, feeWallet);
        assertEq(cfg.streamReceiver, streamReceiver);
        assertEq(cfg.sablier, sablier);
        assertEq(cfg.minThreshold, 10_000e6);
        assertEq(cfg.minResidual, 1_000e6);
        assertEq(cfg.apr, 0.121e18);
        assertEq(cfg.holdingDays, 28);
    }

    function test_roles() public view {
        assertTrue(keeper.hasRole(keeper.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(keeper.hasRole(keeper.CONFIG_MANAGER_ROLE(), admin));
        assertTrue(keeper.hasRole(keeper.KEEPER_ROLE(), keeperBot));
    }

    function test_companionOwnership() public view {
        assertEq(companion.owner(), address(keeper));
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
                companion: address(companion),
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18
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
                companion: address(companion),
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28,
                minProcessingPercent: 0.01e18
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
                companion: address(companion),
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0, // Zero APR should revert
                holdingDays: 28,
                minProcessingPercent: 0.01e18
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
                companion: address(companion),
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 2e18, // 200% APR exceeds max (100%)
                holdingDays: 28,
                minProcessingPercent: 0.01e18
            })
        );
    }

    function test_revertOnZeroHoldingDays() public {
        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                companion: address(companion),
                baseAsset: baseAsset,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 0, // Zero days should revert
                minProcessingPercent: 0.01e18
            })
        );
    }

    function test_yieldCalculation() public pure {
        // Test the yield calculation formula:
        // interest = available * apr * holdingDays / 365 / PRECISION
        //
        // Example from spec:
        // Amount: 34,500 USDC
        // APR: 12.1%
        // Holding 28 days yield in advance
        // 34500 * 12.1 / 100 * 28 / 365 = 320.23561643835615

        uint256 available = 34_500e6; // 34,500 USDC (6 decimals)
        uint256 apr = 0.121e18; // 12.1%
        uint256 holdingDays = 28;
        uint256 PRECISION = 1e18;
        uint256 DAYS_PER_YEAR = 365;

        uint256 interest = (available * apr * holdingDays) / DAYS_PER_YEAR / PRECISION;

        // Expected: ~320.24 USDC = 320_235_616 (6 decimals)
        // Our calculation: 34500e6 * 121e15 * 28 / 365 / 1e18
        //                = 34500 * 121 * 28 * 1e6 * 1e15 / 365 / 1e18
        //                = 34500 * 121 * 28 * 1e6 / 365 / 1e3
        //                = 116886000 * 1e6 / 365000
        //                = 320235616 (rounding may differ slightly)

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

contract KeeperCompanionTest is Test {
    KeeperCompanion public companion;
    address public keeper = address(0x1);
    address public other = address(0x2);

    function setUp() public {
        companion = new KeeperCompanion(keeper);
    }

    function test_ownership() public view {
        assertEq(companion.owner(), keeper);
    }

    function test_approveHash() public {
        bytes32 hash = keccak256("test");

        assertFalse(companion.isHashApproved(hash));

        vm.prank(keeper);
        companion.approveHash(hash);

        assertTrue(companion.isHashApproved(hash));
    }

    function test_revokeHash() public {
        bytes32 hash = keccak256("test");

        vm.prank(keeper);
        companion.approveHash(hash);
        assertTrue(companion.isHashApproved(hash));

        vm.prank(keeper);
        companion.revokeHash(hash);
        assertFalse(companion.isHashApproved(hash));
    }

    function test_isValidSignature() public {
        bytes32 hash = keccak256("test");

        // Not approved - should return invalid
        bytes4 result = companion.isValidSignature(hash, "");
        assertEq(result, bytes4(0xffffffff));

        // Approve and check again
        vm.prank(keeper);
        companion.approveHash(hash);

        result = companion.isValidSignature(hash, "");
        assertEq(result, bytes4(0x1626ba7e)); // MAGIC_VALUE
    }

    function test_revertOnUnauthorizedApprove() public {
        bytes32 hash = keccak256("test");

        vm.prank(other);
        vm.expectRevert();
        companion.approveHash(hash);
    }

    function test_revertOnUnauthorizedRevoke() public {
        bytes32 hash = keccak256("test");

        vm.prank(keeper);
        companion.approveHash(hash);

        vm.prank(other);
        vm.expectRevert();
        companion.revokeHash(hash);
    }
}
