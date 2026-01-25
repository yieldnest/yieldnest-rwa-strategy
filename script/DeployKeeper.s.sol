// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {KeeperCompanion} from "src/KeeperCompanion.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";

/// @title DeployKeeper
/// @notice Deployment script for StrategyKeeper and KeeperCompanion
contract DeployKeeper is Script {
    // Mainnet addresses
    address public constant SABLIER_LOCKUP_LINEAR = 0xcF8ce57fa442ba50aCbC57147a62aD03873FfA73;
    address public constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    // These need to be set before deployment
    address public vault;
    address public targetStrategy;
    address public borrower;
    address public feeWallet;
    address public streamReceiver;
    uint256 public minThreshold;
    uint256 public minResidual;
    uint256 public apr; // 1e18 = 100%
    uint256 public holdingDays;

    StrategyKeeper public keeperImplementation;
    StrategyKeeper public keeper;
    KeeperCompanion public companion;

    function run() external {
        MainnetStrategyActors actors = new MainnetStrategyActors();

        // Set deployment parameters (customize these)
        vault = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8; // YNRWAX
        targetStrategy = address(0); // Set to deployed FlexStrategy address
        borrower = address(0); // Set to borrower address
        feeWallet = address(0); // Set to fee wallet address
        streamReceiver = address(0); // Set to stream receiver address
        minThreshold = 10_000e6; // 10,000 USDC minimum to trigger allocation
        minResidual = 1_000e6; // Keep 1,000 USDC in Safe
        apr = 0.121e18; // 12.1% APR
        holdingDays = 28;

        vm.startBroadcast();

        // 1. Deploy StrategyKeeper implementation
        keeperImplementation = new StrategyKeeper();
        console.log("StrategyKeeper implementation:", address(keeperImplementation));

        // 2. Compute proxy address for KeeperCompanion ownership
        // We need to deploy companion first with the proxy address
        // Use CREATE2 or compute address manually

        // For simplicity, we'll deploy in order and update companion ownership after

        // 3. Deploy proxy with temporary config (will update after companion deployment)
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                actors.ADMIN(),
                IStrategyKeeper.KeeperConfig({
                    vault: vault,
                    targetStrategy: targetStrategy,
                    safe: actors.SAFE(),
                    companion: address(1), // Temporary, will update
                    baseAsset: USDC,
                    borrower: borrower,
                    feeWallet: feeWallet,
                    streamReceiver: streamReceiver,
                    sablier: SABLIER_LOCKUP_LINEAR,
                    minThreshold: minThreshold,
                    minResidual: minResidual,
                    apr: apr,
                    holdingDays: holdingDays
                })
            )
        );

        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(keeperImplementation), actors.ADMIN(), initData);
        keeper = StrategyKeeper(address(proxy));
        console.log("StrategyKeeper proxy:", address(keeper));
        console.log("Proxy admin:", actors.ADMIN());

        // 4. Deploy KeeperCompanion with keeper as owner
        companion = new KeeperCompanion(address(keeper));
        console.log("KeeperCompanion:", address(companion));

        // 5. Update keeper config with correct companion address
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: actors.SAFE(),
                companion: address(companion),
                baseAsset: USDC,
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: SABLIER_LOCKUP_LINEAR,
                minThreshold: minThreshold,
                minResidual: minResidual,
                apr: apr,
                holdingDays: holdingDays
            })
        );

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("StrategyKeeper Implementation:", address(keeperImplementation));
        console.log("StrategyKeeper Proxy:", address(keeper));
        console.log("KeeperCompanion:", address(companion));
        console.log("");
        console.log("=== Required Manual Steps ===");
        console.log("1. Add StrategyKeeper as Safe owner:", address(keeper));
        console.log("2. Add KeeperCompanion as Safe owner:", address(companion));
        console.log("3. Grant PROCESSOR_ROLE to StrategyKeeper on vault");
        console.log("4. Grant KEEPER_ROLE to keeper bot address");
    }
}
