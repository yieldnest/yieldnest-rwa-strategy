// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {KeeperCompanion} from "src/KeeperCompanion.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

/// @title DeployKeeper
/// @notice Deployment script for StrategyKeeper and KeeperCompanion
contract DeployKeeper is Script {
    // Deployment parameters (customize these before deployment)
    uint256 public minThreshold = 10_000e6; // 10,000 USDC minimum to trigger allocation
    uint256 public minResidual = 1_000e6; // Keep 1,000 USDC in Safe
    uint256 public apr = 0.121e18; // 12.1% APR
    uint256 public holdingDays = 28;
    uint256 public minProcessingPercent = 0.01e18; // 1%
    uint256 public feeFraction = 11; // 1/11 to fee wallet, 10/11 to stream

    // Borrower address (set this before deployment)
    address public borrower = address(0); // TODO: Set to borrower address

    StrategyKeeper public keeperImplementation;
    StrategyKeeper public keeper;
    KeeperCompanion public companion;

    function run() external {
        MainnetStrategyActors actors = new MainnetStrategyActors();

        require(borrower != address(0), "Borrower address not set");

        vm.startBroadcast();

        // 1. Deploy StrategyKeeper implementation
        keeperImplementation = new StrategyKeeper();
        console.log("StrategyKeeper implementation:", address(keeperImplementation));

        // 2. Deploy proxy with temporary config (will update after companion deployment)
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                actors.ADMIN(),
                IStrategyKeeper.KeeperConfig({
                    vault: MainnetKeeperContracts.YNRWAX,
                    targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
                    safe: actors.SAFE(),
                    companion: address(1), // Temporary, will update
                    baseAsset: MainnetKeeperContracts.USDC,
                    borrower: borrower,
                    feeWallet: MainnetKeeperContracts.FEE_WALLET,
                    streamReceiver: MainnetKeeperContracts.REWARDS_SWEEPER, // Rewards sweeper receives Sablier streams
                    sablier: MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR,
                    minThreshold: minThreshold,
                    minResidual: minResidual,
                    apr: apr,
                    holdingDays: holdingDays,
                    minProcessingPercent: minProcessingPercent,
                    feeFraction: feeFraction
                })
            )
        );

        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(keeperImplementation), actors.ADMIN(), initData);
        keeper = StrategyKeeper(address(proxy));
        console.log("StrategyKeeper proxy:", address(keeper));
        console.log("Proxy admin:", actors.ADMIN());

        // 3. Deploy KeeperCompanion with keeper as owner
        companion = new KeeperCompanion(address(keeper));
        console.log("KeeperCompanion:", address(companion));

        // 4. Update keeper config with correct companion address
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: MainnetKeeperContracts.YNRWAX,
                targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
                safe: actors.SAFE(),
                companion: address(companion),
                baseAsset: MainnetKeeperContracts.USDC,
                borrower: borrower,
                feeWallet: MainnetKeeperContracts.FEE_WALLET,
                streamReceiver: MainnetKeeperContracts.REWARDS_SWEEPER, // Rewards sweeper receives Sablier streams
                sablier: MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR,
                minThreshold: minThreshold,
                minResidual: minResidual,
                apr: apr,
                holdingDays: holdingDays,
                minProcessingPercent: minProcessingPercent,
                feeFraction: feeFraction
            })
        );

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("StrategyKeeper Implementation:", address(keeperImplementation));
        console.log("StrategyKeeper Proxy:", address(keeper));
        console.log("KeeperCompanion:", address(companion));
        console.log("");
        console.log("=== Configuration ===");
        console.log("Vault (ynRWAx):", MainnetKeeperContracts.YNRWAX);
        console.log("Target Strategy:", MainnetKeeperContracts.FLEX_STRATEGY);
        console.log("Fee Wallet:", MainnetKeeperContracts.FEE_WALLET);
        console.log("Stream Receiver (Rewards Sweeper):", MainnetKeeperContracts.REWARDS_SWEEPER);
        console.log("Borrower:", borrower);
        console.log("");
        console.log("=== Required Manual Steps ===");
        console.log("1. Add StrategyKeeper as Safe owner:", address(keeper));
        console.log("2. Add KeeperCompanion as Safe owner:", address(companion));
        console.log("3. Grant PROCESSOR_ROLE to StrategyKeeper on vault");
        console.log("4. Grant KEEPER_ROLE to keeper bot address");
    }
}
