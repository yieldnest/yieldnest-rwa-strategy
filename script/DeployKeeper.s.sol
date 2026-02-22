// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

/// @title DeployKeeper
/// @notice Deployment script for StrategyKeeper (immutable, no proxy)
contract DeployKeeper is Script {
    // Deployment parameters (customize these before deployment)
    uint256 public minThreshold = 200_000e6; // 200,000 USDC minimum to trigger allocation
    uint256 public minResidual = 1_000e6; // Keep 1,000 USDC in Safe
    uint256 public apr = 0.121e18; // 12.1% APR
    uint256 public holdingPeriod = 28 days;
    uint256 public minProcessingPercent = 0.03e18; // 3%. Eg if vault has 3.5m then 3% is 105k.
    uint256 public feeFraction = 11; // 1/11 to fee wallet, 10/11 to stream

    StrategyKeeper public keeper;

    function run() external {
        MainnetStrategyActors actors = new MainnetStrategyActors();
        address admin = actors.ADMIN();
        address deployer = msg.sender;
        address pauser = actors.PAUSER();
        address processor = actors.PROCESSOR();

        // Build config
        IStrategyKeeper.KeeperConfig memory config = IStrategyKeeper.KeeperConfig({
            vault: MainnetKeeperContracts.YNRWAX,
            targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
            safe: actors.SAFE(),
            baseAsset: MainnetKeeperContracts.USDC,
            borrower: MainnetKeeperContracts.BORROWER,
            feeWallet: MainnetKeeperContracts.FEE_WALLET,
            streamReceiver: MainnetKeeperContracts.REWARDS_SWEEPER, // Rewards sweeper receives Sablier streams
            sablier: MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR,
            minThreshold: minThreshold,
            minResidual: minResidual,
            apr: apr,
            holdingPeriod: holdingPeriod,
            minProcessingPercent: minProcessingPercent,
            feeFraction: feeFraction
        });

        vm.startBroadcast();

        // 1. Deploy StrategyKeeper — constructor assigns all roles:
        //    admin  -> DEFAULT_ADMIN_ROLE, CONFIG_MANAGER_ROLE, PAUSER_ROLE
        //    deployer -> INITIALIZER_ROLE (revoked after initialize)
        //    pauser -> PAUSER_ROLE
        //    processor -> KEEPER_ROLE, POWER_KEEPER_ROLE
        keeper = new StrategyKeeper(admin, deployer, pauser, processor);
        console.log("StrategyKeeper:", address(keeper));

        // 2. Initialize with config (deployer's INITIALIZER_ROLE is revoked after this call)
        keeper.initialize(config);

        vm.stopBroadcast();

        // Save deployment to JSON
        _saveDeployment(admin, config);

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("StrategyKeeper:", address(keeper));
        console.log("");
        console.log("=== Configuration ===");
        console.log("Vault (ynRWAx):", config.vault);
        console.log("Target Strategy:", config.targetStrategy);
        console.log("Safe:", config.safe);
        console.log("Fee Wallet:", config.feeWallet);
        console.log("Stream Receiver (Rewards Sweeper):", config.streamReceiver);
        console.log("Borrower:", config.borrower);
        console.log("");
        console.log("=== Roles ===");
        console.log("Admin:", admin);
        console.log("Pauser:", pauser);
        console.log("Processor:", processor);
        console.log("");
        console.log("=== Required Manual Steps ===");
        console.log("1. Enable StrategyKeeper as a module on the Safe:", address(keeper));
        console.log("   - Execute: Safe.enableModule(keeperAddress)");
        console.log("2. Grant PROCESSOR_ROLE to StrategyKeeper on vault");
        console.log("");
        console.log("Deployment saved to: deployments/keeper-deployment.json");
    }

    function _saveDeployment(address admin, IStrategyKeeper.KeeperConfig memory config) internal {
        string memory obj = "deployment";

        // Deployed contract
        vm.serializeAddress(obj, "keeper", address(keeper));
        vm.serializeAddress(obj, "admin", admin);

        // Configuration addresses
        vm.serializeAddress(obj, "vault", config.vault);
        vm.serializeAddress(obj, "targetStrategy", config.targetStrategy);
        vm.serializeAddress(obj, "safe", config.safe);
        vm.serializeAddress(obj, "baseAsset", config.baseAsset);
        vm.serializeAddress(obj, "borrower", config.borrower);
        vm.serializeAddress(obj, "feeWallet", config.feeWallet);
        vm.serializeAddress(obj, "streamReceiver", config.streamReceiver);
        vm.serializeAddress(obj, "sablier", config.sablier);

        // Configuration values
        vm.serializeUint(obj, "minThreshold", config.minThreshold);
        vm.serializeUint(obj, "minResidual", config.minResidual);
        vm.serializeUint(obj, "apr", config.apr);
        vm.serializeUint(obj, "holdingPeriod", config.holdingPeriod);
        vm.serializeUint(obj, "minProcessingPercent", config.minProcessingPercent);
        vm.serializeUint(obj, "feeFraction", config.feeFraction);

        // Metadata
        vm.serializeUint(obj, "chainId", block.chainid);
        string memory json = vm.serializeUint(obj, "deploymentTimestamp", block.timestamp);

        vm.writeJson(json, "deployments/keeper-deployment.json");
    }
}
