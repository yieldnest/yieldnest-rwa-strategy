// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

/// @title DeployKeeper
/// @notice Deployment script for StrategyKeeper (module-based execution)
contract DeployKeeper is Script {
    // Deployment parameters (customize these before deployment)
    uint256 public minThreshold = 10_000e6; // 10,000 USDC minimum to trigger allocation
    uint256 public minResidual = 1_000e6; // Keep 1,000 USDC in Safe
    uint256 public apr = 0.121e18; // 12.1% APR
    uint256 public holdingPeriod = 28 days;
    uint256 public minProcessingPercent = 0.01e18; // 1%
    uint256 public feeFraction = 11; // 1/11 to fee wallet, 10/11 to stream

    StrategyKeeper public keeperImplementation;
    StrategyKeeper public keeper;

    function run() external {
        MainnetStrategyActors actors = new MainnetStrategyActors();
        address admin = actors.ADMIN();
        address deployer = msg.sender;

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

        // 1. Deploy StrategyKeeper implementation
        keeperImplementation = new StrategyKeeper();
        console.log("StrategyKeeper implementation:", address(keeperImplementation));

        // 2. Deploy proxy with deployer as initial admin (so we can transfer roles)
        bytes memory initData = abi.encodeCall(StrategyKeeper.initialize, (deployer, config));

        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(keeperImplementation), admin, initData);
        keeper = StrategyKeeper(address(proxy));
        console.log("StrategyKeeper proxy:", address(keeper));
        console.log("Proxy admin:", admin);

        // 3. Transfer roles to admin and renounce deployer roles
        bytes32 defaultAdminRole = keeper.DEFAULT_ADMIN_ROLE();
        bytes32 configManagerRole = keeper.CONFIG_MANAGER_ROLE();

        // Grant roles to admin
        keeper.grantRole(defaultAdminRole, admin);
        keeper.grantRole(configManagerRole, admin);

        // Renounce deployer roles
        keeper.renounceRole(configManagerRole, deployer);
        keeper.renounceRole(defaultAdminRole, deployer);

        vm.stopBroadcast();

        // Save deployment to JSON
        _saveDeployment(admin, config);

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("StrategyKeeper Implementation:", address(keeperImplementation));
        console.log("StrategyKeeper Proxy:", address(keeper));
        console.log("");
        console.log("=== Configuration ===");
        console.log("Vault (ynRWAx):", config.vault);
        console.log("Target Strategy:", config.targetStrategy);
        console.log("Safe:", config.safe);
        console.log("Fee Wallet:", config.feeWallet);
        console.log("Stream Receiver (Rewards Sweeper):", config.streamReceiver);
        console.log("Borrower:", config.borrower);
        console.log("");
        console.log("=== Roles Transferred ===");
        console.log("Admin:", admin);
        console.log("Deployer renounced all roles");
        console.log("");
        console.log("=== Required Manual Steps ===");
        console.log("1. Enable StrategyKeeper as a module on the Safe:", address(keeper));
        console.log("   - Execute: Safe.enableModule(keeperAddress)");
        console.log("2. Grant PROCESSOR_ROLE to StrategyKeeper on vault");
        console.log("3. Grant KEEPER_ROLE to keeper bot address");
        console.log("");
        console.log("Deployment saved to: deployments/keeper-deployment.json");
    }

    function _saveDeployment(address admin, IStrategyKeeper.KeeperConfig memory config) internal {
        string memory obj = "deployment";

        // Deployed contracts
        vm.serializeAddress(obj, "keeperImplementation", address(keeperImplementation));
        vm.serializeAddress(obj, "keeperProxy", address(keeper));
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
