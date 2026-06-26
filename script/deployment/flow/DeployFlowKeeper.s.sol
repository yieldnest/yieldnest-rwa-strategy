// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {stdJson} from "forge-std/StdJson.sol";

import {FlowStrategyKeeper, IFlowStrategyKeeper} from "@src/FlowStrategyKeeper.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {FlowDeploymentFiles} from "@script/deployment/flow/FlowDeploymentFiles.sol";

/// @notice Deploy and initialize FlowStrategyKeeper.
contract DeployFlowKeeper is FlowDeploymentFiles {
    using stdJson for string;

    uint256 internal constant DEFAULT_MIN_THRESHOLD = 200_000e6;
    uint256 internal constant DEFAULT_MIN_RESIDUAL = 1_000e6;
    uint256 internal constant DEFAULT_MIN_PROCESSING_PERCENT = 0.01e18;
    uint256 internal constant DEFAULT_MAX_PROCESSING_PERCENT = 0.01e18;
    error MissingFlowHandlerProxy();

    function run() external returns (FlowStrategyKeeper keeper) {
        console2.log("=== Deploy FlowStrategyKeeper ===");
        console2.log("vault", MainnetKeeperContracts.YNRWAX);
        console2.log("targetStrategy", MainnetKeeperContracts.FLEX_STRATEGY);
        console2.log("safe", new MainnetStrategyActors().SAFE());
        console2.log("baseAsset", MainnetKeeperContracts.USDC);

        address flowHandler = vm.envOr("FLOW_HANDLER_PROXY", address(0));
        if (flowHandler == address(0)) revert MissingFlowHandlerProxy();

        IFlowStrategyKeeper.FlowKeeperConfig memory cfg = IFlowStrategyKeeper.FlowKeeperConfig({
            vault: MainnetKeeperContracts.YNRWAX,
            targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
            safe: new MainnetStrategyActors().SAFE(),
            baseAsset: MainnetKeeperContracts.USDC,
            flowHandler: flowHandler,
            minThreshold: DEFAULT_MIN_THRESHOLD,
            minResidual: DEFAULT_MIN_RESIDUAL,
            minProcessingPercent: DEFAULT_MIN_PROCESSING_PERCENT,
            maxProcessingPercent: DEFAULT_MAX_PROCESSING_PERCENT
        });

        vm.startBroadcast();
        (, address initializer,) = vm.readCallers();
        keeper = new FlowStrategyKeeper(
            new MainnetStrategyActors().ADMIN(),
            new MainnetStrategyActors().ADMIN(),
            initializer,
            new MainnetStrategyActors().PAUSER(),
            new MainnetStrategyActors().PROCESSOR()
        );
        keeper.initialize(cfg);
        vm.stopBroadcast();

        console2.log("keeper", address(keeper));

        string memory objectKey = "flowKeeperDeployment";
        vm.serializeUint(objectKey, "chainId", block.chainid);
        vm.serializeUint(objectKey, "deploymentTimestamp", block.timestamp);
        vm.serializeAddress(objectKey, "admin", new MainnetStrategyActors().ADMIN());
        vm.serializeAddress(objectKey, "configManager", new MainnetStrategyActors().ADMIN());
        vm.serializeAddress(objectKey, "initializer", initializer);
        vm.serializeAddress(objectKey, "pauser", new MainnetStrategyActors().PAUSER());
        vm.serializeAddress(objectKey, "processor", new MainnetStrategyActors().PROCESSOR());
        vm.serializeAddress(objectKey, "vault", MainnetKeeperContracts.YNRWAX);
        vm.serializeAddress(objectKey, "targetStrategy", MainnetKeeperContracts.FLEX_STRATEGY);
        vm.serializeAddress(objectKey, "safe", new MainnetStrategyActors().SAFE());
        vm.serializeAddress(objectKey, "baseAsset", MainnetKeeperContracts.USDC);
        vm.serializeAddress(objectKey, "flowHandler", flowHandler);
        vm.serializeUint(objectKey, "minThreshold", DEFAULT_MIN_THRESHOLD);
        vm.serializeUint(objectKey, "minResidual", DEFAULT_MIN_RESIDUAL);
        vm.serializeUint(objectKey, "minProcessingPercent", DEFAULT_MIN_PROCESSING_PERCENT);
        vm.serializeUint(objectKey, "maxProcessingPercent", DEFAULT_MAX_PROCESSING_PERCENT);
        string memory json = vm.serializeAddress(objectKey, "keeper", address(keeper));
        vm.writeJson(json, KEEPER_PATH);
        console2.log("deploymentFile", KEEPER_PATH);
    }
}
