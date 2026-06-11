// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {FlowStrategyKeeper, IFlowStrategyKeeper} from "@src/FlowStrategyKeeper.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";

/// @notice Deploy and initialize FlowStrategyKeeper.
contract DeployFlowKeeper is Script {
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
        keeper = new FlowStrategyKeeper(
            new MainnetStrategyActors().ADMIN(),
            new MainnetStrategyActors().ADMIN(),
            vm.addr(vm.envUint("PRIVATE_KEY")),
            new MainnetStrategyActors().PAUSER(),
            new MainnetStrategyActors().PROCESSOR()
        );
        keeper.initialize(cfg);
        vm.stopBroadcast();

        console2.log("keeper", address(keeper));
    }
}
