// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {FlowStrategyKeeper, IFlowStrategyKeeper} from "@src/FlowStrategyKeeper.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @notice Deploy and initialize FlowStrategyKeeper.
contract DeployFlowKeeper is Script {
    uint256 internal constant DEFAULT_MIN_THRESHOLD = 200_000e6;
    uint256 internal constant DEFAULT_MIN_RESIDUAL = 1_000e6;
    uint256 internal constant DEFAULT_MIN_PROCESSING_PERCENT = 0.01e18;
    uint256 internal constant DEFAULT_MAX_PROCESSING_PERCENT = 0.01e18;

    function run() external returns (FlowStrategyKeeper keeper) {
        console2.log("=== Deploy FlowStrategyKeeper ===");
        console2.log("vault", MainnetKeeperContracts.YNRWAX);
        console2.log("targetStrategy", MainnetKeeperContracts.FLEX_STRATEGY);
        console2.log("safe", new MainnetStrategyActors().SAFE());
        console2.log("baseAsset", MainnetKeeperContracts.USDC);

        address admin = _promptAddressWithDefault("Admin", new MainnetStrategyActors().ADMIN());
        address configManager = _promptAddressWithDefault("Config manager", new MainnetStrategyActors().ADMIN());
        address initializer = _promptAddressWithDefault("Initializer", vm.addr(vm.envUint("PRIVATE_KEY")));
        address pauser = _promptAddressWithDefault("Pauser", new MainnetStrategyActors().PAUSER());
        address processor =
            _promptAddressWithDefault("Processor / power keeper", new MainnetStrategyActors().PROCESSOR());
        address flowHandler = Prompt.forAddress("FlowHandler proxy");

        IFlowStrategyKeeper.FlowKeeperConfig memory cfg = IFlowStrategyKeeper.FlowKeeperConfig({
            vault: MainnetKeeperContracts.YNRWAX,
            targetStrategy: MainnetKeeperContracts.FLEX_STRATEGY,
            safe: new MainnetStrategyActors().SAFE(),
            baseAsset: MainnetKeeperContracts.USDC,
            flowHandler: flowHandler,
            minThreshold: _promptUintWithDefault("minThreshold", DEFAULT_MIN_THRESHOLD),
            minResidual: _promptUintWithDefault("minResidual", DEFAULT_MIN_RESIDUAL),
            minProcessingPercent: _promptUintWithDefault("minProcessingPercent", DEFAULT_MIN_PROCESSING_PERCENT),
            maxProcessingPercent: _promptUintWithDefault("maxProcessingPercent", DEFAULT_MAX_PROCESSING_PERCENT)
        });

        vm.startBroadcast();
        keeper = new FlowStrategyKeeper(admin, configManager, initializer, pauser, processor);
        keeper.initialize(cfg);
        vm.stopBroadcast();

        console2.log("keeper", address(keeper));
    }

    function _promptAddressWithDefault(string memory label, address defaultValue) internal returns (address) {
        string memory input = Prompt.forString(string.concat(label, " (blank = default)"));
        if (bytes(input).length == 0) return defaultValue;
        return vm.parseAddress(input);
    }

    function _promptUintWithDefault(string memory label, uint256 defaultValue) internal returns (uint256) {
        string memory input = Prompt.forString(string.concat(label, " (blank = default)"));
        if (bytes(input).length == 0) return defaultValue;
        return vm.parseUint(input);
    }
}
