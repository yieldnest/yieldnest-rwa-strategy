// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {FlowValidator} from "@src/validators/FlowValidator.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";

/// @notice Deploy a FlowValidator for a single stream on mainnet.
contract DeployFlowValidator is Script {
    uint8 internal constant TOKEN_DECIMALS = 6;
    uint256 internal constant DEFAULT_MAX_APR = 0.115e18;

    function run() external returns (FlowValidator validator) {
        console2.log("=== Deploy FlowValidator ===");
        console2.log("flow", MainnetKeeperContracts.SABLIER_FLOW);
        console2.log("vault", MainnetKeeperContracts.YNRWAX);
        console2.log("default streamId", MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID);
        console2.log("default admin", new MainnetStrategyActors().ADMIN());
        console2.log("default maxApr", DEFAULT_MAX_APR);

        FlowValidator.StreamLimit[] memory limits = new FlowValidator.StreamLimit[](1);
        limits[0] = FlowValidator.StreamLimit({
            streamId: MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID, maxApr: DEFAULT_MAX_APR
        });

        vm.startBroadcast();
        validator = new FlowValidator(
            MainnetKeeperContracts.SABLIER_FLOW,
            MainnetKeeperContracts.YNRWAX,
            TOKEN_DECIMALS,
            limits,
            new MainnetStrategyActors().ADMIN()
        );
        vm.stopBroadcast();

        console2.log("validator", address(validator));
    }
}
