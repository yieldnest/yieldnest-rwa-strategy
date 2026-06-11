// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {FlowHandler} from "@src/FlowHandler.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {FlowDeploymentFiles} from "@script/deployment/flow/FlowDeploymentFiles.sol";

/// @notice Deploy FlowHandler implementation + proxy and initialize it for a target stream.
contract DeployFlowHandler is FlowDeploymentFiles {
    using stdJson for string;

    uint256 internal constant DEFAULT_APR = 0.11e18;
    uint256 internal constant DEFAULT_HOLDING_PERIOD = 28 days;
    uint256 internal constant DEFAULT_FEE_FRACTION = 10;

    function run()
        external
        returns (FlowHandler implementation, TransparentUpgradeableProxy proxy, FlowHandler handler)
    {
        console2.log("=== Deploy FlowHandler ===");
        console2.log("safe", new MainnetStrategyActors().SAFE());
        console2.log("safeGuard", 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e);
        console2.log("flow", MainnetKeeperContracts.SABLIER_FLOW);
        console2.log("default streamId", MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID);
        console2.log("token", MainnetKeeperContracts.USDC);
        console2.log("recipient", MainnetKeeperContracts.REWARDS_SWEEPER);

        FlowHandler.InitParams memory params = FlowHandler.InitParams({
            admin: new MainnetStrategyActors().ADMIN(),
            safe: new MainnetStrategyActors().SAFE(),
            safeGuard: 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e,
            flow: MainnetKeeperContracts.SABLIER_FLOW,
            streamId: MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID,
            token: MainnetKeeperContracts.USDC,
            streamRecipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            apr: DEFAULT_APR,
            holdingPeriod: DEFAULT_HOLDING_PERIOD,
            maxRateDelta: 0,
            maxRate: 0,
            borrower: MainnetKeeperContracts.BORROWER,
            feeWallet: MainnetKeeperContracts.FEE_WALLET,
            feeFraction: DEFAULT_FEE_FRACTION
        });

        vm.startBroadcast();
        implementation = new FlowHandler();
        proxy = new TransparentUpgradeableProxy(
            address(implementation),
            new MainnetStrategyActors().ADMIN(),
            abi.encodeCall(FlowHandler.initialize, (params))
        );
        vm.stopBroadcast();

        handler = FlowHandler(address(proxy));

        console2.log("implementation", address(implementation));
        console2.log("proxy", address(proxy));

        string memory objectKey = "flowHandlerDeployment";
        vm.serializeUint(objectKey, "chainId", block.chainid);
        vm.serializeUint(objectKey, "deploymentTimestamp", block.timestamp);
        vm.serializeAddress(objectKey, "admin", new MainnetStrategyActors().ADMIN());
        vm.serializeAddress(objectKey, "proxyAdmin", new MainnetStrategyActors().ADMIN());
        vm.serializeAddress(objectKey, "safe", new MainnetStrategyActors().SAFE());
        vm.serializeAddress(objectKey, "safeGuard", 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e);
        vm.serializeAddress(objectKey, "flow", MainnetKeeperContracts.SABLIER_FLOW);
        vm.serializeUint(objectKey, "streamId", MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID);
        vm.serializeAddress(objectKey, "token", MainnetKeeperContracts.USDC);
        vm.serializeAddress(objectKey, "streamRecipient", MainnetKeeperContracts.REWARDS_SWEEPER);
        vm.serializeUint(objectKey, "apr", DEFAULT_APR);
        vm.serializeUint(objectKey, "holdingPeriod", DEFAULT_HOLDING_PERIOD);
        vm.serializeUint(objectKey, "maxRateDelta", 0);
        vm.serializeUint(objectKey, "maxRate", 0);
        vm.serializeAddress(objectKey, "borrower", MainnetKeeperContracts.BORROWER);
        vm.serializeAddress(objectKey, "feeWallet", MainnetKeeperContracts.FEE_WALLET);
        vm.serializeUint(objectKey, "feeFraction", DEFAULT_FEE_FRACTION);
        vm.serializeAddress(objectKey, "implementation", address(implementation));
        string memory json = vm.serializeAddress(objectKey, "proxy", address(proxy));
        vm.writeJson(json, HANDLER_PATH);
        console2.log("deploymentFile", HANDLER_PATH);
    }
}
