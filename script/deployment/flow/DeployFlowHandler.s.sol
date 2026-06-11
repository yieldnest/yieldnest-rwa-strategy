// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {FlowHandler} from "@src/FlowHandler.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @notice Deploy FlowHandler implementation + proxy and initialize it for a target stream.
contract DeployFlowHandler is Script {
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

        uint256 streamId = _promptUintWithDefault("Stream ID", MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID);
        address admin = _promptAddressWithDefault("FlowHandler admin", new MainnetStrategyActors().ADMIN());
        address proxyAdmin = _promptAddressWithDefault("Proxy admin", new MainnetStrategyActors().ADMIN());
        uint256 apr = _promptUintWithDefault("APR (1e18 = 100%)", DEFAULT_APR);
        uint256 holdingPeriod = _promptUintWithDefault("Holding period (seconds)", DEFAULT_HOLDING_PERIOD);
        uint128 maxRateDelta = uint128(_promptUintWithDefault("Max rate delta (0 = unlimited)", 0));
        uint128 maxRate = uint128(_promptUintWithDefault("Max rate (0 = unlimited)", 0));
        uint256 feeFraction = _promptUintWithDefault("Fee fraction", DEFAULT_FEE_FRACTION);

        FlowHandler.InitParams memory params = FlowHandler.InitParams({
            admin: admin,
            safe: new MainnetStrategyActors().SAFE(),
            safeGuard: 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e,
            flow: MainnetKeeperContracts.SABLIER_FLOW,
            streamId: streamId,
            token: MainnetKeeperContracts.USDC,
            streamRecipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            apr: apr,
            holdingPeriod: holdingPeriod,
            maxRateDelta: maxRateDelta,
            maxRate: maxRate,
            borrower: MainnetKeeperContracts.BORROWER,
            feeWallet: MainnetKeeperContracts.FEE_WALLET,
            feeFraction: feeFraction
        });

        vm.startBroadcast();
        implementation = new FlowHandler();
        proxy = new TransparentUpgradeableProxy(
            address(implementation), proxyAdmin, abi.encodeCall(FlowHandler.initialize, (params))
        );
        vm.stopBroadcast();

        handler = FlowHandler(address(proxy));

        console2.log("implementation", address(implementation));
        console2.log("proxy", address(proxy));
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
