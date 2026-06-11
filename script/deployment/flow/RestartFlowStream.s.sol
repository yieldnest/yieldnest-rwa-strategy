// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";

import {ISablierFlow, UD21x18} from "@src/interfaces/sablier/ISablierFlow.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @notice Print the calldata needed for the Safe to restart a Flow stream.
/// @dev The Safe is the stream sender, so production activation must be executed by the Safe.
contract RestartFlowStream is Script {
    uint128 internal constant DEFAULT_RATE = 32105201018518518;

    function run() external {
        console2.log("=== Restart Flow Stream ===");
        console2.log("flow", MainnetKeeperContracts.SABLIER_FLOW);
        console2.log("defaultRate", uint256(DEFAULT_RATE));

        uint256 streamId = Prompt.forUint("Stream ID");
        uint128 rate = uint128(_promptUintWithDefault("Rate (UD21x18 raw)", DEFAULT_RATE));

        bytes memory data = abi.encodeCall(ISablierFlow.restart, (streamId, UD21x18.wrap(rate)));

        console2.log("target", MainnetKeeperContracts.SABLIER_FLOW);
        console2.log("streamId", streamId);
        console2.log("rate", uint256(rate));
        console2.log("Submit this from the Safe as a direct contract call:");
        console2.logBytes(data);
    }

    function _promptUintWithDefault(string memory label, uint256 defaultValue) internal returns (uint256) {
        string memory input = Prompt.forString(string.concat(label, " (blank = default)"));
        if (bytes(input).length == 0) return defaultValue;
        return vm.parseUint(input);
    }
}
