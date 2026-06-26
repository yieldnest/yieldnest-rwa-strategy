// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";

abstract contract FlowDeploymentFiles is Script {
    using stdJson for string;

    string internal constant VALIDATOR_PATH = "./deployments/flow-validator-deployment.json";
    string internal constant HANDLER_PATH = "./deployments/flow-handler-deployment.json";
    string internal constant KEEPER_PATH = "./deployments/flow-keeper-deployment.json";
    string internal constant SAFEGUARD_PATH = "./deployments/flow-safeguard-config.json";

    function _writeJson(string memory objectKey, string memory path) internal {
        string memory json = vm.serializeString(objectKey, "kind", objectKey);
        vm.writeJson(json, path);
    }

    function _readJsonOrEmpty(string memory path) internal view returns (string memory) {
        if (!vm.exists(path)) return "";
        return vm.readFile(path);
    }
}
