// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @title GenerateEnableModuleRule
/// @notice Script to generate processor rules for enabling/disabling a module on a Gnosis Safe
/// @dev Run with: forge script script/rules/GenerateEnableModuleRule.s.sol
contract GenerateEnableModuleRule is Script {
    function run() public {
        console.log("=== Generate Enable/Disable Module Rule ===");
        console.log("");

        address vault = Prompt.forAddress("Enter vault address");
        address safe = Prompt.forAddress("Enter safe address");
        address module = Prompt.forAddress("Enter module address");

        console.log("");
        console.log("Configuration:");
        console.log("  Vault:", vault);
        console.log("  Safe:", safe);
        console.log("  Module:", module);

        address[] memory moduleAllowList = new address[](1);
        moduleAllowList[0] = module;

        // --- enableModule(address module) ---
        bytes4 enableSig = bytes4(keccak256("enableModule(address)"));

        IVault.ParamRule[] memory enableParams = new IVault.ParamRule[](1);
        enableParams[0] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: moduleAllowList});

        IVault.FunctionRule memory enableRule =
            IVault.FunctionRule({isActive: true, paramRules: enableParams, validator: IValidator(address(0))});

        // --- disableModule(address prevModule, address module) ---
        bytes4 disableSig = bytes4(keccak256("disableModule(address,address)"));

        IVault.ParamRule[] memory disableParams = new IVault.ParamRule[](2);
        // prevModule - any value (linked list pointer)
        disableParams[0] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});
        // module - must be in allowlist
        disableParams[1] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: moduleAllowList});

        IVault.FunctionRule memory disableRule =
            IVault.FunctionRule({isActive: true, paramRules: disableParams, validator: IValidator(address(0))});

        // --- Build combined calldata ---
        address[] memory targets = new address[](2);
        bytes4[] memory funcSigs = new bytes4[](2);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](2);

        targets[0] = safe;
        funcSigs[0] = enableSig;
        rules[0] = enableRule;

        targets[1] = safe;
        funcSigs[1] = disableSig;
        rules[1] = disableRule;

        bytes memory callData = abi.encodeCall(IVault.setProcessorRules, (targets, funcSigs, rules));

        console.log("");
        console.log("=== Calldata for setProcessorRules (enable + disable module) ===");
        console.log("Target:", vault);
        console.logBytes(callData);

        // --- Individual calldata ---
        _logIndividualCalldata(vault, "enableModule", safe, enableSig, enableRule);
        _logIndividualCalldata(vault, "disableModule", safe, disableSig, disableRule);
    }

    function _logIndividualCalldata(
        address vault,
        string memory label,
        address safe,
        bytes4 funcSig,
        IVault.FunctionRule memory rule
    ) internal pure {
        address[] memory targets = new address[](1);
        bytes4[] memory funcSigs = new bytes4[](1);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](1);

        targets[0] = safe;
        funcSigs[0] = funcSig;
        rules[0] = rule;

        bytes memory callData = abi.encodeCall(IVault.setProcessorRules, (targets, funcSigs, rules));

        console.log("");
        console.log(string.concat("=== Calldata for ", label, " only ==="));
        console.log("Target:", vault);
        console.logBytes(callData);
    }
}
