// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {SablierRules} from "@script/rules/SablierRules.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

/// @title GenerateTransferRule
/// @notice Script to generate and set an ERC20 transfer rule on a vault
/// @dev Run with: forge script script/rules/GenerateTransferRule.s.sol
contract GenerateTransferRule is Script {
    address constant BORROWER = MainnetKeeperContracts.BORROWER;
    address constant FEE_RECEIVER = MainnetKeeperContracts.FEE_WALLET;

    function run() public {
        console.log("=== Generate ERC20 Transfer Rule ===");
        console.log("");

        console.log("Configuration:");
        console.log("  Token:", MainnetKeeperContracts.USDC);
        console.log("  BORROWER:", BORROWER);
        console.log("  FEE_RECEIVER:", FEE_RECEIVER);

        address[] memory allowedRecipients = new address[](2);
        allowedRecipients[0] = BORROWER;
        allowedRecipients[1] = FEE_RECEIVER;

        SablierRules.RuleParams memory ruleParams =
            SablierRules.getTransferRule(MainnetKeeperContracts.USDC, allowedRecipients);

        console.log("");
        console.log("Generated Rule:");
        console.log("  Contract Address:", ruleParams.contractAddress);
        console.log("  Function Selector:", vm.toString(ruleParams.funcSig));
        console.log("  Is Active:", ruleParams.rule.isActive);
        console.log("  Param Rules Count:", ruleParams.rule.paramRules.length);

        // Log param rule details
        for (uint256 i = 0; i < ruleParams.rule.paramRules.length; i++) {
            console.log("");
            console.log("  Param Rule", i, ":");
            console.log("    Type:", uint256(ruleParams.rule.paramRules[i].paramType));
            console.log("    Is Array:", ruleParams.rule.paramRules[i].isArray);
            console.log("    Allowlist Length:", ruleParams.rule.paramRules[i].allowList.length);
            for (uint256 j = 0; j < ruleParams.rule.paramRules[i].allowList.length; j++) {
                console.log("      Allowed:", ruleParams.rule.paramRules[i].allowList[j]);
            }
        }

        // Build arrays for setProcessorRules
        address[] memory targets = new address[](1);
        bytes4[] memory funcSigs = new bytes4[](1);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](1);

        targets[0] = ruleParams.contractAddress;
        funcSigs[0] = ruleParams.funcSig;
        rules[0] = ruleParams.rule;

        // Generate calldata for setProcessorRules
        bytes memory callData = abi.encodeCall(IVault.setProcessorRules, (targets, funcSigs, rules));

        console.log("");
        console.log("=== Calldata for setProcessorRules ===");
        console.log("Target: ", MainnetKeeperContracts.FLEX_STRATEGY);
        console.logBytes(callData);
    }
}
