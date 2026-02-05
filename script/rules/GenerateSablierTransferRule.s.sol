// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {SablierRules} from "@script/rules/SablierRules.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @title GenerateSablierTransferRule
/// @notice Script to generate and set the Sablier stream NFT transfer rule on a vault
/// @dev Run with: forge script script/rules/GenerateSablierTransferRule.s.sol
contract GenerateSablierTransferRule is Script {
    function run() public {
        console.log("=== Generate Sablier Stream Transfer Rule ===");
        console.log("");
        console.log("Using Sablier LockupLinear:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("");

        address vault = Prompt.forAddress("Enter vault address");
        address from = Prompt.forAddress("Enter from address (stream owner, typically the vault)");
        address recipient = Prompt.forAddress("Enter allowed recipient address");

        console.log("");
        console.log("Configuration:");
        console.log("  Vault:", vault);
        console.log("  Sablier Contract:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("  From (stream owner):", from);
        console.log("  Allowed Recipient:", recipient);

        address[] memory allowedRecipients = new address[](1);
        allowedRecipients[0] = recipient;

        SablierRules.RuleParams memory ruleParams =
            SablierRules.getTransferStreamRule(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, from, allowedRecipients);

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

        if (!Prompt.forConfirmation("Set this rule on the vault?")) {
            console.log("Aborted.");
            return;
        }

        vm.startBroadcast();
        IVault(vault).setProcessorRule(ruleParams.contractAddress, ruleParams.funcSig, ruleParams.rule);
        vm.stopBroadcast();

        console.log("");
        console.log("Rule set successfully on vault!");
    }
}
