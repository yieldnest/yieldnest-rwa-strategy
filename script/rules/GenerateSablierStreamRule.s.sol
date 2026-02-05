// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {SablierRules} from "@script/rules/SablierRules.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @title GenerateSablierStreamRule
/// @notice Script to generate and set the Sablier createWithTimestampsLL rule on a vault
/// @dev Run with: forge script script/rules/GenerateSablierStreamRule.s.sol
contract GenerateSablierStreamRule is Script {
    function run() public {
        console.log("=== Generate Sablier Stream Creation Rule ===");
        console.log("");
        console.log("Using Sablier LockupLinear:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("");

        address vault = Prompt.forAddress("Enter vault address");
        address validatorAddress = Prompt.forAddress("Enter validator address");

        console.log("");
        console.log("Configuration:");
        console.log("  Vault:", vault);
        console.log("  Sablier Contract:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("  Validator:", validatorAddress);

        SablierRules.RuleParams memory ruleParams = SablierRules.getCreateStreamRuleWithValidator(
            MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, IValidator(validatorAddress)
        );

        console.log("");
        console.log("Generated Rule:");
        console.log("  Contract Address:", ruleParams.contractAddress);
        console.log("  Function Selector:", vm.toString(ruleParams.funcSig));
        console.log("  Is Active:", ruleParams.rule.isActive);
        console.log("  Validator:", address(ruleParams.rule.validator));
        console.log("  Param Rules Count:", ruleParams.rule.paramRules.length);

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
