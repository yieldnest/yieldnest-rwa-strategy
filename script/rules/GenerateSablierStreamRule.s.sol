// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {SablierRules} from "@script/rules/SablierRules.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @title GenerateSablierStreamRule
/// @notice Script to generate the Sablier approve + createWithTimestampsLL rules on a vault
/// @dev Run with: forge script script/rules/GenerateSablierStreamRule.s.sol
contract GenerateSablierStreamRule is Script {
    function run() public {
        console.log("=== Generate Sablier Stream Creation Rules ===");
        console.log("");
        console.log("Using Sablier LockupLinear:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("Using USDC:", MainnetKeeperContracts.USDC);
        console.log("");

        address vault = Prompt.forAddress("Enter vault address");
        address validatorAddress = Prompt.forAddress("Enter validator address");

        console.log("");
        console.log("Configuration:");
        console.log("  Vault:", vault);
        console.log("  USDC:", MainnetKeeperContracts.USDC);
        console.log("  Sablier Contract:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("  Validator:", validatorAddress);

        // Rule 1: Approve USDC to Sablier
        SablierRules.RuleParams memory approveRuleParams =
            SablierRules.getApproveRule(MainnetKeeperContracts.USDC, MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);

        console.log("");
        console.log("Generated Approve Rule:");
        console.log("  Contract Address:", approveRuleParams.contractAddress);
        console.log("  Function Selector:", vm.toString(approveRuleParams.funcSig));
        console.log("  Is Active:", approveRuleParams.rule.isActive);
        console.log("  Param Rules Count:", approveRuleParams.rule.paramRules.length);

        // Rule 2: Create stream with validator
        SablierRules.RuleParams memory createStreamRuleParams = SablierRules.getCreateStreamRuleWithValidator(
            MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, IValidator(validatorAddress)
        );

        console.log("");
        console.log("Generated Create Stream Rule:");
        console.log("  Contract Address:", createStreamRuleParams.contractAddress);
        console.log("  Function Selector:", vm.toString(createStreamRuleParams.funcSig));
        console.log("  Is Active:", createStreamRuleParams.rule.isActive);
        console.log("  Validator:", address(createStreamRuleParams.rule.validator));
        console.log("  Param Rules Count:", createStreamRuleParams.rule.paramRules.length);

        // Build arrays for setProcessorRules (2 rules)
        address[] memory targets = new address[](2);
        bytes4[] memory funcSigs = new bytes4[](2);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](2);

        targets[0] = approveRuleParams.contractAddress;
        funcSigs[0] = approveRuleParams.funcSig;
        rules[0] = approveRuleParams.rule;

        targets[1] = createStreamRuleParams.contractAddress;
        funcSigs[1] = createStreamRuleParams.funcSig;
        rules[1] = createStreamRuleParams.rule;

        // Generate calldata for setProcessorRules
        bytes memory callData = abi.encodeCall(IVault.setProcessorRules, (targets, funcSigs, rules));

        console.log("");
        console.log("=== Calldata for setProcessorRules ===");
        console.log("Target: ", vault);
        console.logBytes(callData);
    }
}
