// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {SablierRules} from "@script/rules/SablierRules.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {Prompt} from "@script/utils/Prompt.sol";

/// @title GenerateSablierStreamRule
/// @notice Script to generate and set the Sablier createWithTimestampsLL rules on a vault
/// @dev Generates calldata for both single stream (LockupLinear) and batch stream (BatchLockup) rules
///      Run with: forge script script/rules/GenerateSablierStreamRule.s.sol
contract GenerateSablierStreamRule is Script {
    function run() public {
        console.log("=== Generate Sablier Stream Creation Rules ===");
        console.log("");
        console.log("Using Sablier LockupLinear:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("Using Sablier BatchLockup:", MainnetKeeperContracts.SABLIER_BATCH_LOCKUP);
        console.log("");

        address vault = Prompt.forAddress("Enter vault address");
        address validatorAddress = Prompt.forAddress("Enter validator address");

        console.log("");
        console.log("Configuration:");
        console.log("  Vault:", vault);
        console.log("  Sablier LockupLinear:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("  Sablier BatchLockup:", MainnetKeeperContracts.SABLIER_BATCH_LOCKUP);
        console.log("  Validator:", validatorAddress);

        // Generate and log both rules
        SablierRules.RuleParams memory singleRuleParams = SablierRules.getCreateStreamRuleWithValidator(
            MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, IValidator(validatorAddress)
        );
        SablierRules.RuleParams memory batchRuleParams = SablierRules.getCreateBatchStreamRuleWithValidator(
            MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, IValidator(validatorAddress)
        );

        _logRule("Single Stream Rule (LockupLinear)", singleRuleParams);
        _logRule("Batch Stream Rule (BatchLockup)", batchRuleParams);

        // Generate combined calldata
        _logCombinedCalldata(vault, singleRuleParams, batchRuleParams);

        // Generate individual calldata
        _logIndividualCalldata(vault, "single stream rule", singleRuleParams);
        _logIndividualCalldata(vault, "batch stream rule", batchRuleParams);
    }

    function _logRule(string memory label, SablierRules.RuleParams memory ruleParams) internal pure {
        console.log("");
        console.log(string.concat("--- ", label, " ---"));
        console.log("  Contract Address:", ruleParams.contractAddress);
        console.log("  Is Active:", ruleParams.rule.isActive);
        console.log("  Validator:", address(ruleParams.rule.validator));
        console.log("  Param Rules Count:", ruleParams.rule.paramRules.length);
    }

    function _logCombinedCalldata(
        address vault,
        SablierRules.RuleParams memory singleRule,
        SablierRules.RuleParams memory batchRule
    ) internal pure {
        address[] memory targets = new address[](2);
        bytes4[] memory funcSigs = new bytes4[](2);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](2);

        targets[0] = singleRule.contractAddress;
        funcSigs[0] = singleRule.funcSig;
        rules[0] = singleRule.rule;

        targets[1] = batchRule.contractAddress;
        funcSigs[1] = batchRule.funcSig;
        rules[1] = batchRule.rule;

        bytes memory callData = abi.encodeCall(IVault.setProcessorRules, (targets, funcSigs, rules));

        console.log("");
        console.log("=== Calldata for setProcessorRules (both rules) ===");
        console.log("Target:", vault);
        console.logBytes(callData);
    }

    function _logIndividualCalldata(address vault, string memory label, SablierRules.RuleParams memory ruleParams)
        internal
        pure
    {
        address[] memory targets = new address[](1);
        bytes4[] memory funcSigs = new bytes4[](1);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](1);

        targets[0] = ruleParams.contractAddress;
        funcSigs[0] = ruleParams.funcSig;
        rules[0] = ruleParams.rule;

        bytes memory callData = abi.encodeCall(IVault.setProcessorRules, (targets, funcSigs, rules));

        console.log("");
        console.log(string.concat("=== Calldata for ", label, " only ==="));
        console.log("Target:", vault);
        console.logBytes(callData);
    }
}
