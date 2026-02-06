// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {StrategyKeeperSablierValidator} from "src/validators/StrategyKeeperSablierValidator.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";
import {IAccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";

/// @title DeploySablierValidator
/// @notice Deploys the StrategyKeeperSablierValidator for ynRWAx SPV1 strategy
/// @dev Run with: forge script script/deployment/DeploySablierValidator.s.sol --rpc-url $RPC_URL --broadcast
contract DeploySablierValidator is Script {
    function run() public {
        console.log("=== Deploy StrategyKeeperSablierValidator ===");
        console.log("");

        // Fetch safe from FlexStrategy -> AccountingModule -> safe
        FlexStrategy flexStrategy = FlexStrategy(payable(MainnetKeeperContracts.FLEX_STRATEGY));
        IAccountingModule accountingModule = flexStrategy.accountingModule();
        address safe = accountingModule.safe();

        address token = MainnetKeeperContracts.USDC;
        address rewardsSweeper = MainnetKeeperContracts.REWARDS_SWEEPER;

        console.log("Configuration:");
        console.log("  FlexStrategy:", MainnetKeeperContracts.FLEX_STRATEGY);
        console.log("  AccountingModule:", address(accountingModule));
        console.log("  Safe:", safe);
        console.log("  Token (USDC):", token);
        console.log("  Sablier LockupLinear:", MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        console.log("  Allowed Recipient (RewardsSweeper):", rewardsSweeper);

        address[] memory allowedRecipients = new address[](1);
        allowedRecipients[0] = rewardsSweeper;

        vm.startBroadcast();

        StrategyKeeperSablierValidator validator = new StrategyKeeperSablierValidator(safe, token, allowedRecipients);

        vm.stopBroadcast();

        console.log("");
        console.log("=== Deployment Complete ===");
        console.log("StrategyKeeperSablierValidator:", address(validator));
        console.log("");
        console.log("Validator configuration:");
        console.log("  safe():", validator.safe());
        console.log("  token():", validator.token());
        console.log("  isAllowedRecipient(rewardsSweeper):", validator.isAllowedRecipient(rewardsSweeper));
        console.log("");
        console.log("Use this validator address in GenerateSablierStreamRule script");
    }
}
