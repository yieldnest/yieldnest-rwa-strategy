// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";

import {ISafeGuard} from "@src/interfaces/ISafeGuard.sol";
import {ISablierFlow} from "@src/interfaces/sablier/ISablierFlow.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {FlowDeploymentFiles} from "@script/deployment/flow/FlowDeploymentFiles.sol";

/// @notice Configure the SafeGuard processor rules required by FlowHandler.
contract ConfigureFlowSafeGuard is FlowDeploymentFiles {
    using stdJson for string;

    error MissingFlowValidator();

    function run() external {
        address safe = new MainnetStrategyActors().SAFE();
        address validator = vm.envOr("FLOW_VALIDATOR", address(0));
        address guardAddress = 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e;
        if (validator == address(0)) revert MissingFlowValidator();

        console2.log("=== Configure Flow SafeGuard Rules ===");
        console2.log("guard", guardAddress);
        console2.log("safe", safe);
        console2.log("validator", validator);

        address[] memory targets = new address[](4);
        bytes4[] memory selectors = new bytes4[](4);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](4);

        targets[0] = MainnetKeeperContracts.USDC;
        selectors[0] = IERC20.approve.selector;
        rules[0] = _approveRule(MainnetKeeperContracts.SABLIER_FLOW);

        targets[1] = MainnetKeeperContracts.SABLIER_FLOW;
        selectors[1] = ISablierFlow.deposit.selector;
        rules[1] = _depositRule(safe, MainnetKeeperContracts.REWARDS_SWEEPER);

        targets[2] = MainnetKeeperContracts.SABLIER_FLOW;
        selectors[2] = ISablierFlow.adjustRatePerSecond.selector;
        rules[2] = _adjustRule(validator);

        targets[3] = MainnetKeeperContracts.USDC;
        selectors[3] = IERC20.transfer.selector;
        rules[3] = _transferRule(MainnetKeeperContracts.BORROWER, MainnetKeeperContracts.FEE_WALLET);

        bytes memory callData = abi.encodeCall(ISafeGuard.setProcessorRules, (targets, selectors, rules));

        console2.log("Submit this call manually:");
        console2.log("target", guardAddress);
        console2.logBytes(callData);

        string memory objectKey = "flowSafeGuardConfig";
        vm.serializeUint(objectKey, "chainId", block.chainid);
        vm.serializeUint(objectKey, "generatedTimestamp", block.timestamp);
        vm.serializeAddress(objectKey, "guard", guardAddress);
        vm.serializeAddress(objectKey, "safe", safe);
        vm.serializeAddress(objectKey, "validator", validator);
        vm.serializeAddress(objectKey, "flow", MainnetKeeperContracts.SABLIER_FLOW);
        string memory json = vm.serializeBytes(objectKey, "calldata", callData);
        vm.writeJson(json, SAFEGUARD_PATH);
        console2.log("deploymentFile", SAFEGUARD_PATH);
    }

    function _approveRule(address spender) internal pure returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);
        address[] memory spenders = new address[](1);
        spenders[0] = spender;

        paramRules[0] = IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: spenders});
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});
    }

    function _depositRule(address safe, address recipient) internal pure returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](4);
        address[] memory safeAllowList = new address[](1);
        address[] memory recipientAllowList = new address[](1);
        safeAllowList[0] = safe;
        recipientAllowList[0] = recipient;

        paramRules[0] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});
        paramRules[2] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: safeAllowList});
        paramRules[3] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: recipientAllowList});

        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});
    }

    function _adjustRule(address validator) internal pure returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](0);
        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(validator)});
    }

    function _transferRule(address borrower, address feeWallet)
        internal
        pure
        returns (IVault.FunctionRule memory rule)
    {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);
        address[] memory recipients = new address[](2);
        recipients[0] = borrower;
        recipients[1] = feeWallet;

        paramRules[0] = IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: recipients});
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});
    }
}
