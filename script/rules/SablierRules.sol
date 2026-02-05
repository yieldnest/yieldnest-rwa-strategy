// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

/// @title SablierRules
/// @notice Library for generating processor rules for Sablier stream operations
/// @dev Used to configure vault processor rules for creating and transferring Sablier streams
library SablierRules {
    /// @notice Parameters for setting a processor rule
    /// @dev Same structure as SafeRules.RuleParams but defined locally to avoid import issues
    struct RuleParams {
        address contractAddress;
        bytes4 funcSig;
        IVault.FunctionRule rule;
    }

    /// @notice Get the rule for creating a Sablier stream with timestamps
    /// @param sablierContract The address of the Sablier LockupLinear contract
    /// @return RuleParams for createWithTimestampsLL function
    /// @dev The function signature is:
    ///      createWithTimestampsLL(CreateWithTimestamps calldata params, UnlockAmounts calldata unlockAmounts, uint40 cliffTime)
    ///      Since the params contain nested structs with addresses (sender, recipient, token),
    ///      we need to handle the ABI encoding carefully.
    ///      The params are ABI-encoded as a tuple, so we mark them as UINT256 to allow any value
    ///      (the actual validation is done by the Sablier contract itself).
    function getCreateStreamRule(address sablierContract) internal pure returns (RuleParams memory) {
        bytes4 funcSig = ISablierLockupLinear.createWithTimestampsLL.selector;

        // The function takes 3 parameters but they are complex structs
        // createWithTimestampsLL(CreateWithTimestamps, UnlockAmounts, uint40)
        // For safety, we don't restrict the parameters as they are complex nested structs
        // The Sablier contract itself will validate the parameters
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](0);

        IVault.FunctionRule memory rule =
            IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

        return RuleParams({contractAddress: sablierContract, funcSig: funcSig, rule: rule});
    }

    /// @notice Get the rule for approving tokens to Sablier
    /// @param tokenContract The address of the ERC20 token contract
    /// @param spender The address allowed to spend (typically Sablier contract)
    /// @return RuleParams for approve function
    function getApproveRule(address tokenContract, address spender) internal pure returns (RuleParams memory) {
        bytes4 funcSig = IERC20.approve.selector;

        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);

        // First param: spender address - must be in allowlist
        address[] memory spenderAllowList = new address[](1);
        spenderAllowList[0] = spender;
        paramRules[0] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: spenderAllowList});

        // Second param: amount - any uint256 is allowed
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        IVault.FunctionRule memory rule =
            IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

        return RuleParams({contractAddress: tokenContract, funcSig: funcSig, rule: rule});
    }

    /// @notice Get the rule for transferring a Sablier stream NFT
    /// @param sablierContract The address of the Sablier LockupLinear contract (which is also the NFT)
    /// @param from The address transferring the stream (typically the vault)
    /// @param allowedRecipients Array of addresses allowed to receive the stream NFT
    /// @return RuleParams for safeTransferFrom(address,address,uint256) function
    /// @dev Sablier streams are ERC721 NFTs, so transferring ownership uses safeTransferFrom
    function getTransferStreamRule(address sablierContract, address from, address[] memory allowedRecipients)
        internal
        pure
        returns (RuleParams memory)
    {
        // safeTransferFrom(address from, address to, uint256 tokenId)
        bytes4 funcSig = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));

        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](3);

        // First param: from address - must be in allowlist (typically the vault itself)
        address[] memory fromAllowList = new address[](1);
        fromAllowList[0] = from;
        paramRules[0] = IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: fromAllowList});

        // Second param: to address - must be in allowlist of allowed recipients
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: allowedRecipients});

        // Third param: tokenId - any uint256 is allowed
        paramRules[2] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        IVault.FunctionRule memory rule =
            IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

        return RuleParams({contractAddress: sablierContract, funcSig: funcSig, rule: rule});
    }

    /// @notice Get the rule for transferring a Sablier stream NFT using transferFrom
    /// @param sablierContract The address of the Sablier LockupLinear contract (which is also the NFT)
    /// @param from The address transferring the stream (typically the vault)
    /// @param allowedRecipients Array of addresses allowed to receive the stream NFT
    /// @return RuleParams for transferFrom(address,address,uint256) function
    /// @dev Alternative to safeTransferFrom for when the recipient doesn't implement IERC721Receiver
    function getTransferFromRule(address sablierContract, address from, address[] memory allowedRecipients)
        internal
        pure
        returns (RuleParams memory)
    {
        // transferFrom(address from, address to, uint256 tokenId)
        bytes4 funcSig = bytes4(keccak256("transferFrom(address,address,uint256)"));

        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](3);

        // First param: from address - must be in allowlist (typically the vault itself)
        address[] memory fromAllowList = new address[](1);
        fromAllowList[0] = from;
        paramRules[0] = IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: fromAllowList});

        // Second param: to address - must be in allowlist of allowed recipients
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: allowedRecipients});

        // Third param: tokenId - any uint256 is allowed
        paramRules[2] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        IVault.FunctionRule memory rule =
            IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

        return RuleParams({contractAddress: sablierContract, funcSig: funcSig, rule: rule});
    }

    /// @notice Get the rule for ERC20 transfer
    /// @param tokenContract The address of the ERC20 token contract
    /// @param allowedRecipients Array of addresses allowed to receive tokens
    /// @return RuleParams for transfer(address,uint256) function
    function getTransferRule(address tokenContract, address[] memory allowedRecipients)
        internal
        pure
        returns (RuleParams memory)
    {
        bytes4 funcSig = IERC20.transfer.selector;

        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);

        // First param: to address - must be in allowlist
        paramRules[0] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: allowedRecipients});

        // Second param: amount - any uint256 is allowed
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        IVault.FunctionRule memory rule =
            IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

        return RuleParams({contractAddress: tokenContract, funcSig: funcSig, rule: rule});
    }

    /// @notice Helper to set multiple processor rules on a vault
    /// @param vault The vault to set rules on
    /// @param rules Array of rule parameters
    function setProcessorRules(IVault vault, RuleParams[] memory rules) internal {
        for (uint256 i = 0; i < rules.length; i++) {
            vault.setProcessorRule(rules[i].contractAddress, rules[i].funcSig, rules[i].rule);
        }
    }
}
