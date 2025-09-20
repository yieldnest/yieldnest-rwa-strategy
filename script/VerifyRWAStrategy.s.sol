// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {RolesVerification} from "lib/yieldnest-flex-strategy/script/verification/RolesVerification.sol";
import {BaseScript} from "lib/yieldnest-flex-strategy/script/BaseScript.sol";
import {MainnetRWAStrategyActors} from "@script/Actors.sol";
import {console} from "forge-std/console.sol";
import {ProxyUtils} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/script/ProxyUtils.sol";
import {VerifyFlexStrategy} from "lib/yieldnest-flex-strategy/script/verification/VerifyFlexStrategy.s.sol";
import {IActors} from "@yieldnest-vault-script/Actors.sol";
import {IContracts} from "@yieldnest-vault-script/Contracts.sol";
import {L1Contracts} from "@yieldnest-vault-script/Contracts.sol";
import {IVault} from "@yieldnest-vault/interface/IVault.sol";

// forge script VerifyFlexStrategy --rpc-url <MAINNET_RPC_URL>
contract VerifyRWAStrategy is VerifyFlexStrategy {
    address public YNRWAX = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8;

    function _setup() public virtual override {
        MainnetRWAStrategyActors _actors = new MainnetRWAStrategyActors();
        if (block.chainid == 1) {
            minDelay = 1 days;

            actors = IActors(_actors);
            contracts = IContracts(new L1Contracts());
        }

        address[] memory _allocators = new address[](1);
        _allocators[0] = YNRWAX;

        setVerificationParameters(
            VerifyFlexStrategy.VerificationParameters({
                name: "YieldNest USDC Flex Strategy - ynRWAx - SPV1",
                symbol_: "ynFlex-USDC-ynRWAx-SPV1",
                accountTokenName: "YieldNest Flex Strategy - ynRWAx - SPV1 Accounting Token",
                accountTokenSymbol: "ynFlexUSDC-ynRWAx-SPV1-Tok",
                decimals: 6, // 6 decimals for USDC
                paused: true,
                targetApy: 0.15 ether, // max 15% rewards per year
                lowerBound: 0.0001 ether, // Ability to mark 0.01% of TVL as losses
                minRewardableAssets: 1000e6, // min 1000 USDC
                accountingProcessor: _actors.PROCESSOR(),
                baseAsset: IVault(YNRWAX).asset(),
                allocators: _allocators,
                alwaysComputeTotalAssets: true
            })
        );
    }
}
