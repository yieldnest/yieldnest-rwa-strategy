// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "lib/yieldnest-flex-strategy/script/DeployFlexStrategy.s.sol";
import {L1Contracts} from "@yieldnest-vault-script/Contracts.sol";
import {IContracts} from "@yieldnest-vault-script/Contracts.sol";
import {IActors} from "@yieldnest-vault-script/Actors.sol";
import {console} from "forge-std/console.sol";
import {RewardsSweeper} from "lib/yieldnest-flex-strategy/src/utils/RewardsSweeper.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {ProxyUtils} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/script/ProxyUtils.sol";
import {MainnetRWAStrategyActors} from "@script/Actors.sol";

contract DeployRWAStrategy is DeployFlexStrategy {
    // Additional functionality for DeployRWAStrategy can be added here

    address public constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public constant ynRWAx = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8;

    address public constant rwaSAFE = 0x7e92AbC00F58Eb325C7fC95Ed52ACdf74584Be2c;

    RewardsSweeper rewardsSweeperImplementation;
    RewardsSweeper rewardsSweeper;

    function run() public override {
        setDeploymentParameters(
            DeploymentParameters({
                name: "YieldNest USDC Private Credit",
                symbol_: "ynRWA-USDC-PrivateCredit",
                accountTokenName: "YieldNest USDC Private Credit Flex Token",
                accountTokenSymbol: "ynFLEX-RWA-USDC-PrivateCredit",
                decimals: 6,
                paused: true,
                targetApy: 0.12 ether, // 12% per year
                lowerBound: 0.5 ether, // max slash of 50% at a given time
                minRewardableAssets: 1000e6, // 1000 USDC
                accountingProcessor: accountingProcessor,
                baseAsset: USDC,
                allocator: ynRWAx,
                safe: rwaSAFE,
                alwaysComputeTotalAssets: true
            })
        );

        super.run();
    }

    function configureStrategy() internal virtual override {
        // Assumes the deployment has already happened

        // Deploy the RewardsSweeper contract as a TransparentUpgradeableProxy and initialize it

        // Assuming RewardsSweeper is a contract that needs to be deployed
        rewardsSweeperImplementation = new RewardsSweeper();

        rewardsSweeper = RewardsSweeper(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(rewardsSweeperImplementation),
                        address(timelock),
                        abi.encodeWithSelector(RewardsSweeper.initialize.selector, deployer, address(accountingModule))
                    )
                )
            )
        );

        rewardsSweeper.grantRole(rewardsSweeper.DEFAULT_ADMIN_ROLE(), actors.ADMIN());

        rewardsSweeper.grantRole(
            rewardsSweeper.REWARDS_SWEEPER_ROLE(), MainnetRWAStrategyActors(address(actors)).REWARDS_SWEEPER_ADMIN()
        );

        accountingModule.grantRole(accountingModule.REWARDS_PROCESSOR_ROLE(), address(rewardsSweeper));

        // Log the deployment
        console.log("RewardsSweeper deployed at:", address(rewardsSweeper));

        // renounce roles
        rewardsSweeper.renounceRole(rewardsSweeper.REWARDS_SWEEPER_ROLE(), deployer);
        rewardsSweeper.renounceRole(rewardsSweeper.DEFAULT_ADMIN_ROLE(), deployer);

        // deploy and configure sweeper
        super.configureStrategy();
    }

    function _saveDeployment(Env env) internal virtual override {
        vm.serializeAddress(symbol(), string.concat(symbol(), "-rewardsSweeper-proxy"), address(rewardsSweeper));
        vm.serializeAddress(
            symbol(),
            string.concat(symbol(), "-rewardsSweeper-proxyAdmin"),
            ProxyUtils.getProxyAdmin(address(rewardsSweeper))
        );
        vm.serializeAddress(
            symbol(), string.concat(symbol(), "-rewardsSweeper-implementation"), address(rewardsSweeperImplementation)
        );

        super._saveDeployment(env);
    }

    function _setup() public override {
        if (block.chainid == 1) {
            minDelay = 1 days;
            MainnetRWAStrategyActors _actors = new MainnetRWAStrategyActors();
            actors = IActors(_actors);
            contracts = IContracts(new L1Contracts());
        }
    }
}
