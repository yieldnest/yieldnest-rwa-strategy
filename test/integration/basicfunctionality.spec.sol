pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {BaseIntegrationTest} from "./BaseIntegrationTest.sol";
import {RewardsSweeper} from "lib/yieldnest-flex-strategy/src/utils/RewardsSweeper.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {UpgradeUtils} from "lib/yieldnest-flex-strategy/script/UpgradeUtils.sol";
import {ProxyUtils} from "lib/yieldnest-vault/script/ProxyUtils.sol";
import {AccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";
import {AccountingToken} from "lib/yieldnest-flex-strategy/src/AccountingToken.sol";
import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";

contract BasicFunctionalityTest is BaseIntegrationTest {
    //DeployRWAStrategy strategy;

    function setUp() public override {
        super.setUp();
    }

    function testDeploymentParameters() public {
        // // Check if the deployment parameters are set correctly
        assertEq(strategy.symbol(), "ynRWA-USDC-PrivateCredit");
        assertEq(strategy.asset(), 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    }

    function testRewardsSweeperUpgrade() public {
        // Deploy a new implementation of RewardsSweeper
        RewardsSweeper newRewardsSweeperImplementation = new RewardsSweeper();

        UpgradeUtils.timelockUpgrade(
            deployment.timelock(),
            deployment.actors().ADMIN(),
            address(deployment.rewardsSweeper()),
            address(newRewardsSweeperImplementation)
        );

        assertEq(
            address(ProxyUtils.getImplementation(address(deployment.rewardsSweeper()))),
            address(newRewardsSweeperImplementation),
            "Rewards Sweeper implementation address mismatch after upgrade"
        );
    }

    function testAccountingModuleUpgrade() public {
        // Deploy a new implementation of AccountingModule
        AccountingModule newAccountingModuleImplementation = new AccountingModule(address(0), address(0));

        UpgradeUtils.timelockUpgrade(
            deployment.timelock(),
            deployment.actors().ADMIN(),
            address(deployment.accountingModule()),
            address(newAccountingModuleImplementation)
        );

        assertEq(
            address(ProxyUtils.getImplementation(address(deployment.accountingModule()))),
            address(newAccountingModuleImplementation)
        );
    }

    function testAccountingTokenUpgrade() public {
        // Deploy a new implementation of AccountingToken
        AccountingToken newAccountingTokenImplementation = new AccountingToken(address(0));

        UpgradeUtils.timelockUpgrade(
            deployment.timelock(),
            deployment.actors().ADMIN(),
            address(deployment.accountingToken()),
            address(newAccountingTokenImplementation)
        );

        assertEq(
            address(ProxyUtils.getImplementation(address(deployment.accountingToken()))),
            address(newAccountingTokenImplementation)
        );
    }

    function testFlexStrategyUpgrade() public {
        // Deploy a new implementation of FlexStrategy
        FlexStrategy newFlexStrategyImplementation = new FlexStrategy();

        UpgradeUtils.timelockUpgrade(
            deployment.timelock(),
            deployment.actors().ADMIN(),
            address(deployment.strategy()),
            address(newFlexStrategyImplementation)
        );

        assertEq(
            address(ProxyUtils.getImplementation(address(deployment.strategy()))),
            address(newFlexStrategyImplementation)
        );
    }
}
