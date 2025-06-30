pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {BaseIntegrationTest} from "./BaseIntegrationTest.sol";

contract BasicFunctionalityTest is BaseIntegrationTest {
    //DeployRWAStrategy strategy;

    function setUp() public override {
        super.setUp();
        // strategy = new DeployRWAStrategy();
    }

    function testDeploymentParameters() public {
        // // Check if the deployment parameters are set correctly
        // assertEq(strategy.symbol(), "ynRWA-USDC-PrivateCredit");
        // assertEq(strategy.USDC(), 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        // assertEq(strategy.ynRWAx(), 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8);
        // assertEq(strategy.rwaSAFE(), 0x7e92AbC00F58Eb325C7fC95Ed52ACdf74584Be2c);
    }

    function testRewardsSweeperDeployment() public {
        // Simulate the deployment process
        // strategy.run();

        // // Check if the RewardsSweeper is deployed
        // address rewardsSweeperAddress = address(strategy.rewardsSweeper());
        // assertTrue(rewardsSweeperAddress != address(0), "RewardsSweeper should be deployed");
    }
}
