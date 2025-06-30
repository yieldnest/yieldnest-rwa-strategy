pragma solidity ^0.8.28;

import "forge-std/Test.sol";
import {BaseIntegrationTest} from "./BaseIntegrationTest.sol";

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
}
