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
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract BaseFunctionalityTest is BaseIntegrationTest {
    //DeployRWAStrategy strategy;

    address constant ALICE_ADDRESS = address(0x123); // Replace with Alice's actual address
    address constant USDC_ADDRESS = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48; // USDC token address
    uint256 constant DEPOSIT_AMOUNT = 1000 * 10 ** 6; // 1000 USDC with 6 decimals

    function setUp() public override {
        super.setUp();
        // Prank as admin to grant ALLOCATOR role to Alice
        vm.startPrank(deployment.actors().ADMIN());
        deployment.strategy().grantRole(deployment.strategy().ALLOCATOR_ROLE(), ALICE_ADDRESS);
        vm.stopPrank();
    }

    function testDepositUSDCAsAlice() public {
        // Assume we have a mock USDC token and a strategy that accepts USDC deposits
        IERC20 usdc = IERC20(USDC_ADDRESS);

        // Deal USDC to Alice
        deal(USDC_ADDRESS, ALICE_ADDRESS, DEPOSIT_AMOUNT);

        // Approve the strategy to spend USDC as Alice
        vm.startPrank(ALICE_ADDRESS);
        usdc.approve(address(deployment.strategy()), DEPOSIT_AMOUNT);

        // Record initial balances
        uint256 initialStrategyBalance = usdc.balanceOf(address(deployment.strategy()));
        uint256 initialUserBalance = usdc.balanceOf(ALICE_ADDRESS);
        uint256 initialSafeBalance = usdc.balanceOf(deployment.safe());

        // Deposit USDC into the strategy as Alice
        deployment.strategy().deposit(DEPOSIT_AMOUNT, ALICE_ADDRESS);

        // Check final balances
        uint256 finalStrategyBalance = usdc.balanceOf(address(deployment.strategy()));
        uint256 finalUserBalance = usdc.balanceOf(ALICE_ADDRESS);
        uint256 finalSafeBalance = usdc.balanceOf(deployment.safe());

        // Assert that the strategy's balance increased by the deposit amount
        assertEq(finalStrategyBalance, initialStrategyBalance, "Strategy balance increased incorrectly");

        // Assert that the safe's balance increased by the deposit amount
        assertEq(finalSafeBalance, initialSafeBalance + DEPOSIT_AMOUNT, "Safe balance did not increase correctly");

        // Assert that Alice's balance decreased by the deposit amount
        assertEq(finalUserBalance, initialUserBalance - DEPOSIT_AMOUNT, "Alice's balance did not decrease correctly");
        vm.stopPrank();
    }
}
