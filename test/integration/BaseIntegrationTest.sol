// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {DeployRWAStrategy} from "@script/DeployRWAStrategy.s.sol";
import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";
import {IAccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";
import {IAccountingToken} from "lib/yieldnest-flex-strategy/src/AccountingToken.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {BaseScript} from "lib/yieldnest-flex-strategy/script/BaseScript.sol";
import {VerifyRWAStrategy} from "@script/VerifyRWAStrategy.s.sol";

contract BaseIntegrationTest is Test {
    BaseScript public deployment;
    address DEPLOYER = address(0xd34db33f);

    FlexStrategy public strategy;
    IAccountingModule public accountingModule;
    IAccountingToken public accountingToken;

    function setUp() public virtual {
        /// For new deployments, uncomment the following: ///

        // deployment = new DeployStrategy();
        // DeployStrategy(address(deployment)).run();

        // // Approve strategy to spend unlimited funds from the SAFE
        // address safe = deployment.safe();
        // address baseAsset = deployment.baseAsset();
        // vm.startPrank(safe);
        // IERC20(baseAsset).approve(address(deployment.accountingModule()), type(uint256).max);
        // vm.stopPrank();

        deployment = new VerifyRWAStrategy();
        VerifyRWAStrategy(address(deployment)).run();

        strategy = FlexStrategy(payable(address(deployment.strategy())));
        accountingModule = strategy.accountingModule();
        accountingToken = accountingModule.accountingToken();
    }
}
