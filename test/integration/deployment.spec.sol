// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BaseIntegrationTest} from "./BaseIntegrationTest.sol";
import {VerifyStrategy} from "@script/VerifyStrategy.s.sol";
import {BaseScript} from "lib/yieldnest-flex-strategy/script/BaseScript.sol";

contract FlexStrategyDeployment is BaseIntegrationTest {
    function test_verify_setup() public {
        VerifyStrategy verify = new VerifyStrategy();
        verify.setEnv(BaseScript.Env.PROD);
        verify.run();
    }

    // TODO: add test for upgrade
}
