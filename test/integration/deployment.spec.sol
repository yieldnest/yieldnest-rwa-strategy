// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {BaseIntegrationTest} from "./BaseIntegrationTest.sol";
import {VerifyRWAStrategy} from "@script/VerifyRWAStrategy.s.sol";
import {BaseScript} from "lib/yieldnest-flex-strategy/script/BaseScript.sol";

contract FlexStrategyDeployment is BaseIntegrationTest {
    function test_verify_setup() public {
        VerifyRWAStrategy verify = new VerifyRWAStrategy();
        verify.setEnv(BaseScript.Env.TEST);
        verify.run();
    }

    // function test_upgrade_success() public {
    //     FlexStrategy newImpl = new FlexStrategy();
    //     address securityCouncil = MainnetActors(address(deployment.actors())).YnSecurityCouncil();
    //     UpgradeUtils.timelockUpgrade(
    //         deployment.timelock(), securityCouncil, address(deployment.strategy()), address(newImpl)
    //     );

    //     assertEq(address(ProxyUtils.getImplementation(address(deployment.strategy()))), address(newImpl));
    // }

    // function test_addNewAdmin_success() public {
    //     address newAdmin = address(0x1234567890123456789012345678901234567890);

    //     vm.startPrank(deployment.actors().ADMIN());
    //     deployment.strategy().grantRole(deployment.strategy().DEFAULT_ADMIN_ROLE(), newAdmin);
    //     RolesVerification.verifyRole(
    //         deployment.strategy(),
    //         newAdmin,
    //         deployment.strategy().DEFAULT_ADMIN_ROLE(),
    //         true,
    //         "newAdmin has DEFAULT_ADMIN_ROLE"
    //     );
    // }
}
