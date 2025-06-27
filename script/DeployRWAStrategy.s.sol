// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "lib/yieldnest-flex-strategy/script/DeployFlexStrategy.s.sol";

contract DeployRWAStrategy is DeployFlexStrategy {
// Additional functionality for DeployRWAStrategy can be added here


    // function _setup() public override {
    //     if (block.chainid == 1) {
    //         minDelay = 1 days;
    //         MainnetActors _actors = new MainnetActors();
    //         actors = IActors(_actors);
    //         contracts = IContracts(new L1Contracts());
    //     }
    // }

}
