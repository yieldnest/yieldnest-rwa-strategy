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

// forge script VerifyFlexStrategy --rpc-url <MAINNET_RPC_URL>
contract VerifyRWAStrategy is VerifyFlexStrategy {}
