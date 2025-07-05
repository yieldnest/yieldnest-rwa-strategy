// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
// import { IVault } from "@yieldnest-vault/interface/IVault.sol"; // Commented out due to missing source
import {Ownable} from "openzeppelin-contracts/contracts/access/Ownable.sol";
import {RolesVerification} from "lib/yieldnest-flex-strategy/script/verification/RolesVerification.sol";
import {BaseScript} from "lib/yieldnest-flex-strategy/script/BaseScript.sol";
import {MainnetRWAStrategyActors} from "@script/Actors.sol";
import {console} from "forge-std/console.sol";
import {ProxyUtils} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/script/ProxyUtils.sol";
import {RewardsSweeper} from "lib/yieldnest-flex-strategy/src/utils/RewardsSweeper.sol";

// forge script VerifyFlexStrategy --rpc-url <MAINNET_RPC_URL>
contract VerifyRWAStrategy is BaseScript, Test {
    RewardsSweeper public rewardsSweeper;
    RewardsSweeper public rewardsSweeperImplementation;
    address public rewardsSweeperProxyAdmin;

    function symbol() public pure override returns (string memory) {
        return "ynRWA-USDC-PrivateCredit";
    }

    function run() public {
        _loadDeployment(deploymentEnv);
        _loadRewardsSweeperDeployment(deploymentEnv);
        _setup();

        verify();
    }

    function _verifyDeploymentParams() internal view virtual {
        assertEq(strategy.name(), "YieldNest USDC Private Credit", "Strategy name does not match expected value");
        assertEq(strategy.symbol(), "ynRWA-USDC-PrivateCredit", "Strategy symbol does not match expected value");
        assertEq(strategy.decimals(), 6, "Strategy decimals do not match expected value");
        RolesVerification.verifyRole(
            strategy,
            allocator,
            strategy.ALLOCATOR_ROLE(),
            true,
            "Allocator role is not correctly assigned to parent vault"
        );
        assertEq(accountingModule.targetApy(), 0.12 ether, "Accounting module target APY does not match expected value");
        assertEq(
            accountingModule.lowerBound(), 0.5 ether, "Accounting module lower bound does not match expected value"
        );
        RolesVerification.verifyRole(
            accountingModule,
            safe,
            accountingModule.REWARDS_PROCESSOR_ROLE(),
            true,
            "Safe does not have rewards processor role"
        );

        RolesVerification.verifyRole(
            accountingModule,
            safe,
            accountingModule.LOSS_PROCESSOR_ROLE(),
            true,
            "Safe does not have loss processor role"
        );
    }

    function verify() internal view virtual {
        _verifyDeploymentParams();

        _verifyProxyParameters();

        assertNotEq(address(strategy), address(0), "strategy is not set");
        assertNotEq(address(strategyImplementation), address(0), "strategy implementation is not set");
        assertNotEq(address(strategyProxyAdmin), address(0), "strategy proxy admin is not set");

        assertEq(address(strategy.accountingModule()), address(accountingModule), "strategy.accountingModule() not set");
        assertEq(
            address(accountingToken.accountingModule()),
            address(accountingModule),
            "accountingToken.accountingModule() not set"
        );
        assertEq(
            address(accountingModule.accountingToken()),
            address(accountingToken),
            "accountingModule.accountingToken() not set"
        );
        assertEq(
            address(accountingModule.strategy()),
            address(strategy),
            "accountingModule.strategy() does not match strategy address"
        );
        assertEq(
            address(accountingToken.TRACKED_ASSET()),
            baseAsset,
            "accountingToken.TRACKED_ASSET() does not match base asset"
        );

        assertNotEq(address(rateProvider), address(0), "provider is invalid");
        assertEq(strategy.provider(), address(rateProvider), "provider is invalid");

        assertTrue(strategy.getHasAllocator(), "has allocator is invalid");
        assertEq(strategy.countNativeAsset(), false, "count native asset is invalid");
        assertEq(strategy.alwaysComputeTotalAssets(), true, "always compute total assets is invalid");

        address[] memory assets = strategy.getAssets();
        assertEq(assets.length, 2, "assets length is invalid");
        assertEq(assets[0], baseAsset, "assets[0] is invalid");
        assertEq(assets[1], address(accountingToken), "assets[1] is invalid");
        assertFalse(strategy.paused(), "paused is invalid");

        RolesVerification.verifyDefaultRoles(strategy, accountingModule, accountingToken, timelock, actors);
        RolesVerification.verifyTemporaryRoles(strategy, accountingModule, accountingToken, deployer);
        RolesVerification.verifyRole(
            timelock,
            MainnetRWAStrategyActors(address(actors)).YnSecurityCouncil(),
            timelock.PROPOSER_ROLE(),
            true,
            "proposer role for timelock is YnSecurityCouncil"
        );
        RolesVerification.verifyRole(
            timelock,
            MainnetRWAStrategyActors(address(actors)).YnSecurityCouncil(),
            timelock.EXECUTOR_ROLE(),
            true,
            "executor role for timelock is YnSecurityCouncil"
        );
        RolesVerification.verifyRole(
            strategy,
            MainnetRWAStrategyActors(address(actors)).YnBootstrapper(),
            strategy.ALLOCATOR_ROLE(),
            true,
            "bootstrapper has allocator role"
        );

        assertEq(timelock.getMinDelay(), 1 days, "min delay is invalid");
        assertEq(Ownable(strategyProxyAdmin).owner(), address(timelock), "proxy admin owner is invalid");
    }

    function _loadRewardsSweeperDeployment(Env env) internal virtual {
        if (!vm.isFile(_deploymentFilePath(env))) {
            return;
        }

        string memory jsonInput = vm.readFile(_deploymentFilePath(env));
        rewardsSweeperImplementation = RewardsSweeper(
            payable(
                address(vm.parseJsonAddress(jsonInput, string.concat(".", symbol(), "-rewardsSweeper-implementation")))
            )
        );
        rewardsSweeper = RewardsSweeper(
            payable(address(vm.parseJsonAddress(jsonInput, string.concat(".", symbol(), "-rewardsSweeper-proxy"))))
        );
        rewardsSweeperProxyAdmin =
            address(vm.parseJsonAddress(jsonInput, string.concat(".", symbol(), "-rewardsSweeper-proxyAdmin")));
    }

    function _verifyProxyParameters() internal view virtual {
        {
            // Verify proxy admin and implementation addresses
            console.log("==============================================");
            console.log("=        VERIFYING PROXY CONFIGURATION      =");
            console.log("==============================================");

            // Verify strategy proxy configuration
            address strategyImpl = ProxyUtils.getImplementation(address(strategy));
            address strategyAdmin = ProxyUtils.getProxyAdmin(address(strategy));
            assertEq(strategyImpl, address(strategyImplementation), "Strategy implementation address mismatch");
            assertEq(strategyAdmin, strategyProxyAdmin, "Strategy proxy admin address mismatch");
            console.log("\u2705 Strategy implementation:  ", strategyImpl);
            console.log("\u2705 Strategy proxy admin:     ", strategyAdmin);
        }

        {
            // Verify accounting module proxy configuration
            address accountingModuleImpl = ProxyUtils.getImplementation(address(accountingModule));
            address accountingModuleAdmin = ProxyUtils.getProxyAdmin(address(accountingModule));
            assertEq(
                accountingModuleImpl,
                address(accountingModuleImplementation),
                "Accounting Module implementation address mismatch"
            );
            assertEq(
                accountingModuleAdmin, accountingModuleProxyAdmin, "Accounting Module proxy admin address mismatch"
            );
            console.log("\u2705 Accounting Module implementation: ", accountingModuleImpl);
            console.log("\u2705 Accounting Module proxy admin:    ", accountingModuleAdmin);
        }

        {
            // Verify accounting token proxy configuration
            address accountingTokenImpl = ProxyUtils.getImplementation(address(accountingToken));
            address accountingTokenAdmin = ProxyUtils.getProxyAdmin(address(accountingToken));
            assertEq(
                accountingTokenImpl,
                address(accountingTokenImplementation),
                "Accounting Token implementation address mismatch"
            );
            assertEq(accountingTokenAdmin, accountingTokenProxyAdmin, "Accounting Token proxy admin address mismatch");
            console.log("\u2705 Accounting Token implementation: ", accountingTokenImpl);
            console.log("\u2705 Accounting Token proxy admin:    ", accountingTokenAdmin);
        }

        {
            // Verify rewards sweeper proxy configuration
            address rewardsSweeperImpl = ProxyUtils.getImplementation(address(rewardsSweeper));
            address rewardsSweeperAdmin = ProxyUtils.getProxyAdmin(address(rewardsSweeper));
            assertEq(
                rewardsSweeperImpl,
                address(rewardsSweeperImplementation),
                "Rewards Sweeper implementation address mismatch"
            );
            assertEq(rewardsSweeperAdmin, rewardsSweeperProxyAdmin, "Rewards Sweeper proxy admin address mismatch");
            console.log("\u2705 Rewards Sweeper implementation: ", rewardsSweeperImpl);
            console.log("\u2705 Rewards Sweeper proxy admin:    ", rewardsSweeperAdmin);
        }
    }
}
