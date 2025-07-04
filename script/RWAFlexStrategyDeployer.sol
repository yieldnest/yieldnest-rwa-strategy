import {FlexStrategyDeployer} from "lib/yieldnest-flex-strategy/script/FlexStrategyDeployer.sol";
import {RewardsSweeper} from "lib/yieldnest-flex-strategy/src/utils/RewardsSweeper.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {MainnetRWAStrategyActors} from "@script/Actors.sol";

contract RWAFlexStrategyDeployer is FlexStrategyDeployer {
    // Additional functionality for RWAFlexStrategyDeployer can be added here

    RewardsSweeper public rewardsSweeper;
    RewardsSweeper public rewardsSweeperImplementation;

    constructor(DeploymentParams memory params) FlexStrategyDeployer(params) {}

    function configureStrategy() internal virtual override {
        // Assumes the deployment has already happened

        // Deploy the RewardsSweeper contract as a TransparentUpgradeableProxy and initialize it

        // Assuming RewardsSweeper is a contract that needs to be deployed
        rewardsSweeperImplementation = new RewardsSweeper();

        rewardsSweeper = RewardsSweeper(
            payable(
                address(
                    new TransparentUpgradeableProxy(
                        address(rewardsSweeperImplementation),
                        address(timelock),
                        abi.encodeWithSelector(RewardsSweeper.initialize.selector, deployer, address(accountingModule))
                    )
                )
            )
        );

        rewardsSweeper.grantRole(rewardsSweeper.DEFAULT_ADMIN_ROLE(), actors.ADMIN());

        rewardsSweeper.grantRole(
            rewardsSweeper.REWARDS_SWEEPER_ROLE(), MainnetRWAStrategyActors(address(actors)).REWARDS_SWEEPER_ADMIN()
        );

        accountingModule.grantRole(accountingModule.REWARDS_PROCESSOR_ROLE(), address(rewardsSweeper));

        // renounce roles
        rewardsSweeper.renounceRole(rewardsSweeper.REWARDS_SWEEPER_ROLE(), deployer);
        rewardsSweeper.renounceRole(rewardsSweeper.DEFAULT_ADMIN_ROLE(), deployer);

        // deploy and configure sweeper
        super.configureStrategy();
    }
}
