// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "lib/yieldnest-flex-strategy/script/DeployFlexStrategy.s.sol";
import { L1Contracts } from "@yieldnest-vault-script/Contracts.sol";
import { IContracts } from "@yieldnest-vault-script/Contracts.sol";
import { IActors } from "@yieldnest-vault-script/Actors.sol";
import { console } from "forge-std/console.sol";


contract MainnetRWAStrategyActors is IActors {
    address public constant YnSecurityCouncil = 0xfcad670592a3b24869C0b51a6c6FDED4F95D6975;
    address public constant YnProcessor = 0x56866A6D5655C9E534320DA95fbBB82Fb3bF3D7D;
    address public constant YnDev = 0xa08F39d30dc865CC11a49b6e5cBd27630D6141C3;
    address public constant YnBootstrapper = 0x832e0D8e7A7Bdfe181f30df614383FAA4B5C2924;

    address public constant TIMELOCK = address(0);

    address public constant ADMIN = YnSecurityCouncil;
    address public constant PROCESSOR = YnProcessor;
    address public constant EXECUTOR_1 = YnSecurityCouncil;
    address public constant PROPOSER_1 = YnSecurityCouncil;

    address public constant PROVIDER_MANAGER = YnSecurityCouncil;
    address public constant BUFFER_MANAGER = YnSecurityCouncil;
    address public constant ASSET_MANAGER = YnSecurityCouncil;
    address public constant PROCESSOR_MANAGER = YnSecurityCouncil;
    address public constant PAUSER = YnDev;
    address public constant UNPAUSER = YnSecurityCouncil;
    address public constant FEE_MANAGER = YnSecurityCouncil;

    address public constant ALLOCATOR_MANAGER = YnSecurityCouncil;

    address public constant UPDATER = YnDev;
    // FIXME; set different bootstrapper for mainnet
    address public constant BOOTSTRAPPER = YnBootstrapper;
    address public constant UNAUTHORIZED = address(0);
}

contract DeployRWAStrategy is DeployFlexStrategy {
// Additional functionality for DeployRWAStrategy can be added here

    address public constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public constant ynRWAx = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8;

    function run() public override {
        setDeploymentParameters(
            DeploymentParameters({
                name: "YieldNest USDC Private Credit",
                symbol_: "ynRWA-USDC-PrivateCredit",
                accountTokenName: "YieldNest USDC Private Credit Flex Token",
                accountTokenSymbol: "ynFLEX-RWA-USDC-PrivateCredit",
                decimals: 6,
                paused: true,
                targetApy: 0.12 ether,
                lowerBound: 0.5 ether,
                minRewardableAssets: 1000e6,
                accountingProcessor: accountingProcessor,
                baseAsset: USDC,
                allocator: ynRWAx,
                safe: safe,
                alwaysComputeTotalAssets: true
            })
        );
        
        super.run();
    }



    function _setup() public override {
        if (block.chainid == 1) {
            minDelay = 1 days;
            MainnetRWAStrategyActors _actors = new MainnetRWAStrategyActors();
            actors = IActors(_actors);
            contracts = IContracts(new L1Contracts());
        }
    }

}
