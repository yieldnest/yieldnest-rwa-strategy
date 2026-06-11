// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";

import {FlowHandler} from "@src/FlowHandler.sol";
import {FlowStrategyKeeper, IFlowStrategyKeeper} from "@src/FlowStrategyKeeper.sol";
import {FlowValidator} from "@src/validators/FlowValidator.sol";
import {IGnosisSafe} from "@src/interfaces/IGnosisSafe.sol";
import {ISafeGuard} from "@src/interfaces/ISafeGuard.sol";
import {ISablierFlow} from "@src/interfaces/sablier/ISablierFlow.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";

/// @notice Verifies the final Flow production setup end to end.
contract VerifyFlowSetup is Script {
    bytes32 internal constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 internal constant EIP1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 internal constant EIP1967_ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 internal constant SAFE_GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    address internal constant DEFAULT_SAFE_GUARD = 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e;

    uint8 internal constant TOKEN_DECIMALS = 6;
    uint256 internal constant DEFAULT_MAX_APR = 0.115e18;
    uint256 internal constant DEFAULT_APR = 0.11e18;
    uint256 internal constant DEFAULT_HOLDING_PERIOD = 28 days;
    uint256 internal constant DEFAULT_MIN_THRESHOLD = 200_000e6;
    uint256 internal constant DEFAULT_MIN_RESIDUAL = 1_000e6;
    uint256 internal constant DEFAULT_MIN_PROCESSING_PERCENT = 0.01e18;
    uint256 internal constant DEFAULT_MAX_PROCESSING_PERCENT = 0.01e18;
    uint256 internal constant DEFAULT_FEE_FRACTION = 10;
    error MissingFlowHandlerProxy();
    error MissingFlowKeeper();
    error MissingFlowValidator();

    function run() external view {
        console2.log("=== Verify Flow Setup ===");

        address flowHandlerProxy = vm.envOr("FLOW_HANDLER_PROXY", address(0));
        address flowKeeper = vm.envOr("FLOW_KEEPER", address(0));
        address flowValidator = vm.envOr("FLOW_VALIDATOR", address(0));
        if (flowHandlerProxy == address(0)) revert MissingFlowHandlerProxy();
        if (flowKeeper == address(0)) revert MissingFlowKeeper();
        if (flowValidator == address(0)) revert MissingFlowValidator();

        address flowHandlerAdmin = new MainnetStrategyActors().ADMIN();
        address proxyAdmin = new MainnetStrategyActors().ADMIN();
        address keeperAdmin = new MainnetStrategyActors().ADMIN();
        address keeperConfigManager = new MainnetStrategyActors().ADMIN();
        address keeperPauser = new MainnetStrategyActors().PAUSER();
        address keeperPowerKeeper = new MainnetStrategyActors().PROCESSOR();
        address disburseOperator = flowKeeper;
        address decreaseOperator = vm.envOr("FLOW_DECREASE_OPERATOR", address(0));
        address keeperAutomation = vm.envOr("FLOW_KEEPER_AUTOMATION", address(0));

        address safe = new MainnetStrategyActors().SAFE();
        address safeGuard = DEFAULT_SAFE_GUARD;
        uint256 streamId = MainnetKeeperContracts.DEFAULT_FLOW_STREAM_ID;
        uint256 maxApr = DEFAULT_MAX_APR;
        uint256 apr = DEFAULT_APR;
        uint256 holdingPeriod = DEFAULT_HOLDING_PERIOD;
        uint128 maxRateDelta = 0;
        uint128 maxRate = 0;
        uint256 minThreshold = DEFAULT_MIN_THRESHOLD;
        uint256 minResidual = DEFAULT_MIN_RESIDUAL;
        uint256 minProcessingPercent = DEFAULT_MIN_PROCESSING_PERCENT;
        uint256 maxProcessingPercent = DEFAULT_MAX_PROCESSING_PERCENT;
        uint256 feeFraction = DEFAULT_FEE_FRACTION;

        _verifyFlowHandlerProxy(flowHandlerProxy, proxyAdmin);
        _verifyFlowHandler(
            flowHandlerProxy,
            flowValidator,
            safe,
            safeGuard,
            streamId,
            apr,
            holdingPeriod,
            maxRateDelta,
            maxRate,
            feeFraction,
            flowHandlerAdmin,
            disburseOperator,
            decreaseOperator
        );
        _verifyFlowKeeper(
            flowKeeper,
            flowHandlerProxy,
            safe,
            keeperAdmin,
            keeperConfigManager,
            keeperPauser,
            keeperPowerKeeper,
            keeperAutomation,
            minThreshold,
            minResidual,
            minProcessingPercent,
            maxProcessingPercent
        );
        _verifySafe(flowHandlerProxy, safe, safeGuard);
        _verifyValidator(flowValidator, streamId, maxApr, flowHandlerAdmin);
        _verifySafeGuardRules(safeGuard, flowValidator, safe);

        console2.log("Flow setup verification passed.");
    }

    function _verifyFlowHandlerProxy(address proxy, address expectedProxyAdmin) internal view {
        console2.log("-- verifying FlowHandler proxy");

        address implementation = _readAddressSlot(proxy, EIP1967_IMPLEMENTATION_SLOT);
        address proxyAdmin = _readAddressSlot(proxy, EIP1967_ADMIN_SLOT);

        _require(implementation != address(0), "FlowHandler proxy implementation is zero");
        _require(proxyAdmin == expectedProxyAdmin, "FlowHandler proxy admin mismatch");

        console2.log("flowHandlerImplementation", implementation);
        console2.log("flowHandlerProxyAdmin", proxyAdmin);
    }

    function _verifyFlowHandler(
        address flowHandlerProxy,
        address flowValidator,
        address safe,
        address safeGuard,
        uint256 streamId,
        uint256 apr,
        uint256 holdingPeriod,
        uint128 maxRateDelta,
        uint128 maxRate,
        uint256 feeFraction,
        address flowHandlerAdmin,
        address disburseOperator,
        address decreaseOperator
    ) internal view {
        console2.log("-- verifying FlowHandler");

        FlowHandler handler = FlowHandler(flowHandlerProxy);
        ISablierFlow flow = ISablierFlow(MainnetKeeperContracts.SABLIER_FLOW);

        _require(handler.safe() == safe, "FlowHandler safe mismatch");
        _require(handler.safeGuard() == safeGuard, "FlowHandler safeGuard mismatch");
        _require(handler.flow() == MainnetKeeperContracts.SABLIER_FLOW, "FlowHandler flow mismatch");
        _require(handler.streamId() == streamId, "FlowHandler streamId mismatch");
        _require(handler.token() == MainnetKeeperContracts.USDC, "FlowHandler token mismatch");
        _require(handler.streamRecipient() == MainnetKeeperContracts.REWARDS_SWEEPER, "FlowHandler recipient mismatch");
        _require(handler.tokenDecimals() == TOKEN_DECIMALS, "FlowHandler tokenDecimals mismatch");
        _require(handler.apr() == apr, "FlowHandler apr mismatch");
        _require(handler.holdingPeriod() == holdingPeriod, "FlowHandler holdingPeriod mismatch");
        _require(handler.maxRateDelta() == maxRateDelta, "FlowHandler maxRateDelta mismatch");
        _require(handler.maxRate() == maxRate, "FlowHandler maxRate mismatch");
        _require(handler.borrower() == MainnetKeeperContracts.BORROWER, "FlowHandler borrower mismatch");
        _require(handler.feeWallet() == MainnetKeeperContracts.FEE_WALLET, "FlowHandler feeWallet mismatch");
        _require(handler.feeFraction() == feeFraction, "FlowHandler feeFraction mismatch");

        _require(flow.getSender(streamId) == safe, "Sablier sender mismatch");
        _require(address(flow.getToken(streamId)) == MainnetKeeperContracts.USDC, "Sablier token mismatch");
        _require(flow.getRecipient(streamId) == MainnetKeeperContracts.REWARDS_SWEEPER, "Sablier recipient mismatch");
        _require(flow.getTokenDecimals(streamId) == TOKEN_DECIMALS, "Sablier tokenDecimals mismatch");

        _require(
            IAccessControl(flowHandlerProxy).hasRole(DEFAULT_ADMIN_ROLE, flowHandlerAdmin),
            "FlowHandler DEFAULT_ADMIN_ROLE missing"
        );
        _require(
            IAccessControl(flowHandlerProxy).hasRole(handler.MANAGER_ROLE(), flowHandlerAdmin),
            "FlowHandler MANAGER_ROLE missing"
        );
        _require(
            IAccessControl(flowHandlerProxy).hasRole(handler.DISBURSE_OPERATOR_ROLE(), disburseOperator),
            "FlowHandler DISBURSE_OPERATOR_ROLE missing"
        );
        if (decreaseOperator != address(0)) {
            _require(
                IAccessControl(flowHandlerProxy).hasRole(handler.DECREASE_OPERATOR_ROLE(), decreaseOperator),
                "FlowHandler DECREASE_OPERATOR_ROLE missing"
            );
        }

        _require(flowValidator != address(0), "FlowValidator expected non-zero");
    }

    function _verifyFlowKeeper(
        address flowKeeper,
        address flowHandlerProxy,
        address safe,
        address keeperAdmin,
        address keeperConfigManager,
        address keeperPauser,
        address keeperPowerKeeper,
        address keeperAutomation,
        uint256 minThreshold,
        uint256 minResidual,
        uint256 minProcessingPercent,
        uint256 maxProcessingPercent
    ) internal view {
        console2.log("-- verifying FlowStrategyKeeper");

        FlowStrategyKeeper keeper = FlowStrategyKeeper(flowKeeper);
        IFlowStrategyKeeper.FlowKeeperConfig memory cfg = keeper.getConfig();

        _require(cfg.vault == MainnetKeeperContracts.YNRWAX, "Keeper vault mismatch");
        _require(cfg.targetStrategy == MainnetKeeperContracts.FLEX_STRATEGY, "Keeper targetStrategy mismatch");
        _require(cfg.safe == safe, "Keeper safe mismatch");
        _require(cfg.baseAsset == MainnetKeeperContracts.USDC, "Keeper baseAsset mismatch");
        _require(cfg.flowHandler == flowHandlerProxy, "Keeper flowHandler mismatch");
        _require(cfg.minThreshold == minThreshold, "Keeper minThreshold mismatch");
        _require(cfg.minResidual == minResidual, "Keeper minResidual mismatch");
        _require(cfg.minProcessingPercent == minProcessingPercent, "Keeper minProcessingPercent mismatch");
        _require(cfg.maxProcessingPercent == maxProcessingPercent, "Keeper maxProcessingPercent mismatch");

        _require(
            IAccessControl(flowKeeper).hasRole(DEFAULT_ADMIN_ROLE, keeperAdmin), "Keeper DEFAULT_ADMIN_ROLE missing"
        );
        _require(
            IAccessControl(flowKeeper).hasRole(keeper.CONFIG_MANAGER_ROLE(), keeperConfigManager),
            "Keeper CONFIG_MANAGER_ROLE missing"
        );
        _require(IAccessControl(flowKeeper).hasRole(keeper.PAUSER_ROLE(), keeperPauser), "Keeper PAUSER_ROLE missing");
        _require(
            IAccessControl(flowKeeper).hasRole(keeper.POWER_KEEPER_ROLE(), keeperPowerKeeper),
            "Keeper POWER_KEEPER_ROLE missing"
        );
        if (keeperAutomation != address(0)) {
            _require(
                IAccessControl(flowKeeper).hasRole(keeper.KEEPER_ROLE(), keeperAutomation), "Keeper KEEPER_ROLE missing"
            );
        }
    }

    function _verifySafe(address flowHandlerProxy, address safe, address safeGuard) internal view {
        console2.log("-- verifying Safe wiring");

        _require(IGnosisSafe(safe).isModuleEnabled(flowHandlerProxy), "FlowHandler module not enabled on Safe");
        _require(_readAddressSlot(safe, SAFE_GUARD_SLOT) == safeGuard, "Safe guard slot mismatch");
    }

    function _verifyValidator(address flowValidator, uint256 streamId, uint256 maxApr, address flowHandlerAdmin)
        internal
        view
    {
        console2.log("-- verifying FlowValidator");

        FlowValidator validator = FlowValidator(flowValidator);
        FlowValidator.StreamLimit[] memory limits = validator.getLimits();

        _require(validator.flow() == MainnetKeeperContracts.SABLIER_FLOW, "Validator flow mismatch");
        _require(address(validator.vault()) == MainnetKeeperContracts.YNRWAX, "Validator vault mismatch");
        _require(validator.tokenDecimals() == TOKEN_DECIMALS, "Validator tokenDecimals mismatch");
        _require(limits.length == 1, "Validator limits length mismatch");
        _require(limits[0].streamId == streamId, "Validator streamId limit mismatch");
        _require(limits[0].maxApr == maxApr, "Validator maxApr mismatch");
        _require(
            IAccessControl(flowValidator).hasRole(DEFAULT_ADMIN_ROLE, flowHandlerAdmin),
            "Validator DEFAULT_ADMIN_ROLE missing"
        );
        _require(
            IAccessControl(flowValidator).hasRole(validator.MANAGER_ROLE(), flowHandlerAdmin),
            "Validator MANAGER_ROLE missing"
        );
    }

    function _verifySafeGuardRules(address safeGuard, address flowValidator, address safe) internal view {
        console2.log("-- verifying SafeGuard rules");

        ISafeGuard guard = ISafeGuard(safeGuard);

        IVault.FunctionRule memory approveRule =
            guard.getProcessorRule(MainnetKeeperContracts.USDC, IERC20.approve.selector);
        _require(approveRule.isActive, "SafeGuard approve rule inactive");
        _require(address(approveRule.validator) == address(0), "SafeGuard approve validator mismatch");
        _require(approveRule.paramRules.length == 2, "SafeGuard approve paramRules length mismatch");
        _require(
            uint256(approveRule.paramRules[0].paramType) == uint256(IVault.ParamType.ADDRESS),
            "SafeGuard approve spender type mismatch"
        );
        _require(
            approveRule.paramRules[0].allowList.length == 1
                && approveRule.paramRules[0].allowList[0] == MainnetKeeperContracts.SABLIER_FLOW,
            "SafeGuard approve spender allowList mismatch"
        );

        IVault.FunctionRule memory depositRule =
            guard.getProcessorRule(MainnetKeeperContracts.SABLIER_FLOW, ISablierFlow.deposit.selector);
        _require(depositRule.isActive, "SafeGuard deposit rule inactive");
        _require(address(depositRule.validator) == address(0), "SafeGuard deposit validator mismatch");
        _require(depositRule.paramRules.length == 4, "SafeGuard deposit paramRules length mismatch");
        _require(
            depositRule.paramRules[2].allowList.length == 1 && depositRule.paramRules[2].allowList[0] == safe,
            "SafeGuard deposit sender allowList mismatch"
        );
        _require(
            depositRule.paramRules[3].allowList.length == 1
                && depositRule.paramRules[3].allowList[0] == MainnetKeeperContracts.REWARDS_SWEEPER,
            "SafeGuard deposit recipient allowList mismatch"
        );

        IVault.FunctionRule memory adjustRule =
            guard.getProcessorRule(MainnetKeeperContracts.SABLIER_FLOW, ISablierFlow.adjustRatePerSecond.selector);
        _require(adjustRule.isActive, "SafeGuard adjust rule inactive");
        _require(address(adjustRule.validator) == flowValidator, "SafeGuard adjust validator mismatch");
        _require(adjustRule.paramRules.length == 0, "SafeGuard adjust paramRules length mismatch");

        IVault.FunctionRule memory transferRule =
            guard.getProcessorRule(MainnetKeeperContracts.USDC, IERC20.transfer.selector);
        _require(transferRule.isActive, "SafeGuard transfer rule inactive");
        _require(address(transferRule.validator) == address(0), "SafeGuard transfer validator mismatch");
        _require(transferRule.paramRules.length == 2, "SafeGuard transfer paramRules length mismatch");
        _require(transferRule.paramRules[0].allowList.length == 2, "SafeGuard transfer allowList length mismatch");
        _require(
            transferRule.paramRules[0].allowList[0] == MainnetKeeperContracts.BORROWER,
            "SafeGuard transfer borrower mismatch"
        );
        _require(
            transferRule.paramRules[0].allowList[1] == MainnetKeeperContracts.FEE_WALLET,
            "SafeGuard transfer feeWallet mismatch"
        );
    }

    function _readAddressSlot(address account, bytes32 slot) internal view returns (address value) {
        value = address(uint160(uint256(vm.load(account, slot))));
    }

    function _require(bool condition, string memory message) internal pure {
        if (!condition) revert(message);
    }
}
