// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";
import {
    TransparentUpgradeableProxy
} from "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

import {BaseIntegrationTest} from "./BaseIntegrationTest.sol";
import {FlowStrategyKeeper, IFlowStrategyKeeper} from "src/FlowStrategyKeeper.sol";
import {FlowHandler} from "src/FlowHandler.sol";
import {FlowValidator} from "src/validators/FlowValidator.sol";
import {ISablierFlow, UD21x18} from "src/interfaces/sablier/ISablierFlow.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";
import {ISafeGuard} from "src/interfaces/ISafeGuard.sol";
import {MainnetStrategyActors} from "@script/Actors.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

interface ISafeModuleGuardManager {
    function setModuleGuard(address moduleGuard) external;
    function getModulesPaginated(address start, uint256 pageSize)
        external
        view
        returns (address[] memory array, address next);
}

interface IAccessControlErrors {
    error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
}

interface IPausableErrors {
    error EnforcedPause();
}

/// @title FlowStrategyKeeperIntegrationTest
/// @notice Fork tests using the deployed strategy Safe and the deployed YieldNest SafeGuard.
///         The FlowHandler is installed as a new Safe module, and SafeGuard module rules are
///         configured to permit only the exact Flow operations required by disbursement.
contract FlowStrategyKeeperIntegrationTest is BaseIntegrationTest {
    address constant USDC_WHALE = 0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341;
    address constant EXISTING_STRATEGY_SAFE_MODULE = 0x68521bE2613785A0E4710caE32D8F3219f05b6D2;
    address constant SENTINEL_MODULES = address(0x1);
    address constant SAFEGUARD = 0x81e3E4224D9a2d66D9edbA6d4781d475AA65F01e;

    uint256 constant APR = 0.11e18;
    uint256 constant MAX_APR = 0.115e18;
    uint256 constant HOLDING_PERIOD = 28 days;
    uint256 constant MIN_THRESHOLD = 200_000e6;
    uint256 constant MIN_RESIDUAL = 1_000e6;
    uint256 constant FEE_FRACTION = 10;
    uint8 constant TOKEN_DECIMALS = 6;

    FlowStrategyKeeper public keeper;
    FlowHandler public flowHandler;
    FlowValidator public flowValidator;
    ISablierFlow public sablierFlow;
    ISafeGuard public safeguard;
    IERC20 public usdc;

    address public admin;
    address public keeperBot = address(0x2222);
    address public powerKeeperBot = address(0x3333);
    address public vault;
    address public targetStrategy;
    address public borrower = MainnetKeeperContracts.BORROWER;
    address public feeWallet = MainnetKeeperContracts.FEE_WALLET;
    address public streamReceiver = MainnetKeeperContracts.REWARDS_SWEEPER;
    address public proxyAdmin = address(0x9999);
    address public safe;

    uint256 public streamId;

    function setUp() public override {
        super.setUp();

        admin = new MainnetStrategyActors().ADMIN();
        sablierFlow = ISablierFlow(MainnetKeeperContracts.SABLIER_FLOW);
        usdc = IERC20(MainnetKeeperContracts.USDC);
        safeguard = ISafeGuard(SAFEGUARD);

        safe = accountingModule.safe();
        vault = address(strategy);
        targetStrategy = address(strategy);

        _assertExistingSafeState();

        uint128 initialRate = 1;
        streamId =
            sablierFlow.create(safe, streamReceiver, UD21x18.wrap(initialRate), uint40(block.timestamp), usdc, true);
        FlowHandler flowHandlerImpl = new FlowHandler();
        bytes memory initData = abi.encodeCall(
            FlowHandler.initialize,
            (FlowHandler.InitParams({
                    admin: address(this),
                    safe: safe,
                    safeGuard: address(safeguard),
                    flow: address(sablierFlow),
                    streamId: streamId,
                    token: address(usdc),
                    streamRecipient: streamReceiver,
                    apr: APR,
                    holdingPeriod: HOLDING_PERIOD,
                    maxRateDelta: 0,
                    maxRate: 0,
                    borrower: borrower,
                    feeWallet: feeWallet,
                    feeFraction: FEE_FRACTION
                }))
        );
        TransparentUpgradeableProxy proxy =
            new TransparentUpgradeableProxy(address(flowHandlerImpl), proxyAdmin, initData);
        flowHandler = FlowHandler(address(proxy));

        FlowValidator.StreamLimit[] memory limits = new FlowValidator.StreamLimit[](1);
        limits[0] = FlowValidator.StreamLimit({streamId: streamId, maxApr: MAX_APR});
        flowValidator = new FlowValidator(address(sablierFlow), vault, TOKEN_DECIMALS, limits, admin);

        // Install the new module before enabling the module guard.
        vm.prank(safe);
        IGnosisSafe(safe).enableModule(address(flowHandler));

        keeper = new FlowStrategyKeeper(admin, address(this), admin, keeperBot);
        keeper.initialize(
            IFlowStrategyKeeper.FlowKeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: safe,
                baseAsset: address(usdc),
                flowHandler: address(flowHandler),
                minThreshold: MIN_THRESHOLD,
                minResidual: MIN_RESIDUAL,
                minProcessingPercent: 0.01e18
            })
        );

        flowHandler.grantRole(flowHandler.DISBURSE_OPERATOR_ROLE(), address(keeper));

        vm.startPrank(admin);
        strategy.grantRole(strategy.PROCESSOR_ROLE(), address(keeper));
        keeper.grantRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot);
        keeper.revokeRole(keeper.POWER_KEEPER_ROLE(), keeperBot);
        keeper.grantRole(keeper.DEFAULT_ADMIN_ROLE(), admin);
        keeper.grantRole(keeper.CONFIG_MANAGER_ROLE(), admin);
        keeper.grantRole(keeper.PAUSER_ROLE(), admin);
        vm.stopPrank();

        flowHandler.grantRole(flowHandler.DEFAULT_ADMIN_ROLE(), admin);
        flowHandler.grantRole(flowHandler.MANAGER_ROLE(), admin);
        flowHandler.renounceRole(flowHandler.DEFAULT_ADMIN_ROLE(), address(this));

        keeper.renounceRole(keeper.PAUSER_ROLE(), address(this));
        keeper.renounceRole(keeper.CONFIG_MANAGER_ROLE(), address(this));
        keeper.renounceRole(keeper.DEFAULT_ADMIN_ROLE(), address(this));

        _setSafeGuardRules();

        vm.prank(USDC_WHALE);
        usdc.transfer(safe, 20_000_000e6);
    }

    function _assertExistingSafeState() internal view {
        assertTrue(IGnosisSafe(safe).isModuleEnabled(EXISTING_STRATEGY_SAFE_MODULE), "existing safe module missing");

        (address[] memory modules,) = ISafeModuleGuardManager(safe).getModulesPaginated(SENTINEL_MODULES, 10);
        assertGt(modules.length, 0, "strategy safe should already have modules");

        assertEq(safeguard.name(), "ynRWAx-SPV1-SAFE-Guard", "unexpected safeguard");
        assertTrue(safeguard.checkModuleTransactionEnabled(), "module transaction checks should be enabled");
        assertTrue(safeguard.hasRole(safeguard.PROCESSOR_MANAGER_ROLE(), admin), "security council should manage rules");
    }

    function _setSafeGuardRules() internal {
        address[] memory targets = new address[](4);
        bytes4[] memory funcSigs = new bytes4[](4);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](4);

        targets[0] = address(usdc);
        funcSigs[0] = IERC20.approve.selector;
        rules[0] = _approveRule(address(sablierFlow));

        targets[1] = address(sablierFlow);
        funcSigs[1] = ISablierFlow.deposit.selector;
        rules[1] = _depositRule();

        targets[2] = address(sablierFlow);
        funcSigs[2] = ISablierFlow.adjustRatePerSecond.selector;
        rules[2] = _adjustRateRule();

        targets[3] = address(usdc);
        funcSigs[3] = IERC20.transfer.selector;
        rules[3] = _transferRule();

        vm.prank(admin);
        safeguard.setProcessorRules(targets, funcSigs, rules);
    }

    function _executeDirectSafeTransaction(address to, bytes memory data) internal {
        address[] memory owners = IGnosisSafe(safe).getOwners();
        uint256 threshold = IGnosisSafe(safe).getThreshold();
        _sortAddresses(owners);

        address executor = owners[0];
        bytes32 txHash = IGnosisSafe(safe)
            .getTransactionHash(
                to, 0, data, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), address(0), IGnosisSafe(safe).nonce()
            );

        bytes memory signatures;
        for (uint256 i = 0; i < threshold; i++) {
            address owner = owners[i];
            if (owner != executor) {
                vm.prank(owner);
                IGnosisSafe(safe).approveHash(txHash);
            }

            signatures = bytes.concat(signatures, bytes32(uint256(uint160(owner))), bytes32(0), bytes1(uint8(1)));
        }

        vm.prank(executor);
        IGnosisSafe(safe)
            .execTransaction(
                to, 0, data, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures
            );
    }

    function _buildDirectSafeSignaturesAndExecutor(address to, bytes memory data)
        internal
        returns (address executor, bytes memory signatures)
    {
        address[] memory owners = IGnosisSafe(safe).getOwners();
        uint256 threshold = IGnosisSafe(safe).getThreshold();
        _sortAddresses(owners);

        executor = owners[0];
        bytes32 txHash = IGnosisSafe(safe)
            .getTransactionHash(
                to, 0, data, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), address(0), IGnosisSafe(safe).nonce()
            );

        for (uint256 i = 0; i < threshold; i++) {
            address owner = owners[i];
            if (owner != executor) {
                vm.prank(owner);
                IGnosisSafe(safe).approveHash(txHash);
            }

            signatures = bytes.concat(signatures, bytes32(uint256(uint160(owner))), bytes32(0), bytes1(uint8(1)));
        }
    }

    function _sortAddresses(address[] memory addrs) internal pure {
        uint256 length = addrs.length;
        for (uint256 i = 0; i < length; i++) {
            for (uint256 j = i + 1; j < length; j++) {
                if (uint160(addrs[j]) < uint160(addrs[i])) {
                    address tmp = addrs[i];
                    addrs[i] = addrs[j];
                    addrs[j] = tmp;
                }
            }
        }
    }

    function _approveRule(address spender) internal pure returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);
        address[] memory spenders = new address[](1);
        spenders[0] = spender;

        paramRules[0] = IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: spenders});
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});
    }

    function _depositRule() internal view returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](4);
        address[] memory safeAllowList = new address[](1);
        address[] memory recipientAllowList = new address[](1);
        safeAllowList[0] = safe;
        recipientAllowList[0] = streamReceiver;

        paramRules[0] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});
        paramRules[2] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: safeAllowList});
        paramRules[3] =
            IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: recipientAllowList});

        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});
    }

    function _adjustRateRule() internal view returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](0);
        rule = IVault.FunctionRule({
            isActive: true, paramRules: paramRules, validator: IValidator(address(flowValidator))
        });
    }

    function _transferRule() internal view returns (IVault.FunctionRule memory rule) {
        IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);
        address[] memory recipients = new address[](2);
        recipients[0] = borrower;
        recipients[1] = feeWallet;

        paramRules[0] = IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: recipients});
        paramRules[1] =
            IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

        rule = IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});
    }

    /*//////////////////////////////////////////////////////////////
                            SETUP VERIFICATION
    //////////////////////////////////////////////////////////////*/

    function test_keeperIsNotModule() public view {
        assertFalse(IGnosisSafe(safe).isModuleEnabled(address(keeper)), "keeper should not be a module");
    }

    function test_flowHandlerIsProxy() public view {
        assertTrue(IGnosisSafe(safe).isModuleEnabled(address(flowHandler)), "flow handler should be a module");
    }

    function test_streamExists() public view {
        assertTrue(sablierFlow.isStream(streamId), "stream should exist");
        assertEq(sablierFlow.getSender(streamId), safe, "stream sender should be strategy safe");
        assertEq(sablierFlow.getRecipient(streamId), streamReceiver, "stream recipient should match");
    }

    function test_validatorTracksStream() public view {
        FlowValidator.StreamLimit[] memory limits = flowValidator.getLimits();
        assertEq(limits.length, 1, "should track one stream");
        assertEq(limits[0].streamId, streamId, "should track the created stream");
        assertEq(limits[0].maxApr, MAX_APR, "max APR should be 11.5%");
    }

    function test_validatorAllowsNormalDisburse() public view {
        uint256 available = 100_000e6;
        uint256 interest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 rateDelta = uint128((interest * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        uint128 newRate = 1 + rateDelta;

        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(newRate)));
        flowValidator.validate(address(sablierFlow), 0, data);
    }

    function test_validatorBlocksExcessiveRate() public {
        uint256 totalAssets = strategy.totalAssets();
        uint128 maxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * uint256(365 days)));
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(maxRate + 1)));

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                maxRate + 1,
                flowValidator.effectiveApr(maxRate + 1),
                MAX_APR
            )
        );
        flowValidator.validate(address(sablierFlow), 0, data);
    }

    function test_safeGuardRulesAreSet() public view {
        IVault.FunctionRule memory depositRule =
            safeguard.getProcessorRule(address(sablierFlow), ISablierFlow.deposit.selector);
        assertTrue(depositRule.isActive, "deposit rule should be active");
        assertEq(depositRule.paramRules.length, 4, "deposit rule should have 4 param rules");
        assertEq(depositRule.paramRules[2].allowList[0], safe, "deposit sender should be strategy safe");
        assertEq(depositRule.paramRules[3].allowList[0], streamReceiver, "deposit recipient should be configured");

        IVault.FunctionRule memory adjustRule =
            safeguard.getProcessorRule(address(sablierFlow), ISablierFlow.adjustRatePerSecond.selector);
        assertTrue(adjustRule.isActive, "adjust rule should be active");
        assertEq(address(adjustRule.validator), address(flowValidator), "adjust rule should use flow validator");
    }

    function test_configIsCorrect() public view {
        IFlowStrategyKeeper.FlowKeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.vault, vault);
        assertEq(cfg.safe, safe);
        assertEq(cfg.flowHandler, address(flowHandler));

        assertEq(flowHandler.borrower(), borrower);
        assertEq(flowHandler.feeWallet(), feeWallet);
        assertEq(flowHandler.feeFraction(), FEE_FRACTION);
        assertEq(flowHandler.tokenDecimals(), TOKEN_DECIMALS);
        assertEq(flowHandler.apr(), APR);
        assertEq(flowHandler.holdingPeriod(), HOLDING_PERIOD);
    }

    /*//////////////////////////////////////////////////////////////
                       BASIC PROCESS INFLOWS
    //////////////////////////////////////////////////////////////*/

    function test_processInflows_basic() public {
        uint256 available = 100_000e6;

        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedFee = expectedInterest / FEE_FRACTION;
        uint256 expectedStreamAmount = expectedInterest;
        uint256 expectedPrincipal = available - expectedInterest - expectedFee;

        uint256 borrowerBalBefore = usdc.balanceOf(borrower);
        uint256 feeWalletBalBefore = usdc.balanceOf(feeWallet);
        uint256 safeBalBefore = usdc.balanceOf(safe);
        uint128 streamBalBefore = sablierFlow.getBalance(streamId);

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        assertEq(usdc.balanceOf(borrower) - borrowerBalBefore, expectedPrincipal, "principal to borrower");
        assertEq(usdc.balanceOf(feeWallet) - feeWalletBalBefore, expectedFee, "fee to fee wallet");

        uint128 streamBalAfter = sablierFlow.getBalance(streamId);
        assertEq(uint256(streamBalAfter) - uint256(streamBalBefore), expectedStreamAmount, "stream deposit");

        uint256 safeBalAfter = usdc.balanceOf(safe);
        assertEq(safeBalBefore - safeBalAfter, available, "safe deduction");

        uint128 expectedRate = 1 + uint128((expectedStreamAmount * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        uint128 rate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertEq(rate, expectedRate, "rate should equal initial plus delta");
    }

    function test_excessiveDisbursementRateIsRejectedByValidator() public {
        uint128 currentRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        uint128 maxRate = uint128(MAX_APR * strategy.totalAssets() / ((10 ** TOKEN_DECIMALS) * uint256(365 days)));
        uint256 available =
            ((uint256(maxRate - currentRate) + 1) * uint256(365 days) * (10 ** TOKEN_DECIMALS) + APR - 1) / APR;
        available += 1e6;
        uint128 newRate = _expectedNewRateForDisbursement(available, currentRate);

        assertGt(newRate, maxRate, "derived disbursement should exceed validator cap");

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                newRate,
                flowValidator.effectiveApr(newRate),
                MAX_APR
            )
        );
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(newRate)));
        flowValidator.validate(address(sablierFlow), 0, data);
    }

    function test_excessiveDirectRateAdjustmentIsRejectedByValidatorDirectly() public {
        uint128 excessiveRate = _excessiveRateForDirectAdjustment();
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(excessiveRate)));

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                excessiveRate,
                flowValidator.effectiveApr(excessiveRate),
                MAX_APR
            )
        );
        flowValidator.validate(address(sablierFlow), 0, data);
    }

    function test_excessiveDirectRateAdjustmentIsRejectedBySafeGuardValidateCall() public {
        uint128 excessiveRate = _excessiveRateForDirectAdjustment();
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(excessiveRate)));

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                excessiveRate,
                flowValidator.effectiveApr(excessiveRate),
                MAX_APR
            )
        );
        safeguard.validateCall(address(sablierFlow), 0, data);
    }

    function test_excessiveDirectRateAdjustmentIsRejectedBySafeGuardCheckTransaction() public {
        uint128 excessiveRate = _excessiveRateForDirectAdjustment();
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(excessiveRate)));
        (address executor, bytes memory signatures) = _buildDirectSafeSignaturesAndExecutor(address(sablierFlow), data);

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                excessiveRate,
                flowValidator.effectiveApr(excessiveRate),
                MAX_APR
            )
        );
        safeguard.checkTransaction(
            address(sablierFlow),
            0,
            data,
            uint8(IGnosisSafe.Operation.Call),
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            signatures,
            executor
        );
    }

    function test_directSafeTransactionInvokesSafeGuardCheckTransaction() public {
        uint128 currentRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        uint128 nextRate = currentRate + 1;
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(nextRate)));
        (address executor, bytes memory signatures) = _buildDirectSafeSignaturesAndExecutor(address(sablierFlow), data);

        uint128 rateBefore = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        vm.expectCall(
            address(safeguard),
            abi.encodeCall(
                ISafeGuard.checkTransaction,
                (
                    address(sablierFlow),
                    0,
                    data,
                    uint8(IGnosisSafe.Operation.Call),
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    signatures,
                    executor
                )
            )
        );

        _executeDirectSafeTransaction(address(sablierFlow), data);

        uint128 rateAfter = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertEq(rateBefore + 1, rateAfter, "direct safe tx should update rate");
    }

    function test_directSafeTransactionInvokesSafeGuardCheckTransaction_excessiveRate() public {
        uint128 currentRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        uint128 nextRate = currentRate + 10000e18;
        bytes memory data = abi.encodeCall(ISablierFlow.adjustRatePerSecond, (streamId, UD21x18.wrap(nextRate)));
        (address executor, bytes memory signatures) = _buildDirectSafeSignaturesAndExecutor(address(sablierFlow), data);

        vm.expectCall(
            address(safeguard),
            abi.encodeCall(
                ISafeGuard.checkTransaction,
                (
                    address(sablierFlow),
                    0,
                    data,
                    uint8(IGnosisSafe.Operation.Call),
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    signatures,
                    executor
                )
            )
        );

        vm.prank(executor);
        address(safe)
            .call(
                abi.encodeCall(
                    IGnosisSafe.execTransaction,
                    (
                        address(sablierFlow),
                        0,
                        data,
                        IGnosisSafe.Operation.Call,
                        0,
                        0,
                        0,
                        address(0),
                        payable(address(0)),
                        signatures
                    )
                )
            );
    }

    function test_flowHandlerSafeGuardRejectsExcessiveDisbursement() public {
        uint128 currentRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        uint128 maxRate = uint128(MAX_APR * strategy.totalAssets() / ((10 ** TOKEN_DECIMALS) * uint256(365 days)));
        uint256 available =
            ((uint256(maxRate - currentRate) + 1) * uint256(365 days) * (10 ** TOKEN_DECIMALS) + APR - 1) / APR;
        available += 1e6;
        uint128 newRate = _expectedNewRateForDisbursement(available, currentRate);

        assertGt(newRate, maxRate, "derived disbursement should exceed validator cap");

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                newRate,
                flowValidator.effectiveApr(newRate),
                MAX_APR
            )
        );
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);
    }

    function test_flowHandlerSafeGuardRejectsExcessiveDisbursementAfterPriorValidDisbursement() public {
        uint256 firstAvailable = 100_000e6;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, firstAvailable);

        uint128 currentRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        uint128 maxRate = uint128(MAX_APR * strategy.totalAssets() / ((10 ** TOKEN_DECIMALS) * uint256(365 days)));
        uint256 secondAvailable = _availableToExceedRate(maxRate, currentRate);
        uint128 newRate = _expectedNewRateForDisbursement(secondAvailable, currentRate);

        assertLt(currentRate, maxRate, "first disbursement should stay below cap");
        assertGt(newRate, maxRate, "second disbursement should exceed remaining rate headroom");

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                newRate,
                flowValidator.effectiveApr(newRate),
                MAX_APR
            )
        );
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, secondAvailable);
    }

    function test_flowHandlerSafeGuardRejectsDisbursementAfterTighteningLimits() public {
        uint256 available = 100_000e6;
        uint128 newRate =
            _expectedNewRateForDisbursement(available, UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId)));
        uint256 tightenedMaxApr = flowValidator.effectiveApr(newRate) - 1;

        FlowValidator.StreamLimit[] memory tightenedLimits = new FlowValidator.StreamLimit[](1);
        tightenedLimits[0] = FlowValidator.StreamLimit({streamId: streamId, maxApr: tightenedMaxApr});

        vm.prank(admin);
        flowValidator.setLimits(tightenedLimits);

        vm.expectRevert(
            abi.encodeWithSelector(
                FlowValidator.RateExceedsMaxApr.selector,
                streamId,
                newRate,
                flowValidator.effectiveApr(newRate),
                tightenedMaxApr
            )
        );
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);
    }

    /*//////////////////////////////////////////////////////////////
                        YIELD CALCULATION
    //////////////////////////////////////////////////////////////*/

    function test_processInflows_yieldCalculation() public {
        uint256 available = 34_500e6;

        uint256 borrowerBalBefore = usdc.balanceOf(borrower);
        uint256 feeWalletBalBefore = usdc.balanceOf(feeWallet);

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 actualPrincipal = usdc.balanceOf(borrower) - borrowerBalBefore;
        uint256 actualFee = usdc.balanceOf(feeWallet) - feeWalletBalBefore;
        uint256 actualInterest = available - actualPrincipal - actualFee;

        assertEq(actualInterest, expectedInterest, "interest calculation");
        assertEq(actualFee, expectedInterest / FEE_FRACTION, "fee calculation");
        assertEq(actualPrincipal, available - expectedInterest - actualFee, "principal calculation");
    }

    function _expectedNewRateForDisbursement(uint256 available, uint128 currentRate) internal pure returns (uint128) {
        uint256 interest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 additionalRate = uint128((interest * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        return currentRate + additionalRate;
    }

    function _excessiveRateForDirectAdjustment() internal view returns (uint128 excessiveRate) {
        uint256 totalAssets = strategy.totalAssets();
        uint128 maxRate = uint128(MAX_APR * totalAssets / ((10 ** TOKEN_DECIMALS) * uint256(365 days)));
        excessiveRate = maxRate + 1;

        while (flowValidator.effectiveApr(excessiveRate) <= MAX_APR) {
            excessiveRate++;
        }
    }

    function _availableToExceedRate(uint128 maxRate, uint128 currentRate) internal pure returns (uint256 available) {
        available = ((uint256(maxRate - currentRate) + 1) * uint256(365 days) * (10 ** TOKEN_DECIMALS) + APR - 1) / APR;
        return available + 1e6;
    }

    function test_processInflows_rateCalculation() public {
        uint256 available = 100_000e6;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedStreamAmount = expectedInterest;
        uint128 additionalRate = uint128((expectedStreamAmount * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        uint128 expectedRate = 1 + additionalRate;

        uint128 actualRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertEq(actualRate, expectedRate, "rate should match calculated value");
    }

    /*//////////////////////////////////////////////////////////////
                    MULTIPLE DEPOSITS SAME EPOCH
    //////////////////////////////////////////////////////////////*/

    function test_processInflows_multipleSameEpoch() public {
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        vm.warp(block.timestamp + 7 days);

        uint256 available2 = 50_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        uint256 interest2 = (available2 * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 additionalRate = uint128((interest2 * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        assertEq(rate2, rate1 + additionalRate, "rate should be additive");
        assertTrue(sablierFlow.getBalance(streamId) > 0, "stream should have positive balance");
    }

    /*//////////////////////////////////////////////////////////////
                    DEPOSITS ACROSS EPOCHS
    //////////////////////////////////////////////////////////////*/

    function test_processInflows_acrossEpochs() public {
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        vm.warp(block.timestamp + 29 days);

        uint256 available2 = 80_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));

        uint256 interest2 = (available2 * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint128 additionalRate = uint128((interest2 * 1e18) / (HOLDING_PERIOD * (10 ** TOKEN_DECIMALS)));
        assertEq(rate2, rate1 + additionalRate, "rate should be additive across epochs");
    }

    /*//////////////////////////////////////////////////////////////
                     DIFFERENT DEPOSIT SIZES
    //////////////////////////////////////////////////////////////*/

    function test_processInflows_differentSizes() public {
        uint256 small = 10_000e6;
        uint256 borrowerBal0 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, small);
        uint256 principal1 = usdc.balanceOf(borrower) - borrowerBal0;

        vm.warp(block.timestamp + HOLDING_PERIOD + 1);

        uint256 medium = 500_000e6;
        uint256 borrowerBal1 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, medium);
        uint256 principal2 = usdc.balanceOf(borrower) - borrowerBal1;

        vm.warp(block.timestamp + HOLDING_PERIOD + 1);

        uint256 large = 5_000_000e6;
        uint256 borrowerBal2 = usdc.balanceOf(borrower);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, large);
        uint256 principal3 = usdc.balanceOf(borrower) - borrowerBal2;

        assertApproxEqRel(principal2 * 1e18 / principal1, (medium * 1e18) / small, 0.001e18, "medium/small ratio");
        assertApproxEqRel(principal3 * 1e18 / principal1, (large * 1e18) / small, 0.001e18, "large/small ratio");
    }

    /*//////////////////////////////////////////////////////////////
                    LATE TOP-UP (INSOLVENCY)
    //////////////////////////////////////////////////////////////*/

    function test_processInflows_lateTopUp_insolvency() public {
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint256 depletionTime = sablierFlow.depletionTimeOf(streamId);
        assertTrue(depletionTime > block.timestamp, "depletion should be in the future");

        vm.warp(depletionTime + 14 days);

        uint256 uncoveredDebt = sablierFlow.uncoveredDebtOf(streamId);
        assertTrue(uncoveredDebt > 0, "stream should be insolvent");

        uint256 available2 = 200_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 newRate = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(newRate > 0, "rate should be positive after recovery");
        assertEq(sablierFlow.uncoveredDebtOf(streamId), 0, "should be solvent after top-up");
    }

    /*//////////////////////////////////////////////////////////////
                     STREAM RECEIVER WITHDRAWAL
    //////////////////////////////////////////////////////////////*/

    function test_streamReceiver_canWithdraw() public {
        uint256 available = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        vm.warp(block.timestamp + 14 days);

        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertTrue(withdrawable > 0, "should have withdrawable amount after 14 days");

        uint256 receiverBalBefore = usdc.balanceOf(streamReceiver);

        vm.prank(streamReceiver);
        sablierFlow.withdrawMax(streamId, streamReceiver);

        uint256 received = usdc.balanceOf(streamReceiver) - receiverBalBefore;
        assertEq(received, withdrawable, "receiver should get the withdrawable amount");

        vm.warp(block.timestamp + 14 days);

        uint128 remainingWithdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertTrue(remainingWithdrawable > 0, "should have more to withdraw");
    }

    /*//////////////////////////////////////////////////////////////
                      STREAMING OVER FULL PERIOD
    //////////////////////////////////////////////////////////////*/

    function test_totalStreamedOverFullPeriod() public {
        uint256 available = 100_000e6;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        uint256 expectedInterest = (available * APR * HOLDING_PERIOD) / 365 days / 1e18;
        uint256 expectedStreamAmount = expectedInterest;

        vm.warp(block.timestamp + HOLDING_PERIOD);

        uint128 withdrawable = sablierFlow.withdrawableAmountOf(streamId);
        assertApproxEqRel(
            uint256(withdrawable), expectedStreamAmount, 0.001e18, "total streamed should match deposited yield"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    ACCESS CONTROL & PAUSE
    //////////////////////////////////////////////////////////////*/

    function test_revertOnUnauthorizedKeeper() public {
        address unauthorized = address(0xBEEF);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlErrors.AccessControlUnauthorizedAccount.selector, unauthorized, keeper.POWER_KEEPER_ROLE()
            )
        );
        vm.prank(unauthorized);
        keeper.processInflows(0, 100_000e6);
    }

    function test_revertOnKeeperCallingPowerKeeperFunction() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControlErrors.AccessControlUnauthorizedAccount.selector, keeperBot, keeper.POWER_KEEPER_ROLE()
            )
        );
        vm.prank(keeperBot);
        keeper.processInflows(0, 100_000e6);
    }

    function test_revertOnPowerKeeperZeroAvailable() public {
        vm.prank(powerKeeperBot);
        vm.expectRevert(IFlowStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows(0, 0);
    }

    function test_revertOnInsufficientSafeBalance() public {
        uint256 balance = usdc.balanceOf(safe);
        uint256 required = 100_000_000e6 + MIN_RESIDUAL;
        vm.expectRevert(abi.encodeWithSelector(IFlowStrategyKeeper.InsufficientSafeBalance.selector, balance, required));
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, 100_000_000e6);
    }

    function test_pauseBlocksProcessing() public {
        vm.prank(admin);
        keeper.pause();

        vm.expectRevert(IPausableErrors.EnforcedPause.selector);
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, 100_000e6);
    }

    function test_unpauseAllowsProcessing() public {
        vm.prank(admin);
        keeper.pause();

        vm.prank(admin);
        keeper.unpause();

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, 100_000e6);
    }

    /*//////////////////////////////////////////////////////////////
                   EVENT EMISSION
    //////////////////////////////////////////////////////////////*/

    function test_emitsKeeperExecutedEvent() public {
        uint256 available = 100_000e6;

        vm.expectEmit(true, false, false, false);
        emit IFlowStrategyKeeper.KeeperExecuted(block.timestamp, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);
    }

    /*//////////////////////////////////////////////////////////////
                 MULTI-EPOCH LIFECYCLE
    //////////////////////////////////////////////////////////////*/

    function test_multiEpochLifecycle() public {
        uint256 available1 = 100_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1);

        uint128 rate1 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate1 > 0, "rate should be set in epoch 1");

        vm.warp(block.timestamp + 14 days);
        vm.prank(streamReceiver);
        sablierFlow.withdrawMax(streamId, streamReceiver);

        uint256 available1b = 50_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available1b);

        uint128 rate1b = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate1b > rate1, "rate should increase with additional deposit");

        vm.warp(block.timestamp + HOLDING_PERIOD + 1);

        uint256 available2 = 200_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available2);

        uint128 rate2 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate2 > rate1b, "rate should increase with third deposit");

        vm.warp(block.timestamp + HOLDING_PERIOD);

        vm.prank(streamReceiver);
        uint128 withdrawn = sablierFlow.withdrawMax(streamId, streamReceiver);
        assertTrue(withdrawn > 0, "should withdraw accumulated yield");

        vm.warp(block.timestamp + 7 days);

        uint256 available3 = 150_000e6;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available3);

        uint128 rate3 = UD21x18.unwrap(sablierFlow.getRatePerSecond(streamId));
        assertTrue(rate3 > rate2, "rate should increase with fourth deposit");
    }
}
