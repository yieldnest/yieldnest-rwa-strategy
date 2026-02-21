// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";

import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";
import {IAccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";

import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";
import {ISablierBatchLockup} from "src/interfaces/sablier/ISablierBatchLockup.sol";
import {SablierRules} from "@script/rules/SablierRules.sol";
import {StrategyKeeperSablierValidator} from "src/validators/StrategyKeeperSablierValidator.sol";
import {MainnetKeeperContracts} from "@script/Contracts.sol";

interface ISablierLockup {
    function nextStreamId() external view returns (uint256);
    function getSender(uint256 streamId) external view returns (address);
    function getRecipient(uint256 streamId) external view returns (address);
    function getDepositedAmount(uint256 streamId) external view returns (uint128);
}

/// @title SablierIntegrationTest
/// @notice Integration tests for SablierRules and StrategyKeeperSablierValidator using real mainnet contracts
contract SablierIntegrationTest is Test {
    FlexStrategy public strategy;
    IAccountingModule public accountingModule;
    ISablierLockupLinear public sablier;
    ISablierBatchLockup public batchLockup;
    IERC20 public usdc;
    StrategyKeeperSablierValidator public validator;

    address public safe;
    address public processor;
    address public timelock;
    address public admin;

    // Known mainnet addresses
    address constant YN_SECURITY_COUNCIL = 0xfcad670592a3b24869C0b51a6c6FDED4F95D6975;
    address constant YN_TIMELOCK = 0x9F58041aC9d30dcf1B270Af0F3724A9D5ad68e88;

    function setUp() public {
        // Use deployed strategy directly
        strategy = FlexStrategy(payable(MainnetKeeperContracts.FLEX_STRATEGY));
        accountingModule = strategy.accountingModule();

        // Real mainnet contracts
        sablier = ISablierLockupLinear(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        batchLockup = ISablierBatchLockup(MainnetKeeperContracts.SABLIER_BATCH_LOCKUP);
        usdc = IERC20(MainnetKeeperContracts.USDC);

        // Get safe from the deployed accounting module
        safe = accountingModule.safe();

        // Known role holders
        admin = YN_SECURITY_COUNCIL; // has DEFAULT_ADMIN_ROLE
        timelock = YN_TIMELOCK; // has PROCESSOR_MANAGER_ROLE

        // Use a processor address
        processor = address(0x2222);

        // Deploy validator with real addresses
        address[] memory allowedRecipients = new address[](1);
        allowedRecipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        validator = new StrategyKeeperSablierValidator(
            safe, MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, address(usdc), allowedRecipients
        );

        // Grant processor role using admin (has DEFAULT_ADMIN_ROLE)
        // Note: need to cache the role hash before prank since prank only works for next call
        bytes32 processorRole = strategy.PROCESSOR_ROLE();
        vm.prank(admin);
        strategy.grantRole(processorRole, processor);

        // Set up Sablier rules using timelock (has PROCESSOR_MANAGER_ROLE)
        vm.startPrank(timelock);
        _setupSablierRulesWithLibrary();
        vm.stopPrank();

        // Fund the strategy with USDC
        deal(address(usdc), address(strategy), 100_000e6);
    }

    function _setupSablierRulesWithLibrary() internal {
        // Rule 1: Approve USDC to Sablier and BatchLockup
        address[] memory spenders = new address[](2);
        spenders[0] = address(sablier);
        spenders[1] = address(batchLockup);
        SablierRules.RuleParams memory approveRule = SablierRules.getApproveRule(address(usdc), spenders);

        // Rule 2: Create stream on Sablier WITH VALIDATOR
        SablierRules.RuleParams memory createStreamRule =
            SablierRules.getCreateStreamRuleWithValidator(address(sablier), IValidator(address(validator)));

        // Rule 3: Batch create streams on BatchLockup WITH VALIDATOR
        SablierRules.RuleParams memory createBatchStreamRule =
            SablierRules.getCreateBatchStreamRuleWithValidator(address(batchLockup), IValidator(address(validator)));

        // Rule 4: Transfer stream NFT
        address[] memory transferRecipients = new address[](1);
        transferRecipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        SablierRules.RuleParams memory transferRule =
            SablierRules.getTransferStreamRule(address(sablier), address(strategy), transferRecipients);

        // Rule 5: ERC20 transfer
        address[] memory erc20Recipients = new address[](1);
        erc20Recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        SablierRules.RuleParams memory erc20TransferRule = SablierRules.getTransferRule(address(usdc), erc20Recipients);

        // Apply all rules using setProcessorRules
        address[] memory targets = new address[](5);
        bytes4[] memory funcSigs = new bytes4[](5);
        IVault.FunctionRule[] memory rules = new IVault.FunctionRule[](5);

        targets[0] = approveRule.contractAddress;
        funcSigs[0] = approveRule.funcSig;
        rules[0] = approveRule.rule;

        targets[1] = createStreamRule.contractAddress;
        funcSigs[1] = createStreamRule.funcSig;
        rules[1] = createStreamRule.rule;

        targets[2] = createBatchStreamRule.contractAddress;
        funcSigs[2] = createBatchStreamRule.funcSig;
        rules[2] = createBatchStreamRule.rule;

        targets[3] = transferRule.contractAddress;
        funcSigs[3] = transferRule.funcSig;
        rules[3] = transferRule.rule;

        targets[4] = erc20TransferRule.contractAddress;
        funcSigs[4] = erc20TransferRule.funcSig;
        rules[4] = erc20TransferRule.rule;

        IVault(address(strategy)).setProcessorRules(targets, funcSigs, rules);
    }

    /*//////////////////////////////////////////////////////////////
                         RULE GENERATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getApproveRule() public view {
        SablierRules.RuleParams memory rule = SablierRules.getApproveRule(address(usdc), address(sablier));

        assertEq(rule.contractAddress, address(usdc), "Contract address should be USDC");
        assertEq(rule.funcSig, IERC20.approve.selector, "Function sig should be approve");
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(rule.rule.paramRules.length, 2, "Should have 2 param rules");
        assertEq(rule.rule.paramRules[0].allowList[0], address(sablier), "Spender should be Sablier");
    }

    function test_getApproveRule_multipleSpenders() public view {
        address[] memory spenders = new address[](2);
        spenders[0] = address(sablier);
        spenders[1] = address(batchLockup);
        SablierRules.RuleParams memory rule = SablierRules.getApproveRule(address(usdc), spenders);

        assertEq(rule.contractAddress, address(usdc), "Contract address should be USDC");
        assertEq(rule.funcSig, IERC20.approve.selector, "Function sig should be approve");
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(rule.rule.paramRules[0].allowList.length, 2, "Should have 2 spenders");
        assertEq(rule.rule.paramRules[0].allowList[0], address(sablier), "First spender should be Sablier");
        assertEq(rule.rule.paramRules[0].allowList[1], address(batchLockup), "Second spender should be BatchLockup");
    }

    function test_getCreateStreamRule() public view {
        SablierRules.RuleParams memory rule = SablierRules.getCreateStreamRule(address(sablier));

        assertEq(rule.contractAddress, address(sablier), "Contract address should be Sablier");
        assertEq(
            rule.funcSig,
            ISablierLockupLinear.createWithTimestampsLL.selector,
            "Function sig should be createWithTimestampsLL"
        );
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(rule.rule.paramRules.length, 0, "Should have no param rules");
        assertEq(address(rule.rule.validator), address(0), "Should have no validator");
    }

    function test_getCreateStreamRuleWithValidator() public view {
        SablierRules.RuleParams memory rule =
            SablierRules.getCreateStreamRuleWithValidator(address(sablier), IValidator(address(validator)));

        assertEq(rule.contractAddress, address(sablier), "Contract address should be Sablier");
        assertEq(
            rule.funcSig,
            ISablierLockupLinear.createWithTimestampsLL.selector,
            "Function sig should be createWithTimestampsLL"
        );
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(address(rule.rule.validator), address(validator), "Should have validator set");
    }

    function test_getCreateBatchStreamRule() public view {
        SablierRules.RuleParams memory rule = SablierRules.getCreateBatchStreamRule(address(batchLockup));

        assertEq(rule.contractAddress, address(batchLockup), "Contract address should be BatchLockup");
        assertEq(
            rule.funcSig,
            ISablierBatchLockup.createWithTimestampsLL.selector,
            "Function sig should be batch createWithTimestampsLL"
        );
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(rule.rule.paramRules.length, 0, "Should have no param rules");
        assertEq(address(rule.rule.validator), address(0), "Should have no validator");
    }

    function test_getCreateBatchStreamRuleWithValidator() public view {
        SablierRules.RuleParams memory rule =
            SablierRules.getCreateBatchStreamRuleWithValidator(address(batchLockup), IValidator(address(validator)));

        assertEq(rule.contractAddress, address(batchLockup), "Contract address should be BatchLockup");
        assertEq(
            rule.funcSig,
            ISablierBatchLockup.createWithTimestampsLL.selector,
            "Function sig should be batch createWithTimestampsLL"
        );
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(address(rule.rule.validator), address(validator), "Should have validator set");
    }

    function test_getTransferStreamRule() public view {
        address[] memory recipients = new address[](1);
        recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;

        SablierRules.RuleParams memory rule =
            SablierRules.getTransferStreamRule(address(sablier), address(strategy), recipients);

        assertEq(rule.contractAddress, address(sablier), "Contract address should be Sablier");
        assertEq(
            rule.funcSig,
            bytes4(keccak256("safeTransferFrom(address,address,uint256)")),
            "Function sig should be safeTransferFrom"
        );
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(rule.rule.paramRules.length, 3, "Should have 3 param rules");
        assertEq(rule.rule.paramRules[0].allowList[0], address(strategy), "From should be strategy");
        assertEq(
            rule.rule.paramRules[1].allowList[0], MainnetKeeperContracts.REWARDS_SWEEPER, "To should be rewards sweeper"
        );
    }

    function test_getTransferRule() public view {
        address[] memory recipients = new address[](1);
        recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;

        SablierRules.RuleParams memory rule = SablierRules.getTransferRule(address(usdc), recipients);

        assertEq(rule.contractAddress, address(usdc), "Contract address should be USDC");
        assertEq(rule.funcSig, IERC20.transfer.selector, "Function sig should be transfer");
        assertTrue(rule.rule.isActive, "Rule should be active");
        assertEq(rule.rule.paramRules.length, 2, "Should have 2 param rules");
        assertEq(
            rule.rule.paramRules[0].allowList[0], MainnetKeeperContracts.REWARDS_SWEEPER, "To should be rewards sweeper"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         RULES SET CORRECTLY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_sablierRulesAreSet() public view {
        // Check approve rule
        IVault.FunctionRule memory approveRule =
            IVault(address(strategy)).getProcessorRule(address(usdc), IERC20.approve.selector);
        assertTrue(approveRule.isActive, "Approve rule should be active");
        assertEq(approveRule.paramRules.length, 2, "Approve rule should have 2 param rules");
        assertEq(approveRule.paramRules[0].allowList.length, 2, "Approve rule should allow 2 spenders");
        assertEq(approveRule.paramRules[0].allowList[0], address(sablier), "First spender should be Sablier");
        assertEq(approveRule.paramRules[0].allowList[1], address(batchLockup), "Second spender should be BatchLockup");

        // Check create stream rule with validator
        IVault.FunctionRule memory createRule = IVault(address(strategy)).getProcessorRule(
            address(sablier), ISablierLockupLinear.createWithTimestampsLL.selector
        );
        assertTrue(createRule.isActive, "Create stream rule should be active");
        assertEq(address(createRule.validator), address(validator), "Validator should be set");

        // Check batch create stream rule with validator
        IVault.FunctionRule memory batchCreateRule = IVault(address(strategy)).getProcessorRule(
            address(batchLockup), ISablierBatchLockup.createWithTimestampsLL.selector
        );
        assertTrue(batchCreateRule.isActive, "Batch create stream rule should be active");
        assertEq(address(batchCreateRule.validator), address(validator), "Batch validator should be set");

        // Check transfer stream rule
        bytes4 safeTransferSig = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
        IVault.FunctionRule memory transferRule =
            IVault(address(strategy)).getProcessorRule(address(sablier), safeTransferSig);
        assertTrue(transferRule.isActive, "Transfer rule should be active");
        assertEq(transferRule.paramRules.length, 3, "Transfer rule should have 3 param rules");

        // Check ERC20 transfer rule
        IVault.FunctionRule memory erc20TransferRule =
            IVault(address(strategy)).getProcessorRule(address(usdc), IERC20.transfer.selector);
        assertTrue(erc20TransferRule.isActive, "ERC20 transfer rule should be active");
    }

    /*//////////////////////////////////////////////////////////////
                         PROCESSOR INTEGRATION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_createSablierStreamViaProcessor() public {
        uint256 streamAmount = 1000e6;

        // Build processor calls
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        // Call 1: Approve Sablier to spend USDC
        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Call 2: Create stream with valid params
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount),
            token: usdc,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});
        targets[1] = address(sablier);
        values[1] = 0;
        data[1] = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        uint256 balanceBefore = usdc.balanceOf(address(strategy));

        // Execute via processor
        vm.prank(processor);
        strategy.processor(targets, values, data);

        // Verify USDC was transferred to Sablier
        assertEq(
            usdc.balanceOf(address(strategy)), balanceBefore - streamAmount, "Strategy USDC balance should decrease"
        );
    }

    function test_createBatchSablierStreamViaProcessor() public {
        uint256 streamAmount1 = 1000e6;
        uint256 streamAmount2 = 2000e6;
        uint256 streamAmount3 = 500e6;
        uint256 totalAmount = streamAmount1 + streamAmount2 + streamAmount3;

        ISablierLockup sablierLockup = ISablierLockup(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        uint256 nextStreamIdBefore = sablierLockup.nextStreamId();

        // Build processor calls
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        // Call 1: Approve BatchLockup to spend USDC
        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), totalAmount));

        // Call 2: Batch create 3 streams
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](3);

        batch[0] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount1),
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        batch[1] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount2),
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 56 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        batch[2] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount3),
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 14 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        uint256 balanceBefore = usdc.balanceOf(address(strategy));

        // Execute via processor
        vm.prank(processor);
        strategy.processor(targets, values, data);

        // Verify USDC was transferred
        assertEq(
            usdc.balanceOf(address(strategy)), balanceBefore - totalAmount, "Strategy USDC balance should decrease"
        );

        // Verify 3 stream IDs were created
        assertEq(sablierLockup.nextStreamId(), nextStreamIdBefore + 3, "3 stream IDs should be created");

        // Verify stream details
        assertEq(sablierLockup.getSender(nextStreamIdBefore), safe, "Stream 1 sender should be safe");
        assertEq(
            sablierLockup.getRecipient(nextStreamIdBefore),
            MainnetKeeperContracts.REWARDS_SWEEPER,
            "Stream 1 recipient should match"
        );
        assertEq(
            sablierLockup.getDepositedAmount(nextStreamIdBefore), uint128(streamAmount1), "Stream 1 amount should match"
        );

        assertEq(sablierLockup.getSender(nextStreamIdBefore + 1), safe, "Stream 2 sender should be safe");
        assertEq(
            sablierLockup.getDepositedAmount(nextStreamIdBefore + 1),
            uint128(streamAmount2),
            "Stream 2 amount should match"
        );

        assertEq(sablierLockup.getSender(nextStreamIdBefore + 2), safe, "Stream 3 sender should be safe");
        assertEq(
            sablierLockup.getDepositedAmount(nextStreamIdBefore + 2),
            uint128(streamAmount3),
            "Stream 3 amount should match"
        );
    }

    function test_erc20TransferViaProcessor() public {
        uint256 transferAmount = 500e6;

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory data = new bytes[](1);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.transfer, (MainnetKeeperContracts.REWARDS_SWEEPER, transferAmount));

        uint256 receiverBalanceBefore = usdc.balanceOf(MainnetKeeperContracts.REWARDS_SWEEPER);

        vm.prank(processor);
        strategy.processor(targets, values, data);

        assertEq(
            usdc.balanceOf(MainnetKeeperContracts.REWARDS_SWEEPER),
            receiverBalanceBefore + transferAmount,
            "Receiver should have received tokens"
        );
    }

    /*//////////////////////////////////////////////////////////////
                         VALIDATION FAILURE TESTS (SINGLE)
    //////////////////////////////////////////////////////////////*/

    function test_revert_createStreamWithInvalidSender() public {
        uint256 streamAmount = 1000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Use wrong sender (not the safe)
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: address(strategy), // WRONG - should be safe
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount),
            token: usdc,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});
        targets[1] = address(sablier);
        values[1] = 0;
        data[1] = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidSender.selector, address(strategy), safe)
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_createStreamWithInvalidRecipient() public {
        uint256 streamAmount = 1000e6;
        address invalidRecipient = address(0xDEAD);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: invalidRecipient, // WRONG - not in allowed list
            depositAmount: uint128(streamAmount),
            token: usdc,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});
        targets[1] = address(sablier);
        values[1] = 0;
        data[1] = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidRecipient.selector, invalidRecipient)
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_createStreamNotCancelable() public {
        uint256 streamAmount = 1000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount),
            token: usdc,
            cancelable: false, // WRONG - must be true
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});
        targets[1] = address(sablier);
        values[1] = 0;
        data[1] = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        vm.prank(processor);
        vm.expectRevert(StrategyKeeperSablierValidator.StreamMustBeCancelable.selector);
        strategy.processor(targets, values, data);
    }

    function test_revert_createStreamNotTransferable() public {
        uint256 streamAmount = 1000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount),
            token: usdc,
            cancelable: true,
            transferable: false, // WRONG - must be true
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});
        targets[1] = address(sablier);
        values[1] = 0;
        data[1] = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        vm.prank(processor);
        vm.expectRevert(StrategyKeeperSablierValidator.StreamMustBeTransferable.selector);
        strategy.processor(targets, values, data);
    }

    function test_revert_createStreamWithInvalidToken() public {
        uint256 streamAmount = 1000e6;
        address wrongToken = address(0xBEEF);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: uint128(streamAmount),
            token: IERC20(wrongToken), // WRONG - not USDC
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});
        targets[1] = address(sablier);
        values[1] = 0;
        data[1] = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidToken.selector, wrongToken, address(usdc))
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_approveUnauthorizedSpender() public {
        address unauthorizedSpender = address(0xBEEF);

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory data = new bytes[](1);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (unauthorizedSpender, 1000e6));

        vm.prank(processor);
        vm.expectRevert();
        strategy.processor(targets, values, data);
    }

    function test_revert_erc20TransferUnauthorizedRecipient() public {
        address unauthorizedRecipient = address(0xBEEF);

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory data = new bytes[](1);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.transfer, (unauthorizedRecipient, 1000e6));

        vm.prank(processor);
        vm.expectRevert();
        strategy.processor(targets, values, data);
    }

    /*//////////////////////////////////////////////////////////////
                     VALIDATION FAILURE TESTS (BATCH)
    //////////////////////////////////////////////////////////////*/

    function _buildValidBatch(uint256 count)
        internal
        view
        returns (ISablierBatchLockup.CreateWithTimestampsLL[] memory batch)
    {
        batch = new ISablierBatchLockup.CreateWithTimestampsLL[](count);
        for (uint256 i = 0; i < count; i++) {
            batch[i] = ISablierBatchLockup.CreateWithTimestampsLL({
                sender: safe,
                recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
                depositAmount: 1000e6,
                cancelable: true,
                transferable: true,
                timestamps: ISablierLockupLinear.Timestamps({
                    start: uint40(block.timestamp),
                    end: uint40(block.timestamp + 28 days)
                }),
                cliffTime: 0,
                unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
                shape: "linear"
            });
        }
    }

    function test_revert_batchStreamWithInvalidSender() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = _buildValidBatch(2);
        batch[1].sender = address(0xDEAD); // WRONG sender in second item

        uint256 totalAmount = 2000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), totalAmount));

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidSender.selector, address(0xDEAD), safe)
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_batchStreamWithInvalidRecipient() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = _buildValidBatch(2);
        batch[0].recipient = address(0xDEAD); // WRONG recipient in first item

        uint256 totalAmount = 2000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), totalAmount));

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidRecipient.selector, address(0xDEAD))
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_batchStreamNotCancelable() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = _buildValidBatch(2);
        batch[1].cancelable = false; // WRONG

        uint256 totalAmount = 2000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), totalAmount));

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        vm.prank(processor);
        vm.expectRevert(StrategyKeeperSablierValidator.StreamMustBeCancelable.selector);
        strategy.processor(targets, values, data);
    }

    function test_revert_batchStreamNotTransferable() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = _buildValidBatch(2);
        batch[0].transferable = false; // WRONG

        uint256 totalAmount = 2000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), totalAmount));

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        vm.prank(processor);
        vm.expectRevert(StrategyKeeperSablierValidator.StreamMustBeTransferable.selector);
        strategy.processor(targets, values, data);
    }

    function test_revert_batchStreamWithInvalidToken() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = _buildValidBatch(1);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), 1000e6));

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL,
            (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, IERC20(address(0xBEEF)), batch) // WRONG token
        );

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidToken.selector, address(0xBEEF), address(usdc))
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_batchStreamWithInvalidLockup() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = _buildValidBatch(1);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(batchLockup), 1000e6));

        targets[1] = address(batchLockup);
        values[1] = 0;
        data[1] = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL,
            (address(0xDEAD), usdc, batch) // WRONG lockup
        );

        vm.prank(processor);
        vm.expectRevert(
            abi.encodeWithSelector(
                StrategyKeeperSablierValidator.InvalidLockupAddress.selector,
                address(0xDEAD),
                MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR
            )
        );
        strategy.processor(targets, values, data);
    }
}

/// @title StrategyKeeperSablierValidatorIntegrationTest
/// @notice Direct unit tests for the StrategyKeeperSablierValidator with real contracts
contract StrategyKeeperSablierValidatorIntegrationTest is Test {
    FlexStrategy public strategy;
    IAccountingModule public accountingModule;
    ISablierLockupLinear public sablier;
    IERC20 public usdc;
    StrategyKeeperSablierValidator public validator;

    address public safe;

    function setUp() public {
        // Use deployed strategy directly
        strategy = FlexStrategy(payable(MainnetKeeperContracts.FLEX_STRATEGY));
        accountingModule = strategy.accountingModule();

        sablier = ISablierLockupLinear(MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR);
        usdc = IERC20(MainnetKeeperContracts.USDC);
        safe = accountingModule.safe();

        address[] memory allowedRecipients = new address[](1);
        allowedRecipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        validator = new StrategyKeeperSablierValidator(
            safe, MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, address(usdc), allowedRecipients
        );
    }

    function test_validatorDeployment() public view {
        assertEq(validator.safe(), safe, "Safe should be set correctly");
        assertEq(validator.lockup(), MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, "Lockup should be set correctly");
        assertEq(validator.token(), address(usdc), "Token should be set correctly");
        assertTrue(
            validator.isAllowedRecipient(MainnetKeeperContracts.REWARDS_SWEEPER), "Rewards sweeper should be allowed"
        );
        assertEq(validator.getAllowedRecipientsCount(), 1, "Should have 1 allowed recipient");
    }

    function test_revert_validatorDeployment_zeroSafe() public {
        address[] memory recipients = new address[](1);
        recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        vm.expectRevert(StrategyKeeperSablierValidator.ZeroAddress.selector);
        new StrategyKeeperSablierValidator(
            address(0), MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, address(usdc), recipients
        );
    }

    function test_revert_validatorDeployment_zeroLockup() public {
        address[] memory recipients = new address[](1);
        recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        vm.expectRevert(StrategyKeeperSablierValidator.ZeroAddress.selector);
        new StrategyKeeperSablierValidator(safe, address(0), address(usdc), recipients);
    }

    function test_revert_validatorDeployment_zeroToken() public {
        address[] memory recipients = new address[](1);
        recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        vm.expectRevert(StrategyKeeperSablierValidator.ZeroAddress.selector);
        new StrategyKeeperSablierValidator(safe, MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, address(0), recipients);
    }

    function test_revert_validatorDeployment_emptyRecipients() public {
        address[] memory recipients = new address[](0);
        vm.expectRevert(StrategyKeeperSablierValidator.EmptyAllowedRecipients.selector);
        new StrategyKeeperSablierValidator(
            safe, MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, address(usdc), recipients
        );
    }

    function test_validateValidCalldata() public view {
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: 1000e6,
            token: usdc,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            shape: ""
        });
        ISablierLockupLinear.UnlockAmounts memory unlockAmounts =
            ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0});

        bytes memory callData = abi.encodeCall(ISablierLockupLinear.createWithTimestampsLL, (params, unlockAmounts, 0));

        // Should not revert
        validator.validate(address(sablier), 0, callData);
    }

    function test_validateValidBatchCalldata() public view {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](1);

        batch[0] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: 1000e6,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        bytes memory callData = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        // Should not revert
        validator.validate(MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, 0, callData);
    }

    function test_validateBatchMultipleItems() public view {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](3);

        for (uint256 i = 0; i < 3; i++) {
            batch[i] = ISablierBatchLockup.CreateWithTimestampsLL({
                sender: safe,
                recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
                depositAmount: uint128((i + 1) * 1000e6),
                cancelable: true,
                transferable: true,
                timestamps: ISablierLockupLinear.Timestamps({
                    start: uint40(block.timestamp),
                    end: uint40(block.timestamp + 28 days)
                }),
                cliffTime: 0,
                unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
                shape: "linear"
            });
        }

        bytes memory callData = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        // Should not revert
        validator.validate(MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, 0, callData);
    }

    function test_revert_invalidFunctionSelector() public {
        bytes memory data = abi.encodeWithSelector(bytes4(0xdeadbeef), "test");

        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidFunctionSelector.selector, bytes4(0xdeadbeef))
        );
        validator.validate(address(sablier), 0, data);
    }

    function test_revert_batchInvalidSenderInOneItem() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](2);

        batch[0] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: safe, // Valid
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: 1000e6,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        batch[1] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: address(0xDEAD), // INVALID
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: 1000e6,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        bytes memory callData = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidSender.selector, address(0xDEAD), safe)
        );
        validator.validate(MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, 0, callData);
    }

    function test_revert_batchEmptyBatch() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](0);

        bytes memory callData = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL, (MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, usdc, batch)
        );

        vm.expectRevert(StrategyKeeperSablierValidator.EmptyBatch.selector);
        validator.validate(MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, 0, callData);
    }

    function test_revert_batchInvalidLockup() public {
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](1);

        batch[0] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: safe,
            recipient: MainnetKeeperContracts.REWARDS_SWEEPER,
            depositAmount: 1000e6,
            cancelable: true,
            transferable: true,
            timestamps: ISablierLockupLinear.Timestamps({
                start: uint40(block.timestamp),
                end: uint40(block.timestamp + 28 days)
            }),
            cliffTime: 0,
            unlockAmounts: ISablierLockupLinear.UnlockAmounts({start: 0, cliff: 0}),
            shape: "linear"
        });

        bytes memory callData = abi.encodeCall(
            ISablierBatchLockup.createWithTimestampsLL,
            (address(0xDEAD), usdc, batch) // WRONG lockup
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                StrategyKeeperSablierValidator.InvalidLockupAddress.selector,
                address(0xDEAD),
                MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR
            )
        );
        validator.validate(MainnetKeeperContracts.SABLIER_BATCH_LOCKUP, 0, callData);
    }

    function test_getAllowedRecipients() public view {
        address[] memory recipients = validator.getAllowedRecipients();
        assertEq(recipients.length, 1, "Should have 1 recipient");
        assertEq(recipients[0], MainnetKeeperContracts.REWARDS_SWEEPER, "Should be rewards sweeper");
    }

    function test_multipleAllowedRecipients() public {
        address recipient2 = address(0x6666);
        address recipient3 = address(0x7777);

        address[] memory recipients = new address[](3);
        recipients[0] = MainnetKeeperContracts.REWARDS_SWEEPER;
        recipients[1] = recipient2;
        recipients[2] = recipient3;

        StrategyKeeperSablierValidator multiValidator = new StrategyKeeperSablierValidator(
            safe, MainnetKeeperContracts.SABLIER_LOCKUP_LINEAR, address(usdc), recipients
        );

        assertTrue(
            multiValidator.isAllowedRecipient(MainnetKeeperContracts.REWARDS_SWEEPER),
            "Rewards sweeper should be allowed"
        );
        assertTrue(multiValidator.isAllowedRecipient(recipient2), "recipient2 should be allowed");
        assertTrue(multiValidator.isAllowedRecipient(recipient3), "recipient3 should be allowed");
        assertFalse(multiValidator.isAllowedRecipient(address(0xDEAD)), "0xDEAD should not be allowed");
        assertEq(multiValidator.getAllowedRecipientsCount(), 3, "Should have 3 recipients");
    }
}
