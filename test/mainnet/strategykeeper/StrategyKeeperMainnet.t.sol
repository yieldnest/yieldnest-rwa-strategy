// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {Enum} from "lib/safe-smart-account/contracts/libraries/Enum.sol";
import {IAccessControl} from "lib/openzeppelin-contracts/contracts/access/IAccessControl.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";
import {ISablierBatchLockup} from "src/interfaces/sablier/ISablierBatchLockup.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";

interface IVaultRoles is IAccessControl {
    function PROCESSOR_ROLE() external view returns (bytes32);
}

interface ISablierLockup {
    function nextStreamId() external view returns (uint256);
    function getSender(uint256 streamId) external view returns (address);
    function getRecipient(uint256 streamId) external view returns (address);
    function getDepositedAmount(uint256 streamId) external view returns (uint128);
    function getStartTime(uint256 streamId) external view returns (uint40);
    function getEndTime(uint256 streamId) external view returns (uint40);
    function isCancelable(uint256 streamId) external view returns (bool);
    function isTransferable(uint256 streamId) external view returns (bool);
    function ownerOf(uint256 streamId) external view returns (address); // ERC-721 NFT owner
}

/// @title StrategyKeeperMainnetTest
/// @notice Integration tests for StrategyKeeper with mainnet fork using module execution
/// @dev Run with: forge test --match-path "test/mainnet/strategykeeper/*.sol" --fork-url <RPC_URL>
contract StrategyKeeperMainnetTest is Test {
    // Mainnet addresses
    address constant VAULT = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8; // ynRWAx
    address constant TARGET_STRATEGY = 0xF6e1443e3F70724cec8C0a779C7C35A8DcDA928B;
    address constant FEE_WALLET = 0xC92Dd1837EBcb0365eB0a8795f9c8E474f8B6183;
    address constant BORROWER = 0xaa7f79Bb105833D655D1C13C175142c44e209912;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant SABLIER = 0xcF8ce57fa442ba50aCbC57147a62aD03873FfA73;
    address constant SABLIER_BATCH_LOCKUP = 0x0636D83B184D65C242c43de6AAd10535BFb9D45a;

    // Mainnet Safe infrastructure
    address constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    // USDC whale for funding
    address constant USDC_WHALE = 0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341;

    // Test accounts
    address public admin;
    address public keeperBot;
    address public powerKeeperBot;
    address public streamReceiver;

    // EOA owner for the Safe
    uint256 public eoaOwnerPk = 0xA11CE;
    address public eoaOwner;

    // Contracts
    StrategyKeeper public keeper;
    Safe public safe;

    function setUp() public {
        admin = makeAddr("admin");
        keeperBot = makeAddr("keeperBot");
        powerKeeperBot = makeAddr("powerKeeperBot");
        streamReceiver = makeAddr("streamReceiver");
        eoaOwner = vm.addr(eoaOwnerPk);

        // Deploy Safe first (keeper address not yet known, will enable module after)
        safe = _deploySafe();

        // Deploy keeper: admin gets admin roles, address(this) is initializer,
        // admin is pauser, keeperBot is processor (gets both keeper roles)
        keeper = new StrategyKeeper(admin, address(this), admin, keeperBot);
        keeper.initialize(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.01e18, // 1%
                feeFraction: 11
            })
        );

        // Enable keeper as a module on the Safe
        _enableModuleOnSafe(address(keeper));

        // For testing: separate KEEPER_ROLE and POWER_KEEPER_ROLE onto different addresses
        vm.startPrank(admin);
        keeper.grantRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot);
        keeper.revokeRole(keeper.POWER_KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund safe with USDC from whale
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(address(safe), 100_000e6);

        // Grant PROCESSOR_ROLE to keeper on the vault
        bytes32 processorRole = IVaultRoles(VAULT).PROCESSOR_ROLE();
        vm.prank(0xfcad670592a3b24869C0b51a6c6FDED4F95D6975);
        IVaultRoles(VAULT).grantRole(processorRole, address(keeper));
    }

    function _deploySafe() internal returns (Safe) {
        address[] memory owners = new address[](1);
        owners[0] = eoaOwner;

        bytes memory setupData = abi.encodeCall(
            Safe.setup,
            (
                owners,
                1, // threshold
                address(0),
                "",
                address(0),
                address(0),
                0,
                payable(address(0))
            )
        );

        SafeProxyFactory factory = SafeProxyFactory(SAFE_PROXY_FACTORY);
        SafeProxy safeProxy = factory.createProxyWithNonce(SAFE_SINGLETON, setupData, block.timestamp);
        return Safe(payable(address(safeProxy)));
    }

    function _enableModuleOnSafe(address module) internal {
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", module);
        bytes32 txHash = safe.getTransactionHash(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPk, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        safe.execTransaction(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signature
        );
    }

    function test_initialization() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();

        assertEq(cfg.vault, VAULT, "vault mismatch");
        assertEq(cfg.targetStrategy, TARGET_STRATEGY, "targetStrategy mismatch");
        assertEq(cfg.safe, address(safe), "safe mismatch");
        assertEq(cfg.baseAsset, USDC, "baseAsset mismatch");
        assertEq(cfg.borrower, BORROWER, "borrower mismatch");
        assertEq(cfg.feeWallet, FEE_WALLET, "feeWallet mismatch");
        assertEq(cfg.streamReceiver, streamReceiver, "streamReceiver mismatch");
        assertEq(cfg.sablier, SABLIER, "sablier mismatch");
        assertEq(cfg.minThreshold, 10_000e6, "minThreshold mismatch");
        assertEq(cfg.minResidual, 1_000e6, "minResidual mismatch");
        assertEq(cfg.apr, 0.121e18, "apr mismatch");
        assertEq(cfg.holdingPeriod, 28 days, "holdingPeriod mismatch");
        assertEq(cfg.minProcessingPercent, 0.01e18, "minProcessingPercent mismatch");
    }

    function test_safeSetup() public view {
        assertTrue(safe.isModuleEnabled(address(keeper)), "keeper should be enabled as module");
        assertTrue(safe.isOwner(eoaOwner), "EOA should be safe owner");
        assertEq(safe.getThreshold(), 1, "safe threshold should be 1");
        assertEq(safe.getOwners().length, 1, "safe should have 1 owner");
    }

    function test_safeBalance() public view {
        assertEq(IERC20(USDC).balanceOf(address(safe)), 100_000e6, "safe should have 100k USDC");
    }

    function test_roles() public view {
        assertTrue(keeper.hasRole(keeper.DEFAULT_ADMIN_ROLE(), admin), "admin should have DEFAULT_ADMIN_ROLE");
        assertTrue(keeper.hasRole(keeper.CONFIG_MANAGER_ROLE(), admin), "admin should have CONFIG_MANAGER_ROLE");
        assertTrue(keeper.hasRole(keeper.KEEPER_ROLE(), keeperBot), "keeperBot should have KEEPER_ROLE");
        assertTrue(
            keeper.hasRole(keeper.POWER_KEEPER_ROLE(), powerKeeperBot), "powerKeeperBot should have POWER_KEEPER_ROLE"
        );
        assertTrue(keeper.hasRole(keeper.PAUSER_ROLE(), admin), "admin should have PAUSER_ROLE");
    }

    function test_vaultExists() public view {
        assertTrue(VAULT.code.length > 0, "vault should have code");
    }

    function test_targetStrategyExists() public view {
        assertTrue(TARGET_STRATEGY.code.length > 0, "targetStrategy should have code");
    }

    function test_sablierExists() public view {
        assertTrue(SABLIER.code.length > 0, "sablier should have code");
    }

    function test_usdcDecimals() public view {
        (bool success, bytes memory data) = USDC.staticcall(abi.encodeWithSignature("decimals()"));
        assertTrue(success, "decimals() call should succeed");
        assertEq(abi.decode(data, (uint8)), 6, "USDC should have 6 decimals");
    }

    function test_yieldCalculation() public pure {
        // 100,000 USDC at 12.1% APR for 28 days
        // 100000 * 0.121 * 28 / 365 = 928.22
        uint256 available = 100_000e6;
        uint256 apr = 0.121e18;
        uint256 holdingPeriod = 28 days;
        uint256 SECONDS_PER_YEAR = 365 days;
        uint256 PRECISION = 1e18;

        uint256 interest = (available * apr * holdingPeriod) / SECONDS_PER_YEAR / PRECISION;

        assertApproxEqAbs(interest, 928_219_178, 1e3, "interest calculation mismatch");

        uint256 fee = interest / 11;
        uint256 streamAmount = interest - fee;
        assertEq(fee + streamAmount, interest, "fee + streamAmount should equal interest");
    }

    function test_revertOnUnauthorizedKeeper() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_revertOnUnauthorizedPowerKeeper() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.processInflows(0, 50_000e6);
    }

    function test_revertOnUnauthorizedConfigUpdate() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.setConfig(cfg);
    }

    function test_configValidation_zeroVault() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.vault = address(0);

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.ZeroAddress.selector);
        keeper.setConfig(cfg);
    }

    function test_configValidation_zeroApr() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.apr = 0;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_configValidation_aprTooHigh() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.apr = 2e18;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_configValidation_zeroHoldingPeriod() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.holdingPeriod = 0;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_processInflows_success() public {
        // Seed vault with USDC so _shouldProcess triggers (vault >= minThreshold)
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(VAULT, 20_000e6);

        // Get initial balances
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));
        uint256 borrowerBalanceBefore = IERC20(USDC).balanceOf(BORROWER);
        uint256 feeWalletBalanceBefore = IERC20(USDC).balanceOf(FEE_WALLET);
        uint256 sablierBalanceBefore = IERC20(USDC).balanceOf(SABLIER);

        // Get expected stream ID before execution
        ISablierLockup sablier = ISablierLockup(SABLIER);
        uint256 expectedStreamId = sablier.nextStreamId();

        // Calculate expected amounts
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = safeBalanceBefore - cfg.minResidual;
        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        // Record timestamp for stream verification
        uint256 expectedStartTime = block.timestamp;
        uint256 expectedEndTime = block.timestamp + cfg.holdingPeriod;

        // Execute processInflows
        vm.prank(keeperBot);
        keeper.processInflows();

        // Assert borrower received principal
        assertEq(
            IERC20(USDC).balanceOf(BORROWER), borrowerBalanceBefore + principal, "Borrower should receive principal"
        );

        // Assert fee wallet received fee
        assertEq(IERC20(USDC).balanceOf(FEE_WALLET), feeWalletBalanceBefore + fee, "Fee wallet should receive fee");

        // Assert safe balance decreased correctly (principal + fee + streamAmount)
        assertEq(IERC20(USDC).balanceOf(address(safe)), cfg.minResidual, "Safe should only have minResidual left");

        // Assert stream was created (Sablier balance increased by streamAmount)
        assertEq(
            IERC20(USDC).balanceOf(SABLIER), sablierBalanceBefore + streamAmount, "Sablier should hold stream amount"
        );

        // Assert next stream ID incremented
        assertEq(sablier.nextStreamId(), expectedStreamId + 1, "Stream ID should increment");

        // Assert stream fields are correct
        assertEq(sablier.getSender(expectedStreamId), address(safe), "Stream sender should be safe");
        assertEq(sablier.getRecipient(expectedStreamId), streamReceiver, "Stream recipient should be streamReceiver");
        assertEq(sablier.ownerOf(expectedStreamId), streamReceiver, "Stream NFT owner should be streamReceiver");
        assertEq(sablier.getDepositedAmount(expectedStreamId), uint128(streamAmount), "Stream deposit should match");
        assertEq(sablier.getStartTime(expectedStreamId), uint40(expectedStartTime), "Stream start time should match");
        assertEq(sablier.getEndTime(expectedStreamId), uint40(expectedEndTime), "Stream end time should match");
        assertTrue(sablier.isCancelable(expectedStreamId), "Stream should be cancelable");
        assertTrue(sablier.isTransferable(expectedStreamId), "Stream should be transferable");
    }

    // ======== POWER_KEEPER_ROLE processInflows(uint256, uint256) tests ========

    function test_processInflowsManual_success() public {
        // Get initial balances
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));
        uint256 borrowerBalanceBefore = IERC20(USDC).balanceOf(BORROWER);
        uint256 feeWalletBalanceBefore = IERC20(USDC).balanceOf(FEE_WALLET);
        uint256 sablierBalanceBefore = IERC20(USDC).balanceOf(SABLIER);

        // Get expected stream ID before execution
        ISablierLockup sablier = ISablierLockup(SABLIER);
        uint256 expectedStreamId = sablier.nextStreamId();

        // Use same available as the auto version would compute
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = safeBalanceBefore - cfg.minResidual;
        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        // Record timestamp for stream verification
        uint256 expectedStartTime = block.timestamp;
        uint256 expectedEndTime = block.timestamp + cfg.holdingPeriod;

        // Execute processInflows with manual params (no vault allocation, full available)
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // Assert borrower received principal
        assertEq(
            IERC20(USDC).balanceOf(BORROWER), borrowerBalanceBefore + principal, "Borrower should receive principal"
        );

        // Assert fee wallet received fee
        assertEq(IERC20(USDC).balanceOf(FEE_WALLET), feeWalletBalanceBefore + fee, "Fee wallet should receive fee");

        // Assert safe balance decreased correctly
        assertEq(IERC20(USDC).balanceOf(address(safe)), cfg.minResidual, "Safe should only have minResidual left");

        // Assert stream was created
        assertEq(
            IERC20(USDC).balanceOf(SABLIER), sablierBalanceBefore + streamAmount, "Sablier should hold stream amount"
        );

        // Assert stream fields are correct
        assertEq(sablier.nextStreamId(), expectedStreamId + 1, "Stream ID should increment");
        assertEq(sablier.getSender(expectedStreamId), address(safe), "Stream sender should be safe");
        assertEq(sablier.getRecipient(expectedStreamId), streamReceiver, "Stream recipient should be streamReceiver");
        assertEq(sablier.ownerOf(expectedStreamId), streamReceiver, "Stream NFT owner should be streamReceiver");
        assertEq(sablier.getDepositedAmount(expectedStreamId), uint128(streamAmount), "Stream deposit should match");
        assertEq(sablier.getStartTime(expectedStreamId), uint40(expectedStartTime), "Stream start time should match");
        assertEq(sablier.getEndTime(expectedStreamId), uint40(expectedEndTime), "Stream end time should match");
        assertTrue(sablier.isCancelable(expectedStreamId), "Stream should be cancelable");
        assertTrue(sablier.isTransferable(expectedStreamId), "Stream should be transferable");
    }

    function test_processInflowsManual_partialAvailable() public {
        // Power keeper can choose to disburse less than the full available amount
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));
        uint256 borrowerBalanceBefore = IERC20(USDC).balanceOf(BORROWER);
        uint256 feeWalletBalanceBefore = IERC20(USDC).balanceOf(FEE_WALLET);
        uint256 sablierBalanceBefore = IERC20(USDC).balanceOf(SABLIER);

        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();

        // Use only half of the available amount
        uint256 fullAvailable = safeBalanceBefore - cfg.minResidual;
        uint256 partialAvailable = fullAvailable / 2;

        uint256 interest = (partialAvailable * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = partialAvailable - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, partialAvailable);

        // Assert borrower received principal for partial amount
        assertEq(
            IERC20(USDC).balanceOf(BORROWER), borrowerBalanceBefore + principal, "Borrower should receive principal"
        );

        // Assert fee wallet received fee
        assertEq(IERC20(USDC).balanceOf(FEE_WALLET), feeWalletBalanceBefore + fee, "Fee wallet should receive fee");

        // Assert safe retained more than minResidual (since we only used half)
        uint256 expectedSafeBalance = safeBalanceBefore - partialAvailable;
        assertEq(IERC20(USDC).balanceOf(address(safe)), expectedSafeBalance, "Safe should retain extra funds");
        assertTrue(expectedSafeBalance > cfg.minResidual, "Safe should have more than minResidual");

        // Assert stream was created
        assertEq(
            IERC20(USDC).balanceOf(SABLIER), sablierBalanceBefore + streamAmount, "Sablier should hold stream amount"
        );
    }

    function test_processInflowsManual_matchesAutoVersion() public {
        // Both versions should produce identical results when given the same parameters
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 safeBalance = IERC20(USDC).balanceOf(address(safe));
        uint256 available = safeBalance - cfg.minResidual;

        // Calculate expected amounts
        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        // Record balances before
        uint256 borrowerBefore = IERC20(USDC).balanceOf(BORROWER);
        uint256 feeBefore = IERC20(USDC).balanceOf(FEE_WALLET);
        uint256 sablierBefore = IERC20(USDC).balanceOf(SABLIER);

        // Execute via power keeper (no vault allocation, same available as auto would compute)
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // Verify results match expected (same as auto version would produce)
        assertEq(IERC20(USDC).balanceOf(BORROWER), borrowerBefore + principal, "principal mismatch");
        assertEq(IERC20(USDC).balanceOf(FEE_WALLET), feeBefore + fee, "fee mismatch");
        assertEq(IERC20(USDC).balanceOf(SABLIER), sablierBefore + streamAmount, "stream mismatch");
        assertEq(IERC20(USDC).balanceOf(address(safe)), cfg.minResidual, "safe balance mismatch");
    }

    function test_processInflowsManual_updatesTimestamp() public {
        assertEq(keeper.lastProcessedTimestamp(), 0, "should start at 0");

        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = IERC20(USDC).balanceOf(address(safe)) - cfg.minResidual;

        uint256 expectedTimestamp = block.timestamp;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        assertEq(keeper.lastProcessedTimestamp(), expectedTimestamp, "timestamp should be updated");
    }

    function test_processInflowsManual_emitsEvent() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 safeBalance = IERC20(USDC).balanceOf(address(safe));
        uint256 available = safeBalance - cfg.minResidual;

        uint256 interest = (available * cfg.apr * cfg.holdingPeriod) / 365 days / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / cfg.feeFraction;
        uint256 streamAmount = interest - fee;

        vm.expectEmit(true, false, false, false);
        emit IStrategyKeeper.KeeperExecuted(
            block.timestamp,
            0,
            safeBalance,
            cfg.minResidual,
            available,
            interest,
            cfg.apr,
            cfg.holdingPeriod,
            principal,
            fee,
            streamAmount,
            0
        );

        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);
    }

    function test_processInflowsManual_revertOnZeroAvailable() public {
        vm.prank(powerKeeperBot);
        vm.expectRevert(IStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows(0, 0);
    }

    function test_processInflowsManual_revertOnInsufficientSafeBalance() public {
        // Try to disburse more than safe has (minus minResidual)
        uint256 safeBalance = IERC20(USDC).balanceOf(address(safe));
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();

        // available that would leave less than minResidual
        uint256 tooMuch = safeBalance; // Would need safeBalance + minResidual in safe

        vm.prank(powerKeeperBot);
        vm.expectRevert(
            abi.encodeWithSelector(
                IStrategyKeeper.InsufficientSafeBalance.selector, safeBalance, tooMuch + cfg.minResidual
            )
        );
        keeper.processInflows(0, tooMuch);
    }

    function test_processInflowsManual_revertOnKeeperRole() public {
        // KEEPER_ROLE should not be able to call the manual version
        vm.prank(keeperBot);
        vm.expectRevert();
        keeper.processInflows(0, 50_000e6);
    }

    function test_processInflows_revertOnPowerKeeperRole() public {
        // POWER_KEEPER_ROLE should not be able to call the auto version
        vm.prank(powerKeeperBot);
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_processInflowsManual_revertWhenPaused() public {
        vm.prank(admin);
        keeper.pause();

        vm.prank(powerKeeperBot);
        vm.expectRevert();
        keeper.processInflows(0, 50_000e6);
    }

    // ======== Original processInflows() tests ========

    function test_processInflows_noFundsToProcess() public {
        // Update config to set minThreshold very high so vault allocation is skipped
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max, // Skip vault allocation
                minResidual: 100_000e6, // Set minResidual equal to safe balance
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
        vm.stopPrank();

        // Now safe balance (100_000e6) equals minResidual, so no funds to process
        vm.prank(keeperBot);
        vm.expectRevert(IStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows();
    }

    function test_shouldProcess_noFundsAvailable() public {
        // Set minResidual equal to safe balance AND minThreshold very high
        // AND minProcessingPercent high enough that vault balance is below minAmount
        // so neither condition triggers
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max, // Skip vault threshold condition
                minResidual: 100_000e6, // Equal to safe balance
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.5e18, // 50% - vault balance (77K) < 50% of totalAssets (~1.77M) = ~885K
                feeFraction: 11
            })
        );

        // Even with 24h passed, vault balance is below minProcessingPercent of totalAssets
        vm.warp(block.timestamp + 24 hours);
        assertFalse(
            keeper.shouldProcess(), "shouldProcess should be false when vault balance below minProcessingPercent"
        );
    }

    function test_shouldProcess_vaultAboveThreshold() public {
        // Fund vault with USDC above threshold
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(VAULT, 20_000e6);

        // minThreshold is 10_000e6, vault now has > 10k USDC
        assertTrue(keeper.shouldProcess(), "shouldProcess should be true when vault above threshold");
    }

    function test_shouldProcess_timeBasedFallback() public {
        // Set minThreshold very high so condition 1 won't trigger
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.01e18, // 1%
                feeFraction: 11
            })
        );

        // Use manual processInflows to set lastProcessedTimestamp
        // (bypasses _shouldProcess, so we don't need to seed the vault for this step)
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = IERC20(USDC).balanceOf(address(safe)) - cfg.minResidual;
        vm.prank(powerKeeperBot);
        keeper.processInflows(0, available);

        // Now lastProcessedTimestamp is set to current block.timestamp
        assertEq(keeper.lastProcessedTimestamp(), block.timestamp, "lastProcessedTimestamp should be set");

        // Reset vault balance to 2% of vault totalAssets by transferring from USDC_WHALE to the vault
        (bool success, bytes memory data) = VAULT.call(abi.encodeWithSignature("totalAssets()"));
        require(success, "totalAssets() call failed");
        uint256 totalAssets = abi.decode(data, (uint256));
        uint256 twoPercent = totalAssets * 2 / 100;
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(VAULT, twoPercent);

        // Should be false immediately after processing (24h hasn't passed)
        assertFalse(keeper.shouldProcess(), "shouldProcess should be false before 24h");

        // Warp 24 hours
        vm.warp(block.timestamp + 24 hours);

        // Now should be true (24h passed and available >= 1% of vault total)
        assertTrue(keeper.shouldProcess(), "shouldProcess should be true after 24h");
    }

    function test_shouldProcess_timeBasedFallback_belowMinPercent() public {
        // Set minThreshold very high so condition 1 won't trigger
        // Set minProcessingPercent very high so time-based fallback fails
        vm.prank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max,
                minResidual: 99_999e6, // Only 1e6 available
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.5e18, // 50% - way higher than available
                feeFraction: 11
            })
        );

        // Warp 24 hours from now
        vm.warp(block.timestamp + 24 hours);

        // Should be false (24h passed but available < 50% of vault total)
        assertFalse(keeper.shouldProcess(), "shouldProcess should be false when below minProcessingPercent");
    }

    function test_lastProcessedTimestamp_initiallyZero() public view {
        // New keeper should have 0 timestamp
        assertEq(keeper.lastProcessedTimestamp(), 0, "lastProcessedTimestamp should be 0 initially");
    }

    function test_lastProcessedTimestamp_updatedAfterProcess() public {
        // Seed vault with USDC above minThreshold so processInflows triggers
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(VAULT, 20_000e6);

        uint256 expectedTimestamp = block.timestamp;
        vm.prank(keeperBot);
        keeper.processInflows();

        assertEq(
            keeper.lastProcessedTimestamp(), expectedTimestamp, "lastProcessedTimestamp should be updated after process"
        );
    }

    function test_configValidation_minProcessingPercentTooHigh() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.minProcessingPercent = 2e18; // 200%, invalid

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    // ======== Batch Lockup tests ========

    function test_batchLockupExists() public view {
        assertTrue(SABLIER_BATCH_LOCKUP.code.length > 0, "batch lockup should have code");
    }

    function test_batchCreateStreams_viaModule() public {
        uint256 streamAmount1 = 500e6;
        uint256 streamAmount2 = 800e6;
        uint256 totalAmount = streamAmount1 + streamAmount2;

        ISablierLockup sablierLockup = ISablierLockup(SABLIER);
        uint256 nextStreamIdBefore = sablierLockup.nextStreamId();

        // Execute module calls as the keeper (which is an enabled module on the Safe)
        vm.startPrank(address(keeper));

        // Step 1: Approve BatchLockup to spend USDC from the Safe
        bytes memory approveData = abi.encodeCall(IERC20.approve, (SABLIER_BATCH_LOCKUP, totalAmount));
        bool success =
            IGnosisSafe(address(safe)).execTransactionFromModule(USDC, 0, approveData, IGnosisSafe.Operation.Call);
        assertTrue(success, "Approve should succeed");

        // Step 2: Build batch params
        ISablierBatchLockup.CreateWithTimestampsLL[] memory batch = new ISablierBatchLockup.CreateWithTimestampsLL[](2);

        batch[0] = ISablierBatchLockup.CreateWithTimestampsLL({
            sender: address(safe),
            recipient: streamReceiver,
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
            sender: address(safe),
            recipient: streamReceiver,
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

        // Step 3: Call batch createWithTimestampsLL from the Safe
        bytes memory batchData =
            abi.encodeCall(ISablierBatchLockup.createWithTimestampsLL, (SABLIER, IERC20(USDC), batch));
        success = IGnosisSafe(address(safe)).execTransactionFromModule(
            SABLIER_BATCH_LOCKUP, 0, batchData, IGnosisSafe.Operation.Call
        );
        assertTrue(success, "Batch create should succeed");

        vm.stopPrank();

        // Verify 2 streams were created
        assertEq(sablierLockup.nextStreamId(), nextStreamIdBefore + 2, "2 streams should be created");
        assertEq(sablierLockup.getSender(nextStreamIdBefore), address(safe), "Stream 1 sender should be safe");
        assertEq(sablierLockup.getRecipient(nextStreamIdBefore), streamReceiver, "Stream 1 recipient should match");
        assertEq(
            sablierLockup.getDepositedAmount(nextStreamIdBefore), uint128(streamAmount1), "Stream 1 amount should match"
        );
        assertEq(sablierLockup.getSender(nextStreamIdBefore + 1), address(safe), "Stream 2 sender should be safe");
        assertEq(sablierLockup.getRecipient(nextStreamIdBefore + 1), streamReceiver, "Stream 2 recipient should match");
        assertEq(
            sablierLockup.getDepositedAmount(nextStreamIdBefore + 1),
            uint128(streamAmount2),
            "Stream 2 amount should match"
        );
    }
}
