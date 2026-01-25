// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {Enum} from "lib/safe-smart-account/contracts/libraries/Enum.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {KeeperCompanion} from "src/KeeperCompanion.sol";

/// @title StrategyKeeperMainnetTest
/// @notice Integration tests for StrategyKeeper with mainnet fork
/// @dev Run with: forge test --match-path "test/mainnet/strategykeeper/*.sol" --fork-url <RPC_URL>
contract StrategyKeeperMainnetTest is Test {
    // Mainnet addresses
    address constant VAULT = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8; // ynRWAx
    address constant TARGET_STRATEGY = 0xF6e1443e3F70724cec8C0a779C7C35A8DcDA928B;
    address constant FEE_WALLET = 0xC92Dd1837EBcb0365eB0a8795f9c8E474f8B6183;
    address constant BORROWER = 0xaa7f79Bb105833D655D1C13C175142c44e209912;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant SABLIER = 0xcF8ce57fa442ba50aCbC57147a62aD03873FfA73;

    // Mainnet Safe infrastructure
    address constant SAFE_SINGLETON = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address constant SAFE_PROXY_FACTORY = 0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67;

    // USDC whale for funding
    address constant USDC_WHALE = 0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341;

    // Test accounts
    address public admin;
    address public keeperBot;
    address public streamReceiver;

    // Contracts
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;
    KeeperCompanion public companion;
    Safe public safe;

    function setUp() public {
        admin = makeAddr("admin");
        keeperBot = makeAddr("keeperBot");
        streamReceiver = makeAddr("streamReceiver");

        // Deploy keeper implementation
        keeperImpl = new StrategyKeeper();

        // Deploy proxy with placeholder safe/companion
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                admin,
                IStrategyKeeper.KeeperConfig({
                    vault: VAULT,
                    targetStrategy: TARGET_STRATEGY,
                    safe: address(1), // placeholder
                    companion: address(0xBEEF), // placeholder
                    baseAsset: USDC,
                    borrower: BORROWER,
                    feeWallet: FEE_WALLET,
                    streamReceiver: streamReceiver,
                    sablier: SABLIER,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18,
                    holdingDays: 28
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Deploy companion
        companion = new KeeperCompanion(address(keeper));

        // Deploy real Safe with keeper + companion as owners
        safe = _deploySafe();

        // Update keeper config with real addresses
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28
            })
        );
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund safe with USDC from whale
        vm.prank(USDC_WHALE);
        IERC20(USDC).transfer(address(safe), 100_000e6);
    }

    function _deploySafe() internal returns (Safe) {
        address[] memory owners = new address[](2);
        owners[0] = address(keeper);
        owners[1] = address(companion);

        // Sort owners (Safe requires ascending order)
        if (uint160(owners[0]) > uint160(owners[1])) {
            (owners[0], owners[1]) = (owners[1], owners[0]);
        }

        bytes memory setupData = abi.encodeCall(
            Safe.setup,
            (
                owners,
                2, // threshold
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

    function test_initialization() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();

        assertEq(cfg.vault, VAULT);
        assertEq(cfg.targetStrategy, TARGET_STRATEGY);
        assertEq(cfg.safe, address(safe));
        assertEq(cfg.companion, address(companion));
        assertEq(cfg.baseAsset, USDC);
        assertEq(cfg.borrower, BORROWER);
        assertEq(cfg.feeWallet, FEE_WALLET);
        assertEq(cfg.streamReceiver, streamReceiver);
        assertEq(cfg.sablier, SABLIER);
        assertEq(cfg.minThreshold, 10_000e6);
        assertEq(cfg.minResidual, 1_000e6);
        assertEq(cfg.apr, 0.121e18);
        assertEq(cfg.holdingDays, 28);
    }

    function test_safeSetup() public view {
        assertTrue(safe.isOwner(address(keeper)));
        assertTrue(safe.isOwner(address(companion)));
        assertEq(safe.getThreshold(), 2);
        assertEq(safe.getOwners().length, 2);
    }

    function test_safeBalance() public view {
        assertEq(IERC20(USDC).balanceOf(address(safe)), 100_000e6);
    }

    function test_roles() public view {
        assertTrue(keeper.hasRole(keeper.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(keeper.hasRole(keeper.CONFIG_MANAGER_ROLE(), admin));
        assertTrue(keeper.hasRole(keeper.KEEPER_ROLE(), keeperBot));
    }

    function test_companionOwnership() public view {
        assertEq(companion.owner(), address(keeper));
    }

    function test_vaultExists() public view {
        assertTrue(VAULT.code.length > 0);
    }

    function test_targetStrategyExists() public view {
        assertTrue(TARGET_STRATEGY.code.length > 0);
    }

    function test_sablierExists() public view {
        assertTrue(SABLIER.code.length > 0);
    }

    function test_usdcDecimals() public view {
        (bool success, bytes memory data) = USDC.staticcall(abi.encodeWithSignature("decimals()"));
        assertTrue(success);
        assertEq(abi.decode(data, (uint8)), 6);
    }

    function test_yieldCalculation() public pure {
        // 100,000 USDC at 12.1% APR for 28 days
        // 100000 * 0.121 * 28 / 365 = 928.22
        uint256 available = 100_000e6;
        uint256 apr = 0.121e18;
        uint256 holdingDays = 28;

        uint256 interest = (available * apr * holdingDays) / 365 / 1e18;

        assertApproxEqAbs(interest, 928_219_178, 1e3);

        uint256 fee = interest / 11;
        uint256 streamAmount = interest - fee;
        assertEq(fee + streamAmount, interest);
    }

    function test_revertOnUnauthorizedKeeper() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.processInflows();
    }

    function test_revertOnUnauthorizedConfigUpdate() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        vm.prank(address(0xDEAD));
        vm.expectRevert();
        keeper.setConfig(cfg);
    }

    function test_safeTransferWithContractSignatures() public {
        uint256 amount = 1000e6;
        address recipient = makeAddr("recipient");

        uint256 recipientBefore = IERC20(USDC).balanceOf(recipient);
        uint256 safeBefore = IERC20(USDC).balanceOf(address(safe));

        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient, amount));
        bytes32 txHash = safe.getTransactionHash(
            USDC, 0, transferData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        // Approve hash on companion
        vm.prank(address(keeper));
        companion.approveHash(txHash);

        // Build contract signatures
        bytes memory signatures = _buildContractSignatures(address(keeper), address(companion));

        // Mock isValidSignature for both keeper and companion
        // Safe 1.4.1 uses legacy bytes format: isValidSignature(bytes,bytes) -> 0x20c13b0b
        vm.mockCall(address(keeper), abi.encodeWithSelector(bytes4(0x20c13b0b)), abi.encode(bytes4(0x20c13b0b)));
        vm.mockCall(address(companion), abi.encodeWithSelector(bytes4(0x20c13b0b)), abi.encode(bytes4(0x20c13b0b)));

        bool success = safe.execTransaction(
            USDC, 0, transferData, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signatures
        );

        assertTrue(success);
        assertEq(IERC20(USDC).balanceOf(recipient), recipientBefore + amount);
        assertEq(IERC20(USDC).balanceOf(address(safe)), safeBefore - amount);
    }

    function test_companionHashApproval() public {
        bytes32 testHash = keccak256("test");

        assertFalse(companion.isHashApproved(testHash));

        vm.prank(address(keeper));
        companion.approveHash(testHash);
        assertTrue(companion.isHashApproved(testHash));

        vm.prank(address(keeper));
        companion.revokeHash(testHash);
        assertFalse(companion.isHashApproved(testHash));
    }

    function test_companionIsValidSignature() public {
        bytes32 testHash = keccak256("test");

        assertEq(companion.isValidSignature(testHash, ""), bytes4(0xffffffff));

        vm.prank(address(keeper));
        companion.approveHash(testHash);

        assertEq(companion.isValidSignature(testHash, ""), bytes4(0x1626ba7e));
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

    function test_configValidation_zeroHoldingDays() public {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        cfg.holdingDays = 0;

        vm.prank(admin);
        vm.expectRevert(IStrategyKeeper.InvalidConfiguration.selector);
        keeper.setConfig(cfg);
    }

    function test_processInflows_success() public {
        // Update config to set minThreshold very high so vault allocation is skipped
        // (we don't have PROCESSOR_ROLE on the real vault)
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max, // Set very high to skip vault allocation
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28
            })
        );
        vm.stopPrank();

        // Get initial balances
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));
        uint256 borrowerBalanceBefore = IERC20(USDC).balanceOf(BORROWER);
        uint256 feeWalletBalanceBefore = IERC20(USDC).balanceOf(FEE_WALLET);
        uint256 sablierBalanceBefore = IERC20(USDC).balanceOf(SABLIER);

        // Calculate expected amounts
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        uint256 available = safeBalanceBefore - cfg.minResidual;
        uint256 interest = (available * cfg.apr * cfg.holdingDays) / 365 / 1e18;
        uint256 principal = available - interest;
        uint256 fee = interest / 11;
        uint256 streamAmount = interest - fee;

        // Mock isValidSignature for both keeper and companion
        // Safe 1.4.1 uses legacy bytes format: isValidSignature(bytes,bytes) -> 0x20c13b0b
        vm.mockCall(address(keeper), abi.encodeWithSelector(bytes4(0x20c13b0b)), abi.encode(bytes4(0x20c13b0b)));
        vm.mockCall(address(companion), abi.encodeWithSelector(bytes4(0x20c13b0b)), abi.encode(bytes4(0x20c13b0b)));

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
    }

    function test_processInflows_noFundsToProcess() public {
        // Update config to set minThreshold very high so vault allocation is skipped
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER,
                minThreshold: type(uint256).max, // Skip vault allocation
                minResidual: 100_000e6, // Set minResidual equal to safe balance
                apr: 0.121e18,
                holdingDays: 28
            })
        );
        vm.stopPrank();

        // Now safe balance (100_000e6) equals minResidual, so no funds to process
        vm.prank(keeperBot);
        vm.expectRevert(IStrategyKeeper.NoFundsToProcess.selector);
        keeper.processInflows();
    }

    function _buildContractSignatures(address signer1, address signer2) internal pure returns (bytes memory) {
        address lower = uint160(signer1) < uint160(signer2) ? signer1 : signer2;
        address higher = uint160(signer1) < uint160(signer2) ? signer2 : signer1;

        return abi.encodePacked(
            bytes32(uint256(uint160(lower))),
            bytes32(uint256(130)),
            uint8(0),
            bytes32(uint256(uint160(higher))),
            bytes32(uint256(162)),
            uint8(0),
            bytes32(0),
            bytes32(0)
        );
    }
}
