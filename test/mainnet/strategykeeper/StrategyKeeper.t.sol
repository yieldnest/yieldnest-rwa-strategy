// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {Safe} from "lib/safe-smart-account/contracts/Safe.sol";
import {SafeProxyFactory} from "lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import {SafeProxy} from "lib/safe-smart-account/contracts/proxies/SafeProxy.sol";
import {Enum} from "lib/safe-smart-account/contracts/libraries/Enum.sol";
import {StrategyKeeper, IStrategyKeeper} from "src/StrategyKeeper.sol";
import {KeeperCompanion} from "src/KeeperCompanion.sol";
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";

/// @title StrategyKeeperMainnetTest
/// @notice Integration tests for StrategyKeeper using mainnet fork
/// @dev Requires MAINNET_RPC_URL environment variable
contract StrategyKeeperMainnetTest is Test {
    // Mainnet addresses
    address public constant YNRWAX_VAULT = 0x01Ba69727E2860b37bc1a2bd56999c1aFb4C15D8;
    address public constant TARGET_STRATEGY = 0xF6e1443e3F70724cec8C0a779C7C35A8DcDA928B;
    address public constant FEE_WALLET = 0xC92Dd1837EBcb0365eB0a8795f9c8E474f8B6183;
    address public constant BORROWER = 0xaa7f79Bb105833D655D1C13C175142c44e209912;
    address public constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address public constant SABLIER_LOCKUP_LINEAR = 0xcF8ce57fa442ba50aCbC57147a62aD03873FfA73;

    // YieldNest multisig (used as admin)
    address public constant YN_SECURITY_COUNCIL = 0xfcad670592a3b24869C0b51a6c6FDED4F95D6975;

    // Deployed contracts
    Safe public safe;
    Safe public safeSingleton;
    SafeProxyFactory public safeFactory;
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;
    KeeperCompanion public companion;

    // Test accounts
    address public admin;
    address public keeperBot = address(0x2222);
    address public streamReceiver = address(0x7777);
    address public eoaOwner1 = address(0xAAAA);
    address public eoaOwner2 = address(0xBBBB);

    function setUp() public {
        // Fork mainnet - requires MAINNET_RPC_URL env var
        string memory rpcUrl = vm.envOr("MAINNET_RPC_URL", vm.envOr("ETH_RPC_URL", string("")));
        require(bytes(rpcUrl).length > 0, "Set MAINNET_RPC_URL or ETH_RPC_URL env var");
        vm.createSelectFork(rpcUrl);

        admin = YN_SECURITY_COUNCIL;

        // Deploy keeper implementation
        keeperImpl = new StrategyKeeper();

        // Deploy keeper proxy with placeholder addresses
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                admin,
                IStrategyKeeper.KeeperConfig({
                    vault: YNRWAX_VAULT,
                    targetStrategy: TARGET_STRATEGY,
                    safe: address(1), // Placeholder
                    companion: address(0xBEEF), // Placeholder
                    baseAsset: USDC,
                    borrower: BORROWER,
                    feeWallet: FEE_WALLET,
                    streamReceiver: streamReceiver,
                    sablier: SABLIER_LOCKUP_LINEAR,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18, // 12.1%
                    holdingDays: 28
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Deploy companion with keeper as owner
        companion = new KeeperCompanion(address(keeper));

        // Deploy Safe singleton and factory
        safeSingleton = new Safe();
        safeFactory = new SafeProxyFactory();

        // Setup Safe with keeper and companion as owners (2/4 threshold)
        address[] memory owners = new address[](4);
        owners[0] = address(keeper);
        owners[1] = address(companion);
        owners[2] = eoaOwner1;
        owners[3] = eoaOwner2;
        _sortAddresses(owners);

        bytes memory safeSetupData = abi.encodeCall(
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

        SafeProxy safeProxy = safeFactory.createProxyWithNonce(address(safeSingleton), safeSetupData, 0);
        safe = Safe(payable(address(safeProxy)));

        // Update keeper config with correct Safe address
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: YNRWAX_VAULT,
                targetStrategy: TARGET_STRATEGY,
                safe: address(safe),
                companion: address(companion),
                baseAsset: USDC,
                borrower: BORROWER,
                feeWallet: FEE_WALLET,
                streamReceiver: streamReceiver,
                sablier: SABLIER_LOCKUP_LINEAR,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28
            })
        );
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund Safe with USDC from a whale
        address usdcWhale = 0x37305B1cD40574E4C5Ce33f8e8306Be057fD7341;
        vm.prank(usdcWhale);
        IERC20(USDC).transfer(address(safe), 100_000e6);
    }

    function _sortAddresses(address[] memory arr) internal pure {
        for (uint256 i = 0; i < arr.length; i++) {
            for (uint256 j = i + 1; j < arr.length; j++) {
                if (uint160(arr[i]) > uint160(arr[j])) {
                    address temp = arr[i];
                    arr[i] = arr[j];
                    arr[j] = temp;
                }
            }
        }
    }

    /// @notice Test that Safe is properly configured
    function test_safeSetup() public view {
        assertTrue(safe.isOwner(address(keeper)), "Keeper should be owner");
        assertTrue(safe.isOwner(address(companion)), "Companion should be owner");
        assertEq(safe.getThreshold(), 2, "Threshold should be 2");
        assertEq(safe.getOwners().length, 4, "Should have 4 owners");
    }

    /// @notice Test keeper configuration
    function test_keeperConfig() public view {
        IStrategyKeeper.KeeperConfig memory cfg = keeper.getConfig();
        assertEq(cfg.vault, YNRWAX_VAULT);
        assertEq(cfg.targetStrategy, TARGET_STRATEGY);
        assertEq(cfg.safe, address(safe));
        assertEq(cfg.companion, address(companion));
        assertEq(cfg.baseAsset, USDC);
        assertEq(cfg.borrower, BORROWER);
        assertEq(cfg.feeWallet, FEE_WALLET);
        assertEq(cfg.streamReceiver, streamReceiver);
        assertEq(cfg.sablier, SABLIER_LOCKUP_LINEAR);
        assertEq(cfg.minThreshold, 10_000e6);
        assertEq(cfg.minResidual, 1_000e6);
        assertEq(cfg.apr, 0.121e18);
        assertEq(cfg.holdingDays, 28);
    }

    /// @notice Test Safe USDC balance
    function test_safeBalance() public view {
        uint256 balance = IERC20(USDC).balanceOf(address(safe));
        assertEq(balance, 100_000e6, "Safe should have 100k USDC");
    }

    /// @notice Test executing a transfer from Safe with contract signatures
    function test_safeTransferWithContractSignatures() public {
        uint256 transferAmount = 1000e6;
        address recipient = address(0xCAFE);

        uint256 recipientBalanceBefore = IERC20(USDC).balanceOf(recipient);
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));

        // Build transfer call
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient, transferAmount));

        // Get transaction hash
        bytes32 txHash = safe.getTransactionHash(
            USDC, 0, transferData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        // Approve hash on companion
        vm.prank(address(keeper));
        companion.approveHash(txHash);

        // Mock keeper's isValidSignature
        vm.mockCall(
            address(keeper),
            abi.encodeWithSelector(keeper.isValidSignature.selector, txHash, ""),
            abi.encode(bytes4(0x1626ba7e))
        );

        // Build signatures
        bytes memory signatures = _buildContractSignatures(address(keeper), address(companion));

        // Execute
        bool success = safe.execTransaction(
            USDC, 0, transferData, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signatures
        );

        assertTrue(success, "Transaction should succeed");
        assertEq(IERC20(USDC).balanceOf(recipient), recipientBalanceBefore + transferAmount);
        assertEq(IERC20(USDC).balanceOf(address(safe)), safeBalanceBefore - transferAmount);
    }

    /// @notice Test yield calculation matches spec
    function test_yieldCalculation() public pure {
        // From spec: 34,500 USDC at 12.1% APR for 28 days
        // Expected: 34500 * 12.1 / 100 * 28 / 365 = 320.24
        uint256 available = 34_500e6;
        uint256 apr = 0.121e18;
        uint256 holdingDays = 28;
        uint256 PRECISION = 1e18;
        uint256 DAYS_PER_YEAR = 365;

        uint256 interest = (available * apr * holdingDays) / DAYS_PER_YEAR / PRECISION;

        // Should be ~320.24 USDC
        assertApproxEqAbs(interest, 320_235_616, 1e3);

        // Fee split: 1/11 to fee wallet, 10/11 to stream
        uint256 fee = interest / 11;
        uint256 streamAmount = interest - fee;

        assertEq(fee + streamAmount, interest);
    }

    /// @notice Test interaction with mainnet USDC contract
    function test_mainnetUsdcTransfer() public {
        uint256 amount = 5000e6;
        address recipient = address(0xDEAD);

        uint256 recipientBalanceBefore = IERC20(USDC).balanceOf(recipient);
        uint256 safeBalanceBefore = IERC20(USDC).balanceOf(address(safe));

        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient, amount));
        bytes32 txHash = safe.getTransactionHash(
            USDC, 0, transferData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        vm.prank(address(keeper));
        companion.approveHash(txHash);

        vm.mockCall(
            address(keeper),
            abi.encodeWithSelector(keeper.isValidSignature.selector, txHash, ""),
            abi.encode(bytes4(0x1626ba7e))
        );

        bytes memory signatures = _buildContractSignatures(address(keeper), address(companion));

        safe.execTransaction(USDC, 0, transferData, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signatures);

        assertEq(IERC20(USDC).balanceOf(recipient), recipientBalanceBefore + amount);
        assertEq(IERC20(USDC).balanceOf(address(safe)), safeBalanceBefore - amount);
    }

    /// @notice Test Sablier contract exists and is valid
    function test_sablierExists() public view {
        uint256 codeSize;
        address sablier = SABLIER_LOCKUP_LINEAR;
        assembly {
            codeSize := extcodesize(sablier)
        }
        assertTrue(codeSize > 0, "Sablier contract should exist");
    }

    /// @notice Test vault exists and is valid ERC4626
    function test_vaultExists() public view {
        uint256 codeSize;
        address vaultAddr = YNRWAX_VAULT;
        assembly {
            codeSize := extcodesize(vaultAddr)
        }
        assertTrue(codeSize > 0, "Vault should exist");

        // Check it returns an asset
        (bool success, bytes memory data) = vaultAddr.staticcall(abi.encodeWithSignature("asset()"));
        assertTrue(success, "Vault should have asset()");
        address asset = abi.decode(data, (address));
        assertEq(asset, USDC, "Vault asset should be USDC");
    }

    /// @notice Test target strategy exists
    function test_strategyExists() public view {
        uint256 codeSize;
        address strategyAddr = TARGET_STRATEGY;
        assembly {
            codeSize := extcodesize(strategyAddr)
        }
        assertTrue(codeSize > 0, "Strategy should exist");
    }

    /// @notice Build contract signatures for two signers
    function _buildContractSignatures(address signer1, address signer2) internal pure returns (bytes memory signatures) {
        address lower;
        address higher;
        if (uint160(signer1) < uint160(signer2)) {
            lower = signer1;
            higher = signer2;
        } else {
            lower = signer2;
            higher = signer1;
        }

        uint256 offset1 = 130;
        uint256 offset2 = 162;

        signatures = abi.encodePacked(
            bytes32(uint256(uint160(lower))),
            bytes32(offset1),
            uint8(0),
            bytes32(uint256(uint160(higher))),
            bytes32(offset2),
            uint8(0),
            bytes32(0),
            bytes32(0)
        );
    }
}
