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
import {IGnosisSafe} from "src/interfaces/IGnosisSafe.sol";

/// @title MockERC20
/// @notice Simple mock ERC20 for testing
contract MockERC20 is IERC20 {
    string public name = "Mock USDC";
    string public symbol = "USDC";
    uint8 public decimals = 6;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "Insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "Insufficient balance");
        require(allowance[from][msg.sender] >= amount, "Insufficient allowance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        emit Transfer(from, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }
}

/// @title StrategyKeeperSafeTest
/// @notice Tests for StrategyKeeper with a real Gnosis Safe using module execution
contract StrategyKeeperSafeTest is Test {
    MockERC20 public usdc;
    Safe public safe;
    Safe public safeSingleton;
    SafeProxyFactory public safeFactory;
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;

    address public admin = address(0x1111);
    address public keeperBot = address(0x2222);
    address public vault = address(0x3333);
    address public targetStrategy = address(0x4444);
    address public borrower = address(0x5555);
    address public feeWallet = address(0x6666);
    address public streamReceiver = address(0x7777);
    address public sablier = address(0x8888);

    // EOA owner for the Safe
    uint256 public eoaOwnerPk = 0xA11CE;
    address public eoaOwner;

    function setUp() public {
        eoaOwner = vm.addr(eoaOwnerPk);

        // Deploy mock USDC
        usdc = new MockERC20();

        // Deploy keeper implementation
        keeperImpl = new StrategyKeeper();

        // Deploy keeper proxy with placeholder safe address
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                admin,
                IStrategyKeeper.KeeperConfig({
                    vault: vault,
                    targetStrategy: targetStrategy,
                    safe: address(1), // Placeholder, will update
                    baseAsset: address(usdc),
                    borrower: borrower,
                    feeWallet: feeWallet,
                    streamReceiver: streamReceiver,
                    sablier: sablier,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18,
                    holdingPeriod: 28 days,
                    minProcessingPercent: 0.01e18,
                    feeFraction: 11
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Deploy Safe singleton and factory
        safeSingleton = new Safe();
        safeFactory = new SafeProxyFactory();

        // Setup Safe with 1 EOA owner and threshold 1
        address[] memory owners = new address[](1);
        owners[0] = eoaOwner;

        // Build Safe setup call
        bytes memory safeSetupData = abi.encodeCall(
            Safe.setup,
            (
                owners,
                1, // threshold
                address(0), // to (no delegate call)
                "", // data
                address(0), // fallbackHandler
                address(0), // paymentToken
                0, // payment
                payable(address(0)) // paymentReceiver
            )
        );

        // Deploy Safe proxy using factory
        SafeProxy safeProxy = safeFactory.createProxyWithNonce(address(safeSingleton), safeSetupData, 0);
        safe = Safe(payable(address(safeProxy)));

        // Enable keeper as a module on the Safe
        // This requires executing a transaction from the Safe to call enableModule
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", address(keeper));
        bytes32 txHash = safe.getTransactionHash(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        // Sign the transaction with EOA owner
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaOwnerPk, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute enableModule transaction
        safe.execTransaction(
            address(safe), 0, enableModuleData, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), signature
        );

        // Update keeper config with correct safe address
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: address(safe),
                baseAsset: address(usdc),
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingPeriod: 28 days,
                minProcessingPercent: 0.01e18,
                feeFraction: 11
            })
        );
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund the Safe with USDC
        usdc.mint(address(safe), 100_000e6);
    }

    /// @notice Test that keeper is enabled as a module on the Safe
    function test_keeperIsModule() public view {
        assertTrue(safe.isModuleEnabled(address(keeper)), "Keeper should be enabled as module");
    }

    /// @notice Test Safe ownership
    function test_safeOwnership() public view {
        assertTrue(safe.isOwner(eoaOwner), "EOA should be owner");
        assertEq(safe.getThreshold(), 1, "Threshold should be 1");
        assertEq(safe.getOwners().length, 1, "Should have 1 owner");
    }

    /// @notice Test module execution for transfer
    function test_moduleExecutionTransfer() public {
        uint256 transferAmount = 1000e6;
        address recipient = address(0xCAFE);

        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);
        uint256 safeBalanceBefore = usdc.balanceOf(address(safe));

        // Execute transfer as module - must be called FROM the keeper (which is the enabled module)
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient, transferAmount));
        vm.prank(address(keeper));
        bool success = safe.execTransactionFromModule(address(usdc), 0, transferData, Enum.Operation.Call);

        assertTrue(success, "Module execution should succeed");
        assertEq(usdc.balanceOf(recipient), recipientBalanceBefore + transferAmount, "Recipient should receive tokens");
        assertEq(usdc.balanceOf(address(safe)), safeBalanceBefore - transferAmount, "Safe balance should decrease");
    }

    /// @notice Test multiple module executions in sequence
    function test_multipleModuleExecutions() public {
        address recipient1 = address(0xCAFE);
        address recipient2 = address(0xDEAD);
        uint256 amount1 = 500e6;
        uint256 amount2 = 300e6;

        // First transfer - must be called FROM the keeper
        bytes memory transferData1 = abi.encodeCall(IERC20.transfer, (recipient1, amount1));
        vm.prank(address(keeper));
        bool success1 = safe.execTransactionFromModule(address(usdc), 0, transferData1, Enum.Operation.Call);
        assertTrue(success1, "First transfer should succeed");

        // Second transfer
        bytes memory transferData2 = abi.encodeCall(IERC20.transfer, (recipient2, amount2));
        vm.prank(address(keeper));
        bool success2 = safe.execTransactionFromModule(address(usdc), 0, transferData2, Enum.Operation.Call);
        assertTrue(success2, "Second transfer should succeed");

        assertEq(usdc.balanceOf(recipient1), amount1, "Recipient1 should have correct balance");
        assertEq(usdc.balanceOf(recipient2), amount2, "Recipient2 should have correct balance");
    }

    /// @notice Test that non-module cannot execute transactions
    function test_revertOnNonModuleExecution() public {
        address nonModule = address(0xBEEF);
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (address(0xCAFE), 100e6));

        // Try to execute as non-module (should revert)
        vm.prank(nonModule);
        vm.expectRevert();
        safe.execTransactionFromModule(address(usdc), 0, transferData, Enum.Operation.Call);
    }

    /// @notice Test module execution with return data
    function test_moduleExecutionWithReturnData() public {
        uint256 transferAmount = 1000e6;
        address recipient = address(0xCAFE);

        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient, transferAmount));
        vm.prank(address(keeper));
        (bool success, bytes memory returnData) =
            safe.execTransactionFromModuleReturnData(address(usdc), 0, transferData, Enum.Operation.Call);

        assertTrue(success, "Module execution should succeed");
        assertTrue(abi.decode(returnData, (bool)), "Transfer should return true");
    }
}
