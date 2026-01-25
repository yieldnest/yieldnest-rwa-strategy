// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {StrategyKeeper, IStrategyKeeper} from "@src/StrategyKeeper.sol";
import {KeeperCompanion} from "@src/KeeperCompanion.sol";
import {IGnosisSafe} from "@src/interfaces/IGnosisSafe.sol";

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

/// @title MockGnosisSafe
/// @notice Mock Gnosis Safe that validates ERC-1271 signatures
contract MockGnosisSafe is IGnosisSafe {
    mapping(address => bool) public isOwner;
    address[] public owners;
    uint256 public threshold;
    uint256 public nonce;
    mapping(address => mapping(bytes32 => uint256)) public approvedHashes;

    bytes4 constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    constructor(address[] memory _owners, uint256 _threshold) {
        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
            owners.push(_owners[i]);
        }
        threshold = _threshold;
    }

    function addOwner(address owner) external {
        isOwner[owner] = true;
        owners.push(owner);
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getThreshold() external view returns (uint256) {
        return threshold;
    }

    function approveHash(bytes32 hashToApprove) external {
        approvedHashes[msg.sender][hashToApprove] = 1;
    }

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32) {
        return keccak256(
            abi.encode(
                to, value, keccak256(data), operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, _nonce, address(this)
            )
        );
    }

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures
    ) external payable returns (bool success) {
        // Silence unused variable warnings
        safeTxGas;
        baseGas;
        gasPrice;
        gasToken;
        refundReceiver;

        bytes32 txHash = this.getTransactionHash(to, value, data, operation, 0, 0, 0, address(0), address(0), nonce);

        // Validate signatures
        _checkSignatures(txHash, signatures);

        // Increment nonce
        nonce++;

        // Execute transaction
        if (operation == Operation.Call) {
            (success,) = to.call{value: value}(data);
        } else {
            (success,) = to.delegatecall(data);
        }

        require(success, "Transaction failed");
        return success;
    }

    function _checkSignatures(bytes32 dataHash, bytes memory signatures) internal view {
        uint256 _threshold = threshold;
        require(_threshold > 0, "Threshold not set");
        require(signatures.length >= _threshold * 65, "Signatures too short");

        address lastOwner = address(0);
        address currentOwner;

        for (uint256 i = 0; i < _threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = _signatureSplit(signatures, i);

            if (v == 0) {
                // Contract signature (ERC-1271)
                currentOwner = address(uint160(uint256(r)));

                // s contains the offset to signature data
                // For our implementation, we pass empty signature data
                // The contract validates via isValidSignature

                require(isOwner[currentOwner], "Not an owner");

                // Call isValidSignature on the contract
                bytes4 magicValue = IERC1271(currentOwner).isValidSignature(dataHash, "");
                require(magicValue == ERC1271_MAGIC_VALUE, "Invalid contract signature");
            } else if (v == 1) {
                // Approved hash signature
                currentOwner = address(uint160(uint256(r)));
                require(isOwner[currentOwner], "Not an owner");
                require(approvedHashes[currentOwner][dataHash] == 1, "Hash not approved");
            } else {
                // ECDSA signature (v = 27 or 28)
                currentOwner = ecrecover(dataHash, v, r, s);
                require(isOwner[currentOwner], "Not an owner");
            }

            // Check owner ordering (prevent duplicates)
            require(uint160(currentOwner) > uint160(lastOwner), "Invalid owner order");
            lastOwner = currentOwner;
        }
    }

    function _signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4);
}

/// @title StrategyKeeperSafeTest
/// @notice Tests for StrategyKeeper with a mock Gnosis Safe
contract StrategyKeeperSafeTest is Test {
    MockERC20 public usdc;
    MockGnosisSafe public safe;
    StrategyKeeper public keeper;
    StrategyKeeper public keeperImpl;
    KeeperCompanion public companion;

    address public admin = address(0x1111);
    address public keeperBot = address(0x2222);
    address public vault = address(0x3333);
    address public targetStrategy = address(0x4444);
    address public borrower = address(0x5555);
    address public feeWallet = address(0x6666);
    address public streamReceiver = address(0x7777);
    address public sablier = address(0x8888);

    function setUp() public {
        // Deploy mock USDC
        usdc = new MockERC20();

        // Deploy keeper implementation
        keeperImpl = new StrategyKeeper();

        // We need to know keeper and companion addresses before creating Safe
        // Use CREATE2 or compute addresses

        // For testing, deploy keeper first, then Safe, then add keeper as owner
        bytes memory initData = abi.encodeCall(
            StrategyKeeper.initialize,
            (
                admin,
                IStrategyKeeper.KeeperConfig({
                    vault: vault,
                    targetStrategy: targetStrategy,
                    safe: address(1), // Placeholder, will update
                    companion: address(0xBEEF), // Placeholder
                    baseAsset: address(usdc),
                    borrower: borrower,
                    feeWallet: feeWallet,
                    streamReceiver: streamReceiver,
                    sablier: sablier,
                    minThreshold: 10_000e6,
                    minResidual: 1_000e6,
                    apr: 0.121e18,
                    holdingDays: 28
                })
            )
        );

        TransparentUpgradeableProxy proxy = new TransparentUpgradeableProxy(address(keeperImpl), admin, initData);
        keeper = StrategyKeeper(address(proxy));

        // Deploy companion with keeper as owner
        companion = new KeeperCompanion(address(keeper));

        // Deploy Safe with keeper and companion as owners (2/4 threshold)
        address[] memory owners = new address[](4);
        owners[0] = address(keeper);
        owners[1] = address(companion);
        owners[2] = address(0xAAAA);
        owners[3] = address(0xBBBB);
        _sortAddresses(owners);

        safe = new MockGnosisSafe(owners, 2);

        // Update keeper config with correct addresses
        vm.startPrank(admin);
        keeper.setConfig(
            IStrategyKeeper.KeeperConfig({
                vault: vault,
                targetStrategy: targetStrategy,
                safe: address(safe),
                companion: address(companion),
                baseAsset: address(usdc),
                borrower: borrower,
                feeWallet: feeWallet,
                streamReceiver: streamReceiver,
                sablier: sablier,
                minThreshold: 10_000e6,
                minResidual: 1_000e6,
                apr: 0.121e18,
                holdingDays: 28
            })
        );
        keeper.grantRole(keeper.KEEPER_ROLE(), keeperBot);
        vm.stopPrank();

        // Fund the Safe with USDC
        usdc.mint(address(safe), 100_000e6);
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

    /// @notice Test that keeper and companion are Safe owners
    function test_safeOwnership() public view {
        assertTrue(safe.isOwner(address(keeper)), "Keeper should be owner");
        assertTrue(safe.isOwner(address(companion)), "Companion should be owner");
        assertEq(safe.getThreshold(), 2, "Threshold should be 2");
    }

    /// @notice Test ERC-1271 signature validation on keeper
    function test_keeperIsValidSignature() public view {
        bytes32 testHash = keccak256("test");

        // Initially not approved
        bytes4 result = keeper.isValidSignature(testHash, "");
        assertEq(result, bytes4(0xffffffff), "Should not be valid initially");
    }

    /// @notice Test ERC-1271 signature validation on companion
    function test_companionIsValidSignature() public {
        bytes32 testHash = keccak256("test");

        // Initially not approved
        bytes4 result = companion.isValidSignature(testHash, "");
        assertEq(result, bytes4(0xffffffff), "Should not be valid initially");

        // Approve from keeper (companion owner)
        vm.prank(address(keeper));
        companion.approveHash(testHash);

        // Now should be valid
        result = companion.isValidSignature(testHash, "");
        assertEq(result, bytes4(0x1626ba7e), "Should be valid after approval");
    }

    /// @notice Test executing a Safe transaction with contract signatures
    function test_safeExecutionWithContractSignatures() public {
        uint256 transferAmount = 1000e6;
        address recipient = address(0xCAFE);

        uint256 recipientBalanceBefore = usdc.balanceOf(recipient);
        uint256 safeBalanceBefore = usdc.balanceOf(address(safe));

        // Build transfer call
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (recipient, transferAmount));

        // Get transaction hash
        bytes32 txHash = safe.getTransactionHash(
            address(usdc),
            0,
            transferData,
            IGnosisSafe.Operation.Call,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        // Approve hash on companion
        vm.prank(address(keeper));
        companion.approveHash(txHash);

        // Mock keeper's isValidSignature to return magic value
        vm.mockCall(
            address(keeper),
            abi.encodeWithSelector(keeper.isValidSignature.selector, txHash, ""),
            abi.encode(bytes4(0x1626ba7e))
        );

        // Build contract signatures for keeper and companion
        bytes memory signatures = _buildContractSignatures(address(keeper), address(companion));

        // Execute transaction
        bool success = safe.execTransaction(
            address(usdc),
            0,
            transferData,
            IGnosisSafe.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(0),
            signatures
        );

        assertTrue(success, "Transaction should succeed");
        assertEq(
            usdc.balanceOf(recipient),
            recipientBalanceBefore + transferAmount,
            "Recipient should receive tokens"
        );
        assertEq(
            usdc.balanceOf(address(safe)),
            safeBalanceBefore - transferAmount,
            "Safe balance should decrease"
        );
    }

    /// @notice Test multiple Safe transactions in sequence
    function test_multipleSafeTransactions() public {
        address recipient1 = address(0xCAFE);
        address recipient2 = address(0xBEEF);
        uint256 amount1 = 500e6;
        uint256 amount2 = 300e6;

        // First transaction
        bytes memory transferData1 = abi.encodeCall(IERC20.transfer, (recipient1, amount1));
        bytes32 txHash1 = safe.getTransactionHash(
            address(usdc), 0, transferData1, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        vm.prank(address(keeper));
        companion.approveHash(txHash1);

        vm.mockCall(
            address(keeper),
            abi.encodeWithSelector(keeper.isValidSignature.selector, txHash1, ""),
            abi.encode(bytes4(0x1626ba7e))
        );

        bytes memory signatures1 = _buildContractSignatures(address(keeper), address(companion));
        bool success1 = safe.execTransaction(
            address(usdc), 0, transferData1, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), payable(0), signatures1
        );
        assertTrue(success1, "First transaction should succeed");

        // Second transaction (nonce incremented)
        bytes memory transferData2 = abi.encodeCall(IERC20.transfer, (recipient2, amount2));
        bytes32 txHash2 = safe.getTransactionHash(
            address(usdc), 0, transferData2, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        vm.prank(address(keeper));
        companion.approveHash(txHash2);

        vm.mockCall(
            address(keeper),
            abi.encodeWithSelector(keeper.isValidSignature.selector, txHash2, ""),
            abi.encode(bytes4(0x1626ba7e))
        );

        bytes memory signatures2 = _buildContractSignatures(address(keeper), address(companion));
        bool success2 = safe.execTransaction(
            address(usdc), 0, transferData2, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), payable(0), signatures2
        );
        assertTrue(success2, "Second transaction should succeed");

        assertEq(usdc.balanceOf(recipient1), amount1, "Recipient1 should have correct balance");
        assertEq(usdc.balanceOf(recipient2), amount2, "Recipient2 should have correct balance");
        assertEq(safe.nonce(), 2, "Nonce should be 2");
    }

    /// @notice Test that unapproved signatures fail
    function test_revertOnUnapprovedSignature() public {
        bytes memory transferData = abi.encodeCall(IERC20.transfer, (address(0xCAFE), 100e6));
        bytes32 txHash = safe.getTransactionHash(
            address(usdc), 0, transferData, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce()
        );

        // Don't approve on companion, but mock keeper approval
        vm.mockCall(
            address(keeper),
            abi.encodeWithSelector(keeper.isValidSignature.selector, txHash, ""),
            abi.encode(bytes4(0x1626ba7e))
        );

        bytes memory signatures = _buildContractSignatures(address(keeper), address(companion));

        // Should fail because companion hasn't approved
        vm.expectRevert("Invalid contract signature");
        safe.execTransaction(
            address(usdc), 0, transferData, IGnosisSafe.Operation.Call, 0, 0, 0, address(0), payable(0), signatures
        );
    }

    /// @notice Test signature ordering enforcement
    function test_signatureOrdering() public view {
        // Keeper and companion addresses should be in correct order
        address lower;
        address higher;
        if (uint160(address(keeper)) < uint160(address(companion))) {
            lower = address(keeper);
            higher = address(companion);
        } else {
            lower = address(companion);
            higher = address(keeper);
        }

        // Verify ordering is maintained in signature building
        bytes memory signatures = _buildContractSignatures(address(keeper), address(companion));

        // Extract first signer address from r value
        bytes32 r1;
        assembly {
            r1 := mload(add(signatures, 32))
        }
        address signer1 = address(uint160(uint256(r1)));
        assertEq(signer1, lower, "First signer should be lower address");
    }

    /// @notice Build contract signatures for two contract signers
    function _buildContractSignatures(address signer1, address signer2)
        internal
        pure
        returns (bytes memory signatures)
    {
        // Sort signers
        address lower;
        address higher;
        if (uint160(signer1) < uint160(signer2)) {
            lower = signer1;
            higher = signer2;
        } else {
            lower = signer2;
            higher = signer1;
        }

        // Contract signature format:
        // r (32 bytes) = verifying contract address (padded)
        // s (32 bytes) = offset to signature data (from start of signatures)
        // v (1 byte) = 0 (indicates contract signature)

        // Static part: 2 * 65 = 130 bytes
        // Dynamic data starts at offset 130

        uint256 offset1 = 130;
        uint256 offset2 = 162;

        signatures = abi.encodePacked(
            // First signer (lower address)
            bytes32(uint256(uint160(lower))), // r = signer address
            bytes32(offset1), // s = offset to data
            uint8(0), // v = 0 for contract signature
            // Second signer (higher address)
            bytes32(uint256(uint160(higher))), // r = signer address
            bytes32(offset2), // s = offset to data
            uint8(0), // v = 0 for contract signature
            // Dynamic data for first signer
            bytes32(0), // length = 0
            // Dynamic data for second signer
            bytes32(0) // length = 0
        );
    }
}
