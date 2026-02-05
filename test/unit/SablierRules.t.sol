// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {TransparentUpgradeableProxy} from
    "lib/openzeppelin-contracts/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721.sol";

import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";
import {AccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";
import {AccountingToken, IAccountingToken} from "lib/yieldnest-flex-strategy/src/AccountingToken.sol";
import {FixedRateProvider} from "lib/yieldnest-flex-strategy/src/FixedRateProvider.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {IValidator} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IValidator.sol";

import {ISablierLockupLinear} from "src/interfaces/sablier/ISablierLockupLinear.sol";

/// @title MockUSDC
/// @notice Simple mock USDC for testing
contract MockUSDC is IERC20 {
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

/// @title MockSablierLockupLinear
/// @notice Mock Sablier contract that implements ERC721 for stream NFTs
contract MockSablierLockupLinear is IERC721 {
    uint256 public nextStreamId = 1;
    mapping(uint256 => address) public streamOwner;
    mapping(uint256 => StreamData) public streams;
    mapping(address => mapping(address => bool)) private _operatorApprovals;
    mapping(uint256 => address) private _tokenApprovals;

    struct StreamData {
        address sender;
        address recipient;
        uint128 depositAmount;
        address token;
        uint40 startTime;
        uint40 endTime;
    }

    event StreamCreated(uint256 indexed streamId, address indexed sender, address indexed recipient, uint128 amount);

    // ERC721 implementation
    function balanceOf(address owner) external view returns (uint256) {
        uint256 count = 0;
        for (uint256 i = 1; i < nextStreamId; i++) {
            if (streamOwner[i] == owner) count++;
        }
        return count;
    }

    function ownerOf(uint256 tokenId) external view returns (address) {
        require(streamOwner[tokenId] != address(0), "ERC721: invalid token ID");
        return streamOwner[tokenId];
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata) external {
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        _transfer(from, to, tokenId);
    }

    function transferFrom(address from, address to, uint256 tokenId) external {
        _transfer(from, to, tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        require(streamOwner[tokenId] == from, "ERC721: transfer from incorrect owner");
        require(to != address(0), "ERC721: transfer to zero address");
        require(
            msg.sender == from || _operatorApprovals[from][msg.sender] || _tokenApprovals[tokenId] == msg.sender,
            "ERC721: caller is not owner nor approved"
        );

        delete _tokenApprovals[tokenId];
        streamOwner[tokenId] = to;
        emit Transfer(from, to, tokenId);
    }

    function approve(address to, uint256 tokenId) external {
        address owner = streamOwner[tokenId];
        require(msg.sender == owner || _operatorApprovals[owner][msg.sender], "ERC721: approve caller is not owner");
        _tokenApprovals[tokenId] = to;
        emit Approval(owner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        _operatorApprovals[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function getApproved(uint256 tokenId) external view returns (address) {
        require(streamOwner[tokenId] != address(0), "ERC721: invalid token ID");
        return _tokenApprovals[tokenId];
    }

    function isApprovedForAll(address owner, address operator) external view returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC721).interfaceId;
    }

    // Sablier-specific function
    function createWithTimestampsLL(
        ISablierLockupLinear.CreateWithTimestamps calldata params,
        ISablierLockupLinear.UnlockAmounts calldata,
        uint40
    ) external returns (uint256 streamId) {
        // Transfer tokens from sender to this contract
        IERC20(address(params.token)).transferFrom(msg.sender, address(this), params.depositAmount);

        streamId = nextStreamId++;
        streamOwner[streamId] = params.recipient;
        streams[streamId] = StreamData({
            sender: params.sender,
            recipient: params.recipient,
            depositAmount: params.depositAmount,
            token: address(params.token),
            startTime: params.timestamps.start,
            endTime: params.timestamps.end
        });

        emit StreamCreated(streamId, params.sender, params.recipient, params.depositAmount);
        emit Transfer(address(0), params.recipient, streamId);

        return streamId;
    }
}

/// @title SablierRulesTest
/// @notice Tests for SablierRules with a FlexStrategy vault
contract SablierRulesTest is Test {
    MockUSDC public usdc;
    MockSablierLockupLinear public sablier;
    FlexStrategy public strategy;
    AccountingModule public accountingModule;
    AccountingToken public accountingToken;
    FixedRateProvider public rateProvider;

    address public admin = address(0x1111);
    address public processor = address(0x2222);
    address public safe = address(0x3333);
    address public streamReceiver = address(0x4444);
    address public alice = address(0x5555);

    function setUp() public {
        // Deploy mock contracts
        usdc = new MockUSDC();
        sablier = new MockSablierLockupLinear();

        // Deploy AccountingToken
        AccountingToken accountingTokenImpl = new AccountingToken(address(usdc));
        TransparentUpgradeableProxy accountingTokenProxy = new TransparentUpgradeableProxy(
            address(accountingTokenImpl),
            admin,
            abi.encodeCall(AccountingToken.initialize, (admin, "Accounting Token", "AT"))
        );
        accountingToken = AccountingToken(payable(address(accountingTokenProxy)));

        // Deploy rate provider
        rateProvider = new FixedRateProvider(address(accountingToken));

        // Deploy FlexStrategy
        FlexStrategy strategyImpl = new FlexStrategy();
        TransparentUpgradeableProxy strategyProxy = new TransparentUpgradeableProxy(
            address(strategyImpl),
            admin,
            abi.encodeCall(
                FlexStrategy.initialize,
                (
                    admin,
                    "Test Flex Strategy",
                    "TFS",
                    6, // decimals
                    address(usdc),
                    address(accountingToken),
                    true, // paused
                    address(rateProvider),
                    false // alwaysComputeTotalAssets
                )
            )
        );
        strategy = FlexStrategy(payable(address(strategyProxy)));

        // Deploy AccountingModule
        AccountingModule accountingModuleImpl = new AccountingModule();
        TransparentUpgradeableProxy accountingModuleProxy = new TransparentUpgradeableProxy(
            address(accountingModuleImpl),
            admin,
            abi.encodeCall(
                AccountingModule.initialize,
                (
                    address(strategy),
                    admin,
                    safe,
                    IAccountingToken(address(accountingToken)),
                    0.15 ether, // targetApy
                    0, // lowerBound
                    0, // minRewardableAssets
                    uint16(3600) // cooldownSeconds (1 hour)
                )
            )
        );
        accountingModule = AccountingModule(payable(address(accountingModuleProxy)));

        // Configure strategy
        vm.startPrank(admin);

        // Set accounting module for token
        accountingToken.setAccountingModule(address(accountingModule));

        // Set accounting module for strategy
        strategy.setAccountingModule(address(accountingModule));

        // Grant roles
        strategy.grantRole(strategy.PROCESSOR_ROLE(), processor);
        strategy.grantRole(strategy.PROCESSOR_MANAGER_ROLE(), admin);
        strategy.grantRole(strategy.ALLOCATOR_ROLE(), alice);
        strategy.grantRole(strategy.UNPAUSER_ROLE(), admin);

        // Set up Sablier rules for the strategy
        _setupSablierRules();

        // Unpause strategy
        strategy.unpause();

        vm.stopPrank();

        // Fund the strategy with USDC (simulating deposited funds)
        usdc.mint(address(strategy), 100_000e6);

        // Approve strategy to spend safe's funds for accounting module
        vm.prank(safe);
        usdc.approve(address(accountingModule), type(uint256).max);

        // Fund safe with USDC
        usdc.mint(safe, 100_000e6);
    }

    function _setupSablierRules() internal {
        // Set up rules directly without using SafeRules library

        // Rule 1: Approve USDC to Sablier
        {
            bytes4 funcSig = IERC20.approve.selector;
            IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);

            address[] memory spenderAllowList = new address[](1);
            spenderAllowList[0] = address(sablier);
            paramRules[0] =
                IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: spenderAllowList});
            paramRules[1] =
                IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

            IVault.FunctionRule memory rule =
                IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

            IVault(address(strategy)).setProcessorRule(address(usdc), funcSig, rule);
        }

        // Rule 2: Create stream on Sablier
        {
            bytes4 funcSig = ISablierLockupLinear.createWithTimestampsLL.selector;
            IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](0);

            IVault.FunctionRule memory rule =
                IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

            IVault(address(strategy)).setProcessorRule(address(sablier), funcSig, rule);
        }

        // Rule 3: Transfer stream NFT via safeTransferFrom
        {
            bytes4 funcSig = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
            IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](3);

            address[] memory fromAllowList = new address[](1);
            fromAllowList[0] = address(strategy);
            paramRules[0] =
                IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: fromAllowList});

            address[] memory toAllowList = new address[](1);
            toAllowList[0] = streamReceiver;
            paramRules[1] =
                IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: toAllowList});

            paramRules[2] =
                IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

            IVault.FunctionRule memory rule =
                IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

            IVault(address(strategy)).setProcessorRule(address(sablier), funcSig, rule);
        }
    }

    /// @notice Test that Sablier rules are set correctly
    function test_sablierRulesAreSet() public view {
        // Check approve rule
        IVault.FunctionRule memory approveRule =
            IVault(address(strategy)).getProcessorRule(address(usdc), IERC20.approve.selector);
        assertTrue(approveRule.isActive, "Approve rule should be active");
        assertEq(approveRule.paramRules.length, 2, "Approve rule should have 2 param rules");

        // Check create stream rule
        IVault.FunctionRule memory createRule = IVault(address(strategy)).getProcessorRule(
            address(sablier), ISablierLockupLinear.createWithTimestampsLL.selector
        );
        assertTrue(createRule.isActive, "Create stream rule should be active");

        // Check transfer rule
        bytes4 safeTransferSig = bytes4(keccak256("safeTransferFrom(address,address,uint256)"));
        IVault.FunctionRule memory transferRule =
            IVault(address(strategy)).getProcessorRule(address(sablier), safeTransferSig);
        assertTrue(transferRule.isActive, "Transfer rule should be active");
        assertEq(transferRule.paramRules.length, 3, "Transfer rule should have 3 param rules");
    }

    /// @notice Test creating a Sablier stream via processor
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

        // Call 2: Create stream
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: address(strategy),
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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

        // Execute via processor
        vm.prank(processor);
        strategy.processor(targets, values, data);

        // Verify stream was created
        assertEq(sablier.ownerOf(1), streamReceiver, "Stream should be owned by receiver");
        (,, uint128 amount,,,) = sablier.streams(1);
        assertEq(amount, streamAmount, "Stream amount should match");
    }

    /// @notice Test transferring a Sablier stream NFT via processor
    function test_transferSablierStreamViaProcessor() public {
        uint256 streamAmount = 1000e6;

        // First create a stream where strategy is the recipient (so strategy owns the NFT)
        // Build processor calls
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        // Call 1: Approve Sablier to spend USDC
        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Call 2: Create stream with strategy as recipient
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: address(strategy),
            recipient: address(strategy), // Strategy receives the NFT
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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

        // Execute via processor to create stream
        vm.prank(processor);
        strategy.processor(targets, values, data);

        // Verify strategy owns the stream
        uint256 streamId = 1;
        assertEq(sablier.ownerOf(streamId), address(strategy), "Strategy should own the stream");

        // Now transfer the stream NFT to streamReceiver
        address[] memory transferTargets = new address[](1);
        uint256[] memory transferValues = new uint256[](1);
        bytes[] memory transferData = new bytes[](1);

        transferTargets[0] = address(sablier);
        transferValues[0] = 0;
        transferData[0] = abi.encodeWithSignature(
            "safeTransferFrom(address,address,uint256)", address(strategy), streamReceiver, streamId
        );

        // Execute transfer via processor
        vm.prank(processor);
        strategy.processor(transferTargets, transferValues, transferData);

        // Verify stream was transferred
        assertEq(sablier.ownerOf(streamId), streamReceiver, "Stream should now be owned by receiver");
    }

    /// @notice Test that transfer to unauthorized recipient fails
    function test_revert_transferToUnauthorizedRecipient() public {
        uint256 streamAmount = 1000e6;
        address unauthorizedRecipient = address(0xDEAD);

        // Create stream with strategy as recipient
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: address(strategy),
            recipient: address(strategy),
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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
        strategy.processor(targets, values, data);

        // Try to transfer to unauthorized recipient (should fail)
        address[] memory transferTargets = new address[](1);
        uint256[] memory transferValues = new uint256[](1);
        bytes[] memory transferData = new bytes[](1);

        transferTargets[0] = address(sablier);
        transferValues[0] = 0;
        transferData[0] = abi.encodeWithSignature(
            "safeTransferFrom(address,address,uint256)", address(strategy), unauthorizedRecipient, uint256(1)
        );

        // Should revert because unauthorizedRecipient is not in allowlist
        vm.prank(processor);
        vm.expectRevert();
        strategy.processor(transferTargets, transferValues, transferData);
    }

    /// @notice Test approve to unauthorized spender fails
    function test_revert_approveUnauthorizedSpender() public {
        address unauthorizedSpender = address(0xBEEF);

        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory data = new bytes[](1);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (unauthorizedSpender, 1000e6));

        // Should revert because unauthorizedSpender is not in allowlist
        vm.prank(processor);
        vm.expectRevert();
        strategy.processor(targets, values, data);
    }
}

import {StrategyKeeperSablierValidator} from "src/validators/StrategyKeeperSablierValidator.sol";

/// @title StrategyKeeperSablierValidatorTest
/// @notice Tests for the StrategyKeeperSablierValidator
contract StrategyKeeperSablierValidatorTest is Test {
    MockUSDC public usdc;
    MockSablierLockupLinear public sablier;
    FlexStrategy public strategy;
    AccountingModule public accountingModule;
    AccountingToken public accountingToken;
    FixedRateProvider public rateProvider;
    StrategyKeeperSablierValidator public validator;

    address public admin = address(0x1111);
    address public processor = address(0x2222);
    address public safe = address(0x3333);
    address public streamReceiver = address(0x4444);
    address public alice = address(0x5555);

    function setUp() public {
        // Deploy mock contracts
        usdc = new MockUSDC();
        sablier = new MockSablierLockupLinear();

        // Deploy validator with safe, token, and allowed recipients
        address[] memory allowedRecipients = new address[](1);
        allowedRecipients[0] = streamReceiver;
        validator = new StrategyKeeperSablierValidator(safe, address(usdc), allowedRecipients);

        // Deploy AccountingToken
        AccountingToken accountingTokenImpl = new AccountingToken(address(usdc));
        TransparentUpgradeableProxy accountingTokenProxy = new TransparentUpgradeableProxy(
            address(accountingTokenImpl),
            admin,
            abi.encodeCall(AccountingToken.initialize, (admin, "Accounting Token", "AT"))
        );
        accountingToken = AccountingToken(payable(address(accountingTokenProxy)));

        // Deploy rate provider
        rateProvider = new FixedRateProvider(address(accountingToken));

        // Deploy FlexStrategy
        FlexStrategy strategyImpl = new FlexStrategy();
        TransparentUpgradeableProxy strategyProxy = new TransparentUpgradeableProxy(
            address(strategyImpl),
            admin,
            abi.encodeCall(
                FlexStrategy.initialize,
                (
                    admin,
                    "Test Flex Strategy",
                    "TFS",
                    6,
                    address(usdc),
                    address(accountingToken),
                    true,
                    address(rateProvider),
                    false
                )
            )
        );
        strategy = FlexStrategy(payable(address(strategyProxy)));

        // Deploy AccountingModule
        AccountingModule accountingModuleImpl = new AccountingModule();
        TransparentUpgradeableProxy accountingModuleProxy = new TransparentUpgradeableProxy(
            address(accountingModuleImpl),
            admin,
            abi.encodeCall(
                AccountingModule.initialize,
                (
                    address(strategy),
                    admin,
                    safe,
                    IAccountingToken(address(accountingToken)),
                    0.15 ether,
                    0,
                    0,
                    uint16(3600)
                )
            )
        );
        accountingModule = AccountingModule(payable(address(accountingModuleProxy)));

        // Configure strategy
        vm.startPrank(admin);
        accountingToken.setAccountingModule(address(accountingModule));
        strategy.setAccountingModule(address(accountingModule));
        strategy.grantRole(strategy.PROCESSOR_ROLE(), processor);
        strategy.grantRole(strategy.PROCESSOR_MANAGER_ROLE(), admin);
        strategy.grantRole(strategy.ALLOCATOR_ROLE(), alice);
        strategy.grantRole(strategy.UNPAUSER_ROLE(), admin);

        // Set up Sablier rules with the validator
        _setupSablierRulesWithValidator();

        strategy.unpause();
        vm.stopPrank();

        // Fund the strategy with USDC
        usdc.mint(address(strategy), 100_000e6);
        usdc.mint(safe, 100_000e6);
    }

    function _setupSablierRulesWithValidator() internal {
        // Rule 1: Approve USDC to Sablier
        {
            bytes4 funcSig = IERC20.approve.selector;
            IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](2);

            address[] memory spenderAllowList = new address[](1);
            spenderAllowList[0] = address(sablier);
            paramRules[0] =
                IVault.ParamRule({paramType: IVault.ParamType.ADDRESS, isArray: false, allowList: spenderAllowList});
            paramRules[1] =
                IVault.ParamRule({paramType: IVault.ParamType.UINT256, isArray: false, allowList: new address[](0)});

            IVault.FunctionRule memory rule =
                IVault.FunctionRule({isActive: true, paramRules: paramRules, validator: IValidator(address(0))});

            IVault(address(strategy)).setProcessorRule(address(usdc), funcSig, rule);
        }

        // Rule 2: Create stream on Sablier WITH VALIDATOR
        {
            bytes4 funcSig = ISablierLockupLinear.createWithTimestampsLL.selector;
            IVault.ParamRule[] memory paramRules = new IVault.ParamRule[](0);

            IVault.FunctionRule memory rule = IVault.FunctionRule({
                isActive: true,
                paramRules: paramRules,
                validator: IValidator(address(validator)) // Use the validator
            });

            IVault(address(strategy)).setProcessorRule(address(sablier), funcSig, rule);
        }
    }

    /*//////////////////////////////////////////////////////////////
                         VALIDATOR DEPLOYMENT TESTS
    //////////////////////////////////////////////////////////////*/

    function test_validatorDeployment() public view {
        assertEq(validator.safe(), safe, "Safe should be set correctly");
        assertEq(validator.token(), address(usdc), "Token should be set correctly");
        assertTrue(validator.isAllowedRecipient(streamReceiver), "Stream receiver should be allowed");
        assertEq(validator.getAllowedRecipientsCount(), 1, "Should have 1 allowed recipient");
    }

    function test_revert_validatorDeployment_zeroSafe() public {
        address[] memory recipients = new address[](1);
        recipients[0] = streamReceiver;
        vm.expectRevert(StrategyKeeperSablierValidator.ZeroAddress.selector);
        new StrategyKeeperSablierValidator(address(0), address(usdc), recipients);
    }

    function test_revert_validatorDeployment_zeroToken() public {
        address[] memory recipients = new address[](1);
        recipients[0] = streamReceiver;
        vm.expectRevert(StrategyKeeperSablierValidator.ZeroAddress.selector);
        new StrategyKeeperSablierValidator(safe, address(0), recipients);
    }

    function test_revert_validatorDeployment_emptyRecipients() public {
        address[] memory recipients = new address[](0);
        vm.expectRevert(StrategyKeeperSablierValidator.EmptyAllowedRecipients.selector);
        new StrategyKeeperSablierValidator(safe, address(usdc), recipients);
    }

    function test_revert_validatorDeployment_zeroRecipient() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0);
        vm.expectRevert(StrategyKeeperSablierValidator.ZeroAddress.selector);
        new StrategyKeeperSablierValidator(safe, address(usdc), recipients);
    }

    /*//////////////////////////////////////////////////////////////
                         VALIDATION SUCCESS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_validStreamCreation() public {
        uint256 streamAmount = 1000e6;

        // Build processor calls
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        // Call 1: Approve Sablier
        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Call 2: Create stream with VALID params (sender=safe, recipient=streamReceiver, cancelable=true, transferable=true)
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe, // Must be the configured safe
            recipient: streamReceiver, // Must be in allowed recipients
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)), // Must be the configured token
            cancelable: true, // Must be true
            transferable: true, // Must be true
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

        // Execute via processor - should succeed
        vm.prank(processor);
        strategy.processor(targets, values, data);

        // Verify stream was created
        assertEq(sablier.ownerOf(1), streamReceiver, "Stream should be owned by receiver");
    }

    /*//////////////////////////////////////////////////////////////
                         VALIDATION FAILURE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_revert_invalidSender() public {
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
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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

    function test_revert_invalidRecipient() public {
        uint256 streamAmount = 1000e6;
        address invalidRecipient = address(0xDEAD);

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Use unauthorized recipient
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: invalidRecipient, // WRONG - not in allowed list
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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

    function test_revert_invalidToken() public {
        uint256 streamAmount = 1000e6;
        MockUSDC wrongToken = new MockUSDC();

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Use wrong token
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount),
            token: IERC20(address(wrongToken)), // WRONG - not the configured token
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
            abi.encodeWithSelector(
                StrategyKeeperSablierValidator.InvalidToken.selector, address(wrongToken), address(usdc)
            )
        );
        strategy.processor(targets, values, data);
    }

    function test_revert_notCancelable() public {
        uint256 streamAmount = 1000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Stream not cancelable
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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

    function test_revert_notTransferable() public {
        uint256 streamAmount = 1000e6;

        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory data = new bytes[](2);

        targets[0] = address(usdc);
        values[0] = 0;
        data[0] = abi.encodeCall(IERC20.approve, (address(sablier), streamAmount));

        // Stream not transferable
        ISablierLockupLinear.CreateWithTimestamps memory params = ISablierLockupLinear.CreateWithTimestamps({
            sender: safe,
            recipient: streamReceiver,
            depositAmount: uint128(streamAmount),
            token: IERC20(address(usdc)),
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

    function test_revert_invalidFunctionSelector() public {
        // Test directly calling validator with wrong selector
        bytes memory data = abi.encodeWithSelector(bytes4(0xdeadbeef), "test");

        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidFunctionSelector.selector, bytes4(0xdeadbeef))
        );
        validator.validate(address(sablier), 0, data);
    }

    function test_revert_dataTooShort() public {
        // Test directly calling validator with data that's too short
        bytes memory data = hex"dead";

        vm.expectRevert(
            abi.encodeWithSelector(StrategyKeeperSablierValidator.InvalidFunctionSelector.selector, bytes4(0))
        );
        validator.validate(address(sablier), 0, data);
    }

    /*//////////////////////////////////////////////////////////////
                         VIEW FUNCTION TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getAllowedRecipients() public view {
        address[] memory recipients = validator.getAllowedRecipients();
        assertEq(recipients.length, 1, "Should have 1 recipient");
        assertEq(recipients[0], streamReceiver, "Should be stream receiver");
    }

    function test_multipleAllowedRecipients() public {
        address recipient2 = address(0x6666);
        address recipient3 = address(0x7777);

        address[] memory recipients = new address[](3);
        recipients[0] = streamReceiver;
        recipients[1] = recipient2;
        recipients[2] = recipient3;

        StrategyKeeperSablierValidator multiValidator =
            new StrategyKeeperSablierValidator(safe, address(usdc), recipients);

        assertTrue(multiValidator.isAllowedRecipient(streamReceiver), "streamReceiver should be allowed");
        assertTrue(multiValidator.isAllowedRecipient(recipient2), "recipient2 should be allowed");
        assertTrue(multiValidator.isAllowedRecipient(recipient3), "recipient3 should be allowed");
        assertFalse(multiValidator.isAllowedRecipient(address(0xDEAD)), "0xDEAD should not be allowed");
        assertEq(multiValidator.getAllowedRecipientsCount(), 3, "Should have 3 recipients");
    }
}
