// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IERC4626} from "lib/openzeppelin-contracts/contracts/interfaces/IERC4626.sol";
import {FlexStrategy} from "lib/yieldnest-flex-strategy/src/FlexStrategy.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {ISablierLockupLinear} from "./interfaces/sablier/ISablierLockupLinear.sol";
import {IAccountingModule} from "lib/yieldnest-flex-strategy/src/AccountingModule.sol";

contract StrategyKeeper {
    // --- Config ---
    IERC20 public immutable asset;
    IVault public immutable vault;
    FlexStrategy public immutable strategy;
    ISablierLockupLinear public immutable sablier;

    uint256 public minAssetToRoll;
    uint256 public minAssetToRollAfterMaxInactive;
    uint256 public maxInactiveTime;

    uint256 public lastRolled;

    address public strategyFundsReceiver;
    address public feeReceiver;

    // --- Events ---
    event Rolled(uint256 usdcRolled, uint256 sablierStreamId, uint256 time);

    address public yieldnestFeeRecipient;

    constructor(
        address _asset,
        address _vault,
        address _strategy,
        address _sablier,
        address _yieldnestFeeRecipient,
        uint256 _minAssetToRoll,
        uint256 _minAssetToRollAfterMaxInactive,
        uint256 _maxInactiveTime,
        address _strategyFundsReceiver,
        address _feeReceiver
    ) {
        asset = IERC20(_asset);
        vault = IVault(_vault);
        strategy = FlexStrategy(payable(_strategy));
        sablier = ISablierLockupLinear(_sablier);
        yieldnestFeeRecipient = _yieldnestFeeRecipient;
        minAssetToRoll = _minAssetToRoll;
        minAssetToRollAfterMaxInactive = _minAssetToRollAfterMaxInactive;
        maxInactiveTime = _maxInactiveTime;
        strategyFundsReceiver = _strategyFundsReceiver;
        feeReceiver = _feeReceiver;
        lastRolled = block.timestamp;
    }

    error NotEnoughAssets();
    error NotEnoughAssetsOrInactiveTimeNotReached();

    function roll() external {
        uint256 assetBalance = asset.balanceOf(address(vault));
        // Check if we satisfy the normal roll condition
        if (assetBalance >= minAssetToRoll) {
            // ok
        }
        // Else, check if inactive time has passed and we have enough for fallback min
        else if (block.timestamp > lastRolled + maxInactiveTime) {
            if (assetBalance < minAssetToRollAfterMaxInactive) {
                revert NotEnoughAssets();
            }
        }
        // Neither condition satisfied
        else {
            revert NotEnoughAssetsOrInactiveTimeNotReached();
        }

        lastRolled = block.timestamp;

        rollToStrategy(assetBalance);

        address strategySafe = IAccountingModule(strategy.accountingModule()).safe();

        emit Rolled(assetBalance, 0, block.timestamp); // sablierStreamId is 0 since not interacting with sablier here
    }

    function rollToStrategy(uint256 amount) internal {
        // Prepare an "approve" call to allow the strategy to spend "amount" of the asset
        bytes memory approveCalldata = abi.encodeWithSelector(IERC20.approve.selector, address(strategy), amount);

        // Prepare a "deposit" call for the strategy: deposit(uint256 amount, address receiver)
        bytes memory depositCalldata = abi.encodeWithSelector(
            IERC4626.deposit.selector,
            amount,
            address(this) // receiver can be changed as needed
        );

        // Prepare arguments for vault.processor using both approve and deposit actions
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory calldatas = new bytes[](2);

        targets[0] = address(asset);
        values[0] = 0;
        calldatas[0] = approveCalldata;

        targets[1] = address(strategy);
        values[1] = 0;
        calldatas[1] = depositCalldata;

        vault.processor(targets, values, calldatas);
    }
}
