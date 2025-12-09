// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import {IERC20} from "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";
import {IStrategy} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IStrategy.sol";
import {IVault} from "lib/yieldnest-flex-strategy/lib/yieldnest-vault/src/interface/IVault.sol";
import {ISablierLockupLinear} from "./interfaces/sablier/ISablierLockupLinear.sol";

contract StrategyKeeper {
    // --- Config ---
    IERC20 public immutable asset;
    IVault public immutable vault;
    ISPV1Strategy public immutable strategy;

    uint256 public minAssetToRoll;
    uint256 public minAssetToRollAfterMaxInactive;
    uint256 public maxInactiveTime;

    uint256 public lastRolled;

    // --- Events ---
    event Rolled(uint256 usdcRolled, uint256 sablierStreamId, uint256 time);

    constructor(address _usdc, address _spv1, address _sablier, address _wayne, address _yieldnestFeeRecipient) {
        usdc = IERC20(_usdc);
        spv1 = IStrategy(_spv1);
        sablier = ISablier(_sablier);
        wayne = _wayne;
        yieldnestFeeRecipient = _yieldnestFeeRecipient;
        lastRolled = block.timestamp;
    }

    function roll() external {}
}
