// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";

import {FlowHandler} from "src/FlowHandler.sol";

/// @dev Exposes the actual assembly slots used by FlowHandler and BaseSafeModule
///      so the tests can assert they match the ERC-7201 derivation of the
///      namespaces declared in the @custom:storage-location annotations.
contract FlowHandlerSlotHarness is FlowHandler {
    function flowHandlerSlot() external pure returns (bytes32 slot) {
        FlowHandlerStorage storage $ = _getFlowHandlerStorage();
        assembly {
            slot := $.slot
        }
    }

    function baseSafeModuleSlot() external pure returns (bytes32 slot) {
        BaseSafeModuleStorage storage $ = _getBaseSafeModuleStorage();
        assembly {
            slot := $.slot
        }
    }
}

contract StorageSlotsTest is Test {
    FlowHandlerSlotHarness internal harness;

    function setUp() public {
        harness = new FlowHandlerSlotHarness();
    }

    function _erc7201Slot(string memory namespace) internal pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encode(uint256(keccak256(bytes(namespace))) - 1))) & ~uint256(0xff));
    }

    function test_flowHandlerSlotMatchesErc7201Namespace() public view {
        assertEq(harness.flowHandlerSlot(), _erc7201Slot("yieldnest.storage.flow_handler"));
    }

    function test_baseSafeModuleSlotMatchesErc7201Namespace() public view {
        assertEq(harness.baseSafeModuleSlot(), _erc7201Slot("yieldnest.storage.base_safe_module"));
    }
}
