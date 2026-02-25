// SPDX-License-Identifier: BSD-3-Clause
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";

/// @title Prompt
/// @notice Library for prompting user input in forge scripts
/// @dev Uses forge's FFI to read from stdin
library Prompt {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @notice Prompts the user to enter an address
    /// @param message The prompt message to display
    /// @return The address entered by the user
    function forAddress(string memory message) internal returns (address) {
        string memory input = vm.prompt(message);
        return vm.parseAddress(input);
    }

    /// @notice Prompts the user to enter a uint256
    /// @param message The prompt message to display
    /// @return The uint256 entered by the user
    function forUint(string memory message) internal returns (uint256) {
        string memory input = vm.prompt(message);
        return vm.parseUint(input);
    }

    /// @notice Prompts the user to enter a string
    /// @param message The prompt message to display
    /// @return The string entered by the user
    function forString(string memory message) internal returns (string memory) {
        return vm.prompt(message);
    }

    /// @notice Prompts the user to confirm (y/n)
    /// @param message The prompt message to display
    /// @return True if user enters 'y' or 'Y', false otherwise
    function forConfirmation(string memory message) internal returns (bool) {
        string memory input = vm.prompt(string.concat(message, " (y/n)"));
        bytes32 inputHash = keccak256(bytes(input));
        return inputHash == keccak256("y") || inputHash == keccak256("Y") || inputHash == keccak256("yes")
            || inputHash == keccak256("Yes") || inputHash == keccak256("YES");
    }
}
