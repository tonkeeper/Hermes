// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/// @dev Return-bombing target for tests: reverts with an arbitrarily large payload, so callers
///      exercise the bound on copied and logged return data.
contract ReturnBomber {

    /// @dev Reverts with exactly `size` bytes of return data.
    function boom(uint256 size) external pure {
        assembly {
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, size))
            revert(ptr, size)
        }
    }
}
