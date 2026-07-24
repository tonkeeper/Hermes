// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/// @dev Worst-case griefing target for tests: consumes every unit of gas forwarded to it
///      (out-of-gas, not a revert), so callers exercise the EIP-150 63/64 reserve path.
contract GasBurner {

    uint256 private sink;

    function burn() external {
        while (true) {
            sink = uint256(keccak256(abi.encode(sink)));
        }
    }
}
