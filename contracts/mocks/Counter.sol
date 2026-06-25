// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

contract Counter {

    uint256 public value;

    event Bumped(address caller, uint256 by, uint256 newValue);

    error CounterBoom();

    function bump(uint256 by) external {
        value += by;
        emit Bumped(msg.sender, by, value);
    }

    /// @dev Always reverts; lets tests exercise failing calls inside a batch.
    function boom() external pure {
        revert CounterBoom();
    }
}
