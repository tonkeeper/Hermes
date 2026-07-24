// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/// @dev Reentrancy probe for tests: `attack()` re-submits a pre-loaded payload (e.g. the very
///      signed `execute` calldata currently being executed) back at the account and records the
///      outcome instead of reverting, so the outer batch keeps running and the test can assert
///      that the replay was attempted and rejected.
contract ReentrantTarget {

    address public account;
    bytes public payload;

    bool public reentered;
    bool public reentrySucceeded;
    bytes public reentryReturnData;

    function arm(address _account, bytes calldata _payload) external {
        account = _account;
        payload = _payload;
    }

    function attack() external {
        reentered = true;
        (bool ok, bytes memory ret) = account.call(payload);
        reentrySucceeded = ok;
        reentryReturnData = ret;
    }
}
