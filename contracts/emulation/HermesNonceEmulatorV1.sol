// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

import "../interfaces/IHermesNonce.sol";

/**
 * @title HermesNonceEmulatorV1 - Gas-emulation twin of HermesV1 (the nonce manager). NEVER DEPLOY.
 * @author anchupin
 * @dev Injected by the relay server via state overrides at the emulator's virtual manager address
 *      (`0x…7702`) during `eth_estimateGas`, so `manager.useNonce()` costs the same as against the
 *      real singleton (cold external call + first-write SSTORE). Code mirrors HermesV1 exactly.
 */
contract HermesNonceEmulatorV1 is IHermesNonce {

    mapping(address => uint256) private _nonces;

    function nonceOf(address account) external view returns (uint256) {
        return _nonces[account];
    }

    function useNonce() external override returns (uint256 current) {
        current = _nonces[msg.sender];
        unchecked { _nonces[msg.sender] = current + 1; }
    }
}
