// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/**
 * @title HermesGasMeterV1 - eth_call gas probe for relay emulation. NEVER DEPLOY.
 * @author anchupin
 * @dev Injected at a virtual address via `eth_call` state overrides (works on nodes that don't
 *      support overrides for `eth_estimateGas`, e.g. hardhat). Measures the gas consumed by the
 *      full `execute()` call against the emulator-overridden account and returns it together with
 *      the call's outcome; the server adds tx intrinsic + calldata gas on top.
 */
contract HermesGasMeterV1 {

    function measure(address target, bytes calldata data)
        external
        returns (uint256 gasUsed, bool success, bytes memory result)
    {
        uint256 before = gasleft();
        (success, result) = target.call(data);
        gasUsed = before - gasleft();
    }
}
