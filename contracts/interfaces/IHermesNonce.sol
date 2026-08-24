// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/**
 * @title IHermesNonce - Minimal nonce-manager interface pinned by every Hermes delegate.
 * @dev The one call a delegate needs from the `HermesV1` singleton; read-only helpers such as
 *      `nonceOf` live on the manager itself and are deliberately out of this interface.
 */
interface IHermesNonce {
    /**
     * @notice Consumes the caller's current nonce and advances it by one.
     * @dev Nonces are keyed by `msg.sender`, so a caller only ever advances its own counter. The
     *      pre-increment value is what a delegate folds into the signed `Execute` struct hash.
     * @return The caller's nonce as it was prior to this call.
     */
    function useNonce() external returns (uint256);
}
