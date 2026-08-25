// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

import "../interfaces/IHermesNonce.sol";

/**
 * @title HermesV1 - Singleton nonce manager for Hermes delegates.
 * @author anchupin
 * @notice Sole source of replay protection for the signature-based execution path
 *         (`HermesDelegateV1.executeWithSignature`). Deployed once and shared by every
 *         Hermes-delegated account; each account's nonce is isolated by `msg.sender`.
 *
 * @dev Design and trust model:
 *      - **Per-account isolation.** Nonces are keyed by `msg.sender`. Because an EIP-7702
 *        delegated EOA is itself the caller when it invokes the manager, `_nonces[eoa]` is that
 *        EOA's private counter — no account can read, advance, or grief another account's nonce.
 *      - **Sequential & monotonic.** `useNonce()` returns the current value and increments by one.
 *        The returned (pre-increment) value is the nonce a delegate folds into the EIP-712
 *        `Execute(bytes32 mode,Call[] calls,uint256 nonce,uint256 deadline)` struct hash, binding each
 *        signature to exactly one slot in the sequence.
 *      - **Signature lifecycle (EOA-like).** A pending `executeWithSignature` signature stays valid
 *        until its nonce is consumed; advancing the nonce (e.g. the EOA calling `useNonce()`
 *        directly, or executing any signed batch) invalidates it, mirroring how replacing a pending
 *        EOA transaction spends the account nonce. This manager imposes no expiry of its own; the
 *        delegate additionally time-bounds each signature via the signed `deadline` in that struct.
 *      - **Spent only on success.** A delegate consumes the nonce in the same transaction as the
 *        batch it authorizes, so a reverting batch rolls the increment back — unlike an EOA
 *        transaction, which spends its nonce either way. A signature whose batch failed on a
 *        transient condition stays executable once that clears; `useNonce()` retires it. Only mined,
 *        successful batches advance the counter.
 *      - **Immutable trust anchor.** This contract has no owner, no upgrade path, no pause, and no
 *        `selfdestruct`. Once deployed it cannot be altered or replaced at its address, so delegates
 *        can safely pin it as an `immutable` dependency. Its address is therefore a security-critical
 *        deploy parameter and must be verified (correct code, correct identity) before a delegate
 *        that references it is shipped.
 */
contract HermesV1 is IHermesNonce {

    /// @dev Per-account monotonic nonce counter, keyed by the calling account (`msg.sender`).
    mapping(address => uint256) private _nonces;

    /**
     * @notice Returns the next unused nonce for `account` — i.e. the value a signer must embed in
     *         the next `Execute` struct for that account.
     * @dev View-only; does not mutate state. Off-chain signers read this to build the digest, and
     *      relayers can compare it against a signed nonce to detect an already-spent signature.
     * @param account The Hermes-delegated account whose nonce to read.
     * @return The current (next-to-consume) nonce for `account`.
     */
    function nonceOf(address account) external view returns (uint256) {
        return _nonces[account];
    }

    /**
     * @notice Consumes the caller's current nonce and advances it by one.
     * @dev Returns the value *before* the increment — that is the nonce bound into the caller's
     *      signature. Anyone may call this, but only ever for their own `msg.sender` slot, so it
     *      doubles as a self-service "cancel pending signature" primitive.
     *
     *      Also reachable from inside a delegate's batch, since under EIP-7702 the account is
     *      `msg.sender` either way: a signed batch consumes *at least* one nonce. Read
     *      `nonceOf(account)` instead of assuming one increment per batch.
     * @return current The caller's nonce as it was prior to this call.
     */
    function useNonce() external override returns (uint256 current) {
        current = _nonces[msg.sender];
        unchecked { _nonces[msg.sender] = current + 1; }
    }
}
