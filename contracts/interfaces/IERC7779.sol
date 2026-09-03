// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/**
 * @title IERC7779 - Account-introspection interface for EIP-7702 delegated accounts.
 * @dev Verbatim surface of ERC-7779: a namespace identifier plus the storage bases the account's
 *      implementations claim, so a wallet can inspect an already-delegated account before
 *      re-delegating it.
 * @custom:security-contact bugs@tonkeeper.com
 */
interface IERC7779 {

    /**
     * @dev    Provides the namespace of the account.
     *         namespace of accounts can possibly include, account version, account name, wallet vendor name, etc
     * @notice this standard does not standardize the namespace format
     *         e.g., "v0.1.2.7702Account.WalletProjectA"
     * @return The account's namespace identifier.
     */
    function accountId() external view returns (string memory);

    /**
    * @dev    Externally shares the storage bases that has been used throughout the account.
    *         Majority of 7702 accounts will have their distinctive storage base to reduce the chance of storage collision.
    *         This allows the external entities to know what the storage base is of the account.
    *         Wallets willing to redelegate already-delegated accounts should call accountStorageBase() to check if it confirms with the account it plans to redelegate.
    *
    *         The bytes32 array should be stored at the storage slot: keccak(keccak('InteroperableDelegatedAccount.ERC.Storage')-1) & ~0xff
    *         This is an append-only array so newly redelegated accounts should not overwrite the storage at this slot, but just append their base to the array.
    *         This append operation should be done during the initialization of the account.
    * 		   This array should return a value of keccak hash unless using external storage.
    * @return The storage bases claimed by the implementations this account has been delegated to.
    */
    function accountStorageBases() external view returns (bytes32[] memory);
}
