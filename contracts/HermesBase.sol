// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/interfaces/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC7779} from "./interfaces/IERC7779.sol";

/**
 * @title HermesBase - Token-receiver and ERC-7779 surface for Hermes delegates.
 * @author anchupin
 * @dev Stateless base of every Hermes delegate: the token-receiver callbacks (ERC-721, ERC-1155,
 *      ERC-677, and an ERC-777 hook that fires only once the account self-registers in ERC-1820),
 *      ERC-165 introspection over them, and the ERC-7779 surface a wallet reads before
 *      re-delegating. Every callback is a `pure` no-op returning only its acceptance value.
 * @custom:security-contact bugs@tonkeeper.com
 */
abstract contract HermesBase is IERC165, IERC7779, IERC721Receiver, IERC1155Receiver {

    /// @dev ERC-7779 storage slot holding the append-only list of storage bases, computed as
    ///      `keccak256(abi.encode(uint256(keccak256(bytes("InteroperableDelegatedAccount.ERC.Storage"))) - 1)) & ~bytes32(uint256(0xff))`.
    bytes32 internal constant ERC7779_STORAGE_BASE = 0xc473de86d0138e06e4d4918a106463a7cc005258d2e21915272bcb4594c18900;

    /// @dev Layout of the ERC-7779 slot: the append-only list of storage bases claimed by the
    ///      implementations this account has been delegated to. Hermes never appends — it is
    ///      read-only here, exposed so a wallet re-delegating the account can check for collisions.
    struct ERC7779Storage {
        bytes32[] storageBases;
    }

    /// @notice ERC-165 introspection over the interfaces every Hermes account implements: ERC-165
    ///         itself, the ERC-721 and ERC-1155 receiver hooks, ERC-7779 introspection and ERC-1271.
    /// @dev Delegates extend this set by overriding and falling through to `super`.
    /// @param interfaceId The ERC-165 interface identifier to probe.
    /// @return True iff `interfaceId` is one of the interfaces implemented by this account.
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId
            || interfaceId == type(IERC7779).interfaceId
            || interfaceId == type(IERC1271).interfaceId;
    }

    /// @notice ERC-721 `safeTransferFrom` callback: every incoming token is accepted.
    /// @dev The four arguments (operator, from, tokenId, data) are unused and left unnamed.
    /// @return The `onERC721Received` selector, which is what ERC-721 requires for acceptance.
    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }

    /// @notice ERC-1155 single-transfer callback: every incoming token is accepted.
    /// @dev The five arguments (operator, from, id, value, data) are unused and left unnamed.
    /// @return The `onERC1155Received` selector, which is what ERC-1155 requires for acceptance.
    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    /// @notice ERC-1155 batch-transfer callback: every incoming token is accepted.
    /// @dev The five arguments (operator, from, ids, values, data) are unused and left unnamed.
    /// @return The `onERC1155BatchReceived` selector, which is what ERC-1155 requires for acceptance.
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    /// @notice ERC-777 `tokensReceived` hook. No-op: the transfer is accepted as-is.
    /// @dev Unreachable until the account registers itself as its own `ERC777TokensRecipient` in the
    ///      ERC-1820 registry: a delegated EOA has code, so an ERC-777 token treats it as a contract
    ///      recipient and reverts the transfer when it finds no implementer. Self-registration via
    ///      `execute` is accepted without the registry's `canImplementInterfaceForAddress` check.
    ///      Hermes does not register on the account's behalf — that is a per-account, per-chain write.
    ///      The six arguments (operator, from, to, amount, userData, operatorData) are unused and
    ///      left unnamed. ERC-777 signals acceptance by not reverting, so there is no return value.
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external pure {}

    /// @notice ERC-677 `transferAndCall` callback: every incoming transfer is accepted.
    /// @dev The three arguments (sender, value, data) are unused and left unnamed.
    /// @return Always true — ERC-677 tokens treat a false return as a rejected transfer.
    function onTokenTransfer(address, uint256, bytes calldata) external pure returns (bool) {
        return true;
    }

    /// @notice ERC-7779 namespace identifier of the account. Overridden per delegate version.
    /// @return The account identifier; empty in this base, which never ships on its own.
    function accountId() external pure virtual override returns (string memory) {}

    /// @notice ERC-7779: the storage bases claimed by the implementations this account has been
    ///         delegated to, which a wallet reads to check for collisions before re-delegating it.
    /// @dev Reads the append-only array at the fixed `ERC7779_STORAGE_BASE` slot.
    /// @return The list of storage bases recorded at `ERC7779_STORAGE_BASE`.
    function accountStorageBases() external view override returns (bytes32[] memory) {
        ERC7779Storage storage $;
        assembly {
            $.slot := ERC7779_STORAGE_BASE
        }
        return $.storageBases;
    }
}
