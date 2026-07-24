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
 */
abstract contract HermesBase is IERC165, IERC7779, IERC721Receiver, IERC1155Receiver {

    // keccak256(abi.encode(uint256(keccak256(bytes("InteroperableDelegatedAccount.ERC.Storage"))) - 1)) & ~bytes32(uint256(0xff))
    bytes32 internal constant ERC7779_STORAGE_BASE = 0xc473de86d0138e06e4d4918a106463a7cc005258d2e21915272bcb4594c18900;

    struct ERC7779Storage {
        bytes32[] storageBases;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId
            || interfaceId == type(IERC721Receiver).interfaceId
            || interfaceId == type(IERC165).interfaceId
            || interfaceId == type(IERC7779).interfaceId
            || interfaceId == type(IERC1271).interfaceId;
    }

    function onERC721Received(address, address, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return this.onERC1155BatchReceived.selector;
    }

    /// @notice ERC-777 callback. No-op.
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external pure {}

    /// @notice ERC-677 callback.
    function onTokenTransfer(address, uint256, bytes calldata) external pure returns (bool) {
        return true;
    }

    /// @notice Namespace identifier of the account. Overridden per delegate version.
    function accountId() external pure virtual override returns (string memory) {}

    function accountStorageBases() external view override returns (bytes32[] memory) {
        ERC7779Storage storage $;
        assembly {
            $.slot := ERC7779_STORAGE_BASE
        }
        return $.storageBases;
    }
}
