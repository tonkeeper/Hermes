// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

/// @custom:security-contact bugs@tonkeeper.com
interface IHermesNonce {
    function useNonce() external returns (uint256);
}
