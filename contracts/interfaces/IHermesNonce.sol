// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

interface IHermesNonce {
    function useNonce() external returns (uint256);
}
