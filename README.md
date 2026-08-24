# Hermes

Minimal smart account for delegated EOAs ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)), targeting ERC-4337 EntryPoint v0.8 and v0.9.

An EOA delegates its code to `HermesDelegateV1` and gains smart-account capabilities — call batching, gas abstraction through ERC-4337, typed-data authorization, ERC-1271/ERC-7739 signature verification — while keeping its address and an EOA-like signature lifecycle. The delegate holds **no mutable storage**: the only mutable state lives in the `HermesV1` manager singleton (a per-account nonce), so re-delegation never leaves stale storage behind.

## Contracts

| Contract | Purpose |
| --- | --- |
| [`HermesDelegateV1.sol`](contracts/v1/HermesDelegateV1.sol) | The EIP-7702 delegate implementation. ERC-4337 account (`IAccount`), ERC-1271/ERC-7739 verifier, ERC-7821 batch executor, ERC-5267 domain. |
| [`HermesBase.sol`](contracts/HermesBase.sol) | Token-receiver callbacks (ERC-721/1155/777/677), ERC-165 and the ERC-7779 surface (`accountId`, `accountStorageBases`). |
| [`HermesV1.sol`](contracts/v1/HermesV1.sol) | Manager singleton (`IHermesNonce`): per-account incrementing nonce used as replay protection for signature-based execution. |
| [`interfaces/IHermesNonce.sol`](contracts/interfaces/IHermesNonce.sol) | Minimal manager interface (`useNonce`) the delegate pins as an immutable dependency. |
| [`interfaces/IERC7779.sol`](contracts/interfaces/IERC7779.sol) | ERC-7779 account-introspection interface. |

## Execution flows

All execution goes through the single standard [ERC-7821](https://eips.ethereum.org/EIPS/eip-7821) entry point `execute(bytes32 mode, bytes executionData)`, with two supported modes. The three authorization schemes map onto them:

| Flow | Mode | Authorization | Replay protection |
| --- | --- | --- | --- |
| ERC-4337 | `validateUserOp` → `execute` (no `opData`) | EOA signature over `userOpHash`, checked in `validateUserOp`; `execute` is callable by a trusted EntryPoint (v0.8/v0.9) | EntryPoint nonce |
| Self-call | `execute` (no `opData`) | `msg.sender == address(this)` (the delegated EOA sends a tx to itself) | The EOA's own tx nonce |
| Signature-based | `execute` (with `opData`) | EIP-712 `Execute(bytes32 mode, Call[] calls, uint256 nonce, uint256 deadline)` signature carried in `opData`; any relayer may submit | Hermes manager nonce |

- **No-`opData` mode** (`0x01000000000000000000…`) — `executionData` is `abi.encode(Call[])`; authorized by `msg.sender` (the account itself or a trusted EntryPoint).
- **`opData` mode** (`0x01000000000078210001…`) — `executionData` is `abi.encode(Call[], opData)`, where `opData` is `abi.encode(uint256 deadline, bytes signature)`; `msg.sender`-agnostic.

Notes on the design:

- **Standard execution surface.** Exposing ERC-7821 (`execute` + `supportsExecutionMode`) lets standard tooling drive the account — e.g. an [EIP-5792](https://eips.ethereum.org/EIPS/eip-5792) `wallet_sendCalls` batch routes through the no-`opData` mode.
- **Validation/execution coupling (4337).** `validateUserOp` rejects any userOp whose callData does not target `execute`, and the no-`opData` mode only authorizes a trusted EntryPoint (or self). EntryPoint's protocol guarantees validation runs before execution, so no transient flag is needed.
- **Fully-typed signing.** The `opData` path is authorized by a canonical EIP-712 struct, so `eth_signTypedData_v4` wallets render every target, value and calldata at signing time — no opaque hashes.
- **EOA-like signature lifecycle.** Signatures have no expiry; a pending signature is cancelled by consuming its nonce, exactly like replacing a pending EOA transaction. The nonce is consumed before any of the batch's calls, so a signature cannot be replayed by reentering from a target.
- **Re-delegation safety.** The EIP-712 domain uses the implementation address as `salt`, pinning every signature to the specific delegate version. Re-delegating the EOA to different code invalidates all outstanding signatures.
- **Defensive ERC-1271 ([ERC-7739](https://eips.ethereum.org/EIPS/eip-7739)).** Contract-signature checks use ERC-7739 nested rehashing — the two standard forms `TypedDataSign` (typed data) and `PersonalSign` (an EIP-191 mimic) — built on OpenZeppelin's audited `ERC7739Utils`. The request is re-nested under this account's EIP-712 domain (including the impl-pinning `salt`), so a signature for one account, domain or protocol never validates here while the signed content stays human-readable. The empty-signature probe (`hash = 0x7739…7739`) returns the ERC-7739 detection magic `0x77390001`.
- **Discoverable domain.** [ERC-5267](https://eips.ethereum.org/EIPS/eip-5267) `eip712Domain()` exposes the full domain (including the non-standard `salt`), so signers/tooling can reconstruct the signing domain on-chain instead of hardcoding it per deployment.
- **EntryPoints.** Two canonical EntryPoints are trusted as callers — v0.8 (`0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`) and v0.9 (`0x433709009B8330FDa32311DF1C2AFA402eD8D009`) — at the same addresses on all supported chains. Discovery goes through `isSupportedEntryPoint(address)`, which probes that set — there is no single-valued `entryPoint()` getter, because the account trusts two EntryPoints rather than one (a call to that selector is absorbed by the empty `fallback` and returns no data, so tooling must not read it). Each EntryPoint binds its own address as the EIP-712 `verifyingContract`, so a userOp signature never replays across the two.

## Development

Toolchain: Hardhat, Solidity 0.8.35 (viaIR, Prague EVM), TypeChain, ethers v6.

```bash
yarn install
yarn compile          # hardhat compile (+ ABI export to reports/abi)
yarn hardhat test     # full suite on the in-process Hardhat network
yarn coverage         # solidity-coverage
yarn size             # contract size report
REPORT_GAS=true yarn hardhat test   # gas report to reports/gas
```

Against a local node:

```bash
yarn lh               # start a Hardhat node on 127.0.0.1:8545
yarn test:lh          # run the tests against it
```

Tests live in [`test/`](test): [`HermesDelegateV1.test.ts`](test/HermesDelegateV1.test.ts) covers the three flows, ERC-1271 and the EIP-712 encoding against reference implementations; [`GasComparison.test.ts`](test/GasComparison.test.ts) benchmarks the execution paths.

## License

[Apache License 2.0](LICENSE).
