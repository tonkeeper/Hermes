# Hermes

Minimal smart account for delegated EOAs ([EIP-7702](https://eips.ethereum.org/EIPS/eip-7702)), targeting ERC-4337 EntryPoint v0.8 and v0.9.

An EOA delegates its code to `HermesDelegateV1` and gains smart-account capabilities — call batching, gas abstraction through ERC-4337, typed-data authorization, ERC-1271/ERC-7739 signature verification — while keeping its address and an EOA-like signature lifecycle. The delegate holds **no mutable storage**: the only mutable state lives in the `HermesV1` manager singleton (a per-account nonce), so re-delegation never leaves stale storage behind.

## Contracts

| Contract | Purpose |
| --- | --- |
| [`HermesDelegateV1.sol`](contracts/v1/HermesDelegateV1.sol) | The EIP-7702 delegate implementation. ERC-4337 account (`IAccount`), ERC-1271/ERC-7739 verifier, ERC-7821 batch executor, ERC-5267 domain. |
| [`HermesBase.sol`](contracts/HermesBase.sol) | Token-receiver callbacks (ERC-721/1155/677), ERC-165 and the ERC-7779 surface (`accountId`, `accountStorageBases`). |
| [`HermesV1.sol`](contracts/v1/HermesV1.sol) | Manager singleton (`IHermesNonce`): per-account incrementing nonce used as replay protection for signature-based execution. |
| [`interfaces/IHermesNonce.sol`](contracts/interfaces/IHermesNonce.sol) | Minimal manager interface (`useNonce`) the delegate pins as an immutable dependency. |
| [`interfaces/IERC7779.sol`](contracts/interfaces/IERC7779.sol) | ERC-7779 account-introspection interface. |

## Execution flows

All execution goes through the single standard [ERC-7821](https://eips.ethereum.org/EIPS/eip-7821) entry point `execute(bytes32 mode, bytes executionData)`, with two supported modes. The three authorization schemes map onto them:

| Flow | Mode | Authorization | Replay protection |
| --- | --- | --- | --- |
| ERC-4337 | `validateUserOp` → `execute` (no `opData`) | EOA signature over `userOpHash`, checked in `validateUserOp`; `execute` is callable by a trusted EntryPoint (v0.8/v0.9) | EntryPoint nonce |
| Self-call | `execute` (no `opData`) | `msg.sender == address(this)` (the delegated EOA sends a tx to itself) | The EOA's own tx nonce |
| Signature-based | `execute` (with `opData`) | EIP-712 `Execute(bytes32 mode, Call[] calls, uint256 nonce)` signature carried in `opData`; any relayer may submit | Hermes manager nonce |

- **No-`opData` mode** (`0x01000000000000000000…`) — `executionData` is `abi.encode(Call[])`; authorized by `msg.sender` (the account itself or a trusted EntryPoint).
- **`opData` mode** (`0x01000000000078210001…`) — `executionData` is `abi.encode(Call[], opData)`, where `opData` is the EOA's signature; `msg.sender`-agnostic.

Notes on the design:

- **Bounded failure logs.** A callee alone chooses how many bytes it reverts with, while the caller pays to copy and log them. A non-fatal try-mode failure is therefore logged as `CallFailed(index)` — the index only, with no return data copied — so no target in a batch can set the transaction's gas cost and out-of-gas a try batch that is supposed to survive its failure. A fatal failure still bubbles the callee's raw revert data: there the whole transaction reverts either way. The reason behind a logged failure stays recoverable by simulating the call.
- **Standard execution surface.** Exposing ERC-7821 (`execute` + `supportsExecutionMode`) lets standard tooling drive the account — e.g. an [EIP-5792](https://eips.ethereum.org/EIPS/eip-5792) `wallet_sendCalls` batch routes through the no-`opData` mode.
- **Validation/execution coupling (4337).** `validateUserOp` rejects any userOp whose callData does not target `execute`, and the no-`opData` mode only authorizes a trusted EntryPoint (or self). EntryPoint's protocol guarantees validation runs before execution, so no transient flag is needed.
- **Fully-typed signing.** The `opData` path is authorized by a canonical EIP-712 struct, so `eth_signTypedData_v4` wallets render every target, value and calldata at signing time — no opaque hashes. A `Call.target` of `address(0)` — ERC-7821's shorthand for the account itself — is canonicalized to `address(this)` before hashing, so a self-call is always signed under its real address and the zero form stays a pure calldata-size optimization a submitter may apply.
- **EOA-like signature lifecycle.** Signatures have no expiry; a pending signature is cancelled by consuming its nonce, exactly like replacing a pending EOA transaction. The nonce is consumed before any external call, so a signature cannot be replayed by reentering from a target.
- **At least one nonce per signed batch.** The manager keys nonces by `msg.sender`, and under EIP-7702 the account is the caller both when `execute` consumes the batch's nonce and when a call *inside* the batch reaches the manager. A batch that itself calls `useNonce` therefore advances the counter twice, and every skipped value is permanently unusable — retiring any signature pending at it. That is also the only way to cancel several pending signatures at once. Relayers and indexers must read `nonceOf(account)` on-chain rather than track it incrementally; the same is true regardless, since the EOA can advance its nonce with an ordinary transaction to the manager, outside any batch.
- **Re-delegation safety.** The EIP-712 domain uses the implementation address as `salt`, pinning every signature to the specific delegate version. Re-delegating the EOA to different code **suspends** outstanding signed batches: the salt is a domain check evaluated against the delegation in effect at execution time, and the manager nonce is keyed by the account and survives re-delegation, so a signature whose `deadline` has not passed and whose nonce is unspent validates again if the account is re-delegated back to Hermes. The ERC-4337 surface is not pinned at all — `validateUserOp` verifies the bare `userOpHash`, which does not commit to the code at the account's address, so a withheld userOp survives re-delegation too. Permanent cancellation is spending the nonce — `HermesV1.useNonce()` for a signed batch, the EntryPoint nonce for a userOp — or an expired `deadline`. Wallets should implement "cancel a pending signature" as a nonce-spending transaction, not as a re-delegation.
- **Defensive ERC-1271 ([ERC-7739](https://eips.ethereum.org/EIPS/eip-7739)).** Contract-signature checks use ERC-7739 nested rehashing — the two standard forms `TypedDataSign` (typed data) and `PersonalSign` (an EIP-191 mimic) — built on OpenZeppelin's audited `ERC7739Utils`. The request is re-nested under this account's EIP-712 domain (including the impl-pinning `salt`), so a signature for one account, domain or protocol never validates here while the signed content stays human-readable. The empty-signature probe (`hash = 0x7739…7739`) returns the ERC-7739 detection magic `0x77390001`.
- **Accepted signature encodings.** Every signing surface — the `opData` batch path, `validateUserOp` and `isValidSignature` — accepts both the 65-byte `(r, s, v)` encoding and the 64-byte `(r, vs)` encoding of [EIP-2098](https://eips.ethereum.org/EIPS/eip-2098). `isValidSignature` additionally falls back to a plain ECDSA signature over `hash` itself, checked *after* both ERC-7739 nested forms and the detection probe: verifiers route an account with code into ERC-1271 by `code.length`, so without the fallback a delegated account would reject signatures its own key produced — including from wallets that do not implement ERC-7739 — and be less signature-compatible than the bare EOA it replaced. The trade-off is that a raw signature over a bare `hash` carries no domain and is replayable at any verifier asking this account about the same `hash`; it stays bound to this account, since recovery must return `address(this)`.
- **Discoverable domain.** [ERC-5267](https://eips.ethereum.org/EIPS/eip-5267) `eip712Domain()` exposes the full domain (including the non-standard `salt`), so signers/tooling can reconstruct the signing domain on-chain instead of hardcoding it per deployment.
- **EntryPoints.** Two canonical EntryPoints are trusted as callers — v0.8 (`0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108`) and v0.9 (`0x433709009B8330FDa32311DF1C2AFA402eD8D009`) — at the same addresses on all supported chains. `entryPoint()` reports v0.9 for discovery and `isSupportedEntryPoint` probes the set. v0.7 is intentionally excluded: its `userOpHash` is a plain keccak rather than an EIP-712 typed hash. Each EntryPoint binds its own address as the EIP-712 `verifyingContract`, so a userOp signature never replays across the two.

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
