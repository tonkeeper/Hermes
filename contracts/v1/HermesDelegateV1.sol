// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC7739Utils} from "@openzeppelin/contracts/utils/cryptography/draft-ERC7739Utils.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IAccount, PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC7821} from "@openzeppelin/contracts/interfaces/draft-IERC7821.sol";
import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";
import {ERC7579Utils, Mode, CallType, ExecType, ModeSelector, ModePayload} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {HermesBase} from "../HermesBase.sol";
import {IHermesNonce} from "../interfaces/IHermesNonce.sol";

/**
 * @title HermesDelegateV1.sol - Smart wallet for delegated EOAs (EIP-7702), targeting EntryPoint v0.8/v0.9.
 * @author anchupin
 * @dev The delegated EOA's key is the sole authority. Execution is exposed through the standard
 *      ERC-7821 minimal batch executor (`execute(bytes32 mode, bytes executionData)`) rather than
 *      bespoke per-flow selectors, so standard tooling (e.g. EIP-5792 `wallet_sendCalls`) can drive it.
 *
 *      Two ERC-7821 modes are supported, carrying three authorization flows:
 *      - `0x01000000000000000000…` (batch, no `opData`): authorized by `msg.sender`.
 *          - The delegated EOA itself (self-call) — the plain batching flow.
 *          - The canonical EntryPoint — the ERC-4337 flow. Coupling is
 *            implicit: `validateUserOp` only accepts userOps whose callData targets `execute`, and
 *            EntryPoint's protocol guarantees `validateUserOp` runs before the execution call.
 *      - `0x01000000000078210001…` (batch, with `opData`): msg.sender agnostic, signature-authorized
 *          — the relayed flow. `opData` is `abi.encode(uint256 deadline, bytes signature)`,
 *          where `signature` is the delegated EOA's EIP-712 signature over
 *          `Execute(bytes32 mode,Call[] calls,uint256 nonce,uint256 deadline)`; replay-protected via the
 *          Hermes nonce and time-bounded by the signed `deadline` (a signature dies when its nonce is
 *          consumed or its deadline passes; a `deadline` of 0 disables expiry). The payload is a
 *          fully-typed struct, so signing wallets render targets, values and calldata — no opaque hashes.
 *
 *      Both modes are also accepted with ERC-7579 exec type `0x01` ("try", `0x0101…`). In try mode
 *      the otherwise-unused mode payload (bytes [10:32]) carries a per-call outcome policy — 2 bits
 *      per call, call `i` at bits [2i+1:2i] counting from the least significant bit:
 *      - `00` OPTIONAL:         a failure emits `CallFailed` and the batch continues;
 *                               a zero payload is thus the uniform try batch (standard try semantics).
 *      - `01` REVERT_ON_FAIL:   a failure reverts the whole batch, as in the default exec type.
 *      - `10` BREAK_ON_FAIL:    a failure emits `CallFailed` and ends the batch early —
 *                               the remaining calls are skipped, the transaction still succeeds.
 *      - `11` BREAK_ON_SUCCESS: a success ends the batch early (remaining calls are skipped, the
 *                               transaction succeeds); a failure emits `CallFailed` and
 *                               the batch continues — "try fallbacks until one lands".
 *      A non-fatal failure emits `CallFailed(i)`; either early termination additionally emits
 *      `BatchInterrupted(i)`. A log consumer therefore sees which call failed and where the batch
 *      stopped, without decoding the policy bits out of `mode`. The packed
 *      policies are readable back through the pure `decodeCallPolicies` view, so an integration can
 *      round-trip its encoder against the contract instead of reimplementing the bit layout.
 *
 *      A policy governs what a call's outcome does to the rest of the batch, not whether that call
 *      is reached: a break triggered earlier skips everything after it, REVERT_ON_FAIL included,
 *      while the transaction still succeeds. A relayer that wants its fee to be unconditional puts
 *      it at index 0, or rejects batches where a break-capable call precedes it.
 *      Try batches are capped at 88 calls (176 payload bits / 2) so every call's policy is always
 *      expressible. The exec type and policies are part of `mode` and thus bound into the signed
 *      digest — a submitter can neither replay a signature under another exec type nor downgrade
 *      any call's policy.
 *
 *      Per ERC-7821, a `Call.target` of `address(0)` is executed against `address(this)`, and
 *      `_hashCalls` canonicalizes it the same way — the signer always signs the address the call
 *      runs against, and `address(0)` is only a calldata-size shorthand for a self-call.
 *
 *      State surface: immutable `delegateAddress` (implementation pin for EIP-712 salt) and
 *      immutable `manager` (singleton nonce source). No mutable storage.
 *
 * @custom:security-contact bugs@tonkeeper.com
 */
contract HermesDelegateV1 is HermesBase, IAccount, IERC1271, IERC7821, IERC5267 {

    /// @notice A single external call: `target.call{value: value}(data)`.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    /// @notice A try-mode call failed non-fatally: call `index` failed and its policy is not
    ///         REVERT_ON_FAIL, so the batch continued (OPTIONAL, BREAK_ON_SUCCESS) or stopped after it
    ///         (BREAK_ON_FAIL).
    /// @param index Index of the call that failed.
    event CallFailed(uint256 index);

    /// @notice A try-mode batch ended early: call `index` matched its break policy and the calls
    ///         after it were skipped. Emitted for both break policies — BREAK_ON_FAIL when call
    ///         `index` failed (right after its `CallFailed`) and BREAK_ON_SUCCESS when it
    ///         succeeded — so early termination is readable from logs alone, without decoding the
    ///         policy bits out of `mode`. `CallFailed` on its own does not imply termination: an
    ///         OPTIONAL failure emits it too and the batch continues.
    /// @param index Index of the call that ended the batch; calls `index + 1 …` did not run.
    event BatchInterrupted(uint256 index);

    /// @notice Caller is not the canonical EntryPoint.
    error OnlyEntryPoint();
    /// @notice Caller of an `opData`-less batch is neither the account itself nor the EntryPoint.
    error UnauthorizedExecutor();
    /// @notice ECDSA recovery failed or the signer is not the delegated EOA.
    error InvalidSignature();
    /// @notice Zero manager address passed to the constructor.
    error ZeroAddressManager();
    /// @notice `userOp.callData` does not start with the `execute` selector.
    error Invalid4337ExecutionSelector();
    /// @notice ERC-7821 execution mode is not a supported single-batch mode.
    error UnsupportedExecutionMode();
    /// @notice The signed batch's deadline has passed (`block.timestamp > deadline`).
    error ExpiredSignature();
    /// @notice A try-mode batch has more calls than the mode payload's 88 two-bit policy slots.
    error BatchTooLarge();

    /// @dev EIP-712 typehash of a single `Call` struct.
    bytes32 private constant CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
    /// @dev EIP-712 typehash of the signed batch payload (referenced `Call` type appended per spec).
    ///      `mode` is bound so a signature authorizes its calls only under the exact ERC-7821 mode it
    ///      was signed for — future-proofs against added exec types / batch-of-batches under opData.
    ///      `deadline` is bound so the signature self-expires; it is a unix timestamp the batch must be
    ///      mined at or before (`block.timestamp <= deadline`). A `deadline` of 0 disables expiry (the
    ///      EOA-like default), so expiry is strictly opt-in.
    bytes32 private constant EXECUTE_TYPEHASH = keccak256("Execute(bytes32 mode,Call[] calls,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)");
    /// @dev EIP-712 domain typehash; the `salt` field carries the implementation address (see `_domainSeparator`).
    bytes32 private constant HERMES_DOMAIN_SEPARATOR_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    /// @dev EIP-712 domain `name` field, pre-hashed. The preimage "Hermes" is what `eip712Domain()` reports.
    bytes32 private constant HERMES_NAME_HASH = keccak256("Hermes");
    /// @dev EIP-712 domain `version` field, pre-hashed. The preimage "v1.0.0" is what `eip712Domain()` reports.
    bytes32 private constant VERSION_HASH = keccak256("v1.0.0");
    /// @dev ERC-1271 magic value for a valid signature.
    bytes4 internal constant ERC1271_SUCCESS = IERC1271.isValidSignature.selector;
    /// @dev ERC-1271 return value for an invalid signature.
    bytes4 internal constant ERC1271_FAILURE = 0xffffffff;
    /// @dev ERC-7739 support-detection probe hash: `isValidSignature(0x7739…7739, "")` — this
    ///      constant as the `hash` argument, with an empty signature — returns the magic below.
    bytes32 private constant ERC7739_SUPPORT_HASH = 0x7739773977397739773977397739773977397739773977397739773977397739;
    /// @dev ERC-7739 support-detection magic value returned for the probe.
    bytes4 private constant ERC7739_SUPPORT_MAGIC = 0x77390001;

    /// @dev Trusted canonical ERC-4337 EntryPoints. Both produce an EIP-712 typed `userOpHash`
    ///      with the EntryPoint's own address as the EIP-712 `verifyingContract`, so a signature for
    ///      one EntryPoint never validates at the other — there is no cross-EntryPoint replay even
    ///      though their nonce stores are independent.
    address private constant ENTRY_POINT_V8 = 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108;
    address private constant ENTRY_POINT_V9 = 0x433709009B8330FDa32311DF1C2AFA402eD8D009;

    // ─── ERC-7821 mode ───
    /// @dev ERC-7821 mode selector of the batch mode without `opData` (`executionData` is
    ///      `abi.encode(Call[])`), authorized by `msg.sender`.
    ModeSelector private constant MODE_SELECTOR_NO_OPDATA = ModeSelector.wrap(0x00000000);
    /// @dev ERC-7821 mode selector of the batch mode with `opData` (`executionData` is
    ///      `abi.encode(Call[], bytes opData)`), authorized by the delegated EOA's EIP-712 signature.
    ModeSelector private constant MODE_SELECTOR_OPDATA = ModeSelector.wrap(0x78210001);

    /// @dev `_decodeExecutionMode` classification; `Unsupported` first so the zero value fails closed.
    enum ModeId {
        Unsupported,
        Batch,
        BatchOpData
    }

    /// @dev Bit width of the ERC-7821 mode payload (`bytes22`, mode bytes [10:32]).
    uint256 private constant MODE_PAYLOAD_BITS = 176;
    /// @dev Maximum batch size in try mode — the mode payload carries one `POLICY_BITS`-wide
    ///      policy per call, so 88 slots keep every call's policy always expressible.
    uint256 private constant MAX_TRY_CALLS = MODE_PAYLOAD_BITS / POLICY_BITS;

    // ─── Per-call try-mode policies (2 bits each; call `i` at bits [2i+1:2i] of the payload) ───
    /// @dev Bit width of one per-call policy slot inside the packed policies word.
    uint256 private constant POLICY_BITS = 2;
    /// @dev Mask selecting a single `POLICY_BITS`-wide policy slot (`0b11`).
    uint256 private constant POLICY_MASK = 3;
    /// @dev `00`: a failure is logged via `CallFailed` and the batch continues.
    uint256 private constant POLICY_OPTIONAL = 0x0;
    /// @dev `01`: a failure reverts the whole batch, as in the default exec type.
    uint256 private constant POLICY_REVERT_ON_FAIL = 0x1;
    /// @dev `10`: a failure is logged and ends the batch early; the transaction still succeeds.
    uint256 private constant POLICY_BREAK_ON_FAIL = 0x2;
    /// @dev `11`: a success ends the batch early; a failure is logged and the batch continues.
    uint256 private constant POLICY_BREAK_ON_SUCCESS = 0x3;

    /// @notice Singleton nonce source shared by all Hermes accounts; replay protection for the signed batch path.
    IHermesNonce public immutable manager;
    /// @dev This implementation's address, used as the EIP-712 domain salt (see `_domainSeparator`).
    bytes32 private immutable delegateAddress;

    /// @param _manager Singleton nonce contract; fixed for the lifetime of this implementation.
    constructor(IHermesNonce _manager) {
        if (address(_manager) == address(0)) {
            revert ZeroAddressManager();
        }

        manager = _manager;
        delegateAddress = bytes32(uint256(uint160(address(this))));
    }

    /// @dev Restricts a function to the two trusted canonical EntryPoints (v0.8 and v0.9); any
    ///      other caller reverts with `OnlyEntryPoint`.
    modifier onlyEntryPoint() {
        if (!_isEntryPoint(msg.sender)) {
            revert OnlyEntryPoint();
        }
        _;
    }

    /// @notice True iff `account` is one of the trusted EntryPoints (v0.8 or v0.9).
    /// @dev EntryPoint discovery surface for SDKs and indexers: probe an address rather than read a
    ///      single `entryPoint()` getter, since this account trusts two EntryPoints, not one.
    /// @param account The address to probe.
    /// @return True iff `account` is the v0.8 or the v0.9 canonical EntryPoint.
    function isSupportedEntryPoint(address account) external pure returns (bool) {
        return _isEntryPoint(account);
    }

    function _isEntryPoint(address account) private pure returns (bool) {
        return account == ENTRY_POINT_V8 || account == ENTRY_POINT_V9;
    }

    /// @notice ERC-7779 account identifier: vendor, account type and version.
    /// @return The identifier of this implementation, `"Hermes.Delegate.v1.0.0"`.
    function accountId() external pure override returns (string memory) {
        return "Hermes.Delegate.v1.0.0";
    }

    /// @notice ERC-165: extends HermesBase with the interfaces this delegate adds — ERC-4337
    ///         `IAccount`, the ERC-7821 batch executor and ERC-5267 domain introspection.
    /// @dev ERC-7821 is canonically probed via `supportsExecutionMode`; this is the complementary
    ///      ERC-165 advertisement.
    /// @param interfaceId The ERC-165 interface identifier to probe.
    /// @return True iff `interfaceId` is implemented by this account, here or in `HermesBase`.
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return interfaceId == type(IAccount).interfaceId
            || interfaceId == type(IERC7821).interfaceId
            || interfaceId == type(IERC5267).interfaceId
            || super.supportsInterface(interfaceId);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-4337: validate (called by EntryPoint v0.8/v0.9)
    // ─────────────────────────────────────────────────────────────────────────
    /// @notice ERC-4337 validation hook: checks the delegated EOA's signature over `userOpHash`
    ///         and pre-funds the EntryPoint with `missingAccountFunds`.
    /// @dev Only userOps whose callData targets `execute` are accepted, so a validated op can never be
    ///      coupled with an arbitrary execution path. Per ERC-4337 a bad signature returns 1
    ///      (SIG_VALIDATION_FAILED) instead of reverting.
    ///
    ///      The signature covers the bare `userOpHash`, which does not commit to the code at the
    ///      account's address, so a withheld userOp survives re-delegation and is retired only by
    ///      consuming its EntryPoint nonce.
    /// @param userOp The user operation being validated; only `callData` (selector check) and
    ///        `signature` are read.
    /// @param userOpHash The EntryPoint's EIP-712 typed hash of `userOp`, signed by the EOA as-is.
    /// @param missingAccountFunds Deposit shortfall to pre-fund; forwarded to the caller and not
    ///        checked, since the EntryPoint checks its own balance.
    /// @return validationData 0 for the delegated EOA's signature, 1 (SIG_VALIDATION_FAILED) otherwise.
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        override
        onlyEntryPoint
        returns (uint256 validationData)
    {
        if (bytes4(userOp.callData[:4]) != IERC7821.execute.selector) {
            revert Invalid4337ExecutionSelector();
        }

        // EntryPoint v0.8+ returns an EIP-712 typed-data hash that binds its own address (the EIP-712
        // verifyingContract); we sign over it directly, and that binding also prevents a signature
        // validated under one EntryPoint from being replayed through the other.
        bool isValid = _validateSignature(userOpHash, userOp.signature);
        validationData = isValid ? 0 : 1;

        // Pre-fund the EntryPoint; result deliberately ignored — EntryPoint checks its own balance.
        assembly {
            if missingAccountFunds { pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0)) }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-7821: minimal batch executor (single entry point for all execution)
    // ─────────────────────────────────────────────────────────────────────────
    /// @notice Executes a batch encoded per ERC-7821. `mode` selects the authorization scheme:
    ///         - no `opData`  : authorized by `msg.sender` (the account itself, or the EntryPoint
    ///                          after a validated userOp).
    ///         - with `opData`: msg.sender agnostic; `opData` is `abi.encode(uint256 deadline, bytes
    ///                          signature)`, the signature being the delegated EOA's EIP-712 signature
    ///                          over `Execute(bytes32 mode,Call[] calls,uint256 nonce,uint256 deadline)`,
    ///                          replay-protected by the Hermes nonce and rejected once `block.timestamp`
    ///                          passes `deadline`. The nonce is consumed before any of the batch's
    ///                          calls, so the signature cannot be replayed by reentering from a target. A signed
    ///                          batch consumes *at least* one nonce: the manager keys nonces by
    ///                          `msg.sender`, which under EIP-7702 is the account here and for a call
    ///                          inside the batch alike, so a batch that itself calls `useNonce`
    ///                          advances the counter again. Read `nonceOf(account)` rather than
    ///                          tracking it incrementally.
    ///         Both modes accept exec type `0x00` (atomic: revert and bubble up on the first failing
    ///         call) and `0x01` ("try": each call's outcome is governed by its 2-bit policy in the
    ///         mode payload, described in the contract docstring). The exec type and the policies are
    ///         part of `mode` and therefore bound into the signed digest.
    /// @param mode ERC-7821 execution mode; only the two single-batch modes are supported.
    /// @param executionData `abi.encode(Call[] calls)` for the no-`opData` mode, or
    ///        `abi.encode(Call[] calls, bytes opData)` for the `opData` mode, where `opData` is itself
    ///        `abi.encode(uint256 deadline, bytes signature)`.
    function execute(bytes32 mode, bytes calldata executionData) external payable override {
        (ModeId id, bool tryExec, uint176 payload) = _decodeExecutionMode(mode);
        if (id == ModeId.Unsupported) {
            revert UnsupportedExecutionMode();
        }

        // The payload is the packed per-call policies; it is meaningful only in try mode — in the
        // default exec type `_executeBatch` takes the classic atomic path and never consults it.
        if (id == ModeId.Batch) {
            // Batch without opData: the caller authorizes itself.
            if (msg.sender != address(this) && !_isEntryPoint(msg.sender)) {
                revert UnauthorizedExecutor();
            }

            _executeBatch(abi.decode(executionData, (Call[])), tryExec, payload);
        } else {
            // Batch with opData: authorized by the delegated EOA's EIP-712 signature.
            (Call[] memory calls, bytes memory opData) = abi.decode(executionData, (Call[], bytes));
            _verifySignedBatch(mode, calls, opData);
            _executeBatch(calls, tryExec, payload);
        }
    }

    /// @dev Authorizes a signed (opData) batch: deadline check, then nonce consumption, then the
    ///      EIP-712 signature check. `opData` is `abi.encode(uint256 deadline, bytes signature)`.
    ///      `mode` and `deadline` are bound into the digest, so the signature validates only under
    ///      the exact mode it was signed for and a relayer cannot extend its lifetime; `deadline == 0`
    ///      means "no expiry". The nonce is consumed before any of the batch's calls — the
    ///      `manager.useNonce()` call is the only external call that precedes them — so the signature
    ///      cannot be replayed by reentering from a target.
    ///
    ///      Nonce consumption and the batch share one transaction, so the nonce is spent whenever the
    ///      transaction does not revert — a batch ended early by a break policy spends it too, while a
    ///      reverting one leaves the nonce and the signature valid. This is where the EOA analogy
    ///      stops: a mined EOA transaction spends its nonce either way. A batch that failed on a
    ///      transient condition therefore stays executable once that condition clears, indefinitely at
    ///      `deadline` 0 — sign a short, non-zero `deadline`, or retire the signature with
    ///      `manager.useNonce()`.
    function _verifySignedBatch(bytes32 mode, Call[] memory calls, bytes memory opData) private {
        (uint256 deadline, bytes memory signature) = abi.decode(opData, (uint256, bytes));

        if (deadline != 0 && block.timestamp > deadline) {
            revert ExpiredSignature();
        }

        bytes32 structHash =
            keccak256(abi.encode(EXECUTE_TYPEHASH, mode, _hashCalls(calls), manager.useNonce(), deadline));

        if (!_validateSignature(MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash), signature)) {
            revert InvalidSignature();
        }
    }

    /// @notice ERC-7821 support probe for frontends. True only for the two supported single-batch
    ///         modes, each in the default (`0x00`) and try (`0x01`) exec types.
    /// @param mode The ERC-7821 execution mode to probe.
    /// @return True iff `execute` accepts `mode`. The payload is ignored: every value is valid.
    function supportsExecutionMode(bytes32 mode) external pure override returns (bool) {
        (ModeId id, , ) = _decodeExecutionMode(mode);
        return id != ModeId.Unsupported;
    }

    /// @notice Unpacks the per-call try-mode policies packed into `mode`'s payload, so an integrator
    ///         can round-trip its own encoder against the contract before asking a user to sign.
    /// @dev Mirrors what `_executeBatch` reads: call `i`'s 2-bit policy sits at bits [2i+1:2i] of the
    ///      mode payload, least-significant-bit first. Reports rejection through `isValid` instead of
    ///      reverting, so decoding a mode never has to be wrapped in a try/catch. The payload is only
    ///      consulted under the try exec type; under the default one the first failing call reverts
    ///      the batch whatever these bits say.
    /// @param mode ERC-7821 execution mode whose payload to unpack.
    /// @param callCount Number of calls in the batch this `mode` is meant to execute.
    /// @return isValid Whether `execute` accepts this pair: a supported single-batch mode, and — in
    ///         try mode — a batch that fits the payload's `MAX_TRY_CALLS` policy slots.
    /// @return policies Policy governing each call: `policies[i]` is 0 OPTIONAL, 1 REVERT_ON_FAIL,
    ///         2 BREAK_ON_FAIL or 3 BREAK_ON_SUCCESS. Slots the encoder never set read as OPTIONAL,
    ///         which is why an under-specified encoding is well-formed on-chain and shows up only by
    ///         comparing this output against the intended policies.
    function decodeCallPolicies(bytes32 mode, uint256 callCount)
        external
        pure
        returns (bool isValid, uint8[] memory policies)
    {
        (ModeId id, bool tryExec, uint176 payload) = _decodeExecutionMode(mode);

        isValid = id != ModeId.Unsupported && (!tryExec || callCount <= MAX_TRY_CALLS);
        policies = new uint8[](callCount);

        for (uint256 i; i < callCount; ++i) {
            policies[i] = uint8((uint256(payload) >> (POLICY_BITS * i)) & POLICY_MASK);
        }
    }

    /// @dev Decodes an ERC-7821 `mode` via `ERC7579Utils.decodeMode` and classifies it against the
    ///      supported single-batch modes. The payload is ignored for classification and returned
    ///      raw — in try mode it carries the packed per-call policies (see `execute`).
    /// @return The mode's classification: `Batch` (no opData), `BatchOpData` (with opData), or
    ///         `Unsupported` (fails closed).
    /// @return True for exec type `0x01` (continue past failing calls), false for `0x00`.
    /// @return The mode payload (bytes [10:32]) as an integer.
    function _decodeExecutionMode(bytes32 mode) private pure returns (ModeId, bool, uint176) {
        (CallType callType, ExecType execType, ModeSelector modeSelector, ModePayload modePayload) =
            ERC7579Utils.decodeMode(Mode.wrap(mode));

        if (!(callType == ERC7579Utils.CALLTYPE_BATCH)) {
            return (ModeId.Unsupported, false, 0);
        }

        bool defaultExec = execType == ERC7579Utils.EXECTYPE_DEFAULT;
        bool tryExec = execType == ERC7579Utils.EXECTYPE_TRY;

        if (!defaultExec && !tryExec) {
            return (ModeId.Unsupported, false, 0);
        }

        uint176 payload = uint176(ModePayload.unwrap(modePayload));

        if (modeSelector == MODE_SELECTOR_NO_OPDATA) {
            return (ModeId.Batch, tryExec, payload);
        }

        if (modeSelector == MODE_SELECTOR_OPDATA) {
            return (ModeId.BatchOpData, tryExec, payload);
        }

        return (ModeId.Unsupported, false, 0);
    }

    /// @dev Executes each call in order. With `tryExec` false — the classic atomic batch — the
    ///      first failure reverts and bubbles up the callee's raw revert data; `policies` is never
    ///      consulted. With `tryExec` true, call `i`'s 2-bit policy (bits [2i+1:2i] of `policies`)
    ///      decides what its outcome does — the four policies are described in the contract
    ///      docstring. Both early terminations emit `BatchInterrupted(i)` at the single break site.
    ///      A policy is only consulted for a call that is reached: a break earlier in the batch skips
    ///      every later call, whatever its policy. Try batches are capped at `MAX_TRY_CALLS` so every
    ///      call has a policy slot; the default exec type has no cap.
    ///      Per ERC-7821, a `Call.target` of `address(0)` is executed against this account; on the
    ///      signed path `_hashCalls` canonicalizes it identically, so the signed and the executed
    ///      target are always the same address.
    ///
    ///      A non-fatal failure is recorded as `CallFailed(i)`: the log says that call `i` failed and
    ///      which one it was, and the reason is investigated off-chain from the transaction itself.
    ///      A fatal failure still bubbles the callee's raw revert data.
    function _executeBatch(Call[] memory calls, bool tryExec, uint256 policies) private {
        uint256 length = calls.length;
        if (tryExec && length > MAX_TRY_CALLS) {
            revert BatchTooLarge();
        }

        for (uint256 i; i < length; ++i) {
            address target = calls[i].target == address(0) ? address(this) : calls[i].target;
            bool success = _call(target, calls[i].value, calls[i].data);

            // Classic atomic batch: the first failure reverts everything; `policies` plays no role.
            if (!tryExec) {
                if (!success) {
                    _bubbleRevert();
                }
                continue;
            }

            uint256 policy = (policies >> (POLICY_BITS * i)) & POLICY_MASK;

            if (!success) {
                if (policy == POLICY_REVERT_ON_FAIL) {
                    _bubbleRevert();
                }

                emit CallFailed(i);
            }

            if (policy == (success ? POLICY_BREAK_ON_SUCCESS : POLICY_BREAK_ON_FAIL)) {
                emit BatchInterrupted(i);
                break;
            }
        }
    }

    /// @dev Calls `target` with `value` and `data`, discarding whatever it returns. Unlike
    ///      `target.call(...)`, which copies all of the return data before the outcome is even
    ///      inspected, this copies none of it — only `_bubbleRevert` reads the return buffer, and
    ///      only when a call fails fatally.
    function _call(address target, uint256 value, bytes memory data) private returns (bool success) {
        assembly ("memory-safe") {
            success := call(gas(), target, value, add(data, 0x20), mload(data), 0x00, 0x00)
        }
    }

    /// @dev Reverts with the failing callee's raw revert data (bubbles an inner revert).
    function _bubbleRevert() private pure {
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            returndatacopy(ptr, 0x00, returndatasize())
            revert(ptr, returndatasize())
        }
    }

    /// @dev EIP-712 encoding of `Call[]`: keccak256 of the concatenated hashStructs of the elements.
    ///      A `target` of `address(0)` is canonicalized to `address(this)` before hashing, exactly as
    ///      `_executeBatch` rewrites it before calling, so a self-call has one signable form — its
    ///      real address — and the zero form is a calldata-size shorthand a submitter may substitute
    ///      without changing the digest.
    function _hashCalls(Call[] memory calls) private view returns (bytes32) {
        uint256 length = calls.length;
        bytes32[] memory callHashes = new bytes32[](length);
        for (uint256 i; i < length; ++i) {
            address target = calls[i].target == address(0) ? address(this) : calls[i].target;
            callHashes[i] = keccak256(abi.encode(CALL_TYPEHASH, target, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(callHashes));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ERC-1271: signature validation
    // ─────────────────────────────────────────────────────────────────────────
    /// @notice ERC-1271 / ERC-7739 signature check. Valid iff `signature` is the delegated EOA's
    ///         signature under ERC-7739 defensive rehashing: the request is nested under this account's
    ///         EIP-712 domain (including the impl-pinning `salt`), preventing cross-account and
    ///         cross-domain replay while keeping the signed content readable. Accepts the two ERC-7739
    ///         nested forms — `TypedDataSign` (EIP-712 typed data) and `PersonalSign` (an EIP-191 mimic)
    ///         — or, as a fallback, a plain ECDSA signature over `hash` itself.
    /// @dev The account domain is `_domainSeparator()` — the same domain the opData path uses and
    ///      ERC-5267 `eip712Domain()` reports, so every signing surface stays on one domain.
    ///      Returns the ERC-7739 detection magic for the empty-signature probe.
    ///
    ///      The raw fallback is checked last, so an ERC-7739-aware wallet keeps the nested,
    ///      domain-bound path unchanged. It exists because verifiers route an account with code into
    ///      ERC-1271 by `code.length`, so after delegation every signature the key produces lands
    ///      here, including from wallets that do not implement ERC-7739. Its trade-off is that a raw
    ///      signature carries no domain: it is replayable at any verifier asking this account about
    ///      the same `hash`, though recovery to `address(this)` keeps it bound to this account.
    /// @param hash The digest the verifier wants checked, or `0x7739…7739` for the ERC-7739 probe.
    /// @param signature One of the two ERC-7739 nested encodings, a raw ECDSA signature over `hash`
    ///        (65-byte or EIP-2098 compact), or empty for the probe.
    /// @return `0x1626ba7e` (ERC-1271 magic) if the signature is valid, `0x77390001` for the
    ///         ERC-7739 detection probe, and `0xffffffff` otherwise.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view override returns (bytes4) {
        if (_isValidTypedDataSig(hash, signature) || _isValidPersonalSig(hash, signature)) {
            return ERC1271_SUCCESS;
        }

        if (hash == ERC7739_SUPPORT_HASH && signature.length == 0) {
            return ERC7739_SUPPORT_MAGIC;
        }

        if (_validateSignature(hash, signature)) {
            return ERC1271_SUCCESS;
        }

        return ERC1271_FAILURE;
    }

    /// @dev ERC-7739 `TypedDataSign` path: the app's `contents` digest re-nested under the app's domain,
    ///      with this account's domain bound into the struct. Mirrors OpenZeppelin `ERC7739`.
    function _isValidTypedDataSig(bytes32 hash, bytes calldata encodedSignature) private view returns (bool) {
        (bytes calldata signature, bytes32 appSeparator, bytes32 contentsHash, string calldata contentsDescr) =
            ERC7739Utils.decodeTypedDataSig(encodedSignature);

        return bytes(contentsDescr).length != 0
            && hash == MessageHashUtils.toTypedDataHash(appSeparator, contentsHash)
            && _validateSignature(
                MessageHashUtils.toTypedDataHash(
                    appSeparator,
                    ERC7739Utils.typedDataSignStructHash(
                        contentsDescr,
                        contentsHash,
                        abi.encode(HERMES_NAME_HASH, VERSION_HASH, block.chainid, address(this), delegateAddress)
                    )
                ),
                signature
            );
    }

    /// @dev ERC-7739 `PersonalSign` path: an EIP-191 message nested under this account's EIP-712 domain.
    function _isValidPersonalSig(bytes32 hash, bytes calldata signature) private view returns (bool) {
        return _validateSignature(
            MessageHashUtils.toTypedDataHash(_domainSeparator(), ERC7739Utils.personalSignStructHash(hash)),
            signature
        );
    }

    /// @dev True iff `signature` is a valid ECDSA signature over `hash` by the delegated EOA
    ///      (address(this) under EIP-7702). Never reverts on malformed input.
    ///
    ///      `ECDSA.parse` accepts both the 65-byte `(r, s, v)` and the 64-byte `(r, vs)` EIP-2098
    ///      encodings, so a compact signature validates on every signing surface. Any other length
    ///      parses to `(0, 0, 0)`, recovery fails and this returns false — malformed input is
    ///      fail-closed.
    function _validateSignature(bytes32 hash, bytes memory signature) private view returns (bool isValid) {
        (uint8 v, bytes32 r, bytes32 s) = ECDSA.parse(signature);
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, v, r, s);
        isValid = (err == ECDSA.RecoverError.NoError && recovered == address(this));
    }

    /// @dev `delegateAddress` pins the signature to the implementation address, so an outstanding
    ///      signature stops validating while the account is delegated to other code, and validates
    ///      again once it is delegated back: the salt is checked against the delegation in effect at
    ///      execution time, and the nonce survives re-delegation. Re-delegation is a suspension; the
    ///      permanent cancellations are spending the nonce and letting `deadline` pass.
    function _domainSeparator() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                HERMES_DOMAIN_SEPARATOR_HASH,
                HERMES_NAME_HASH,
                VERSION_HASH,
                block.chainid,
                address(this),
                delegateAddress
            )
        );
    }

    /// @notice ERC-5267: exposes this account's EIP-712 domain so off-chain signers and tooling can
    ///         reconstruct it. `salt` = the implementation address, which
    ///         pins signatures to this delegate version. Mirrors `_domainSeparator` exactly; the
    ///         returned `name`/`version` are the preimages of `HERMES_NAME_HASH`/`VERSION_HASH`.
    /// @dev `fields = 0x1f` (11111): name, version, chainId, verifyingContract and salt are all present;
    ///      no `extensions`.
    /// @return fields Bitmap of the populated domain fields, always `0x1f`.
    /// @return name Domain `name`, always `"Hermes"` (preimage of `HERMES_NAME_HASH`).
    /// @return version Domain `version`, always `"v1.0.0"` (preimage of `VERSION_HASH`).
    /// @return chainId The chain this account signs for (`block.chainid`).
    /// @return verifyingContract The account itself (`address(this)`), i.e. the delegated EOA.
    /// @return salt The implementation address, pinning signatures to this delegate version.
    /// @return extensions Always empty; this domain declares no ERC-5267 extensions.
    function eip712Domain()
        external
        view
        override
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        fields = hex"1f";
        name = "Hermes";
        version = "v1.0.0";
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = delegateAddress;
        extensions = new uint256[](0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utility
    // ─────────────────────────────────────────────────────────────────────────
    /// @notice Accepts plain native-value transfers with empty calldata, preserving EOA-like behavior.
    receive() external payable {}

    /// @dev Accepts calls with unknown selectors (e.g. token callbacks not modeled in HermesBase)
    ///      without reverting, preserving EOA-like behavior.
    fallback() external payable {}
}
