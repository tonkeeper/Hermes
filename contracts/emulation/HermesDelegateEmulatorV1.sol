// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC7821} from "@openzeppelin/contracts/interfaces/draft-IERC7821.sol";
import {ERC7579Utils, Mode, CallType, ExecType, ModeSelector, ModePayload} from "@openzeppelin/contracts/account/utils/draft-ERC7579Utils.sol";
import {IHermesNonce} from "../interfaces/IHermesNonce.sol";

/**
 * @title HermesDelegateEmulatorV1 - Gas-emulation twin of HermesDelegateV1. NEVER DEPLOY.
 * @author anchupin
 * @dev Injected by the relay server via `eth_estimateGas` state overrides in place of the real
 *      delegate at the user's EOA, so a signed batch can be emulated *without* the user's key:
 *
 *      - `_validateSignature` runs the exact same ECDSA recovery as the real delegate (so signature
 *        verification is fully included in the gas estimate), but accepts any well-formed signature
 *        (`recovered != address(0)`) instead of requiring `recovered == address(this)`. The relay
 *        signs the digest with a throwaway key.
 *      - `manager` is a constant at the virtual address `0x…7702`; the server overrides that address
 *        with `HermesNonceEmulatorV1` code in the same call, mirroring the real manager's gas
 *        (cold external call + nonce SSTORE).
 *      - `delegateAddress` (the EIP-712 domain salt) is a constant zero — the digest isn't checked
 *        against a fixed signer, and hashing gas is identical.
 *
 *      Everything else — mode decoding, deadline check, nonce consumption, the mustSјucceed mask and
 *      batch execution — is copied verbatim from HermesDelegateV1 so the estimate tracks the real
 *      execution path. The ERC-4337/1271/7739 surfaces are omitted: they are not part of the
 *      relayed `execute` flow being emulated.
 */
contract HermesDelegateEmulatorV1 {

    /// @notice A single external call: `target.call{value: value}(data)`.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    error InvalidSignature();
    error UnsupportedExecutionMode();
    error ExpiredSignature();
    error BatchTooLarge();

    bytes32 private constant CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
    bytes32 private constant EXECUTE_TYPEHASH = keccak256("Execute(bytes32 mode,Call[] calls,uint256 nonce,uint256 deadline)Call(address target,uint256 value,bytes data)");
    bytes32 private constant HERMES_DOMAIN_SEPARATOR_HASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant HERMES_NAME_HASH = keccak256("Hermes");
    bytes32 private constant VERSION_HASH = keccak256("v1.0.0");

    // ─── ERC-7821 mode ───
    ModeSelector private constant MODE_SELECTOR_NO_OPDATA = ModeSelector.wrap(0x00000000);
    ModeSelector private constant MODE_SELECTOR_OPDATA = ModeSelector.wrap(0x78210001);

    enum ModeId {
        Unsupported,
        Batch,
        BatchOpData
    }

    /// @dev Mirror of HermesDelegateV1: 88 two-bit policy slots in the 176-bit payload.
    uint256 private constant MAX_TRY_CALLS = 88;

    // ─── Per-call try-mode policies (2 bits each; call `i` at bits [2i+1:2i]) ───
    uint256 private constant POLICY_OPTIONAL = 0x0;        // failure logged, batch continues
    uint256 private constant POLICY_REQUIRED = 0x1;        // failure reverts the whole batch
    uint256 private constant POLICY_BREAK_ON_FAIL = 0x2;   // failure logged, batch ends early
    uint256 private constant POLICY_BREAK_ON_SUCCESS = 0x3;// success ends batch early; failure continues

    /// @notice Virtual manager address; the server state-overrides it with HermesNonceEmulatorV1 code.
    IHermesNonce public constant manager = IHermesNonce(0x0000000000000000000000000000000000007702);
    /// @dev Stands in for the real delegate's implementation-address salt; zero like an unset immutable.
    bytes32 private constant delegateAddress = bytes32(0);

    /// @notice Mirror of HermesDelegateV1.execute (both authorization branches). The payload carries
    ///         the packed per-call policies, meaningful only in try mode.
    function execute(bytes32 mode, bytes calldata executionData) external payable {
        (ModeId id, bool tryExec, uint176 payload) = _decodeExecutionMode(mode);
        if (id == ModeId.Unsupported) {
            revert UnsupportedExecutionMode();
        }

        if (id == ModeId.Batch) {
            // Emulation relaxation: the real delegate requires msg.sender == address(this) (the relay
            // self-call for the gasless proxy). Relaxed so the gas meter (a different caller) can
            // drive the same no-opData path during eth_call emulation; the gas is identical.
            _executeBatch(abi.decode(executionData, (Call[])), tryExec, payload);
        } else {
            (Call[] memory calls, bytes memory opData) = abi.decode(executionData, (Call[], bytes));
            _verifySignedBatch(mode, calls, opData);
            _executeBatch(calls, tryExec, payload);
        }
    }

    /// @dev Verbatim copy of HermesDelegateV1._verifySignedBatch.
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

    /// @dev Verbatim copy of HermesDelegateV1._decodeExecutionMode.
    function _decodeExecutionMode(bytes32 mode) private pure returns (ModeId id, bool tryExec, uint176 payload) {
        (CallType callType, ExecType execType, ModeSelector modeSelector, ModePayload modePayload) =
            ERC7579Utils.decodeMode(Mode.wrap(mode));

        if (!(callType == ERC7579Utils.CALLTYPE_BATCH)) {
            return (ModeId.Unsupported, false, 0);
        }

        bool defaultExec = execType == ERC7579Utils.EXECTYPE_DEFAULT;
        tryExec = execType == ERC7579Utils.EXECTYPE_TRY;

        if (!defaultExec && !tryExec) {
            return (ModeId.Unsupported, false, 0);
        }

        payload = uint176(ModePayload.unwrap(modePayload));

        if (modeSelector == MODE_SELECTOR_NO_OPDATA) {
            return (ModeId.Batch, tryExec, payload);
        }

        if (modeSelector == MODE_SELECTOR_OPDATA) {
            return (ModeId.BatchOpData, tryExec, payload);
        }

        return (ModeId.Unsupported, false, 0);
    }

    /// @dev Mirror of HermesDelegateV1._executeBatch — 2-bit per-call policies in try mode.
    function _executeBatch(Call[] memory calls, bool tryExec, uint256 policies) private {
        uint256 length = calls.length;
        if (tryExec && length > MAX_TRY_CALLS) {
            revert BatchTooLarge();
        }

        for (uint256 i; i < length; ++i) {
            address target = calls[i].target == address(0) ? address(this) : calls[i].target;
            (bool success, bytes memory result) = target.call{value: calls[i].value}(calls[i].data);

            if (!tryExec) {
                if (!success) {
                    _bubbleRevert(result);
                }
                continue;
            }

            uint256 policy = (policies >> (2 * i)) & 3;

            if (success) {
                if (policy == POLICY_BREAK_ON_SUCCESS) {
                    break;
                }
            } else {
                if (policy == POLICY_REQUIRED) {
                    _bubbleRevert(result);
                }

                emit ERC7579Utils.ERC7579TryExecuteFail(i, result);

                if (policy == POLICY_BREAK_ON_FAIL) {
                    break;
                }
            }
        }
    }

    /// @dev Reverts with `result` as the raw revert data (bubbles an inner revert).
    function _bubbleRevert(bytes memory result) private pure {
        assembly {
            revert(add(result, 32), mload(result))
        }
    }

    /// @dev Verbatim copy of HermesDelegateV1._hashCalls.
    function _hashCalls(Call[] memory calls) private pure returns (bytes32) {
        uint256 length = calls.length;
        bytes32[] memory callHashes = new bytes32[](length);
        for (uint256 i; i < length; ++i) {
            callHashes[i] = keccak256(abi.encode(CALL_TYPEHASH, calls[i].target, calls[i].value, keccak256(calls[i].data)));
        }
        return keccak256(abi.encodePacked(callHashes));
    }

    /// @dev THE emulation tweak: full ECDSA recovery runs (same gas as the real delegate), but any
    ///      well-formed signature passes — `recovered != address(0)` instead of `== address(this)`.
    function _validateSignature(bytes32 hash, bytes memory signature) private view returns (bool isValid) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(hash, signature);
        isValid = (err == ECDSA.RecoverError.NoError && recovered != address(0));
    }

    /// @dev Verbatim copy of HermesDelegateV1._domainSeparator (salt is the zero constant above).
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

    receive() external payable {}

    fallback() external payable {}
}
