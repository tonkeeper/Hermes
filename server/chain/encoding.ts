/**
 * HermesDelegateV1 encoding helpers: ERC-7821 modes, EIP-712 typed data for the signed (opData)
 * batch path, calldata builders and the emulation-artifact loader. Mirrors the constants in
 * contracts/v1/HermesDelegateV1.sol and the encoders used by test/HermesDelegateV1.test.ts.
 */

import * as fs from "fs";
import * as path from "path";
import { AbiCoder, Interface, TypedDataEncoder, ZeroAddress, zeroPadValue } from "ethers";

export interface Call {
    target: string;
    value: bigint;
    data: string;
}

// EIP-712 types of the signed batch — exactly what a wallet receives via eth_signTypedData_v4.
export const EXECUTE_TYPES = {
    Call: [
        { name: "target", type: "address" },
        { name: "value", type: "uint256" },
        { name: "data", type: "bytes" },
    ],
    Execute: [
        { name: "mode", type: "bytes32" },
        { name: "calls", type: "Call[]" },
        { name: "nonce", type: "uint256" },
        { name: "deadline", type: "uint256" },
    ],
} as const;

/** Constant manager address inside HermesDelegateEmulatorV1; state-overridden during emulation. */
export const VIRTUAL_NONCE_MANAGER = "0x0000000000000000000000000000000000007702";
/** Virtual address the gas meter is injected at during emulation (never deployed). */
export const VIRTUAL_GAS_METER = "0x0000000000000000000000000000000000007703";

const abi = AbiCoder.defaultAbiCoder();
const CALLS_TYPE = "tuple(address target,uint256 value,bytes data)[]";

export const EXECUTE_IFACE = new Interface([
    "function execute(bytes32 mode, bytes executionData) payable",
]);
export const ERC20_IFACE = new Interface([
    "function transfer(address to, uint256 amount) returns (bool)",
    "function balanceOf(address owner) view returns (uint256)",
]);
export const NONCE_IFACE = new Interface([
    "function nonceOf(address account) view returns (uint256)",
]);
export const GAS_METER_IFACE = new Interface([
    "function measure(address target, bytes data) returns (uint256 gasUsed, bool success, bytes result)",
]);

// ─────────────────────────────────────────────────────────────────────────
// ERC-7821 mode: [0] callType | [1] execType | [2:6] unused | [6:10] selector | [10:32] payload
// In try mode the payload packs a 2-bit per-call outcome policy (call i at bits [2i+1:2i]).
// ─────────────────────────────────────────────────────────────────────────
const OPDATA_SELECTOR = "78210001";

/** Per-call try-mode outcome policy — mirrors HermesDelegateV1's POLICY_* constants. */
export enum CallPolicy {
    /** `00`: failure logged (ERC7579TryExecuteFail), batch continues. */
    Optional = 0,
    /** `01`: failure reverts the whole batch. */
    Required = 1,
    /** `10`: failure logged, batch ends early (tx still succeeds). */
    BreakOnFail = 2,
    /** `11`: success ends the batch early; failure logged and batch continues. */
    BreakOnSuccess = 3,
}

/** Try batches are capped at 88 calls (176 payload bits / 2). */
export const MAX_TRY_CALLS = 88;

/** Pack per-call policies into the mode payload; calls past the array default to Optional (`00`). */
export function packPolicies(policies: CallPolicy[]): bigint {
    if (policies.length > MAX_TRY_CALLS) {
        throw new Error(`try batches are capped at ${MAX_TRY_CALLS} calls (2 policy bits each)`);
    }
    return policies.reduce((mask, p, i) => mask | (BigInt(p) << BigInt(2 * i)), 0n);
}

/** The 2-bit policy of call `i` in a packed payload. */
export const policyAt = (policies: bigint, i: number): CallPolicy =>
    Number((policies >> BigInt(2 * i)) & 3n) as CallPolicy;

export function buildMode(opts: { opData: boolean; tryExec: boolean; policies?: bigint }): string {
    const payload = opts.policies ?? 0n;
    if (!opts.tryExec && payload !== 0n) {
        throw new Error("call policies only apply to try mode");
    }
    if (payload >> 176n !== 0n) {
        throw new Error("policies overflow the 176-bit mode payload");
    }
    return (
        "0x01" + // callType: batch
        (opts.tryExec ? "01" : "00") +
        "00000000" +
        (opts.opData ? OPDATA_SELECTOR : "00000000") +
        payload.toString(16).padStart(44, "0")
    );
}

export interface DecodedMode {
    batch: boolean;
    tryExec: boolean;
    opData: boolean;
    policies: bigint;
}

export function decodeMode(mode: string): DecodedMode {
    const hex = mode.toLowerCase().replace(/^0x/, "").padEnd(64, "0");
    if (hex.length !== 64) throw new Error(`bad mode: ${mode}`);
    const callType = hex.slice(0, 2);
    const execType = hex.slice(2, 4);
    const selector = hex.slice(12, 20);
    if (callType !== "01" || !["00", "01"].includes(execType) || !["00000000", OPDATA_SELECTOR].includes(selector)) {
        throw new Error(`unsupported mode: ${mode}`);
    }
    return {
        batch: true,
        tryExec: execType === "01",
        opData: selector === OPDATA_SELECTOR,
        policies: BigInt("0x" + hex.slice(20)),
    };
}

// ─────────────────────────────────────────────────────────────────────────
// executionData / calldata encoders (signed opData path)
// ─────────────────────────────────────────────────────────────────────────
export const encodeOpData = (deadline: bigint, signature: string): string =>
    abi.encode(["uint256", "bytes"], [deadline, signature]);

export const encodeBatchWithOpData = (calls: Call[], opData: string): string =>
    abi.encode([CALLS_TYPE, "bytes"], [calls, opData]);

/** No-opData executionData: `abi.encode(Call[])` — the self-authorized (msg.sender) batch path. */
export const encodeBatch = (calls: Call[]): string => abi.encode([CALLS_TYPE], [calls]);

export const encodeExecute = (mode: string, executionData: string): string =>
    EXECUTE_IFACE.encodeFunctionData("execute", [mode, executionData]);

/** Full `execute()` calldata for a signed (opData) batch — used both as the relayed tx data
 *  (battery, direct to the user account) and as one inner call of the gasless proxy batch. */
export const encodeSignedExecute = (mode: string, calls: Call[], deadline: bigint, signature: string): string =>
    encodeExecute(mode, encodeBatchWithOpData(calls, encodeOpData(deadline, signature)));

// ─── Modes for the two-artifact flow ───
/** The fee transfer and the user batch are each a signed, atomic (non-try) opData batch. */
export const OPDATA_ATOMIC_MODE = buildMode({ opData: true, tryExec: false });
/** The gasless proxy: relay self-call (no opData), try mode — call 0 (the fee) REQUIRED, call 1
 *  (the user batch) OPTIONAL (a failure is logged and swallowed, the fee stays collected). */
export const PROXY_TRY_MODE = buildMode({
    opData: false,
    tryExec: true,
    policies: packPolicies([CallPolicy.Required, CallPolicy.Optional]),
});

/** The `direct` gasless mode: one signed try-batch on the user account — call 0 the fee (Required),
 *  the user's own calls BreakOnFail (a failure is logged and ends the batch early; the fee stays
 *  collected). */
export const directGaslessMode = (userCallCount: number): string =>
    buildMode({
        opData: true,
        tryExec: true,
        policies: packPolicies([CallPolicy.Required, ...Array(userCallCount).fill(CallPolicy.BreakOnFail)]),
    });

// ─────────────────────────────────────────────────────────────────────────
// EIP-712
// ─────────────────────────────────────────────────────────────────────────
export interface ExecuteTypedData {
    domain: { name: string; version: string; chainId: number; verifyingContract: string; salt: string };
    types: typeof EXECUTE_TYPES;
    primaryType: "Execute";
    message: { mode: string; calls: Call[]; nonce: bigint; deadline: bigint };
}

/** Domain of the delegated account: verifyingContract = the EOA, salt = the delegate implementation. */
export function executeTypedData(opts: {
    chainId: number;
    account: string;
    delegate: string;
    mode: string;
    calls: Call[];
    nonce: bigint;
    deadline: bigint;
}): ExecuteTypedData {
    return {
        domain: {
            name: "Hermes",
            version: "v1.0.0",
            chainId: opts.chainId,
            verifyingContract: opts.account,
            salt: zeroPadValue(opts.delegate === "" ? ZeroAddress : opts.delegate, 32),
        },
        types: EXECUTE_TYPES,
        primaryType: "Execute",
        message: { mode: opts.mode, calls: opts.calls, nonce: opts.nonce, deadline: opts.deadline },
    };
}

export const executeDigest = (td: ExecuteTypedData): string =>
    TypedDataEncoder.hash(td.domain, td.types as unknown as Record<string, { name: string; type: string }[]>, td.message);

/** EIP-712 digest of an arbitrary (client-echoed) typed-data object; throws on a malformed shape.
 *  `types` must not include `EIP712Domain` (ethers derives the domain separately) — the shape
 *  /emulate returns already omits it, matching what ethers/viem `signTypedData` expect. */
export function hashTypedData(domain: unknown, types: unknown, message: unknown): string {
    return TypedDataEncoder.hash(
        domain as Record<string, unknown>,
        types as Record<string, { name: string; type: string }[]>,
        message as Record<string, unknown>,
    );
}

// ─────────────────────────────────────────────────────────────────────────
// Emulation artifacts (compiled by hardhat; `yarn compile` first)
// ─────────────────────────────────────────────────────────────────────────
const artifactCache = new Map<string, string>();

export function emulationBytecode(contract: "HermesDelegateEmulatorV1" | "HermesNonceEmulatorV1" | "HermesGasMeterV1"): string {
    const cached = artifactCache.get(contract);
    if (cached) return cached;

    const file = path.join(__dirname, "..", "..", "artifacts", "contracts", "emulation", `${contract}.sol`, `${contract}.json`);
    if (!fs.existsSync(file)) {
        throw new Error(`missing artifact ${file} — run \`yarn compile\` first`);
    }
    const code = JSON.parse(fs.readFileSync(file, "utf8")).deployedBytecode as string;
    artifactCache.set(contract, code);
    return code;
}

/** Intrinsic tx gas: 21k + calldata bytes (4 per zero, 16 per non-zero). */
export function intrinsicGas(txData: string): bigint {
    let gas = 21_000n;
    const hex = txData.replace(/^0x/, "");
    for (let i = 0; i < hex.length; i += 2) {
        gas += hex.slice(i, i + 2) === "00" ? 4n : 16n;
    }
    return gas;
}

/** Best-effort human message from raw revert data (Error(string) or a bare selector). */
export function revertReason(data: string): string {
    if (!data || data === "0x") return "reverted without data";
    if (data.startsWith("0x08c379a0")) {
        try {
            return AbiCoder.defaultAbiCoder().decode(["string"], "0x" + data.slice(10))[0] as string;
        } catch { /* fall through to raw data */ }
    }
    return `reverted with data ${data}`;
}

// ─────────────────────────────────────────────────────────────────────────
// Fallback gas heuristic — used when the RPC rejects state overrides.
// ─────────────────────────────────────────────────────────────────────────
export function heuristicGas(calls: Call[], erc20Fee: boolean): bigint {
    // 21k intrinsic + execute dispatch, opData decode, ecrecover and the manager nonce write.
    let gas = 21_000n + 48_000n;
    for (const call of calls) {
        const dataBytes = BigInt(Math.max(0, (call.data.length - 2) / 2));
        gas += 9_000n + dataBytes * 16n;
    }
    if (erc20Fee) gas += 45_000n; // cold ERC20 + transfer SSTOREs
    return gas;
}
