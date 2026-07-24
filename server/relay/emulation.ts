/**
 * Gas emulation. Gas is measured against the real path with state overrides (user + relay accounts
 * get the emulator, the virtual nonce manager gets its twin), via eth_estimateGas or, where the node
 * rejects overrides on estimateGas (hardhat), a gasleft() probe inside eth_call; heuristic as last
 * resort. The emulator accepts any signature and any no-opData caller, so we emulate without the
 * user's key.
 */

import { AbiCoder, Wallet, keccak256, toBeHex } from "ethers";
import { ChainConfig } from "../config";
import { provider, relayAddress } from "../chain/provider";
import { HttpError } from "../errors";
import {
    Call,
    GAS_METER_IFACE,
    OPDATA_ATOMIC_MODE,
    PROXY_TRY_MODE,
    VIRTUAL_GAS_METER,
    VIRTUAL_NONCE_MANAGER,
    directGaslessMode,
    emulationBytecode,
    encodeBatch,
    encodeExecute,
    encodeSignedExecute,
    executeDigest,
    executeTypedData,
    intrinsicGas,
    revertReason,
} from "../chain/encoding";

// Cold account access per 0xef0100 designator the direct-code override skips (relay + user hops).
const DELEGATE_RESOLUTION_GAS = 2_600n;

export interface GasEstimate {
    gas: bigint;
    source: "estimateGas" | "gasMeter" | "heuristic";
}

const fakeSig = (digest: string): string => Wallet.createRandom().signingKey.sign(digest).serialized;

const relayBalanceOverride = () => ({ [relayAddress()]: { balance: "0x" + (10n ** 22n).toString(16) } });

/** Mirror `account`'s current nonce into the nonce emulator (mapping slot 0) so useNonce()'s SSTORE
 *  costs match the real manager (fresh vs repeat write). */
function nonceOverride(account: string, nonce: bigint): Record<string, unknown> {
    const slot = keccak256(AbiCoder.defaultAbiCoder().encode(["address", "uint256"], [account, 0]));
    return {
        code: emulationBytecode("HermesNonceEmulatorV1"),
        stateDiff: { [slot]: toBeHex(nonce, 32) },
    };
}

/**
 * Full-transaction gas for the calldata sent to `to`, priced against overridden state.
 * Tier 1: eth_estimateGas with overrides (node prices the whole tx). Tier 2: gasleft() probe via
 * eth_call (nodes that reject overrides on estimateGas). Tier 3: caller's heuristic. A genuine
 * revert surfaces as a 400, not a silent fallback.
 */
async function estimateGas(
    chain: ChainConfig,
    from: string,
    to: string,
    data: string,
    overrides: Record<string, unknown>,
    fallbackGas: bigint,
    resolutionHops: bigint,
): Promise<GasEstimate> {
    try {
        const gasHex = await provider(chain).send("eth_estimateGas", [{ from, to, data }, "latest", overrides]);
        return { gas: BigInt(gasHex) + resolutionHops * DELEGATE_RESOLUTION_GAS, source: "estimateGas" };
    } catch {
        // fall through
    }
    try {
        const measured = await provider(chain).send("eth_call", [
            { from, to: VIRTUAL_GAS_METER, data: GAS_METER_IFACE.encodeFunctionData("measure", [to, data]) },
            "latest",
            overrides,
        ]);
        const [innerGas, success, result] =
            GAS_METER_IFACE.decodeFunctionResult("measure", measured) as unknown as [bigint, boolean, string];
        if (!success) throw new HttpError(400, `emulation reverted: ${revertReason(result)}`);
        return { gas: intrinsicGas(data) + innerGas, source: "gasMeter" };
    } catch (error) {
        if (error instanceof HttpError) throw error;
        return { gas: fallbackGas, source: "heuristic" };
    }
}

/** Emulate the battery path: relay → userAccount.execute(atomic, userCalls). */
export async function emulateBattery(chain: ChainConfig, account: string, userCalls: Call[], nonce: bigint, deadline: bigint): Promise<GasEstimate> {
    const td = executeTypedData({ chainId: chain.chainId, account, delegate: chain.delegate, mode: OPDATA_ATOMIC_MODE, calls: userCalls, nonce, deadline });
    const data = encodeSignedExecute(OPDATA_ATOMIC_MODE, userCalls, deadline, fakeSig(executeDigest(td)));
    const overrides = {
        [account]: { code: emulationBytecode("HermesDelegateEmulatorV1") },
        [VIRTUAL_NONCE_MANAGER]: nonceOverride(account, nonce),
        [VIRTUAL_GAS_METER]: { code: emulationBytecode("HermesGasMeterV1") },
        ...relayBalanceOverride(),
    };
    const fallback = intrinsicGas(data) + 60_000n;
    return estimateGas(chain, relayAddress(), account, data, overrides, fallback, 1n);
}

/** Emulate the gasless proxy: relay self-call try-batch of [feeExec, userExec] on the user account. */
export async function emulateGasless(chain: ChainConfig, account: string, userCalls: Call[], fee: Call, nonce: bigint, deadline: bigint): Promise<GasEstimate> {
    const relay = relayAddress();
    const feeTd = executeTypedData({ chainId: chain.chainId, account, delegate: chain.delegate, mode: OPDATA_ATOMIC_MODE, calls: [fee], nonce, deadline });
    const userTd = executeTypedData({ chainId: chain.chainId, account, delegate: chain.delegate, mode: OPDATA_ATOMIC_MODE, calls: userCalls, nonce: nonce + 1n, deadline });
    const feeInner = encodeSignedExecute(OPDATA_ATOMIC_MODE, [fee], deadline, fakeSig(executeDigest(feeTd)));
    const userInner = encodeSignedExecute(OPDATA_ATOMIC_MODE, userCalls, deadline, fakeSig(executeDigest(userTd)));
    const outerCalls: Call[] = [
        { target: account, value: 0n, data: feeInner },
        { target: account, value: 0n, data: userInner },
    ];
    const data = encodeExecute(PROXY_TRY_MODE, encodeBatch(outerCalls));
    const overrides = {
        [relay]: { code: emulationBytecode("HermesDelegateEmulatorV1"), balance: "0x" + (10n ** 22n).toString(16) },
        [account]: { code: emulationBytecode("HermesDelegateEmulatorV1") },
        [VIRTUAL_NONCE_MANAGER]: nonceOverride(account, nonce),
        [VIRTUAL_GAS_METER]: { code: emulationBytecode("HermesGasMeterV1") },
    };
    const fallback = intrinsicGas(data) + 140_000n;
    return estimateGas(chain, relay, relay, data, overrides, fallback, 2n);
}

/** Emulate the gasless direct path: relay → userAccount.execute(try, [fee(REQUIRED), ...user(BREAK_ON_FAIL)]). */
export async function emulateDirect(chain: ChainConfig, account: string, userCalls: Call[], fee: Call, nonce: bigint, deadline: bigint): Promise<GasEstimate> {
    const mode = directGaslessMode(userCalls.length);
    const calls = [fee, ...userCalls];
    const td = executeTypedData({ chainId: chain.chainId, account, delegate: chain.delegate, mode, calls, nonce, deadline });
    const data = encodeSignedExecute(mode, calls, deadline, fakeSig(executeDigest(td)));
    const overrides = {
        [account]: { code: emulationBytecode("HermesDelegateEmulatorV1") },
        [VIRTUAL_NONCE_MANAGER]: nonceOverride(account, nonce),
        [VIRTUAL_GAS_METER]: { code: emulationBytecode("HermesGasMeterV1") },
        ...relayBalanceOverride(),
    };
    const fallback = intrinsicGas(data) + 80_000n;
    return estimateGas(chain, relayAddress(), account, data, overrides, fallback, 1n);
}
