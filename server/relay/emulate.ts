/**
 * POST /emulate — quote an exact token and return the signable artifact(s).
 *
 * The user signs up to TWO atomic (opData) batches on their own account:
 *   - fee   : ERC20 transfer(relay, amount)      — gasless only
 *   - user  : the user's own calls               — gasless & battery
 *
 * Three delivery paths, selected by `type` (+ `path` for gasless):
 *   - battery  (full sponsorship): one atomic user batch, no on-chain fee. Relay eats the gas.
 *   - direct   (gasless): one signed try-batch [fee(Required), ...user(BreakOnFail)] sent straight
 *                to the account. The fee is always collected; a failing user call ends the batch early.
 *   - delegate (gasless): the relay (itself 7702-delegated) self-calls a try-batch of two inner
 *                executes on the user account — fee (nonce N, Required) then user (nonce N+1).
 *
 * Two-pass fee: emulate with a prelim amount, then charge from the measured gas (the on-chain gas
 * barely depends on the fee amount). authorizationGas is folded into what the user pays.
 */

import { formatUnits } from "ethers";
import { DEADLINE_SECONDS, GAS_MULTIPLIER_PCT } from "../config";
import { HttpError } from "../errors";
import { delegationStatus, readNonce, relayAddress } from "../chain/provider";
import { Call, OPDATA_ATOMIC_MODE, directGaslessMode, executeDigest, executeTypedData } from "../chain/encoding";
import { GasEstimate, emulateBattery, emulateDirect, emulateGasless } from "./emulation";
import { feeCall, feeInAsset } from "./fees";
import { parseInputCalls, parsePath, requireAddress, requireChain, requireFeeToken } from "./parse";
import { QuoteArtifact, nowSeconds, storeQuote } from "./quotes";

export async function emulate(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const type = body.type;
    if (type !== "battery" && type !== "gasless") {
        throw new HttpError(400, "type must be 'battery' (full sponsorship) or 'gasless' (fee paid in token)");
    }
    const gasless = type === "gasless";
    const chain = requireChain(body.chain);
    const account = requireAddress(body.from, "from");
    const userCalls = parseInputCalls(body.payloads);
    const relay = relayAddress();
    const path = gasless ? parsePath(body.path) : undefined;
    const token = gasless ? requireFeeToken(chain, body.asset) : undefined;

    const [nonce, delegation] = await Promise.all([readNonce(chain, account), delegationStatus(chain, account)]);
    const deadline = BigInt(nowSeconds() + DEADLINE_SECONDS);

    // Two-pass fee: emulate with a prelim amount, then charge from the measured gas (the on-chain
    // gas barely depends on the fee amount). authorizationGas is folded into what the user pays.
    const chargeFrom = (gas: bigint): bigint => (gas + delegation.authorizationGas) * GAS_MULTIPLIER_PCT / 100n;

    let execGas: bigint;
    let gasSource: GasEstimate["source"];
    let amount = 0n;
    const artifacts: Record<string, QuoteArtifact> = {};
    const sign: Record<string, unknown> = {};
    const td = (mode: string, calls: Call[], n: bigint) =>
        executeTypedData({ chainId: chain.chainId, account, delegate: chain.delegate, mode, calls, nonce: n, deadline });
    const record = (role: string, mode: string, calls: Call[], n: bigint) => {
        const typedData = td(mode, calls, n);
        const digest = executeDigest(typedData);
        artifacts[role] = { digest, mode };
        sign[role] = { typedData, digest };
    };

    if (!gasless) {
        // battery — full sponsorship: one atomic user batch, no on-chain fee.
        const est = await emulateBattery(chain, account, userCalls, nonce, deadline);
        execGas = est.gas;
        gasSource = est.source;
        record("user", OPDATA_ATOMIC_MODE, userCalls, nonce);
    } else if (path === "direct") {
        // direct — one signed try-batch [fee(REQUIRED), ...user(BREAK_ON_FAIL)] sent straight to the account.
        const prelim = feeInAsset(200_000n * chain.gasPriceWei, token);
        const est = await emulateDirect(chain, account, userCalls, feeCall(relay, token!, prelim), nonce, deadline);
        execGas = est.gas;
        gasSource = est.source;
        amount = feeInAsset(chargeFrom(execGas) * chain.gasPriceWei, token);
        record("combined", directGaslessMode(userCalls.length), [feeCall(relay, token!, amount), ...userCalls], nonce);
    } else {
        // delegate — proxy self-call over two atomic batches: fee (nonce N) + user (nonce N+1).
        const prelim = feeInAsset(200_000n * chain.gasPriceWei, token);
        const est = await emulateGasless(chain, account, userCalls, feeCall(relay, token!, prelim), nonce, deadline);
        execGas = est.gas;
        gasSource = est.source;
        amount = feeInAsset(chargeFrom(execGas) * chain.gasPriceWei, token);
        record("fee", OPDATA_ATOMIC_MODE, [feeCall(relay, token!, amount)], nonce);
        record("user", OPDATA_ATOMIC_MODE, userCalls, nonce + 1n);
    }

    const gasUsed = execGas + delegation.authorizationGas;
    const gasCharged = (gasUsed * GAS_MULTIPLIER_PCT) / 100n;
    const feeWei = gasCharged * chain.gasPriceWei;

    const uuid = storeQuote({ type, path, chainKey: chain.key, account, artifacts, expiresAt: Number(deadline) });

    return {
        uuid,
        type,
        ...(path ? { path } : {}),
        chain: chain.key,
        chainId: chain.chainId,
        amount: gasless ? amount.toString() : feeWei.toString(),
        amountFormatted: gasless ? formatUnits(amount, token!.decimals) : formatUnits(feeWei, chain.native.decimals),
        asset: gasless
            ? { kind: "erc20", address: token!.address, symbol: token!.symbol, decimals: token!.decimals, rate: token!.rate }
            : { kind: "native", symbol: chain.native.symbol, decimals: chain.native.decimals, note: "battery fee is charged off-chain (virtual)" },
        account: {
            address: account,
            delegated: delegation.delegated,
            delegatedTo: delegation.delegatedTo,
            requiresAuthorization: delegation.requiresAuthorization,
            authorization: delegation.authorization,
        },
        gas: {
            estimated: gasUsed.toString(),
            charged: gasCharged.toString(),
            source: gasSource,
            authorizationGas: delegation.authorizationGas.toString(),
            gasPriceWei: chain.gasPriceWei.toString(),
            feeNativeWei: feeWei.toString(),
            feeNativeFormatted: formatUnits(feeWei, chain.native.decimals),
        },
        // Sign each present `sign.*.typedData` (eth_signTypedData_v4) and echo it back to /send.
        // direct → { combined }; delegate → { fee, user }; battery → { user }.
        sign,
    };
}
