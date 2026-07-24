/**
 * POST /routes — one emulation of the chosen path, with the resulting fee previewed across every
 * accepted ERC20 token (no calldata returned; this is a quote preview).
 */

import { formatUnits } from "ethers";
import { DEADLINE_SECONDS, GAS_MULTIPLIER_PCT } from "../config";
import { HttpError } from "../errors";
import { readNonce, relayAddress } from "../chain/provider";
import { emulateDirect, emulateGasless } from "./emulation";
import { feeCall, feeInAsset } from "./fees";
import { parseInputCalls, parsePath, requireAddress, requireChain } from "./parse";
import { nowSeconds } from "./quotes";

export async function routes(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const chain = requireChain(body.chain);
    const account = requireAddress(body.from, "from");
    const userCalls = parseInputCalls(body.payloads);

    const path = parsePath(body.path);
    const tokens = Object.values(chain.tokens);
    if (tokens.length === 0) throw new HttpError(400, `no fee tokens configured on ${chain.key}`);

    const nonce = await readNonce(chain, account);
    const deadline = BigInt(nowSeconds() + DEADLINE_SECONDS);
    const relay = relayAddress();

    // One emulation of the chosen path, using the first token as a representative fee call. The token
    // only nudges the ERC20 transfer gas; for a preview we reprice the resulting fee by rate across all.
    const sample = tokens[0];
    const feeC = feeCall(relay, sample, feeInAsset(200_000n * chain.gasPriceWei, sample));
    const { gas, source } = path === "direct"
        ? await emulateDirect(chain, account, userCalls, feeC, nonce, deadline)
        : await emulateGasless(chain, account, userCalls, feeC, nonce, deadline);

    const gasCharged = (gas * GAS_MULTIPLIER_PCT) / 100n;
    const feeWei = gasCharged * chain.gasPriceWei;

    return {
        chain: chain.key,
        chainId: chain.chainId,
        path,
        gas: { estimated: gas.toString(), charged: gasCharged.toString(), source, gasPriceWei: chain.gasPriceWei.toString(), feeNativeWei: feeWei.toString() },
        tokens: tokens.map((t) => {
            const amount = feeInAsset(feeWei, t);
            return { address: t.address, symbol: t.symbol, decimals: t.decimals, rate: t.rate, feeAmount: amount.toString(), feeFormatted: formatUnits(amount, t.decimals) };
        }),
    };
}
