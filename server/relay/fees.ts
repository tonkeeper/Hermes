/** Fee math (hardcoded rates) and the ERC20 fee-transfer call. */

import { TokenConfig } from "../config";
import { Call, ERC20_IFACE } from "../chain/encoding";

/** feeWei → fee-asset base units: ceil(feeWei * rate * 10^decimals / 10^18); native passes through. */
export function feeInAsset(feeWei: bigint, token: TokenConfig | undefined): bigint {
    if (!token) return feeWei;
    const numerator = feeWei * BigInt(token.rate) * 10n ** BigInt(token.decimals);
    return (numerator + 10n ** 18n - 1n) / 10n ** 18n;
}

/** ERC20 `transfer(relay, amount)` — the fee the user signs over to the relay. */
export const feeCall = (relay: string, token: TokenConfig, amount: bigint): Call => ({
    target: token.address,
    value: 0n,
    data: ERC20_IFACE.encodeFunctionData("transfer", [relay, amount]),
});
