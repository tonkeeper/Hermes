/**
 * Chain access layer: cached providers, the nonce-managed relay wallet, and the reads the relay
 * needs before quoting — account nonce, EIP-7702 delegation status, and one-time relay self-delegation.
 */

import {
    JsonRpcProvider,
    NonceManager,
    Wallet,
    ZeroAddress,
    getAddress,
} from "ethers";
import { ChainConfig, relayPrivateKey } from "../config";
import { HttpError } from "../errors";
import { NONCE_IFACE } from "./encoding";

// EIP-7702 authorization surcharge: 25000 up front, 12500 refunded when the authority account
// already exists — net 12500 for an existing account, 25000 for an empty one.
const AUTH_GAS_EMPTY_ACCOUNT = 25_000n;
const AUTH_GAS_EXISTING_ACCOUNT = 12_500n;

// ─────────────────────────────────────────────────────────────────────────
// Providers / wallets
// ─────────────────────────────────────────────────────────────────────────
const providers = new Map<string, JsonRpcProvider>();

export function provider(chain: ChainConfig): JsonRpcProvider {
    let cached = providers.get(chain.key);
    if (!cached) {
        cached = new JsonRpcProvider(chain.rpcUrl, chain.chainId, { staticNetwork: true });
        providers.set(chain.key, cached);
    }
    return cached;
}

export const relayAddress = (): string => new Wallet(relayPrivateKey()).address;

// Cached per chain and nonce-managed so back-to-back relayed txs don't race on the account nonce.
const relaySigners = new Map<string, NonceManager>();

export function relayWallet(chain: ChainConfig): NonceManager {
    let signer = relaySigners.get(chain.key);
    if (!signer) {
        signer = new NonceManager(new Wallet(relayPrivateKey(), provider(chain)));
        relaySigners.set(chain.key, signer);
    }
    return signer;
}

// ─────────────────────────────────────────────────────────────────────────
// Chain reads
// ─────────────────────────────────────────────────────────────────────────
/** Current Hermes nonce of `account`; 0 when the manager is not configured/deployed on the chain. */
export async function readNonce(chain: ChainConfig, account: string): Promise<bigint> {
    if (chain.manager === ZeroAddress) return 0n;
    try {
        const data = NONCE_IFACE.encodeFunctionData("nonceOf", [account]);
        const result = await provider(chain).call({ to: chain.manager, data });
        return NONCE_IFACE.decodeFunctionResult("nonceOf", result)[0] as bigint;
    } catch {
        return 0n;
    }
}

/** Raw `eth_getCode` at latest — bypasses ethers' per-block getCode cache, which can serve a stale
 *  result right after a delegating tx. */
export async function fetchCode(chain: ChainConfig, account: string): Promise<string> {
    return provider(chain).send("eth_getCode", [account, "latest"]) as Promise<string>;
}

/** Delegate address from an EIP-7702 designator (`0xef0100 ‖ address`), or null. */
export function parseDelegation(code: string): string | null {
    return code.toLowerCase().startsWith("0xef0100") && code.length === 48 ? getAddress("0x" + code.slice(8)) : null;
}

export interface DelegationStatus {
    delegated: boolean;
    delegatedTo: string | null;
    requiresAuthorization: boolean;
    authorizationGas: bigint;
    authorization: { chainId: number; address: string; nonce: number } | null;
}

export async function delegationStatus(chain: ChainConfig, account: string): Promise<DelegationStatus> {
    const [code, txNonce, balance] = await Promise.all([
        fetchCode(chain, account),
        provider(chain).getTransactionCount(account),
        provider(chain).getBalance(account),
    ]);
    const delegatedTo = parseDelegation(code);
    const delegated = delegatedTo !== null
        && (chain.delegate === ZeroAddress || delegatedTo.toLowerCase() === chain.delegate.toLowerCase());
    const requiresAuthorization = !delegated;
    const accountExists = txNonce > 0 || balance > 0n || code !== "0x";
    return {
        delegated,
        delegatedTo,
        requiresAuthorization,
        authorizationGas: requiresAuthorization ? (accountExists ? AUTH_GAS_EXISTING_ACCOUNT : AUTH_GAS_EMPTY_ACCOUNT) : 0n,
        authorization: requiresAuthorization && chain.delegate !== ZeroAddress
            ? { chainId: chain.chainId, address: chain.delegate, nonce: txNonce }
            : null,
    };
}

/** One-time: 7702-delegate the relay EOA to the chain's delegate so it can run the gasless proxy
 *  self-call. Self-authorization → the authorization nonce is the relay tx nonce + 1. */
const relayDelegated = new Map<string, boolean>();

export async function ensureRelayDelegated(chain: ChainConfig): Promise<void> {
    if (relayDelegated.get(chain.key)) return;
    if (chain.delegate === ZeroAddress) {
        throw new HttpError(500, `no delegate configured for ${chain.key}; gasless proxy needs the relay delegated`);
    }
    const relay = relayAddress();
    const code = await fetchCode(chain, relay);
    if (parseDelegation(code)?.toLowerCase() === chain.delegate.toLowerCase()) {
        relayDelegated.set(chain.key, true);
        return;
    }
    const wallet = new Wallet(relayPrivateKey(), provider(chain));
    const txNonce = await provider(chain).getTransactionCount(relay);
    const auth = await wallet.authorize({ address: chain.delegate, nonce: txNonce + 1, chainId: chain.chainId });
    const tx = await wallet.sendTransaction({ to: relay, nonce: txNonce, type: 4, authorizationList: [auth] });
    await tx.wait();
    relaySigners.delete(chain.key); // the manual tx advanced the nonce; drop the cached NonceManager
    relayDelegated.set(chain.key, true);
}
