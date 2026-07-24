/**
 * Hardcoded relay configuration: chains, fee tokens and their rates, gas prices.
 *
 * Everything here is a mock — rates and gas prices are fixed numbers, not oracles.
 * RPC urls and contract addresses can be overridden through env (same vars as hardhat.config.ts
 * plus HERMES_MANAGER[_<CHAIN>] / HERMES_DELEGATE[_<CHAIN>] / RELAY_PRIVATE_KEY).
 */

export interface TokenConfig {
    address: string;
    symbol: string;
    decimals: number;
    /** Price of 1 native coin expressed in this token (hardcoded mock rate). */
    rate: number;
}

export interface ChainConfig {
    key: string;
    chainId: number;
    rpcUrl: string;
    native: { symbol: string; decimals: number };
    /** Hardcoded gas price used for fee quoting, wei. */
    gasPriceWei: bigint;
    /** Fee tokens accepted by the relay, keyed by lowercase address. */
    tokens: Record<string, TokenConfig>;
    /** HermesV1 nonce manager (zero if not deployed / unknown). */
    manager: string;
    /** HermesDelegateV1 implementation — EIP-712 domain salt of user signatures. */
    delegate: string;
}

/** Fee buffer applied on top of the emulated gas, percent. */
export const GAS_MULTIPLIER_PCT = 120n;
/** Signature lifetime the relay quotes, seconds. */
export const DEADLINE_SECONDS = 600;
/** Default port of the relay server. */
export const DEFAULT_PORT = 8787;

const ZERO = "0x0000000000000000000000000000000000000000";
// Hardhat well-known accounts: #0 is the deployer in hardhat.config.ts, the relay defaults to #1.
const DEFAULT_RELAY_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const ALIASES: Record<string, string> = {
    eth: "eth",
    ethereum: "eth",
    mainnet: "eth",
    bsc: "bsc",
    bnb: "bsc",
    arb: "arb",
    arbitrum: "arb",
    base: "base",
    local: "local",
    localhost: "local",
    hardhat: "local",
};

const env = (name: string): string | undefined => {
    const value = process.env[name];
    return value && value.trim() !== "" ? value.trim() : undefined;
};

/** HERMES_MANAGER_ETH beats HERMES_MANAGER beats zero (same scheme for the delegate). */
const contractAddr = (kind: "MANAGER" | "DELEGATE", chainKey: string): string =>
    env(`HERMES_${kind}_${chainKey.toUpperCase()}`) ?? env(`HERMES_${kind}`) ?? ZERO;

const token = (address: string, symbol: string, decimals: number, rate: number): [string, TokenConfig] =>
    [address.toLowerCase(), { address, symbol, decimals, rate }];

export function relayPrivateKey(): string {
    return env("RELAY_PRIVATE_KEY") ?? DEFAULT_RELAY_KEY;
}

export function chainKeys(): string[] {
    return ["eth", "bsc", "arb", "base", "local"];
}

/** Resolved lazily so env tweaks (tests, dotenv) are picked up per request. */
export function getChain(slug: string): ChainConfig | undefined {
    const key = ALIASES[slug?.toLowerCase?.() ?? ""];
    if (!key) return undefined;

    switch (key) {
        case "eth":
            return {
                key,
                chainId: 1,
                rpcUrl: env("ETH_RPC_URL") ?? "https://eth.llamarpc.com",
                native: { symbol: "ETH", decimals: 18 },
                gasPriceWei: 2_000_000_000n, // 2 gwei
                tokens: Object.fromEntries([
                    token("0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", 6, 4000),
                    token("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", 6, 4000),
                ]),
                manager: contractAddr("MANAGER", key),
                delegate: contractAddr("DELEGATE", key),
            };
        case "bsc":
            return {
                key,
                chainId: 56,
                rpcUrl: env("BSC_RPC_URL") ?? "https://bsc-dataseed.binance.org",
                native: { symbol: "BNB", decimals: 18 },
                gasPriceWei: 1_000_000_000n, // 1 gwei
                tokens: Object.fromEntries([
                    token("0x55d398326f99059fF775485246999027B3197955", "USDT", 18, 1000),
                    token("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", 18, 1000),
                ]),
                manager: contractAddr("MANAGER", key),
                delegate: contractAddr("DELEGATE", key),
            };
        case "arb":
            return {
                key,
                chainId: 42161,
                rpcUrl: env("ARBITRUM_RPC_URL") ?? "https://arb1.arbitrum.io/rpc",
                native: { symbol: "ETH", decimals: 18 },
                gasPriceWei: 20_000_000n, // 0.02 gwei
                tokens: Object.fromEntries([
                    token("0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "USDT", 6, 4000),
                    token("0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USDC", 6, 4000),
                ]),
                manager: contractAddr("MANAGER", key),
                delegate: contractAddr("DELEGATE", key),
            };
        case "base":
            return {
                key,
                chainId: 8453,
                rpcUrl: env("BASE_RPC_URL") ?? "https://mainnet.base.org",
                native: { symbol: "ETH", decimals: 18 },
                gasPriceWei: 50_000_000n, // 0.05 gwei
                tokens: Object.fromEntries([
                    token("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC", 6, 4000),
                ]),
                manager: contractAddr("MANAGER", key),
                delegate: contractAddr("DELEGATE", key),
            };
        case "local": {
            // Dev chain against `yarn hardhat node`; the fee token is whatever LOCAL_TOKEN_ADDRESS points at.
            const localToken = env("LOCAL_TOKEN_ADDRESS");
            return {
                key,
                chainId: 31337,
                rpcUrl: env("LOCAL_RPC_URL") ?? "http://127.0.0.1:8545",
                native: { symbol: "ETH", decimals: 18 },
                gasPriceWei: 1_000_000_000n, // 1 gwei
                tokens: Object.fromEntries(localToken ? [token(localToken, "MOCK", 18, 4000)] : []),
                manager: contractAddr("MANAGER", key),
                delegate: contractAddr("DELEGATE", key),
            };
        }
        default:
            return undefined;
    }
}
