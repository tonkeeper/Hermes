/**
 * Request parsing and validation (canonical field names only). Every helper throws HttpError(400)
 * on bad input, so handlers can parse straight into typed values without defensive checks.
 */

import {
    AuthorizationLike,
    Signature,
    ZeroAddress,
    getAddress,
    isAddress,
    isHexString,
} from "ethers";
import { ChainConfig, TokenConfig, getChain } from "../config";
import { HttpError } from "../errors";
import { Call } from "../chain/encoding";
import { Path } from "./quotes";

export function asObject(value: unknown, field: string): Record<string, unknown> {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
        throw new HttpError(400, `${field} must be an object`);
    }
    return value as Record<string, unknown>;
}

export function requireAddress(value: unknown, field: string): string {
    if (!isAddress(value)) throw new HttpError(400, `${field} is required and must be a 20-byte address`);
    return getAddress(value as string);
}

export function toBig(value: unknown, field: string): bigint {
    try {
        if (value === undefined || value === null || value === "") return 0n;
        if (typeof value === "bigint") return value;
        if (typeof value === "number") {
            if (!Number.isInteger(value)) throw new Error("not an integer");
            return BigInt(value);
        }
        if (typeof value === "string") return BigInt(value);
        throw new Error("unsupported type");
    } catch {
        throw new HttpError(400, `bad ${field}: ${String(value)}`);
    }
}

export function requireHex(value: unknown, field: string): string {
    if (typeof value !== "string" || !isHexString(value)) throw new HttpError(400, `${field} must be a 0x hex string`);
    return value;
}

interface ParsedAsset {
    chainKey: string;
    kind: "erc20" | "native";
    address?: string;
}

/** `eth/mainnet/erc20/0xdAC1…` or `eth/mainnet/native` (chain first, erc20 address last). */
function parseAsset(asset: unknown): ParsedAsset {
    if (typeof asset !== "string" || asset.trim() === "") {
        throw new HttpError(400, "asset is required, e.g. eth/mainnet/erc20/0xdAC17F958D2ee523a2206206994597C13D831ec7");
    }
    const parts = asset.split("/").map((p) => p.trim()).filter(Boolean);
    if (parts.length < 2) {
        throw new HttpError(400, `bad asset '${asset}': expected <chain>/<network>/<erc20|native>[/<address>]`);
    }
    const chainKey = parts[0];
    if (parts.some((p) => p.toLowerCase() === "erc20")) {
        const address = parts[parts.length - 1];
        if (!isAddress(address)) throw new HttpError(400, `bad asset '${asset}': last segment must be the token address`);
        return { chainKey, kind: "erc20", address: getAddress(address) };
    }
    return { chainKey, kind: "native" };
}

/** /routes & /emulate input calls: `[{to, value?, data?}]` (wallet convention). */
export function parseInputCalls(payloads: unknown): Call[] {
    if (!Array.isArray(payloads) || payloads.length === 0) {
        throw new HttpError(400, "payloads must be a non-empty array of {to, value, data}");
    }
    return payloads.map((item, i) => {
        const raw = asObject(item, `payloads[${i}]`);
        return {
            target: requireAddress(raw.to, `payloads[${i}].to`),
            value: toBig(raw.value, `payloads[${i}].value`),
            data: raw.data === undefined ? "0x" : requireHex(raw.data, `payloads[${i}].data`),
        };
    });
}

/** Calls inside an echoed typedData.message: `[{target, value, data}]` (Call struct). */
export function parseMessageCalls(calls: unknown): Call[] {
    if (!Array.isArray(calls) || calls.length === 0) {
        throw new HttpError(400, "typedData.message.calls must be a non-empty array of {target, value, data}");
    }
    return calls.map((item, i) => {
        const raw = asObject(item, `calls[${i}]`);
        return {
            target: requireAddress(raw.target, `calls[${i}].target`),
            value: toBig(raw.value, `calls[${i}].value`),
            data: requireHex(raw.data, `calls[${i}].data`),
        };
    });
}

export function requireChain(chainKey: unknown): ChainConfig {
    const chain = typeof chainKey === "string" ? getChain(chainKey) : undefined;
    if (!chain) throw new HttpError(404, `unknown chain '${String(chainKey)}' (expected eth|bsc|arb|base|local)`);
    return chain;
}

/** Signed EIP-7702 authorization tuple: `{chainId, address, nonce, yParity, r, s}`. */
export function parseAuthorization(raw: unknown, chain: ChainConfig): AuthorizationLike {
    const auth = asObject(raw, "authorization");
    const address = requireAddress(auth.address, "authorization.address");
    if (chain.delegate !== ZeroAddress && address !== getAddress(chain.delegate)) {
        throw new HttpError(400, `authorization.address ${address} is not the delegate this relay serves (${chain.delegate})`);
    }
    let signature: Signature;
    try {
        signature = Signature.from({ r: auth.r as string, s: auth.s as string, yParity: Number(auth.yParity) as 0 | 1 });
    } catch {
        throw new HttpError(400, "authorization signature is invalid: expected {yParity, r, s}");
    }
    return {
        address,
        chainId: toBig(auth.chainId, "authorization.chainId"),
        nonce: toBig(auth.nonce, "authorization.nonce"),
        signature,
    };
}

/** `path` selects the gasless delivery mechanism; battery ignores it. paymaster (4337) is not yet supported. */
export function parsePath(value: unknown): Path {
    const p = value === undefined ? "direct" : value;
    if (p !== "direct" && p !== "delegate") {
        throw new HttpError(400, "path must be 'direct' or 'delegate' (paymaster not yet supported)");
    }
    return p;
}

export function requireFeeToken(chain: ChainConfig, asset: unknown): TokenConfig {
    const parsed = parseAsset(asset);
    if (parsed.chainKey && getChain(parsed.chainKey)?.key !== chain.key) {
        throw new HttpError(400, `asset chain '${parsed.chainKey}' does not match chain '${chain.key}'`);
    }
    if (parsed.kind !== "erc20") throw new HttpError(400, "gasless requires an erc20 fee asset");
    const token = chain.tokens[parsed.address!.toLowerCase()];
    if (!token) throw new HttpError(400, `token ${parsed.address} is not an accepted fee token on ${chain.key}`);
    return token;
}
