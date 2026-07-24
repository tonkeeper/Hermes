/**
 * Quote store: /emulate mints a uuid bound to the digest(s) it quoted; /send must present that uuid
 * and echo typed data that re-hashes to them. In-memory and per-process (a mock).
 */

import { randomUUID } from "crypto";

/** Delivery mechanism for a gasless (token-fee) transaction. */
export type Path = "direct" | "delegate";

/** One signable batch the /emulate quote committed to: its digest and the exact ERC-7821 mode it
 *  must carry. /send re-hashes the echoed typed data and requires both to match. */
export interface QuoteArtifact {
    digest: string;
    mode: string;
}

export interface Quote {
    type: "battery" | "gasless";
    path?: Path; // gasless only
    chainKey: string;
    account: string;
    /** Signable batches by role: battery→{user}; gasless direct→{combined}; gasless delegate→{fee,user}. */
    artifacts: Record<string, QuoteArtifact>;
    expiresAt: number;
}

export const nowSeconds = (): number => Math.floor(Date.now() / 1000);

const quotes = new Map<string, Quote>();

export function storeQuote(quote: Quote): string {
    if (quotes.size > 10_000) {
        const cutoff = nowSeconds();
        for (const [id, q] of quotes) if (q.expiresAt < cutoff) quotes.delete(id);
    }
    const uuid = randomUUID();
    quotes.set(uuid, quote);
    return uuid;
}

export const getQuote = (uuid: string): Quote | undefined => quotes.get(uuid);

export const deleteQuote = (uuid: string): void => void quotes.delete(uuid);
