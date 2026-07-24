/**
 * POST /send — verify the echoed signature(s) against the stored quote and broadcast.
 *
 *   - battery / direct : the relay calls the user account directly (no relay delegation needed).
 *   - delegate         : the relay self-calls a try-batch [userAcc.execute(fee), userAcc.execute(user)].
 *
 * An undelegated account rides a signed EIP-7702 authorization along in a type-4 tx.
 */

import { recoverAddress } from "ethers";
import { HttpError } from "../errors";
import { ensureRelayDelegated, fetchCode, relayAddress, relayWallet } from "../chain/provider";
import { Call, PROXY_TRY_MODE, encodeBatch, encodeExecute, encodeSignedExecute, hashTypedData } from "../chain/encoding";
import { asObject, parseAuthorization, parseMessageCalls, requireChain, requireHex, toBig } from "./parse";
import { QuoteArtifact, deleteQuote, getQuote, nowSeconds } from "./quotes";

interface SignedBatch {
    calls: Call[];
    deadline: bigint;
    signature: string;
    mode: string;
}

/** Verify an echoed {typedData, signature} against a quoted artifact and pull out its batch. The
 *  echoed typed data must re-hash to the quoted digest and carry the quoted mode, and the signature
 *  must recover to the account. */
function verifyArtifact(part: unknown, expected: QuoteArtifact | undefined, account: string, role: string): SignedBatch {
    if (!expected) throw new HttpError(500, `quote missing the ${role} artifact`);
    const obj = asObject(part, role);
    const signature = requireHex(obj.signature, `${role}.signature`);
    if (signature.length !== 132) throw new HttpError(400, `${role}.signature must be a 65-byte 0x hex`);
    const typedData = asObject(obj.typedData, `${role}.typedData`);
    const message = asObject(typedData.message, `${role}.typedData.message`);

    let digest: string;
    try {
        digest = hashTypedData(typedData.domain, typedData.types, message);
    } catch {
        throw new HttpError(400, `${role}.typedData is malformed`);
    }
    if (digest !== expected.digest) throw new HttpError(400, `${role} does not match the quote for this uuid`);
    if (recoverAddress(expected.digest, signature) !== account) throw new HttpError(400, `${role} signature does not recover to ${account}`);
    if (message.mode !== expected.mode) throw new HttpError(400, `${role}.typedData.message.mode does not match the quote`);

    return { calls: parseMessageCalls(message.calls), deadline: toBig(message.deadline, `${role}.deadline`), signature, mode: expected.mode };
}

export async function send(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    if (typeof body.uuid !== "string" || body.uuid === "") throw new HttpError(400, "uuid is required: the id returned by /emulate");
    const uuid = body.uuid;
    const quote = getQuote(uuid);
    if (!quote) throw new HttpError(400, "unknown uuid: quote not found, already used, or expired");
    if (quote.expiresAt !== 0 && quote.expiresAt < nowSeconds()) {
        deleteQuote(uuid);
        throw new HttpError(400, "quote expired: re-run /emulate");
    }

    const chain = requireChain(quote.chainKey);
    const account = quote.account;

    // An undelegated account needs a signed EIP-7702 authorization riding along in a type-4 tx.
    const authorizationList = body.authorization ? [parseAuthorization(body.authorization, chain)] : undefined;
    if (!authorizationList && (await fetchCode(chain, account)) === "0x") {
        throw new HttpError(400, "account has no delegation: include the signed EIP-7702 'authorization' from /emulate (account.authorization)");
    }

    const one = (role: string) => verifyArtifact(body[role], quote.artifacts[role], account, role);
    const inner = (b: SignedBatch): Call => ({ target: account, value: 0n, data: encodeSignedExecute(b.mode, b.calls, b.deadline, b.signature) });

    let to: string;
    let data: string;
    let sendMode: "direct" | "proxy";

    if (quote.type === "battery" || quote.path === "direct") {
        // battery: atomic user batch. direct gasless: one try-batch [fee(REQUIRED), ...user(BREAK_ON_FAIL)].
        // Either way the relay calls the user account directly — no relay delegation needed.
        const batch = one(quote.type === "battery" ? "user" : "combined");
        to = account;
        data = encodeSignedExecute(batch.mode, batch.calls, batch.deadline, batch.signature);
        sendMode = "direct";
    } else {
        // delegate: relay self-call try-batch [userAcc.execute(fee), userAcc.execute(user)].
        const fee = one("fee");
        const user = one("user");
        await ensureRelayDelegated(chain);
        to = relayAddress();
        data = encodeExecute(PROXY_TRY_MODE, encodeBatch([inner(fee), inner(user)]));
        sendMode = "proxy";
    }

    const signer = relayWallet(chain);
    try {
        const tx = await signer.sendTransaction({ to, data, ...(authorizationList ? { type: 4, authorizationList } : {}) });
        deleteQuote(uuid); // one-time use
        return { tx_hash: tx.hash, chain: chain.key, mode: sendMode, authorizationIncluded: Boolean(authorizationList) };
    } catch (error: unknown) {
        signer.reset();
        const err = error as { shortMessage?: string; message?: string };
        throw new HttpError(400, `broadcast failed: ${err.shortMessage ?? err.message ?? String(error)}`);
    }
}
