/**
 * HTTP transport: request/response plumbing and route dispatch.
 *
 *   POST /routes    preview the fee across every accepted ERC20 token (one emulation, no calldata)
 *   POST /emulate   quote an exact token: fee amount + the batch(es) to sign
 *   POST /send      broadcast the signed batch(es) through the relay
 */

import * as fs from "fs";
import * as http from "http";
import * as path from "path";
import { HttpError } from "../errors";
import { emulate } from "../relay/emulate";
import { routes } from "../relay/routes";
import { send } from "../relay/send";

const jsonReplacer = (_key: string, value: unknown): unknown =>
    typeof value === "bigint" ? value.toString() : value;

function respond(res: http.ServerResponse, status: number, body: unknown): void {
    res.writeHead(status, {
        "content-type": "application/json",
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "content-type",
    });
    res.end(JSON.stringify(body, jsonReplacer, 2));
}

function readBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
        const chunks: Buffer[] = [];
        let size = 0;
        req.on("data", (chunk: Buffer) => {
            size += chunk.length;
            if (size > 1 << 20) {
                reject(new HttpError(413, "body too large"));
                req.destroy();
                return;
            }
            chunks.push(chunk);
        });
        req.on("end", () => {
            const raw = Buffer.concat(chunks).toString("utf8");
            if (raw.trim() === "") return resolve({});
            try {
                resolve(JSON.parse(raw));
            } catch {
                reject(new HttpError(400, "body is not valid JSON"));
            }
        });
        req.on("error", reject);
    });
}

async function route(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");

    if (req.method === "OPTIONS") {
        return respond(res, 204, {});
    }

    if (req.method === "GET" && url.pathname === "/") {
        return respond(res, 200, {
            ok: true,
            endpoints: ["POST /routes", "POST /emulate", "POST /send", "GET /openapi.yaml"],
        });
    }

    if (req.method === "GET" && url.pathname === "/openapi.yaml") {
        res.writeHead(200, { "content-type": "text/yaml", "access-control-allow-origin": "*" });
        res.end(fs.readFileSync(path.join(__dirname, "..", "openapi.yaml"), "utf8"));
        return;
    }

    if (req.method === "POST" && url.pathname === "/routes") {
        return respond(res, 200, await routes(await readBody(req)));
    }

    if (req.method === "POST" && url.pathname === "/emulate") {
        return respond(res, 200, await emulate(await readBody(req)));
    }

    if (req.method === "POST" && url.pathname === "/send") {
        return respond(res, 200, await send(await readBody(req)));
    }

    respond(res, 404, { error: `no route ${req.method} ${url.pathname}` });
}

export function createRelayServer(): http.Server {
    return http.createServer((req, res) => {
        route(req, res).catch((error: unknown) => {
            if (error instanceof HttpError) {
                return respond(res, error.status, { error: error.message });
            }
            console.error(`[relay] ${req.method} ${req.url} failed:`, error);
            respond(res, 500, { error: (error as Error).message ?? "internal error" });
        });
    });
}

export function startServer(port: number): Promise<http.Server> {
    const server = createRelayServer();
    return new Promise((resolve) => server.listen(port, () => resolve(server)));
}
