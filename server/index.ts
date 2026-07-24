/**
 * Hermes relay mock server — entry point.
 *
 * Run: `yarn server` (compile contracts first: `yarn compile`).
 * Layout: http/ (transport) · chain/ (config, encoding, RPC) · relay/ (parse, quotes, fees,
 * emulation, and the /routes /emulate /send handlers).
 */

import { DEFAULT_PORT } from "./config";
import { startServer } from "./http/server";

export { createRelayServer, startServer } from "./http/server";

if (require.main === module) {
    const port = Number(process.env.PORT ?? DEFAULT_PORT);
    startServer(port).then(() => console.log(`Hermes relay mock listening on http://127.0.0.1:${port}`));
}
