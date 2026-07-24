/**
 * End-to-end smoke test of the relay mock against a running `yarn hardhat node`.
 *
 * Fresh (undelegated) user EOA + undelegated relay, over the HTTP API:
 *   /routes                fee preview across tokens for a path
 *   gasless path=direct    first tx: 7702-authorize the user, one try-batch
 *                          [fee(REQUIRED), user(BREAK_ON_FAIL)] sent straight to the account
 *   gasless path=delegate  relay self-delegates, proxy [userAcc.execute(fee), userAcc.execute(user)]
 *   battery                full sponsorship, direct call, no fee
 *   negative               a spent uuid can't be replayed
 *
 * Run: `yarn hardhat node` in another terminal, then `yarn server:smoke`.
 */

import * as fs from "fs";
import * as path from "path";
import { Contract, ContractFactory, Interface, InterfaceAbi, JsonRpcProvider, NonceManager, Wallet, parseEther, parseUnits } from "ethers";

const RPC = "http://127.0.0.1:8545";
const PORT = 8790;
const BASE = `http://127.0.0.1:${PORT}`;
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const RELAY_ADDRESS = new Wallet(process.env.RELAY_PRIVATE_KEY ?? "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d").address;

function artifact(rel: string): { abi: InterfaceAbi; bytecode: string } {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "artifacts", "contracts", rel), "utf8"));
}

function assert(cond: boolean, message: string): void {
    if (!cond) throw new Error(`ASSERT: ${message}`);
    console.log(`  ok: ${message}`);
}

async function api(method: "GET" | "POST", route: string, body?: unknown): Promise<any> {
    const res = await fetch(BASE + route, {
        method,
        headers: { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await res.json();
    if (!res.ok) throw new Error(`${method} ${route} -> ${res.status}: ${JSON.stringify(json)}`);
    return json;
}

/** Sign a `sign.*` artifact's typed data with the user key → {typedData, signature}. */
async function signArtifact(user: Wallet, artifactPart: any): Promise<{ typedData: any; signature: string }> {
    const { domain, types, message } = artifactPart.typedData;
    return { typedData: artifactPart.typedData, signature: await user.signTypedData(domain, types, message) };
}

const authTuple = (auth: any) => ({
    chainId: auth.chainId.toString(), address: auth.address, nonce: auth.nonce.toString(),
    yParity: auth.signature.yParity, r: auth.signature.r, s: auth.signature.s,
});

async function main(): Promise<void> {
    const provider = new JsonRpcProvider(RPC, 31337, { staticNetwork: true });
    const deployer = new NonceManager(new Wallet(DEPLOYER_KEY, provider));

    const deploy = async (rel: string, ...args: unknown[]): Promise<Contract> => {
        const { abi, bytecode } = artifact(rel);
        const contract = await (await new ContractFactory(abi, bytecode, deployer).deploy(...args)).waitForDeployment() as Contract;
        console.log(`deployed ${rel.split("/").pop()} at ${await contract.getAddress()}`);
        return contract;
    };

    const manager = await deploy("v1/HermesV1.sol/HermesV1.json");
    const delegate = await deploy("v1/HermesDelegateV1.sol/HermesDelegateV1.json", await manager.getAddress());
    const mock = await deploy("mocks/MockERC20.sol/MockERC20.json", "MockUSD", "MUSD");
    const counter = await deploy("mocks/Counter.sol/Counter.json");
    const delegateAddr = await delegate.getAddress();
    const tokenAddr = await mock.getAddress();

    const user = new Wallet(Wallet.createRandom().privateKey, provider);
    await (await deployer.sendTransaction({ to: user.address, value: parseEther("1") })).wait();
    await (await (mock.connect(deployer) as Contract).mint(user.address, parseUnits("1000", 18))).wait();
    console.log(`user EOA ${user.address} funded (no delegation yet); relay ${RELAY_ADDRESS} also undelegated`);

    process.env.LOCAL_TOKEN_ADDRESS = tokenAddr;
    process.env.HERMES_MANAGER_LOCAL = await manager.getAddress();
    process.env.HERMES_DELEGATE_LOCAL = delegateAddr;
    const { startServer } = await import("./index");
    const server = await startServer(PORT);

    try {
        const counterIface = new Interface(["function bump(uint256 by)"]);
        const counterAddr = await counter.getAddress();
        const bump = (n: bigint) => ({ to: counterAddr, value: "0", data: counterIface.encodeFunctionData("bump", [n]) });
        const asset = `local/localhost/erc20/${tokenAddr}`;
        const designator = "0xef0100" + delegateAddr.slice(2).toLowerCase();

        // ── /routes ──
        console.log("\n── POST /routes (path=direct) — fee preview across tokens ──");
        const routes = await api("POST", "/routes", { chain: "local", path: "direct", from: user.address, payloads: [bump(5n)] });
        console.log(`  path=${routes.path}, gas=${routes.gas.estimated} (${routes.gas.source}); ${routes.tokens.map((t: any) => `${t.symbol}=${t.feeFormatted}`).join(", ")}`);
        assert(routes.path === "direct", "routes echoes the path");
        assert(routes.tokens.some((t: any) => t.address.toLowerCase() === tokenAddr.toLowerCase() && BigInt(t.feeAmount) > 0n), "routes prices the fee in the MOCK token");

        // ── gasless path=direct: first tx (one signed try-batch [fee, bump]) ──
        console.log("\n── gasless path=direct: authorize user + direct try-batch [fee(REQUIRED), bump(BREAK_ON_FAIL)] ──");
        const d = await api("POST", "/emulate", { type: "gasless", path: "direct", chain: "local", asset, from: user.address, payloads: [bump(5n)] });
        console.log(`  amount=${d.amountFormatted} MUSD, gas=${d.gas.estimated} (${d.gas.source}, auth=${d.gas.authorizationGas})`);
        assert(d.path === "direct", "emulate echoes path=direct");
        assert(!!d.sign.combined && !d.sign.fee && !d.sign.user, "direct returns a single 'combined' artifact");
        assert(d.sign.combined.typedData.message.calls.length === 2, "combined batch = [fee, bump]");
        assert(d.sign.combined.typedData.message.mode.startsWith("0x0101"), "combined batch is try mode");
        assert(d.account.requiresAuthorization === true, "undelegated user needs authorization");

        const dAuth = await user.authorize({ address: d.account.authorization.address, nonce: d.account.authorization.nonce, chainId: d.account.authorization.chainId });
        const relayBeforeD: bigint = await mock.balanceOf(RELAY_ADDRESS);
        const sentD = await api("POST", "/send", { uuid: d.uuid, combined: await signArtifact(user, d.sign.combined), authorization: authTuple(dAuth) });
        const rD = await provider.waitForTransaction(sentD.tx_hash);
        console.log(`  tx ${sentD.tx_hash}: mode=${sentD.mode}, gasUsed=${rD!.gasUsed} vs quoted=${d.gas.estimated}`);
        assert(rD!.status === 1 && sentD.mode === "direct", "direct gasless mined via a direct call (no relay delegate needed)");
        assert((await provider.getCode(user.address)).toLowerCase() === designator, "user now delegated");
        assert(await counter.value() === 5n, "bump(5) executed");
        assert(await mock.balanceOf(RELAY_ADDRESS) - relayBeforeD === BigInt(d.amount), "relay received exactly the direct-path fee");

        // ── gasless path=delegate: proxy (relay self-delegates) ──
        console.log("\n── gasless path=delegate: relay self-delegates + proxy [fee, bump(7)] ──");
        const g = await api("POST", "/emulate", { type: "gasless", path: "delegate", chain: "local", asset, from: user.address, payloads: [bump(7n)] });
        console.log(`  amount=${g.amountFormatted} MUSD, gas=${g.gas.estimated} (${g.gas.source})`);
        assert(g.path === "delegate", "emulate echoes path=delegate");
        assert(!!g.sign.fee && !!g.sign.user && !g.sign.combined, "delegate returns two artifacts: fee + user");
        assert(BigInt(g.sign.fee.typedData.message.nonce) + 1n === BigInt(g.sign.user.typedData.message.nonce), "user nonce = fee nonce + 1");
        assert(g.account.requiresAuthorization === false, "user already delegated");

        const relayBeforeG: bigint = await mock.balanceOf(RELAY_ADDRESS);
        const sentG = await api("POST", "/send", { uuid: g.uuid, fee: await signArtifact(user, g.sign.fee), user: await signArtifact(user, g.sign.user) });
        const rG = await provider.waitForTransaction(sentG.tx_hash);
        console.log(`  tx ${sentG.tx_hash}: mode=${sentG.mode}, gasUsed=${rG!.gasUsed} vs quoted=${g.gas.estimated}`);
        assert(rG!.status === 1 && sentG.mode === "proxy", "delegate gasless mined via proxy");
        assert((await provider.getCode(RELAY_ADDRESS)).toLowerCase() === designator, "relay self-delegated for the proxy");
        assert(await counter.value() === 12n, "bump(7) executed on top of 5");
        assert(await mock.balanceOf(RELAY_ADDRESS) - relayBeforeG === BigInt(g.amount), "relay received the delegate-path fee");

        // ── battery: full sponsorship, direct call, no fee ──
        console.log("\n── battery: direct call, no fee ──");
        const b = await api("POST", "/emulate", { type: "battery", chain: "local", from: user.address, payloads: [bump(3n)] });
        console.log(`  amount=${b.amountFormatted} ${b.asset.symbol} (virtual), gas=${b.gas.estimated} (${b.gas.source})`);
        assert(!!b.sign.user && !b.sign.fee && !b.sign.combined, "battery returns only the user artifact");
        assert(b.path === undefined, "battery has no path");
        const relayBeforeB: bigint = await mock.balanceOf(RELAY_ADDRESS);
        const sentB = await api("POST", "/send", { uuid: b.uuid, user: await signArtifact(user, b.sign.user) });
        const rB = await provider.waitForTransaction(sentB.tx_hash);
        console.log(`  tx ${sentB.tx_hash}: mode=${sentB.mode}, gasUsed=${rB!.gasUsed} vs quoted=${b.gas.estimated}`);
        assert(rB!.status === 1 && sentB.mode === "direct", "battery mined via direct call");
        assert(await counter.value() === 15n, "bump(3) executed on top of 12");
        assert(await mock.balanceOf(RELAY_ADDRESS) === relayBeforeB, "no token moved in battery mode");

        // ── negative: spent uuid ──
        console.log("\n── negative: spent uuid can't be replayed ──");
        const replay = await fetch(BASE + "/send", {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ uuid: b.uuid, user: await signArtifact(user, b.sign.user) }),
        });
        assert(replay.status === 400, `replay rejected with 400 (${JSON.stringify(await replay.json())})`);

        console.log("\nSMOKE PASSED");
    } finally {
        server.close();
    }
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});
