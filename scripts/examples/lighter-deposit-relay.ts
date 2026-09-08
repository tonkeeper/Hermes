import { ethers, network } from "hardhat";
import { HDNodeWallet, JsonRpcProvider, type Signer } from "ethers";

/**
 * Cross-chain top-up of Lighter via Relay's cross-chain calls.
 * https://docs.relay.link/references/api/api_guides/calling-integration-guide
 *
 * Same goal as scripts/examples/lighter-deposit-swapxyz.ts (which uses swaps.xyz): pay with a token on a
 * source chain, land USDC on Ethereum, and in the SAME cross-chain action deposit
 * that USDC into Lighter's L1 gateway.
 *
 *   WETH (BSC, chainId 56)  ──relay.link──▶  USDC (ETH, chainId 1)  ──▶  Lighter.deposit(...)
 *
 * How Relay differs from swaps.xyz, in one paragraph: Relay has no `erc20Amount` /
 * `erc20Spender` fields. Destination calls are executed by Relay's Multicaller
 * (Vectorized's), so the USDC lands on the Multicaller and the Multicaller must
 * approve Lighter itself — that approval is a transaction YOU encode as `txs[0]`.
 * The origin-side approval (source token → Relay's ERC20Router) comes back in the
 * response as a `steps[]` entry with `id: "approve"`; you just sign it. There is no
 * API key.
 *
 * Lighter deposit gateway (Ethereum mainnet, writeProxyContract):
 *   0x3b4d794a66304f130a4db8f2551b0070dfcf5ca7
 *   deposit(address _to, uint16 _assetIndex, uint8 _routeType, uint256 _amount) payable
 *   selector 0x8a857083
 *
 * Two flows (FLOW env):
 *   FLOW=deposit        txs = [USDC.approve(Lighter), Lighter.deposit(_to = receiver)]
 *                       No EIP-7702, nothing attached to the user's EOA. This is the
 *                       plain top-up and the one that works today.
 *
 *   FLOW=deposit+pubkey Adds a third tx calling the user's EOA, which an EIP-7702
 *                       `authorizationList` has delegated to HermesDelegateV1, so
 *                       `changePubKey` runs with msg.sender == the user.
 *                       ⚠ BLOCKED until Lighter ships the accountIndex magic number:
 *                       today changePubKey reverts (0x240391a0) for an address with
 *                       no account yet, and the account created by the deposit above
 *                       only exists as a queued L2 priority request at that point.
 *                       See the warning printed by the script.
 *
 * Unlike swaps.xyz, Relay does NOT require the deposit receiver to equal the sender —
 * the Multicaller is msg.sender and Lighter credits the explicit `_to`. The check is
 * kept as an opt-out (ALLOW_THIRD_PARTY_RECEIVER=1) because sending someone else's
 * money into their Lighter account is rarely what you meant.
 *
 * Modes (MODE env; default `quote`):
 *   MODE=quote   Build the txs + fetch the Relay quote and print it. Read-only.
 *   MODE=preview Everything MODE=send does except the broadcast: preflight, then every
 *                transaction that WOULD be signed — decoded, with a real gas estimate and
 *                its cost in the native token. Read-only. Run this before committing funds.
 *   MODE=send    Preview, then execute every step in order, poll to completion, and print a
 *                settlement report: wall-clock timings, what actually left the wallet, what
 *                actually landed in Lighter, and the difference in %.
 *   MODE=status  Re-poll an existing request. Needs REQUEST_ID.
 *
 * Usage:
 *   MODE=quote   yarn hardhat run scripts/examples/lighter-deposit-relay.ts --network bsc
 *   MODE=preview yarn hardhat run scripts/examples/lighter-deposit-relay.ts --network bsc
 *   MODE=send    yarn hardhat run scripts/examples/lighter-deposit-relay.ts --network bsc
 *   MODE=status REQUEST_ID=0x… yarn hardhat run scripts/examples/lighter-deposit-relay.ts --network bsc
 *
 * Env (all optional unless noted):
 *   MODE                 quote | preview | send | status  (default quote)
 *   FLOW                 deposit | deposit+pubkey         (default deposit)
 *   AMOUNT_USDC          USDC to deposit                  (default "5", min 1)
 *   RECEIVER             Lighter _to                      (default sender)
 *   SENDER               sender address for quote mode when no signer is configured
 *   DEPOSIT_MNEMONIC     BIP-39 phrase for the deposit wallet; takes precedence
 *                        over hardhat's DEPLOYER_PRIVATE_KEY account
 *   DEPOSIT_MNEMONIC_INDEX  account index on m/44'/60'/0'/0/<i>   (default 0)
 *   DEPOSIT_MNEMONIC_PATH   full derivation path override (else the index path)
 *   LIGHTER_ASSET_INDEX  USDC asset index in Lighter      (default 3)
 *   LIGHTER_ROUTE_TYPE   route type (0=Perps, 1=Spot)     (default 0)
 *   SLIPPAGE_BPS         slippage tolerance in bps        (default 100 = 1%)
 *   TXS_GAS_LIMIT        destination gas limit for txs    (default 400000, 700000 w/ pubkey)
 *   ETH_RPC_URL          destination RPC for verification (default publicnode)
 *   SRC_TOKEN/SRC_CHAIN_ID, DST_TOKEN/DST_CHAIN_ID, LIGHTER_DEPOSIT to override defaults
 *   RELAY_API            override https://api.relay.link
 *   RELAY_REFERRER       referrer tag sent with the quote
 *   USE_QUOTED_FEES=1    send with Relay's maxFeePerGas instead of the node's estimate
 *   ALLOW_THIRD_PARTY_RECEIVER=1   permit RECEIVER != sender
 *
 * FLOW=deposit+pubkey additionally needs:
 *   HERMES_DELEGATE      HermesDelegateV1 address on the destination chain (required)
 *   LIGHTER_PUBKEY       40-byte Poseidon-Schnorr pubkey, 0x-prefixed        (required)
 *   LIGHTER_API_KEY_INDEX  api key slot                  (default 1)
 *   LIGHTER_ACCOUNT_INDEX  accountIndex passed to changePubKey (default 0 = the
 *                        placeholder for Lighter's upcoming msg.sender magic number)
 */

// ── Constants ────────────────────────────────────────────────────────────────
const RELAY_API = process.env.RELAY_API ?? "https://api.relay.link";
const QUOTE_PATH = "/quote/v2";

// Lighter L1 deposit gateway on Ethereum (ZkLighter proxy → impl). deposit() pulls the
// token via safeTransferFrom(msg.sender, ...) — under Relay, msg.sender is the Multicaller,
// which is why txs[0] has to approve this gateway. On-chain assetConfigs(3) (USDC):
// token 0xA0b8…eB48, minDeposit 1_000_000 (1 USDC), so AMOUNT_USDC must be ≥ 1.
const LIGHTER_DEPOSIT = "0x3b4d794a66304f130a4db8f2551b0070dfcf5ca7";
const LIGHTER_ABI = [
  "function deposit(address _to, uint16 _assetIndex, uint8 _routeType, uint256 _amount) payable",
  "function changePubKey(uint48 _accountIndex, uint8 _apiKeyIndex, bytes _pubKey)",
  "function addressToAccountIndex(address) view returns (uint48)",
];
const DEPOSIT_SELECTOR = "0x8a857083"; // deposit(address,uint16,uint8,uint256)
const CHANGE_PUBKEY_SELECTOR = "0x17010c68"; // changePubKey(uint48,uint8,bytes)

// Cross-chain leg: pay with WETH on BSC, deliver USDC on Ethereum.
const SRC_CHAIN_ID = 56; // BSC
const DST_CHAIN_ID = 1; // Ethereum
const WETH_BSC = "0x2170Ed0880ac9A755fd29B2688956BD959F933F8"; // Binance-Peg ETH ("WETH" on BSC)
const USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // native USDC on Ethereum
const USDC_DECIMALS = 6;

const NATIVE = "0x0000000000000000000000000000000000000000";
const NATIVE_ALT = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
];

// HermesDelegateV1 is an ERC-7821 executor: execute(bytes32 mode, bytes executionData).
// Mode 0x01..00 is the plain batch mode; the signature travels inside executionData in
// the opData variant, which is what a relayer-submitted batch uses.
const HERMES_DELEGATE_ABI = ["function execute(bytes32 mode, bytes executionData) payable"];
const ERC7821_BATCH_MODE = "0x0100000000000000000000000000000000000000000000000000000000000000";

// Relay marks a request finished with one of these; everything else means keep polling.
const TERMINAL_OK = new Set(["success"]);
const TERMINAL_BAD = new Set(["failure", "refund"]);

const erc20Iface = new ethers.Interface(ERC20_ABI);
const lighterIface = new ethers.Interface(LIGHTER_ABI);
const delegateIface = new ethers.Interface(HERMES_DELEGATE_ABI);

// ── Config from env ──────────────────────────────────────────────────────────
const withPubKey = (process.env.FLOW ?? "deposit").toLowerCase() === "deposit+pubkey";

const cfg = {
  mode: (process.env.MODE ?? "quote").toLowerCase(),
  flow: withPubKey ? "deposit+pubkey" : "deposit",
  amountUsdc: process.env.AMOUNT_USDC ?? "5",
  assetIndex: Number(process.env.LIGHTER_ASSET_INDEX ?? "3"), // USDC_ASSET_INDEX on Lighter (verified on-chain)
  routeType: Number(process.env.LIGHTER_ROUTE_TYPE ?? "0"), // TxTypes.RouteType: 0 = Perps, 1 = Spot
  slippageBps: Number(process.env.SLIPPAGE_BPS ?? "100"),
  srcToken: process.env.SRC_TOKEN ?? WETH_BSC,
  srcChainId: Number(process.env.SRC_CHAIN_ID ?? String(SRC_CHAIN_ID)),
  dstToken: process.env.DST_TOKEN ?? USDC_ETH,
  dstChainId: Number(process.env.DST_CHAIN_ID ?? String(DST_CHAIN_ID)),
  lighter: process.env.LIGHTER_DEPOSIT ?? LIGHTER_DEPOSIT,
  receiver: process.env.RECEIVER,
  txsGasLimit: Number(process.env.TXS_GAS_LIMIT ?? (withPubKey ? "700000" : "400000")),
  ethRpcUrl: process.env.ETH_RPC_URL ?? "https://ethereum-rpc.publicnode.com",
  referrer: process.env.RELAY_REFERRER,
  useQuotedFees: process.env.USE_QUOTED_FEES === "1",
  allowThirdPartyReceiver: process.env.ALLOW_THIRD_PARTY_RECEIVER === "1",
  // FLOW=deposit+pubkey only
  delegate: process.env.HERMES_DELEGATE,
  pubKey: process.env.LIGHTER_PUBKEY,
  apiKeyIndex: Number(process.env.LIGHTER_API_KEY_INDEX ?? "1"),
  accountIndex: Number(process.env.LIGHTER_ACCOUNT_INDEX ?? "0"),
};

const isNative = (t: string) =>
  t.toLowerCase() === NATIVE || t.toLowerCase() === NATIVE_ALT;

// ── Calldata ─────────────────────────────────────────────────────────────────
/** Encode Lighter's deposit(...) and assert the selector still matches 0x8a857083. */
function buildDepositCalldata(
  to: string,
  assetIndex: number,
  routeType: number,
  amount: bigint
): string {
  const data = lighterIface.encodeFunctionData("deposit", [to, assetIndex, routeType, amount]);
  assertSelector(data, DEPOSIT_SELECTOR, "deposit(address,uint16,uint8,uint256)");
  return data;
}

/** Encode Lighter's changePubKey(...) and assert the selector still matches 0x17010c68. */
function buildChangePubKeyCalldata(
  accountIndex: number,
  apiKeyIndex: number,
  pubKey: string
): string {
  const data = lighterIface.encodeFunctionData("changePubKey", [accountIndex, apiKeyIndex, pubKey]);
  assertSelector(data, CHANGE_PUBKEY_SELECTOR, "changePubKey(uint48,uint8,bytes)");
  return data;
}

function assertSelector(data: string, expected: string, signature: string): void {
  const selector = data.slice(0, 10).toLowerCase();
  if (selector !== expected) {
    throw new Error(
      `${signature} selector drifted: built ${selector}, expected ${expected}. ` +
        `The ABI no longer matches Lighter's on-chain interface.`
    );
  }
}

/** Wrap calls into HermesDelegateV1.execute(batchMode, executionData). */
function buildDelegateExecuteCalldata(calls: { to: string; value: bigint; data: string }[]): string {
  const executionData = ethers.AbiCoder.defaultAbiCoder().encode(
    ["tuple(address,uint256,bytes)[]"],
    [calls.map((c) => [c.to, c.value, c.data])]
  );
  return delegateIface.encodeFunctionData("execute", [ERC7821_BATCH_MODE, executionData]);
}

type RelayTx = { to: string; value: string; data: string };

/**
 * The destination transactions Relay's Multicaller runs in order, after it has been
 * handed `amount` of dstToken. txs[0] is the approval the Multicaller grants Lighter —
 * Relay has no erc20Spender field, this IS that field.
 */
function buildTxs(receiver: string, amount: bigint): RelayTx[] {
  const txs: RelayTx[] = [
    {
      to: cfg.dstToken,
      value: "0",
      data: erc20Iface.encodeFunctionData("approve", [cfg.lighter, amount]),
    },
    {
      to: cfg.lighter,
      value: "0",
      data: buildDepositCalldata(receiver, cfg.assetIndex, cfg.routeType, amount),
    },
  ];

  if (!withPubKey) return txs;

  if (!cfg.delegate) throw new Error("FLOW=deposit+pubkey needs HERMES_DELEGATE (delegate address on the destination chain).");
  if (!cfg.pubKey) throw new Error("FLOW=deposit+pubkey needs LIGHTER_PUBKEY (0x-prefixed 40-byte pubkey).");
  if (ethers.dataLength(cfg.pubKey) !== 40) {
    throw new Error(`LIGHTER_PUBKEY must be 40 bytes, got ${ethers.dataLength(cfg.pubKey)}.`);
  }

  // Runs inside the user's EOA once the 7702 authorization has delegated it, so
  // Lighter sees msg.sender == receiver rather than the Multicaller.
  txs.push({
    to: receiver,
    value: "0",
    data: buildDelegateExecuteCalldata([
      {
        to: cfg.lighter,
        value: 0n,
        data: buildChangePubKeyCalldata(cfg.accountIndex, cfg.apiKeyIndex, cfg.pubKey),
      },
    ]),
  });
  return txs;
}

// ── EIP-7702 authorization ───────────────────────────────────────────────────
type Authorization = {
  chainId: number;
  address: string;
  nonce: number;
  yParity: number;
  r: string;
  s: string;
};

/**
 * Sign the authorization that delegates the user's EOA to HermesDelegateV1 on the
 * DESTINATION chain. Relay's solver includes it in the type-4 fill transaction.
 *
 * The nonce is the EOA's current nonce on the destination chain: the solver sends the
 * transaction, not the user, so the authority's nonce is untouched at execution time.
 * That also makes it fragile — any mainnet transaction the user sends between signing
 * and the fill invalidates this authorization, and Relay cannot re-sign it.
 */
async function signAuthorization(signer: Signer, receiver: string): Promise<Authorization> {
  const authorizer = signer as Signer & {
    authorize?: (a: { address: string; chainId: number; nonce: number }) => Promise<any>;
  };
  if (typeof authorizer.authorize !== "function") {
    throw new Error(
      "The configured signer cannot sign EIP-7702 authorizations. FLOW=deposit+pubkey needs " +
        "DEPOSIT_MNEMONIC (an ethers Wallet), not a hardhat network account."
    );
  }

  const dstProvider = new JsonRpcProvider(cfg.ethRpcUrl, cfg.dstChainId);
  const nonce = await dstProvider.getTransactionCount(receiver, "latest");
  const auth = await authorizer.authorize({
    address: cfg.delegate!,
    chainId: cfg.dstChainId,
    nonce,
  });
  return {
    chainId: Number(auth.chainId),
    address: auth.address,
    nonce: Number(auth.nonce),
    yParity: auth.signature.yParity,
    r: auth.signature.r,
    s: auth.signature.s,
  };
}

// ── Relay API ────────────────────────────────────────────────────────────────
async function getQuote(body: Record<string, unknown>): Promise<any> {
  const res = await fetch(`${RELAY_API}${QUOTE_PATH}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`relay ${QUOTE_PATH} ${res.status} ${res.statusText}: ${text}`);
  }
  return JSON.parse(text);
}

/** `endpoint` arrives relative, e.g. "/intents/status/v3?requestId=0x…". */
async function getStatus(endpoint: string): Promise<any> {
  const res = await fetch(`${RELAY_API}${endpoint}`);
  const text = await res.text();
  if (!res.ok) throw new Error(`relay ${endpoint} ${res.status} ${res.statusText}: ${text}`);
  return JSON.parse(text);
}

/** Poll until Relay reports a terminal status. Statuses: waiting/depositing/pending/submitted → success|failure|refund. */
async function pollUntilDone(endpoint: string, timeoutMs = 15 * 60_000): Promise<any> {
  const started = Date.now();
  let last = "";
  for (;;) {
    const status = await getStatus(endpoint);
    const state = String(status.status ?? "unknown");
    if (state !== last) {
      console.log(`  status ${state}${status.details ? ` (${status.details})` : ""}`);
      last = state;
    }
    if (TERMINAL_OK.has(state)) return status;
    if (TERMINAL_BAD.has(state)) {
      throw new Error(`Relay reported ${state}: ${JSON.stringify(status)}`);
    }
    if (Date.now() - started > timeoutMs) {
      throw new Error(`Timed out after ${timeoutMs / 1000}s waiting on ${endpoint} (last status ${state}).`);
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

function fmtFee(f: any): string {
  if (!f) return "—";
  return `${f.amountFormatted} ${f.currency?.symbol ?? ""} ($${f.amountUsd})`.trim();
}

// ── Cross-chain flow (quote / send) ──────────────────────────────────────────
type Action = "quote" | "preview" | "send";

async function runRelayFlow(signer: Signer | undefined, action: Action): Promise<void> {
  const send = action === "send";
  const signerAddress = signer ? await signer.getAddress() : undefined;
  const sender = process.env.SENDER ?? signerAddress;
  if (!sender) {
    throw new Error("No signer and no SENDER set. Provide DEPOSIT_MNEMONIC / DEPLOYER_PRIVATE_KEY or SENDER.");
  }
  // SENDER is a convenience for quoting without a wallet. Quoting for one address and
  // broadcasting from another produces a quote whose steps the signer cannot fill.
  if (send && signerAddress && sender.toLowerCase() !== signerAddress.toLowerCase()) {
    throw new Error(
      `SENDER ${sender} != signer ${signerAddress}. Unset SENDER to send from the configured wallet.`
    );
  }
  const receiver = cfg.receiver ?? sender;

  // Relay does not require this (Lighter credits the explicit _to and the Multicaller is
  // msg.sender either way) — but depositing into someone else's Lighter account is almost
  // never intended, so it stays on by default.
  if (!cfg.allowThirdPartyReceiver && receiver.toLowerCase() !== sender.toLowerCase()) {
    throw new Error(
      `receiver ${receiver} != sender ${sender}. Set ALLOW_THIRD_PARTY_RECEIVER=1 if that is deliberate.`
    );
  }

  const amount = ethers.parseUnits(cfg.amountUsdc, USDC_DECIMALS);
  const txs = buildTxs(receiver, amount);

  const body: Record<string, unknown> = {
    user: sender,
    recipient: receiver, // surplus / refunds on the destination chain
    originChainId: cfg.srcChainId,
    originCurrency: cfg.srcToken,
    destinationChainId: cfg.dstChainId,
    destinationCurrency: cfg.dstToken,
    amount: amount.toString(),
    tradeType: "EXACT_OUTPUT", // txs[] hardcode `amount`, so the delivered amount must be exact
    refundTo: sender,
    slippageTolerance: String(cfg.slippageBps),
    txsGasLimit: cfg.txsGasLimit,
    txs,
  };
  if (cfg.referrer) body.referrer = cfg.referrer;

  if (withPubKey) {
    if (!signer) throw new Error("FLOW=deposit+pubkey needs a signer to produce the EIP-7702 authorization.");
    console.log("⚠ FLOW=deposit+pubkey is not expected to work yet.");
    console.log("  changePubKey reverts (0x240391a0) for an address with no Lighter account, and the");
    console.log("  account this batch creates is still only a queued L2 priority request at that point.");
    console.log("  Waiting on Lighter's accountIndex magic-number build. Quote away, but do not MODE=send.\n");
    body.authorizationList = [await signAuthorization(signer, receiver)];
  }

  console.log(`Relay cross-chain call — ${cfg.srcToken} (chain ${cfg.srcChainId}) → USDC (chain ${cfg.dstChainId}) → Lighter.deposit\n`);
  console.log(`  flow             ${cfg.flow}`);
  console.log(`  sender           ${sender}`);
  console.log(`  receiver (_to)   ${receiver}`);
  console.log(`  amount           ${cfg.amountUsdc} USDC (${amount})`);
  console.log(`  lighter          ${cfg.lighter}`);
  console.log(`  assetIndex       ${cfg.assetIndex}   routeType ${cfg.routeType}   slippage ${cfg.slippageBps}bps`);
  console.log(`  txsGasLimit      ${cfg.txsGasLimit}`);
  txs.forEach((t, i) => console.log(`  txs[${i}]          ${t.to}  ${t.data.slice(0, 10)}  (${(t.data.length - 2) / 2} bytes)`));
  if (body.authorizationList) {
    const a = (body.authorizationList as Authorization[])[0];
    console.log(`  7702 delegate    ${a.address}  (chainId ${a.chainId}, nonce ${a.nonce})`);
  }
  console.log();

  const quote = await getQuote(body);

  console.log("Quote:");
  console.log(`  requestId        ${quote.requestId}`);
  console.log(`  steps            ${(quote.steps ?? []).map((s: any) => `${s.id}(${s.kind})`).join(" -> ") || "—"}`);
  console.log(`  currencyIn       ${fmtFee(quote.details?.currencyIn)}`);
  console.log(`  currencyOut      ${fmtFee(quote.details?.currencyOut)}`);
  console.log(`  rate             ${quote.details?.rate ?? "—"}`);
  console.log(`  est. time        ${quote.details?.timeEstimate ?? "—"}s`);
  console.log(`  fees.gas         ${fmtFee(quote.fees?.gas)}`);
  console.log(`  fees.relayerGas  ${fmtFee(quote.fees?.relayerGas)}`);
  console.log(`  fees.relayerSvc  ${fmtFee(quote.fees?.relayerService)}`);
  console.log(`  origin router    ${quote.details?.route?.origin?.router ?? "—"}\n`);

  if (action === "quote") {
    console.log("MODE=quote — not broadcasting. Run MODE=preview to see the exact transactions.");
    return;
  }
  if (!signer) {
    throw new Error(`MODE=${action} needs a signer. Set DEPOSIT_MNEMONIC (or DEPLOYER_PRIVATE_KEY) and run with --network <src>.`);
  }
  if (!Array.isArray(quote.steps) || quote.steps.length === 0) {
    throw new Error(`Unexpected response: no steps. Full body:\n${JSON.stringify(quote, null, 2)}`);
  }

  const net = await ethers.provider.getNetwork();
  if (Number(net.chainId) !== cfg.srcChainId) {
    throw new Error(
      `Connected to chain ${net.chainId} but the source chain is ${cfg.srcChainId}. ` +
        `Run with --network for the source chain (e.g. --network bsc).`
    );
  }

  await preflight(signer, sender, quote);
  const prices = derivePrices(quote);
  await previewTransactions(signer, sender, quote, txs, amount, prices);

  if (!send) {
    console.log("MODE=preview — nothing was broadcast. Re-run with MODE=send to execute.");
    return;
  }

  const before = await snapshotBalances(sender);
  const startedAt = Date.now();
  const telemetry = await executeSteps(signer, quote);
  const after = await snapshotBalances(sender);

  await settlementReport({ sender, receiver, quote, prices, before, after, telemetry, startedAt });
  await verifyOutcome(receiver);
}

// ── Prices ───────────────────────────────────────────────────────────────────
/**
 * Every USD figure in this script comes from the quote Relay just returned — its own
 * pricing, not an independent oracle. Derive unit prices so on-chain deltas measured
 * afterwards can be valued on the same basis the quote used.
 */
type Prices = { srcUsd: number; dstUsd: number; nativeUsd: number };

function unitPrice(f: any): number {
  const amount = Number(f?.amountFormatted ?? 0);
  const usd = Number(f?.amountUsd ?? 0);
  return amount > 0 ? usd / amount : 0;
}

function derivePrices(quote: any): Prices {
  return {
    srcUsd: unitPrice(quote.details?.currencyIn),
    dstUsd: unitPrice(quote.details?.currencyOut),
    nativeUsd: unitPrice(quote.fees?.gas),
  };
}

const usd = (v: number) => (Number.isFinite(v) ? `$${v.toFixed(6)}` : "—");

// ── Token metadata ───────────────────────────────────────────────────────────
type TokenMeta = { symbol: string; decimals: number };

async function tokenMeta(address: string, provider: any, nativeSymbol: string): Promise<TokenMeta> {
  if (isNative(address)) return { symbol: nativeSymbol, decimals: 18 };
  try {
    const c = new ethers.Contract(address, ERC20_ABI, provider);
    const [symbol, decimals] = await Promise.all([c.symbol(), c.decimals()]);
    return { symbol, decimals: Number(decimals) };
  } catch {
    return { symbol: "?", decimals: 18 };
  }
}

// ── Preview ──────────────────────────────────────────────────────────────────
/** Best-effort human rendering of calldata we recognise; raw selector otherwise. */
function decodeCall(to: string, data: string, amountDecimals: number): string {
  const selector = data.slice(0, 10).toLowerCase();
  try {
    if (selector === "0x095ea7b3") {
      const [spender, value] = erc20Iface.decodeFunctionData("approve", data);
      return `approve(spender=${spender}, amount=${ethers.formatUnits(value, amountDecimals)})`;
    }
    if (selector === DEPOSIT_SELECTOR) {
      const [to_, assetIndex, routeType, amount] = lighterIface.decodeFunctionData("deposit", data);
      return `deposit(_to=${to_}, _assetIndex=${assetIndex}, _routeType=${routeType}, _amount=${ethers.formatUnits(amount, amountDecimals)})`;
    }
    if (selector === "0xe9ae5c53") {
      return `execute(bytes32 mode, bytes executionData)  [ERC-7821 batch → ${to}]`;
    }
  } catch {
    /* fall through to the raw form */
  }
  return `${selector}  (${(data.length - 2) / 2} bytes, not decoded)`;
}

/**
 * Print exactly what would be signed, before anything is signed. Gas is estimated against
 * the live node; the deposit step usually cannot be estimated yet because it spends an
 * allowance the approve step has not granted, so Relay's own gas figure is used and marked.
 */
async function previewTransactions(
  signer: Signer,
  sender: string,
  quote: any,
  txs: RelayTx[],
  amount: bigint,
  prices: Prices
): Promise<void> {
  const provider = ethers.provider;
  const net = await provider.getNetwork();
  const nativeSymbol = cfg.srcChainId === 56 ? "BNB" : "ETH";
  const src = await tokenMeta(cfg.srcToken, provider, nativeSymbol);
  const dstProvider = new JsonRpcProvider(cfg.ethRpcUrl, cfg.dstChainId);
  const dst = await tokenMeta(cfg.dstToken, dstProvider, "ETH");

  const feeData = await provider.getFeeData();
  const gasPrice = feeData.maxFeePerGas ?? feeData.gasPrice ?? 0n;

  console.log("═".repeat(78));
  console.log(`TRANSACTIONS TO BE SIGNED — origin chain ${net.chainId} (${network.name})`);
  console.log("═".repeat(78));

  let totalGas = 0n;
  let i = 0;
  for (const step of quote.steps as any[]) {
    for (const item of step.items ?? []) {
      if (item.status === "complete") continue;
      const tx = item.data;
      let estimated: bigint | null = null;
      try {
        estimated = await provider.estimateGas({ from: sender, to: tx.to, data: tx.data, value: BigInt(tx.value ?? "0") });
      } catch {
        estimated = null;
      }
      const gasLimit = tx.gas ? BigInt(tx.gas) : estimated ?? 0n;
      const cost = gasLimit * gasPrice;
      totalGas += cost;

      console.log(`\n[${++i}] step "${step.id}" — ${step.description ?? ""}`);
      console.log(`    to        ${tx.to}`);
      console.log(`    value     ${ethers.formatEther(BigInt(tx.value ?? "0"))} ${nativeSymbol}`);
      console.log(`    calldata  ${decodeCall(tx.to, tx.data, src.decimals)}`);
      console.log(`    gasLimit  ${gasLimit}  (${estimated !== null ? `node estimate ${estimated}` : "node estimate unavailable — needs the prior approve; using Relay's figure"})`);
      console.log(`    gas cost  ~${ethers.formatEther(cost)} ${nativeSymbol}  ${usd(Number(ethers.formatEther(cost)) * prices.nativeUsd)}`);
    }
  }

  console.log(`\n${"─".repeat(78)}`);
  console.log(`DESTINATION BATCH — chain ${cfg.dstChainId}, run by Relay's Multicaller, paid by the solver`);
  console.log("─".repeat(78));
  txs.forEach((t, n) => {
    console.log(`\n[d${n + 1}] to        ${t.to}`);
    console.log(`     calldata  ${decodeCall(t.to, t.data, dst.decimals)}`);
  });

  const inAmount = Number(quote.details?.currencyIn?.amountFormatted ?? 0);
  const outAmount = Number(quote.details?.currencyOut?.amountFormatted ?? 0);
  const gasNative = Number(ethers.formatEther(totalGas));
  const paidUsd = inAmount * prices.srcUsd + gasNative * prices.nativeUsd;
  const gotUsd = outAmount * prices.dstUsd;

  console.log(`\n${"═".repeat(78)}`);
  console.log("EXPECTED — quoted, before execution");
  console.log("═".repeat(78));
  console.log(`  OUT  ${inAmount} ${src.symbol} — ${cfg.srcToken} on chain ${cfg.srcChainId}`);
  console.log(`       ${usd(inAmount * prices.srcUsd)}`);
  console.log(`     + ${gasNative} ${nativeSymbol} origin gas   ${usd(gasNative * prices.nativeUsd)}`);
  console.log(`     = total leaving the wallet      ${usd(paidUsd)}`);
  console.log(`  IN   ${outAmount} ${dst.symbol} — ${cfg.dstToken} on chain ${cfg.dstChainId}`);
  console.log(`       ${usd(gotUsd)}, deposited into Lighter for ${quote.details?.recipient ?? "—"}`);
  console.log(`  DIFF ${usd(gotUsd - paidUsd)}  (${(((gotUsd - paidUsd) / paidUsd) * 100).toFixed(2)}%)`);
  console.log(`       amount deposited is exact (${ethers.formatUnits(amount, dst.decimals)} ${dst.symbol}) — EXACT_OUTPUT`);
  console.log("═".repeat(78) + "\n");
}

/**
 * Make sure the wallet can pay before spending gas: srcToken >= currencyIn (Relay quotes
 * EXACT_OUTPUT, so currencyIn is what the deposit step will pull) and native > the sum of
 * step values, which for a native origin is the whole input amount.
 */
async function preflight(signer: Signer, sender: string, quote: any): Promise<void> {
  const needed = BigInt(quote.details?.currencyIn?.amount ?? "0");
  const stepValue = (quote.steps as any[]).reduce(
    (acc, s) => acc + s.items.reduce((a: bigint, i: any) => a + BigInt(i.data?.value ?? "0"), 0n),
    0n
  );
  const nativeBal = await ethers.provider.getBalance(sender);

  if (!isNative(cfg.srcToken)) {
    const srcErc20 = new ethers.Contract(cfg.srcToken, ERC20_ABI, signer);
    const bal: bigint = await srcErc20.balanceOf(sender);
    if (bal < needed) {
      throw new Error(
        `Insufficient srcToken on chain ${cfg.srcChainId}: have ${bal}, need ${needed} (currencyIn) of ${cfg.srcToken}. Fund the wallet and retry.`
      );
    }
  }
  if (nativeBal <= stepValue) {
    throw new Error(
      `Insufficient native gas token on chain ${cfg.srcChainId}: have ${nativeBal}, need > ${stepValue} (step values) plus gas. Top up native balance.`
    );
  }
  console.log(`Preflight OK — native ${nativeBal}, srcToken ${isNative(cfg.srcToken) ? "(native)" : `>= ${needed}`}.\n`);
}

/**
 * Walk the steps in order. Relay returns the origin-side approval as its own step when
 * the allowance is short, so there is no requiresTokenApproval flag to read — the
 * presence of the step IS the flag. Every item carries a ready-to-send transaction;
 * items with a `check` need polling before the request counts as filled.
 */
type StepTelemetry = {
  id: string;
  hash: string;
  gasUsed: bigint;
  gasCost: bigint;
  broadcastMs: number; // broadcast → mined
};
type Telemetry = {
  steps: StepTelemetry[];
  fillMs: number | null; // last origin tx mined → Relay reports success
  destinationTxHashes: string[];
};

async function executeSteps(signer: Signer, quote: any): Promise<Telemetry> {
  const telemetry: Telemetry = { steps: [], fillMs: null, destinationTxHashes: [] };

  for (const step of quote.steps as any[]) {
    for (const item of step.items ?? []) {
      if (item.status === "complete") {
        console.log(`Step ${step.id}: already complete, skipping.`);
        continue;
      }
      if (step.kind !== "transaction") {
        throw new Error(
          `Step ${step.id} is kind "${step.kind}", which this script does not handle. ` +
            `Signature steps need /execute/permits. Full step:\n${JSON.stringify(step, null, 2)}`
        );
      }

      const tx = item.data;
      console.log(`Step ${step.id}: ${step.description ?? ""}`);
      console.log(`  to ${tx.to}  value ${tx.value ?? "0"}  data ${tx.data.slice(0, 10)}…`);

      const request: Record<string, unknown> = {
        to: tx.to,
        data: tx.data,
        value: BigInt(tx.value ?? "0"),
      };
      if (tx.gas) request.gasLimit = BigInt(tx.gas);
      // Relay's fee numbers can be stale (it quoted 0.05 gwei on BSC); default to the
      // node's own estimate and only trust the quote when explicitly asked.
      if (cfg.useQuotedFees && tx.maxFeePerGas) {
        request.maxFeePerGas = BigInt(tx.maxFeePerGas);
        request.maxPriorityFeePerGas = BigInt(tx.maxPriorityFeePerGas ?? tx.maxFeePerGas);
      }

      const broadcastAt = Date.now();
      const sent = await signer.sendTransaction(request);
      console.log(`  sent ${sent.hash}`);
      const receipt = await sent.wait();
      if (receipt?.status !== 1) {
        throw new Error(`Step ${step.id} transaction ${sent.hash} reverted.`);
      }
      const minedAt = Date.now();
      const gasCost = receipt.gasUsed * (receipt.gasPrice ?? 0n);
      console.log(`  mined in block ${receipt.blockNumber} after ${((minedAt - broadcastAt) / 1000).toFixed(1)}s`);
      console.log(`  gasUsed ${receipt.gasUsed}  cost ${ethers.formatEther(gasCost)}`);
      telemetry.steps.push({
        id: step.id,
        hash: sent.hash,
        gasUsed: receipt.gasUsed,
        gasCost,
        broadcastMs: minedAt - broadcastAt,
      });

      if (item.check?.endpoint) {
        const final = await pollUntilDone(item.check.endpoint);
        telemetry.fillMs = Date.now() - minedAt;
        for (const h of final.txHashes ?? []) {
          telemetry.destinationTxHashes.push(h);
          console.log(`  destination tx ${h}`);
        }
        console.log(`  filled ${(telemetry.fillMs / 1000).toFixed(1)}s after the origin tx was mined`);
      }
      console.log();
    }
  }
  console.log("All steps complete.\n");
  return telemetry;
}

// ── Settlement ───────────────────────────────────────────────────────────────
type Balances = { native: bigint; srcToken: bigint };

async function snapshotBalances(sender: string): Promise<Balances> {
  const native = await ethers.provider.getBalance(sender);
  const srcToken = isNative(cfg.srcToken)
    ? 0n
    : await new ethers.Contract(cfg.srcToken, ERC20_ABI, ethers.provider).balanceOf(sender);
  return { native, srcToken };
}

const TRANSFER_TOPIC = ethers.id("Transfer(address,address,uint256)");

/**
 * How much of dstToken actually reached the Lighter gateway, read from the destination
 * fill transaction rather than from the quote — the quote is a promise, the logs are fact.
 */
async function readDelivered(txHashes: string[]): Promise<{ amount: bigint; txHash: string } | null> {
  if (txHashes.length === 0) return null;
  const dst = new JsonRpcProvider(cfg.ethRpcUrl, cfg.dstChainId);
  const lighterTopic = ethers.zeroPadValue(cfg.lighter, 32).toLowerCase();
  const tokenAddr = cfg.dstToken.toLowerCase();

  for (const hash of txHashes) {
    const receipt = await dst.getTransactionReceipt(hash);
    if (!receipt) continue;
    let total = 0n;
    for (const log of receipt.logs) {
      if (log.address.toLowerCase() !== tokenAddr) continue;
      if (log.topics[0] !== TRANSFER_TOPIC) continue;
      if (log.topics[2]?.toLowerCase() !== lighterTopic) continue; // to == Lighter gateway
      total += BigInt(log.data);
    }
    if (total > 0n) return { amount: total, txHash: hash };
  }
  return null;
}

/**
 * What it cost, what arrived, and the gap — measured from on-chain deltas and the fill
 * transaction's logs. USD uses the quote's own unit prices (see derivePrices).
 */
async function settlementReport(args: {
  sender: string;
  receiver: string;
  quote: any;
  prices: Prices;
  before: Balances;
  after: Balances;
  telemetry: Telemetry;
  startedAt: number;
}): Promise<void> {
  const { quote, prices, before, after, telemetry, startedAt } = args;
  const nativeSymbol = cfg.srcChainId === 56 ? "BNB" : "ETH";
  const src = await tokenMeta(cfg.srcToken, ethers.provider, nativeSymbol);
  const dstProvider = new JsonRpcProvider(cfg.ethRpcUrl, cfg.dstChainId);
  const dst = await tokenMeta(cfg.dstToken, dstProvider, "ETH");

  const gasSpent = telemetry.steps.reduce((a, s) => a + s.gasCost, 0n);
  const srcSpent = isNative(cfg.srcToken)
    ? before.native - after.native - gasSpent
    : before.srcToken - after.srcToken;

  const delivered = await readDelivered(telemetry.destinationTxHashes);

  const srcSpentNum = Number(ethers.formatUnits(srcSpent, src.decimals));
  const gasNum = Number(ethers.formatEther(gasSpent));
  const deliveredNum = delivered ? Number(ethers.formatUnits(delivered.amount, dst.decimals)) : 0;

  const outUsd = srcSpentNum * prices.srcUsd + gasNum * prices.nativeUsd;
  const inUsd = deliveredNum * prices.dstUsd;
  const totalMs = Date.now() - startedAt;

  console.log("═".repeat(78));
  console.log("SETTLEMENT REPORT");
  console.log("═".repeat(78));

  console.log("\nTIMING");
  for (const s of telemetry.steps) {
    console.log(`  ${s.id.padEnd(8)} broadcast → mined   ${(s.broadcastMs / 1000).toFixed(1)}s   ${s.hash}`);
  }
  if (telemetry.fillMs !== null) {
    console.log(`  fill     mined → success      ${(telemetry.fillMs / 1000).toFixed(1)}s`);
  }
  console.log(`  TOTAL    wall clock           ${(totalMs / 1000).toFixed(1)}s   (quoted estimate ${quote.details?.timeEstimate ?? "—"}s)`);

  console.log("\nOUT — left the wallet on chain " + cfg.srcChainId);
  console.log(`  ${src.symbol.padEnd(6)} ${ethers.formatUnits(srcSpent, src.decimals).padEnd(24)} ${usd(srcSpentNum * prices.srcUsd)}`);
  console.log(`  ${nativeSymbol.padEnd(6)} ${ethers.formatEther(gasSpent).padEnd(24)} ${usd(gasNum * prices.nativeUsd)}   (gas, ${telemetry.steps.length} tx)`);
  console.log(`  ${"TOTAL".padEnd(6)} ${"".padEnd(24)} ${usd(outUsd)}`);

  console.log("\nIN — credited on chain " + cfg.dstChainId);
  if (delivered) {
    console.log(`  ${dst.symbol.padEnd(6)} ${ethers.formatUnits(delivered.amount, dst.decimals).padEnd(24)} ${usd(inUsd)}`);
    console.log(`  into   ${cfg.lighter}  (Lighter gateway)`);
    console.log(`  _to    ${args.receiver}  assetIndex ${cfg.assetIndex}  routeType ${cfg.routeType}`);
    console.log(`  tx     ${delivered.txHash}`);
  } else {
    console.log("  ⚠ could not read the destination transfer — check the fill tx manually:");
    for (const h of telemetry.destinationTxHashes) console.log(`    ${h}`);
  }

  const diffUsd = inUsd - outUsd;
  const diffPct = outUsd > 0 ? (diffUsd / outUsd) * 100 : NaN;
  console.log("\nDIFFERENCE");
  console.log(`  ${usd(diffUsd)}   ${Number.isFinite(diffPct) ? `${diffPct.toFixed(2)}%` : "—"}   (in − out, relative to out)`);
  console.log(`  USD priced from this quote: ${src.symbol} ${usd(prices.srcUsd)}, ${dst.symbol} ${usd(prices.dstUsd)}, ${nativeSymbol} ${usd(prices.nativeUsd)}`);
  console.log("═".repeat(78) + "\n");
}

/**
 * Read back what actually happened on the destination chain. This is the safety net for
 * the failure mode Relay cannot report: a CALL into an EOA with no code succeeds and
 * returns empty, so if the 7702 authorization did not apply (a stale nonce, most likely),
 * the batch still "succeeds" with the pubkey silently unset.
 */
async function verifyOutcome(receiver: string): Promise<void> {
  try {
    const dst = new JsonRpcProvider(cfg.ethRpcUrl, cfg.dstChainId);
    const lighter = new ethers.Contract(cfg.lighter, LIGHTER_ABI, dst);
    const accountIndex: bigint = await lighter.addressToAccountIndex(receiver);
    console.log("Verification (destination chain):");
    console.log(`  addressToAccountIndex(${receiver}) = ${accountIndex}`);
    if (accountIndex === 0n) {
      console.log("  ↳ 0 means L1 has not seen the account yet. The deposit is a priority request;");
      console.log("    the index appears once L2 executes it and the block syncs back. Re-run MODE=status later.");
    }

    if (withPubKey) {
      const code = await dst.getCode(receiver);
      const delegated = code.toLowerCase().startsWith("0xef0100");
      const target = delegated ? ethers.getAddress("0x" + code.slice(8, 48)) : null;
      console.log(`  code at receiver = ${code === "0x" ? "0x (none)" : code}`);
      if (!delegated) {
        console.log("  ⚠ NO 7702 DELEGATION. The changePubKey call went into a bare EOA, which succeeds");
        console.log("    silently and does nothing. The deposit landed; the pubkey did NOT get set.");
      } else {
        console.log(`  ↳ delegated to ${target}${
          cfg.delegate && target?.toLowerCase() === cfg.delegate.toLowerCase() ? " (matches HERMES_DELEGATE)" : " (DOES NOT match HERMES_DELEGATE)"
        }`);
      }
    }
  } catch (e: any) {
    console.log(`Verification skipped: ${e?.shortMessage ?? e?.message ?? e}`);
  }
}

// ── Status mode ──────────────────────────────────────────────────────────────
async function runStatus(): Promise<void> {
  const requestId = process.env.REQUEST_ID;
  if (!requestId) throw new Error("MODE=status needs REQUEST_ID (printed by MODE=send).");
  const endpoint = `/intents/status/v3?requestId=${requestId}`;
  const status = await getStatus(endpoint);
  console.log(JSON.stringify(status, null, 2));
}

// ── Signer ───────────────────────────────────────────────────────────────────
/**
 * Resolve the wallet that signs/broadcasts. A DEPOSIT_MNEMONIC (BIP-39 phrase) takes
 * precedence over hardhat's configured account (DEPLOYER_PRIVATE_KEY), so the deposit can
 * run from a dedicated wallet. DEPOSIT_MNEMONIC_INDEX picks the account on the standard
 * path m/44'/60'/0'/0/<index> (default 0); override the whole path with
 * DEPOSIT_MNEMONIC_PATH. Only the address is ever logged.
 */
async function resolveSigner(): Promise<{ signer?: Signer; source: string }> {
  const mnemonic = process.env.DEPOSIT_MNEMONIC?.trim();
  if (mnemonic) {
    const index = Number(process.env.DEPOSIT_MNEMONIC_INDEX ?? "0");
    const path = process.env.DEPOSIT_MNEMONIC_PATH ?? `m/44'/60'/0'/0/${index}`;
    let hd: HDNodeWallet;
    try {
      hd = HDNodeWallet.fromPhrase(mnemonic, "", path);
    } catch (e: any) {
      throw new Error(`DEPOSIT_MNEMONIC is not a valid BIP-39 phrase: ${e?.shortMessage ?? e?.message ?? e}`);
    }
    return { signer: hd.connect(ethers.provider), source: `mnemonic (${path})` };
  }
  const signers = await ethers.getSigners();
  return { signer: signers[0], source: "hardhat account (DEPLOYER_PRIVATE_KEY)" };
}

// ── Entry ────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  if (cfg.mode === "status") {
    await runStatus();
    return;
  }

  const { signer, source } = await resolveSigner();

  console.log(`Network: ${network.name}   MODE=${cfg.mode}   FLOW=${cfg.flow}`);
  if (signer) console.log(`Signer:  ${await signer.getAddress()}  (${source})`);
  console.log();

  switch (cfg.mode) {
    case "quote":
    case "preview":
    case "send":
      await runRelayFlow(signer, cfg.mode as Action);
      break;
    default:
      throw new Error(`Unknown MODE "${cfg.mode}". Use quote | preview | send | status.`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
