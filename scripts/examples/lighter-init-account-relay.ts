import { ethers, network } from "hardhat";
import { HDNodeWallet, JsonRpcProvider, Wallet } from "ethers";

/**
 * Lighter account init in ONE Relay cross-chain call: deposit USDC and set the API pubkey.
 * https://docs.relay.link/references/api/api_guides/calling-integration-guide
 *
 *   WETH (BSC) ──relay.link──▶ USDC (ETH) ──▶ Relay Multicaller runs txs[] in one fill tx:
 *
 *     authorizationList: [user → HermesDelegateV1]              (EIP-7702, signed by the user)
 *     txs[0]  USDC.approve(Lighter, amount)                     msg.sender = Multicaller
 *     txs[1]  Lighter.deposit(user, assetIndex, routeType, amount)
 *     txs[2]  user.execute(MODE_BATCH_OPDATA,                   the user's EOA, now running
 *               abi.encode([Lighter.changePubKey(accountIndex,  HermesDelegateV1 code; inside it
 *                 apiKeyIndex, pubKey)], opData))               msg.sender for Lighter = user
 *
 * `executeDelegatedBatch(signature, calls)` in the design sketch is HermesDelegateV1's ERC-7821
 * `execute(bytes32 mode, bytes executionData)` in the signed (opData) mode:
 *   mode          = 0x01 00 00000000 78210001 00…   (batch, revert on any failure)
 *   executionData = abi.encode(Call[] calls, bytes opData)
 *   opData        = abi.encode(uint256 deadline, bytes signature)
 *   signature     = EIP-712 over Execute(bytes32 mode,Call[] calls,uint256 nonce,uint256 deadline),
 *                   domain { name "Hermes", version "v1.0.0", chainId, verifyingContract = user,
 *                   salt = bytes32(HermesDelegateV1) }, nonce = HermesV1.nonceOf(user).
 * The signature is what lets the Multicaller (not the user) trigger the batch; the 7702
 * authorization is what puts the delegate's code on the user's address in the same tx.
 *
 * `initAccount(pubKey)` = Lighter's `changePubKey(uint48 accountIndex, uint8 apiKeyIndex, bytes pubKey)`.
 * accountIndex:
 *   - the user already has a Lighter account → read from addressToAccountIndex(user), works today;
 *   - fresh address → changePubKey reverts (0x240391a0) until Lighter ships the msg.sender
 *     magic number. Pass it via LIGHTER_ACCOUNT_INDEX once it exists. Without it the whole
 *     fill reverts and Relay refunds — the script refuses MODE=send in that case unless
 *     FORCE_SEND=1.
 *
 * Modes (MODE env; default `quote`):
 *   MODE=quote   Sign the authorization + batch, fetch the Relay quote, print it. Nothing broadcast.
 *   MODE=preview quote + preflight + every origin tx that would be sent, with gas. Nothing broadcast.
 *   MODE=send    preview, then execute the origin steps, poll to completion, verify on Ethereum.
 *   MODE=status  Re-poll an existing request. Needs REQUEST_ID.
 *
 * Usage:
 *   LIGHTER_PUBKEY=0x… AMOUNT_USDC=5 MODE=quote yarn hardhat run scripts/examples/lighter-init-account-relay.ts --network bsc
 *   LIGHTER_PUBKEY=0x… AMOUNT_USDC=5 MODE=send  yarn hardhat run scripts/examples/lighter-init-account-relay.ts --network bsc
 *
 * Env:
 *   LIGHTER_PUBKEY         40-byte Poseidon-Schnorr pubkey, 0x-prefixed     (required)
 *   AMOUNT_USDC            USDC to deposit, ≥ 1                             (required)
 *   MODE                   quote | preview | send | status                  (default quote)
 *   DEPOSIT_MNEMONIC       BIP-39 phrase for the user wallet (else DEPLOYER_PRIVATE_KEY).
 *                          Must be a raw key: hardhat signers cannot sign EIP-7702 authorizations.
 *   DEPOSIT_MNEMONIC_INDEX / DEPOSIT_MNEMONIC_PATH   derivation (default m/44'/60'/0'/0/0)
 *   LIGHTER_API_KEY_INDEX  api key slot                                     (default 1)
 *   LIGHTER_ACCOUNT_INDEX  override the accountIndex (magic number for a fresh address)
 *   LIGHTER_ASSET_INDEX    USDC asset index in Lighter                      (default 3)
 *   LIGHTER_ROUTE_TYPE     0 = Perps, 1 = Spot                              (default 0)
 *   HERMES_DELEGATE        HermesDelegateV1                                 (default v1.0.0 deployment)
 *   HERMES_MANAGER         HermesV1 nonce manager                           (default v1.0.0 deployment)
 *   DEADLINE_SEC           signed batch lifetime in seconds                 (default 1800)
 *   SLIPPAGE_BPS           (default 100)    TXS_GAS_LIMIT (default 700000)
 *   SRC_TOKEN/SRC_CHAIN_ID, DST_TOKEN/DST_CHAIN_ID, LIGHTER_DEPOSIT, ETH_RPC_URL, RELAY_API, RELAY_REFERRER
 *   USE_QUOTED_FEES=1      send origin txs with Relay's maxFeePerGas instead of the node's
 *   FORCE_SEND=1           allow MODE=send for a fresh address without LIGHTER_ACCOUNT_INDEX
 */

// ── Constants ────────────────────────────────────────────────────────────────
const RELAY_API = process.env.RELAY_API ?? "https://api.relay.link";
const QUOTE_PATH = "/quote/v2";

const LIGHTER_DEPOSIT = "0x3b4d794a66304f130a4db8f2551b0070dfcf5ca7";
const LIGHTER_ABI = [
  "function deposit(address _to, uint16 _assetIndex, uint8 _routeType, uint256 _amount) payable",
  "function changePubKey(uint48 _accountIndex, uint8 _apiKeyIndex, bytes _pubKey)",
  "function addressToAccountIndex(address) view returns (uint48)",
];
const DEPOSIT_SELECTOR = "0x8a857083"; // deposit(address,uint16,uint8,uint256)
const CHANGE_PUBKEY_SELECTOR = "0x17010c68"; // changePubKey(uint48,uint8,bytes)

// Hermes v1.0.0 — same CREATE2 address on every chain (see README "Deployed contracts").
const HERMES_DELEGATE_V1 = "0x24b576BC271823bF9C24BE627B4363b9b00191e9";
const HERMES_MANAGER_V1 = "0x79ffaCa44dC6A7aAC1ad0239e398D652317b167B";
const HERMES_DELEGATE_ABI = ["function execute(bytes32 mode, bytes executionData) payable"];
const HERMES_MANAGER_ABI = ["function nonceOf(address account) view returns (uint256)"];
// callType 0x01 (batch) | execType 0x00 (revert) | modeSelector 0x78210001 (opData)
const MODE_BATCH_OPDATA = "0x01" + "00".repeat(5) + "78210001" + "00".repeat(22);
const EXECUTE_SELECTOR = "0xe9ae5c53"; // execute(bytes32,bytes)

// EIP-712 types of the signed batch — byte-for-byte HermesDelegateV1.EXECUTE_TYPEHASH.
const EXECUTE_TYPES = {
  Call: [
    { name: "target", type: "address" },
    { name: "value", type: "uint256" },
    { name: "data", type: "bytes" },
  ],
  Execute: [
    { name: "mode", type: "bytes32" },
    { name: "calls", type: "Call[]" },
    { name: "nonce", type: "uint256" },
    { name: "deadline", type: "uint256" },
  ],
};

const SRC_CHAIN_ID = 56; // BSC
const DST_CHAIN_ID = 1; // Ethereum
const WETH_BSC = "0x2170Ed0880ac9A755fd29B2688956BD959F933F8";
const USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
const USDC_DECIMALS = 6;

const ERC20_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function balanceOf(address account) view returns (uint256)",
];

const TERMINAL_OK = new Set(["success"]);
const TERMINAL_BAD = new Set(["failure", "refund"]);

const erc20Iface = new ethers.Interface(ERC20_ABI);
const lighterIface = new ethers.Interface(LIGHTER_ABI);
const delegateIface = new ethers.Interface(HERMES_DELEGATE_ABI);
const abi = ethers.AbiCoder.defaultAbiCoder();

// ── Config from env ──────────────────────────────────────────────────────────
const cfg = {
  mode: (process.env.MODE ?? "quote").toLowerCase(),
  pubKey: process.env.LIGHTER_PUBKEY,
  amountUsdc: process.env.AMOUNT_USDC,
  apiKeyIndex: Number(process.env.LIGHTER_API_KEY_INDEX ?? "1"),
  accountIndexOverride: process.env.LIGHTER_ACCOUNT_INDEX,
  assetIndex: Number(process.env.LIGHTER_ASSET_INDEX ?? "3"),
  routeType: Number(process.env.LIGHTER_ROUTE_TYPE ?? "0"),
  delegate: process.env.HERMES_DELEGATE ?? HERMES_DELEGATE_V1,
  manager: process.env.HERMES_MANAGER ?? HERMES_MANAGER_V1,
  deadlineSec: Number(process.env.DEADLINE_SEC ?? "1800"),
  slippageBps: Number(process.env.SLIPPAGE_BPS ?? "100"),
  txsGasLimit: Number(process.env.TXS_GAS_LIMIT ?? "700000"),
  srcToken: process.env.SRC_TOKEN ?? WETH_BSC,
  srcChainId: Number(process.env.SRC_CHAIN_ID ?? String(SRC_CHAIN_ID)),
  dstToken: process.env.DST_TOKEN ?? USDC_ETH,
  dstChainId: Number(process.env.DST_CHAIN_ID ?? String(DST_CHAIN_ID)),
  lighter: process.env.LIGHTER_DEPOSIT ?? LIGHTER_DEPOSIT,
  ethRpcUrl: process.env.ETH_RPC_URL ?? "https://ethereum-rpc.publicnode.com",
  referrer: process.env.RELAY_REFERRER,
  useQuotedFees: process.env.USE_QUOTED_FEES === "1",
  forceSend: process.env.FORCE_SEND === "1",
};

const dstProvider = new JsonRpcProvider(cfg.ethRpcUrl, cfg.dstChainId, { staticNetwork: true });

// ── Calldata ─────────────────────────────────────────────────────────────────
function assertSelector(data: string, expected: string, signature: string): void {
  const selector = data.slice(0, 10).toLowerCase();
  if (selector !== expected) {
    throw new Error(`${signature} selector drifted: built ${selector}, expected ${expected}.`);
  }
}

type Call = { target: string; value: bigint; data: string };
type RelayTx = { to: string; value: string; data: string };

function buildChangePubKeyCall(accountIndex: bigint, pubKey: string): Call {
  const data = lighterIface.encodeFunctionData("changePubKey", [accountIndex, cfg.apiKeyIndex, pubKey]);
  assertSelector(data, CHANGE_PUBKEY_SELECTOR, "changePubKey(uint48,uint8,bytes)");
  return { target: cfg.lighter, value: 0n, data };
}

/** execute(MODE_BATCH_OPDATA, abi.encode(Call[], abi.encode(deadline, signature))). */
function buildSignedExecuteCalldata(calls: Call[], deadline: bigint, signature: string): string {
  const opData = abi.encode(["uint256", "bytes"], [deadline, signature]);
  const executionData = abi.encode(
    ["tuple(address,uint256,bytes)[]", "bytes"],
    [calls.map((c) => [c.target, c.value, c.data]), opData]
  );
  const data = delegateIface.encodeFunctionData("execute", [MODE_BATCH_OPDATA, executionData]);
  assertSelector(data, EXECUTE_SELECTOR, "execute(bytes32,bytes)");
  return data;
}

/** The three destination txs the Multicaller runs, in order, after receiving `amount` USDC. */
function buildTxs(user: string, amount: bigint, executeCalldata: string): RelayTx[] {
  const depositData = lighterIface.encodeFunctionData("deposit", [user, cfg.assetIndex, cfg.routeType, amount]);
  assertSelector(depositData, DEPOSIT_SELECTOR, "deposit(address,uint16,uint8,uint256)");
  return [
    { to: cfg.dstToken, value: "0", data: erc20Iface.encodeFunctionData("approve", [cfg.lighter, amount]) },
    { to: cfg.lighter, value: "0", data: depositData },
    { to: user, value: "0", data: executeCalldata },
  ];
}

// ── Destination-chain state ──────────────────────────────────────────────────
type DstState = {
  existingAccountIndex: bigint; // 0 = no Lighter account yet
  hermesNonce: bigint;
  eoaNonce: number;
  delegatedTo: string | null; // current 7702 delegation target, if any
};

async function readDstState(user: string): Promise<DstState> {
  const lighter = new ethers.Contract(cfg.lighter, LIGHTER_ABI, dstProvider);
  const manager = new ethers.Contract(cfg.manager, HERMES_MANAGER_ABI, dstProvider);
  const [existingAccountIndex, hermesNonce, eoaNonce, code] = await Promise.all([
    lighter.addressToAccountIndex(user) as Promise<bigint>,
    manager.nonceOf(user) as Promise<bigint>,
    dstProvider.getTransactionCount(user, "latest"),
    dstProvider.getCode(user),
  ]);
  const delegatedTo = code.toLowerCase().startsWith("0xef0100") ? ethers.getAddress("0x" + code.slice(8, 48)) : null;
  return { existingAccountIndex, hermesNonce, eoaNonce, delegatedTo };
}

// ── Signatures ───────────────────────────────────────────────────────────────
type Authorization = { chainId: number; address: string; nonce: number; yParity: number; r: string; s: string };

/**
 * EIP-7702 authorization for the DESTINATION chain. The solver sends the fill, so the
 * authority's nonce is the user's current Ethereum nonce — any Ethereum tx the user sends
 * before the fill invalidates it (the batch then lands on a bare EOA; see verifyOutcome).
 */
async function signAuthorization(wallet: Wallet | HDNodeWallet, eoaNonce: number): Promise<Authorization> {
  const auth = await wallet.authorize({ address: cfg.delegate, chainId: cfg.dstChainId, nonce: eoaNonce });
  return {
    chainId: Number(auth.chainId),
    address: auth.address,
    nonce: Number(auth.nonce),
    yParity: auth.signature.yParity,
    r: auth.signature.r,
    s: auth.signature.s,
  };
}

/** EIP-712 signature over the batch, against the domain the delegated EOA will expose. */
async function signBatch(
  wallet: Wallet | HDNodeWallet,
  user: string,
  calls: Call[],
  nonce: bigint,
  deadline: bigint
): Promise<string> {
  const domain = {
    name: "Hermes",
    version: "v1.0.0",
    chainId: cfg.dstChainId,
    verifyingContract: user,
    salt: ethers.zeroPadValue(cfg.delegate, 32),
  };
  return wallet.signTypedData(domain, EXECUTE_TYPES, { mode: MODE_BATCH_OPDATA, calls, nonce, deadline });
}

// ── Relay API ────────────────────────────────────────────────────────────────
async function relayFetch(path: string, body?: unknown): Promise<any> {
  const res = await fetch(`${RELAY_API}${path}`, {
    method: body ? "POST" : "GET",
    headers: body ? { "content-type": "application/json" } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`relay ${path} ${res.status} ${res.statusText}: ${text}`);
  return JSON.parse(text);
}

async function pollUntilDone(endpoint: string, timeoutMs = 15 * 60_000): Promise<any> {
  const started = Date.now();
  let last = "";
  for (;;) {
    const status = await relayFetch(endpoint);
    const state = String(status.status ?? "unknown");
    if (state !== last) {
      console.log(`  status ${state}${status.details ? ` (${status.details})` : ""}`);
      last = state;
    }
    if (TERMINAL_OK.has(state)) return status;
    if (TERMINAL_BAD.has(state)) throw new Error(`Relay reported ${state}: ${JSON.stringify(status)}`);
    if (Date.now() - started > timeoutMs) throw new Error(`Timed out waiting on ${endpoint} (last status ${state}).`);
    await new Promise((r) => setTimeout(r, 3000));
  }
}

const fmtFee = (f: any) => (f ? `${f.amountFormatted} ${f.currency?.symbol ?? ""} ($${f.amountUsd})` : "—");

// ── Flow ─────────────────────────────────────────────────────────────────────
type Action = "quote" | "preview" | "send";

async function runInit(wallet: Wallet | HDNodeWallet, action: Action): Promise<void> {
  if (!cfg.pubKey) throw new Error("LIGHTER_PUBKEY is required (0x-prefixed 40-byte pubkey).");
  if (ethers.dataLength(cfg.pubKey) !== 40) {
    throw new Error(`LIGHTER_PUBKEY must be 40 bytes, got ${ethers.dataLength(cfg.pubKey)}.`);
  }
  if (!cfg.amountUsdc) throw new Error("AMOUNT_USDC is required (≥ 1, Lighter's minDeposit).");
  const amount = ethers.parseUnits(cfg.amountUsdc, USDC_DECIMALS);
  if (amount < 1_000_000n) throw new Error(`AMOUNT_USDC ${cfg.amountUsdc} is below Lighter's 1 USDC minimum.`);

  const user = await wallet.getAddress();
  const state = await readDstState(user);

  // accountIndex: explicit override > existing account > 0 (fresh address, reverts today).
  const freshWithoutIndex = state.existingAccountIndex === 0n && cfg.accountIndexOverride === undefined;
  const accountIndex =
    cfg.accountIndexOverride !== undefined ? BigInt(cfg.accountIndexOverride) : state.existingAccountIndex;

  // Already delegated to this delegate → no authorization needed (and none to invalidate).
  const alreadyDelegated = state.delegatedTo?.toLowerCase() === cfg.delegate.toLowerCase();
  if (state.delegatedTo && !alreadyDelegated) {
    console.log(`⚠ ${user} is currently delegated to ${state.delegatedTo}; the authorization below re-delegates it.\n`);
  }

  const calls = [buildChangePubKeyCall(accountIndex, cfg.pubKey)];
  const deadline = BigInt(Math.floor(Date.now() / 1000) + cfg.deadlineSec);
  const signature = await signBatch(wallet, user, calls, state.hermesNonce, deadline);
  const txs = buildTxs(user, amount, buildSignedExecuteCalldata(calls, deadline, signature));
  const authorization = alreadyDelegated ? null : await signAuthorization(wallet, state.eoaNonce);

  console.log(`Lighter init via Relay — ${cfg.srcToken} (chain ${cfg.srcChainId}) → USDC (chain ${cfg.dstChainId}) → deposit + changePubKey\n`);
  console.log(`  user             ${user}`);
  console.log(`  amount           ${cfg.amountUsdc} USDC (${amount})`);
  console.log(`  pubKey           ${cfg.pubKey}`);
  console.log(`  accountIndex     ${accountIndex}  ${
    cfg.accountIndexOverride !== undefined ? "(LIGHTER_ACCOUNT_INDEX)" : freshWithoutIndex ? "(⚠ no Lighter account yet)" : "(existing account)"
  }`);
  console.log(`  apiKeyIndex      ${cfg.apiKeyIndex}`);
  console.log(`  delegate         ${cfg.delegate}${alreadyDelegated ? "  (already delegated, no authorization)" : ""}`);
  console.log(`  hermes nonce     ${state.hermesNonce}   deadline ${deadline} (${new Date(Number(deadline) * 1000).toISOString()})`);
  console.log(`  signature        ${signature}`);
  if (authorization) {
    console.log(`  7702 auth        → ${authorization.address}  chainId ${authorization.chainId}  EOA nonce ${authorization.nonce}`);
  }
  console.log(`  txs[0]           ${txs[0].to}  approve(${cfg.lighter}, ${amount})`);
  console.log(`  txs[1]           ${txs[1].to}  deposit(${user}, ${cfg.assetIndex}, ${cfg.routeType}, ${amount})`);
  console.log(`  txs[2]           ${txs[2].to}  execute(opData) → changePubKey(${accountIndex}, ${cfg.apiKeyIndex}, pubKey)  (${(txs[2].data.length - 2) / 2} bytes)`);
  console.log();

  if (freshWithoutIndex) {
    console.log("⚠ No Lighter account for this address and no LIGHTER_ACCOUNT_INDEX: changePubKey reverts");
    console.log("  (0x240391a0) until Lighter ships the msg.sender magic number, so the whole fill reverts");
    console.log("  and Relay refunds. Set LIGHTER_ACCOUNT_INDEX=<magic> when it exists.\n");
  }

  const body: Record<string, unknown> = {
    user,
    recipient: user,
    originChainId: cfg.srcChainId,
    originCurrency: cfg.srcToken,
    destinationChainId: cfg.dstChainId,
    destinationCurrency: cfg.dstToken,
    amount: amount.toString(),
    tradeType: "EXACT_OUTPUT", // txs[] hardcode `amount`
    refundTo: user,
    slippageTolerance: String(cfg.slippageBps),
    txsGasLimit: cfg.txsGasLimit,
    txs,
  };
  if (authorization) body.authorizationList = [authorization];
  if (cfg.referrer) body.referrer = cfg.referrer;

  const quote = await relayFetch(QUOTE_PATH, body);
  console.log("Quote:");
  console.log(`  requestId        ${quote.requestId}`);
  console.log(`  steps            ${(quote.steps ?? []).map((s: any) => `${s.id}(${s.kind})`).join(" -> ") || "—"}`);
  console.log(`  currencyIn       ${fmtFee(quote.details?.currencyIn)}`);
  console.log(`  currencyOut      ${fmtFee(quote.details?.currencyOut)}`);
  console.log(`  fees.relayerGas  ${fmtFee(quote.fees?.relayerGas)}`);
  console.log(`  fees.relayerSvc  ${fmtFee(quote.fees?.relayerService)}`);
  console.log(`  est. time        ${quote.details?.timeEstimate ?? "—"}s\n`);

  if (action === "quote") {
    console.log("MODE=quote — nothing broadcast. MODE=preview shows the origin transactions.");
    return;
  }

  const net = await ethers.provider.getNetwork();
  if (Number(net.chainId) !== cfg.srcChainId) {
    throw new Error(`Connected to chain ${net.chainId}, source chain is ${cfg.srcChainId}. Use --network for the source chain.`);
  }
  if (!Array.isArray(quote.steps) || quote.steps.length === 0) {
    throw new Error(`Unexpected response: no steps.\n${JSON.stringify(quote, null, 2)}`);
  }

  await preflight(user, quote);
  await previewOrigin(user, quote);

  if (action === "preview") {
    console.log("MODE=preview — nothing broadcast. MODE=send executes.");
    return;
  }
  if (freshWithoutIndex && !cfg.forceSend) {
    throw new Error("Refusing MODE=send: the fill would revert (see warning above). FORCE_SEND=1 overrides.");
  }

  const destinationTxHashes = await executeSteps(wallet, quote);
  await verifyOutcome(user, state.hermesNonce, destinationTxHashes);
}

async function preflight(user: string, quote: any): Promise<void> {
  const needed = BigInt(quote.details?.currencyIn?.amount ?? "0");
  const bal: bigint = await new ethers.Contract(cfg.srcToken, ERC20_ABI, ethers.provider).balanceOf(user);
  if (bal < needed) {
    throw new Error(`Insufficient srcToken on chain ${cfg.srcChainId}: have ${bal}, need ${needed} of ${cfg.srcToken}.`);
  }
  const native = await ethers.provider.getBalance(user);
  if (native === 0n) throw new Error(`No native gas token on chain ${cfg.srcChainId}.`);
  console.log(`Preflight OK — srcToken ${bal} ≥ ${needed}, native ${ethers.formatEther(native)}.\n`);
}

async function previewOrigin(user: string, quote: any): Promise<void> {
  const fee = await ethers.provider.getFeeData();
  const gasPrice = fee.maxFeePerGas ?? fee.gasPrice ?? 0n;
  console.log(`Origin transactions (chain ${cfg.srcChainId}, ${network.name}):`);
  let i = 0;
  for (const step of quote.steps as any[]) {
    for (const item of step.items ?? []) {
      if (item.status === "complete") continue;
      const tx = item.data;
      let estimate: bigint | null = null;
      try {
        estimate = await ethers.provider.estimateGas({ from: user, to: tx.to, data: tx.data, value: BigInt(tx.value ?? "0") });
      } catch {
        estimate = null; // the deposit step needs the approve first
      }
      const gas = tx.gas ? BigInt(tx.gas) : estimate ?? 0n;
      console.log(`  [${++i}] ${step.id}  to ${tx.to}  value ${tx.value ?? "0"}  data ${tx.data.slice(0, 10)}…`);
      console.log(`      gas ${gas}${estimate === null ? " (Relay's figure)" : ""}  ~${ethers.formatEther(gas * gasPrice)} native`);
    }
  }
  console.log();
}

async function executeSteps(wallet: Wallet | HDNodeWallet, quote: any): Promise<string[]> {
  const signer = wallet.connect(ethers.provider);
  const destinationTxHashes: string[] = [];
  for (const step of quote.steps as any[]) {
    for (const item of step.items ?? []) {
      if (item.status === "complete") continue;
      if (step.kind !== "transaction") {
        throw new Error(`Step ${step.id} is kind "${step.kind}", not handled.\n${JSON.stringify(step, null, 2)}`);
      }
      const tx = item.data;
      const request: Record<string, unknown> = { to: tx.to, data: tx.data, value: BigInt(tx.value ?? "0") };
      if (tx.gas) request.gasLimit = BigInt(tx.gas);
      if (cfg.useQuotedFees && tx.maxFeePerGas) {
        request.maxFeePerGas = BigInt(tx.maxFeePerGas);
        request.maxPriorityFeePerGas = BigInt(tx.maxPriorityFeePerGas ?? tx.maxFeePerGas);
      }
      console.log(`Step ${step.id}: ${step.description ?? ""}`);
      const sent = await signer.sendTransaction(request);
      console.log(`  sent ${sent.hash}`);
      const receipt = await sent.wait();
      if (receipt?.status !== 1) throw new Error(`Step ${step.id} tx ${sent.hash} reverted.`);
      console.log(`  mined in block ${receipt.blockNumber}`);
      if (item.check?.endpoint) {
        const final = await pollUntilDone(item.check.endpoint);
        for (const h of final.txHashes ?? []) {
          destinationTxHashes.push(h);
          console.log(`  destination tx ${h}`);
        }
      }
    }
  }
  console.log();
  return destinationTxHashes;
}

/**
 * Relay's "success" only says the fill tx did not revert. A call into an EOA without code
 * also "succeeds", so check what actually happened: the delegation is in place and the
 * Hermes nonce moved past the signed one (it only moves if the signed batch executed —
 * a revert would have rolled it back along with the whole fill).
 */
async function verifyOutcome(user: string, signedNonce: bigint, txHashes: string[]): Promise<void> {
  const after = await readDstState(user);
  console.log("Verification (destination chain):");
  console.log(`  delegation        ${after.delegatedTo ?? "none"}${
    after.delegatedTo?.toLowerCase() === cfg.delegate.toLowerCase() ? "  ✓" : "  ✗ expected " + cfg.delegate
  }`);
  console.log(`  hermes nonce      ${signedNonce} → ${after.hermesNonce}  ${after.hermesNonce > signedNonce ? "✓ batch executed" : "✗ batch did NOT execute"}`);
  console.log(`  accountIndex      ${after.existingAccountIndex}${
    after.existingAccountIndex === 0n ? "  (L1 not synced yet — deposit + changePubKey are queued priority requests)" : ""
  }`);
  for (const h of txHashes) console.log(`  fill tx           https://etherscan.io/tx/${h}`);
}

async function runStatus(): Promise<void> {
  const requestId = process.env.REQUEST_ID;
  if (!requestId) throw new Error("MODE=status needs REQUEST_ID.");
  console.log(JSON.stringify(await relayFetch(`/intents/status/v3?requestId=${requestId}`), null, 2));
}

// ── Signer ───────────────────────────────────────────────────────────────────
/**
 * A raw-key wallet: the user signs both the 7702 authorization and the EIP-712 batch,
 * and hardhat's network signers cannot produce the former.
 */
function resolveWallet(): { wallet: Wallet | HDNodeWallet; source: string } {
  const mnemonic = process.env.DEPOSIT_MNEMONIC?.trim();
  if (mnemonic) {
    const index = Number(process.env.DEPOSIT_MNEMONIC_INDEX ?? "0");
    const path = process.env.DEPOSIT_MNEMONIC_PATH ?? `m/44'/60'/0'/0/${index}`;
    return { wallet: HDNodeWallet.fromPhrase(mnemonic, "", path), source: `mnemonic (${path})` };
  }
  const pk = process.env.DEPLOYER_PRIVATE_KEY;
  if (pk) return { wallet: new Wallet(pk), source: "DEPLOYER_PRIVATE_KEY" };
  throw new Error("Set DEPOSIT_MNEMONIC or DEPLOYER_PRIVATE_KEY: the user must sign the 7702 authorization and the batch.");
}

// ── Entry ────────────────────────────────────────────────────────────────────
async function main(): Promise<void> {
  if (cfg.mode === "status") return runStatus();
  if (!["quote", "preview", "send"].includes(cfg.mode)) {
    throw new Error(`Unknown MODE "${cfg.mode}". Use quote | preview | send | status.`);
  }
  const { wallet, source } = resolveWallet();
  console.log(`Network: ${network.name}   MODE=${cfg.mode}`);
  console.log(`Signer:  ${await wallet.getAddress()}  (${source})\n`);
  await runInit(wallet, cfg.mode as Action);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
