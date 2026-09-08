import { ethers, network } from "hardhat";
import { HDNodeWallet, type Signer } from "ethers";

/**
 * Cross-chain top-up of Lighter via swaps.xyz "calldata call".
 * https://docs.swaps.xyz/guides/calldata-call
 *
 * Goal: pay with WETH on BSC, land 5 USDC on Ethereum, and in the SAME cross-chain
 * action deposit that USDC into Lighter's L1 gateway — a swap + deposit.
 *
 *   WETH (BSC, chainId 56)  ──swaps.xyz──▶  USDC (ETH, chainId 1)  ──▶  Lighter.deposit(...)
 *
 * How the calldata call works (evm-calldata-tx): we hand swaps.xyz the destination
 * contract (`to`), the encoded call (`data`), how much of the destination ERC20 the
 * call consumes (`erc20Amount`) and who to approve for it (`erc20Spender`). swaps.xyz
 * routes the swap, delivers USDC on Ethereum, approves the spender and fires our
 * calldata — all triggered by a single transaction we broadcast on BSC.
 *
 * Lighter deposit gateway (Ethereum mainnet, writeProxyContract):
 *   0x3b4d794a66304f130a4db8f2551b0070dfcf5ca7
 *   deposit(address _to, uint16 _assetIndex, uint8 _routeType, uint256 _amount) payable
 *   selector 0x8a857083
 *
 * Requirement: the swap sender and the Lighter deposit receiver (`_to`) are the SAME
 * address — you top up your own Lighter L1 balance.
 *
 * Modes (set via MODE env; default `quote`):
 *   MODE=quote  Build the calldata + fetch the swaps.xyz quote and print it. Read-only.
 *   MODE=send   Same, then approve (if needed) and broadcast the tx on the source chain.
 *
 * Usage:
 *   MODE=quote yarn hardhat run scripts/examples/lighter-deposit-swapxyz.ts --network bsc
 *   MODE=send  yarn hardhat run scripts/examples/lighter-deposit-swapxyz.ts --network bsc     # broadcasts on BSC
 *
 * Env (all optional unless noted):
 *   SWAPS_API_KEY        required — x-api-key for api-v2.swaps.xyz
 *   MODE                 quote | send                   (default quote)
 *   AMOUNT_USDC          USDC to deposit                (default "5")
 *   RECEIVER             Lighter _to; must equal sender (default sender)
 *   SENDER               sender address for quote mode when no signer is configured
 *   DEPOSIT_MNEMONIC     BIP-39 phrase for the deposit wallet; takes precedence
 *                        over hardhat's DEPLOYER_PRIVATE_KEY account
 *   DEPOSIT_MNEMONIC_INDEX  account index on m/44'/60'/0'/0/<i>   (default 0)
 *   DEPOSIT_MNEMONIC_PATH   full derivation path override (else the index path)
 *   LIGHTER_ASSET_INDEX  USDC asset index in Lighter    (default 3 = USDC_ASSET_INDEX)
 *   LIGHTER_ROUTE_TYPE   route type (0=Perps, 1=Spot)    (default 0)
 *   SLIPPAGE_BPS         slippage tolerance in bps       (default 100 = 1%)
 *   SRC_TOKEN/SRC_CHAIN_ID, DST_TOKEN/DST_CHAIN_ID, LIGHTER_DEPOSIT to override defaults
 */

// ── Constants ────────────────────────────────────────────────────────────────
const SWAPS_API = "https://api-v2.swaps.xyz/api/getAction";

// Lighter L1 deposit gateway on Ethereum (ZkLighter proxy → impl 0x831EF6…7008).
// deposit() pulls the token via safeTransferFrom(msg.sender, ...), so whoever calls
// it must hold the USDC AND have approved this gateway for it. On-chain assetConfigs(3)
// (USDC): token 0xA0b8…eB48, tickSize 1, minDeposit 1_000_000 (1 USDC) — so AMOUNT_USDC
// must be ≥ 1 or the deposit reverts (AdditionalZkLighter_InvalidDepositAmount).
const LIGHTER_DEPOSIT = "0x3b4d794a66304f130a4db8f2551b0070dfcf5ca7";
const LIGHTER_DEPOSIT_ABI = [
  "function deposit(address _to, uint16 _assetIndex, uint8 _routeType, uint256 _amount) payable",
];
const DEPOSIT_SELECTOR = "0x8a857083"; // deposit(address,uint16,uint8,uint256)

// Cross-chain leg: pay with WETH on BSC, deliver USDC on Ethereum.
const SRC_CHAIN_ID = 56; // BSC
const DST_CHAIN_ID = 1; // Ethereum
const WETH_BSC = "0x2170Ed0880ac9A755fd29B2688956BD959F933F8"; // Binance-Peg ETH ("WETH" on BSC)
const USDC_ETH = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"; // native USDC on Ethereum
const USDC_DECIMALS = 6;

const NATIVE = "0x0000000000000000000000000000000000000000";
const NATIVE_ALT = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

// Minimal ERC20 surface for source-side approval.
const ERC20_ABI = [
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address account) view returns (uint256)",
  "function decimals() view returns (uint8)",
  "function symbol() view returns (string)",
];

const lighterIface = new ethers.Interface(LIGHTER_DEPOSIT_ABI);

// ── Config from env ──────────────────────────────────────────────────────────
const cfg = {
  mode: (process.env.MODE ?? "quote").toLowerCase(),
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
  const selector = data.slice(0, 10).toLowerCase();
  if (selector !== DEPOSIT_SELECTOR) {
    throw new Error(
      `deposit() selector drifted: built ${selector}, expected ${DEPOSIT_SELECTOR}. ` +
        `The ABI no longer matches Lighter's deposit(address,uint16,uint8,uint256).`
    );
  }
  return data;
}

// ── swaps.xyz getAction ──────────────────────────────────────────────────────
type ActionRequest = Record<string, string | number>;

async function getAction(req: ActionRequest): Promise<any> {
  const apiKey = process.env.SWAPS_API_KEY;
  if (!apiKey) {
    throw new Error("Set SWAPS_API_KEY in .env (x-api-key header for api-v2.swaps.xyz).");
  }
  const url = new URL(SWAPS_API);
  for (const [k, v] of Object.entries(req)) {
    if (v === undefined || v === null || v === "") continue;
    url.searchParams.set(k, String(v));
  }
  const res = await fetch(url.toString(), { method: "GET", headers: { "x-api-key": apiKey } });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`getAction ${res.status} ${res.statusText}: ${text}`);
  }
  return JSON.parse(text);
}

function fmtPayment(p: any): string {
  if (!p) return "—";
  const usd = p.usdAmount != null ? ` ($${p.usdAmount})` : "";
  return `${p.amount} ${p.symbol ?? ""} [chain ${p.chainId}]${usd}`.trim();
}

// ── Cross-chain flow (quote / send) ──────────────────────────────────────────
async function runSwapsFlow(signer: Signer | undefined, send: boolean): Promise<void> {
  const sender = process.env.SENDER ?? (signer ? await signer.getAddress() : undefined);
  if (!sender) {
    throw new Error("No signer and no SENDER set. Provide DEPLOYER_PRIVATE_KEY or SENDER.");
  }
  const receiver = cfg.receiver ?? sender;

  // Requirement: the swap sender and Lighter deposit receiver (_to) are identical.
  if (receiver.toLowerCase() !== sender.toLowerCase()) {
    throw new Error(
      `receiver ${receiver} != sender ${sender}. SwapFrom and Deposit(_to) must be the same address.`
    );
  }

  const amount = ethers.parseUnits(cfg.amountUsdc, USDC_DECIMALS);
  const data = buildDepositCalldata(receiver, cfg.assetIndex, cfg.routeType, amount);

  const req: ActionRequest = {
    actionType: "evm-calldata-tx",
    sender,
    srcChainId: cfg.srcChainId,
    srcToken: cfg.srcToken,
    dstChainId: cfg.dstChainId,
    dstToken: cfg.dstToken,
    slippage: cfg.slippageBps,
    to: cfg.lighter, // Lighter deposit gateway on the destination chain
    data, // deposit(_to, _assetIndex, _routeType, _amount)
    erc20Amount: amount.toString(), // USDC delivered into Lighter
    erc20Spender: cfg.lighter, // Lighter pulls the USDC via approval (defaults to `to`)
    value: "0", // ERC20 deposit — no native value forwarded to the call
  };

  console.log("swaps.xyz calldata call — WETH(BSC) → USDC(ETH) → Lighter.deposit\n");
  console.log(`  sender / _to     ${sender}`);
  console.log(`  src              ${cfg.amountUsdc} USDC-worth of ${cfg.srcToken} on chain ${cfg.srcChainId}`);
  console.log(`  dst              ${cfg.amountUsdc} USDC (${cfg.dstToken}) on chain ${cfg.dstChainId}`);
  console.log(`  lighter          ${cfg.lighter}`);
  console.log(`  assetIndex       ${cfg.assetIndex}   routeType ${cfg.routeType}   slippage ${cfg.slippageBps}bps`);
  console.log(`  deposit calldata ${data}`);
  console.log(`  selector         ${data.slice(0, 10)} (Lighter deposit)\n`);

  const resp = await getAction(req);

  console.log("Quote:");
  console.log(`  amountIn         ${fmtPayment(resp.amountIn)}`);
  console.log(`  amountInMax      ${fmtPayment(resp.amountInMax)}`);
  console.log(`  amountOut        ${fmtPayment(resp.amountOut)}`);
  console.log(`  amountOutMin     ${fmtPayment(resp.amountOutMin)}`);
  console.log(`  protocolFee      ${fmtPayment(resp.protocolFee)}`);
  console.log(`  bridgeFee        ${fmtPayment(resp.bridgeFee)}`);
  console.log(`  exchangeRate     ${resp.exchangeRate ?? "—"}`);
  console.log(`  est. time        ${resp.estimatedTxTime ?? "—"}s`);
  console.log(`  needs approval   ${resp.requiresTokenApproval}`);
  console.log(`  bridges          ${(resp.bridgeIds ?? []).join(", ") || "—"}`);
  console.log(`  tx.to            ${resp.tx?.to}`);
  console.log(`  tx.value         ${resp.tx?.value}`);
  console.log(`  tx.chainId       ${resp.tx?.chainId}\n`);

  if (!send) {
    console.log("MODE=quote — not broadcasting. Set MODE=send to execute on the source chain.");
    return;
  }

  if (!signer) {
    throw new Error("MODE=send needs a signer. Set DEPLOYER_PRIVATE_KEY and run with --network <src>.");
  }
  const tx = resp.tx;
  if (!tx?.to || !tx?.data) {
    throw new Error(`Unexpected response: missing tx. Full body:\n${JSON.stringify(resp, null, 2)}`);
  }

  const net = await ethers.provider.getNetwork();
  if (Number(net.chainId) !== cfg.srcChainId) {
    throw new Error(
      `Connected to chain ${net.chainId} but the source chain is ${cfg.srcChainId}. ` +
        `Run with --network for the source chain (e.g. --network bsc).`
    );
  }

  // Preflight: make sure the wallet can actually pay on the source chain before
  // spending gas. Needs srcToken >= amountInMax AND native > bridge fee (+ gas).
  const needed = BigInt(resp.amountInMax?.amount ?? resp.amountIn?.amount ?? "0");
  const bridgeValue = BigInt(tx.value ?? "0");
  const nativeBal = await ethers.provider.getBalance(sender);
  const srcErc20 = isNative(cfg.srcToken) ? null : new ethers.Contract(cfg.srcToken, ERC20_ABI, signer);
  if (srcErc20) {
    const bal: bigint = await srcErc20.balanceOf(sender);
    if (bal < needed) {
      throw new Error(
        `Insufficient srcToken on chain ${cfg.srcChainId}: have ${bal}, need ${needed} (amountInMax) of ${cfg.srcToken}. Fund the wallet and retry.`
      );
    }
  }
  if (nativeBal <= bridgeValue) {
    throw new Error(
      `Insufficient native gas token on chain ${cfg.srcChainId}: have ${nativeBal}, need > ${bridgeValue} (bridge fee) plus gas. Top up native balance.`
    );
  }
  console.log(`Preflight OK — native balance ${nativeBal}, srcToken ${srcErc20 ? "sufficient" : "(native)"}.`);

  // Source-side approval: swaps.xyz's router (tx.to) pulls srcToken from the sender.
  if (resp.requiresTokenApproval && srcErc20) {
    const spender: string = tx.to;
    const current: bigint = await srcErc20.allowance(sender, spender);
    if (current < needed) {
      console.log(`Approving ${needed} of ${cfg.srcToken} to ${spender} ...`);
      const a = await srcErc20.approve(spender, needed);
      await a.wait();
      console.log(`  approved (tx ${a.hash})`);
    } else {
      console.log(`Allowance already sufficient (${current} >= ${needed}).`);
    }
  }

  console.log("Broadcasting source transaction ...");
  const sent = await signer.sendTransaction({
    to: tx.to,
    data: tx.data,
    value: BigInt(tx.value ?? "0"),
  });
  console.log(`  sent ${sent.hash}`);
  const receipt = await sent.wait();
  console.log(`  mined in block ${receipt?.blockNumber} (status ${receipt?.status})`);
  if (resp.txId) console.log(`  track: https://app.swaps.xyz  (txId ${resp.txId})`);
}

// ── Signer ───────────────────────────────────────────────────────────────────
/**
 * Resolve the wallet that signs/broadcasts. A DEPOSIT_MNEMONIC (BIP-39 phrase)
 * takes precedence over hardhat's configured account (DEPLOYER_PRIVATE_KEY), so
 * the deposit can run from a dedicated wallet. DEPOSIT_MNEMONIC_INDEX picks the
 * account on the standard path m/44'/60'/0'/0/<index> (default 0); override the
 * whole path with DEPOSIT_MNEMONIC_PATH. Only the address is ever logged.
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
  const { signer, source } = await resolveSigner();

  console.log(`Network: ${network.name}   MODE=${cfg.mode}`);
  if (signer) console.log(`Signer:  ${await signer.getAddress()}  (${source})`);
  console.log();

  switch (cfg.mode) {
    case "quote":
      await runSwapsFlow(signer, false);
      break;
    case "send":
      await runSwapsFlow(signer, true);
      break;
    default:
      throw new Error(`Unknown MODE "${cfg.mode}". Use quote | send.`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
