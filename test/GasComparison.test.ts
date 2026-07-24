import { ethers, network } from "hardhat";
import {
    AbiCoder,
    Contract,
    ContractTransactionReceipt,
    HDNodeWallet,
    Signer,
    TypedDataEncoder,
    Wallet,
    parseEther,
    parseUnits,
    solidityPacked,
    zeroPadValue,
} from "ethers";
import {
    deployContract,
    attachContract,
    expectSuccess,
} from "../scripts/utils/contracts";
import { Address } from "../scripts/utils/types";
import { HermesV1, HermesDelegateV1, MockERC20 } from "../typechain-types";
import entryPointFixture from "./fixtures/entrypoint-v09.json";

const ENTRY_POINT_ADDR = "0x433709009B8330FDa32311DF1C2AFA402eD8D009" as Address;

// EntryPoint v0.9 — minimal ABI (9-field PackedUserOperation, same as OZ draft-IERC4337).
const ENTRY_POINT_ABI = [
    "function handleOps((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature)[] ops, address beneficiary)",
    "function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp) view returns (bytes32)",
    "function getNonce(address sender, uint192 key) view returns (uint256)",
    "function depositTo(address account) payable",
    "function balanceOf(address account) view returns (uint256)",
];

interface Call { target: Address; value: bigint; data: string; }

// ERC-7821 execution encoding (single entry point for every Hermes execution path).
const abiCoder = AbiCoder.defaultAbiCoder();
const CALLS_TYPE = "tuple(address target,uint256 value,bytes data)[]";
const MODE_BATCH = "0x01" + "00".repeat(31);
const MODE_BATCH_OPDATA = "0x01" + "00".repeat(5) + "78210001" + "00".repeat(22);
const encodeBatch = (calls: Call[]): string => abiCoder.encode([CALLS_TYPE], [calls]);
const encodeBatchWithOpData = (calls: Call[], opData: string): string =>
    abiCoder.encode([CALLS_TYPE, "bytes"], [calls, opData]);
// opData envelope for the signed path: `abi.encode(uint256 deadline, bytes signature)`.
const encodeOpData = (deadline: bigint, signature: string): string =>
    abiCoder.encode(["uint256", "bytes"], [deadline, signature]);
const oneCall = (target: Address, data: string, value = 0n): Call[] => [{ target, value, data }];

// A deadline far enough in the future that it never lapses mid-test (year ~2100).
const FAR_FUTURE = 4102444800n;

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

function computeExecDigest(opts: {
    mode: string; calls: Call[]; nonce: bigint; deadline: bigint; chainId: bigint; eoa: Address; implAddr: Address;
}): string {
    return TypedDataEncoder.hash(
        {
            name: "Hermes", version: "v1.0.0", chainId: opts.chainId,
            verifyingContract: opts.eoa, salt: zeroPadValue(opts.implAddr, 32),
        },
        EXECUTE_TYPES,
        { mode: opts.mode, calls: opts.calls, nonce: opts.nonce, deadline: opts.deadline },
    );
}

const signRaw = (w: HDNodeWallet, hash: string) => w.signingKey.sign(hash).serialized;

async function delegateEoa(user: HDNodeWallet, impl: Address, relayer: Signer) {
    const auth = await user.authorize({ address: impl });
    const tx = await relayer.sendTransaction({
        type: 4, to: user.address, data: "0x", authorizationList: [auth],
    });
    expectSuccess((await tx.wait()) as ContractTransactionReceipt);
}

interface Sample { label: string; gas: bigint; calldataBytes: number; }

describe("HONEST gas comparison: steady-state (2nd op), real EntryPoint.handleOps", () => {
    it("measures self-call, signed opData, and full 4337 handleOps", async () => {
        const [admin, funder, beneficiary] = await ethers.getSigners();

        // Plant the real EntryPoint v0.9 runtime bytecode at its canonical address.
        await network.provider.send("hardhat_setCode", [
            ENTRY_POINT_ADDR, entryPointFixture.code,
        ]);
        const entryPoint = new Contract(ENTRY_POINT_ADDR, ENTRY_POINT_ABI, admin);

        const userSelf = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
        const userSig = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
        const user4337 = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
        for (const w of [userSelf, userSig, user4337]) {
            await funder.sendTransaction({ to: w.address, value: parseEther("10") });
        }

        const guard = await deployContract<HermesV1>("HermesV1", [], admin);
        const guardAddr = (await guard.getAddress()) as Address;
        const v1 = await deployContract<HermesDelegateV1>("HermesDelegateV1", [guardAddr], admin);
        const implAddr = (await v1.getAddress()) as Address;
        const token = await deployContract<MockERC20>("MockERC20", ["Gas Token", "GAS"], admin);
        const tokenAddr = (await token.getAddress()) as Address;

        // Pre-warm recipient slot (non-zero balance) so every transfer is nonzero->nonzero.
        const recipient = Wallet.createRandom().address as Address;
        expectSuccess(await (await token.mint(recipient, 1n)).wait());
        for (const w of [userSelf, userSig, user4337]) {
            expectSuccess(await (await token.mint(w.address, parseUnits("1000", 18))).wait());
        }

        await delegateEoa(userSelf, implAddr, admin);
        await delegateEoa(userSig, implAddr, admin);
        await delegateEoa(user4337, implAddr, admin);

        const sigDelegate = await attachContract<HermesDelegateV1>(
            "HermesDelegateV1", userSig.address, admin,
        );

        const { chainId } = await ethers.provider.getNetwork();
        const transferData = token.interface.encodeFunctionData("transfer", [recipient, parseUnits("1", 18)]);

        const firsts: Sample[] = [];
        const seconds: Sample[] = [];

        // ───────── 1) Direct self-call: execute(MODE_BATCH, abi.encode(Call[])) ─────────
        {
            const calldata = sigDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH, encodeBatch(oneCall(tokenAddr, transferData)),
            ]);
            const run = async () => {
                const tx = await userSelf.sendTransaction({ to: userSelf.address, data: calldata });
                return (await tx.wait()) as ContractTransactionReceipt;
            };
            const r1 = await run(); expectSuccess(r1);
            const r2 = await run(); expectSuccess(r2);
            const cd = (calldata.length - 2) / 2;
            firsts.push({ label: "execute (self-call)", gas: r1.gasUsed, calldataBytes: cd });
            seconds.push({ label: "execute (self-call)", gas: r2.gasUsed, calldataBytes: cd });
        }

        // ───────── 2) Signed batch via ERC-7821 opData mode ─────────
        {
            const run = async () => {
                const calls: Call[] = [{ target: tokenAddr, value: 0n, data: transferData }];
                const nonce = await guard.nonceOf(userSig.address);
                const digest = computeExecDigest({ mode: MODE_BATCH_OPDATA, calls, nonce, deadline: FAR_FUTURE, chainId, eoa: userSig.address as Address, implAddr });
                const sig = signRaw(userSig, digest);
                const executionData = encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig));
                const calldata = sigDelegate.interface.encodeFunctionData("execute", [MODE_BATCH_OPDATA, executionData]);
                const tx = await sigDelegate.execute(MODE_BATCH_OPDATA, executionData);
                const r = (await tx.wait()) as ContractTransactionReceipt;
                return { r, cd: (calldata.length - 2) / 2 };
            };
            const a = await run(); expectSuccess(a.r);
            const b = await run(); expectSuccess(b.r);
            firsts.push({ label: "execute (signed opData)", gas: a.r.gasUsed, calldataBytes: a.cd });
            seconds.push({ label: "execute (signed opData)", gas: b.r.gasUsed, calldataBytes: b.cd });
        }

        // ───────── 3) Full ERC-4337 via real EntryPoint.handleOps ─────────
        {
            const block = await ethers.provider.getBlock("latest");
            const baseFee = block!.baseFeePerGas ?? parseUnits("1", "gwei");
            const maxPriority = parseUnits("1", "gwei");
            const maxFee = baseFee * 2n + maxPriority;

            const verificationGasLimit = 500_000n;
            const callGasLimit = 500_000n;
            const preVerificationGas = 50_000n;
            const accountGasLimits = solidityPacked(["uint128", "uint128"], [verificationGasLimit, callGasLimit]);
            const gasFees = solidityPacked(["uint128", "uint128"], [maxPriority, maxFee]);

            const innerCalldata = sigDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH, encodeBatch(oneCall(tokenAddr, transferData)),
            ]);

            const buildOp = async (signature: string) => ({
                sender: user4337.address,
                nonce: await entryPoint.getNonce(user4337.address, 0n),
                initCode: "0x",
                callData: innerCalldata,
                accountGasLimits,
                preVerificationGas,
                gasFees,
                paymasterAndData: "0x",
                signature,
            });

            const run = async () => {
                const draft = await buildOp("0x");
                const userOpHash: string = await entryPoint.getUserOpHash(draft);
                const op = await buildOp(signRaw(user4337, userOpHash));
                const tx = await entryPoint.connect(beneficiary).getFunction("handleOps")(
                    [op], beneficiary.address, { maxFeePerGas: maxFee, maxPriorityFeePerGas: maxPriority },
                );
                const r = (await tx.wait()) as ContractTransactionReceipt;
                const cd = (entryPoint.interface.encodeFunctionData("handleOps", [[op], beneficiary.address]).length - 2) / 2;
                return { r, cd };
            };
            const a = await run(); expectSuccess(a.r);
            const b = await run(); expectSuccess(b.r);
            firsts.push({ label: "ERC-4337 handleOps (real EntryPoint)", gas: a.r.gasUsed, calldataBytes: a.cd });
            seconds.push({ label: "ERC-4337 handleOps (real EntryPoint)", gas: b.r.gasUsed, calldataBytes: b.cd });
        }

        // ───────── Pretty-print ─────────
        const print = (title: string, rows: Sample[]) => {
            const base = rows[0].gas;
            const w = Math.max(...rows.map((s) => s.label.length));
            console.log(`\n────────── ${title} ──────────`);
            console.log("path".padEnd(w) + " | " + "gasUsed".padStart(8) + " | " + "calldata".padStart(9) + " | " + "Δ vs self-call".padStart(15));
            console.log("-".repeat(w + 3 + 8 + 3 + 9 + 3 + 15));
            for (const s of rows) {
                const d = s.gas - base;
                const isBase = s === rows[0];
                console.log(
                    s.label.padEnd(w) + " | " + s.gas.toString().padStart(8) + " | " + `${s.calldataBytes}B`.padStart(9) +
                    " | " + (isBase ? "      baseline".padStart(15) : `${d > 0n ? "+" : ""}${d}`.padStart(15)),
                );
            }
        };
        print("1st op (cold: nonce 0->1, fresh deposit)", firsts);
        print("2nd op (STEADY STATE: warm nonce, existing deposit)", seconds);
        console.log("");
    });

    it("4337 batch amortization: N UserOps share one handleOps tx", async () => {
        const [admin, funder, beneficiary] = await ethers.getSigners();

        await network.provider.send("hardhat_setCode", [ENTRY_POINT_ADDR, entryPointFixture.code]);
        const entryPoint = new Contract(ENTRY_POINT_ADDR, ENTRY_POINT_ABI, admin);

        const guard = await deployContract<HermesV1>("HermesV1", [], admin);
        const v1 = await deployContract<HermesDelegateV1>("HermesDelegateV1", [(await guard.getAddress()) as Address], admin);
        const implAddr = (await v1.getAddress()) as Address;
        const token = await deployContract<MockERC20>("MockERC20", ["Gas Token", "GAS"], admin);
        const tokenAddr = (await token.getAddress()) as Address;
        const ifaceDelegate = v1.interface;

        const recipient = Wallet.createRandom().address as Address;
        expectSuccess(await (await token.mint(recipient, 1n)).wait());
        const transferData = token.interface.encodeFunctionData("transfer", [recipient, parseUnits("1", 18)]);

        const block = await ethers.provider.getBlock("latest");
        const baseFee = block!.baseFeePerGas ?? parseUnits("1", "gwei");
        const maxPriority = parseUnits("1", "gwei");
        const maxFee = baseFee * 2n + maxPriority;
        const accountGasLimits = solidityPacked(["uint128", "uint128"], [250_000n, 250_000n]);
        const gasFees = solidityPacked(["uint128", "uint128"], [maxPriority, maxFee]);
        const innerCalldata = ifaceDelegate.encodeFunctionData("execute", [
            MODE_BATCH, encodeBatch(oneCall(tokenAddr, transferData)),
        ]);

        const MAX_N = 10;
        const users: HDNodeWallet[] = [];
        for (let i = 0; i < MAX_N; i++) {
            const w = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
            await funder.sendTransaction({ to: w.address, value: parseEther("10") });
            expectSuccess(await (await token.mint(w.address, parseUnits("1000", 18))).wait());
            await delegateEoa(w, implAddr, admin);
            users.push(w);
        }

        const buildSignedOp = async (w: HDNodeWallet) => {
            const draft = {
                sender: w.address, nonce: await entryPoint.getNonce(w.address, 0n),
                initCode: "0x", callData: innerCalldata, accountGasLimits,
                preVerificationGas: 50_000n, gasFees, paymasterAndData: "0x", signature: "0x",
            };
            const userOpHash: string = await entryPoint.getUserOpHash(draft);
            return { ...draft, signature: signRaw(w, userOpHash) };
        };

        const runBatch = async (n: number) => {
            const ops = [];
            for (let i = 0; i < n; i++) ops.push(await buildSignedOp(users[i]));
            const tx = await entryPoint.connect(beneficiary).getFunction("handleOps")(
                ops, beneficiary.address, { maxFeePerGas: maxFee, maxPriorityFeePerGas: maxPriority },
            );
            return (await tx.wait()) as ContractTransactionReceipt;
        };

        const sizes = [1, 2, 5, 10];
        const rows: { n: number; total: bigint; perOp: bigint }[] = [];
        for (const n of sizes) {
            await runBatch(n);                 // warm-up: deposits + EntryPoint nonces
            const r = await runBatch(n);       // steady-state measurement
            expectSuccess(r);
            rows.push({ n, total: r.gasUsed, perOp: r.gasUsed / BigInt(n) });
        }

        console.log("\n────────── 4337 BATCH AMORTIZATION (steady state, N transfers in 1 handleOps) ──────────");
        console.log("N ops".padStart(5) + " | " + "total gasUsed".padStart(14) + " | " + "gas / op".padStart(9) + " | " + "marginal / op".padStart(14));
        console.log("-".repeat(5 + 3 + 14 + 3 + 9 + 3 + 14));
        let prev: { n: number; total: bigint } | null = null;
        for (const row of rows) {
            const marginal = prev ? (row.total - prev.total) / BigInt(row.n - prev.n) : row.total;
            console.log(
                row.n.toString().padStart(5) + " | " + row.total.toString().padStart(14) +
                " | " + row.perOp.toString().padStart(9) + " | " +
                (prev ? marginal.toString() : "—").padStart(14),
            );
            prev = row;
        }
        console.log("(marginal/op = extra gas per added UserOp = cost WITHOUT the shared 21000 base + fixed EntryPoint overhead)\n");
    });

    it("1/2/3 ops: plain call vs execute (7821) vs signed opData vs 4337 (10 users share tx) — cold & steady", async () => {
        const [admin, funder, beneficiary] = await ethers.getSigners();
        const BUNDLE_USERS = 10; // bundler packs this many UserOps -> base + EntryPoint overhead split across them

        await network.provider.send("hardhat_setCode", [ENTRY_POINT_ADDR, entryPointFixture.code]);
        const entryPoint = new Contract(ENTRY_POINT_ADDR, ENTRY_POINT_ABI, admin);

        const guard = await deployContract<HermesV1>("HermesV1", [], admin);
        const guardAddr = (await guard.getAddress()) as Address;
        const v1 = await deployContract<HermesDelegateV1>("HermesDelegateV1", [guardAddr], admin);
        const implAddr = (await v1.getAddress()) as Address;
        const token = await deployContract<MockERC20>("MockERC20", ["Gas Token", "GAS"], admin);
        const tokenAddr = (await token.getAddress()) as Address;
        const { chainId } = await ethers.provider.getNetwork();

        const recipient = Wallet.createRandom().address as Address;
        expectSuccess(await (await token.mint(recipient, 1n)).wait()); // pre-warm recipient slot
        const transferData = token.interface.encodeFunctionData("transfer", [recipient, parseUnits("1", 18)]);
        const makeCalls = (n: number): Call[] =>
            Array.from({ length: n }, () => ({ target: tokenAddr, value: 0n, data: transferData }));

        const fund = async (w: HDNodeWallet) => {
            await funder.sendTransaction({ to: w.address, value: parseEther("10") });
            expectSuccess(await (await token.mint(w.address, parseUnits("1000000", 18))).wait());
        };
        const mkUser = async () => {
            const w = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
            await fund(w);
            await delegateEoa(w, implAddr, admin);
            return w;
        };
        const mkPlain = async () => {
            const w = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
            await fund(w);
            return w; // NOT delegated — a regular EOA doing raw token.transfer
        };

        const block = await ethers.provider.getBlock("latest");
        const baseFee = block!.baseFeePerGas ?? parseUnits("1", "gwei");
        const maxPriority = parseUnits("1", "gwei");
        const maxFee = baseFee * 2n + maxPriority;
        const accountGasLimits = solidityPacked(["uint128", "uint128"], [400_000n, 400_000n]);
        const gasFees = solidityPacked(["uint128", "uint128"], [maxPriority, maxFee]);

        // 4337 inner callData: an ERC-7821 no-opData batch (a single op is just a batch of one).
        const inner4337 = (n: number) =>
            v1.interface.encodeFunctionData("execute", [MODE_BATCH, encodeBatch(makeCalls(n))]);

        const buildSignedOp = async (w: HDNodeWallet, n: number) => {
            const draft = {
                sender: w.address, nonce: await entryPoint.getNonce(w.address, 0n),
                initCode: "0x", callData: inner4337(n), accountGasLimits,
                preVerificationGas: 50_000n, gasFees, paymasterAndData: "0x", signature: "0x",
            };
            const h: string = await entryPoint.getUserOpHash(draft);
            return { ...draft, signature: signRaw(w, h) };
        };

        // run twice on the SAME fresh actor: [0] = cold (nonce 0->1 / fresh deposit), [1] = steady
        const twice = async (exec: () => Promise<ContractTransactionReceipt>): Promise<[bigint, bigint]> => {
            const a = await exec(); expectSuccess(a);
            const b = await exec(); expectSuccess(b);
            return [a.gasUsed, b.gasUsed];
        };

        interface Row { n: number; plain: [bigint, bigint]; self: [bigint, bigint]; sig: [bigint, bigint]; bundle: [bigint, bigint]; }
        const rows: Row[] = [];

        for (const n of [1, 2, 3]) {
            // fresh actors per N so "cold" is genuinely cold for each batch size
            const plainUser = await mkPlain();
            const selfUser = await mkUser();
            const sigUser = await mkUser();
            const sigDelegate = await attachContract<HermesDelegateV1>("HermesDelegateV1", sigUser.address, admin);
            const bundleUsers: HDNodeWallet[] = [];
            for (let i = 0; i < BUNDLE_USERS; i++) bundleUsers.push(await mkUser());

            // plain call: a regular EOA can't batch -> N separate transfers; measure one, multiply by N
            const plainOne = await twice(async () =>
                (await (await token.connect(plainUser).transfer(recipient, parseUnits("1", 18))).wait()) as ContractTransactionReceipt);
            const plain: [bigint, bigint] = [plainOne[0] * BigInt(n), plainOne[1] * BigInt(n)];

            const self = await twice(async () => {
                const data = v1.interface.encodeFunctionData("execute", [MODE_BATCH, encodeBatch(makeCalls(n))]);
                return (await (await selfUser.sendTransaction({ to: selfUser.address, data })).wait()) as ContractTransactionReceipt;
            });

            const sig = await twice(async () => {
                const calls = makeCalls(n);
                const nonce = await guard.nonceOf(sigUser.address);
                const digest = computeExecDigest({ mode: MODE_BATCH_OPDATA, calls, nonce, deadline: FAR_FUTURE, chainId, eoa: sigUser.address as Address, implAddr });
                const s = signRaw(sigUser, digest);
                const executionData = encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, s));
                return (await (await sigDelegate.execute(MODE_BATCH_OPDATA, executionData)).wait()) as ContractTransactionReceipt;
            });

            const bundleTotals = await twice(async () => {
                const ops = [];
                for (const w of bundleUsers) ops.push(await buildSignedOp(w, n));
                const tx = await entryPoint.connect(beneficiary).getFunction("handleOps")(
                    ops, beneficiary.address, { maxFeePerGas: maxFee, maxPriorityFeePerGas: maxPriority });
                return (await tx.wait()) as ContractTransactionReceipt;
            });
            const bundle: [bigint, bigint] = [bundleTotals[0] / BigInt(BUNDLE_USERS), bundleTotals[1] / BigInt(BUNDLE_USERS)];

            rows.push({ n, plain, self, sig, bundle });
        }

        const c = (s: string, w: number) => s.padStart(w);
        const printTable = (title: string, idx: 0 | 1) => {
            console.log(`\n────────── ${title} ──────────`);
            console.log(
                c("ops", 4) + " | " + c("plain call xN", 13) + " | " + c("execute/Batch", 13) +
                " | " + c("execWithSig", 12) + " | " + c(`4337/user(${BUNDLE_USERS})`, 14),
            );
            console.log("-".repeat(4 + 3 + 13 + 3 + 13 + 3 + 12 + 3 + 14));
            for (const r of rows) {
                console.log(
                    c(r.n.toString(), 4) + " | " + c(r.plain[idx].toString(), 13) + " | " + c(r.self[idx].toString(), 13) +
                    " | " + c(r.sig[idx].toString(), 12) + " | " + c(r.bundle[idx].toString(), 14),
                );
            }
        };
        printTable("1st op (COLD: nonce 0->1, fresh EntryPoint deposit)", 0);
        printTable("2nd op (STEADY STATE: warm nonce, existing deposit)", 1);
        console.log("(plain call xN = N separate raw EOA transfers; 4337/user = handleOps total / 10 users)\n");
    });
});
