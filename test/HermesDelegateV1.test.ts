import { expect } from "chai";
import { ethers, network } from "hardhat";
import {
    AbiCoder,
    ContractTransactionReceipt,
    HDNodeWallet,
    Signer,
    TypedDataEncoder,
    Wallet,
    concat,
    keccak256,
    parseEther,
    parseUnits,
    toBeHex,
    toUtf8Bytes,
    zeroPadValue,
} from "ethers";
import {
    deployContract,
    attachContract,
    expectSuccess,
    wait,
} from "../scripts/utils/contracts";
import { Address } from "../scripts/utils/types";
import {
    Counter,
    HermesV1,
    HermesDelegateV1,
    MockERC20,
    ReentrantTarget,
} from "../typechain-types";

// ─────────────────────────────────────────────────────────────────────────
// Constants mirroring HermesDelegateV1.sol
// ─────────────────────────────────────────────────────────────────────────
const ENTRY_POINT_ADDR = "0x433709009B8330FDa32311DF1C2AFA402eD8D009";
const ENTRY_POINT_V9_ADDR = ENTRY_POINT_ADDR; // the newer of the two trusted EntryPoints
const ENTRY_POINT_V8_ADDR = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";
const ACCOUNT_ID = "Hermes.Delegate.v1.0.0";
const ERC1271_SUCCESS = "0x1626ba7e";
const ERC1271_FAILURE = "0xffffffff";

const HERMES_NAME_HASH = keccak256(toUtf8Bytes("Hermes"));
const HERMES_VERSION_HASH = keccak256(toUtf8Bytes("v1.0.0"));
const HERMES_DOMAIN_TYPEHASH = keccak256(
    toUtf8Bytes(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
    ),
);
// ERC-4337 v0.8+ userOpHash construction (used to model the EntryPoint's own hashing). The domain's
// `verifyingContract` is the EntryPoint address, so each EntryPoint produces a distinct hash for the
// same UserOp — the property that blocks cross-EntryPoint signature replay.
const EIP712_DOMAIN4_TYPEHASH = keccak256(
    toUtf8Bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
);
const PACKED_USEROP_TYPEHASH = keccak256(
    toUtf8Bytes(
        "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)",
    ),
);
const ERC4337_NAME_HASH = keccak256(toUtf8Bytes("ERC4337"));
const ERC4337_VERSION_HASH = keccak256(toUtf8Bytes("1"));

// EIP-712 types for the signed (opData) batch — what a wallet receives via eth_signTypedData_v4.
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

// A deadline far enough in the future that it never lapses mid-test (year ~2100). Signing
// type(uint256).max would mean "no expiry"; a concrete value keeps the expiry path exercisable.
const FAR_FUTURE = 4102444800n;

// ERC-7821 execution modes (bytes32, big-endian):
//   [0] callType=0x01 (batch) | [1] execType=0x00 | [6:10] modeSelector | [10:32] payload
const MODE_BATCH = "0x01" + "00".repeat(31);
const MODE_BATCH_OPDATA = "0x01" + "00".repeat(5) + "78210001" + "00".repeat(22);
const MODE_SINGLE = "0x00" + "00".repeat(31); // callType=0x00 (single) -> unsupported
const MODE_BATCH_OF_BATCHES = "0x01" + "00".repeat(5) + "78210002" + "00".repeat(22);
const MODE_DELEGATECALL = "0xff" + "00".repeat(31); // callType=0xff (ERC-7579 delegatecall) -> MUST be rejected
// execType=0x01 (ERC-7579 "try"): failing calls are logged and skipped instead of reverting the batch.
const MODE_BATCH_TRY = "0x0101" + "00".repeat(30);
const MODE_BATCH_OPDATA_TRY = "0x0101" + "00".repeat(4) + "78210001" + "00".repeat(22);
const MODE_EXEC_TYPE_2 = "0x0102" + "00".repeat(30); // execType=0x02 (unknown) -> unsupported

// Try-mode `mode` with packed per-call 2-bit policies in the payload bytes [10:32]:
// call i's policy sits at bits [2i+1:2i]. 00 OPTIONAL (log-and-continue), 01 REVERT_ON_FAIL
// (failure reverts the batch), 10 BREAK_ON_FAIL (failure logs and ends the batch early),
// 11 BREAK_ON_SUCCESS (success ends the batch early; failure logs and continues).
const POLICY_REVERT_ON_FAIL = 1n;
const POLICY_BREAK_ON_FAIL = 2n;
const POLICY_BREAK_ON_SUCCESS = 3n;
const policyAt = (i: number, policy: bigint): bigint => policy << BigInt(2 * i);
const modeTryWithPolicies = (policies: bigint, withOpData: boolean): string =>
    "0x0101" +
    "00000000" +
    (withOpData ? "78210001" : "00000000") +
    policies.toString(16).padStart(44, "0");

const abi = AbiCoder.defaultAbiCoder();
const CALLS_TYPE = "tuple(address target,uint256 value,bytes data)[]";

// ERC-7821 `executionData` encoders.
const encodeBatch = (calls: Call[]): string => abi.encode([CALLS_TYPE], [calls]);
const encodeBatchWithOpData = (calls: Call[], opData: string): string =>
    abi.encode([CALLS_TYPE, "bytes"], [calls, opData]);
// opData envelope for the signed path: `abi.encode(uint256 deadline, bytes signature)`.
const encodeOpData = (deadline: bigint, signature: string): string =>
    abi.encode(["uint256", "bytes"], [deadline, signature]);

// ─────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────
interface Call {
    target: Address;
    value: bigint;
    data: string;
}

interface PackedUserOperationStruct {
    sender: Address;
    nonce: bigint;
    initCode: string;
    callData: string;
    accountGasLimits: string;
    preVerificationGas: bigint;
    gasFees: string;
    paymasterAndData: string;
    signature: string;
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────
function computeDomainSeparator(
    chainId: bigint,
    eoa: Address,
    implAddr: Address,
): string {
    return keccak256(
        abi.encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address", "bytes32"],
            [
                HERMES_DOMAIN_TYPEHASH,
                HERMES_NAME_HASH,
                HERMES_VERSION_HASH,
                chainId,
                eoa,
                zeroPadValue(implAddr, 32),
            ],
        ),
    );
}

function hermesDomain(chainId: bigint, eoa: Address, implAddr: Address) {
    return {
        name: "Hermes",
        version: "v1.0.0",
        chainId,
        verifyingContract: eoa,
        salt: zeroPadValue(implAddr, 32),
    };
}

// Computed via ethers' TypedDataEncoder — i.e. exactly the digest a wallet produces for
// eth_signTypedData_v4. If the contract deviated from canonical EIP-712, this would not match.
function computeExecDigest(opts: {
    mode: string;
    calls: Call[];
    nonce: bigint;
    deadline: bigint;
    chainId: bigint;
    eoa: Address;
    implAddr: Address;
}): string {
    return TypedDataEncoder.hash(
        hermesDomain(opts.chainId, opts.eoa, opts.implAddr),
        EXECUTE_TYPES,
        { mode: opts.mode, calls: opts.calls, nonce: opts.nonce, deadline: opts.deadline },
    );
}

// ── ERC-7739 helpers: build the nested signatures a 7739-aware wallet produces ──
const PERSONAL_SIGN_TYPEHASH = keccak256(toUtf8Bytes("PersonalSign(bytes prefixed)"));

// A demo "application" contents type the account is asked to sign via ERC-1271.
const APP_CONTENTS_TYPES = { Contents: [{ name: "stuff", type: "bytes32" }] };
const APP_CONTENTS_DESCR = "Contents(bytes32 stuff)"; // implicit mode (ends with ")")

interface AccountDomain {
    name: string;
    version: string;
    chainId: bigint;
    verifyingContract: Address;
    salt: string;
}

// ERC-7739 `TypedDataSign`: app `contents` re-nested under the app domain, embedding the account domain.
// `hash` is the plain app digest passed to isValidSignature; `signature` is the 7739-encoded blob.
function buildTypedDataSig(opts: {
    signer: HDNodeWallet;
    appDomain: { name: string; version: string; chainId: bigint; verifyingContract: Address };
    contents: { stuff: string };
    account: AccountDomain;
}): { hash: string; signature: string } {
    const appSeparator = TypedDataEncoder.hashDomain(opts.appDomain);
    const contentsHash = TypedDataEncoder.hashStruct("Contents", APP_CONTENTS_TYPES, opts.contents);
    const hash = TypedDataEncoder.hash(opts.appDomain, APP_CONTENTS_TYPES, opts.contents);

    const tdsTypes = {
        Contents: APP_CONTENTS_TYPES.Contents,
        TypedDataSign: [
            { name: "contents", type: "Contents" },
            { name: "name", type: "string" },
            { name: "version", type: "string" },
            { name: "chainId", type: "uint256" },
            { name: "verifyingContract", type: "address" },
            { name: "salt", type: "bytes32" },
        ],
    };
    const signedDigest = TypedDataEncoder.hash(opts.appDomain, tdsTypes, {
        contents: opts.contents,
        name: opts.account.name,
        version: opts.account.version,
        chainId: opts.account.chainId,
        verifyingContract: opts.account.verifyingContract,
        salt: opts.account.salt,
    });

    const descrBytes = toUtf8Bytes(APP_CONTENTS_DESCR);
    const signature = concat([
        signRaw(opts.signer, signedDigest),
        appSeparator,
        contentsHash,
        descrBytes,
        toBeHex(descrBytes.length, 2), // uint16 contentsDescr length, big-endian
    ]);
    return { hash, signature };
}

// ERC-7739 `PersonalSign`: a raw message hash nested under the account's EIP-712 domain (no app domain).
function buildPersonalSig(opts: {
    signer: HDNodeWallet;
    msgHash: string;
    chainId: bigint;
    eoa: Address;
    implAddr: Address;
}): string {
    const structHash = keccak256(concat([PERSONAL_SIGN_TYPEHASH, opts.msgHash]));
    const domainSep = computeDomainSeparator(opts.chainId, opts.eoa, opts.implAddr);
    return signRaw(opts.signer, keccak256(concat(["0x1901", domainSep, structHash])));
}

// Models the ERC-4337 v0.8+ userOpHash: an EIP-712 digest whose domain `verifyingContract` is the
// EntryPoint. Two EntryPoints => two hashes for the same UserOp, so a signature for one is rejected
// by the other. The on-chain EntryPoint computes this before calling validateUserOp.
function erc4337UserOpHash(op: PackedUserOperationStruct, chainId: bigint, entryPoint: Address): string {
    const structHash = keccak256(
        abi.encode(
            ["bytes32", "address", "uint256", "bytes32", "bytes32", "bytes32", "uint256", "bytes32", "bytes32"],
            [
                PACKED_USEROP_TYPEHASH,
                op.sender,
                op.nonce,
                keccak256(op.initCode),
                keccak256(op.callData),
                op.accountGasLimits,
                op.preVerificationGas,
                op.gasFees,
                keccak256(op.paymasterAndData),
            ],
        ),
    );
    const domainSep = keccak256(
        abi.encode(
            ["bytes32", "bytes32", "bytes32", "uint256", "address"],
            [EIP712_DOMAIN4_TYPEHASH, ERC4337_NAME_HASH, ERC4337_VERSION_HASH, chainId, entryPoint],
        ),
    );
    return keccak256(concat(["0x1901", domainSep, structHash]));
}

function signRaw(wallet: HDNodeWallet, hash: string): string {
    return wallet.signingKey.sign(hash).serialized;
}

// The same signature in the 64-byte EIP-2098 `(r, vs)` encoding wallets and SDKs emit to save calldata.
function signRawCompact(wallet: HDNodeWallet, hash: string): string {
    return wallet.signingKey.sign(hash).compactSerialized;
}

async function delegateEoaToContract(
    user: HDNodeWallet,
    delegateAddress: Address,
    relayer: Signer,
) {
    const auth = await user.authorize({ address: delegateAddress });
    const tx = await relayer.sendTransaction({
        type: 4,
        to: user.address,
        data: "0x",
        authorizationList: [auth],
    });
    expectSuccess((await tx.wait()) as ContractTransactionReceipt);
}

async function impersonate(addr: Address): Promise<Signer> {
    await network.provider.request({
        method: "hardhat_impersonateAccount",
        params: [addr],
    });
    await network.provider.send("hardhat_setBalance", [
        addr,
        "0x21e19e0c9bab2400000", // 10_000 ETH
    ]);
    return ethers.getSigner(addr);
}

async function stopImpersonate(addr: Address) {
    await network.provider.request({
        method: "hardhat_stopImpersonatingAccount",
        params: [addr],
    });
}

function bumpCall(counter: Counter, by: bigint, counterAddr: Address): Call {
    return {
        target: counterAddr,
        value: 0n,
        data: counter.interface.encodeFunctionData("bump", [by]),
    };
}

function emptyUserOp(sender: Address, callData: string, signature: string): PackedUserOperationStruct {
    return {
        sender,
        nonce: 0n,
        initCode: "0x",
        callData,
        accountGasLimits: zeroPadValue("0x", 32),
        preVerificationGas: 0n,
        gasFees: zeroPadValue("0x", 32),
        paymasterAndData: "0x",
        signature,
    };
}

// ─────────────────────────────────────────────────────────────────────────
// Suite
// ─────────────────────────────────────────────────────────────────────────
describe("HermesDelegateV1 (EIP-7702 + ERC-4337 + ERC-1271)", () => {
    async function setup() {
        const [admin, funder, stranger] = await ethers.getSigners();

        const user = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
        await funder.sendTransaction({ to: user.address, value: parseEther("10") });

        const guard = await deployContract<HermesV1>("HermesV1", [], admin);
        const guardAddr = (await guard.getAddress()) as Address;

        const delegate = await deployContract<HermesDelegateV1>(
            "HermesDelegateV1",
            [guardAddr],
            admin,
        );
        const implAddr = (await delegate.getAddress()) as Address;

        const token = await deployContract<MockERC20>(
            "MockERC20",
            ["Gas Token", "GAS"],
            admin,
        );
        const counter = await deployContract<Counter>("Counter", [], admin);
        const counterAddr = (await counter.getAddress()) as Address;
        const tokenAddr = (await token.getAddress()) as Address;

        expectSuccess(await wait(token.mint(user.address, parseUnits("1000", 18))));

        await delegateEoaToContract(user, implAddr, admin);

        const userAsDelegate = await attachContract<HermesDelegateV1>(
            "HermesDelegateV1",
            user.address,
            admin,
        );

        const { chainId } = await ethers.provider.getNetwork();

        return {
            admin,
            funder,
            stranger,
            user,
            guard,
            guardAddr,
            delegate,
            implAddr,
            token,
            tokenAddr,
            counter,
            counterAddr,
            userAsDelegate,
            chainId,
        };
    }

    // ───────────────────── constructor / pure views ─────────────────────
    describe("constructor & pure views", () => {
        it("reverts when manager is the zero address", async () => {
            const [admin] = await ethers.getSigners();
            const factory = await ethers.getContractFactory("HermesDelegateV1", admin);
            await expect(factory.deploy(ethers.ZeroAddress)).to.be.revertedWithCustomError(
                factory,
                "ZeroAddressManager",
            );
        });

        it("stores the manager address", async () => {
            const { delegate, guardAddr } = await setup();
            expect(await delegate.manager()).to.equal(guardAddr);
        });

        it("accountId() returns the namespaced version", async () => {
            const { delegate } = await setup();
            expect(await delegate.accountId()).to.equal(ACCOUNT_ID);
        });

        it("supportsExecutionMode() recognizes the two single-batch modes in both exec types (ERC-7821)", async () => {
            const { delegate } = await setup();
            expect(await delegate.supportsExecutionMode(MODE_BATCH)).to.equal(true);
            expect(await delegate.supportsExecutionMode(MODE_BATCH_OPDATA)).to.equal(true);
            expect(await delegate.supportsExecutionMode(MODE_BATCH_TRY)).to.equal(true);
            expect(await delegate.supportsExecutionMode(MODE_BATCH_OPDATA_TRY)).to.equal(true);
            expect(await delegate.supportsExecutionMode(MODE_SINGLE)).to.equal(false);
            expect(await delegate.supportsExecutionMode(MODE_BATCH_OF_BATCHES)).to.equal(false);
            expect(await delegate.supportsExecutionMode(MODE_DELEGATECALL)).to.equal(false);
            expect(await delegate.supportsExecutionMode(MODE_EXEC_TYPE_2)).to.equal(false);
        });

        it("decodeCallPolicies() round-trips the packed try-mode policies", async () => {
            const { delegate } = await setup();
            const packed =
                policyAt(0, POLICY_BREAK_ON_SUCCESS) |
                policyAt(2, POLICY_REQUIRED) |
                policyAt(3, POLICY_BREAK_ON_FAIL);

            for (const withOpData of [false, true]) {
                const [isValid, policies] = await delegate.decodeCallPolicies(
                    modeTryWithPolicies(packed, withOpData),
                    4,
                );
                expect(isValid).to.equal(true);
                expect(policies.map(Number)).to.deep.equal([3, 0, 1, 2]);
            }
        });

        // A batch longer than the policies its mode specifies is well-formed on-chain — the missing
        // slots read as OPTIONAL, so a call meant to be REQUIRED silently is not. Round-tripping the
        // encoding through this view before requesting a signature is what surfaces that.
        it("decodeCallPolicies() reads unset slots as OPTIONAL", async () => {
            const { delegate } = await setup();
            const [, policies] = await delegate.decodeCallPolicies(
                modeTryWithPolicies(policyAt(0, POLICY_REQUIRED), false),
                3,
            );
            expect(policies.map(Number)).to.deep.equal([1, 0, 0]);
        });

        // The decoder is not a second validator: it reports what `execute` would reject instead of
        // reverting, so decoding never has to be wrapped in a try/catch.
        it("decodeCallPolicies() reports rejection through isValid instead of reverting", async () => {
            const { delegate } = await setup();

            for (const mode of [MODE_SINGLE, MODE_BATCH_OF_BATCHES, MODE_DELEGATECALL, MODE_EXEC_TYPE_2]) {
                expect((await delegate.decodeCallPolicies(mode, 1))[0]).to.equal(false);
            }

            // Try mode is capped at the payload's 88 policy slots; the default exec type has no cap.
            expect((await delegate.decodeCallPolicies(MODE_BATCH_TRY, 88))[0]).to.equal(true);
            expect((await delegate.decodeCallPolicies(MODE_BATCH_TRY, 89))[0]).to.equal(false);
            expect((await delegate.decodeCallPolicies(MODE_BATCH, 89))[0]).to.equal(true);
        });

        it("eip712Domain() (ERC-5267) returns the domain the signed paths use", async () => {
            const { userAsDelegate, user, implAddr, chainId, counter, counterAddr } = await setup();
            const d = await userAsDelegate.eip712Domain();
            expect(d.fields).to.equal("0x1f");
            expect(d.name).to.equal("Hermes");
            expect(d.version).to.equal("v1.0.0");
            expect(d.chainId).to.equal(chainId);
            expect(d.verifyingContract).to.equal(user.address); // address(this) == the EOA under EIP-7702
            expect(d.salt).to.equal(zeroPadValue(implAddr, 32)); // salt == implementation address
            expect(d.extensions.length).to.equal(0);

            // Reconstruct the domain purely from eip712Domain() and confirm it reproduces the opData
            // digest — i.e. a tooling client that auto-discovers the domain signs the right thing.
            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const reconstructed = TypedDataEncoder.hash(
                {
                    name: d.name,
                    version: d.version,
                    chainId: d.chainId,
                    verifyingContract: d.verifyingContract,
                    salt: d.salt,
                },
                EXECUTE_TYPES,
                { mode: MODE_BATCH_OPDATA, calls, nonce: 0n, deadline: FAR_FUTURE },
            );
            const expected = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce: 0n,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            expect(reconstructed).to.equal(expected);
        });

        it("supportsInterface() advertises ERC-165/721/1155/1271/7779 + IAccount/ERC-7821/ERC-5267", async () => {
            const { delegate } = await setup();
            // ERC-165
            expect(await delegate.supportsInterface("0x01ffc9a7")).to.equal(true);
            // ERC-721 receiver (onERC721Received) — selector 0x150b7a02
            expect(await delegate.supportsInterface("0x150b7a02")).to.equal(true);
            // ERC-1155 receiver — interfaceId 0x4e2312e0
            expect(await delegate.supportsInterface("0x4e2312e0")).to.equal(true);
            // ERC-1271 — interfaceId 0x1626ba7e
            expect(await delegate.supportsInterface("0x1626ba7e")).to.equal(true);

            // Interfaces this delegate adds — IDs computed from the ABI (XOR of function selectors).
            const iface = delegate.interface;
            const id = (...fns: string[]): string => {
                let acc = 0n;
                for (const f of fns) acc ^= BigInt(iface.getFunction(f)!.selector);
                return "0x" + acc.toString(16).padStart(8, "0");
            };
            // ERC-7779
            expect(await delegate.supportsInterface(id("accountId", "accountStorageBases"))).to.equal(true);
            // ERC-4337 IAccount
            expect(await delegate.supportsInterface(id("validateUserOp"))).to.equal(true);
            // ERC-7821
            expect(await delegate.supportsInterface(id("execute", "supportsExecutionMode"))).to.equal(true);
            // ERC-5267
            expect(await delegate.supportsInterface(id("eip712Domain"))).to.equal(true);

            // unknown selector
            expect(await delegate.supportsInterface("0xdeadbeef")).to.equal(false);
        });

        it("accountStorageBases() returns an empty array (Hermes is stateless)", async () => {
            const { delegate } = await setup();
            const bases = await delegate.accountStorageBases();
            expect(bases.length).to.equal(0);
        });
    });

    // ───────────────────── Token-receiver callbacks ─────────────────────
    describe("HermesBase token-receiver callbacks", () => {
        it("onERC721Received returns its own selector", async () => {
            const { delegate } = await setup();
            const sel = await delegate.onERC721Received(
                ethers.ZeroAddress,
                ethers.ZeroAddress,
                0n,
                "0x",
            );
            expect(sel).to.equal("0x150b7a02");
        });

        it("onERC1155Received returns its own selector", async () => {
            const { delegate } = await setup();
            const sel = await delegate.onERC1155Received(
                ethers.ZeroAddress,
                ethers.ZeroAddress,
                0n,
                0n,
                "0x",
            );
            expect(sel).to.equal("0xf23a6e61");
        });

        it("onERC1155BatchReceived returns its own selector", async () => {
            const { delegate } = await setup();
            const sel = await delegate.onERC1155BatchReceived(
                ethers.ZeroAddress,
                ethers.ZeroAddress,
                [],
                [],
                "0x",
            );
            expect(sel).to.equal("0xbc197c81");
        });

        it("onTokenTransfer (ERC-677) returns true", async () => {
            const { delegate } = await setup();
            expect(await delegate.onTokenTransfer(ethers.ZeroAddress, 0n, "0x")).to.equal(true);
        });

        it("receive() accepts ETH", async () => {
            const { admin, user, userAsDelegate } = await setup();
            const eoa = user.address as Address;
            const before = await ethers.provider.getBalance(eoa);
            await admin.sendTransaction({ to: eoa, value: parseEther("0.1") });
            const after = await ethers.provider.getBalance(eoa);
            expect(after - before).to.equal(parseEther("0.1"));
            // sanity: userAsDelegate is the same address as the EOA
            expect(await userAsDelegate.getAddress()).to.equal(eoa);
        });
    });

    // ───────────────────── ERC-7821 self-call (no-opData batch) ─────────────────────
    describe("ERC-7821 execute — self-call (no opData)", () => {
        it("reverts with UnauthorizedExecutor when called by a stranger", async () => {
            const { stranger, userAsDelegate, counter, counterAddr } = await setup();
            await expect(
                userAsDelegate
                    .connect(stranger)
                    .execute(MODE_BATCH, encodeBatch([bumpCall(counter, 1n, counterAddr)])),
            ).to.be.revertedWithCustomError(userAsDelegate, "UnauthorizedExecutor");
        });

        it("reverts with UnsupportedExecutionMode for an unsupported mode", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_SINGLE,
                encodeBatch([bumpCall(counter, 1n, counterAddr)]),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(userAsDelegate, "UnsupportedExecutionMode");
        });

        // SECURITY REGRESSION GUARD: the ERC-7821 mode parser must NEVER accept a call type other
        // than batch. callType 0xFF is ERC-7579 DELEGATECALL — accepting it would run arbitrary code
        // in the account's context (full takeover). Asserted from the account ITSELF, the most
        // privileged caller, so a future change to the mode mask can't silently open delegatecall.
        it("rejects the delegatecall call type (0xFF) even when called by the account itself", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_DELEGATECALL,
                encodeBatch([bumpCall(counter, 1n, counterAddr)]),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(userAsDelegate, "UnsupportedExecutionMode");
        });

        it("rejects an unknown exec type (0x02) — only default and try are supported", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_EXEC_TYPE_2,
                encodeBatch([bumpCall(counter, 1n, counterAddr)]),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(userAsDelegate, "UnsupportedExecutionMode");
        });

        it("try mode (0x01): a failing call is logged and the rest of the batch still runs", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 10n, counterAddr),
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH_TRY,
                encodeBatch(calls),
            ]);

            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            // Calls 0 and 2 landed; the failure of call 1 was logged with its raw revert data.
            expect(await counter.value()).to.equal(11n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(1n);
        });

        it("try mode + REVERT_ON_FAIL policy: a reached call's failure reverts the whole batch", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 10n, counterAddr),
            ];
            // The failing `boom` at index 1 is REVERT_ON_FAIL (01) -> atomic revert despite try mode.
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(1, POLICY_REVERT_ON_FAIL), false),
                encodeBatch(calls),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(counter, "CounterBoom");
            expect(await counter.value()).to.equal(0n);
        });

        it("try mode + policies: OPTIONAL failures still log-and-continue", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 10n, counterAddr),
            ];
            // Calls 0 and 2 are REVERT_ON_FAIL, call 1 keeps the OPTIONAL default (00) and may fail.
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(0, POLICY_REVERT_ON_FAIL) | policyAt(2, POLICY_REVERT_ON_FAIL), false),
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(11n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(1n);
            // An OPTIONAL failure is not a termination: the batch ran to completion.
            await expect(tx).to.not.emit(userAsDelegate, "BatchInterrupted");
        });

        // L-04 regression. A callee alone chooses how many bytes it reverts with, and the caller pays
        // to copy and log them (3 gas/word copied, 8 gas/byte logged). Logging them unbounded turns a
        // non-fatal try-mode failure into an out-of-gas revert of the whole transaction, rolling back
        // the calls that already succeeded. The explicit 1M gas limit is the assertion: a 500 KB
        // payload could not fit through it.
        it("try mode survives a return-bombing call: only the index is logged, the batch continues", async () => {
            const { admin, user, userAsDelegate, counter, counterAddr } = await setup();
            const bomber = await deployContract<Counter>("ReturnBomber" as never, [], admin);
            const bomberAddr = (await bomber.getAddress()) as Address;
            const bombData = new ethers.Interface(["function boom(uint256)"]).encodeFunctionData("boom", [500_000n]);

            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: bomberAddr, value: 0n, data: bombData }, // OPTIONAL (00): log and continue
                bumpCall(counter, 10n, counterAddr),
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH_TRY,
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata, gasLimit: 1_000_000 });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            // Both honest calls ran: the bomb did not become fatal.
            expect(await counter.value()).to.equal(11n);
            await expect(tx).to.emit(userAsDelegate, "CallFailed").withArgs(1n);
        });

        it("try mode + BREAK_ON_FAIL policy: a failure logs, skips the rest and the tx succeeds", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 10n, counterAddr),
            ];
            // The failing `boom` at index 1 is BREAK_ON_FAIL (10): its failure is logged and ends
            // the batch early — the index-2 bump must NOT run, yet the index-0 bump stays committed.
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(1, POLICY_BREAK_ON_FAIL), false),
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(1n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(1n);
            await expect(tx).to.emit(userAsDelegate, "BatchInterrupted").withArgs(1n);
        });

        it("try mode + BREAK_ON_FAIL policy: a success does NOT end the batch", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                bumpCall(counter, 10n, counterAddr),
            ];
            // Call 0 is BREAK_ON_FAIL (10) and succeeds: the break applies only to failures, so
            // call 1 must still run.
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(0, POLICY_BREAK_ON_FAIL), false),
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(11n);
            await expect(tx).to.not.emit(userAsDelegate, "CallFailed");
            await expect(tx).to.not.emit(userAsDelegate, "BatchInterrupted");
        });

        it("try mode: a REVERT_ON_FAIL call is skipped when an earlier break ends the batch", async () => {
            const { user, userAsDelegate, counter, counterAddr, token, tokenAddr, admin } = await setup();

            // The shape from the finding: [action = BREAK_ON_SUCCESS, fee = REVERT_ON_FAIL]. A policy
            // governs what a call's outcome does, not whether the call is reached — the succeeding
            // action ends the batch, so the fee at index 1 never runs and the tx still succeeds.
            const relayer = admin.address as Address;
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [relayer, parseUnits("5", 18)]),
                },
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(
                    policyAt(0, POLICY_BREAK_ON_SUCCESS) | policyAt(1, POLICY_REVERT_ON_FAIL),
                    false,
                ),
                encodeBatch(calls),
            ]);

            const feeBefore = await token.balanceOf(relayer);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(1n);
            expect(await token.balanceOf(relayer)).to.equal(feeBefore); // fee never reached
            await expect(tx).to.emit(userAsDelegate, "BatchInterrupted").withArgs(0n);
        });

        it("try mode + BREAK_ON_SUCCESS policy: a success ends the batch early", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                bumpCall(counter, 10n, counterAddr),
            ];
            // Call 0 is BREAK_ON_SUCCESS (11) and succeeds -> call 1 is skipped, nothing is logged.
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(0, POLICY_BREAK_ON_SUCCESS), false),
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(1n);
            await expect(tx).to.not.emit(userAsDelegate, "CallFailed");
            // Nothing failed, so `BatchInterrupted` is the account's only log — and the sole
            // evidence that call 1 was skipped rather than executed.
            await expect(tx).to.emit(userAsDelegate, "BatchInterrupted").withArgs(0n);
        });

        it("try mode + BREAK_ON_SUCCESS policy: failures log-and-continue until one lands", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 5n, counterAddr),
                bumpCall(counter, 100n, counterAddr),
            ];
            // Fallback chain: calls 0 and 1 are BREAK_ON_SUCCESS (11). The `boom` at index 0 fails
            // silently and the batch continues; the bump at index 1 succeeds and ends the batch —
            // the index-2 bump must NOT run.
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(0, POLICY_BREAK_ON_SUCCESS) | policyAt(1, POLICY_BREAK_ON_SUCCESS), false),
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(5n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(0n);
            // The fallback that landed is index 1 — named directly, not inferred from the absence
            // of a `CallFailed(1)`.
            await expect(tx).to.emit(userAsDelegate, "BatchInterrupted").withArgs(1n);
        });

        it("BREAK_ON_FAIL logs the failure and the termination, in that order, for the same index", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 10n, counterAddr),
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeTryWithPolicies(policyAt(1, POLICY_BREAK_ON_FAIL), false),
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            const receipt = (await tx.wait()) as ContractTransactionReceipt;
            expectSuccess(receipt);

            // A BREAK_ON_FAIL stop is exactly two logs from the account: the failure, then the
            // termination marker — both for call 1. (The `Bumped` log of
            // call 0 comes from the Counter, so filtering by the account's address drops it.)
            const accountLogs = receipt.logs
                .filter((log) => log.address.toLowerCase() === user.address.toLowerCase())
                .map((log) =>
                    userAsDelegate.interface.parseLog({ topics: [...log.topics], data: log.data }),
                );

            expect(accountLogs.map((parsed) => parsed?.name)).to.deep.equal([
                "CallFailed",
                "BatchInterrupted",
            ]);
            expect(accountLogs[0]?.args[0]).to.equal(1n);
            expect(accountLogs[1]?.args[0]).to.equal(1n);
        });

        it("try mode caps the batch at 88 calls (2-bit policy slots); atomic mode has no cap", async () => {
            const { user, userAsDelegate } = await setup();
            const sink = Wallet.createRandom().address as Address;
            const noops = (n: number): Call[] =>
                Array.from({ length: n }, () => ({ target: sink, value: 0n, data: "0x" }));

            // 89 calls under try -> every call must have a 2-bit policy slot -> BatchTooLarge.
            await expect(
                user.sendTransaction({
                    to: user.address,
                    data: userAsDelegate.interface.encodeFunctionData("execute", [
                        MODE_BATCH_TRY,
                        encodeBatch(noops(89)),
                    ]),
                }),
            ).to.be.revertedWithCustomError(userAsDelegate, "BatchTooLarge");

            // Exactly 88 under try -> at the limit, fine.
            const atLimit = await user.sendTransaction({
                to: user.address,
                data: userAsDelegate.interface.encodeFunctionData("execute", [
                    MODE_BATCH_TRY,
                    encodeBatch(noops(88)),
                ]),
            });
            expectSuccess((await atLimit.wait()) as ContractTransactionReceipt);

            // 89 under the default (atomic) exec type -> no policies, no cap.
            const atomicBig = await user.sendTransaction({
                to: user.address,
                data: userAsDelegate.interface.encodeFunctionData("execute", [
                    MODE_BATCH,
                    encodeBatch(noops(89)),
                ]),
            });
            expectSuccess((await atomicBig.wait()) as ContractTransactionReceipt);
        });

        // REGRESSION GUARD for the success side of `_executeBatch`: the atomic path must never
        // consult the policies. If a refactor routed atomic batches through the try-mode policy
        // logic, a payload of `11` slots would end an atomic batch after its first successful
        // call — this test would then see counter == 1.
        it("atomic mode ignores the payload: BREAK_ON_SUCCESS bits do not end an atomic batch early", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            // Atomic exec type (0x00) with a dirty payload: 11 (BREAK_ON_SUCCESS) in slots 0 and 1.
            // The classifier only reads bytes [0], [1] and [6:10], so this is still ModeId.Batch.
            const modeAtomicDirtyPayload =
                "0x0100" +
                "00000000" +
                "00000000" +
                (policyAt(0, POLICY_BREAK_ON_SUCCESS) | policyAt(1, POLICY_BREAK_ON_SUCCESS))
                    .toString(16)
                    .padStart(44, "0");
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                bumpCall(counter, 10n, counterAddr),
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                modeAtomicDirtyPayload,
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(11n); // both calls ran; nothing broke early
            await expect(tx).to.not.emit(userAsDelegate, "BatchInterrupted");
        });

        // FAIL-CLOSED REGRESSION GUARD: atomic mode takes the classic path in `_executeBatch` —
        // any failure reverts, the policies word is never consulted. Index 299 sits far beyond the
        // 128 policy slots a uint256 could carry, so if a refactor ever routed atomic batches
        // through the per-call policy logic (where a missing slot reads as OPTIONAL, i.e. silently
        // skipped), this batch would commit the index-0 bump instead of reverting.
        it("atomic mode is fail-closed past the policy slots: a failure at index 299 of 300 reverts everything", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const sink = Wallet.createRandom().address as Address;
            const calls: Call[] = [
                bumpCall(counter, 7n, counterAddr),
                ...Array.from({ length: 298 }, (): Call => ({ target: sink, value: 0n, data: "0x" })),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH,
                encodeBatch(calls),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(counter, "CounterBoom");
            expect(await counter.value()).to.equal(0n); // the index-0 bump rolled back too
        });

        it("default mode is unchanged: the same failing batch reverts atomically", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH,
                encodeBatch(calls),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(counter, "CounterBoom");
            expect(await counter.value()).to.equal(0n);
        });

        it("executes a single call when the EOA calls itself (msg.sender == address(this))", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH,
                encodeBatch([bumpCall(counter, 42n, counterAddr)]),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            expect(await counter.value()).to.equal(42n);
        });

        it("runs each call of a batch in order via self-call", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const calls: Call[] = [
                bumpCall(counter, 1n, counterAddr),
                bumpCall(counter, 10n, counterAddr),
                bumpCall(counter, 100n, counterAddr),
            ];
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH,
                encodeBatch(calls),
            ]);
            const tx = await user.sendTransaction({ to: user.address, data: calldata });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            expect(await counter.value()).to.equal(111n);
        });

        it("forwards msg.value to the target", async () => {
            const { admin, user, userAsDelegate } = await setup();
            const sink = Wallet.createRandom().address as Address;
            const eoa = user.address as Address;
            // Top up the EOA so it can forward ETH.
            await admin.sendTransaction({ to: eoa, value: parseEther("1") });

            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH,
                encodeBatch([{ target: sink, value: parseEther("0.25"), data: "0x" }]),
            ]);
            const before = await ethers.provider.getBalance(sink);
            const tx = await user.sendTransaction({
                to: eoa,
                data: calldata,
                value: parseEther("0.25"),
            });
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            const after = await ethers.provider.getBalance(sink);
            expect(after - before).to.equal(parseEther("0.25"));
        });

        it("bubbles the inner revert reason from a failing call", async () => {
            const { user, userAsDelegate, token, tokenAddr } = await setup();
            // transfer() of more than balance should revert with ERC20InsufficientBalance.
            const innerData = token.interface.encodeFunctionData("transfer", [
                Wallet.createRandom().address,
                parseUnits("999999999", 18),
            ]);
            const calldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH,
                encodeBatch([{ target: tokenAddr, value: 0n, data: innerData }]),
            ]);
            await expect(
                user.sendTransaction({ to: user.address, data: calldata }),
            ).to.be.revertedWithCustomError(token, "ERC20InsufficientBalance");
        });
    });

    // ───────────────────── ERC-7821 signed batch (opData) ─────────────────────
    describe("ERC-7821 execute — signed batch (opData)", () => {
        it("happy path: anyone can submit, calls run, nonce advances", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                counter,
                counterAddr,
                chainId,
                implAddr,
            } = await setup();

            const calls: Call[] = [bumpCall(counter, 7n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const tx = await userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(7n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
        });

        it("signed try batch: a failing call is logged, the rest runs, the nonce advances", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } =
                await setup();

            const calls: Call[] = [
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 3n, counterAddr),
            ];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA_TRY,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const tx = await userAsDelegate
                .connect(admin)
                .execute(MODE_BATCH_OPDATA_TRY, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect(await counter.value()).to.equal(3n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(0n);
        });

        it("binds the exec type: a signature for the atomic mode is rejected under try mode", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } =
                await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            // Signed for the atomic opData mode, submitted under the try variant: the mode is part of
            // the digest, so the signature must not validate — atomicity cannot be downgraded.
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate
                    .connect(admin)
                    .execute(MODE_BATCH_OPDATA_TRY, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
        });

        it("gasless relay composition: atomic fee transfer + nested try batch for the user's calls", async () => {
            const { admin, user, userAsDelegate, guard, token, tokenAddr, counter, counterAddr, chainId, implAddr } =
                await setup();

            // Outer batch is ATOMIC (default exec type): if the fee transfer fails, nothing runs.
            // The user's calls sit in a nested self-call executed in TRY mode, so their failure
            // cannot roll back the fee — the relayer keeps its payment even if the action reverts.
            const fee = parseUnits("5", 18);
            const relayer = admin.address as Address;
            const userCalls: Call[] = [
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 9n, counterAddr),
            ];
            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [relayer, fee]),
                },
                {
                    // target 0x0 -> address(this) per ERC-7821: the account calls itself in try mode.
                    target: ethers.ZeroAddress as Address,
                    value: 0n,
                    data: userAsDelegate.interface.encodeFunctionData("execute", [
                        MODE_BATCH_TRY,
                        encodeBatch(userCalls),
                    ]),
                },
            ];

            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const relayerBalanceBefore = await token.balanceOf(relayer);
            const tx = await userAsDelegate
                .connect(admin)
                .execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            // Fee survived the failing user call; the non-failing user call still landed.
            expect((await token.balanceOf(relayer)) - relayerBalanceBefore).to.equal(fee);
            expect(await counter.value()).to.equal(9n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(0n);
        });

        it("gasless relay vs out-of-gas griefing: an all-gas-burning user call cannot roll back the fee", async () => {
            const { admin, user, userAsDelegate, guard, token, tokenAddr, chainId, implAddr } =
                await setup();

            // Worst-case grief: the user call OOGs, consuming ALL gas forwarded to it (not a revert).
            // EIP-150 keeps 1/64 in each calling frame, which must cover the tail (event + return) —
            // the fee, already executed in the outer atomic batch, must survive.
            const burner = await deployContract<Counter>("GasBurner" as never, [], admin);
            const burnerAddr = (await burner.getAddress()) as Address;

            const fee = parseUnits("5", 18);
            const relayer = admin.address as Address;
            const userCalls: Call[] = [
                {
                    target: burnerAddr,
                    value: 0n,
                    data: new ethers.Interface(["function burn()"]).encodeFunctionData("burn"),
                },
            ];
            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [relayer, fee]),
                },
                {
                    target: ethers.ZeroAddress as Address,
                    value: 0n,
                    data: userAsDelegate.interface.encodeFunctionData("execute", [
                        MODE_BATCH_TRY,
                        encodeBatch(userCalls),
                    ]),
                },
            ];

            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const relayerBalanceBefore = await token.balanceOf(relayer);
            // Explicit gasLimit: estimation is impossible against an infinite loop, and the relayer
            // pays exactly this much — the burner consumes everything forwarded to it.
            const tx = await userAsDelegate
                .connect(admin)
                .execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)), {
                    gasLimit: 1_000_000,
                });
            const receipt = (await tx.wait()) as ContractTransactionReceipt;
            expectSuccess(receipt);

            // The tx succeeded on the 1/64 reserves, the fee stands, and the OOG shows up as a
            // CallFailed for call 0.
            expect((await token.balanceOf(relayer)) - relayerBalanceBefore).to.equal(fee);
            await expect(tx).to.emit(userAsDelegate, "CallFailed").withArgs(0n);
            // The grief is still expensive for the relayer: nearly the whole gasLimit was consumed.
            expect(receipt.gasUsed).to.be.greaterThan(900_000n);
        });

        it("flat gasless batch via policies: fee is REVERT_ON_FAIL, user calls may fail", async () => {
            const { admin, user, userAsDelegate, guard, token, tokenAddr, counter, counterAddr, chainId, implAddr } =
                await setup();

            // No nesting: one signed try batch where call 0 (the fee) is REVERT_ON_FAIL and the user's
            // calls are best-effort. Replaces the outer-atomic + inner-try composition.
            const fee = parseUnits("5", 18);
            const relayer = admin.address as Address;
            const mode = modeTryWithPolicies(policyAt(0, POLICY_REVERT_ON_FAIL), true); // call 0 = fee transfer
            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [relayer, fee]),
                },
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 9n, counterAddr),
            ];

            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const relayerBalanceBefore = await token.balanceOf(relayer);
            const tx = await userAsDelegate
                .connect(admin)
                .execute(mode, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect((await token.balanceOf(relayer)) - relayerBalanceBefore).to.equal(fee);
            expect(await counter.value()).to.equal(9n);
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(1n);
        });

        it("flat gasless batch via policies: a failing REVERT_ON_FAIL fee reverts everything — drain front-run gives nothing", async () => {
            const { admin, user, userAsDelegate, guard, token, tokenAddr, counter, counterAddr, chainId, implAddr } =
                await setup();

            // The user's token balance is 1000 GAS; a fee of 2000 models a front-run drain — the
            // REVERT_ON_FAIL fee transfer reverts, so the user's calls must NOT execute (no free service).
            const fee = parseUnits("2000", 18);
            const relayer = admin.address as Address;
            const mode = modeTryWithPolicies(policyAt(0, POLICY_REVERT_ON_FAIL), true);
            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [relayer, fee]),
                },
                bumpCall(counter, 9n, counterAddr),
            ];

            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate
                    .connect(admin)
                    .execute(mode, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(token, "ERC20InsufficientBalance");
            expect(await counter.value()).to.equal(0n);
        });

        it("flat gasless batch via policies: REVERT_ON_FAIL fee + BREAK_ON_SUCCESS fallback chain", async () => {
            const { admin, user, userAsDelegate, guard, token, tokenAddr, counter, counterAddr, chainId, implAddr } =
                await setup();

            // Product shape for "route with fallbacks": call 0 is the REVERT_ON_FAIL relayer fee, calls
            // 1 and 2 are BREAK_ON_SUCCESS alternatives (primary route fails -> logged, fallback
            // lands -> batch ends), call 3 is a trailing call that must be skipped by the break.
            const fee = parseUnits("5", 18);
            const relayer = admin.address as Address;
            const mode = modeTryWithPolicies(
                policyAt(0, POLICY_REVERT_ON_FAIL) |
                    policyAt(1, POLICY_BREAK_ON_SUCCESS) |
                    policyAt(2, POLICY_BREAK_ON_SUCCESS),
                true,
            );
            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [relayer, fee]),
                },
                { target: counterAddr, value: 0n, data: counter.interface.encodeFunctionData("boom") },
                bumpCall(counter, 9n, counterAddr),
                bumpCall(counter, 100n, counterAddr),
            ];

            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const relayerBalanceBefore = await token.balanceOf(relayer);
            const tx = await userAsDelegate
                .connect(admin)
                .execute(mode, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect((await token.balanceOf(relayer)) - relayerBalanceBefore).to.equal(fee);
            expect(await counter.value()).to.equal(9n); // fallback landed, trailing bump skipped
            await expect(tx)
                .to.emit(userAsDelegate, "CallFailed").withArgs(1n);
            // The relayer reads which route paid out straight off the log: index 2.
            await expect(tx).to.emit(userAsDelegate, "BatchInterrupted").withArgs(2n);
        });

        it("binds the policies: a relayer cannot downgrade a REVERT_ON_FAIL call", async () => {
            const { admin, user, userAsDelegate, guard, token, tokenAddr, chainId, implAddr } = await setup();

            const fee = parseUnits("5", 18);
            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [admin.address, fee]),
                },
            ];
            const nonce = await guard.nonceOf(user.address);
            // Signed with call 0 REVERT_ON_FAIL (fee), submitted with a zero payload (all OPTIONAL): the
            // policies live in `mode`, which is bound into the digest — the downgrade must not validate.
            const digest = computeExecDigest({
                mode: modeTryWithPolicies(policyAt(0, POLICY_REVERT_ON_FAIL), true),
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate
                    .connect(admin)
                    .execute(modeTryWithPolicies(0n, true), encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
        });

        it("reverts with InvalidSignature when signed by a stranger", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                counter,
                counterAddr,
                chainId,
                implAddr,
            } = await setup();
            const stranger = Wallet.createRandom() as HDNodeWallet;

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const badSig = signRaw(stranger, digest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, badSig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
        });

        it("rejects replay (nonce was consumed by the first call)", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                counter,
                counterAddr,
                chainId,
                implAddr,
            } = await setup();

            const calls: Call[] = [bumpCall(counter, 3n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await wait(userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))));

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
        });

        it("rejects a signature whose digest used the wrong chainId (cross-chain replay)", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                counter,
                counterAddr,
                chainId,
                implAddr,
            } = await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const wrongChainDigest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId: chainId + 1n,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, wrongChainDigest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
        });

        it("rejects a signature whose digest used a different impl address (re-delegation invalidates old sigs)", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                counter,
                counterAddr,
                chainId,
            } = await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const otherImpl = Wallet.createRandom().address as Address;
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr: otherImpl,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
        });

        it("bubbles inner revert from a failing call", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                token,
                tokenAddr,
                chainId,
                implAddr,
            } = await setup();

            const calls: Call[] = [
                {
                    target: tokenAddr,
                    value: 0n,
                    data: token.interface.encodeFunctionData("transfer", [
                        Wallet.createRandom().address,
                        parseUnits("999999999", 18),
                    ]),
                },
            ];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(token, "ERC20InsufficientBalance");
        });

        it("accepts a signature produced by a wallet's signTypedData (eth_signTypedData_v4)", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                counter,
                counterAddr,
                chainId,
                implAddr,
            } = await setup();

            const calls: Call[] = [bumpCall(counter, 11n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);

            // Sign the typed struct directly — no manual digest computation anywhere.
            const sig = await user.signTypedData(
                hermesDomain(chainId, user.address as Address, implAddr),
                EXECUTE_TYPES,
                { mode: MODE_BATCH_OPDATA, calls, nonce, deadline: FAR_FUTURE },
            );

            const tx = await userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            expect(await counter.value()).to.equal(11n);
        });

        it("accepts a 64-byte EIP-2098 compact signature", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            const calls: Call[] = [bumpCall(counter, 13n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const compact = signRawCompact(user, digest);
            expect(compact.length).to.equal(2 + 64 * 2);

            const tx = await userAsDelegate
                .connect(admin)
                .execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, compact)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            expect(await counter.value()).to.equal(13n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
        });

        it("a pending signature is invalidated by consuming its nonce (EOA-style cancel)", async () => {
            const {
                admin,
                user,
                userAsDelegate,
                guard,
                guardAddr,
                counter,
                counterAddr,
                chainId,
                implAddr,
            } = await setup();

            const calls: Call[] = [bumpCall(counter, 5n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            // Cancel: the EOA burns the nonce by calling guard.useNonce() directly —
            // the same lifecycle as replacing a pending EOA transaction.
            const cancelTx = await user.sendTransaction({
                to: guardAddr,
                data: guard.interface.encodeFunctionData("useNonce"),
            });
            expectSuccess((await cancelTx.wait()) as ContractTransactionReceipt);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);
        });

        it("binds mode: a signature is rejected when the submitted mode differs, even in ignored payload bits", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            // modeAlt also classifies as the opData batch (the classifier reads only [0],[1],[6:10]);
            // it differs from MODE_BATCH_OPDATA only in the otherwise-ignored [10:32] payload.
            const modeAlt = "0x01" + "00".repeat(5) + "78210001" + "00".repeat(21) + "01";

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            // Submitting under modeAlt: the contract binds the *submitted* mode, so the reconstructed
            // digest no longer matches the signature. The revert surfaces as InvalidSignature (NOT
            // UnsupportedExecutionMode), which proves modeAlt reached the opData branch and the bind bit.
            await expect(
                userAsDelegate.connect(admin).execute(modeAlt, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);
        });

        it("an opData signature made WITHOUT the mode field (old typehash) no longer validates", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            // The pre-binding EIP-712 type: Execute(Call[] calls,uint256 nonce) — no `mode`.
            const OLD_TYPES = {
                Call: EXECUTE_TYPES.Call,
                Execute: [
                    { name: "calls", type: "Call[]" },
                    { name: "nonce", type: "uint256" },
                ],
            };
            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const oldDigest = TypedDataEncoder.hash(
                hermesDomain(chainId, user.address as Address, implAddr),
                OLD_TYPES,
                { calls, nonce },
            );
            const sig = signRaw(user, oldDigest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);
        });

        it("reverts with ExpiredSignature once block.timestamp passes the signed deadline", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            // A deadline already in the past: the next mined block's timestamp is strictly greater.
            const latest = (await ethers.provider.getBlock("latest"))!.timestamp;
            const pastDeadline = BigInt(latest) - 1n;
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: pastDeadline,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(pastDeadline, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "ExpiredSignature");
            // Fast-failed before consuming the nonce: it stays spendable.
            expect(await counter.value()).to.equal(0n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce);
        });

        it("treats deadline == 0 as no expiry (opt-in default, matching Calibur)", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            const calls: Call[] = [bumpCall(counter, 8n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: 0n,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const tx = await userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(0n, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            expect(await counter.value()).to.equal(8n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
        });

        it("binds deadline: a signature is rejected when opData carries a different (still-future) deadline", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            // Signed over FAR_FUTURE, but submitted with a different future deadline. The submitted
            // deadline passes the time check yet reconstructs a different digest → InvalidSignature
            // (NOT ExpiredSignature), proving the deadline is bound into the signature.
            const otherFuture = FAR_FUTURE + 1n;
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(otherFuture, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);
        });

        it("an opData signature made WITHOUT the deadline field (pre-deadline typehash) no longer validates", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } = await setup();

            // The pre-deadline EIP-712 type: Execute(bytes32 mode,Call[] calls,uint256 nonce) — no `deadline`.
            const PREV_TYPES = {
                Call: EXECUTE_TYPES.Call,
                Execute: [
                    { name: "mode", type: "bytes32" },
                    { name: "calls", type: "Call[]" },
                    { name: "nonce", type: "uint256" },
                ],
            };
            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const prevDigest = TypedDataEncoder.hash(
                hermesDomain(chainId, user.address as Address, implAddr),
                PREV_TYPES,
                { mode: MODE_BATCH_OPDATA, calls, nonce },
            );
            const sig = signRaw(user, prevDigest);

            await expect(
                userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);
        });

        // SECURITY REGRESSION GUARD: the contract's only defense against replay-through-reentry is
        // the ORDER of operations in _verifySignedBatch — the nonce is consumed before any external
        // call. A target reached mid-batch re-submits the exact same signed payload; the re-derived
        // digest uses the already-advanced nonce, so the replay must die with InvalidSignature and
        // the batch must execute exactly once. If the nonce consumption is ever moved after
        // _executeBatch, this test fails with a doubled counter.
        it("reentrancy: a target cannot replay the same signed batch mid-execution (nonce burned first)", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } =
                await setup();

            const attacker = await deployContract<ReentrantTarget>("ReentrantTarget", [], admin);
            const attackerAddr = (await attacker.getAddress()) as Address;

            const calls: Call[] = [
                { target: attackerAddr, value: 0n, data: attacker.interface.encodeFunctionData("attack") },
                bumpCall(counter, 5n, counterAddr),
            ];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);
            const executionData = encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig));

            // Arm the attacker with the byte-identical calldata the relayer is about to submit.
            const fullCalldata = userAsDelegate.interface.encodeFunctionData("execute", [
                MODE_BATCH_OPDATA,
                executionData,
            ]);
            expectSuccess(await wait(attacker.arm(user.address, fullCalldata)));

            const tx = await userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, executionData);
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            // The replay was attempted and rejected with InvalidSignature...
            expect(await attacker.reentered()).to.equal(true);
            expect(await attacker.reentrySucceeded()).to.equal(false);
            expect(await attacker.reentryReturnData()).to.equal(
                userAsDelegate.interface.encodeErrorResult("InvalidSignature"),
            );
            // ...and the batch ran exactly once: one bump, one nonce.
            expect(await counter.value()).to.equal(5n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
        });

        it("cross-account: a signature for account A is rejected on account B sharing the same impl", async () => {
            const { admin, funder, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } =
                await setup();

            // A second EOA delegated to the SAME implementation, with the SAME (zero) nonce — the
            // only thing separating the two accounts is the EIP-712 domain's verifyingContract.
            const userB = Wallet.createRandom().connect(ethers.provider) as HDNodeWallet;
            await funder.sendTransaction({ to: userB.address, value: parseEther("10") });
            await delegateEoaToContract(userB, implAddr, admin);
            const userBAsDelegate = await attachContract<HermesDelegateV1>(
                "HermesDelegateV1",
                userB.address,
                admin,
            );

            const calls: Call[] = [bumpCall(counter, 6n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            expect(await guard.nonceOf(userB.address)).to.equal(nonce); // both 0 — nonce can't save us here

            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address, // signed for account A
                implAddr,
            });
            const sig = signRaw(user, digest);
            const executionData = encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig));

            // Submitted on account B: B's domain reconstructs a different digest -> InvalidSignature.
            await expect(
                userBAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, executionData),
            ).to.be.revertedWithCustomError(userBAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);

            // Sanity: the very same payload is valid on account A — the signature itself was fine.
            const tx = await userAsDelegate.connect(admin).execute(MODE_BATCH_OPDATA, executionData);
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);
            expect(await counter.value()).to.equal(6n);
        });

        it("a signed batch sends ETH from the ACCOUNT's balance; the relayer attaches nothing", async () => {
            const { admin, user, userAsDelegate, guard, chainId, implAddr } = await setup();
            const sink = Wallet.createRandom().address as Address;
            const eoa = user.address as Address;
            const amount = parseEther("0.25");

            const calls: Call[] = [{ target: sink, value: amount, data: "0x" }];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa,
                implAddr,
            });
            const sig = signRaw(user, digest);

            const sinkBefore = await ethers.provider.getBalance(sink);
            const eoaBefore = await ethers.provider.getBalance(eoa);
            // The relayer submits with msg.value == 0: the 0.25 ETH must come out of the account.
            const tx = await userAsDelegate
                .connect(admin)
                .execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig)));
            expectSuccess((await tx.wait()) as ContractTransactionReceipt);

            expect((await ethers.provider.getBalance(sink)) - sinkBefore).to.equal(amount);
            // The account sent no transaction (the relayer paid gas), so its delta is exactly -0.25.
            expect(eoaBefore - (await ethers.provider.getBalance(eoa))).to.equal(amount);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
        });

        it("accepts a signature when block.timestamp == deadline (expiry check is strictly greater-than)", async () => {
            const { admin, user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } =
                await setup();

            const latest = (await ethers.provider.getBlock("latest"))!.timestamp;
            const deadline = BigInt(latest) + 1000n;

            const calls: Call[] = [bumpCall(counter, 4n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const sig = signRaw(user, digest);

            // Mine the executing block at EXACTLY the deadline: `block.timestamp > deadline` is
            // false, so the last valid second must still execute.
            await network.provider.send("evm_setNextBlockTimestamp", [Number(deadline)]);
            const tx = await userAsDelegate
                .connect(admin)
                .execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(deadline, sig)));
            const receipt = (await tx.wait()) as ContractTransactionReceipt;
            expectSuccess(receipt);

            // Prove the boundary was actually exercised, not a block mined earlier.
            expect((await ethers.provider.getBlock(receipt.blockNumber))!.timestamp).to.equal(Number(deadline));
            expect(await counter.value()).to.equal(4n);
            expect(await guard.nonceOf(user.address)).to.equal(nonce + 1n);
        });

    });

    // ───────────────────── ERC-1271 + ERC-7739: isValidSignature ─────────────────────
    describe("isValidSignature (ERC-1271 + ERC-7739 defensive rehashing)", () => {
        const APP_VERIFYING_CONTRACT = "0x000000000000000000000000000000000000A911" as Address;
        const CONTENTS = { stuff: keccak256(toUtf8Bytes("order #42")) };

        const accountOf = (chainId: bigint, eoa: Address, implAddr: Address): AccountDomain => ({
            name: "Hermes",
            version: "v1.0.0",
            chainId,
            verifyingContract: eoa,
            salt: zeroPadValue(implAddr, 32),
        });
        const appOf = (chainId: bigint) => ({
            name: "DemoApp",
            version: "1",
            chainId,
            verifyingContract: APP_VERIFYING_CONTRACT,
        });

        it("TypedDataSign: accepts the EOA's nested typed-data signature", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const { hash, signature } = buildTypedDataSig({
                signer: user,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account: accountOf(chainId, user.address as Address, implAddr),
            });
            expect(await userAsDelegate.isValidSignature(hash, signature)).to.equal(ERC1271_SUCCESS);
        });

        it("TypedDataSign: rejects a signature by a stranger", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const stranger = Wallet.createRandom() as HDNodeWallet;
            const { hash, signature } = buildTypedDataSig({
                signer: stranger,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account: accountOf(chainId, user.address as Address, implAddr),
            });
            expect(await userAsDelegate.isValidSignature(hash, signature)).to.equal(ERC1271_FAILURE);
        });

        it("TypedDataSign: rejects when the embedded account domain is a different account (cross-account replay)", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const otherAccount = Wallet.createRandom().address as Address;
            const { hash, signature } = buildTypedDataSig({
                signer: user,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account: accountOf(chainId, otherAccount, implAddr), // wrong verifyingContract
            });
            expect(await userAsDelegate.isValidSignature(hash, signature)).to.equal(ERC1271_FAILURE);
        });

        it("TypedDataSign: rejects when the embedded salt is a different impl (re-delegation invalidates)", async () => {
            const { user, userAsDelegate, chainId } = await setup();
            const otherImpl = Wallet.createRandom().address as Address;
            const { hash, signature } = buildTypedDataSig({
                signer: user,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account: accountOf(chainId, user.address as Address, otherImpl), // wrong salt
            });
            expect(await userAsDelegate.isValidSignature(hash, signature)).to.equal(ERC1271_FAILURE);
        });

        it("PersonalSign: accepts the EOA's nested personal-sign signature", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const msg = keccak256(toUtf8Bytes("hello hermes"));
            const sig = buildPersonalSig({ signer: user, msgHash: msg, chainId, eoa: user.address as Address, implAddr });
            expect(await userAsDelegate.isValidSignature(msg, sig)).to.equal(ERC1271_SUCCESS);
        });

        it("PersonalSign: rejects a signature by a stranger", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const stranger = Wallet.createRandom() as HDNodeWallet;
            const msg = keccak256(toUtf8Bytes("hello hermes"));
            const sig = buildPersonalSig({ signer: stranger, msgHash: msg, chainId, eoa: user.address as Address, implAddr });
            expect(await userAsDelegate.isValidSignature(msg, sig)).to.equal(ERC1271_FAILURE);
        });

        it("returns the ERC-7739 detection magic 0x77390001 for the sentinel probe", async () => {
            const { userAsDelegate } = await setup();
            const SENTINEL = "0x7739773977397739773977397739773977397739773977397739773977397739";
            expect(await userAsDelegate.isValidSignature(SENTINEL, "0x")).to.equal("0x77390001");
            // A non-empty signature over the sentinel hash still goes through normal validation.
            expect(await userAsDelegate.isValidSignature(SENTINEL, "0xdead")).to.equal(ERC1271_FAILURE);
        });

        it("returns failure for an unrecognized (empty) signature on a normal hash", async () => {
            const { userAsDelegate } = await setup();
            const msg = keccak256(toUtf8Bytes("whatever"));
            expect(await userAsDelegate.isValidSignature(msg, "0x")).to.equal(ERC1271_FAILURE);
        });

        // ERC-1271 consumers (marketplaces, protocols) staticcall isValidSignature and expect
        // 0xffffffff on anything invalid — a revert on malformed input breaks integrations. The
        // 7739 decoder reads structure (trailing uint16 descr length, sliced segments) from
        // attacker-controlled bytes, so feed it every malformed shape.
        it("never reverts on malformed/garbage signature blobs — returns failure", async () => {
            const { user, userAsDelegate } = await setup();
            const msg = keccak256(toUtf8Bytes("garbage probe"));

            const blobs: string[] = [
                "0x" + "ab".repeat(64), // 64B: compact-sig length, garbage
                "0x" + "ab".repeat(65), // 65B: ECDSA length, invalid sig
                // 66B: minimal 7739 length; trailing 0xabab claims a 43947-byte descr > buffer
                "0x" + "ab".repeat(66),
                // trailing uint16 claims a descr longer than the whole blob
                "0x" + "cd".repeat(80) + "ffff",
                // structurally valid 7739 envelope (descr len 16 fits) but every segment is noise
                concat([signRaw(user, msg), keccak256("0x01"), keccak256("0x02"), "0x" + "ee".repeat(16), "0x0010"]),
                "0x" + "00".repeat(200), // all zeros: descr len 0, personal-sign fallback gets 200B sig
            ];
            for (const blob of blobs) {
                expect(await userAsDelegate.isValidSignature(msg, blob)).to.equal(ERC1271_FAILURE);
            }
        });

        it("TypedDataSign: rejects a blob whose contentsDescr is empty", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const { hash, signature } = buildTypedDataSig({
                signer: user,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account: accountOf(chainId, user.address as Address, implAddr),
            });
            // Strip the descr from the otherwise-valid blob: sig(65) ‖ appSeparator ‖ contentsHash ‖ len=0.
            // The `bytes(contentsDescr).length != 0` guard must fail it closed.
            const descrLen = toUtf8Bytes(APP_CONTENTS_DESCR).length;
            const withoutDescr = ethers.dataSlice(signature, 0, ethers.dataLength(signature) - descrLen - 2);
            const emptyDescrBlob = concat([withoutDescr, "0x0000"]);
            expect(await userAsDelegate.isValidSignature(hash, emptyDescrBlob)).to.equal(ERC1271_FAILURE);
        });

        it("TypedDataSign: rejects when `hash` does not match the blob's appSeparator/contentsHash", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const { signature } = buildTypedDataSig({
                signer: user,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account: accountOf(chainId, user.address as Address, implAddr),
            });
            // A hash for DIFFERENT contents with the same (validly signed) blob: the
            // `hash == toTypedDataHash(appSeparator, contentsHash)` cross-check must fail it.
            const otherHash = TypedDataEncoder.hash(appOf(chainId), APP_CONTENTS_TYPES, {
                stuff: keccak256(toUtf8Bytes("order #43")),
            });
            expect(await userAsDelegate.isValidSignature(otherHash, signature)).to.equal(ERC1271_FAILURE);
        });

        it("PersonalSign: rejects a signature nested under another account's domain (cross-account replay)", async () => {
            const { user, userAsDelegate, chainId, implAddr } = await setup();
            const otherAccount = Wallet.createRandom().address as Address;
            const msg = keccak256(toUtf8Bytes("hello hermes"));
            // Signed by the right key but under a domain whose verifyingContract is another account.
            const sig = buildPersonalSig({ signer: user, msgHash: msg, chainId, eoa: otherAccount, implAddr });
            expect(await userAsDelegate.isValidSignature(msg, sig)).to.equal(ERC1271_FAILURE);
        });

        // A verifier that is not ERC-7739-aware routes the account into ERC-1271 by `code.length` and
        // passes a plain digest with a plain signature — including flows where the verifier applies
        // the EIP-191 prefix itself and hands over the already-prefixed hash.
        it("raw ECDSA: accepts a plain 65-byte signature by the account over `hash`", async () => {
            const { user, userAsDelegate } = await setup();
            const hash = keccak256(toUtf8Bytes("app digest"));
            const sig = signRaw(user, hash);
            expect(sig.length).to.equal(2 + 65 * 2);
            expect(await userAsDelegate.isValidSignature(hash, sig)).to.equal(ERC1271_SUCCESS);
        });

        it("raw ECDSA: accepts the 64-byte EIP-2098 compact form of the same signature", async () => {
            const { user, userAsDelegate } = await setup();
            const hash = keccak256(toUtf8Bytes("app digest"));
            const compact = signRawCompact(user, hash);
            expect(compact.length).to.equal(2 + 64 * 2);
            expect(await userAsDelegate.isValidSignature(hash, compact)).to.equal(ERC1271_SUCCESS);
        });

        it("raw ECDSA: rejects a plain signature by a stranger", async () => {
            const { userAsDelegate } = await setup();
            const stranger = Wallet.createRandom() as HDNodeWallet;
            const hash = keccak256(toUtf8Bytes("app digest"));
            for (const sig of [signRaw(stranger, hash), signRawCompact(stranger, hash)]) {
                expect(await userAsDelegate.isValidSignature(hash, sig)).to.equal(ERC1271_FAILURE);
            }
        });

        // ANTI-DRIFT: the account domain the 7739 path uses MUST equal what ERC-5267 eip712Domain() reports.
        // Build the signature from the domain READ from the contract; acceptance proves the 7739 path and
        // the introspection getter agree on exactly one domain.
        it("anti-drift: a domain reconstructed from eip712Domain() validates (7739 ⇄ ERC-5267 agree)", async () => {
            const { user, userAsDelegate, chainId } = await setup();
            const d = await userAsDelegate.eip712Domain();
            const account: AccountDomain = {
                name: d.name,
                version: d.version,
                chainId: d.chainId,
                verifyingContract: d.verifyingContract as Address,
                salt: d.salt,
            };
            const { hash, signature } = buildTypedDataSig({
                signer: user,
                appDomain: appOf(chainId),
                contents: CONTENTS,
                account,
            });
            expect(await userAsDelegate.isValidSignature(hash, signature)).to.equal(ERC1271_SUCCESS);
        });
    });

    // ───────────────────── ERC-4337: validateUserOp + EntryPoint-driven execute ─────────────────────
    describe("ERC-4337 paths (validateUserOp + EntryPoint execute)", () => {
        // Inner callData the EntryPoint forwards after validation: an ERC-7821 no-opData batch.
        const innerExecute = (d: HermesDelegateV1, calls: Call[]): string =>
            d.interface.encodeFunctionData("execute", [MODE_BATCH, encodeBatch(calls)]);

        it("validateUserOp reverts with OnlyEntryPoint when called by anyone else", async () => {
            const { stranger, userAsDelegate, counter, counterAddr } = await setup();
            const userOp = emptyUserOp(
                await userAsDelegate.getAddress(),
                innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]),
                "0x".padEnd(132, "0"), // 65-byte placeholder (not validated past selector check)
            );
            await expect(
                userAsDelegate.connect(stranger).validateUserOp(userOp, ethers.ZeroHash, 0n),
            ).to.be.revertedWithCustomError(userAsDelegate, "OnlyEntryPoint");
        });

        it("validateUserOp reverts with Invalid4337ExecutionSelector for a non-execute selector", async () => {
            const { user, userAsDelegate } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                // callData whose selector is NOT execute(bytes32,bytes) — disallowed in the 4337 path.
                const innerCalldata = userAsDelegate.interface.encodeFunctionData("accountId");
                const sig = signRaw(user, ethers.ZeroHash);
                const userOp = emptyUserOp(user.address, innerCalldata, sig);
                await expect(
                    userAsDelegate.connect(ep).validateUserOp(userOp, ethers.ZeroHash, 0n),
                ).to.be.revertedWithCustomError(userAsDelegate, "Invalid4337ExecutionSelector");
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        // callData shorter than 4 bytes can't even reach the selector comparison: the `[:4]` slice
        // reverts on its bounds check (raw revert, empty data — not Invalid4337ExecutionSelector).
        // For the EntryPoint any validation revert means "op rejected", so this pins down that a
        // short-callData op can NEVER validate — a rewrite of the selector check (assembly
        // calldataload, early return) must not let empty callData slip through to fallback().
        it("validateUserOp rejects callData shorter than 4 bytes (slice reverts before the selector check)", async () => {
            const { user, userAsDelegate } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const userOpHash = keccak256(toUtf8Bytes("short callData"));
                const sig = signRaw(user, userOpHash); // signature is valid — length alone must reject

                for (const shortCallData of ["0x", "0xaabb"]) {
                    const userOp = emptyUserOp(user.address, shortCallData, sig);
                    await expect(
                        userAsDelegate.connect(ep).validateUserOp(userOp, userOpHash, 0n),
                    ).to.be.reverted;
                }
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("validateUserOp returns 0 for a valid signature, 1 for an invalid one", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const innerCalldata = innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]);
                const userOpHash = keccak256(toUtf8Bytes("any 4337 hash"));

                const userOpGood = emptyUserOp(user.address, innerCalldata, signRaw(user, userOpHash));
                expect(
                    await userAsDelegate.connect(ep).validateUserOp.staticCall(userOpGood, userOpHash, 0n),
                ).to.equal(0n);

                const stranger = Wallet.createRandom() as HDNodeWallet;
                const userOpBad = emptyUserOp(user.address, innerCalldata, signRaw(stranger, userOpHash));
                expect(
                    await userAsDelegate.connect(ep).validateUserOp.staticCall(userOpBad, userOpHash, 0n),
                ).to.equal(1n);
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("validateUserOp accepts a 64-byte EIP-2098 compact signature", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const innerCalldata = innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]);
                const userOpHash = keccak256(toUtf8Bytes("compact 4337 hash"));
                const compact = signRawCompact(user, userOpHash);
                expect(compact.length).to.equal(2 + 64 * 2);

                const userOp = emptyUserOp(user.address, innerCalldata, compact);
                expect(
                    await userAsDelegate.connect(ep).validateUserOp.staticCall(userOp, userOpHash, 0n),
                ).to.equal(0n);
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("validateUserOp accepts a batch (multi-call) execute payload", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const innerCalldata = innerExecute(userAsDelegate, [
                    bumpCall(counter, 1n, counterAddr),
                    bumpCall(counter, 2n, counterAddr),
                ]);
                const userOpHash = keccak256(toUtf8Bytes("batch 4337 hash"));
                const userOp = emptyUserOp(user.address, innerCalldata, signRaw(user, userOpHash));
                expect(
                    await userAsDelegate.connect(ep).validateUserOp.staticCall(userOp, userOpHash, 0n),
                ).to.equal(0n);
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("validateUserOp refunds missingAccountFunds to the EntryPoint", async () => {
            const { user, userAsDelegate, counter, counterAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const innerCalldata = innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]);
                const userOpHash = keccak256(toUtf8Bytes("refund test"));
                const userOp = emptyUserOp(user.address, innerCalldata, signRaw(user, userOpHash));

                const refund = parseEther("0.01");
                const eoaBefore = await ethers.provider.getBalance(user.address);
                const epBefore = await ethers.provider.getBalance(ENTRY_POINT_ADDR);

                const tx = await userAsDelegate.connect(ep).validateUserOp(userOp, userOpHash, refund);
                const receipt = (await tx.wait()) as ContractTransactionReceipt;
                expectSuccess(receipt);

                const eoaAfter = await ethers.provider.getBalance(user.address);
                const epAfter = await ethers.provider.getBalance(ENTRY_POINT_ADDR);

                expect(eoaBefore - eoaAfter).to.equal(refund);
                // EP paid gas on this tx (it is the impersonated sender), so its net delta is refund - gasCost.
                const gasCost = receipt.gasUsed * receipt.gasPrice;
                expect(epAfter - epBefore).to.equal(refund - gasCost);
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("EntryPoint may execute a no-opData batch (single call)", async () => {
            const { userAsDelegate, counter, counterAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const tx = await userAsDelegate
                    .connect(ep)
                    .execute(MODE_BATCH, encodeBatch([bumpCall(counter, 9n, counterAddr)]));
                expectSuccess((await tx.wait()) as ContractTransactionReceipt);
                expect(await counter.value()).to.equal(9n);
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("EntryPoint may execute a multi-call batch", async () => {
            const { userAsDelegate, counter, counterAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const calls: Call[] = [
                    bumpCall(counter, 2n, counterAddr),
                    bumpCall(counter, 5n, counterAddr),
                ];
                const tx = await userAsDelegate.connect(ep).execute(MODE_BATCH, encodeBatch(calls));
                expectSuccess((await tx.wait()) as ContractTransactionReceipt);
                expect(await counter.value()).to.equal(7n);
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });

        it("EntryPoint-driven execute bubbles a failing inner call's revert reason", async () => {
            const { userAsDelegate, token, tokenAddr } = await setup();
            const ep = await impersonate(ENTRY_POINT_ADDR as Address);
            try {
                const data = token.interface.encodeFunctionData("transfer", [
                    Wallet.createRandom().address,
                    parseUnits("999999999", 18),
                ]);
                await expect(
                    userAsDelegate
                        .connect(ep)
                        .execute(MODE_BATCH, encodeBatch([{ target: tokenAddr, value: 0n, data }])),
                ).to.be.revertedWithCustomError(token, "ERC20InsufficientBalance");
            } finally {
                await stopImpersonate(ENTRY_POINT_ADDR as Address);
            }
        });
    });

    // ───────────────────── ERC-4337: multi-EntryPoint trust (v0.8 + v0.9) ─────────────────────
    describe("ERC-4337 multi-EntryPoint trust (v0.8 + v0.9)", () => {
        const innerExecute = (d: HermesDelegateV1, calls: Call[]): string =>
            d.interface.encodeFunctionData("execute", [MODE_BATCH, encodeBatch(calls)]);

        const ENTRYPOINTS: ReadonlyArray<readonly [string, Address]> = [
            ["v0.8", ENTRY_POINT_V8_ADDR as Address],
            ["v0.9", ENTRY_POINT_V9_ADDR as Address],
        ];

        it("isSupportedEntryPoint() is true for v0.8 and v0.9 only", async () => {
            const { delegate } = await setup();
            expect(await delegate.isSupportedEntryPoint(ENTRY_POINT_V8_ADDR)).to.equal(true);
            expect(await delegate.isSupportedEntryPoint(ENTRY_POINT_V9_ADDR)).to.equal(true);
            expect(await delegate.isSupportedEntryPoint(Wallet.createRandom().address)).to.equal(false);
            expect(await delegate.isSupportedEntryPoint(ethers.ZeroAddress)).to.equal(false);
        });

        // (a) Both EntryPoints can validate userOps and drive execution.
        for (const [label, epAddr] of ENTRYPOINTS) {
            it(`EntryPoint ${label} can validate a userOp (returns 0 for a valid sig, 1 for an invalid one)`, async () => {
                const { user, userAsDelegate, counter, counterAddr } = await setup();
                const ep = await impersonate(epAddr);
                try {
                    const innerCalldata = innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]);
                    const userOpHash = keccak256(toUtf8Bytes(`op-${label}`));

                    const good = emptyUserOp(user.address, innerCalldata, signRaw(user, userOpHash));
                    expect(
                        await userAsDelegate.connect(ep).validateUserOp.staticCall(good, userOpHash, 0n),
                    ).to.equal(0n);

                    const stranger = Wallet.createRandom() as HDNodeWallet;
                    const bad = emptyUserOp(user.address, innerCalldata, signRaw(stranger, userOpHash));
                    expect(
                        await userAsDelegate.connect(ep).validateUserOp.staticCall(bad, userOpHash, 0n),
                    ).to.equal(1n);
                } finally {
                    await stopImpersonate(epAddr);
                }
            });

            it(`EntryPoint ${label} can drive a no-opData batch execute`, async () => {
                const { userAsDelegate, counter, counterAddr } = await setup();
                const ep = await impersonate(epAddr);
                try {
                    const tx = await userAsDelegate
                        .connect(ep)
                        .execute(MODE_BATCH, encodeBatch([bumpCall(counter, 4n, counterAddr)]));
                    expectSuccess((await tx.wait()) as ContractTransactionReceipt);
                    expect(await counter.value()).to.equal(4n);
                } finally {
                    await stopImpersonate(epAddr);
                }
            });
        }

        // (b) Neither-account-nor-trusted-EntryPoint callers are rejected — proves adding v0.8 did not
        //     widen the trusted set beyond {self, v0.8, v0.9}.
        it("validateUserOp from a non-EntryPoint caller reverts OnlyEntryPoint", async () => {
            const { stranger, userAsDelegate, counter, counterAddr } = await setup();
            const userOp = emptyUserOp(
                await userAsDelegate.getAddress(),
                innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]),
                "0x".padEnd(132, "0"),
            );
            await expect(
                userAsDelegate.connect(stranger).validateUserOp(userOp, ethers.ZeroHash, 0n),
            ).to.be.revertedWithCustomError(userAsDelegate, "OnlyEntryPoint");
        });

        it("no-opData execute from a non-EntryPoint, non-self caller reverts UnauthorizedExecutor", async () => {
            const { stranger, userAsDelegate, counter, counterAddr } = await setup();
            await expect(
                userAsDelegate
                    .connect(stranger)
                    .execute(MODE_BATCH, encodeBatch([bumpCall(counter, 1n, counterAddr)])),
            ).to.be.revertedWithCustomError(userAsDelegate, "UnauthorizedExecutor");
        });

        // (c) THE cross-EntryPoint replay guard. Each EntryPoint binds its own address into the
        //     userOpHash (EIP-712 verifyingContract), so the two hashes differ and a signature made for
        //     one EntryPoint is rejected (validationData == 1) by the other — even though the two
        //     EntryPoints keep independent nonce stores. Replay is blocked at the signature, not the nonce.
        it("a signature for v0.8's userOpHash does NOT validate under v0.9's (no cross-EntryPoint replay)", async () => {
            const { user, userAsDelegate, counter, counterAddr, chainId } = await setup();
            const innerCalldata = innerExecute(userAsDelegate, [bumpCall(counter, 1n, counterAddr)]);
            const op = emptyUserOp(user.address, innerCalldata, "0x");

            const hashV8 = erc4337UserOpHash(op, chainId, ENTRY_POINT_V8_ADDR as Address);
            const hashV9 = erc4337UserOpHash(op, chainId, ENTRY_POINT_V9_ADDR as Address);
            // The EntryPoint-address binding is precisely what makes the two hashes differ.
            expect(hashV8).to.not.equal(hashV9);

            // The signature is produced for v0.8's hash only.
            const sigForV8 = signRaw(user, hashV8);

            const epV8 = await impersonate(ENTRY_POINT_V8_ADDR as Address);
            try {
                // Accepted by v0.8 — the EntryPoint the signature was made for.
                expect(
                    await userAsDelegate
                        .connect(epV8)
                        .validateUserOp.staticCall({ ...op, signature: sigForV8 }, hashV8, 0n),
                ).to.equal(0n);
            } finally {
                await stopImpersonate(ENTRY_POINT_V8_ADDR as Address);
            }

            const epV9 = await impersonate(ENTRY_POINT_V9_ADDR as Address);
            try {
                // Rejected by v0.9 — the v0.8 signature does not recover the EOA over v0.9's hash.
                expect(
                    await userAsDelegate
                        .connect(epV9)
                        .validateUserOp.staticCall({ ...op, signature: sigForV8 }, hashV9, 0n),
                ).to.equal(1n);
            } finally {
                await stopImpersonate(ENTRY_POINT_V9_ADDR as Address);
            }
        });
    });

    // ───────────────────── Cross-path replay (opData ⇄ 4337) ─────────────────────
    // The account has two signing surfaces: the EIP-712 `Execute` struct (opData batches, Hermes
    // domain) and the ERC-4337 userOpHash (EntryPoint's domain). A signature made for one must be
    // dead weight on the other — otherwise one user approval could authorize two executions.
    describe("cross-path replay (opData ⇄ 4337)", () => {
        const innerExecute = (d: HermesDelegateV1, calls: Call[]): string =>
            d.interface.encodeFunctionData("execute", [MODE_BATCH, encodeBatch(calls)]);

        it("an opData Execute signature does not validate as a userOp signature", async () => {
            const { user, userAsDelegate, guard, counter, counterAddr, chainId, implAddr } =
                await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const nonce = await guard.nonceOf(user.address);
            const digest = computeExecDigest({
                mode: MODE_BATCH_OPDATA,
                calls,
                nonce,
                deadline: FAR_FUTURE,
                chainId,
                eoa: user.address as Address,
                implAddr,
            });
            const execSig = signRaw(user, digest);

            // The same calls, smuggled through the 4337 path with the Execute signature attached.
            const op = emptyUserOp(user.address, innerExecute(userAsDelegate, calls), execSig);
            const userOpHash = erc4337UserOpHash(op, chainId, ENTRY_POINT_V9_ADDR as Address);

            const ep = await impersonate(ENTRY_POINT_V9_ADDR as Address);
            try {
                expect(
                    await userAsDelegate.connect(ep).validateUserOp.staticCall(op, userOpHash, 0n),
                ).to.equal(1n);
            } finally {
                await stopImpersonate(ENTRY_POINT_V9_ADDR as Address);
            }
        });

        it("a userOp signature does not validate as an opData Execute signature", async () => {
            const { admin, user, userAsDelegate, counter, counterAddr, chainId } = await setup();

            const calls: Call[] = [bumpCall(counter, 1n, counterAddr)];
            const op = emptyUserOp(user.address, innerExecute(userAsDelegate, calls), "0x");
            const userOpHash = erc4337UserOpHash(op, chainId, ENTRY_POINT_V9_ADDR as Address);
            // A perfectly valid 4337 signature by the right key — for the wrong surface.
            const sig4337 = signRaw(user, userOpHash);

            await expect(
                userAsDelegate
                    .connect(admin)
                    .execute(MODE_BATCH_OPDATA, encodeBatchWithOpData(calls, encodeOpData(FAR_FUTURE, sig4337))),
            ).to.be.revertedWithCustomError(userAsDelegate, "InvalidSignature");
            expect(await counter.value()).to.equal(0n);
        });
    });
});
