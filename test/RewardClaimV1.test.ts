import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";
import { Signer } from "ethers";
import { deployContract, wait } from "../scripts/utils/contracts";
import { MockERC20, RewardClaimV1 } from "../typechain-types";

const POOL = ethers.parseEther("1000");
const AMOUNT = ethers.parseEther("5");

describe("RewardClaimV1 (signed reward claims)", () => {
    async function setup() {
        const [deployer, backend, user, relayer, other] = await ethers.getSigners();

        const lit = await deployContract<MockERC20>("MockERC20", ["Lighter", "LIT"], deployer);
        const rewards = await deployContract<RewardClaimV1>(
            "RewardClaimV1",
            [await lit.getAddress(), backend.address],
            deployer,
        );
        await wait(lit.mint(await rewards.getAddress(), POOL));

        return { deployer, backend, user, relayer, other, lit, rewards };
    }

    // What the backend does: sign Claim and hand the client `to` + `calldata`.
    async function signClaim(
        rewards: RewardClaimV1,
        signer: Signer,
        claim: { account: string; amount: bigint; claimId: string; deadline: bigint },
    ) {
        const { chainId } = await ethers.provider.getNetwork();
        const domain = {
            name: "RewardClaim",
            version: "1",
            chainId,
            verifyingContract: await rewards.getAddress(),
        };
        const types = {
            Claim: [
                { name: "account", type: "address" },
                { name: "amount", type: "uint256" },
                { name: "claimId", type: "string" },
                { name: "deadline", type: "uint256" },
            ],
        };
        const signature = await signer.signTypedData(domain, types, claim);

        const to = await rewards.getAddress();
        const data = rewards.interface.encodeFunctionData("claim", [
            claim.amount, claim.claimId, claim.deadline, signature,
        ]);
        return { to, data, signature };
    }

    async function newClaim(account: string, amount = AMOUNT) {
        return {
            account,
            amount,
            // Shaped like the backend id: 32 lowercase chars.
            claimId: ethers.hexlify(ethers.randomBytes(16)).slice(2),
            deadline: BigInt(await time.latest()) + 300n,
        };
    }

    it("pays the caller when the signed account sends the backend calldata", async () => {
        const { backend, user, lit, rewards } = await setup();
        const claim = await newClaim(user.address);
        const { to, data } = await signClaim(rewards, backend, claim);

        await expect(user.sendTransaction({ to, data }))
            .to.emit(rewards, "Claimed").withArgs(claim.claimId, user.address, AMOUNT);

        expect(await lit.balanceOf(user.address)).to.equal(AMOUNT);
        expect(await lit.balanceOf(to)).to.equal(POOL - AMOUNT);
        expect(await rewards.spent(claim.claimId)).to.equal(true);
    });

    it("rejects the proof when anyone but the signed account submits it", async () => {
        const { backend, user, relayer, rewards } = await setup();
        const claim = await newClaim(user.address);
        const { to, data } = await signClaim(rewards, backend, claim);

        await expect(relayer.sendTransaction({ to, data }))
            .to.be.revertedWithCustomError(rewards, "InvalidSignature");
        expect(await rewards.spent(claim.claimId)).to.equal(false);
    });

    it("hashClaim matches the off-chain EIP-712 digest", async () => {
        const { user, rewards } = await setup();
        const claim = await newClaim(user.address);
        const { chainId } = await ethers.provider.getNetwork();

        const offchain = ethers.TypedDataEncoder.hash(
            { name: "RewardClaim", version: "1", chainId, verifyingContract: await rewards.getAddress() },
            { Claim: [
                { name: "account", type: "address" },
                { name: "amount", type: "uint256" },
                { name: "claimId", type: "string" },
                { name: "deadline", type: "uint256" },
            ] },
            claim,
        );

        expect(await rewards.hashClaim(claim.account, claim.amount, claim.claimId, claim.deadline)).to.equal(offchain);
    });

    it("pays one claimId once, even if the backend re-signs it", async () => {
        const { backend, user, lit, rewards } = await setup();
        const claim = await newClaim(user.address);
        const first = await signClaim(rewards, backend, claim);
        const resigned = await signClaim(rewards, backend, { ...claim, deadline: claim.deadline + 3600n });

        await wait(user.sendTransaction(first) as any);

        await expect(user.sendTransaction(first))
            .to.be.revertedWithCustomError(rewards, "ClaimSpent").withArgs(claim.claimId);
        await expect(user.sendTransaction(resigned))
            .to.be.revertedWithCustomError(rewards, "ClaimSpent").withArgs(claim.claimId);
        expect(await lit.balanceOf(user.address)).to.equal(AMOUNT);
    });

    it("rejects a proof after its deadline and accepts it at the deadline", async () => {
        const { backend, user, rewards } = await setup();
        const late = await newClaim(user.address);
        const lateTx = await signClaim(rewards, backend, late);

        await time.setNextBlockTimestamp(late.deadline + 1n);
        await expect(user.sendTransaction(lateTx))
            .to.be.revertedWithCustomError(rewards, "ClaimExpired").withArgs(late.deadline);

        const onTime = await newClaim(user.address);
        const onTimeTx = await signClaim(rewards, backend, onTime);
        await time.setNextBlockTimestamp(onTime.deadline);
        await expect(user.sendTransaction(onTimeTx)).to.emit(rewards, "Claimed");
    });

    it("rejects a proof not signed by the backend", async () => {
        const { other, user, rewards } = await setup();
        const claim = await newClaim(user.address);
        const forged = await signClaim(rewards, other, claim);

        await expect(user.sendTransaction(forged)).to.be.revertedWithCustomError(rewards, "InvalidSignature");
    });

    it("rejects a proof whose amount, claimId or deadline was changed", async () => {
        const { backend, user, rewards } = await setup();
        const claim = await newClaim(user.address);
        const { signature } = await signClaim(rewards, backend, claim);
        const asUser = rewards.connect(user);

        await expect(asUser.claim(claim.amount * 2n, claim.claimId, claim.deadline, signature))
            .to.be.revertedWithCustomError(rewards, "InvalidSignature");
        await expect(asUser.claim(claim.amount, "other-prize", claim.deadline, signature))
            .to.be.revertedWithCustomError(rewards, "InvalidSignature");
        await expect(asUser.claim(claim.amount, claim.claimId, claim.deadline + 1n, signature))
            .to.be.revertedWithCustomError(rewards, "InvalidSignature");
    });

    it("rejects a proof signed for another deployment", async () => {
        const { deployer, backend, user, lit, rewards } = await setup();
        const twin = await deployContract<RewardClaimV1>(
            "RewardClaimV1",
            [await lit.getAddress(), backend.address],
            deployer,
        );
        const claim = await newClaim(user.address);
        const { signature } = await signClaim(twin, backend, claim);

        await expect(rewards.connect(user).claim(claim.amount, claim.claimId, claim.deadline, signature))
            .to.be.revertedWithCustomError(rewards, "InvalidSignature");
    });

    it("leaves the claimId unspent when the pool is short", async () => {
        const { deployer, backend, user, lit, rewards } = await setup();
        const claim = await newClaim(user.address, POOL + 1n);
        const tx = await signClaim(rewards, backend, claim);

        await expect(user.sendTransaction(tx)).to.be.revertedWithCustomError(lit, "ERC20InsufficientBalance");
        expect(await rewards.spent(claim.claimId)).to.equal(false);

        await wait(lit.connect(deployer).mint(await rewards.getAddress(), 1n));
        await expect(user.sendTransaction(tx)).to.emit(rewards, "Claimed");
    });

    it("constructor rejects a zero token or a zero signer", async () => {
        const { deployer, backend, lit, rewards } = await setup();
        const factory = await ethers.getContractFactory("RewardClaimV1", deployer);

        await expect(factory.deploy(ethers.ZeroAddress, backend.address))
            .to.be.revertedWithCustomError(rewards, "ZeroAddress");
        await expect(factory.deploy(await lit.getAddress(), ethers.ZeroAddress))
            .to.be.revertedWithCustomError(rewards, "ZeroAddress");
    });

    it("the backend takes back the rest of the pool by claiming it for itself", async () => {
        const { backend, user, lit, rewards } = await setup();
        await wait(user.sendTransaction(await signClaim(rewards, backend, await newClaim(user.address))) as any);
        const rest = await lit.balanceOf(await rewards.getAddress());

        const drain = await newClaim(backend.address, rest);
        await expect(backend.sendTransaction(await signClaim(rewards, backend, drain)))
            .to.emit(rewards, "Claimed").withArgs(drain.claimId, backend.address, rest);

        expect(await lit.balanceOf(await rewards.getAddress())).to.equal(0n);
        expect(await lit.balanceOf(backend.address)).to.equal(rest);
    });
});
