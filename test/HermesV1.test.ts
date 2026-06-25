import { expect } from "chai";
import { ethers } from "hardhat";
import { deployContract, expectSuccess, wait } from "../scripts/utils/contracts";
import { HermesV1 } from "../typechain-types";

// HermesV1 is the trust anchor of the signed-batch replay protection: every delegate pins it as
// an immutable dependency and folds its nonce into the EIP-712 digest. These tests pin down the
// contract's three documented invariants directly (they are otherwise only exercised through
// HermesDelegateV1): pre-increment return, sequential advance, and strict per-account isolation.
describe("HermesV1 (singleton nonce manager)", () => {
    async function setup() {
        const [admin, accountA, accountB] = await ethers.getSigners();
        const guard = await deployContract<HermesV1>("HermesV1", [], admin);
        return { admin, accountA, accountB, guard };
    }

    it("useNonce returns the pre-increment value and advances by exactly one", async () => {
        const { accountA, guard } = await setup();

        expect(await guard.nonceOf(accountA.address)).to.equal(0n);
        // staticCall previews the return value the delegate would bind into a digest...
        expect(await guard.connect(accountA).useNonce.staticCall()).to.equal(0n);
        // ...and the real call consumes exactly that slot.
        expectSuccess(await wait(guard.connect(accountA).useNonce()));
        expect(await guard.nonceOf(accountA.address)).to.equal(1n);
        expect(await guard.connect(accountA).useNonce.staticCall()).to.equal(1n);
    });

    it("nonces are sequential and monotonic across repeated useNonce calls", async () => {
        const { accountA, guard } = await setup();

        for (const expected of [0n, 1n, 2n]) {
            expect(await guard.connect(accountA).useNonce.staticCall()).to.equal(expected);
            expectSuccess(await wait(guard.connect(accountA).useNonce()));
        }
        expect(await guard.nonceOf(accountA.address)).to.equal(3n);
    });

    it("per-account isolation: advancing A's nonce never moves B's", async () => {
        const { accountA, accountB, guard } = await setup();

        expectSuccess(await wait(guard.connect(accountA).useNonce()));
        expectSuccess(await wait(guard.connect(accountA).useNonce()));

        // B's counter is untouched by A's activity — no cross-account read/advance/grief.
        expect(await guard.nonceOf(accountB.address)).to.equal(0n);
        expect(await guard.connect(accountB).useNonce.staticCall()).to.equal(0n);

        expectSuccess(await wait(guard.connect(accountB).useNonce()));
        expect(await guard.nonceOf(accountB.address)).to.equal(1n);
        expect(await guard.nonceOf(accountA.address)).to.equal(2n);
    });
});
