import { run, network } from "hardhat";
import { loadDeployment, type ContractDeployment } from "./utils/deploy";

/**
 * Verifies the deployed Hermes stack on the active network's block explorer,
 * reading addresses and constructor args from deployments/<network>.json.
 *
 *   yarn verify <network>        e.g. yarn verify sepolia / yarn verify bsc
 *
 * Requires ETHERSCAN_API_KEY (a single Etherscan v2 key covers all chains).
 */

/**
 * Fully-qualified names pin each verification to its exact source unit, so the
 * explorer never has to guess between contracts with similar bytecode.
 */
const CONTRACT_FQN: Record<string, string> = {
  HermesV1: "contracts/v1/HermesV1.sol:HermesV1",
  HermesDelegateV1: "contracts/v1/HermesDelegateV1.sol:HermesDelegateV1",
};

/**
 * A freshly deployed contract takes the explorer a moment to index; until then
 * verification fails with a "no bytecode" style error. These are transient —
 * retry instead of failing the `yarn deploy && yarn verify` flow.
 */
const RETRYABLE_ERRORS = ["does not have bytecode", "unable to locate", "rate limit"];
const MAX_ATTEMPTS = 5;
const RETRY_DELAY_MS = 10_000;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

async function verifyOne(name: string, deployment: ContractDeployment): Promise<void> {
  console.log(`Verifying ${name} at ${deployment.address} ...`);

  for (let attempt = 1; ; attempt++) {
    try {
      await run("verify:verify", {
        address: deployment.address,
        constructorArguments: deployment.args,
        contract: CONTRACT_FQN[name],
      });
      console.log(`  ${name}: verified`);
      return;
    } catch (error: any) {
      const message: string = (error?.message ?? String(error)).toLowerCase();
      if (message.includes("already verified")) {
        console.log(`  ${name}: already verified`);
        return;
      }
      if (attempt >= MAX_ATTEMPTS || !RETRYABLE_ERRORS.some((e) => message.includes(e))) {
        throw error;
      }
      console.log(
        `  ${name}: explorer has not indexed it yet (attempt ${attempt}/${MAX_ATTEMPTS}), ` +
          `retrying in ${RETRY_DELAY_MS / 1000}s ...`
      );
      await sleep(RETRY_DELAY_MS);
    }
  }
}

async function main(): Promise<void> {
  if (!process.env.ETHERSCAN_API_KEY) {
    throw new Error(
      "ETHERSCAN_API_KEY is not set. Add it to .env — a single Etherscan v2 key " +
        "(https://etherscan.io/myapikey) covers every supported chain."
    );
  }

  const deployment = loadDeployment();
  console.log(`Verifying on ${network.name} (chainId ${deployment.chainId})\n`);

  await verifyOne("HermesV1", deployment.contracts.HermesV1);
  await verifyOne("HermesDelegateV1", deployment.contracts.HermesDelegateV1);

  console.log("\nDone.");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
