import { ethers, network } from "hardhat";
import type { Signer } from "ethers";
import {
  CREATE2_FACTORY,
  CREATE2_FACTORY_RUNTIME_CODE,
  SALT_NAMESPACE,
  SALTS,
  computeCreate2Address,
  getInitCode,
  saveDeployment,
  type ContractDeployment,
  type DeploymentRecord,
} from "./utils/deploy";

/**
 * Deterministic deployment of the Hermes stack via CREATE2:
 *   1. HermesV1          — singleton nonce manager (no constructor args)
 *   2. HermesDelegateV1  — EIP-7702 delegate, constructor: IHermesNonce(manager)
 *
 * Both go through the canonical deterministic deployment proxy, so the same salt
 * + identical init code => identical addresses on every chain. Because the manager
 * lands at the same address everywhere, the delegate's init code (which embeds the
 * manager address) is identical everywhere too — so the delegate address matches as
 * well. The script is idempotent: a contract already present at its predicted
 * address is skipped.
 *
 *   yarn deploy <network>        e.g. yarn deploy sepolia / yarn deploy bsc
 */

async function ensureFactory(): Promise<void> {
  const code = await ethers.provider.getCode(CREATE2_FACTORY);
  if (code !== "0x") return;

  // Dev chains start empty — inject the factory's runtime code, the same way the
  // tests inject the EntryPoint fixture. Real networks must have it pre-deployed.
  if (network.name === "hardhat" || network.name === "localhost") {
    await network.provider.send("hardhat_setCode", [CREATE2_FACTORY, CREATE2_FACTORY_RUNTIME_CODE]);
    console.log(`  injected CREATE2 factory at ${CREATE2_FACTORY} (dev network)\n`);
    return;
  }

  throw new Error(
    `Deterministic deployment proxy not found at ${CREATE2_FACTORY} on "${network.name}".\n` +
      `It is normally pre-deployed on all major chains. See ` +
      `https://github.com/Arachnid/deterministic-deployment-proxy to deploy it.`
  );
}

async function deployDeterministic(
  deployer: Signer,
  contractName: string,
  salt: string,
  args: any[]
): Promise<ContractDeployment> {
  const initCode = await getInitCode(contractName, args);
  const initCodeHash = ethers.keccak256(initCode);
  const address = computeCreate2Address(salt, initCode);

  if ((await ethers.provider.getCode(address)) !== "0x") {
    console.log(`  ${contractName.padEnd(16)} already deployed at ${address} (skipping)`);
    return { address, salt, args, initCodeHash };
  }

  // Arachnid proxy ABI is implicit: calldata = salt (32 bytes) ++ initCode.
  const tx = await deployer.sendTransaction({ to: CREATE2_FACTORY, data: ethers.concat([salt, initCode]) });
  const receipt = await tx.wait();

  if ((await ethers.provider.getCode(address)) === "0x") {
    throw new Error(`${contractName} deployment reverted: no code at predicted address ${address}`);
  }
  console.log(`  ${contractName.padEnd(16)} deployed at ${address}  (tx ${receipt?.hash})`);
  console.log(`  ${"".padEnd(16)} initCodeHash ${initCodeHash}`);
  return { address, salt, args, initCodeHash, txHash: receipt?.hash };
}

async function main(): Promise<void> {
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error(`No signer for "${network.name}". Set DEPLOYER_PRIVATE_KEY in your .env.`);
  }

  const net = await ethers.provider.getNetwork();
  const balance = await ethers.provider.getBalance(deployer.address);

  console.log(`Network:   ${network.name} (chainId ${net.chainId})`);
  console.log(`Deployer:  ${deployer.address}`);
  console.log(`Balance:   ${ethers.formatEther(balance)} ETH`);
  console.log(`Salt:      "${SALT_NAMESPACE}"\n`);

  await ensureFactory();

  console.log("Deploying via CREATE2:");
  // 1. Manager first — its address feeds the delegate's constructor.
  const hermes = await deployDeterministic(deployer, "HermesV1", SALTS.HermesV1, []);

  // 2. Delegate, pinned to the manager we just (re)deployed.
  const delegate = await deployDeterministic(
    deployer,
    "HermesDelegateV1",
    SALTS.HermesDelegateV1,
    [hermes.address]
  );

  // Sanity: the on-chain delegate must point at our manager.
  const delegateContract = await ethers.getContractAt("HermesDelegateV1", delegate.address);
  const wiredManager: string = await delegateContract.manager();
  if (wiredManager.toLowerCase() !== hermes.address.toLowerCase()) {
    throw new Error(`Delegate manager mismatch: expected ${hermes.address}, got ${wiredManager}`);
  }
  console.log(`\nVerified  HermesDelegateV1.manager() == ${wiredManager}`);

  const record: DeploymentRecord = {
    network: network.name,
    chainId: net.chainId.toString(),
    deployer: deployer.address,
    create2Factory: CREATE2_FACTORY,
    saltNamespace: SALT_NAMESPACE,
    contracts: { HermesV1: hermes, HermesDelegateV1: delegate },
    timestamp: new Date().toISOString(),
  };
  saveDeployment(record);
  console.log(`Saved      deployments/${network.name}.json`);
  console.log(`\nNext: yarn verify ${network.name}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
