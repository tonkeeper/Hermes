import { ethers, artifacts, network, config } from "hardhat";
import { execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

/**
 * Canonical deterministic deployment proxy (Arachnid / "Nick's method").
 * Pre-deployed at the SAME address on every supported chain, so deploying through
 * it with a fixed salt yields identical contract addresses across all networks.
 * https://github.com/Arachnid/deterministic-deployment-proxy
 */
export const CREATE2_FACTORY = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/**
 * Runtime bytecode of the proxy above (69 bytes), for injecting onto dev chains
 * via `hardhat_setCode` — a fresh hardhat/localhost node starts empty and has no
 * pre-deployed factory. Fetched verbatim from the live contract on mainnet/Base
 * (eth_getCode at CREATE2_FACTORY).
 */
export const CREATE2_FACTORY_RUNTIME_CODE =
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

/**
 * Namespace mixed into every salt. Override via env to grind a vanity address or
 * to deploy an isolated parallel set. MUST be identical across chains for the
 * resulting addresses to match.
 *
 * "Hermes.v1" is retired: it names a pair built with `optimizer.runs = 10` that exists
 * on Ethereum mainnet only (HermesV1 0x3f7DBb097ecd4F35Aa26af9D6f58F8cBF83E4536,
 * HermesDelegateV1 0xD1c44e466B70002AC54fB727eD7CbE8F92c782f1). The production set is
 * "Hermes.v1.0.0", built with the settings in hardhat.config.ts.
 */
export const SALT_NAMESPACE = process.env.CREATE2_SALT ?? "Hermes.v1.0.0";

/** Per-contract CREATE2 salts. Derived deterministically from the namespace. */
export const SALTS = {
  HermesV1: ethers.id(`${SALT_NAMESPACE}:HermesV1`),
  HermesDelegateV1: ethers.id(`${SALT_NAMESPACE}:HermesDelegateV1`),
} as const;

export interface ContractDeployment {
  address: string;
  salt: string;
  args: any[];
  /**
   * keccak256 of the full init code (creation bytecode ++ constructor args) —
   * the third CREATE2 address ingredient. Records from two networks with equal
   * salts and equal hashes are guaranteed to hold identical addresses; a
   * mismatch pinpoints "different build" as the reason addresses diverged.
   */
  initCodeHash: string;
  txHash?: string;
}

export interface CompilerSettings {
  solc: string;
  optimizerRuns: number;
  viaIR: boolean;
  evmVersion: string;
}

export interface DeploymentRecord {
  network: string;
  chainId: string;
  deployer: string;
  create2Factory: string;
  saltNamespace: string;
  /** Git commit the build was made from; `-dirty` if the tree had uncommitted changes. */
  commit: string;
  /** What produced the init code — with `commit`, enough to rebuild it byte for byte. */
  compiler: CompilerSettings;
  contracts: {
    HermesV1: ContractDeployment;
    HermesDelegateV1: ContractDeployment;
  };
  timestamp: string;
}

export const DEPLOYMENTS_DIR = path.join(__dirname, "..", "..", "deployments");

export function deploymentPath(networkName: string = network.name): string {
  return path.join(DEPLOYMENTS_DIR, `${networkName}.json`);
}

export function loadDeployment(networkName: string = network.name): DeploymentRecord {
  const p = deploymentPath(networkName);
  if (!fs.existsSync(p)) {
    throw new Error(`No deployment found at ${p}. Run the deploy script for "${networkName}" first.`);
  }
  return JSON.parse(fs.readFileSync(p, "utf8"));
}

export function saveDeployment(record: DeploymentRecord): void {
  if (!fs.existsSync(DEPLOYMENTS_DIR)) {
    fs.mkdirSync(DEPLOYMENTS_DIR, { recursive: true });
  }
  fs.writeFileSync(deploymentPath(record.network), JSON.stringify(record, null, 2) + "\n");
}

/** CREATE2 address an initcode would land at when deployed through the canonical factory. */
export function computeCreate2Address(salt: string, initCode: string): string {
  return ethers.getCreate2Address(CREATE2_FACTORY, salt, ethers.keccak256(initCode));
}

/**
 * Full init code = creation bytecode ++ abi-encoded constructor args. Built from the
 * artifact alone, so it needs no signer and works on a network without accounts.
 */
export async function getInitCode(contractName: string, args: any[] = []): Promise<string> {
  const artifact = await artifacts.readArtifact(contractName);
  const encodedArgs = new ethers.Interface(artifact.abi).encodeDeploy(args);
  return ethers.concat([artifact.bytecode, encodedArgs]);
}

/** HEAD commit of the checkout the script runs from, flagged when the tree is not clean. */
export function gitCommit(): { hash: string; dirty: boolean } {
  const run = (cmd: string) => execSync(cmd, { stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  try {
    const hash = run("git rev-parse HEAD");
    const dirty = run("git status --porcelain --untracked-files=no") !== "";
    return { hash, dirty };
  } catch {
    return { hash: "unknown", dirty: true };
  }
}

/** The compiler settings every network must share for the CREATE2 addresses to match. */
export function compilerSettings(): CompilerSettings {
  const compiler = config.solidity.compilers[0];
  const settings = compiler.settings ?? {};
  return {
    solc: compiler.version,
    optimizerRuns: settings.optimizer?.runs ?? 200,
    viaIR: Boolean(settings.viaIR),
    evmVersion: settings.evmVersion ?? "default",
  };
}
