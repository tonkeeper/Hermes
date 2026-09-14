import { ethers } from "hardhat";
import {
  CREATE2_FACTORY,
  SALT_NAMESPACE,
  SALTS,
  computeCreate2Address,
  compilerSettings,
  getInitCode,
  gitCommit,
} from "./utils/deploy";

/**
 * Prints the addresses the current build lands at when deployed through the canonical
 * CREATE2 proxy — the same on every chain — without sending a transaction.
 *
 *   yarn predict
 */
async function main(): Promise<void> {
  const { hash, dirty } = gitCommit();
  const compiler = compilerSettings();

  console.log(`Build:     ${hash}${dirty ? " (uncommitted changes)" : ""}`);
  console.log(
    `Compiler:  solc ${compiler.solc}, optimizer runs ${compiler.optimizerRuns}, viaIR ${compiler.viaIR}, ${compiler.evmVersion}`
  );
  console.log(`Factory:   ${CREATE2_FACTORY}`);
  console.log(`Salt:      "${SALT_NAMESPACE}"\n`);

  const managerInitCode = await getInitCode("HermesV1", []);
  const manager = computeCreate2Address(SALTS.HermesV1, managerInitCode);
  const delegateInitCode = await getInitCode("HermesDelegateV1", [manager]);
  const delegate = computeCreate2Address(SALTS.HermesDelegateV1, delegateInitCode);

  console.log(`HermesV1          ${manager}`);
  console.log(`  initCodeHash    ${ethers.keccak256(managerInitCode)}`);
  console.log(`HermesDelegateV1  ${delegate}`);
  console.log(`  initCodeHash    ${ethers.keccak256(delegateInitCode)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
