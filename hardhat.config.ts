import { HardhatUserConfig } from "hardhat/config";
import * as dotenv from "dotenv";
import "@nomicfoundation/hardhat-toolbox";
import "hardhat-abi-exporter";

dotenv.config();

// Single deployer key, used for every remote network. Leave unset to compile/test.
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY;
const accounts = DEPLOYER_PRIVATE_KEY ? [DEPLOYER_PRIVATE_KEY] : [];

// One Etherscan v2 key covers every supported explorer (eth, bsc, arbitrum, base, ...).
// Get it at https://etherscan.io/myapikey. A single string => v2 unified endpoint.
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY ?? "";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.35",
    settings: {
      viaIR: true,
      evmVersion: "prague",
      optimizer: {
        enabled: true,
        runs: 10,
      },
    },
  },
  networks: {
    localhost: {
      url: "http://127.0.0.1:8545",
      accounts: ["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"], // first hardhat account
    },

    // ── Mainnets ──
    mainnet: {
      url: process.env.ETH_RPC_URL ?? "https://eth.llamarpc.com",
      chainId: 1,
      accounts,
    },
    bsc: {
      url: process.env.BSC_RPC_URL ?? "https://bsc-dataseed.binance.org",
      chainId: 56,
      accounts,
    },
    arbitrumOne: {
      url: process.env.ARBITRUM_RPC_URL ?? "https://arb1.arbitrum.io/rpc",
      chainId: 42161,
      accounts,
    },
    base: {
      url: process.env.BASE_RPC_URL ?? "https://mainnet.base.org",
      chainId: 8453,
      accounts,
    },

    // ── Testnets ──
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL ?? "https://ethereum-sepolia-rpc.publicnode.com",
      chainId: 11155111,
      accounts,
    },
    bscTestnet: {
      url: process.env.BSC_TESTNET_RPC_URL ?? "https://data-seed-prebsc-1-s1.binance.org:8545",
      chainId: 97,
      accounts,
    },
    arbitrumSepolia: {
      url: process.env.ARBITRUM_SEPOLIA_RPC_URL ?? "https://sepolia-rollup.arbitrum.io/rpc",
      chainId: 421614,
      accounts,
    },
    baseSepolia: {
      url: process.env.BASE_SEPOLIA_RPC_URL ?? "https://sepolia.base.org",
      chainId: 84532,
      accounts,
    },
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
  },
  abiExporter: [
    {
      path: "reports/abi",
      format: "json",
    },
  ],
  gasReporter: {
    enabled: Boolean(JSON.parse(process.env.REPORT_GAS || "false")),
    outputFile: "reports/gas",
    coinmarketcap: process.env.CMC_API,
  },
};

export default config;
