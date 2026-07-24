import {
    BaseContract,
    ContractRunner,
    ContractTransactionReceipt,
    ContractTransactionResponse,
    EventLog,
    FunctionFragment,
    Log, LogDescription, Signer
} from "ethers";
import {ethers} from "hardhat";
import {Address} from "./types";

export interface Selector {
    name: string;
    value: string;
}

export function selectors(selector: Selector[], filter: string[]) {
    return selector.filter(s => filter.includes(s.name)).map(s => s.value)
}

export async function obtainSelectors<T extends BaseContract>(contract: T) {
    return contract.interface.fragments
        .filter((f) => f.type == "function")
        .map((f) => {
            return {
              name: (f as FunctionFragment).name,
              value: (f as FunctionFragment).selector
            } as Selector
        })
}

export async function deployContract<T extends BaseContract>(
    name: string,
    args: any[] = [],
    admin: Signer,
    runner: ContractRunner = admin,
): Promise<T> {
    const contract = (await ethers.deployContract(name, args, { signer: admin }))
    await contract.waitForDeployment()

    return contract.connect(runner) as T
}

export async function attachContract<T extends BaseContract>(
    name: string,
    address: Address,
    runner: ContractRunner
): Promise<T> {
    const contractFactory = await ethers.getContractFactory(name)
    const contract = contractFactory.attach(address)

    return contract.connect(runner) as T
}

export async function getFactory(
    name: string,
) {
    const contractFactory = await ethers.getContractFactory(name)
    return contractFactory
}

export async function attachInterface<T extends BaseContract>(
    name: string,
    address: Address,
    runner: ContractRunner
): Promise<T> {
    const contract = await ethers.getContractAt(name, address)
    return contract.connect(runner) as T
}

export async function wait(p: Promise<ContractTransactionResponse>): Promise<ContractTransactionReceipt> {
    const result = (await ((await p).wait()))

    if (result == null) {
        console.log(`Wait ContractTransactionReceipt is NULL!`)
    }

    return result!
}

export function expectSuccess(receipt: ContractTransactionReceipt | null) {
    if (!receipt) {
        throw new Error("Transaction receipt is null")
    }

    if (receipt.status !== 1) {
        throw new Error(`Transaction failed with status: ${receipt.status}`)
    }
}

export function findEvent(
    name: string,
    events: Array<EventLog | Log> | undefined,
    contract?: BaseContract
): EventLog | LogDescription | null {
    if (!events) {
        return null
    }

    // First try to find the event as EventLog (normal case)
    const eventLog = events.find((event) => {
        return event instanceof EventLog && event.eventName === name
    })

    if (eventLog) {
        return eventLog as EventLog
    }

    // If not found and contract is provided, try parsing raw logs (multicall case)
    if (contract) {
        for (const log of events) {
            try {
                const parsedLog = contract.interface.parseLog({
                    topics: log.topics,
                    data: log.data
                });
                if (parsedLog?.name === name) {
                    return parsedLog;
                }
            } catch (e) {
                // Skip logs that can't be parsed by this contract's interface
            }
        }
    }

    return null
}

export function spent(result: ContractTransactionReceipt): string {
    return `${ethers.formatEther(result.cumulativeGasUsed * result.gasPrice)} = ${result.cumulativeGasUsed} * ${result.gasPrice}`
}
