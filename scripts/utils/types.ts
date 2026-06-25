// define the same export types as used by export typechain/ethers
import {BytesLike} from 'ethers'

export type Address = string

export function bytes32(num: BytesLike): BytesLike {
    if (num.length <= 32) {
        return num
    }

    return num.slice(0, 32)
}
