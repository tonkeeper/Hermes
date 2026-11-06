// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

/**
 * @title RewardClaimV1 - Pays out loyalty rewards in one ERC20 token against a backend-signed proof.
 * @author anchupin
 * @notice The contract holds a pool of `token`. When a user wins a prize, the backend signs an
 *         EIP-712 `Claim(account, amount, claimId, deadline)` and hands the client a ready
 *         `to` + `calldata` for `claim(...)`. The user's account sends that call; the contract checks
 *         the signature against `msg.sender` and transfers `amount` to it. The caller pays the gas,
 *         so a gasless relay can pay it like any other call.
 *
 * @dev Design and trust model:
 *      - **Only the signed account can claim.** `account` in the signed struct is `msg.sender`, and
 *        the tokens go to it. A proof is useless to anyone else, so leaking or front-running it
 *        gains nothing. The account must be the direct caller: an EOA, or a 7702-delegated account
 *        that makes the call itself. A relayer or a contract calling on the user's behalf cannot.
 *      - **One payout per `claimId`.** The backend picks one `claimId` string per prize. Once
 *        claimed it is spent forever, so the backend may re-sign the same prize as often as it
 *        likes (e.g. a fresh deadline after the old one passed) without risking a double payout.
 *        Ids compare byte for byte: "abc" and "ABC" are two different prizes.
 *      - **Time-bound proofs.** A proof is valid up to and including `deadline`.
 *      - **Domain-bound proofs.** The EIP-712 domain carries the chain id and this contract's
 *        address, so a proof cannot be replayed on another chain or another deployment.
 *      - **Fixed signer, no owner.** The signer is set once in the constructor and nothing can
 *        change the contract afterwards. The signer is the only authority: to take back what is
 *        left of the pool, the backend signs a claim for its own address and sends it. A leaked
 *        signer key exposes the whole pool, so the backend drains it the same way and a new
 *        deployment takes over with a new key. Tokens other than `token` sent here are lost.
 *      - **Plain ECDSA.** `signer` is an EOA key and a proof is its 65-byte `r‖s‖v` signature over
 *        the EIP-712 digest, checked with `ecrecover` alone. There is no ERC-1271 path, so code at
 *        the signer address (an EIP-7702 delegation, say) neither enables nor breaks verification.
 *      - **A failed transfer spends nothing.** If the pool is short, `claim` reverts and the
 *        `claimId` stays unspent; the same proof works again once the pool is topped up.
 *
 * @custom:security-contact bugs@tonkeeper.com
 */
contract RewardClaimV1 is EIP712 {
    using SafeERC20 for IERC20;

    /// @dev keccak256("Claim(address account,uint256 amount,string claimId,uint256 deadline)")
    bytes32 public constant CLAIM_TYPEHASH =
        keccak256("Claim(address account,uint256 amount,string claimId,uint256 deadline)");

    /// @notice The token paid out by every claim.
    IERC20 public immutable token;

    /// @notice The backend key whose signatures authorize claims.
    address public immutable signer;

    /// @notice Whether a `claimId` was already paid out.
    mapping(string claimId => bool) public spent;

    /// @dev `claimId` is not indexed: an indexed string keeps only its hash, and the log should show the id itself.
    event Claimed(string claimId, address indexed account, uint256 amount);

    error ZeroAddress();
    error ClaimExpired(uint256 deadline);
    error ClaimSpent(string claimId);
    error InvalidSignature();

    /**
     * @param token_ The reward token (LIT).
     * @param signer_ The backend key that signs claims.
     */
    constructor(IERC20 token_, address signer_) EIP712("RewardClaim", "1") {
        // No signature recovers to the zero address, so a zero signer would make every claim fail.
        if (address(token_) == address(0) || signer_ == address(0)) {
            revert ZeroAddress();
        }

        token = token_;
        signer = signer_;
    }

    /**
     * @notice Pays `amount` of `token` to the caller against a backend signature.
     * @param amount The reward amount, in token units.
     * @param claimId The backend's unique id of this prize.
     * @param deadline The last timestamp at which the proof is valid.
     * @param signature The backend's 65-byte ECDSA signature over the EIP-712 digest of
     *                  `Claim(msg.sender, amount, claimId, deadline)`.
     */
    function claim(
        uint256 amount,
        string calldata claimId,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) {
            revert ClaimExpired(deadline);
        }

        if (spent[claimId]) {
            revert ClaimSpent(claimId);
        }

        bytes32 digest = hashClaim(msg.sender, amount, claimId, deadline);
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecoverCalldata(digest, signature);
        if (err != ECDSA.RecoverError.NoError || recovered != signer) {
            revert InvalidSignature();
        }

        // Spend the id before the transfer: a reentrant token cannot pay the same prize twice.
        spent[claimId] = true;
        emit Claimed(claimId, msg.sender, amount);
        token.safeTransfer(msg.sender, amount);
    }

    /**
     * @notice Returns the EIP-712 digest the backend signs for a claim.
     * @dev Lets the backend and tests check their digest against the contract's.
     */
    function hashClaim(
        address account,
        uint256 amount,
        string calldata claimId,
        uint256 deadline
    ) public view returns (bytes32) {
        // EIP-712 encodes a string field as the hash of its bytes.
        bytes32 structHash = keccak256(abi.encode(CLAIM_TYPEHASH, account, amount, keccak256(bytes(claimId)), deadline));
        return _hashTypedDataV4(structHash);
    }
}
