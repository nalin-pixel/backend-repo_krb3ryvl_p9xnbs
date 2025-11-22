// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * Minimal demo smart contract for recording anonymized votes.
 * In a real system, integrate a zkSNARK verifier contract and enforce one-vote-per-publicKeyHash.
 */
contract VoteZK {
    struct Vote {
        bytes32 candidateHash;
        bytes zkProof; // opaque blob; real verifier would validate
        uint256 timestamp;
    }

    address public admin;
    mapping(bytes32 => bool) public hasVoted; // publicKeyHash => voted
    mapping(bytes32 => Vote) public votes; // publicKeyHash => vote data

    event VoteCast(bytes32 indexed voterHash, bytes32 candidateHash, bytes txSender, uint256 time);

    constructor() {
        admin = msg.sender;
    }

    function registerVoter(bytes32 voterHash) external {
        require(msg.sender == admin, "only admin");
        require(!hasVoted[voterHash], "already registered or voted");
        // Registration marker; no-op beyond preventing reuse
        hasVoted[voterHash] = false;
    }

    function castVote(bytes32 candidateHash, bytes calldata zkProof) external {
        // In production, derive voterHash from a signature or nullifier; here we use msg.sender based hash
        bytes32 voterHash = keccak256(abi.encodePacked(msg.sender));
        require(!hasVoted[voterHash], "duplicate vote");
        // TODO: integrate zk verifier to check zkProof validity
        votes[voterHash] = Vote({ candidateHash: candidateHash, zkProof: zkProof, timestamp: block.timestamp });
        hasVoted[voterHash] = true;
        emit VoteCast(voterHash, candidateHash, abi.encode(msg.sender), block.timestamp);
    }

    function tallyCandidate(bytes32 candidateHash) external view returns (uint256 count) {
        // Not efficient on-chain; provided for completeness demo. Off-chain tally is recommended.
        // In a real implementation, store per-candidate counters.
        // This function will always return 0 here because we didn't iterate storage mapping.
        return 0;
    }
}
