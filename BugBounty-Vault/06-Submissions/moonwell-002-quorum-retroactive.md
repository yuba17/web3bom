---
tags: [submission, code4rena, moonwell]
severity: High
status: draft
---

# [H-02] MultichainGovernor uses current quorum instead of snapshot, allowing retroactive manipulation of proposal outcomes

## Summary

`MultichainGovernor.state()` compares `proposal.totalVotes` against the current `quorum` value rather than the quorum at proposal creation time. Changing quorum via governance retroactively changes the outcome of all non-executed proposals.

## Vulnerability Detail

In `MultichainGovernor.sol`, the `state()` function (line 546) uses:

```solidity
if (proposal.totalVotes < quorum) {
    return ProposalState.Defeated;
}
```

The `quorum` variable is a storage variable that can be changed via `_setQuorum()`. When quorum changes, ALL proposals in Active, CrossChainVoteCollection, or Succeeded states are retroactively re-evaluated:

- **Quorum decreased**: Previously Defeated proposals may become Succeeded and executable
- **Quorum increased**: Previously Succeeded proposals become Defeated

This violates the principle that governance rules should be fixed at the time of proposal creation.

## Impact

**Attack scenario:**
1. Attacker creates Proposal A with a malicious payload
2. Proposal A gets 500K votes (current quorum is 1M) → Defeated
3. Attacker (or ally) creates Proposal B to reduce quorum to 400K
4. Proposal B passes legitimately
5. Proposal A retroactively becomes Succeeded (500K > 400K new quorum)
6. Anyone can now execute Proposal A's malicious payload

**Reverse scenario:**
- A legitimate proposal that has Succeeded but not yet been executed can be killed by a quorum increase

## Proof of Concept

```solidity
function testQuorumRetroactiveChange() public {
    // 1. Create proposal with current quorum = 1M
    uint proposalId = governor.propose(...);

    // 2. Vote 500K → Defeated
    governor.castVote(proposalId, 1); // 500K votes
    assertEq(uint(governor.state(proposalId)), uint(ProposalState.Defeated));

    // 3. Reduce quorum to 400K via governance
    governor._setQuorum(400_000e18);

    // 4. Same proposal is now Succeeded
    assertEq(uint(governor.state(proposalId)), uint(ProposalState.Succeeded));

    // 5. Execute previously-defeated proposal
    governor.execute(proposalId); // SUCCEEDS
}
```

## Recommended Mitigation

Snapshot quorum at proposal creation time:

```solidity
struct Proposal {
    ...
    uint256 quorumAtCreation; // ADD THIS
    ...
}

function propose(...) {
    ...
    newProposal.quorumAtCreation = quorum; // SNAPSHOT
    ...
}

function state(uint256 proposalId) public view returns (ProposalState) {
    ...
    if (proposal.totalVotes < proposal.quorumAtCreation) { // USE SNAPSHOT
        return ProposalState.Defeated;
    }
    ...
}
```
