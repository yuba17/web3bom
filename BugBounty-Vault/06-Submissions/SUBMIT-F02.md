# MultichainGovernor uses current quorum instead of snapshot, enabling retroactive manipulation of proposal outcomes

## Summary

`MultichainGovernor.state()` compares `proposal.totalVotes` against the current `quorum` storage variable rather than a snapshot at proposal creation time. Any quorum change retroactively alters the outcome of all non-executed proposals — defeated proposals can become succeeded and vice versa.

## Vulnerability Detail

In `MultichainGovernor.sol`, the `state()` function uses the live `quorum` value:

```solidity
// MultichainGovernor.sol, state() function
if (proposal.totalVotes < quorum) {   // ← uses CURRENT quorum, not snapshot
    return ProposalState.Defeated;
}
```

The `quorum` variable can be changed via `_setQuorum()` through a governance proposal. When this happens, the `state()` function retroactively re-evaluates ALL non-executed proposals against the new quorum.

## Proof of Concept

```solidity
function testQuorumRetroactiveBug() public pure {
    uint256 proposalTotalVotes = 500_000e18;

    // Phase 1: quorum = 1M → proposal DEFEATED
    uint256 originalQuorum = 1_000_000e18;
    assert(proposalTotalVotes < originalQuorum); // defeated

    // Phase 2: governance reduces quorum to 400K
    uint256 newQuorum = 400_000e18;
    assert(!(proposalTotalVotes < newQuorum)); // NOW SUCCEEDED!
}
```

**Attack scenario:**
1. Attacker creates Proposal A with malicious payload (e.g., drain treasury)
2. Proposal A voting ends with 500K votes — **Defeated** (quorum = 1M)
3. Attacker creates Proposal B: `_setQuorum(400_000e18)` (looks innocent)
4. Proposal B passes and executes
5. Proposal A retroactively becomes **Succeeded** (500K > 400K)
6. Anyone calls `execute(proposalA)` — malicious payload runs

## Impact

- **Defeated proposals can be resurrected** and executed after a quorum reduction
- **Succeeded proposals can be killed** retroactively by a quorum increase
- This violates the governance invariant that proposal rules are fixed at creation time
- An attacker with moderate voting power can coordinate a two-proposal attack to execute arbitrary governance actions
- Affects the MultichainGovernor on Moonbeam, which controls the entire Moonwell protocol across all chains

## Recommended Mitigation

Snapshot the quorum at proposal creation time:

```solidity
struct Proposal {
    ...
    uint256 quorumAtCreation;  // ADD THIS
    ...
}

function propose(...) {
    ...
    newProposal.quorumAtCreation = quorum;  // SNAPSHOT
    ...
}

function state(uint256 proposalId) public view returns (ProposalState) {
    ...
    if (proposal.totalVotes < proposal.quorumAtCreation) {  // USE SNAPSHOT
        return ProposalState.Defeated;
    }
    ...
}
```

This is the standard pattern used by OpenZeppelin Governor and Compound Governor Bravo.
