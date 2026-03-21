# Finding Title

## Summary
2-3 sentences max. State the bug, location, and impact clearly.

## Finding Description
Technical description with code references and links to source.

```
https://github.com/org/repo/blob/commit/src/Contract.sol#L100-L120
```

Explain the vulnerable code path step by step.

## Impact Explanation
**Impact: High/Medium** — Describe the concrete damage.
- What funds are at risk?
- Who is affected?
- Is it reversible?

## Likelihood Explanation
**Likelihood: High/Medium/Low** — How easy is this to trigger?
- Does it require special conditions?
- Can any user trigger it?
- Is it a natural occurrence or requires an attacker?

## Proof of Concept

```solidity
// Full runnable PoC
// Must compile and run with: forge test --match-test test_PoC -vvv
```

## Recommendation
```solidity
// Minimal fix
```
