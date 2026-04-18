---
name: library_analyzer
placeholders: [COMPONENT, CODE, LIBRARY_CODE, PROTOCOL, HYP_DIR]
---

# Library Deep Analyzer — {{COMPONENT}}

You are analyzing the libraries used by {{COMPONENT}} in {{PROTOCOL}}.

## Main Contract
```solidity
{{CODE}}
```

## Libraries
```solidity
{{LIBRARY_CODE}}
```

## Mandatory Analysis (line by line for EACH library function)

### 1. Order of Operations — Stale State Detection
For each function that updates state:
- Is the rate/index recalculated BEFORE being used?
- Or does it use a stale value from the previous call?
- Pattern to flag: `newValue = oldIndex * storedAmount / storedIndex` where oldIndex should have been refreshed first

### 2. Decimal Boundary Analysis (MANDATORY TABLE)
For EACH arithmetic operation, evaluate with:

| Operation | Location | decimals=6 | decimals=8 | decimals=18 | Truncates to 0? |
|---|---|---|---|---|---|
| rate * timeDelta / SECONDS_PER_YEAR | ? | ? | ? | ? | ? |
| amount * exchangeRate / PRECISION | ? | ? | ? | ? | ? |

Flag any operation where result == 0 for a reasonable input (e.g., $100 worth of WBTC).

### 3. Compounding Accuracy
If there's a binomial approximation or linear interest:
- What's the maximum error vs exact exponentiation?
- Does the error accumulate over time?
- Is there a scenario where the approximation diverges significantly?

### 4. Return Value Chain (CRITICAL)
For EACH function that returns a modified value:
- Does the caller capture the return value?
- Pattern to flag: `x.doSomething()` where doSomething returns new x but it's not captured
  Example bug: `path.skipToken()` returns new path but caller doesn't reassign

### 5. Loop Variable Mutation
For EACH loop:
- Does the loop variable actually change?
- Pattern to flag: `while (x.hasMore()) { x.skip(); }` where skip() returns new x but x isn't updated

## Output
Write findings to: {{HYP_DIR}}/hyp_{{COMPONENT}}_DeepDiveHunter.yaml
Append to existing if present. Each finding needs solidity_property with Chimera assertion code.
