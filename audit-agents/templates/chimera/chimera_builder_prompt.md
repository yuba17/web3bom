# ChimeraBuilder — Auto-Setup Generation

## Your Task
Generate 3 Solidity files for the Chimera fuzzing framework. You receive:
1. The target contract source code
2. A list of invariants (from YAML — each has `solidity` body and `ghost_vars`)
3. The 7 universal invariant definitions (below)

## Files to Generate

### 1. `Setup.sol`
- Import the target contract
- Deploy it in a `setup()` function
- Create 3 actors: `user` (0x20000), `attacker` (0x30000), `keeper` (0x40000)
- Fund actors with ETH and relevant tokens
- Store contract instance as `internal` variable accessible by Properties and TargetFunctions

### 2. `TargetFunctions.sol`
- Inherit from `Setup`
- For EACH external/public non-view function in the target contract:
  - Create a handler function (no prefix needed)
  - Use `_clampBetween(x, min, max)` for numeric params
  - 5% chance of 0, 5% chance of 1, 5% chance of type(uint).max
  - Call the target function wrapped in try/catch
- Chimera helpers available: `_clampBetween(uint256, uint256, uint256)`, `_actors()`, `_randomActor()`

### 3. `Properties.sol`
- Inherit from `Setup`
- Include ALL ghost variables from the invariant list
- For each invariant with `validated: true`:
  - Create function `property_<id>() public` with the Solidity body from YAML
- Chimera assertion helpers: `t(bool, string)`, `eq(uint256, uint256, string)`, `gt()`, `gte()`, `lt()`, `lte()`
- Include the 7 universal invariants (below)

## 7 Universal Invariants (ALWAYS include)

```solidity
// U-01: Setup canary
function property_canary() public {
    t(true, "CANARY: setup is working");
}

// U-02: No self-destruct
function property_no_selfdestruct() public {
    uint256 size;
    address target = address(targetContract);
    assembly { size := extcodesize(target) }
    t(size > 0, "U-02: contract self-destructed");
}

// U-03: Reentrancy canary
// Ghost: bool internal ghost_entered;
function property_no_reentrancy() public {
    t(!ghost_entered, "U-03: reentrancy detected");
}

// U-04: Supply conservation (if ERC20/ERC4626)
function property_supply_conservation() public {
    uint256 tracked = 0;
    for (uint i = 0; i < actors.length; i++) {
        tracked += targetContract.balanceOf(actors[i]);
    }
    eq(tracked, targetContract.totalSupply(), "U-04: supply != sum(balances)");
}

// U-05: Basic solvency (if vault/pool)
function property_solvency() public {
    gte(
        token.balanceOf(address(targetContract)),
        targetContract.totalAssets(),
        "U-05: token balance < totalAssets"
    );
}

// U-06: Share price monotonicity (if ERC4626)
function property_share_price_monotonic() public {
    uint256 currentPrice = targetContract.convertToAssets(1e18);
    if (ghost_lastSharePrice > 0) {
        gte(currentPrice + 1, ghost_lastSharePrice, "U-06: share price decreased > 1 wei");
    }
    ghost_lastSharePrice = currentPrice;
}
// Ghost: uint256 internal ghost_lastSharePrice;

// U-07: No-revert on exit (test separately — call in try/catch and log)
// This is tested via handler functions, not as a property
```

## Rules
- Use Solidity ^0.8.0
- Import paths: use relative `../src/Contract.sol` or adjust to repo structure
- If a universal invariant doesn't apply (e.g., U-06 on non-vault), SKIP it — don't force it
- Ghost variables go at contract level in Properties.sol
- The `setup()` function in Setup.sol must be called by CryticTester constructor

## Compile-Fix Loop
After generating, the orchestrator runs `forge build`. If it fails:
- You will receive the compiler error
- Fix ONLY the error — don't rewrite everything
- Maximum 3 fix attempts
- If after 3 failures: strip all hunter-specific invariants, keep ONLY universals, retry once more
