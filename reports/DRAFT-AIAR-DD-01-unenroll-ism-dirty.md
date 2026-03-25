# `unenrollRemoteRouter()` leaves `isms[domain]` dirty — permanent domain brick prevents re-enrollment

## Summary

`Router._unenrollRemoteRouter(domain)` clears the `_routers` mapping but does NOT clear `isms[domain]` in `AbstractInterchainAccountRouter`. The `_enrollRemoteRouterAndIsm()` function requires BOTH `routers(domain) == 0` AND `isms[domain] == 0` to enroll. After unenroll, `isms[domain]` remains non-zero, so re-enrollment always reverts. The domain is permanently bricked with no recovery mechanism — the contract must be redeployed.

## Vulnerability Details

**Contract:** `AbstractInterchainAccountRouter.sol` (deployed as `InterchainAccountRouter`)
**Function:** `_enrollRemoteRouterAndIsm()` lines 293–305, interacting with `Router._unenrollRemoteRouter()` line 132
**Type:** State inconsistency / Incomplete cleanup

### Vulnerable Code

**Router.sol (base class) — line 132:**
```solidity
function _unenrollRemoteRouter(uint32 _domain) internal {
    _routers.remove(_domain);
    // NOTE: isms[_domain] is NOT cleared here
}
```

**AbstractInterchainAccountRouter.sol — lines 293–305:**
```solidity
function _enrollRemoteRouterAndIsm(
    uint32 _domain,
    bytes32 _router,
    bytes32 _ism
) internal {
    require(
        routers(_domain) == EMPTY_SALT && isms[_domain] == EMPTY_SALT,
        "router and ISM defaults are immutable once set"
    );
    _enrollRemoteRouter(_domain, _router);
    if (_ism != EMPTY_SALT) {
        isms[_domain] = _ism;
    }
}
```

### Comparison Evidence

`MovableCollateralRouter` correctly overrides `_unenrollRemoteRouter` to clean up its additional state (`outputAssets`, `feeParams`). `AbstractInterchainAccountRouter` does NOT override `_unenrollRemoteRouter` to clean up `isms[domain]` — proving the pattern was known but not applied.

### Root Cause

`Router._unenrollRemoteRouter()` is a base class function that only knows about `_routers`. `AbstractInterchainAccountRouter` extends `Router` and adds an `isms` mapping, but never overrides `_unenrollRemoteRouter()` to clear `isms[domain]`. The check in `_enrollRemoteRouterAndIsm` requires both to be zero, creating an impossible precondition after unenroll.

### Attack Path

```
1. Owner enrolls domain 42: enrollRemoteRouterAndIsm(42, 0xABC, 0xDEF)
   State: routers(42) = 0xABC, isms[42] = 0xDEF

2. Owner needs to change router (key rotation, migration, compromise):
   unenrollRemoteRouter(42)
   State: routers(42) = 0x0, isms[42] = 0xDEF  ← DIRTY

3. Owner tries to re-enroll:
   enrollRemoteRouterAndIsm(42, newRouter, newIsm)
   → REVERTS: "router and ISM defaults are immutable once set"
   (because isms[42] != 0)

4. Owner tries enrollRemoteRouter(42, newRouter):
   → Also calls _enrollRemoteRouterAndIsm internally
   → REVERTS for same reason

5. No function exists to clear isms[domain] independently
6. Domain 42 is permanently unusable
```

### Call Stack

```
owner.unenrollRemoteRouter(42)
  → Router._unenrollRemoteRouter(42)
    → _routers.remove(42) // SUCCESS — router cleared
    // isms[42] NOT touched — no override exists

... later ...

owner.enrollRemoteRouterAndIsm(42, newRouter, newIsm)
  → _enrollRemoteRouterAndIsm(42, newRouter, newIsm)
    → require(routers(42)==0 && isms[42]==0) // FAILS: isms[42] != 0
    → REVERT "router and ISM defaults are immutable once set"
```

## Impact

**Severity:** High
**Category:** Permanent denial of service for administrative domain management

**Quantified Impact:**
- Any domain that needs re-configuration (router rotation, ISM migration, compromise response) becomes permanently unusable via the enrollment system
- Owner cannot update the router or ISM for that domain through normal enrollment functions
- The only recovery path is deploying a new router contract and migrating ALL state across ALL domains
- For Hyperlane's cross-chain infrastructure, this affects the ability to rotate security configurations — critical for incident response

**Mitigating Factor:**
`callRemoteWithOverrides()` is a public function that accepts `_router` and `_ism` as parameters, bypassing the enrollment system. Users can still interact with ICAs on the bricked domain through this function. This prevents escalation to Critical (no permanent fund freezing), but the administrative DoS remains — the owner loses the ability to set default routing for the domain.

**Preconditions:**
1. Owner must have previously enrolled a domain with a non-zero ISM (standard operational setup)
2. Owner must call `unenrollRemoteRouter()` (legitimate admin operation for key rotation, migration, or incident response)

## Proof of Concept

Working Foundry fork test at `test/chimera/aiar/ForkPoC_AIAR-DD-01.sol`.

Deploys a fresh `InterchainAccountRouter` on a Base mainnet fork using the real Hyperlane Mailbox (`0xeA87ae93Fa0019a82A727bfd3eBd1cFCa8f64f1D`).

**4 tests, all passing:**

| Test | Demonstrates |
|------|-------------|
| `test_AIAR_DD_01_unenrollBricksDomain` | Core bug: enroll → unenroll → re-enroll reverts |
| `test_AIAR_DD_01_cannotReenrollSameValues` | Even re-enrolling with SAME values fails |
| `test_AIAR_DD_01_enrollRouterAlsoFails` | `enrollRemoteRouter()` (single param) also fails |
| `test_AIAR_DD_01_noRecoveryMechanism` | No function exists to clear dirty `isms[domain]` |

**Run command:**
```bash
export BASE_RPC_URL="https://base-mainnet.g.alchemy.com/v2/..."
forge test --match-contract ForkPoC_AIAR_DD_01 -vvv --fork-url $BASE_RPC_URL
```

**Expected output:**
```
[PASS] test_AIAR_DD_01_unenrollBricksDomain()
[PASS] test_AIAR_DD_01_cannotReenrollSameValues()
[PASS] test_AIAR_DD_01_enrollRouterAlsoFails()
[PASS] test_AIAR_DD_01_noRecoveryMechanism()

Suite result: ok. 4 passed; 0 failed
```

## Variant Analysis

| Variant | Contract | Severity | Description |
|---------|----------|----------|-------------|
| GasRouter-destinationGas-stale | `GasRouter.sol` | Low | `destinationGas` mapping not cleared on unenroll — stale gas value after re-enroll |
| EverclearBridge-outputAssets-stale | `EverclearTokenBridge.sol` | Low | `outputAssets`/`feeParams` not cleared — deprecated contract |
| MovableCollateralRouter (reference) | `MovableCollateralRouter.sol` | N/A | Correctly overrides `_unenrollRemoteRouter` — proves the pattern |

## Recommended Fix

**Option 1 — Override `_unenrollRemoteRouter` in `AbstractInterchainAccountRouter`:**
```solidity
function _unenrollRemoteRouter(uint32 _domain) internal virtual override {
    super._unenrollRemoteRouter(_domain);
    delete isms[_domain];
}
```

**Option 2 — Add a standalone `clearIsm` function (less clean):**
```solidity
function clearIsm(uint32 _domain) external onlyOwner {
    require(routers(_domain) == bytes32(0), "unenroll router first");
    delete isms[_domain];
}
```

Option 1 is preferred — it follows the same pattern as `MovableCollateralRouter` and ensures atomic cleanup.

## References

- `AbstractInterchainAccountRouter.sol` lines 293–305 (enrollment check)
- `Router.sol` line 132 (`_unenrollRemoteRouter` — only clears `_routers`)
- `MovableCollateralRouter.sol` — reference implementation with correct override
- CWE-459: Incomplete Cleanup
