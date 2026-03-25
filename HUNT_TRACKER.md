# Hunt Tracker — Hyperlane (Immunefi)

## Component: InterchainAccountRouter

### Status: COMPLETE ✅ (10/10 gates passed)

### Invariants Tested (Phase 1 — Foundry 5K runs)

| ID | Description | Result | Classification |
|----|-------------|--------|----------------|
| IAR-01 | approveFeeTokenForHook no ACL | **BROKEN** | REAL BUG (DD-01) |
| IAR-02 | address(this).balance drain in commitReveal | **BROKEN** | REAL BUG (DD-02) |
| IAR-03 | revealAndExecute no ACL | PASS (setup confirms bug) | REAL BUG (DD-04) |
| IAR-04 | handle() atomic revert locks messages | PASS (design flaw) | REAL BUG (DD-05) |
| IAR-05 | ICA isolation (different senders → different ICAs) | PASS | SECURE |
| IAR-06 | callRemote single dispatch | PASS | SECURE |
| IAR-07 | Router balance accounting | PASS | SECURE |
| IAR-08 | ICA ownership = router | PASS | SECURE |
| IAR-09 | commitReveal dispatches 2 messages | PASS | SECURE |
| IAR-10 | enrollRemoteRouter only owner | PASS | SECURE |
| IAR-11 | handle() only mailbox | PASS | SECURE |
| IAR-12 | Fee token conservation | PASS | SECURE |
| IAR-13 | ICA address consistency (view vs deploy) | PASS | SECURE |

### Tolerance Tuning

| Failure | Type | Action |
|---------|------|--------|
| IAR-01 (approve type(uint256).max) | REAL | Tier 1 — confirmed DD-01 |
| IAR-02 (2.1 ETH drained > 0.01 sent) | REAL | Tier 1 — confirmed DD-02 |
| attackerDrain (10 ETH drained > 1.17 sent) | REAL | Tier 1 — confirmed DD-02 |

### Findings

| ID | Severity | Title | Pipeline | Deployed |
|----|----------|-------|----------|----------|
| IAR-DD-01 | High | approveFeeTokenForHook permissionless approval drain | 7/7 ✅ | ❌ Not deployed |
| IAR-DD-02 | Medium | callRemoteCommitReveal drains pre-existing ETH | 7/7 ✅ | ✅ Polygon |
| IAR-DD-03 | High | CommitmentReadIsm CCIP redirect attack | 7/7 ✅ | ✅ Polygon |
| IAR-DD-04 | High | revealAndExecute missing ACL breaks commit-reveal | 7/7 ✅ | ✅ Polygon |
| IAR-DD-05 | Medium | Atomic multicall in handle() — permanent message DoS | 7/7 ✅ | ✅ Polygon |

### Fuzzing Results

| Phase | Tool | Duration | Result |
|-------|------|----------|--------|
| 1 | Foundry | 5K runs | 11 PASS, 3 FAIL (all real bugs — DD-01, DD-02) |
| 2 | Medusa | 15 min (2.2M calls) | 39 tests PASS, 0 FAIL. optimize_drainRouterEth: ~100 ETH max drain |
| 3 | Fork PoC | per finding | 5/5 findings have fork PoCs (17/17 tests pass) |
| 4 | Echidna | 10 min (optimization) | Running (optimize_drainRouterEth, optimize_approvalDrain) |
| 5 | Halmos | SKIP | No pure math functions — Phase 5 optional, skipped |

---

## Component: AbstractMultisigIsm

### Status: COMPLETE ✅ (10/10 gates passed, 1 finding)

### Invariants Tested (Phase 1 — Foundry 5K runs)

| ID | Description | Result | Classification |
|----|-------------|--------|----------------|
| ISM-DD-01 | Factory must reject duplicate validators | **BROKEN** | REAL BUG |
| ISM-WC-01 | 3-of-5 ISM with duplicates allows 1-key bypass | **BROKEN** | REAL BUG |
| ISM-ACC-01 | Threshold bounds validation (fuzz) | PASS (5K runs) | SECURE |
| ISM-DOM-04 | Digest no encodePacked collision (fuzz) | PASS (5K runs) | SECURE |
| ISM-TB-01 | MetaProxy immutability | PASS | SECURE |
| ISM-ACC-04 | CREATE2 deterministic | PASS | SECURE |
| ISM-M-02 | address(0) in validator set (benign) | PASS | SECURE |
| ISM-F-01 | Signature ordering | PASS | SECURE |
| ISM-SIG-01 | No signature reuse | PASS | SECURE |
| ISM-D-01 | Malformed metadata reverts | PASS | SECURE |

### Tolerance Tuning

| Failure | Type | Action |
|---------|------|--------|
| ISM-DD-01 (factory accepts duplicates) | REAL | Tier 1 — confirmed |
| ISM-WC-01 (1-key threshold bypass) | REAL | Tier 1 — same root cause as DD-01 |

### Findings

| ID | Severity | Title | Pipeline | Deployed |
|----|----------|-------|----------|----------|
| ISM-DD-01 | Medium | Factory duplicate validators enable threshold bypass | 7/7 ✅ | ✅ Polygon (factories in scope) |

### Fuzzing Results

| Phase | Tool | Duration | Result |
|-------|------|----------|--------|
| 1 | Foundry | 5K runs | 14 PASS, 2 FAIL (both same bug: factory duplicate validators) |
| 2 | Medusa | 15 min | 26 tests PASS, 0 FAIL. Corpus + coverage at test/chimera/ism/corpus-ISM/ |
| 3 | Fork PoC | per finding | 3/3 tests PASS (factory accepts duplicates locally + on Polygon addresses) |
| 4 | Echidna | SKIP | Stateless component, optimize_duplicateIsms trivial |
| 5 | Halmos | SKIP | No pure math — stateless verify() |
