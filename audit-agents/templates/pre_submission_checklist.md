# Pre-Submission Checklist

<!--
Run through EVERY item before submitting to ANY platform.
A single "no" on items 1-7 means DO NOT SUBMIT.
Items 8-10 are quality multipliers that affect payout.
-->

## Gate Checks (all must pass or DO NOT SUBMIT)

- [ ] **1. Bug exists in CURRENT deployed/scoped code**
  - Verified against the exact commit hash in the audit/bounty scope
  - Not fixed in a newer version or pending PR
  - For Immunefi: verified against the live mainnet deployment (check Etherscan)
  - For Code4rena/Cantina: verified against the competition repo's HEAD commit

- [ ] **2. Not in known issues (ALL sources checked)**
  - [ ] Audit repo README / known issues section
  - [ ] Previous audit reports (check project's GitHub, docs, and Solodit)
  - [ ] Project's Discord/Telegram announcements
  - [ ] Bounty program's "Known Issues" or "Out of Scope" sections
  - [ ] On-chain: check if a fix was already deployed to a proxy implementation
  - [ ] Solodit.xyz: search for this bug pattern in the same protocol family

- [ ] **3. Not excluded by bounty/competition rules**
  - [ ] Contract/file is in scope (check the exact file list)
  - [ ] Impact type is in scope (check the "Impacts in Scope" table)
  - [ ] Attack vector is not excluded (e.g., "economic attacks excluded")
  - [ ] Chain-specific rules checked (some bugs only valid on specific chains)
  - [ ] Time-based exclusions checked (e.g., "oracle staleness by design")

- [ ] **4. Does NOT require admin/privileged access**
  - Attacker is an unprivileged external user OR
  - If admin access is involved, the attack uses a COMPROMISED admin key
    (only valid if the program explicitly includes this threat model) OR
  - The finding is about an admin being able to rug users AND the program
    explicitly includes centralization risks in scope
  - NOTE: "Owner can call X to steal funds" is almost always out of scope

- [ ] **5. Has concrete, demonstrable impact**
  - Impact is NOT theoretical ("could potentially lead to...")
  - Impact is NOT conditional on unrealistic preconditions
  - Impact maps directly to a severity category on the target platform
  - Loss amount is quantifiable (not "some amount of funds")
  - For fund loss: specify the exact dollar amount at risk
  - For DoS: specify duration and affected functionality
  - For governance: specify the concrete outcome change

- [ ] **6. Validation confidence > 50% payout probability**
  - Self-assessment questions:
    - [ ] Would a senior Solidity auditor agree this is a valid bug? (not just a code smell)
    - [ ] Is the attack path realistic without extraordinary conditions?
    - [ ] Is the severity correctly classified per platform definitions?
    - [ ] Have I seen similar bugs get paid on this platform before?
    - [ ] Is the impact significant enough to justify the severity level?
  - If more than 1 answer is "no" or "unsure," reconsider submitting or
    downgrade severity

- [ ] **7. Report includes runnable PoC**
  - [ ] PoC compiles without errors
  - [ ] PoC runs successfully (forge test passes)
  - [ ] PoC demonstrates the EXACT claimed impact (not a weaker version)
  - [ ] PoC uses the correct test framework (audit repo's existing suite)
  - [ ] For Immunefi: PoC forks mainnet at a specific block number
  - [ ] PoC output clearly shows before/after state proving the exploit
  - [ ] PoC is minimal (no unnecessary code or complexity)

## Quality Multipliers (affect payout amount and judge impression)

- [ ] **8. Severity correctly framed per platform criteria**
  - [ ] Used the platform's EXACT severity language (not generic terms)
  - [ ] Code4rena: matches H(3)/M(2)/QA definitions exactly
  - [ ] Immunefi: maps to their specific impact categories
  - [ ] Cantina: aligns with their Critical/High/Medium/Low thresholds
  - [ ] NOT inflated (inflated severity = reduced credibility with judges)
  - [ ] Edge cases resolved: e.g., yield loss caps at Medium on Code4rena

- [ ] **9. Title is descriptive and impactful**
  - [ ] Format: [Verb/Impact] + [Mechanism] + [Location]
  - [ ] Under 80 characters
  - [ ] Contains the specific function or contract name
  - [ ] Conveys the impact, not just the bug class
  - [ ] No filler words ("Possible," "Potential," "Maybe")
  - GOOD: "Drain all vault ETH via reentrancy in Vault.withdraw()"
  - BAD: "Potential reentrancy vulnerability in withdraw function"

- [ ] **10. USD impact is quantified**
  - [ ] Current TVL/balance checked (DefiLlama, Etherscan, DeBank)
  - [ ] Maximum extractable value calculated
  - [ ] Attacker cost included (flash loan fees, gas, capital requirements)
  - [ ] Net profit stated (extraction minus costs)
  - [ ] For yield/fee bugs: annualized loss calculated
  - [ ] For DoS bugs: estimated cost per hour/day of downtime
  - [ ] Price source and timestamp noted

---

## Platform-Specific Final Checks

### Code4rena Additional Checks
- [ ] GitHub permalink(s) included in "Lines of code" section
- [ ] High/Medium submitted individually (not bundled)
- [ ] Low/QA findings consolidated into single QA report
- [ ] QA report uses L-XX and C-XX labeling convention
- [ ] PoC uses the audit repo's test suite (not standalone)
- [ ] PoC shows exact revert errors (not just "reverts")
- [ ] No bot/automated findings submitted as manual findings
- [ ] Submitted before the competition deadline

### Immunefi Additional Checks
- [ ] Target contract address is in the program's "Assets in Scope"
- [ ] Impact type is in the program's "Impacts in Scope"
- [ ] PoC forks mainnet (not a local mock)
- [ ] Specific fork block number documented
- [ ] Etherscan links to deployed contract source included
- [ ] Current contract balance verified and stated
- [ ] Program-specific exclusions reviewed (each program differs)
- [ ] Communication plan ready (may need to respond to project questions)

### Cantina Additional Checks
- [ ] Competition scope files verified (exact file list)
- [ ] Target chain's specific behaviors accounted for (L1 vs L2)
- [ ] Summary section is self-contained (reviewer can understand bug from summary alone)
- [ ] Attack path section has numbered steps
- [ ] Root cause explicitly identified
- [ ] Mitigation includes concrete code diff

---

## Decision Matrix

```
IF all Gate Checks (1-7) pass:
  IF all Quality Multipliers (8-10) pass:
    -> SUBMIT with confidence
  IF 1 Quality Multiplier fails:
    -> SUBMIT after fixing the gap (10 min investment, big payout impact)
  IF 2+ Quality Multipliers fail:
    -> PAUSE and improve report quality before submitting

IF any Gate Check (1-7) fails:
  -> DO NOT SUBMIT
  -> Document why and move to next finding
```

## Quick Reference: Severity Decision Tree

```
Can attacker steal deposited funds directly?
  YES -> Is it all funds or partial?
    ALL funds -> CRITICAL (Immunefi) / HIGH (Code4rena)
    Partial but significant -> HIGH
  NO -> Continue

Can attacker steal unclaimed yield/rewards?
  YES -> HIGH

Can attacker permanently freeze funds?
  YES, significant amount -> CRITICAL (Immunefi) / HIGH (Code4rena)
  YES, small amount -> HIGH / MEDIUM

Can attacker temporarily freeze funds?
  YES, >24h -> HIGH (Immunefi) / MEDIUM-HIGH (Code4rena)
  YES, <24h -> MEDIUM

Can attacker cause protocol to malfunction?
  YES, permanently -> MEDIUM-HIGH
  YES, temporarily -> MEDIUM

Can attacker grief without profit?
  YES -> MEDIUM (at most)

Is it a code quality / best practice issue?
  YES -> LOW / QA

Does it require admin access?
  YES -> QA at best (usually out of scope)
```
