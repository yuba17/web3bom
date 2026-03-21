# High-Payout Bug Bounty Reports Analysis ($50K+)

> Research compiled 2026-03-17. Patterns from reports that earned $50K to $10M.

---

## TOP PAYOUTS STUDIED

### 1. Wormhole — $10,000,000 (satya0x)
- **Vulnerability**: Uninitialized proxy implementation — self-destruct bug
- **Impact**: $736M in assets at risk. Attacker could brick the Ethereum Wormhole bridge permanently and hold the protocol ransom
- **Discovery Method**: Manual code review of proxy/upgrade patterns
- **What Made It Convincing**: Concrete PoC showing the proxy could be taken over via uninitialized implementation contract, with exact dollar amount at risk calculated
- **Time**: Not publicly disclosed
- **Platform**: Immunefi
- **Source**: https://medium.com/immunefi/wormhole-uninitialized-proxy-bugfix-review-90250c41a43a

### 2. Aurora Engine — $6,000,000 (pwning.eth)
- **Vulnerability**: Infinite ETH minting via the Aurora EVM on NEAR — could drain the nETH pool
- **Impact**: 70,000+ ETH (~$200M) at risk
- **Discovery Method**: Manual review of the Aurora Engine EVM implementation. Found that ETH could be infinitely minted through a flaw in how the EVM tracked balances
- **What Made It Convincing**: Clear infinite-mint exploit path, exact funds at risk, PoC demonstrating unlimited token creation
- **Reward Calculation**: Aurora pays 10% of potential economic damage, capped at $6M — hit the cap
- **Time**: Not publicly disclosed
- **Platform**: Immunefi (launched bounty program just ONE WEEK before this was found)
- **Source**: https://pwning.mirror.xyz/CB4XUkbJVwPo7CaRwRmCApaP2DMjPQccW-NOcCwQlAs

### 3. ily2 — $3,000,000 (undisclosed protocol)
- **Vulnerability**: Undisclosed (protocol not named publicly yet)
- **Impact**: "Saved hundreds of millions in potential hacks"
- **Discovery Method**: Unknown — submitted through Immunefi
- **What Made It Convincing**: The protocol had $500M TVL; $3M bounty = 0.6% of protected assets
- **Time**: Not disclosed
- **Platform**: Immunefi (2026)
- **Source**: https://www.hackernoob.tips/from-bug-hunter-to-millionaire-inside-the-reported-3-million-immunefi-bounty-that-saved-hundreds-of-millions/

### 4. Polygon (Plasma Bridge) — $2,000,000 (Gerhard Wagner)
- **Vulnerability**: Double-spend in Plasma Bridge exit logic
- **Impact**: $850M at risk. Attacker could replay burn transactions 223 times, turning $4,500 into $1M
- **Discovery Method**: Manual review of the bridge's withdrawal/exit mechanism. Noticed the branch mask could be modified to replay withdrawals
- **What Made It Convincing**: Crystal-clear math showing 223x multiplication, exact dollar amounts, runnable PoC
- **Time**: Not publicly disclosed
- **Platform**: Immunefi
- **Source**: https://medium.com/immunefi/polygon-double-spend-bug-fix-postmortem-2m-bounty-5a1db09db7f1

### 5. Polygon (MRC20) — $2,200,000 (Leon Spacewalker)
- **Vulnerability**: Missing balance/allowance check in MRC20 transfer function
- **Impact**: All ~9.27 BILLION MATIC at risk ($24B+ at the time)
- **Discovery Method**: LINE-BY-LINE manual code review of the gasless transfer function (transferWithSig). Found the function didn't validate the sender had sufficient balance
- **What Made It Convincing**: Trivially exploitable — no complex setup needed, just call the function. Impact was total loss of all MATIC in the contract
- **Time**: Not publicly disclosed, but described as methodical line-by-line reading
- **Platform**: Immunefi
- **Note**: A malicious actor actually exploited this bug and stole 801,601 MATIC before the fix was deployed
- **Source**: https://medium.com/immunefi/polygon-lack-of-balance-check-bugfix-postmortem-2-2m-bounty-64ec66c24c7d

### 6. Optimism — $2,000,042 (saurik / Jay Freeman)
- **Vulnerability**: Infinite ETH minting via SELFDESTRUCT in OVM 2.0
- **Impact**: Unlimited ETH creation on Optimism L2
- **Discovery Method**: Running personal unit test suite against new chains. Saurik routinely tests "functionality I either rely on or prefer" when evaluating new platforms. Found the StateDB didn't redirect SELFDESTRUCT balance changes through the OVM_ETH contract override
- **What Made It Convincing**:
  - Code-level evidence showing the missing UsingOVM check in StateDB
  - Historical proof: the bug had been triggered once before (Dec 24, 2021) without being noticed
  - Complete working PoC using Solidity smart contracts
  - Testable via eth_call state overrides (safe simulation)
- **Time**: ~1 YEAR of periodic analysis of Optimism's codebase
- **Response Time**: Optimism fixed within 3 HOURS of report
- **Platform**: Direct disclosure
- **Source**: https://www.saurik.com/optimism.html

### 7. SushiSwap MISO — $350M saved (samczsun, no bounty — whitehat rescue)
- **Vulnerability**: msg.value reuse via BoringBatchable delegatecall + refund logic drain
- **Impact**: 109,000 ETH (~$350M) at risk
- **Discovery Method**: Browsing Telegram, saw discussion about a MISO raise, opened the contract on Etherscan AT 9:42 AM. By 9:52 AM had a working PoC. Recognized the pattern from a previous Opyn exploit
- **What Made It Convincing**: Two individually safe components (batch operations + ETH refunds) combined to create catastrophic risk. The "two rights make a wrong" pattern
- **Time**: 10 minutes from first look to confirmed PoC. ~5 hours to full rescue operation
- **Key Insight**: Pattern recognition from studying PAST exploits (Opyn) enabled instant identification
- **Source**: https://samczsun.com/two-rights-might-make-a-wrong/

### 8. The Graph — $290,497 (GregadETH)
- **Vulnerability**: Two rounding errors causing loss of user funds / unclaimed yield
- **Impact**: Loss of funds through accumulated rounding errors
- **Discovery Method**: Manual review of mathematical operations
- **Platform**: Immunefi (2024)

### 9. Stacks (Bitcoin L2) — $76,011
- **Vulnerability**: Critical DoS vulnerability
- **Discovery Method**: Independent research
- **Platform**: Immunefi (2023)

### 10. VeChainThor — $50,000
- **Vulnerability**: VTHO token inflation via self-destruct + flash loan combination
- **Discovery Method**: Understanding the interaction between self-destruct mechanics and flash loans
- **Platform**: Immunefi (2024)

---

## PATTERN ANALYSIS: What Separates $100K+ from $1K Reports

### The $100K+ Report Has ALL of These:

#### 1. DIRECT FUND LOSS (not theoretical)
- Every $1M+ report showed **direct, immediate loss of user funds** or **total protocol bricking**
- "Users could lose X" beats "this is a best practice violation" every time
- Calculate the EXACT dollar amount at risk at time of submission

#### 2. EXECUTABLE PoC (not steps, not pseudocode)
- Foundry/Hardhat test that runs against a mainnet fork
- Shows the exploit end-to-end: setup -> attack -> profit
- Logs the stolen amount, showing impact in numbers
- Immunefi explicitly states: "runnable exploit code — not a list of steps"

#### 3. MAXIMUM ECONOMIC DAMAGE CALCULATION
- satya0x: "$736M in the contract at time of submission"
- Wagner: "$850M at risk, $4,500 turns into $1M via 223x replay"
- Leon Spacewalker: "9.27 billion MATIC at risk"
- saurik: "unlimited ETH creation"
- The bigger the number, the bigger the payout

#### 4. NO ADMIN/GOVERNANCE REQUIRED
- Every high-payout bug is exploitable by ANY external attacker
- Zero reports requiring privileged access earned $1M+
- If it needs admin keys, it's a Medium at best

#### 5. NOVEL ATTACK VECTOR or COMPOSITION
- samczsun: Two safe components combining unsafely (batch + refund)
- saurik: Architecture-level flaw in L2's balance model
- pwning.eth: EVM implementation gap in cross-chain context
- Wagner: Branch mask modification in bridge exit logic

### The $1K Report Typically Has:

- Theoretical impact without concrete exploit
- "Steps to reproduce" instead of runnable code
- Requires admin/governance action
- Known issue or previously audited finding
- Defense-in-depth suggestion without attack path
- Generic severity classification without dollar amounts
- Vague description, no code snippets

---

## DISCOVERY METHODS THAT LEAD TO HIGH PAYOUTS

### 1. Manual Line-by-Line Review (Most Common)
- Leon Spacewalker ($2.2M): "found the bug by looking line-by-line at the smart contract code"
- This is the #1 method for critical findings
- Focus on: access control, balance checks, state changes before external calls

### 2. Cross-Reference with Past Exploits (Pattern Recognition)
- samczsun recognized the Opyn msg.value pattern instantly in SushiSwap
- Study EVERY major exploit. The patterns repeat in new contexts
- Sources: Rekt.news, DeFiHackLabs, Immunefi bugfix reviews

### 3. Architecture-Level Analysis (Not Just Function-Level)
- saurik found Optimism's bug by understanding the full StateDB architecture
- pwning.eth found Aurora's bug by understanding EVM-on-NEAR architecture
- Think about HOW the system maps one paradigm onto another (L2s, bridges, cross-chain)

### 4. Personal Test Suites
- saurik runs a standard test suite against every new chain he evaluates
- Build YOUR OWN test battery for common invariants
- Deploy it against every new target

### 5. Monitoring Community Channels
- samczsun found SushiSwap bug by browsing Telegram
- New deployments, protocol launches, and migrations are prime hunting time
- Subscribe to protocol Discord/Telegram announcements

### 6. Focus on NEW Code and Recent Changes
- Aurora had launched their bounty program just 1 WEEK before pwning.eth found the bug
- New code = less review = more bugs
- Post-audit diffs, new deployments, and recently upgraded contracts

---

## WINNING REPORT STRUCTURE (Immunefi Standard)

```
TITLE: [Vulnerability Type] in [Function/Contract] leads to [Impact]
Example: "Reentrancy in withdraw() leads to total drain of user deposits"

BUG DESCRIPTION:
- Brief: 1 paragraph — what, where, and what happens
- Details: Full technical explanation with code snippets
  - Show the vulnerable code
  - Explain WHY it's vulnerable
  - Show the attack flow step by step

IMPACT:
- Exact $ amount at risk (TVL * percentage affected)
- What an attacker gains
- What users/protocol loses
- Affected contracts and addresses

RISK BREAKDOWN:
- Use Immunefi severity (NOT CVSS)
- Critical = direct fund loss, unlimited minting, protocol bricking

PROOF OF CONCEPT:
- Runnable Foundry/Hardhat test
- Fork mainnet
- Setup -> Attack -> Verify stolen amount
- Commented code explaining each step
- Console.log the profit

RECOMMENDATION:
- Proposed fix (shows expertise)
- Keep it simple and implementable

REFERENCES:
- Similar past exploits
- Relevant documentation
- Contract addresses
```

---

## CRITICAL LESSONS

### Time Investment
- saurik: 1 YEAR of periodic analysis for $2M
- samczsun: 10 MINUTES from seeing the contract to confirmed PoC (but YEARS of pattern knowledge)
- Leon Spacewalker: Patient line-by-line reading
- **Pattern**: Either invest massive time OR have massive pattern knowledge. No shortcuts.

### Target Selection
- High TVL = High bounty (Aurora had $200M, Wormhole had $736M)
- New programs pay better (Aurora launched bounty 1 week before)
- Bridges and L2s have the highest payouts (architectural complexity)
- Programs with 10% of economic damage formula are most lucrative

### Platform Economics
- Immunefi dominates: $100M+ total payouts
- Smart contract bugs = 77.5% of all payouts ($78M)
- Critical smart contract bugs average minimum $10K, but top out at $10M
- Average critical minimum: $10,000. Median top-tier: $100K-$500K

### The 10% Rule
- Aurora formula: 10% of potential economic damage, up to $6M cap
- Many programs use similar formulas
- This means: MAXIMIZE the demonstrable economic damage in your PoC
- A bug affecting $100M TVL at 10% = potential $10M bounty

---

## VULNERABILITY TYPES THAT PAY THE MOST

Based on Immunefi Top 10 (2023) and actual payouts:

| Rank | Type | Highest Known Payout |
|------|------|---------------------|
| 1 | Uninitialized Proxy | $10M (Wormhole) |
| 2 | Infinite Minting / Inflation | $6M (Aurora), $2M (Optimism) |
| 3 | Missing Balance Check | $2.2M (Polygon MRC20) |
| 4 | Bridge Exit Replay / Double-Spend | $2M (Polygon Plasma) |
| 5 | msg.value Reuse (Batch/Delegatecall) | $350M saved (SushiSwap) |
| 6 | Improper Input Validation | Most common root cause overall |
| 7 | Oracle/Price Manipulation | Variable |
| 8 | Rounding Errors | $290K (The Graph) |
| 9 | Weak Access Control | Variable |
| 10 | Self-Destruct + Flash Loan Combo | $50K (VeChainThor) |

---

## ACTION ITEMS

1. **Study every Immunefi bugfix review** — they publish full technical details
2. **Build a personal test suite** for common invariants (balance checks, proxy init, self-destruct behavior)
3. **Focus on bridges, L2s, and cross-chain** — highest complexity = highest payouts
4. **Target new bounty programs** — less competition, fresh code
5. **Always calculate max economic damage** — it directly determines payout
6. **Always include runnable Foundry PoC** — no exceptions
7. **Study past exploits obsessively** — pattern recognition is the #1 edge
8. **Read code line-by-line** — automated tools find the easy bugs, humans find the $1M+ ones

---

## KEY SOURCES

- Immunefi Bugfix Reviews: https://medium.com/immunefi (search "bugfix review")
- Immunefi Top 10: https://immunefi.com/immunefi-top-10/
- samczsun blog: https://samczsun.com/
- saurik Optimism writeup: https://www.saurik.com/optimism.html
- pwning.eth Aurora writeup: https://pwning.mirror.xyz/CB4XUkbJVwPo7CaRwRmCApaP2DMjPQccW-NOcCwQlAs
- Immunefi report guide: https://immunefi.com/blog/security-guides/how-to-submit-bug-reports-that-get-paid/
- Immunefi PoC templates: https://immunefi.com/blog/security-guides/immunefi-poc-templates/
- Chainlink bug hunting strategies: https://blog.chain.link/smart-contract-bug-hunting/
- GitHub writeup collection: https://github.com/sayan011/Immunefi-bug-bounty-writeups-list
- GitHub critical bug writeups: https://github.com/tpiliposian/Immunefi-bugfixes
