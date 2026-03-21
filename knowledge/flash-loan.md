# Flash Loan Attack Patterns — Combat Briefing

> For smart contract auditors. Each pattern includes grep targets, root cause, invariant, and fix.
> Sources: invariant-registry (INV-EXPLOIT-006, INV-EXPLOIT-020, COMP-FLASH-001/002), DeFiHackLabs.

---

## How Flash Loans Amplify Attacks

Flash loans provide unlimited capital within a single transaction at near-zero cost. They do not create new vulnerability classes -- they amplify existing ones to catastrophic scale. Any state that can be manipulated and consumed in the same transaction is a flash loan target.

Key providers: Aave V3, Balancer, Uniswap V3, dYdX, Maker. Typical available capital: hundreds of millions USD per token.

---

## Pattern 1: Price Oracle Manipulation

```yaml
- id: flash-001
  pattern: flash-loan-oracle-manipulation
  name: "Flash loan + price oracle manipulation (same tx)"
  causa_raiz: "Protocol reads spot price from an AMM pool (getReserves, slot0) that can be moved with borrowed capital in the same transaction."
  como_funciona: |
    1. Borrow large amount via flash loan (e.g., 10M USDC from Aave)
    2. Swap into target token on AMM, moving spot price drastically
    3. Call protocol function that reads the now-inflated spot price (borrow, mint, liquidate)
    4. Extract value at the manipulated price
    5. Swap back, repay flash loan + fee, keep profit
  invariante: "spotPrice <= twapPrice * (100 + MAX_DEVIATION) / 100 && spotPrice >= twapPrice * (100 - MAX_DEVIATION) / 100"
  que_mirar:
    - "getReserves() used for pricing"
    - "slot0() read without TWAP cross-check"
    - "latestAnswer() from a pool-based oracle without staleness check"
    - "Any balanceOf() used to derive price"
    - "Missing manipulation guards on price-dependent functions"
  como_se_arregla: "Use TWAP oracles (Uniswap V3 observe()), Chainlink feeds, or commit-reveal patterns. Never use spot AMM price for valuation. Add same-block manipulation detection (block.number check against last price update)."
  trampas:
    - "High-liquidity pools (>$10M TVL) are expensive but NOT impossible to manipulate with flash loans"
    - "TWAP with short window (< 30 min) can still be manipulated over multiple blocks"
    - "Chainlink feeds can be stale -- check updatedAt"
  incidentes:
    - "Behodler/FlanBackstop — purchasePyroFlan reads flan-LP spot reserves; flash loan sandwich profits within acceptableHighestPrice limit (HIGH)"
    - "Spartan Protocol — Synth realise() calculates baseValueLP/baseValueSynth from spot price; flash loan shifts ratio, extracts value (HIGH)"
    - "Anchor/NonUSTStrategy — reads DAI/UST from Curve pool spot state; flash loan DAI, move rate, deposit/withdraw at favorable rate (HIGH)"
    - "Limbo/LimboDAO — burnAsset() prices LP from EYE reserves; flash loan inflates reserves, attacker burns LP for inflated fate voting power (HIGH)"
    - "Morpho Blue oracle integration — Curve get_virtual_price and spot reserve oracle with no TWAP; flash loan enables unfair liquidations (MEDIUM)"
    - "WooFi Swap — sPMM repeat exploit: sequential sells crash internal price, buy back at discount; caps insufficient, attacker splits trades ($8.5M repeat, HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-001, INV-EXPLOIT-006, INV-EXPLOIT-021"
  verificado: true
  tags: [flash-loan, oracle, price-manipulation, spot-price, AMM]
  relacionado_con: [flash-002, flash-003, oracle-002]
```

**Grep targets:** `getReserves`, `slot0`, `sqrtPriceX96`, `currentPrice`, `spotPrice`, `balanceOf.*price`

**Real incidents:** Prisma Finance (2024-03), Minterest (2024-07), Gamma Strategies (2024-01), UwuLend (2024-06), PeapodsFinance (2025-02), BonqDAO (2023-02, $88M), ZunamiProtocol (2023-08, $2M), Jimbo (2023-05, $8M).

```yaml
incidentes_verificados_oracle_manipulation:
  - nombre: "BonqDAO"
    fecha: "2023-02"
    perdida: "$88M"
    descripcion: "Oracle Manipulation via flash loan"
    verificado: true
    fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  - nombre: "ZunamiProtocol"
    fecha: "2023-08"
    perdida: "$2M"
    descripcion: "Price Manipulation via flash loan"
    verificado: true
    fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  - nombre: "Jimbo"
    fecha: "2023-05"
    perdida: "$8M"
    descripcion: "Protocol-Specific Price Manipulation via flash loan"
    verificado: true
    fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
```

---

## Pattern 2: Governance Voting Manipulation

```yaml
- id: flash-002
  pattern: flash-loan-governance-vote
  name: "Flash loan + governance voting"
  causa_raiz: "Governance voting power derived from current token balance (balanceOf) instead of historical snapshots. Attacker borrows tokens, votes, returns them."
  como_funciona: |
    1. Flash borrow governance tokens
    2. Delegate to self (or directly hold if no delegation required)
    3. Create and/or vote on malicious proposal (e.g., drain treasury)
    4. If quorum uses current balances, proposal passes instantly
    5. Repay flash loan; proposal executes after timelock (or immediately if no timelock)
  invariante: "votingPowerSource == historicalSnapshot && snapshotBlock < block.number - MIN_SNAPSHOT_DELAY"
  que_mirar:
    - "balanceOf() or getCurrentVotes() used for voting power"
    - "Snapshot block == proposal block (zero delay)"
    - "Missing timelock on proposal execution"
    - "delegate() callable and effective in same block as vote"
    - "Quorum calculated from current supply, not historical"
  como_se_arregla: "Use ERC20Votes with checkpoints (OpenZeppelin). Snapshot voting power at proposal creation block minus N blocks. Enforce timelock on execution. Require voting delay > 1 block between proposal and voting start."
  trampas:
    - "OpenZeppelin Governor + ERC20Votes with proper snapshot delay is safe"
    - "Custom governance that wraps OZ but overrides _getVotes may reintroduce the bug"
    - "Timelock alone does not prevent the vote -- it only delays execution"
  incidentes:
    - "PartyDAO — vote multiple times by transferring governance NFT in same block as proposal; any user can pass any proposal unanimously (HIGH)"
    - "DeXe GovPool — flash loan governance tokens, delegate to accomplice who votes, withdraw while Locked; bypasses anti-flash-loan protection (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-020"
  verificado: true
  tags: [flash-loan, governance, voting, snapshot, quorum]
  relacionado_con: [flash-001]
```

**Grep targets:** `castVote`, `getVotes`, `balanceOf.*voting`, `propose`, `quorum`, `delegate`

**Real incidents:** Beanstalk (2022-04), Tornado Cash Governance (2023-05).

---

## Pattern 3: Liquidity Pool Manipulation

```yaml
- id: flash-003
  pattern: flash-loan-pool-manipulation
  name: "Flash loan + liquidity pool reserve manipulation"
  causa_raiz: "Protocol uses pool reserves or pool share price for internal accounting. Flash loan capital temporarily distorts reserves, and the protocol reads the distorted state."
  como_funciona: |
    1. Flash borrow large amount of one side of an LP pair
    2. Add/remove liquidity to shift pool reserves or LP token price
    3. Interact with protocol that values LP tokens or reads reserves (collateral deposit, redemption, reward calculation)
    4. Extract value based on inflated/deflated valuation
    5. Reverse liquidity operation, repay flash loan
  invariante: |
    // Fair LP pricing (Alpha Homora formula):
    // fairPrice = 2 * sqrt(reserve0 * reserve1 * price0 * price1) / totalSupply
    // Where price0, price1 are from external oracle (NOT from pool reserves)
    // NOT: reserve0 / totalSupply (vulnerable to single-block reserve distortion)
    // For Curve: use get_virtual_price() + reentrancy guard, not raw balances
    assert(lpTokenPrice == fairPrice(externalOracle0, externalOracle1, reserves))
  que_mirar:
    - "LP token used as collateral with naive pricing (reserve0/totalSupply)"
    - "totalSupply() of LP token used in same tx as deposit/withdraw"
    - "virtualPrice() read in same block as large swap"
    - "Curve pool virtual_price used without manipulation check"
    - "Any reserve-based calculation without same-block guard"
  como_se_arregla: "Use Alpha Homora fair LP pricing formula. For Curve, use get_virtual_price() with reentrancy guard and manipulation detection. Never price LP tokens from instantaneous reserves. Use external oracle for underlying token prices."
  trampas:
    - "Curve read-only reentrancy (via raw_call) is a separate but related issue"
    - "Fair LP pricing still depends on accurate underlying token prices"
    - "Some protocols intentionally use spot reserves for efficiency -- check if bounded by other mechanisms"
  incidentes:
    - "PartyDAO BuyCrowdfund — attacker contributes flash-loaned funds to dominate contribution share, purchases own NFT, claims majority voting power/equity for free (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-006, COMP-FLASH-001"
  verificado: true
  tags: [flash-loan, liquidity-pool, LP-token, reserves, collateral]
  relacionado_con: [flash-001, flash-004]
```

**Grep targets:** `getReserves`, `totalSupply.*reserve`, `virtualPrice`, `virtual_price`, `get_virtual_price`, `lpPrice`, `lpToken.*value`

**Real incidents:** EulerFinance (2023-03, $200M), PolterFinance (2024-11, $7M), 0vix (2023-04, $2M), CompoundFork/Base (2024-10, $1M), Allbridge (2023-04, $550K), Themis (2023-06, $370K), DDCoin (2023-06, $300K), ParaSpace (2023-03, 2909 ETH), RoeFinance (2023-01, $80K), DKP (2023-03, $80K), LW (2023-05, $50K), Venus THE (2026-03).

---

## Pattern 4: Fee Avoidance

```yaml
- id: flash-004
  pattern: flash-loan-fee-avoidance
  name: "Flash loan fee avoidance or fee underflow"
  causa_raiz: "Flash loan fee calculation rounds down to zero for small amounts, or fee can be bypassed through reentrancy, callback manipulation, or splitting into multiple sub-threshold loans."
  como_funciona: |
    1a. (Rounding) Borrow amount where fee = amount * feeRate / PRECISION rounds to 0; repeat many times
    1b. (Bypass) Call flashLoan through a path that skips fee collection (e.g., internal function exposed, or callback re-enters to repay without fee)
    1c. (Split) Break one large loan into many small loans each below fee threshold
    2. Accumulate borrowed capital without paying proportional fees
    3. Protocol loses expected fee revenue; in severe cases, pool is drained
  invariante: "flashLoanFee >= 1 wei for any non-zero borrow amount; totalFeesCollected >= expectedFeeRate * totalBorrowed"
  que_mirar:
    - "Fee calculation: amount * fee / 10000 with no minimum fee floor"
    - "Flash loan callable internally without fee"
    - "Fee parameter controllable by borrower"
    - "Recursive flash loan (borrow inside callback) without cumulative fee tracking"
    - "ERC-3156 maxFlashLoan() returns 0 but flashLoan() still callable"
  como_se_arregla: "Enforce minimum fee of 1 wei. Use ceil division for fee calculation: (amount * feeRate + PRECISION - 1) / PRECISION. Prevent recursive flash loans or track cumulative fees per tx. Validate fee payment in repayment check, not just total balance."
  trampas:
    - "Fee-free flash loans are intentional in some protocols (Aave V3 for same-asset repay) -- check docs"
    - "Zero fee on flash mint may be by design if the protocol has no flash loan fee model"
    - "Rounding to zero on tiny amounts may be acceptable if gas cost exceeds value"
  incidentes:
    - "TraderJoe LBPair — flash loan fees paid only to active bin LPs while all bins' liquidity lent; JIT liquidity to active bin captures fees, borrower self-refunds (MEDIUM)"
  severidad: high
  confianza: media
  fuente: "COMP-FLASH-001, common audit findings"
  verificado: true
  tags: [flash-loan, fee, rounding, bypass, economic]
  relacionado_con: [flash-006]
```

**Grep targets:** `flashFee`, `flashLoanFee`, `fee.*flash`, `amount.*fee.*PRECISION`, `maxFlashLoan`

---

## Pattern 5: Flash Loan + Reentrancy Combo

```yaml
- id: flash-005
  pattern: flash-loan-reentrancy
  name: "Flash loan + reentrancy combo"
  causa_raiz: "Flash loan callback (onFlashLoan, executeOperation) re-enters the lending protocol or target before state is finalized. The callback is attacker-controlled code that executes between borrow and repayment verification."
  como_funciona: |
    1. Trigger flash loan; protocol transfers tokens to attacker contract
    2. Attacker's callback re-enters the protocol (deposit the borrowed tokens as collateral, borrow against them, withdraw, etc.)
    3. Protocol's state is inconsistent during callback -- balances updated but accounting not yet reconciled
    4. Attacker extracts value from the inconsistent state
    5. Returns to flash loan, repays original amount + fee
  invariante: "No state-changing external call to untrusted address between balance transfer and accounting update. Reentrancy guard active during entire flash loan lifecycle."
  que_mirar:
    - "Flash loan callback without reentrancy guard (nonReentrant modifier)"
    - "State update AFTER external call to borrower (violates CEI)"
    - "Protocol functions callable during flash loan callback (not locked)"
    - "ERC-777 tokens used (tokensReceived hook enables reentrancy)"
    - "Curve pools with raw_call to lending protocols during remove_liquidity"
    - "Cross-function reentrancy (function A locked, but function B is not)"
  como_se_arregla: "Apply nonReentrant modifier to flash loan function AND all state-changing functions that could be called during callback. Follow checks-effects-interactions pattern. Use transient storage reentrancy locks (EIP-1153) for gas efficiency. Lock the entire protocol during flash loan execution, not just the flash loan function."
  trampas:
    - "Single-function reentrancy guards miss cross-function reentrancy"
    - "Read-only reentrancy (Curve) bypasses write-based guards"
    - "Protocol may be safe against reentrancy but vulnerable via a composing protocol that IS vulnerable"
    - "ERC-777 hook reentrancy looks different from classic reentrancy"
  incidentes:
    - "DeFi Saver — attacker triggers random task execution via reentrancy in executeOperation() when taking a flash loan; fixed by adding ReentrancyGuard to executeOperation (High, Consensys)"
    - "Timeswap — borrow() makes external callback to msg.sender before finalizing state; lock modifier guards single-function reentrancy but not cross-function reentrancy (High, Code4rena)"
    - "BadgerDAO — _openCdpCallback / _adjustCdpCallback / _closeCdpCallback lack nonReentrant; attacker can reenter during flash loan callback to open/adjust multiple CDPs (Low, Code4rena)"
    - "Maple Finance — protocol does not follow CEI; transfers mid-execution expose borrowers to callback reentrancy while contract is in inconsistent state (Medium, Cantina)"
  severidad: critical
  confianza: alta
  fuente: "INV-EXPLOIT-006, COMP-FLASH-001"
  verificado: true
  tags: [flash-loan, reentrancy, callback, CEI, cross-function]
  relacionado_con: [flash-001, flash-003]
```

**Grep targets:** `onFlashLoan`, `executeOperation`, `flashLoanCallback`, `nonReentrant`, `_status`, `tokensReceived`, `raw_call`

---

## Pattern 6: Flash Mint Without Proper Checks

```yaml
- id: flash-006
  pattern: flash-mint-unchecked
  name: "ERC-20 native flash mint without supply/cap checks"
  causa_raiz: "Token implements ERC-3156 flash mint (minting tokens instead of lending from a pool). Missing or incorrect supply cap allows minting arbitrary amounts, which can manipulate any system that reads totalSupply or balanceOf for the token."
  como_funciona: |
    1. Call flashLoan on the token contract itself (not a lending pool)
    2. Token mints requested amount to borrower (totalSupply increases temporarily)
    3. Borrower uses inflated balance to manipulate: governance votes, pool reserves, collateral value, reward calculations
    4. Borrower burns/returns tokens in callback
    5. totalSupply returns to normal, but damage is done
  invariante: "flashMintAmount <= maxFlashLoan; totalSupply during flash mint must not affect external protocol reads; maxFlashLoan must have a hard cap"
  que_mirar:
    - "Token has flashLoan/flashMint function that mints (not transfers from pool)"
    - "maxFlashLoan() returns type(uint256).max or uncapped value"
    - "No check that totalSupply + mintAmount won't overflow or exceed cap"
    - "Other protocols read totalSupply of this token for pricing"
    - "Callback can call external protocols before tokens are burned"
    - "Fee on flash mint is 0 (no cost to attacker)"
  como_se_arregla: "Cap maxFlashLoan to a reasonable percentage of current supply. Charge non-trivial fee. Ensure totalSupply-dependent external reads are not exploitable during flash mint window. Consider whether flash mint is even necessary -- most use cases are served by pool-based flash loans."
  trampas:
    - "DAI and many stablecoins have legitimate flash mint -- the issue is when OTHER protocols don't account for it"
    - "Flash mint with proper cap and fee may be safe"
    - "The vulnerability is often in the CONSUMER of the token, not the token itself"
  incidentes:
    - "FairSide — fShareRatio in purchaseMembership manipulable via flash minting and burning FSD tokens; inflated ratio bypasses capital adequacy check and inflates staking rewards (Medium, Code4rena)"
  severidad: high
  confianza: media
  fuente: "ERC-3156 standard analysis, common audit findings"
  verificado: true
  tags: [flash-mint, ERC-3156, totalSupply, mint, cap, governance]
  relacionado_con: [flash-002, flash-004]
```

**Grep targets:** `flashMint`, `maxFlashLoan`, `_mint.*flash`, `flashLoan.*mint`, `type(uint256).max.*flash`

---

## Pattern 7: Flash Loan + Same-Block Checkpoint/Snapshot Bypass

```yaml
- id: flash-007
  pattern: flash-loan-checkpoint-same-block-bypass
  name: "Flash loan + same-block checkpoint/snapshot bypass"
  causa_raiz: >
    Checkpoint or snapshot systems record state per block. When a user can
    stake/delegate AND unstake/undelegate in the same block (via flash loan),
    the checkpoint either (a) returns the first value written that block
    (staked state) even after exit, or (b) overwrites to memory instead of
    storage due to same-block optimization bug. The flash-loaned tokens are
    returned but the inflated checkpoint persists until the next block.
  como_funciona: |
    1. Flash borrow governance/staking tokens
    2. Stake or delegate tokens — checkpoint #0 written at current block with high balance
    3. In SAME transaction: unstake or undelegate — checkpoint #1 written at same block
    4. Bug variant A (getAtBlock): getAtBlock() returns checkpoint #0 (high balance) for current block queries
    5. Bug variant B (_writeCheckpoint memory): same-block overwrite uses `memory` struct, never persists exit to storage
    6. Attacker now has inflated voting power / staking weight for reward distribution
    7. Repay flash loan; the inflated checkpoint remains until overwritten in a future block
  invariante: >
    For any user, checkpoint value at block N must reflect the FINAL state at block N,
    not an intermediate state. assert(checkpoint[user][block.number] == currentBalance[user])
  que_mirar:
    - "_writeCheckpoint uses `Checkpoint memory` instead of `Checkpoint storage` for same-block update"
    - "getAtBlock() or getPriorVotes() returns first checkpoint when multiple exist in same block"
    - "stake() and unstake() / exit() callable in same block with no cooldown"
    - "delegate() and undelegate() callable in same transaction"
    - "NFT-based voting power transferable in same block as proposal creation"
    - "No minimum holding period between deposit and withdrawal"
  como_se_arregla: >
    Use `storage` pointer (not `memory`) when updating same-block checkpoints.
    Enforce minimum 1-block delay between stake/unstake or delegate/undelegate.
    Use OpenZeppelin ERC20Votes which handles same-block correctly.
    For NFT voting: snapshot voting power at proposal.creationBlock - 1 (not creationBlock).
  trampas:
    - "OpenZeppelin Checkpoints library handles same-block correctly since v4.5 — custom implementations often do not"
    - "Even with correct checkpoint logic, transferring vote-bearing NFTs in same block can multiply votes"
    - "The memory vs storage bug is subtle — both compile and run without revert, just silently lose data"
  incidentes:
    - "Vader Protocol — flash loans inflate single voter's weight in DAO.sol via live balanceOf check; attacker can borrow tokens and influence proposal outcome within the same transaction (High, Code4rena)"
    - "Velodrome Finance — balanceOfNFT has flash loan protection (ownershipChange[_tokenId] == block.number → return 0) but balanceOfNFTAt does NOT apply it consistently; inflated voting weight usable via getPriorVotes (Medium, Spearbit)"
    - "Nabla SwapPool — deposit and withdraw in same block exploitable via flash loan; no minimum lock period for LP tokens lets attacker capture fees and rewards atomically (Medium, Pashov)"
    - "Alchemix — veALCX transferable via flash loan to inflate voting balance in same block; allows governance manipulation without sustained token holding (High, Immunefi)"
  severidad: high
  confianza: alta
  fuente: "Solodit: Telcoin #3632, Golom #8733, ConvictionScore #983, PartyDAO #3302"
  verificado: true
  tags: [flash-loan, checkpoint, snapshot, same-block, voting, staking, memory-vs-storage]
  relacionado_con: [flash-002]
```

**Grep targets:** `_writeCheckpoint`, `Checkpoint memory`, `fromBlock == block.number`, `getAtBlock`, `getPriorVotes`, `numCheckpoints`

---

## Pattern 8: Unsolicited Flash Loan Callback — Attacker Triggers Callback on Victim Contract

```yaml
- id: flash-008
  pattern: flash-loan-unsolicited-callback-hijack
  name: "Unsolicited flash loan callback — attacker triggers callback on victim contract"
  causa_raiz: >
    Flash loan protocols (Balancer, Aave, CREAM) allow the caller to specify
    an arbitrary `recipient` / `receiver` address. If a contract's
    onFlashLoan/receiveFlashLoan/executeOperation callback only validates
    that msg.sender is the lending pool (not that the flash loan was
    self-initiated), any attacker can trigger the callback with
    attacker-controlled parameters, causing the victim to execute
    operations it did not intend.
  como_funciona: |
    1. Identify victim contract that implements flash loan callback (onFlashLoan, receiveFlashLoan, executeOperation)
    2. Verify callback only checks msg.sender == lendingPool (does NOT check initiator == address(this))
    3. Call lendingPool.flashLoan(victimContract, tokens, amounts, maliciousUserData)
    4. Lending pool transfers tokens to victim and calls victim's callback
    5. Victim executes its callback logic using attacker-crafted userData (e.g., operate on attacker's trove, approve attacker's tokens, execute arbitrary operations)
    6. Attacker profits from the unintended operations
  invariante: >
    Flash loan callbacks must verify initiator == address(this).
    assert(initiator == address(this)) in every onFlashLoan/executeOperation handler.
  que_mirar:
    - "receiveFlashLoan() or onFlashLoan() that checks msg.sender == vault but NOT initiator"
    - "executeOperation() that checks msg.sender == pool but NOT initiator param"
    - "Flash loan callback that processes userData without verifying origin"
    - "Contracts with approvals or privileged operations in flash loan callback"
    - "Zapper/helper contracts that perform operations on behalf of users in callback"
    - "Previous owner retains approvals after ownership transfer (PrivatePool pattern)"
  como_se_arregla: >
    ALWAYS check `initiator == address(this)` in flash loan callbacks.
    For ERC-3156: verify the `initiator` parameter passed to onFlashLoan().
    For Balancer: store a flag before calling flashLoan, check it in receiveFlashLoan.
    For Aave: verify initiator parameter in executeOperation().
    Revoke all approvals on ownership transfer for pool/vault contracts.
  trampas:
    - "Balancer receiveFlashLoan does NOT pass an initiator param — must use a state variable flag"
    - "Aave executeOperation passes initiator as a parameter — but contracts often ignore it"
    - "Even with initiator check, userData can still be malicious if not validated"
    - "PrivatePool variant: previous owner retains approvals set via execute(), enabling post-sale theft via flashLoan"
  incidentes:
    - "Mimo DeFi — attacker sets SuperVault as flash loan receiver; lendingPool calls executeOperation() on SuperVault with attacker-crafted params, draining funds (High, Code4rena H-02)"
    - "Wido Comet Collateral Swap — WidoCollateralSwap_Aave.executeOperation and WidoCollateralSwap_ERC3156.onFlashLoan check msg.sender == pool but not initiator; attacker can impersonate any user (High, OpenZeppelin)"
    - "Stakewise STAKE-6 — receiveFlashLoan only validates msg.sender == Balancer vault; attacker triggers callback on LeverageStrategy to claim/manipulate other users' positions (Critical, Hexens)"
    - "DODO Margin Trading — MarginTrading.sol missing initiator check; attacker opens/closes trades and steals funds via flash loan to arbitrary receiver (High, Sherlock H-1)"
  severidad: critical
  confianza: alta
  fuente: "Solodit: Bold/Liquity #53948, Caviar #43394"
  verificado: true
  tags: [flash-loan, callback, initiator, receiver, hijack, access-control, unsolicited]
  relacionado_con: [flash-005]
```

**Grep targets:** `receiveFlashLoan`, `onFlashLoan`, `executeOperation`, `msg.sender == vault`, `msg.sender == pool`, `initiator`, `userData`

---

## Pattern 9: Flash Loan Repayment Without End-Balance Verification

```yaml
- id: flash-009
  pattern: flash-loan-missing-balance-verification
  name: "Flash loan repayment without end-balance verification"
  causa_raiz: >
    Flash loan implementation verifies repayment by checking that
    safeTransfer/safeTransferFrom succeeds, but does NOT compare
    post-loan balance against pre-loan balance + fee. Exotic tokens
    (rebasing, fee-on-transfer, blacklistable, upgradeable) can report
    successful transfer while actually withholding funds. Alternatively,
    same-block deposit tracking creates DoS when flash-loan-like internal
    transfers set deposit flags that block legitimate withdrawals.
  como_funciona: |
    1. Variant A (balance theft): Initiate flash loan with exotic token that reports success on safeTransfer but withholds internal balance update
    2. Token transferred out but internal accounting unchanged — pool believes it was repaid
    3. Attacker keeps the tokens; pool balance silently decremented
    4. Variant B (DoS): Protocol performs internal transfer (e.g., LendingPool withdraw during liquidation) that sets depositBlock[user] = block.number
    5. Subsequent withdrawal in same block reverts due to same-block deposit check
    6. Legitimate operations blocked until next block
  invariante: >
    After flash loan completion: balanceOf(pool) >= preBalance + fee.
    assert(token.balanceOf(address(this)) >= preLoanBalance + feeAmount)
  que_mirar:
    - "Flash loan repayment checked via safeTransfer return value only, no balance comparison"
    - "No `require(balanceOf(this) >= preLoanBalance + fee)` after callback"
    - "Protocol supports arbitrary ERC20 tokens including upgradeable ones (USDC, USDT)"
    - "Same-block deposit tracking (depositBlock mapping) that blocks withdrawals"
    - "Internal transfers that trigger deposit tracking inadvertently"
  como_se_arregla: >
    Always verify post-callback balance: require(token.balanceOf(address(this)) >= preLoanBalance + fee).
    Do not rely on safeTransfer success alone for exotic token support.
    For same-block checks: exclude internal/system transfers from deposit tracking,
    or use a whitelist for trusted callers that should not trigger cooldowns.
  trampas:
    - "Most mainstream tokens (WETH, DAI, USDC current) behave correctly — this targets edge cases and upgradeable tokens"
    - "Aave V3 and Uniswap V3 correctly verify balances post-callback — custom implementations often skip this"
    - "Same-block deposit DoS is MEDIUM severity but can block liquidations, causing cascading bad debt"
  severidad: high
  confianza: media
  fuente: "Solodit: Ajna #6310, Elytra/StabilityPool #63404"
  verificado: true
  tags: [flash-loan, balance-check, repayment, exotic-token, same-block, DoS]
  relacionado_con: [flash-004]
```

**Grep targets:** `safeTransfer.*repay`, `flashLoan.*balanceOf`, `preLoanBalance`, `depositBlock`, `block.number.*deposit`

---

## Pattern 10: Flash Loan Deposit Inflates Spot Share for Disproportionate Reward Extraction

```yaml
- id: flash-010
  pattern: flash-loan-reward-share-dilution
  name: "Flash loan deposit inflates spot share for disproportionate reward extraction"
  causa_raiz: >
    Reward or vesting distribution is calculated based on the user's current
    (spot) share of a pool at withdrawal/claim time, not time-weighted.
    An attacker flash-loans tokens, deposits to gain overwhelming pool share
    (e.g., 95%), claims/withdraws to capture most accrued rewards, then
    exits and repays — all in one transaction. The attacker contributed
    zero time-weighted liquidity but captures nearly all rewards.
  como_funciona: |
    1. Flash borrow large amount of the pool's deposit token
    2. Deposit into pool/vault to gain dominant share (e.g., 95% of totalSupply)
    3. Call withdraw or claim — reward calculation uses currentShare = userBalance / totalSupply
    4. Receive ~95% of all accrued bonus/reward tokens
    5. Withdraw deposit, repay flash loan
    6. Net cost: flash loan fee (~0.05%). Net profit: nearly all reward tokens.
  invariante: >
    Reward share must be proportional to time-weighted contribution.
    For any user: rewardAmount <= totalRewards * timeWeightedShare[user] / totalTimeWeightedShares + dust_tolerance
  que_mirar:
    - "Reward calculation uses balanceOf(user) / totalSupply() at claim time"
    - "No minimum staking/deposit duration before reward eligibility"
    - "Bonus token distribution triggered on withdraw (not on periodic claim)"
    - "Share-based vesting that uses spot balance instead of time-weighted average"
    - "Flash loan fee distribution only to active bin LPs (not proportional to all LPs)"
    - "deposit() and withdraw() callable in same block/transaction"
  como_se_arregla: >
    Use time-weighted average balance for reward calculations (similar to Synthetix RewardsDistributor).
    Enforce minimum staking period (at least 1 block, preferably epochs).
    Distribute rewards proportional to liquidity contribution over time, not spot balance.
    For concentrated liquidity: distribute flash loan fees proportional to all LPs providing loaned liquidity, not just active bin.
  trampas:
    - "Synthetix-style rewardPerToken with rewardPerTokenStored is resistant to this — but only if earned() is called before balance changes"
    - "Minimum staking period of 1 block is sufficient defense against single-tx flash loan attacks"
    - "Some protocols intentionally reward active management — distinguish from vulnerable spot-share designs"
    - "Fee manipulation variant (LBPair): JIT liquidity to active bin captures flash loan fees meant for all LPs"
  incidentes:
    - "NFTX NFTXLPStaking — no minimum stake duration; attacker stakes, claims all accrued vault rewards, and unstakes in one tx using flash loan (High, Code4rena H-04)"
    - "Sperax Farms — reward inflation via flash loan: deposit inflates share, withdraw immediately captures disproportionate rewards; fixed by adding depositTs timestamp validation (High, Quantstamp)"
    - "Yield Basis — flash loan manipulates Gauge.get_adjustment() via LP token balanceOf; inflated weight diverts reward allocation to attacker-controlled gauge (High, MixBytes)"
  severidad: high
  confianza: alta
  fuente: "Solodit: Rubicon/BathBuddy #2490, TraderJoe LBPair #5713"
  verificado: true
  tags: [flash-loan, rewards, vesting, share-dilution, time-weighted, JIT-liquidity]
  relacionado_con: [flash-003, flash-004]
```

**Grep targets:** `balanceOf.*totalSupply.*reward`, `bonusToken`, `distributeBonusTokenRewards`, `releasable`, `vestedAmount`, `claimReward.*withdraw`

---

## Pattern 11: Flash Loan Bypasses Governance Voting Power Threshold

```yaml
- id: flash-011
  pattern: flash-loan-governance-bypass
  name: "Flash loan bypasses governance voting power threshold — proposal spam or instant execution"
  causa_raiz: "Governance checks voting power via token balance or lock balance at the current block. Flash-loaned tokens satisfy the minimum proposer threshold. Combined with EarlyExecution mode, an attacker can create a proposal, vote, and execute it in a single transaction, bypassing the intended community deliberation."
  como_funciona: |
    1. Governance requires minProposerVotingPower tokens to create proposals.
    2. MinVotingPowerCondition checks token.balanceOf(user) — includes unlocked balance.
    3. Attacker flash-loans governance tokens from a DEX pool.
    4. Attacker creates a proposal (balance check passes).
    5. With EarlyExecution: attacker locks tokens, votes, auto-executes the proposal.
    6. Attacker unlocks tokens and repays flash loan — all in one transaction.
    7. Malicious proposal executed without any community participation.
  invariante: |
    // Voting power must be based on locked tokens, not current balance
    // Proposal cannot be executed in the same block it was created
    assert(proposal.executionBlock > proposal.creationBlock)
  que_mirar:
    - "rg 'balanceOf.*votingPower|getVotingPower' --type sol — uses live balance?"
    - "Can proposals be created and executed in the same block?"
    - "Is there a time delay between proposal creation and voting?"
    - "Does governance token support flash loans or flash mint?"
    - "rg 'EarlyExecution|earlyExecution' --type sol"
  como_se_arregla: "Require tokens to be locked for N blocks before counting as voting power. Prevent proposal execution in the same block as creation. Use snapshot-based voting power (block.number - 1). Disallow unlocking during active proposals the user created."
  trampas:
    - "If governance token has no flash loan source, attack requires real capital"
    - "If there is a time-weighted voting power, flash loans are ineffective"
  incidentes:
    - "Aragon DAO Gov Plugin — MinVotingPowerCondition bypassed via flash loan; with EarlyExecution, create+vote+execute in one tx (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [flash-loan, governance, voting-power, proposal, EarlyExecution, bypass]
```

**Grep targets:** `balanceOf.*votingPower`, `getVotingPower`, `EarlyExecution`, `earlyExecution`, `minProposerVotingPower`

---

## Pattern 12: First Depositor Flash Loan Staking Reward Manipulation

```yaml
- id: flash-012
  pattern: flash-loan-first-depositor-reward-manipulation
  name: "First depositor uses flash loan to claim disproportionate staking rewards"
  causa_raiz: "Staking reward index update is skipped when totalStakedAmount == 0, meaning the first depositor's stake does not update the lastMinted timestamp. The first depositor can flash-loan a large amount, stake, trigger reward accrual for elapsed time (which was never checkpointed), claim inflated rewards, unstake, and repay — all atomically."
  como_funciona: |
    1. Reward contract: _updateRewardIndex() returns early if totalStakedAmount == 0.
    2. Time passes with no stakers — lastMinted timestamp becomes stale.
    3. First depositor flash-loans large amount of staking tokens.
    4. Stakes tokens — totalStakedAmount goes from 0 to large amount.
    5. Calls claim/getReward — _updateRewardIndex now executes with large elapsed time.
    6. rewardIndex += (elapsed * mintRate * 1e18) / totalStaked.
    7. First depositor owns 100% of stakes, claims all accrued rewards.
    8. Unstakes and repays flash loan in same transaction.
  invariante: |
    // Reward index must update timestamp even when totalStaked == 0
    // Or: require minimum stake duration before claiming
    assert(lastMinted == block.timestamp || totalStaked > 0)
  que_mirar:
    - "rg '_updateRewardIndex|updateReward' --type sol — does it skip when total == 0?"
    - "Does the first deposit update the reward timestamp?"
    - "Can stake + claim + unstake happen in the same transaction?"
    - "Is there a minimum lock period for staking?"
  como_se_arregla: "Always update lastMinted timestamp even when totalStaked == 0. Add a minimum staking duration before rewards can be claimed. Use snapshot-based reward accounting that prevents same-block claim."
  trampas:
    - "If there is a minimum lock period, flash loan cannot be repaid atomically"
    - "If rewards are negligible during the gap, low practical impact"
  incidentes:
    - "Super DCA Liquidity Network — first depositor flash loans to claim inflated token rewards due to skipped timestamp update (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [flash-loan, first-depositor, staking, rewards, timestamp, manipulation]
```

**Grep targets:** `_updateRewardIndex`, `updateReward`, `totalStakedAmount`, `lastMinted`, `totalStaked.*0`

---

## Pattern 13: Flash Loan Sandwich on Admin Pool Size Update

```yaml
- id: flash-013
  pattern: flash-loan-pool-size-sandwich
  name: "Flash loan sandwich on admin pool size update extracts excess value"
  causa_raiz: "Admin calls updatePool(newPoolSize, newYieldRate) to adjust pool parameters. The function sets poolSize from external input without checking current deposits. An attacker front-runs with a redemption (reducing actual pool), the updatePool restores poolSize to the target value, and the attacker back-runs with another redemption at inflated share price."
  como_funciona: |
    1. Pool has 200 deposited. Admin prepares updatePool(200, 10% yield).
    2. Attacker front-runs: redeems 100 (pool now holds 100 actual).
    3. updatePool executes: sets poolSize = 200 (but only 100 actual).
    4. Share price inflated: poolSize says 200 but only 100 real assets.
    5. Attacker back-runs: redeems remaining shares at inflated value.
    6. Attacker extracts more than fair share, stealing from other depositors.
  invariante: |
    // poolSize must reflect actual deposits, not admin input
    // assert(poolSize <= actualDeposits + tolerance)
  que_mirar:
    - "rg 'updatePool|setPoolSize' --type sol — can admin set arbitrary pool size?"
    - "Is poolSize used for share pricing?"
    - "Can deposits/withdrawals happen in the same block as updatePool?"
    - "Is there a pause mechanism around admin updates?"
  como_se_arregla: "Make updatePool callable only while protocol is paused. Add cooldown for user operations after admin updates. Calculate poolSize from actual state rather than external input."
  trampas:
    - "If updatePool is behind a timelock, sandwich timing is harder"
    - "If the function is onlyOwner and owner is a multisig, MEV risk may be lower"
  incidentes:
    - "YuzuUSD YuzuILP — updatePool sets poolSize from external input; sandwich attack extracts excess value from other depositors (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [flash-loan, sandwich, pool-size, admin-update, share-price, MEV]
```

**Grep targets:** `updatePool`, `setPoolSize`, `poolSize`, `admin.*pool`, `poolSize.*share`

---

## Pattern 14: Flash Loan Forces Token Graduation Without Community Support

```yaml
- id: flash-014
  pattern: flash-loan-graduation-forcing
  name: "Flash loan forces token graduation without community support"
  causa_raiz: "Bonding curve graduation requires reaching a token threshold (gradThreshold). The unwrapToken function allows atomic conversion without time restrictions. An attacker flash-loans the threshold amount, buys bonding curve tokens to trigger graduation, sells into the newly deployed DEX pair, and repays — all in one transaction."
  como_funciona: |
    1. Bonding curve requires gradThreshold of virtual tokens to graduate.
    2. Attacker flash-loans virtual tokens from existing DEX pool.
    3. Calls buy() on bonding curve with flash-loaned amount.
    4. gradThreshold reached — graduation triggers, Uniswap pair created.
    5. unwrapToken() converts memecoins to agentTokens (no time restriction).
    6. Attacker sells agentTokens on new Uniswap pair for virtual tokens.
    7. Repays flash loan. Token graduated with zero community support.
    8. Attacker gains exposure to reward emissions from graduated status.
  invariante: |
    // Graduation must require sustained community participation, not atomic
    // assert(block.timestamp - firstDeposit > MIN_GRADUATION_PERIOD)
  que_mirar:
    - "rg 'gradThreshold|graduation|graduate' --type sol"
    - "Can graduation be triggered atomically (same block as deposit)?"
    - "Is unwrapToken time-restricted after graduation?"
    - "Does the bonding curve check for flash loan patterns?"
  como_se_arregla: "Add time delay between reaching graduation threshold and actual graduation. Restrict unwrapToken to be callable only after a cooldown post-graduation. Use time-weighted average deposits for graduation threshold."
  trampas:
    - "If graduation only benefits the token's ecosystem, attacker incentive may be limited"
    - "If flash loan source has insufficient liquidity, attack cost increases"
  incidentes:
    - "Virtuals Protocol Bonding — flash loan forces premature token graduation; attacker gains reward emissions without community support (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [flash-loan, graduation, bonding-curve, unwrap, atomic, MEV]
```

**Grep targets:** `gradThreshold`, `graduation`, `graduate`, `unwrapToken`, `bonding.*curve`

---

## Pattern 15: Flash Loan Repayment Check Uses Wrong Baseline

```yaml
- id: flash-015
  pattern: flash-loan-balance-check-off-by-amount
  name: "Flash loan repayment check uses wrong baseline — always reverts or overcharges"
  causa_raiz: "Flash loan function records balanceBefore pre-transfer, then checks (balanceAfter - balanceBefore) >= amount + fee. Since balanceBefore includes the loan amount (still in contract), the check requires the borrower to return amount + fee as NET increase, meaning they must pay amount + fee ON TOP of the returned principal. Every flash loan either reverts or overcharges by the principal amount."
  como_funciona: |
    1. balanceBefore = token.balanceOf(address(this)) — includes the loan amount.
    2. Contract transfers 'amount' to borrower.
    3. Borrower executes callback and returns amount + fee.
    4. balanceAfter = token.balanceOf(address(this)).
    5. Check: (balanceAfter - balanceBefore) < amount + fee.
    6. balanceAfter - balanceBefore = fee only (amount was there before, left, and came back).
    7. fee < amount + fee → revert. All flash loans fail.
    8. Variant: using safeTransferFrom(address(this), ...) which requires self-approval.
  invariante: |
    // Flash loan check should be: balanceAfter >= balanceBefore + fee
    // OR record balanceBefore AFTER the transfer out
    assert(token.balanceOf(address(this)) >= preTransferBalance + fee)
  que_mirar:
    - "rg 'flashLoan|flashLoanSimple' --type sol"
    - "Where is balanceBefore recorded — before or after the outgoing transfer?"
    - "Does the repayment check compare against amount + fee or just fee?"
    - "Is safeTransfer or safeTransferFrom used for the outgoing transfer?"
  como_se_arregla: "Record balanceBefore AFTER the outgoing transfer. Or check (balanceAfter - balanceBefore) >= fee instead of amount + fee. Use safeTransfer (not safeTransferFrom) for outgoing flash loan transfer."
  trampas:
    - "If the function is unused or behind a flag, no practical impact"
    - "Some implementations wrap this in try/catch, masking the revert"
  incidentes:
    - "Astrolab — flashLoanSimple uses safeTransferFrom(address(this),...) requiring self-approval (always reverts) (High)"
    - "Astrolab — balanceBefore recorded pre-transfer, check requires amount+fee as net increase, overcharging users (High)"
    - "f(x) v2 — returnedAmount computed as post-callback minus pre-loan balance, always less than amount+fee, all flash loans revert (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [flash-loan, balance-check, revert, overcharge, ERC-3156, implementation-bug]
```

**Grep targets:** `flashLoan`, `flashLoanSimple`, `balanceBefore`, `balanceAfter`, `safeTransferFrom.*address(this)`

---

## Pattern 16: Utilization Ratio Checked Immediately During Flash Loan

```yaml
- id: flash-016
  pattern: flash-loan-utilization-ratio-immediate-check
  name: "Utilization ratio checked immediately during flash loan — blocks legitimate use"
  causa_raiz: "Flash loan implementation adds liabilities to the borrower and immediately checks the reserve's utilization ratio. Since the flash loan temporarily increases borrowed amount, the utilization check may fail even though the loan will be repaid in the same transaction. This blocks all flash loans when utilization is near the cap."
  como_funciona: |
    1. Pool has max_utilization_ratio = 80%.
    2. Current utilization is 75%.
    3. User requests flash loan for 10% of pool.
    4. Flash loan adds temporary liabilities: utilization = 85%.
    5. require_utilization_below_max() called immediately: 85% > 80% → revert.
    6. Flash loan rejected even though it would be repaid in the same transaction.
    7. All flash loans blocked when utilization is near the cap.
  invariante: |
    // Utilization check should happen after flash loan is repaid, not during
    // assert(utilizationAfterRepayment <= maxUtilization)
  que_mirar:
    - "rg 'flash_loan|flashLoan' — is utilization checked during or after?"
    - "Does the flash loan add temporary liabilities before repayment?"
    - "Is require_utilization_below_max called before the callback completes?"
    - "Is the flash loan reserve cached before processing user requests?"
  como_se_arregla: "Defer utilization ratio check until after the flash loan callback and repayment. Or exempt flash loans from utilization checks since they are atomic and do not affect end-state utilization."
  trampas:
    - "If flash loans are not a critical feature, lower severity"
    - "If utilization is always well below cap, may never trigger in practice"
  incidentes:
    - "Blend — flash loan adds liabilities then immediately checks utilization ratio; blocks flash loans near max utilization (Medium)"
    - "Blend — flash loan reserve d_supply incorrectly updated and stored due to missing cache step (High)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [flash-loan, utilization, ratio, revert, lending, temporary-liabilities]
```

**Grep targets:** `flash_loan`, `flashLoan`, `utilization`, `max_utilization_ratio`, `require_utilization`

---

## Pattern 17: Unsolicited Callback / Missing Initiator Check

```yaml
- id: flash-017
  pattern: flash-callback-no-initiator-check
  name: "Flash loan callback accepts unsolicited calls — missing initiator validation"
  causa_raiz: >
    ERC-3156 / Aave-style callbacks (onFlashLoan, executeOperation, receiveFlashLoan)
    typically only validate that msg.sender == the lending pool. They do NOT check that
    THIS contract actually initiated the flash loan. An attacker can directly call the
    lending pool's flashLoan() with the victim contract as receiver, and the victim's
    callback will execute with attacker-controlled params — because the caller IS the
    legitimate pool.
  como_funciona: |
    1. Victim FlasherX has onFlashLoan() that: repays, then calls vault.withdraw().
    2. Attacker calls CREAMLending.flashLoan(address(FlasherX), token, amount, maliciousParams).
    3. CREAM calls FlasherX.onFlashLoan(initiator=attacker, token, amount, maliciousParams).
    4. FlasherX checks: msg.sender == CREAM (passes).
    5. FlasherX does NOT check: initiator == address(this) (not validated).
    6. maliciousParams encode attacker-favorable vault.withdraw() call — funds drained.
  invariante: "In onFlashLoan/executeOperation: require(initiator == address(this) || trustedInitiators[initiator])"
  que_mirar:
    - "Does the callback check msg.sender == lendingPool? Does it ALSO check initiator == address(this)?"
    - "Can an external party call the flash loan provider with this contract as receiver?"
    - "Does the callback use params/data from the call without validating their origin?"
    - "Is there a separate mapping of in-flight flash loan IDs to detect unsolicited calls?"
  como_se_arregla: "Add require(initiator == address(this)) in the callback. Or use a transient storage flag: set _inFlashLoan = true before initiating, require it in the callback, unset after."
  trampas:
    - "Validating msg.sender == lendingPool is NECESSARY but NOT SUFFICIENT — attacker controls initiator and params"
    - "If the callback only reads from params but doesn't make external calls, exploitability is limited"
    - "Aave v3 executeOperation passes initiator as first argument — easy to miss vs checking only msg.sender"
    - "If the contract has no valuable functions callable during the callback, the attack surface is minimal"
  incidentes:
    - "DODO Margin Trading — MarginTrading.sol missing initiator check in executeOperation(); attacker opens/closes trades and steals funds using victim contract as flash loan receiver (High, Sherlock H-1)"
    - "Stakewise — LeverageStrategy.receiveFlashLoan validates msg.sender == Balancer vault but not initiator; attacker claims or manipulates other users' positions (Critical, STAKE-6, Hexens)"
    - "Wido Comet Collateral Swap — executeOperation and onFlashLoan check msg.sender == pool but not origin; attacker impersonates any user in collateral swap flow (High, OpenZeppelin)"
    - "Mimo DeFi — SuperVault.executeOperation triggered by attacker-initiated flash loan; attacker crafts userData to drain funds (High, Code4rena H-02)"
  severidad: high
  confianza: alta
  fuente: "Solodit: Fuji Protocol (FlasherFTM CREAM auth bypass), Stakewise (STAKE-6 unprotected flash callback), DODO Margin Trading (H-1 initiator check)"
  verificado: true
  tags: [flash-loan, callback, initiator, ERC-3156, executeOperation, onFlashLoan, access-control]
  relacionado_con: [flash-005, flash-006]
```

**Grep targets:** `onFlashLoan`, `executeOperation`, `receiveFlashLoan`, `initiator`, `msg.sender.*pool`, `_inFlashLoan`

---

## Pattern 18: Wrong Post-Loan Balance Check

```yaml
- id: flash-018
  pattern: flash-repayment-wrong-balance-check
  name: "Flash loan repayment validated against wrong balance — over/undercollection"
  causa_raiz: >
    After the flash loan callback completes, the protocol checks that the borrowed funds
    were repaid. If the validation uses `address(this).balance >= required` but `required`
    was computed using a pre-callback snapshot or a wrong variable (e.g., checking
    `returnedAmount >= amount` instead of `returnedAmount >= amount + fee`), the
    invariant can be satisfied by coincidence — leaving the protocol underpaid —
    or it may NEVER be satisfiable (blocking legitimate use entirely).
  como_funciona: |
    Variant A (undercollection — attacker wins):
    1. Protocol: require(balanceAfter >= amount) — missing the fee.
    2. Attacker returns exactly `amount`, pays no fee. Protocol accepts.
    3. Protocol leaks fee revenue on every flash loan.
    Variant B (overcollection — legitimate users blocked):
    1. Protocol transfers `amount - fee` to receiver (Compound-style: fee deducted pre-transfer).
    2. Protocol requires receiver to return `amount` full.
    3. Receiver only received `amount - fee` and can only return that.
    4. Condition fails — flash loan is permanently broken for that token.
  invariante: "balanceAfter(contract) >= balanceBefore(contract) + fee (no free flash loans, no DoS)"
  que_mirar:
    - "Does the repayment check include the fee amount or just the principal?"
    - "Is the balance snapshot taken before or after the transfer to the receiver?"
    - "Does the protocol transfer less than `amount` (deducting fee pre-transfer) but require `amount` back?"
    - "Are there fee-on-transfer tokens that make the received amount < transferred amount?"
  como_se_arregla: "Repayment check: require(address(this).balance >= balanceBeforeFlashLoan + fee). Always snapshot balance BEFORE transfer, require balance AFTER callback == snapshot + fee. Test with fee-on-transfer tokens."
  trampas:
    - "Many protocols set fee=0 intentionally — in that case, amount == required and both variants collapse"
    - "USDT and other fee-on-transfer tokens make the sender pay more than receiver gets — test explicitly"
    - "f(x) v2 H-01 variant: protocol used `<` instead of `<=` for the check — off-by-one caused a permanent DoS"
    - "Iron Bank variant: USDT non-zero transfer fee broke the balance math on the callback path"
  incidentes:
    - "Astrolab — balanceBefore recorded BEFORE flash loan transfer to receiver; balanceAfter check always fails causing every flash loan to revert (High, Pashov H-02)"
    - "f(x) v2 — flashLoan uses `returnedAmount < amount + fee` (strict less-than instead of <=); off-by-one means flash loan is permanently DoS'd when exact repayment is made (High, OpenZeppelin)"
    - "Sandclock scWETHv2/scUSDCv2 — receiveFlashLoan repays exactly the borrowed amount, ignoring Balancer flash loan fees; protocol bleeds fee revenue on each flash loan (High, Trail of Bits)"
  severidad: high
  confianza: alta
  fuente: "Solodit: Astrolab H-02 (flash loan wrong balance check), f(x) v2 (flashloan blocked), Iron Bank (USDT fee breaks flashloan)"
  verificado: true
  tags: [flash-loan, repayment, balance-check, fee, fee-on-transfer, off-by-one]
  relacionado_con: [flash-004, flash-005]

- id: flash-019
  pattern: flashloan-liquidator-self-liquidation-bonus-extraction
  name: "Self-liquidation via FlashloanLiquidator: atacante extrae liquidation bonus de su propia posicion"
  causa_raiz: >
    FlashloanLiquidator no valida que msg.sender (el liquidador) NO sea el propietario
    de la posicion siendo liquidada. Un deudor puede llamar a liquidate() sobre su propio
    tokenId usando un flash loan para cubrir liquidationCost, recibir el liquidationValue
    (colateral) de vuelta, y retener la diferencia (liquidation bonus) como ganancia neta.
    El protocolo paga el bonus al atacante-liquidador en lugar de a un liquidador honesto
    externo. Si el bonus es >= fee del flash loan, la operacion es rentable.
    Variante avanzada: el atacante puede combinar con manipulacion de oracle (modo TWAP_CHAINLINK_VERIFY)
    para forzar que su posicion sana aparezca liquidable y luego auto-liquidarse.
  como_funciona: |
    1. Atacante tiene posicion tokenId con colateral=$100K, deuda=$90K (saludable normalmente).
    2. Manipula TWAP (si modo TWAP_CHAINLINK_VERIFY con baja liquidez) para que oracle
       reporte colateral=$85K -> posicion aparece unhealthy.
    3. Llama FlashloanLiquidator.liquidate(tokenId, vault, flashPool, ..., liquidator=self).
    4. Flash loan cubre liquidationCost=$90K.
    5. vault.liquidate() transfiere colateral-at-discount al liquidador (FlashloanLiquidator).
    6. FlashloanLiquidator devuelve flash loan + fee, retiene el spread.
    7. Bonus transferido al parametro `liquidator` = msg.sender = el propio deudor.
    8. Posicion liquidada, deuda cancelada, atacante retiene liquidation bonus.
    Sin manipulacion oracle (si posicion ya es liquidable):
    - Protocolos que no verifican que liquidador != deudor permiten auto-liquidacion pura.
    - El deudor evita la penalizacion completa: recibe bonus en lugar de perder el spread.
  invariante: >
    // Liquidador no puede ser el propietario de la posicion
    address positionOwner = vault.ownerOf(params.tokenId);
    require(params.liquidator != positionOwner, "No self-liquidation");
    // O bien: liquidator != loans[tokenId].owner
  que_mirar:
    - "FlashloanLiquidator.liquidate() verifica que msg.sender != owner de la posicion?"
    - "vault.liquidate() en V3Vault.sol: hay restriccion recipient != borrower?"
    - "liquidationValue - liquidationCost > flashLoanFee? (margen de rentabilidad)"
    - "Combinado con oracle manipulation: puede el atacante forzar liquidacion de posicion sana propia?"
    - "rg 'liquidate|liquidator|recipient' en V3Vault.sol -- verificar si hay self-liquidation check"
    - "Euler EVK: self-liquidation sandwiching oracle updates fue HIGH en audit de Spearbit 2024"
  como_se_arregla: >
    Opcion 1: En FlashloanLiquidator.liquidate(), verificar que msg.sender no sea el
    propietario de loans[params.tokenId] en el vault antes de ejecutar.
    Opcion 2: En V3Vault.liquidate(), rechazar si recipient == loans[tokenId].owner.
    Opcion 3: Aplicar un cooldown despues de borrow() que impida liquidacion del propio
    deudor durante N bloques (similar a DYAD fix).
  trampas:
    - "V3Vault puede tener ya un check: grep 'loans[tokenId].owner != recipient' en V3Vault.sol"
    - "Si el liquidation bonus es pequeno (<0.3% flash loan fee), auto-liquidacion no es rentable sin oracle manip"
    - "En un mercado en caida, posicion puede ser genuinamente liquidable sin manipulacion"
    - "El beneficio al atacante depende del spread: MAX_LIQUIDATION_PENALTY_X32=10%, MIN=2% -- 2-10% de colateral"
  incidentes:
    - "Euler Labs EVK (Spearbit 2024) -- self-liquidations of leveraged positions profitable via oracle price sandwich; attacker flash-loans collateral, max-borrows, manipulates oracle, self-liquidates (HIGH, Spearbit)"
    - "DYAD (Solodit lending-42) -- flash loan guard bypassed via self-liquidation; protocol has block-based cooldown on borrows but liquidation path lacks same check (HIGH, Sherlock)"
    - "OpenLeverage (Code4rena) -- anti-flashloan mechanism can block legitimate liquidations; TWAP check makes liquidations fail if price moved >5% (MEDIUM, C4)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Euler Labs EVK Spearbit self-liquidation https://solodit.xyz/issues/self-liquidations-of-leveraged-positions-can-be-profitable-spearbit-none-euler-labs-evk-pdf; DYAD self-liquidation bypass lending-42"
  tags: [flash-loan, liquidation, self-liquidation, liquidator, V3Vault, FlashloanLiquidator, oracle-manipulation, bonus]
  relacionado_con: [flash-001, flash-003, oracle-033, oracle-034, lending-042]

- id: flash-020
  pattern: flashloan-liquidator-fee-token-mismatch
  name: "FlashloanLiquidator: fee del flash loan puede ser en token no-asset — repago incorrecto"
  causa_raiz: >
    FlashloanLiquidator.uniswapV3FlashCallback() repaga el flash loan con:
    `safeTransfer(data.asset, msg.sender, data.liquidationCost + (fee0 + fee1))`
    El comentario en el codigo dice "only one token can have fee". Uniswap V3 cobra
    el fee solo en el token prestado. Si se presta token0 (asset), fee0 > 0 y fee1 == 0.
    Si se presta token1 (asset), fee1 > 0 y fee0 == 0. La suma `fee0 + fee1` es correcta
    en este diseno SIEMPRE QUE asset sea el unico token prestado. Sin embargo, si el pool
    Flash (flashLoanPool) no tiene asset como token0 o token1, la funcion ya revierte por
    `revert InvalidPool()`. El riesgo real surge si un pool tiene fees asimetricos en tokens
    deflacionarios o si la suma fee0+fee1 overflow con tokens de fee exoticos.
    Variante critica: si alguien crea un flashLoanPool falso (no registrado en factory
    pero pasa _isFactoryPool via un pool Slipstream con tickSpacing coincidente), el
    callback puede repagar una cantidad incorrecta.
  como_funciona: |
    Escenario 1 (fee token correcto, repago correcto -- comportamiento normal):
    1. flashLoanPool.token0() == asset, se presta token0 con amount=liquidationCost.
    2. Uniswap cobra fee0 = liquidationCost * 0.3% / 100.
    3. fee1 = 0. Repago: liquidationCost + fee0. Correcto.
    Escenario 2 (pool Slipstream falso con tickSpacing coincidente):
    1. Atacante despliega contrato que imita IUniswapV3Pool con tickSpacing=200.
    2. _isFactoryPool() llama _getPool(token0, token1, _toTickSpacingU24(200)).
    3. Si el pool real en factory para esos tokens con tickSpacing=200 existe y
       es diferente del pool del atacante, la validacion falla correctamente.
    4. Pero si _toTickSpacingU24 convierte tickSpacing negativo a uint24 por overflow
       (assembly cast sin signo), podria existir un pool factory con ese uint24 value
       que el atacante usa para validar su pool malicioso.
    Escenario 3 (tokensOwed en callback -- dust leftover):
    1. Posicion V3 del colateral tiene tokens no-asset en swap0/swap1.
    2. Despues de _routerSwap(), queda dust de token que no es data.asset.
    3. _transferBalanceIfNonZero() retorna el dust al liquidador -- correcto.
    4. Pero si el router devuelve menos de lo esperado (slippage), el assetBalance
       puede ser menor que minReward -> revert NotEnoughReward.
  invariante: >
    // Fee repaid matches the actual fee charged by the flash loan pool
    uint256 feeCharged = isAsset0 ? fee0 : fee1;
    uint256 repaid = liquidationCost + (fee0 + fee1);
    // Ambos deben ser iguales si solo un token tiene fee
    assert(repaid == liquidationCost + feeCharged);
    // Y fee del token incorrecto debe ser 0
    assert(isAsset0 ? fee1 == 0 : fee0 == 0);
  que_mirar:
    - "uniswapV3FlashCallback: fee0 + fee1 -- puede ambos ser no-zero? Uniswap V3 solo cobra en el token prestado"
    - "_isFactoryPool: _toTickSpacingU24(tickSpacing) con tickSpacing negativo -- overflow a uint24?"
    - "flashLoanPool.flash(address(this), isAsset0 ? cost : 0, !isAsset0 ? cost : 0, data) -- correcto"
    - "minReward check: protege contra slippage en swaps del colateral (swap0, swap1)"
    - "Sandclock ToB: receiveFlashLoan ignores fee, repays only principal -- mismo patron aqui si fee mal sumado"
  como_se_arregla: >
    Verificar que exactamente uno de fee0, fee1 es > 0 segun el token prestado:
    `assert((isAsset0 && fee1 == 0) || (!isAsset0 && fee0 == 0))`.
    Para _toTickSpacingU24: usar SafeCast o require(tickSpacing > 0) antes del assembly cast
    (ya existe el check `if (tickSpacing <= 0) return false`).
    Para slippage: minReward ya actua como slippage check global -- documentar su uso obligatorio.
  trampas:
    - "V3 flash callback fee es SOLO en el token prestado -- fee0+fee1 es matematicamente equivalente a fee_asset si solo un token fue prestado"
    - "El check `if (tickSpacing <= 0) return false` en _isFactoryPool YA previene tickSpacing negativo"
    - "activeFlashPool guard previene callbacks no solicitados -- la superficie de ataque de pool falso es muy limitada"
    - "El riesgo real es de configuracion incorrecta (usar pool con asset incorrecto), no de exploit directo"
  incidentes:
    - "Sandclock scWETHv2/scUSDCv2 (Trail of Bits) -- receiveFlashLoan repays principal only, ignores Balancer fee; directly analogous pattern (HIGH, ToB)"
    - "Astrolab (Pashov H-02) -- flash loan callback does not account for fee in repayment; protocol bleeds on every flash loan (HIGH, Pashov)"
    - "Benqi Collateral Migrator (Cyfrin) -- CollateralMigrator reverts when pre-existing funds cover part of flash loan fees; edge case in fee accounting (LOW, Cyfrin)"
  severidad: low
  confianza: media
  verificado: true
  fuente: "Analisis directo FlashloanLiquidator.sol lineas 122-123 uniswapV3FlashCallback(). Solodit: Sandclock ToB flash-018 fee ignoring; Astrolab Pashov H-02"
  tags: [flash-loan, fee, repayment, callback, FlashloanLiquidator, uniswap-v3, fee-token, slippage]
  relacionado_con: [flash-018, flash-019, flash-004]

- id: flash-021
  pattern: unprotected-flash-loan-callback-no-initiator-check
  name: "Flash loan callback validates caller (pool) but not initiator — attacker hijacks any receiver"
  causa_raiz: >
    Flash loan callbacks (onFlashLoan, uniswapV3FlashCallback, executeOperation) typically
    verify that msg.sender is the lending pool. However, many implementations fail to verify
    that the flash loan was initiated by the receiver contract itself (initiator == address(this)).
    An attacker can call pool.flashLoan(victimContract, ...) with a victim as receiver —
    the pool calls victim.onFlashLoan(attacker, ...) and since msg.sender == pool, the victim's
    check passes. The attacker controls the callback parameters, enabling arbitrary actions
    with the victim's balance, approvals, or positions.
  como_funciona: |
    1. Victim implements onFlashLoan(initiator, token, amount, fee, data) with only:
       require(msg.sender == trustedPool, "not pool")
    2. Attacker calls trustedPool.flashLoan(victim, token, amount, data_with_attacker_params).
    3. Pool calls victim.onFlashLoan(attacker, token, amount, fee, attacker_data).
    4. msg.sender == pool -> check passes. initiator == attacker -> NOT checked.
    5. Victim executes onFlashLoan logic with attacker-controlled data:
       - Claims rewards on behalf of the attacker
       - Approves tokens to attacker
       - Executes arbitrary calls embedded in data
    6. Pool repayment: attacker funds the fee from victim's balance.
  invariante: |
    // Both pool and initiator must be validated
    require(msg.sender == trustedPool, "not pool");
    require(initiator == address(this), "not self-initiated");
  que_mirar:
    - "rg 'onFlashLoan|executeOperation|uniswapV3FlashCallback|receiveFlashLoan' --type sol -A 5"
    - "Does the callback check BOTH msg.sender (pool) AND initiator/sender (self-address)?"
    - "Can an external actor call the flash loan function with victim as receiver parameter?"
    - "rg 'flashLoan.*receiver|flash.*initiator' --type sol -- is initiator == address(this) verified?"
    - "Aave V3 executeOperation: initiator param is the address that called flashLoan — must be address(this)"
  como_se_arregla: >
    Always validate both: (1) msg.sender == trustedPool, AND (2) initiator == address(this).
    For Uniswap V3 callbacks, also validate that the calling pool matches the expected pool address.
    Store a 'flashLoanInProgress' flag (transient storage or bool) and check it in the callback
    as an additional guard against unsolicited invocations.
  trampas:
    - "Stakewise finding: attacker uses unsolicited callback to manipulate osToken positions and claim rewards (HIGH, Hats Finance)"
    - "DODO Margin Trading H-1: missing initiator check allows attacker to open positions on behalf of victims (HIGH)"
    - "Paribus and Primitive: rated Low/Medium because contracts had limited value at risk — impact determines severity"
    - "This is different from flash-017 (which covers balance-check bypass) — here the attack is arbitrary action execution"
  incidentes:
    - "Stakewise V3 [STAKE-6] — Unprotected onFlashLoan callback allows attacker to manipulate/claim other users' osToken positions; only pool check, no initiator check (HIGH, Hats Finance)"
    - "DODO Margin Trading H-1 — Missing flash loan initiator check allows attacker to open leveraged positions using victim's collateral (HIGH)"
    - "FlasherFTM / Fuji Protocol — Attacker calls CREAM flashLoan with victim FlasherFTM as receiver; CREAM auth passes because msg.sender == CREAM is checked, not initiator (HIGH)"
    - "Tapioca DAO H-15 — Attacker specifies arbitrary receiver in USD0.flashLoan(), drains receiver's token balance via executeOperation (HIGH)"
    - "Primitive Audit M-03 — Anyone can trigger flash loan for unprotected receivers; onFlashLoan has only pool check (MEDIUM)"
    - "Paribus — Missing flash loan initiator check, rated LOW due to limited in-scope contracts"
  severidad: high
  confianza: alta
  fuente: "Solodit: Stakewise STAKE-6 (HIGH), DODO H-1 (HIGH), Fuji Protocol FlasherFTM (HIGH), Tapioca DAO H-15 (HIGH), Primitive M-03 (MEDIUM)"
  verificado: true
  tags: [flash-loan, callback, initiator-check, onFlashLoan, executeOperation, arbitrary-receiver, Uniswap-V3]
  relacionado_con: [flash-017, flash-008, flash-005]

- id: flash-022
  pattern: flash-loan-protection-bypass-via-self-liquidation
  name: "Flash loan guard bypassed via self-liquidation — borrow + self-liquidate across separate txs"
  causa_raiz: >
    Protocols that implement flash loan protection (e.g., block-based borrow cooldown,
    same-transaction checks) protect the borrow path but often forget the liquidation path.
    An attacker borrows near the maximum LTV in one transaction (triggering the borrow cooldown),
    then in a subsequent transaction uses flash-loaned collateral to self-liquidate their own
    position, receiving the liquidation bonus. The flash loan guard on borrowing is bypassed
    because the liquidation is a separate transaction. The economic incentive: the liquidation
    bonus (typically 5-15%) exceeds the flash loan fee (typically 0.05-0.3%).
  como_funciona: |
    1. Attacker borrows maximum amount (collateral: 100 ETH, borrows: 80 USDC LTV).
    2. Flash loan guard prevents same-tx liquidation: borrow-block check blocks immediate liquidation.
    3. Next block: attacker flash-loans 80 USDC from Aave.
    4. Attacker self-liquidates their own position: repays 80 USDC, receives 100 ETH collateral + 10% bonus.
    5. Attacker now has 110 ETH worth, repays Aave flash loan, pockets 10 ETH (~10% bonus - fees).
    6. Attack requires: position health factor < 1.0 (or attacker manipulates oracle to get there).
  invariante: |
    // Liquidation recipient != borrower
    require(liquidationRecipient != loans[tokenId].owner, "no self-liquidation");
    // OR: same cooldown that applies to borrow also applies to liquidation
  que_mirar:
    - "rg 'liquidate|selfLiquidat' --type sol -- is recipient == borrower checked?"
    - "If flash loan guard exists on borrow, does the same guard apply to liquidation?"
    - "rg 'flashLoanProtection|borrowBlock|depositBlock|_lastBorrowBlock' --type sol"
    - "Does the liquidation bonus (LIQUIDATION_PENALTY) exceed flash loan fee? If yes, self-liquidation is profitable."
    - "Can attacker manipulate oracle (flash-001) to make their position liquidatable, then self-liquidate?"
  como_se_arregla: >
    Option 1: Require liquidationRecipient != borrower (explicit self-liquidation ban).
    Option 2: Apply the same borrow-block cooldown to liquidation calls (same guard, same check).
    Option 3: Implement a minimum time-in-position before a position can be liquidated.
    DYAD used a block-based cooldown on borrows that was not applied to liquidations — fix was to extend the guard.
  trampas:
    - "Self-liquidation on underwater positions (health factor < 1.0) is always risky — even without flash loans"
    - "In Revert Lend FlashloanLiquidator: attacker still needs to manipulate oracle to make position liquidatable (flash-019)"
    - "Some protocols intentionally allow self-liquidation for tax efficiency / deleveraging — check if excluded"
    - "Euler Labs EVK: self-liquidation of leveraged positions with oracle sandwich is a variant (HIGH, Spearbit)"
  incidentes:
    - "DYAD [H-10] — Flash loan guard on borrows not applied to liquidation path; attacker self-liquidates across separate transactions, bypassing guard (HIGH, Sherlock)"
    - "Euler Labs EVK (Spearbit 2024) — Self-liquidation of leveraged positions profitable via oracle price sandwich: flash-loan collateral, max-borrow, manipulate oracle, self-liquidate (HIGH)"
    - "OpenLeverage [M-05] — Anti-flash-loan TWAP check blocks legitimate liquidations when price moves >5%; guard overprotects (MEDIUM, Code4rena)"
  severidad: high
  confianza: alta
  fuente: "Solodit: DYAD H-10 (HIGH Sherlock), Euler Labs EVK Spearbit (HIGH), OpenLeverage M-05 (MEDIUM)"
  verificado: true
  tags: [flash-loan, liquidation, self-liquidation, flash-guard-bypass, borrow-cooldown, bonus, DYAD]
  relacionado_con: [flash-019, flash-001, flash-005, lending-042]

- id: flash-023
  pattern: flash-loan-arbitrary-receiver-drains-vault
  name: "Flash loan with attacker-specified receiver drains victim vault via executeOperation"
  causa_raiz: >
    Aave-style flash loans (flashLoan, flashLoanSimple) accept a receiver parameter —
    the contract that will receive the funds and must implement executeOperation/onFlashLoan.
    If a protocol's vault or strategy contract implements executeOperation without verifying
    that it self-initiated the flash loan, an attacker can call pool.flashLoan(victimVault, ...)
    with arbitrary calldata. The pool sends tokens to the victim vault and calls its
    executeOperation with attacker-controlled params. The vault executes its callback logic
    (e.g., investment, approval, swap) with funds it did not request, potentially approving
    tokens to the attacker or executing unauthorized transfers.
  como_funciona: |
    1. SuperVault implements executeOperation(assets, amounts, premiums, initiator, params).
    2. SuperVault checks only: require(msg.sender == aavePool, "not Aave").
    3. Attacker calls aavePool.flashLoan(superVault, [token], [largeAmount], [0], attacker_params, 0).
    4. Aave sends largeAmount tokens to superVault, calls superVault.executeOperation(attacker_params).
    5. SuperVault executes params as if it initiated the loan: approves token to attacker, or re-deposits into attacker-controlled position.
    6. Attacker drains approved tokens or profits from unauthorized vault operation.
    7. Aave repayment: comes from vault's own token balance (vault unwittingly pays for the attack).
  invariante: |
    // initiator must be address(this) — the vault must have initiated the flash loan
    require(initiator == address(this), "not self-initiated");
    // Alternatively: use a reentrancy-style flag
    require(_flashLoanInProgress, "unsolicited flash loan");
  que_mirar:
    - "rg 'executeOperation|onFlashLoan|receiveFlashLoan' --type sol -- is initiator checked?"
    - "Does the vault store a flag when it initiates a flash loan and check it in the callback?"
    - "Can an external user call pool.flashLoan(vaultAddress, ...) with arbitrary params?"
    - "rg 'aavePool.flashLoan|IPool.*flashLoan' --type sol -- who calls this? Is receiver always address(this)?"
    - "If flash loan is used for liquidation (FlashloanLiquidator pattern): is the pool address validated?"
  como_se_arregla: >
    Always validate initiator == address(this) in the flash loan callback.
    Set a storage/transient flag _inFlashLoan = true before calling pool.flashLoan and check it in executeOperation.
    Ensure the flag is cleared after the callback (even on revert — use try/catch or initialize in fallback).
    Never use approvals inside executeOperation for tokens you did not request.
  trampas:
    - "Mimo DeFi H-02: attacker specifically sets SuperVault as receiver, causing vault to execute attacker params with vault's own funds"
    - "The attack may also DoS the vault if it cannot repay the unexpected flash loan premium from its balance"
    - "Some protocols use a whitelist of valid initiators instead of address(this) — check if whitelist is editable"
  incidentes:
    - "Mimo DeFi [H-02] — Fund loss/theft by attacker setting SuperVault as flash loan receiver; executeOperation runs with attacker params, draining vault assets (HIGH, Spearbit)"
    - "Wido Comet Collateral Swap — Unexpected entry point via flash loan callback leads to user impersonation and fund theft (HIGH)"
    - "Aave Protocol V2 Audit — Anyone can open flash loan for unprotected receiver; generic finding applicable across all Aave integrations (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "Solodit: Mimo DeFi H-02 Spearbit (HIGH), Wido Comet (HIGH), Aave V2 Audit (MEDIUM)"
  verificado: true
  tags: [flash-loan, receiver, executeOperation, initiator-check, Aave, vault, arbitrary-calldata, fund-theft]
  relacionado_con: [flash-021, flash-017, flash-008]

- id: flash-024
  pattern: flash-loan-forces-protocol-cap-griefing
  name: "Flash loan hits global protocol cap — griefing attack blocks all other users"
  causa_raiz: >
    Protocols with global caps (max total supply, max borrow, max mint ceiling) that are
    enforced in-transaction can be hit by an attacker using flash-loaned capital. The attacker
    borrows enough to hit the cap in one transaction, blocking all other users from minting
    or borrowing. Since the flash loan is repaid in the same transaction, the attacker bears
    only the flash loan fee, but all other users are blocked for the duration of their transaction
    (same-block) or indefinitely if the attacker deposits (not just borrows) to maintain the cap.
    Unlike oracle manipulation attacks, this attack exploits legitimate protocol mechanics.
  como_funciona: |
    1. Protocol has globalMintCeiling = 1_000_000 USDA and currentMinted = 999_990 USDA.
    2. Attacker flash-loans 1_000_000 USDC from Aave.
    3. Attacker calls protocol.mint(10 USDA) -- hits ceiling. currentMinted = 1_000_000.
    4. Any other user's mint() call in same block reverts: currentMinted >= globalMintCeiling.
    5. Attacker repays Aave (same tx). Mint is reversed (or attacker keeps 10 USDA + repays loan).
    6. Variant (persistent): Attacker deposits and keeps position — cap remains hit across blocks.
    7. Cost to attacker: flash loan fee (0.09% of 1M = $900) per griefing epoch.
  invariante: |
    // Global caps should not be approachable with flash-loaned single-tx capital
    // OR: Caps should be based on time-weighted supply, not instantaneous
    require(tx.origin == msg.sender, "no flash loan griefing"); // crude but sometimes used
  que_mirar:
    - "rg 'globalMintCeiling|maxSupply|totalBorrowCap|debtCeiling' --type sol -- is cap checked against flash-loanable amounts?"
    - "Can a single user consume the entire remaining cap in one transaction?"
    - "Is there per-user rate limiting separate from the global cap?"
    - "If cap is hit: does the protocol allow admin to increase cap, or is it permanent DoS?"
    - "Is the same user who hit the cap required to reduce it before others can use it?"
  como_se_arregla: >
    Implement per-user or per-block minting limits in addition to global caps.
    Use time-weighted averages or exponential decay for cap tracking.
    Consider a minimum holding period before the cap contribution counts (prevents flash-then-repay from freeing the cap immediately).
    Rate-limit global cap consumption: max X% of remaining cap per block.
  trampas:
    - "AlchemistV2 finding: attacker uses flash loan to hit global synthetic token ceiling, blocking all other minters; cost = small flash fee (MEDIUM)"
    - "Persistent variant (attacker keeps deposit): much more severe but requires actual capital commitment"
    - "If cap is set very high relative to protocol TVL, attack is economically unlikely"
    - "Protocols with dynamic cap adjustments (admin can raise cap) recover faster — but admin latency creates griefing window"
  incidentes:
    - "AlchemistV2 (Alchemix) — Well-financed attacker flash-loans to hit global synthetic token minting ceiling, blocking all other users; griefing at cost of flash loan fee only (MEDIUM, audit finding)"
    - "OpenLeverage [M-05] — Anti-flash-loan mechanism blocks legitimate liquidations when TWAP price deviates >5%; indirect griefing via overcorrection (MEDIUM, Code4rena)"
  severidad: medium
  confianza: alta
  fuente: "Solodit: AlchemistV2 flash loan minting ceiling griefing (MEDIUM), OpenLeverage M-05 (MEDIUM)"
  verificado: true
  tags: [flash-loan, griefing, global-cap, minting-ceiling, DoS, rate-limit, AlchemistV2]
  relacionado_con: [flash-016, flash-002]
```

**Grep targets:** `balanceAfter`, `balanceBefore`, `returnedAmount`, `require.*amount.*fee`, `flashLoan.*balance`

---

## Quick Reference: Flash Loan Detection Checklist

| Signal | What to check | Pattern ID |
|--------|--------------|------------|
| `getReserves()` used for pricing | Spot price manipulation | flash-001 |
| `balanceOf()` for governance power | Vote manipulation | flash-002 |
| LP token as collateral | Reserve distortion | flash-003 |
| `amount * fee / PRECISION` with no floor | Fee rounding to zero | flash-004 |
| Callback without `nonReentrant` | Reentrancy via callback | flash-005 |
| Token has `flashLoan` that `_mint`s | Uncapped flash mint | flash-006 |
| `_writeCheckpoint` uses `memory` / same-block stake+exit | Checkpoint bypass, inflated voting/staking | flash-007 |
| Callback checks `msg.sender == pool` but NOT `initiator` | Unsolicited callback hijack (arbitrary receiver) | flash-008 |
| No post-callback `balanceOf` check / `depositBlock` DoS | Flash repayment theft or same-block withdrawal block | flash-009 |
| Reward uses `balanceOf / totalSupply` at claim time | Spot-share reward dilution via flash deposit | flash-010 |
| `balanceOf.*votingPower` / `EarlyExecution` present | Governance bypass via flash-loaned voting power | flash-011 |
| `_updateRewardIndex` skips when `totalStaked == 0` | First depositor flash loan steals all staking rewards | flash-012 |
| `updatePool` or `setPoolSize` from external input | Admin update sandwich extracts excess pool value | flash-013 |
| `gradThreshold` / `unwrapToken` with no time restriction | Flash loan forces premature bonding curve graduation | flash-014 |
| `balanceBefore` recorded pre-transfer / `safeTransferFrom(address(this))` | Flash loan repayment always reverts or overcharges | flash-015 |
| `utilization` checked during flash loan before repayment | Utilization cap blocks all flash loans near max | flash-016 |
| Callback missing `initiator == address(this)` check | Unsolicited call with attacker params | flash-017 |
| Repayment check omits fee / wrong balance snapshot | Fee-free loans or permanent DoS | flash-018 |

## Verified Flash Loan Incidents (DeFiHackLabs)

```yaml
verificado: true
fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"

incidentes:
  # --- Direct Flash Loan Exploits ---
  - nombre: "EulerFinance"
    fecha: "2023-03"
    perdida: "$200M"
    tipo: "Flash loan used in attack chain (donate + liquidation logic)"
    patron: [flash-005, flash-003]
    notas: "Largest flash loan amplified exploit of 2023. Flash loans funded the donation attack."

  - nombre: "PolterFinance"
    fecha: "2024-11"
    perdida: "$7M"
    tipo: "Flash loan attack"
    patron: [flash-001, flash-003]

  - nombre: "0vix"
    fecha: "2023-04"
    perdida: "$2M"
    tipo: "Flash Loan Manipulation on lending protocol"
    patron: [flash-001, flash-003]

  - nombre: "CompoundFork (Base)"
    fecha: "2024-10"
    perdida: "$1M"
    tipo: "Flash loan attack on Compound fork on Base"
    patron: [flash-003]

  - nombre: "Allbridge"
    fecha: "2023-04"
    perdida: "$550K"
    tipo: "Flash Loan Manipulation"
    patron: [flash-003]

  - nombre: "Themis"
    fecha: "2023-06"
    perdida: "$370K"
    tipo: "Flash Loan Exploit"
    patron: [flash-001, flash-003]

  - nombre: "DDCoin"
    fecha: "2023-06"
    perdida: "$300K"
    tipo: "Flash Loan / Logic Bug"
    patron: [flash-003]

  - nombre: "ParaSpace"
    fecha: "2023-03"
    perdida: "2,909 ETH"
    tipo: "Flash Loan / Manipulation"
    patron: [flash-003, flash-005]

  - nombre: "DKP"
    fecha: "2023-03"
    perdida: "$80K"
    tipo: "Flash Loan Manipulation"
    patron: [flash-001]

  - nombre: "RoeFinance"
    fecha: "2023-01"
    perdida: "$80K"
    tipo: "Flash Loan Manipulation"
    patron: [flash-001, flash-003]

  - nombre: "LW"
    fecha: "2023-05"
    perdida: "$50K"
    tipo: "Flash Loan Manipulation"
    patron: [flash-003]

  # --- Price Manipulation via Flash Loan ---
  - nombre: "BonqDAO"
    fecha: "2023-02"
    perdida: "$88M"
    tipo: "Oracle Manipulation via flash loan"
    patron: [flash-001]

  - nombre: "ZunamiProtocol"
    fecha: "2023-08"
    perdida: "$2M"
    tipo: "Price Manipulation via flash loan"
    patron: [flash-001]

  - nombre: "Jimbo"
    fecha: "2023-05"
    perdida: "$8M"
    tipo: "Protocol-Specific Price Manipulation via flash loan"
    patron: [flash-001]

  # --- Donation + Flash Loan Combos ---
  - nombre: "Venus THE"
    fecha: "2026-03"
    perdida: "TBD"
    tipo: "Donation + BorrowBehalf - flash loan amplified"
    patron: [flash-003, flash-001]
    notas: "Recent incident. Flash loan amplified a donation-based share inflation attack combined with borrowBehalf."
```

## Invariant Test Template (Chimera/Foundry)

From COMP-FLASH-001 and COMP-FLASH-002 in the invariant registry:

```solidity
// Generic flash loan wrapper -- insert attack logic in callback
function invariant_WITH_FLASH_LOAN() public {
    uint256 stateBefore = TARGET_STATE_VAR;
    flashLender.flashLoan(address(this), address(token), 1_000_000e18, "");
    uint256 stateAfter = TARGET_STATE_VAR;
    assert(stateAfter >= stateBefore); // Replace with actual invariant
}

function onFlashLoan(
    address, address token, uint256 amount, uint256 fee, bytes calldata
) external returns (bytes32) {
    // === ATTACKER ACTIONS GO HERE ===
    IERC20(token).approve(msg.sender, amount + fee);
    return keccak256("ERC3156FlashBorrower.onFlashLoan");
}
```

For mainnet fork testing, use Aave V3 (COMP-FLASH-002) for realistic capital amounts up to billions.

---

## Key Principle

Flash loans do not create bugs. They make existing bugs profitable. Every function that reads manipulable state and moves funds is a potential flash loan target. The root question is always: **can state be manipulated and consumed in the same transaction?**

---

## Solodit Verified Findings

> Source: Solodit audit database. Only findings adding new information beyond DeFiHackLabs incidents are included.

### Maps to flash-001 (Price Oracle Manipulation)

- **[HIGH] wstETH-ETH Curve LP Token Price can be manipulated to Cause Unexpected Liquidations** — Curve virtual_price used for LP token valuation in lending protocol (Sentiment); attacker manipulates via flash loan to trigger unfair liquidations on other users' positions.
- **[HIGH] Intra-Transaction Oracle Tampering Possible With LP Pricing Using Flashloans** — LP token priced via balanceOf of underlying tokens multiplied by oracle price; flash loan deposit inflates balanceOf, corrupting LP valuation.
- **[HIGH] LP Token Price Manipulation Through Reserve** — BondSteerOracle uses spot reserves (not TWAP) to calculate Steer Protocol LP token price; direct flash loan manipulation of reserves inflates price.
- **[HIGH] Potential flash loan attack on getPrice in CurveOracle** — CurveOracle reads Curve pool state that is manipulable within a single transaction; downstream lending protocol uses this for collateral valuation.
- **[HIGH] Oracle price can be manipulated (MagicLpAggregator)** — MagicLpAggregator uses pool reserves directly via getReserves() for pair token pricing; classic flash-loan-moveable spot price.
- **[HIGH] Bin Price Manipulation in CLMM** — Concentrated liquidity bins can have their price manipulated; attacker adds/removes liquidity to specific bins to distort reported price.
- **[HIGH] Domain pricing relies on pool price, which can be manipulated** — Non-DeFi use case (Move-based name service) prices domains from DEX spot price; flash loan moves pool price to buy domains cheaply.
- **[HIGH] Attacker can profit by manipulating Uniswap liquidity (stNXM)** — Attacker manipulates Uniswap V3 liquidity to distort price feed used by stNXM protocol, extracting value from the staking system.
- **[HIGH] Manipulation of livePrice to receive defaultIncentive in 2 consecutive blocks** — Stabilizer reads livePrice that can be moved within a flash loan to claim incentive rewards fraudulently across 2 blocks.
- **[HIGH] Accrued maker fees stolen by manipulating Uniswap pool spot price** — Uncompounded maker fees in AMM liquidity position can be stolen by flash-loan-manipulating the pool's spot price, reducing the fee-equivalent liquidity and share price on deposit.

### Maps to flash-003 (Liquidity Pool Manipulation)

- **[HIGH] Overpayment of one side of LP Pair onJoinPool** — CronV1Pool uses only one token to determine LP mint amount; attacker can overpay one side via flash loan to extract the excess on removal.
- **[HIGH] Attacker can manipulate low TVL Uniswap V3 pool to borrow and swap** — ParaSpace accepts UniV3 NFT positions as collateral; attacker creates position in low-TVL pool, flash-loan-inflates its value, borrows against it, causing bad debt.

### Maps to flash-005 (Reentrancy Combo)

- **[HIGH] Re-entrancy + flash loan attack can invalidate price check (Gamma Strategies)** — Reentrancy during deposit bypasses price deviation check that is meant to prevent flash loan manipulation; two bugs chained together.
- **[HIGH] Reentrancy in flashAction() allows draining liquidity pools (Arcadia)** — ERC777 tokensReceived hook enables reentrancy during flash action, allowing attacker to drain creditor pool by re-entering before state update.
- **[HIGH] CNumaToken.leverageStrategy() reentrancy crashes NUMA price** — Missing reentrancy guard on leverageStrategy allows re-entrance that moves all vault funds to a cToken, crashing the NUMA token price.
- **[HIGH] Reentrancy in creating Creds steals all Ether** — Reentrancy via ETH transfer callback during Cred creation allows attacker to drain contract balance.
- **[HIGH] Reentrancy bypasses cooldown for unfair reward extraction via flash loan** — Flash-loan + reentrancy combo bypasses cooldown period in reward distributor, enabling repeated reward claims in a single tx.
- **[HIGH] Stealing funds via reentrancy on removeCollateral + startLiquidationAuction + purchaseLiquidationAuctionNFT** — Cross-function reentrancy chain across collateral/auction functions allows fund theft during flash-loan-funded operations.
- **[HIGH] Random task execution via reentrancy (DeFi Saver)** — Missing ReentrancyGuard on task execution allows attacker to re-enter and execute arbitrary tasks using flash-loaned funds.

### Maps to flash-002 (Governance Voting Manipulation)

- **[HIGH] 51% majority can hijack party tokens through arbitrary call proposal** — AddPartyCardsAuthority allows flash-loan-funded minting of party cards to reach 51% voting power, passing arbitrary call proposals to drain treasury.

### New patterns not in existing bugs

- **[HIGH] Flash loan protection bypass via self-liquidations (DYAD)** — Protocol implements flash loan guard but attacker bypasses it by self-liquidating: borrow in one tx, self-liquidate in another, effectively using flash-loan capital without triggering the guard.
- **[HIGH] Fund theft by setting SuperVault as flash loan receiver** — Aave flash loan allows specifying arbitrary receiver; attacker sets victim's SuperVault as receiver, causing executeOperation() to run with attacker-controlled params, draining vault funds.
- **[HIGH] FlasherFTM unsolicited callback invocation (CREAM auth bypass)** — Attacker directly calls CREAM's flashLoan with victim FlasherFTM as receiver; onFlashLoan() validation only checks that caller is the lending pool, not that the flash loan was self-initiated.
- **[HIGH] Missing Gap Between Borrow LTV and Liquidation Threshold** — No buffer between borrow LTV and liquidation threshold means a flash loan can push a position from healthy to liquidatable in one transaction; distinct from oracle manipulation since the protocol math itself enables instant liquidation.
- **[HIGH] receiptToken balance-tracking enables reward manipulation** — AavePool tracks rewards via receiptToken balance; flash-loan deposit inflates balance, claims disproportionate rewards, then withdraws. Balance-based reward tracking (not time-weighted) is the root cause.
- **[MEDIUM] Flash loan forces premature token graduation and reward manipulation** — Bonding curve graduation threshold can be crossed with flash-loaned capital, forcing premature graduation to Uniswap and manipulating associated rewards.
- **[MEDIUM] Well-financed attacker prevents minting of synthetic tokens** — Attacker flash-loans to hit global minting ceiling in AlchemistV2, blocking all other users from minting; griefing attack using flash loan capital against protocol-wide caps.
- **[HIGH] ERC1155 NFT hijack via reentrancy in reNFT** — Gnosis Safe fallback handler + ERC1155 callback reentrancy allows attacker to hijack rented NFTs during the rental process; flash loan funds the initial rental.
