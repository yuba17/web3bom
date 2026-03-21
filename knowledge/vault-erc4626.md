# ERC-4626 Vault — Combat Briefing

> Everything an auditor needs before reading an ERC-4626 vault.
> Sources: Trail of Bits Crytic Properties (36 invariants), Euler VK/Earn (26 invariants), DeFiHackLabs exploit DB.

---

## 1. Bugs Conocidos

### 1.1 Share Inflation / First Depositor Attack

```yaml
- id: vault-001
  pattern: first-depositor-share-inflation
  name: "Share inflation via first depositor"
  causa_raiz: >
    When totalSupply == 0, the share/asset exchange rate is undefined.
    The first depositor controls the initial ratio. If they deposit 1 wei,
    then donate a large amount directly to the vault, the exchange rate
    becomes extremely high. Subsequent depositors' assets get rounded down
    to 0 shares because shares = assets * totalSupply / totalAssets, and
    totalAssets is now enormous relative to totalSupply (1).
  como_funciona: |
    1. Attacker deposits 1 wei of asset -> receives 1 share
    2. Attacker transfers (donates) X assets directly to the vault contract
    3. Now totalAssets = X+1, totalSupply = 1
    4. Victim deposits Y assets -> shares = Y * 1 / (X+1) -> rounds to 0 if Y < X+1
    5. Attacker redeems their 1 share -> gets Y + X + 1 (everything)
  invariante: "A victim depositing assets must never lose more than 0.1% of their deposit to rounding (INV-V4626C-033)"
  que_mirar:
    - "Is there a MINIMUM_LIQUIDITY burn on first deposit?"
    - "Does the vault use virtual shares/assets offset (OZ decimalsOffset)?"
    - "Is there a minimum deposit amount enforced?"
    - "Does totalSupply start at 0 or is it pre-seeded?"
    - "Check constructor and first-deposit code path specifically"
  como_se_arregla: "Virtual shares/assets offset (add 1e6 to both numerator and denominator in conversion), or burn MINIMUM_LIQUIDITY shares to dead address on first mint, or enforce minimum first deposit."
  trampas:
    - "OZ ERC4626 v4.9+ with _decimalsOffset() is protected — check the offset value"
    - "Vaults with pre-seeded dead shares in constructor are already mitigated"
    - "Some vaults use internal shares that differ from ERC20 totalSupply"
  incidentes:
    - "ChannelsFinance Dec 2023 — $320K (CompoundV2 Inflation)"
    - "bZxProtocol Dec 2023 — $208K (Inflation Attack)"
    - "MetaLend Nov 2023 — $4K (CompoundV2 Inflation)"
    - "MahaLend Nov 2023 — $20K (Inflation/Rounding)"
    - "Raft_fi Nov 2023 — $3.2M (Inflation/Rounding)"
    - "kTAF Oct 2023 — $8K (CompoundV2 Inflation)"
    - "WiseLending Oct 2023 — $260K (Inflation/Rounding)"
    - "HundredFinance Apr 2023 — $7M (Inflation/Rounding)"
    - "BaoCommunity Jul 2023 — $46K (Inflation/Rounding)"
    - "Sonne Finance May 2024 — $20M (Precision loss — CompoundV2 fork)"
    - "RadiantCapital Jan 2024 — $4.5M (Loss of precision)"
    - "Yearn yBOLD (Sherlock) — TokenizedStrategy lacks initial deposit, attacker inflates share value to steal 25% of first depositor (HIGH)"
    - "Peapods/Fraxlend (Pashov) — rounding direction exploit on new Fraxlend pairs exponentially inflates share value, steals 100% of first deposit (HIGH)"
    - "Numa (Sherlock) — CToken.sol uses balanceOf for exchange rate, classic inflation attack on first deposit (HIGH)"
    - "FlatMoney (Sherlock) — inflation attack bypassing MIN_LIQUIDITY check by manipulating stable deposit amounts (MEDIUM)"
    - "Surge (Sherlock) — first depositor deposits 1 wei, donates, truncation steals later deposits (HIGH)"
    - "GoGoPool (Code4rena) — ggAVAX share price inflated by first depositor via deposit+syncRewards (HIGH)"
    - "Redacted Cartel (Code4rena) — AutoPxGmx/AutoPxGlp share price manipulation via first deposit (HIGH)"
    - "Mycelium (Sherlock) — pricePerShare manipulated by first depositor with 1 wei deposit + donation (HIGH)"
    - "Rage Trade (Sherlock) — DnGmxSeniorVault early depositor manipulates exchange rate via aUSDC donation (MEDIUM)"
    - "Sense (Sherlock) — initial depositor manipulates share price in AutoRoller (HIGH)"
    - "BadgerDAO (Code4rena) — StakedCitadel first depositor share price depression attack (HIGH)"
    - "Buffer Finance (Sherlock) — BufferBinaryPool early depositor exchange rate manipulation (HIGH)"
    - "Notional (Sherlock) — Vault Share/Strategy Token first-user manipulation (MEDIUM)"
    - "Astaria (Spearbit) — first vault deposit excessive rounding, mint(1 wei) creates 1 wad shares (MEDIUM)"
    - "Napier (Sherlock) — LST Adaptor inflation attack via 1 wei deposit + direct stETH transfer despite ZeroShares check (HIGH)"
    - "Omo (Pashov) — users can dupe their first deposit in the vault (HIGH)"
    - "Yield Ninja (Pashov) — first vault depositor steals subsequent depositors' tokens (HIGH)"
    - "Dipcoin Vault — vaults susceptible to inflation attacks (HIGH)"
    - "Nexus (Pashov) — share price manipulation via first deposit (HIGH)"
    - "Ammplify (Spearbit) — user loses all funds when creating compounded Maker position due to share inflation in any segment of the underlying pool (HIGH)"
    - "ManifestFinance (Pashov) — first deposit results in zero shares due to direct token transfer enabling inflation (CRITICAL)"
    - "Blueberry (Pashov) — users exploit TVL during EVM to L1 transfer causing share inflation (HIGH)"
    - "Harmonixfinance (Pashov) — first depositor inflates share price to steal from subsequent depositors (CRITICAL)"
    - "Burve (Sherlock) — first deposit front-running attack (HIGH)"
    - "Peapods (Sherlock) — vault inflation attack in AutoCompoundingPodLp due to incorrectly minting dead shares (HIGH)"
    - "Rwa (Code4rena) — first depositor issue in depositAsset() (HIGH)"
    - "Plume Network (Code4rena) — yield distribution share inflation (HIGH)"
    - "Yield Basis (Sherlock) — inflation attack on LiquidityGauge (MEDIUM)"
    - "f(x) v2 — share inflation attack on fxSAVE when totalSupply is zero (MEDIUM)"
    - "infiniFi (Pashov) — first depositor inflation attack in StakedToken contract (MEDIUM)"
    - "Omo (Pashov) — OmoVault first depositor can inflate share price by donating (MEDIUM)"
    - "Blend (Cyfrin) — interest auctions enable inflation attacks on backstop vaults (MEDIUM)"
    - "GMVault (Code4rena) — GMVault suffers from inflation attacks (HIGH)"
    - "Precision Manipulation (Code4rena) — precision manipulation due to missing mint check (HIGH)"
    - "Vault Share Inflation Risk (Code4rena) — vault share inflation risk (HIGH)"
    - "Hub (Sherlock) — lack of available liquidity check when sending token back from Hub leads to first deposit and inflation attack (HIGH)"
  severidad: critical
  confianza: alta
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  verificado: true
  tags: [first-depositor, share-inflation, empty-vault, donation, rounding]
  relacionado_con: [vault-002, vault-003]
```

### 1.2 Donation Attack (Direct Transfer Breaks Accounting)

```yaml
- id: vault-002
  pattern: donation-attack-exchange-rate
  name: "Donation inflates exchange rate via direct transfer"
  causa_raiz: >
    If totalAssets() uses balanceOf(address(this)) instead of internal
    accounting, anyone can call asset.transfer(vault, amount) to increase
    totalAssets without minting shares. This inflates the exchange rate
    (assets per share) and can be used to: (a) steal from future depositors
    via rounding, (b) manipulate liquidation thresholds in lending protocols,
    (c) grief withdrawals by making share prices too large for integer math.
  como_funciona: |
    1. Attacker holds shares in the vault
    2. Attacker calls asset.transfer(address(vault), donationAmount) — no shares minted
    3. totalAssets increases but totalSupply stays the same
    4. Exchange rate jumps: all existing shares are now worth more
    5. New depositors get fewer shares per asset (rounding favors attacker)
    6. In extreme cases, new depositors get 0 shares for their entire deposit
  invariante: "Exchange rate must not change by more than a safety threshold per block. Direct transfers must not affect accounting (INV-V4626-001, INV-V4626-003)"
  que_mirar:
    - "Does totalAssets() use balanceOf or internal tracking?"
    - "Is there a sweep/skim function for excess tokens?"
    - "Can anyone call a function that syncs balanceOf into accounting?"
    - "Are there rate-change limiters per block?"
  como_se_arregla: "Use internal accounting (track deposits/withdrawals explicitly) instead of balanceOf. Or use virtual shares offset to make donation-based inflation economically infeasible."
  trampas:
    - "Protocols using internal accounting are NOT vulnerable even without virtual shares"
    - "Rebasing tokens legitimately change balanceOf — don't flag as donation"
    - "Some protocols have intentional donate() functions for yield distribution"
  incidentes:
    - "HundredFinance Apr 2023 — $7M (Inflation/Rounding via donation)"
    - "Raft_fi Nov 2023 — $3.2M (Inflation/Rounding)"
    - "WiseLending Oct 2023 — $260K (Inflation/Rounding)"
    - "Sonne Finance May 2024 — $20M (Precision loss — CompoundV2 fork)"
    - "Curve LlamaLend Mar 2026 — ~$240K (Share Price Manipulation)"
    - "GMX Jul 2025 (Share Price Manipulation)"
    - "ResupplyFi Jun 2025 (Share Price Manipulation)"
    - "Aragon Generic Money (Spearbit) — vault price manipulation via balance manipulation allows yield manager to mint tokens (HIGH)"
    - "Tenbin — direct vault deposits incorrectly counted as revenue leading to liquidity drain (HIGH)"
    - "Morpho Vaults v2 (Spearbit) — side effects of underlying directly donated to VaultV2 or adapters positions (HIGH)"
    - "Strata Tranches (Cyfrin) — mechanism to prevent donation attack gamed to cause withdrawals to revert, assets stuck on strategy (HIGH)"
    - "Burve (Sherlock) — attacker drains assets from Closure by exploiting NoopVault via donation attack (HIGH)"
    - "Perennial (Sherlock) — Perennial account users with rebalance group suffer donation attack (HIGH)"
    - "Vaults v2 (Code4rena) — vaults vulnerable to donation attack (HIGH)"
    - "ZEALOT (Code4rena) — attacker sets exchange rate of ZEALInfinityPool to very large or unlimited value (HIGH)"
    - "ExchangeRate manipulation via Donation (Pashov) — exchange rate manipulation via direct transfer donation (HIGH)"
    - "Pendle (Code4rena) — PT donation attack will DoS spell deposit permanently (MEDIUM)"
    - "Exchange Rate Manipulation via Direct Transfers (Pashov) — zero HEU payouts due to rounding in exchange rate after donation (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  verificado: true
  tags: [donation, direct-transfer, balanceOf, exchange-rate, totalAssets]
  relacionado_con: [vault-001, vault-007]
```

### 1.3 Rounding Direction Exploitation

```yaml
- id: vault-003
  pattern: rounding-direction-wrong
  name: "Rounding favors user instead of vault"
  causa_raiz: >
    ERC-4626 conversion math uses integer division which truncates.
    The EIP specifies rounding direction: deposit/mint should round UP
    (cost more assets), withdraw/redeem should round DOWN (return fewer
    assets). If a vault rounds in the wrong direction, users extract
    fractional value per operation, drainable via repetition.
    The formula is: shares = assets * totalSupply / totalAssets.
    Without explicit roundUp, Solidity truncates toward zero.
  como_funciona: |
    1. Vault rounds DOWN on deposit (user pays fewer assets than they should)
    2. Or vault rounds UP on redeem (user gets more assets than they should)
    3. Attacker repeats deposit+redeem cycle, extracting 1 wei per roundtrip
    4. With flash loans, millions of iterations are feasible in one tx
  invariante: |
    - previewDeposit(0) == 0, deposit(0) returns 0 shares (INV-V4626C-013, -019)
    - previewMint(shares>0) > 0 — minting always costs something (INV-V4626C-014)
    - previewWithdraw(tokens>0) > 0 — withdrawing always burns something (INV-V4626C-017)
    - previewRedeem(0) == 0, redeem(0) returns 0 assets (INV-V4626C-016, -022)
    - convertToShares(0) == 0, convertToAssets(0) == 0 (INV-V4626C-015, -018)
  que_mirar:
    - "Does mulDivUp exist and is it used for deposit/mint?"
    - "Does mulDivDown exist and is it used for withdraw/redeem?"
    - "Check all 4 functions: deposit rounds UP (shares down), mint rounds UP (assets up), withdraw rounds UP (shares up), redeem rounds DOWN (assets down)"
    - "Search for: mulDiv, mulDivRoundingUp, Math.Rounding"
  como_se_arregla: "Always round against the user: round DOWN on shares received (deposit/redeem), round UP on assets paid (mint/withdraw). Use OZ Math.mulDiv with explicit rounding direction."
  trampas:
    - "1 wei rounding per operation is expected and acceptable — it is NOT a bug"
    - "The bug is when rounding consistently favors the user over the vault"
    - "With virtual shares offset, the rounding error per operation is negligible"
  incidentes:
    - "MahaLend Nov 2023 — $20K (Inflation/Rounding)"
    - "Raft_fi Nov 2023 — $3.2M (Inflation/Rounding)"
    - "HopeLend Oct 2023 — $825K (Precision Loss)"
    - "HundredFinance Apr 2023 — $7M (Inflation/Rounding)"
    - "BaoCommunity Jul 2023 — $46K (Inflation/Rounding)"
    - "OnyxProtocol Nov 2023 — $2M (Precision Loss)"
    - "KyberSwap Nov 2023 — $48M (Precision Loss)"
    - "KR Nov 2023 — $15K (Precision Loss)"
    - "MIMSpell Jan 2024 — $6.5M (Precision loss)"
    - "DeFiPlaza Jul 2024 — $200K (Loss of precision)"
    - "BigBangSwap Apr 2024 — $5K (Precision loss)"
    - "BNBX Apr 2024 — $75 BNB (Precision loss)"
    - "DualPools Feb 2024 — $42K (Precision truncation)"
    - "Sense (Sherlock) — AutoRoller.sol previewWithdraw doesn't round up per EIP-4626 spec (MEDIUM)"
    - "Redacted Cartel (Code4rena) — convertToShares rounds down allowing free asset withdrawal via repeated small withdrawals (HIGH)"
    - "Timeless (Spearbit) — _vaultSharesAmountToUnderlyingAmount rounds down, user receives more value than burned (MEDIUM)"
    - "Tribe (Code4rena) — ERC4626 mint uses wrong amount, shares and assets mismatched (HIGH)"
    - "Blueberry (Sherlock) — borrower drains vault by repeatedly borrowing amounts that round to 0 debt shares (MEDIUM)"
    - "SuperVault (Cyfrin) — incorrect rounding direction in SuperVault.convertToAssets() (MEDIUM)"
    - "ManifestFinance (Pashov) — wrong direction of rounding in redeem may lead to drain if exchange rate grows large (MEDIUM)"
    - "YtokenL2 (Pashov) — previewMint and previewWithdraw round in favor of user (MEDIUM)"
    - "TeaVaultAmbient (Code4rena) — _fractionOfShares causes vault to round in incorrect direction (HIGH)"
    - "Harmonixfinance (Pashov) — users exploit rounding to withdraw excess assets from fund contract (CRITICAL)"
    - "Sentiment V2 (Sherlock) — rounding error due to internal accounting steals portion of first depositor funds (HIGH)"
    - "ratiosX96Value (Code4rena) — ratiosX96Value rounds in favor of user not vault (MEDIUM)"
    - "Connectors (Spearbit) — special withdraw rounding amount direction should not favor user (MEDIUM)"
  severidad: high
  confianza: alta
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  verificado: true
  tags: [rounding, mulDiv, precision, deposit, redeem, mint, withdraw]
  relacionado_con: [vault-004, vault-005]
```

### 1.4 Roundtrip Extraction (Deposit Then Redeem for Profit)

```yaml
- id: vault-004
  pattern: roundtrip-extraction-profit
  name: "Deposit-then-redeem roundtrip yields profit"
  causa_raiz: >
    If the conversion math for deposit and redeem do not round
    consistently against the user, a roundtrip (deposit assets -> get
    shares -> redeem shares -> get assets) can return MORE assets than
    originally deposited. This is a strict violation: the vault must
    never be a money printer. The root cause is inconsistent rounding
    direction between the deposit path and the redeem path.
  como_funciona: |
    1. User deposits X assets -> gets S shares
    2. User immediately redeems S shares -> gets Y assets
    3. If Y > X, user extracted (Y - X) from the vault
    4. Repeat with flash loan for amplification
  invariante: |
    - redeem(deposit(a)) <= a (INV-V4626-011)
    - deposit(redeem(s)) <= s (INV-V4626-013)
    - mint(s) cost >= redeem(s) yield (INV-V4626-014)
    - withdraw(mint(s)) >= s shares burned (INV-V4626-015)
    - All 8 roundtrip invariants from Euler VK (INV-V4626-011 through -018)
    - convertToAssets(convertToShares(a)) <= a (INV-V4626C-035)
    - convertToShares(convertToAssets(s)) <= s (INV-V4626C-036)
  que_mirar:
    - "Test ALL 8 roundtrip directions (deposit/redeem, deposit/withdraw, mint/redeem, mint/withdraw, and reverses)"
    - "Test with small values (1, 2, 3) where rounding matters most"
    - "Test with values that are NOT multiples of the exchange rate"
  como_se_arregla: "Ensure consistent rounding: all entry points round against the user, all exit points round against the user. Same fix as vault-003."
  trampas:
    - "Fee-on-transfer tokens cause apparent profit from vault perspective — use standard ERC20 for testing"
    - "State changes between deposit and redeem (yield accrual) can legitimately change the result — test atomically"
  incidentes:
    - "MahaLend Nov 2023 — $20K (Inflation/Rounding)"
    - "Raft_fi Nov 2023 — $3.2M (Inflation/Rounding)"
    - "WiseLending Oct 2023 — $260K (Inflation/Rounding)"
    - "HundredFinance Apr 2023 — $7M (Inflation/Rounding)"
    - "BaoCommunity Jul 2023 — $46K (Inflation/Rounding)"
    - "DualPools Feb 2024 — $42K (Precision truncation)"
    - "DeFiPlaza Jul 2024 — $200K (Loss of precision)"
    - "Redacted Cartel (Code4rena) — previewWithdraw rounds down allowing withdraw of assets by burning 0 shares (HIGH)"
    - "wstUSR (Pashov) — previewWithdraw returns 0 enabling free withdraw, wrapper divides by offset rounding to zero shares (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  verificado: true
  tags: [roundtrip, extraction, arbitrage, deposit, redeem, mint, withdraw, flash-loan]
  relacionado_con: [vault-003, vault-005]
```

### 1.5 Zero Amount Edge Cases (Free Shares/Assets)

```yaml
- id: vault-005
  pattern: zero-amount-free-shares
  name: "Zero input yields nonzero output"
  causa_raiz: >
    If the vault does not explicitly check for zero inputs, edge cases
    in the math can produce nonzero outputs from zero inputs. For example,
    deposit(0) could mint shares if the conversion formula has an additive
    constant or off-by-one. Similarly, redeem(0) could return assets if
    there is a minimum withdrawal amount that gets applied regardless.
    The EIP-4626 spec requires: zero in = zero out for all functions.
  como_funciona: |
    1. Attacker calls deposit(0) -> if shares > 0 minted, free shares
    2. Or attacker calls redeem(0) -> if assets > 0 returned, free assets
    3. Repeat to accumulate unbacked shares or drain assets
  invariante: |
    - deposit(0) == 0 shares (INV-V4626C-019)
    - redeem(0) == 0 assets (INV-V4626C-022)
    - previewDeposit(0) == 0 (INV-V4626C-013)
    - previewRedeem(0) == 0 (INV-V4626C-016)
    - convertToShares(0) == 0 (INV-V4626C-015)
    - convertToAssets(0) == 0 (INV-V4626C-018)
  que_mirar:
    - "Does deposit/mint/withdraw/redeem handle 0 input explicitly?"
    - "Are there minimum amounts that create edge cases?"
    - "Does mint(1) cost > 0 assets? (INV-V4626C-014, -020)"
    - "Does withdraw(1) burn > 0 shares? (INV-V4626C-017, -021)"
  como_se_arregla: "Explicit require(amount > 0) or ensure the math naturally returns 0 for 0 input. Also ensure nonzero inputs always produce nonzero outputs."
  trampas:
    - "Some vaults intentionally revert on zero — that is acceptable per EIP"
    - "The bug is returning nonzero for zero input, not reverting"
  incidentes:
    - "HopeLend Oct 2023 — $825K (Precision Loss — zero-amount edge case)"
    - "OnyxProtocol Nov 2023 — $2M (Precision Loss)"
    - "KR Nov 2023 — $15K (Precision Loss)"
    - "BigBangSwap Apr 2024 — $5K (Precision loss)"
  severidad: high
  confianza: alta
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  verificado: true
  tags: [zero-amount, free-shares, free-assets, edge-case, rounding]
  relacionado_con: [vault-003, vault-004]
```

### 1.6 Approval/Allowance Bypass on Redeem/Withdraw

```yaml
- id: vault-006
  pattern: approval-bypass-redeem-withdraw
  name: "Third party redeems/withdraws without sufficient approval"
  causa_raiz: >
    ERC-4626 redeem and withdraw accept an `owner` parameter. When
    msg.sender != owner, the vault must check that msg.sender has
    sufficient share allowance. If this check is missing, weak, or
    uses the wrong value (e.g., checking asset allowance instead of
    share allowance), any address can drain any other address's shares.
  como_funciona: |
    1. Victim deposits assets and holds shares in the vault
    2. Attacker calls vault.redeem(victimShares, attacker, victim) with no approval
    3. If allowance check is missing: shares burned from victim, assets sent to attacker
    4. Or: attacker approves themselves for a smaller amount but withdraws more
  invariante: |
    - Redeem with insufficient approval must revert or burn <= approved shares (INV-V4626C-012)
    - Withdraw with insufficient approval must revert or burn <= approved shares (INV-V4626C-011)
    - After full approved redeem, remaining allowance == 0 (INV-V4626C-009)
    - After withdraw, remaining allowance == initial - sharesBurned (INV-V4626C-010)
  que_mirar:
    - "Does redeem() check allowance when msg.sender != owner?"
    - "Does withdraw() check allowance when msg.sender != owner?"
    - "Is the allowance check on SHARES (correct) or ASSETS (wrong)?"
    - "Is allowance decremented by actual shares burned, not requested amount?"
    - "Is there a max approval bypass (type(uint256).max skips decrement)?"
  como_se_arregla: "Check and decrement share allowance in both redeem and withdraw when msg.sender != owner. Use _spendAllowance from OZ ERC20."
  trampas:
    - "Some vaults allow operators/approved-for-all to skip allowance — check if this is intentional"
    - "ERC20 infinite approval (type(uint256).max) typically skips decrement — this is standard behavior, not a bug"
  severidad: critical
  confianza: alta
  fuente: "crytic_properties (ERC4626-009 through -012)"
  verificado: true
  tags: [approval, allowance, access-control, redeem, withdraw, third-party]
  relacionado_con: []
```

### 1.7 Share Price Manipulation

```yaml
- id: vault-007
  pattern: share-price-manipulation
  name: "Share price manipulated downward"
  causa_raiz: >
    The share price (convertToAssets(1e18)) should monotonically increase
    under normal operation. A decrease means either: (a) someone extracted
    value without proportional share burn, (b) a donation attack reduced
    the effective share price, (c) an accounting error in fee/yield
    distribution. The only legitimate decrease is from explicit loss events
    (bad debt socialization, strategy loss reporting, fee share minting).
  como_funciona: |
    1. Record share price before operation
    2. Perform some sequence of transactions
    3. Share price is now lower than before
    4. Existing depositors' holdings are worth less — value was extracted
  invariante: |
    - convertToAssets(1e18) must not decrease except for legitimate loss events (INV-V4626-001)
    - totalAssets == 0 iff totalSupply == 0 (INV-V4626-002)
    - In Earn vaults: share price only decreases on fee minting (INV-V4626-010)
  que_mirar:
    - "Can any public function decrease totalAssets without decreasing totalSupply?"
    - "Can any function increase totalSupply without increasing totalAssets?"
    - "Are fees taken by minting new shares (dilution) — this is legitimate"
    - "Is there a flash-loan-accessible path that temporarily changes the rate?"
  como_se_arregla: "Ensure all operations maintain or increase the share price. Use virtual shares to make manipulation economically infeasible. Rate-limit exchange rate changes per block."
  trampas:
    - "Fee share minting legitimately decreases share price slightly — whitelist this"
    - "Bad debt socialization legitimately decreases share price — whitelist this"
    - "Rebasing tokens change balanceOf externally — exclude from monotonicity check"
  incidentes:
    - "Curve LlamaLend Mar 2026 — ~$240K (Share Price Manipulation)"
    - "GMX Jul 2025 (Share Price Manipulation)"
    - "ResupplyFi Jun 2025 (Share Price Manipulation)"
    - "Sonne Finance May 2024 — $20M (Precision loss — CompoundV2 fork)"
    - "RadiantCapital Jan 2024 — $4.5M (Loss of precision)"
    - "HundredFinance Apr 2023 — $7M (Inflation/Rounding)"
    - "Raft_fi Nov 2023 — $3.2M (Inflation/Rounding)"
    - "Aragon Generic Money (Spearbit) — insufficient slippage control for vault operations enables rate manipulation (HIGH)"
    - "Dipcoin Vault — incorrect share price calculation during withdrawal requests (HIGH)"
    - "Mellow Protocol (Code4rena) — AaveVault does not update TVL on deposit/withdraw (HIGH)"
    - "Hubble (Code4rena) — InsuranceFund depositors priced out, deposits can be stolen via share price manipulation (HIGH)"
    - "SharePrice (Code4rena) — share price can get manipulated (HIGH)"
    - "Nexus (Pashov) — stale share price usage leading to fund loss and unfair distribution (HIGH)"
    - "LEND (Sherlock) — outdated exchange rate utilization causes users to obtain more lTokens than minted (HIGH)"
    - "Hardcoded Exchange Rate (Pashov) — hardcoded exchange rate leading to incorrect deposits and redemptions (HIGH)"
    - "Exchange Rate (Code4rena) — exchange rate can increase by more than 1% during epoch update (MEDIUM)"
    - "Conversion Rate Discrepancy (Code4rena) — conversion rate discrepancy between different functions (MEDIUM)"
    - "Exchange rate not updated properly (Code4rena) — exchange rate not updated properly (MEDIUM)"
  severidad: critical
  confianza: alta
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  verificado: true
  tags: [share-price, monotonicity, exchange-rate, manipulation, fee-minting]
  relacionado_con: [vault-001, vault-002]
```

### 1.8 Preview Function Inconsistency

```yaml
- id: vault-008
  pattern: preview-inconsistent-with-actual
  name: "Preview functions return wrong bounds vs actual operations"
  causa_raiz: >
    EIP-4626 specifies strict relationships between preview and actual:
    previewDeposit <= actual shares minted (user gets at least what was promised),
    previewMint >= actual assets consumed (user pays at most what was quoted),
    previewWithdraw >= actual shares burned (user burns at most what was quoted),
    previewRedeem <= actual assets returned (user gets at least what was quoted).
    If these bounds are violated, integrators using previews for slippage
    protection will accept worse outcomes than they expected.
  como_funciona: |
    1. Integrator calls previewDeposit(X) -> gets estimate S shares
    2. Integrator sets slippage check: require(actualShares >= S)
    3. Actual deposit returns S-1 shares due to inconsistent rounding
    4. Either: (a) integrator's tx reverts (griefing), or (b) integrator
       doesn't check and gets fewer shares than expected (loss)
  invariante: |
    - previewDeposit(a) <= deposit(a) actual shares (INV-V4626-023, INV-V4626C-029)
    - previewMint(s) >= mint(s) actual cost (INV-V4626-024, INV-V4626C-030)
    - previewWithdraw(a) >= withdraw(a) actual shares burned (INV-V4626-025, INV-V4626C-032)
    - previewRedeem(s) <= redeem(s) actual assets (INV-V4626-026, INV-V4626C-031)
    - Preview functions must not depend on msg.sender (INV-V4626C-025 through -028)
  que_mirar:
    - "Do preview and actual use the same internal math function?"
    - "Do preview and actual round in the same direction?"
    - "Does any state change between preview and actual (same-tx test required)?"
    - "Do preview functions call external contracts that could change state?"
    - "Are preview functions view/pure? (they must be per EIP)"
  como_se_arregla: "Use identical math for preview and actual, or ensure preview is a strict bound (pessimistic estimate). Preview must be pure computation on current state."
  trampas:
    - "State changes between preview call and actual call in a multi-step tx are legitimate divergence — always test atomically"
    - "Vaults with fees may legitimately have preview != actual if fees apply on actual but not preview"
  incidentes:
    - "Y2k Finance (Code4rena) — Vault.sol not EIP-4626 compliant, missing mint/redeem, max functions don't account for epoch locking (HIGH)"
    - "Florence Finance (Code4rena) — ERC4626 standard not followed correctly (MEDIUM)"
    - "Popcorn (Code4rena) — non-ERC4626-compliant vault allows malicious users to drain assets (MEDIUM)"
    - "Inverse Finance Junior Tranche (Pashov) — ERC4626 maxDeposit() violates standard by not enforcing actual deposit limits (MEDIUM)"
    - "Monolith Stablecoin (Code4rena) — EIP violation for totalAssets() in the Vault (MEDIUM)"
    - "Astrolab (Pashov) — fee target mismatch in deposit/mint/withdraw/redeem and preview methods (HIGH)"
    - "Astrolab (Pashov) — fee calculation mismatch in mint/deposit/redeem/withdraw (HIGH)"
  severidad: high
  confianza: alta
  fuente: "euler_vk (INV-V4626-023 through -026), crytic_properties (ERC4626-029 through -032)"
  verificado: true
  tags: [preview, slippage, deposit, mint, withdraw, redeem, composability]
  relacionado_con: [vault-003]

- id: vault-009
  pattern: nested-vault-accounting-desync
  name: "Nested vault redemption accounting desync"
  causa_raiz: >
    When a vault wraps another ERC4626 vault (meta-vault or yield aggregator pattern),
    the outer vault calls inner.redeem() during withdrawal but fails to properly track
    the assets flowing through the inner vault. The _withdraw accounting may double-count
    yield, not decrement depositedBase correctly, or fail to account for the inner vault's
    share-to-asset conversion rounding. The result is that the outer vault's internal
    accounting diverges from actual token balances.
  como_funciona: |
    1. Outer vault (yVault) wraps inner vault (pVault) which wraps underlying (sUSDe)
    2. During yield phase, yVault._withdraw calls pVault.redeem()
    3. The withdrawal accounting adds yield to the assets variable but also decrements depositedBase by the inflated amount
    4. This creates a discrepancy: depositedBase is decremented by more than the actual yield
    5. Attacker repeats withdrawals to amplify the accounting error
    6. Eventually the entire inner vault balance can be drained
  invariante: |
    assert(outerVault.totalAssets() <= innerVault.convertToAssets(innerVault.balanceOf(address(outerVault))) + outerVault.idleBalance());
    // Outer vault's reported totalAssets must not exceed actual redeemable value from inner vault
  que_mirar:
    - "vault.redeem() or vault.withdraw() called inside another vault's _withdraw"
    - "assets += previewYield or similar yield addition during withdrawal path"
    - "depositedBase -= or similar state decrement that includes yield component"
    - "Multiple vault layers: meta-vault, wrapper vault, yield vault stacking"
  como_se_arregla: "Separate yield tracking from principal tracking. Never add yield to the withdrawal amount before decrementing principal. Use internal accounting that is independent of inner vault share price changes."
  trampas:
    - "Single-layer vaults (no nesting) are NOT affected"
    - "If inner vault uses 1:1 exchange rate permanently, the rounding issue vanishes"
  incidentes:
    - "Strata (Cyfrin) — attacker drains sUSDe balance via incorrect pUSDeVault._withdraw accounting (HIGH)"
    - "Strata (Cyfrin) — MetaVault.redeemRequiredBaseAssets only redeems from single vault, not aggregating across vaults (MEDIUM)"
    - "Strata (Cyfrin) — DoS of meta vault withdrawals when one inner vault is paused (MEDIUM)"
    - "Morpho Vaults v2 (Spearbit) — losses across all adapters not accounted before shares/assets calculated, nested vault loss propagation gap (MEDIUM)"
    - "Yearn Vault (Code4rena) — Yearn vault withdrawal amount discrepancy due to nested vault conversion (MEDIUM)"
    - "Elytra (Pashov) — TVL double-counts assets returned from strategy; receiveFromDepositPool doesn't track assets (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, erc4626, nested-vault, meta-vault, accounting, yield, wrapper]

- id: vault-010
  pattern: sandwich-exchange-rate-frontrun
  name: "Exchange rate frontrunning via deposit/withdraw sandwich"
  causa_raiz: >
    ERC4626 deposit and mint functions lack slippage protection parameters. When
    vault operations change the exchange rate (yield accrual, interest payments,
    loss reporting, rebalancing), an attacker can sandwich the rate-changing
    transaction: deposit before the rate increase, redeem after. The EIP-4626
    security considerations explicitly warn about this for EOA access. The same
    applies to withdraw: redeem before a rate decrease, deposit after.
  como_funciona: |
    1. Attacker monitors mempool for transactions that will change the vault's exchange rate
       (e.g., yield reporting, interest accrual, allocator rebalancing, loss reporting)
    2. If rate will INCREASE: attacker deposits just before, getting shares at old (lower) rate
    3. Rate-changing transaction executes, increasing totalAssets or decreasing totalSupply
    4. Attacker redeems immediately after, getting assets at new (higher) rate
    5. Profit = (newRate - oldRate) * sharesHeld, minus gas
    6. For rate DECREASES: reverse — redeem before, deposit after
  invariante: |
    // No single address should profit more than dust from a deposit+redeem in the same block
    uint256 sharesBefore = vault.balanceOf(attacker);
    uint256 assetsBefore = asset.balanceOf(attacker);
    // ... attacker deposits and redeems ...
    assert(asset.balanceOf(attacker) <= assetsBefore + DUST_TOLERANCE);
  que_mirar:
    - "deposit() and mint() without minShares parameter"
    - "withdraw() and redeem() without minAssets parameter"
    - "Functions that change totalAssets or exchange rate callable by external actors"
    - "lastTotalAssets or similar variable updated in a separate transaction"
    - "onMorphoSupplyCollateral, onMorphoRepay or similar callbacks that update rate"
  como_se_arregla: "Add slippage protection parameters (minSharesOut for deposit, maxSharesIn for withdraw). Implement time-weighted exchange rates or rate change limits per block. Use streaming yield distribution (linear unlock over time) instead of instant rate jumps."
  trampas:
    - "Vaults with time-locked yield streaming (xERC4626 pattern) are partially protected"
    - "Small rate changes (<0.1%) may not be profitable after gas costs"
    - "This is NOT a vulnerability if the protocol intentionally allows instant rate changes for governance"
  incidentes:
    - "LoopVaults (Pashov) — onMorphoSupplyCollateral/onMorphoRepay instantly modify exchange rate, frontrunnable (LOW but documented)"
    - "Union Finance — exchangeRateStored() frontrunning on repayments to mint-then-redeem for profit (MEDIUM)"
    - "Maple Finance — depositing during unrealized losses window gets inflated share price (MEDIUM)"
    - "Gauntlet (Spearbit) — deposit and withdraw functions susceptible to sandwich attacks on Balancer pool (HIGH)"
    - "GoGoPool — wrong reward distribution between early and late depositors due to late syncRewards() (MEDIUM)"
    - "YuzuUSD (Pashov) — sandwiching yield distributions allows users to profit from redemption (MEDIUM)"
    - "Multipli Vault (Pashov) — attackers exploit yield distribution through onUnderlyingBalanceUpdate sandwiching (HIGH)"
    - "AdapterFi (Pashov) — failure to pass _withdraw_only to _getBalanceTXs allows withdrawing user to drain vault via sandwich (HIGH)"
    - "Yearn yBOLD (Sherlock) — attacker deposits after keeper reports loss but before collateral auction to steal from depositors (HIGH)"
    - "Multipli Vault (Pashov) — lack of slippage protection in deposit and mint functions (MEDIUM)"
    - "Bunni (Code4rena) — share price increases lead to sandwiching attacks when using only one vault (HIGH)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, erc4626, sandwich, frontrunning, slippage, exchange-rate, mev]

- id: vault-011
  pattern: withdrawal-fee-accounting-mismatch
  name: "Withdrawal fee not reflected in share/asset accounting"
  causa_raiz: >
    When a vault or underlying strategy charges a withdrawal fee, the actual
    amount received is less than the amount requested. If the caller's accounting
    uses the pre-fee amount to update internal state (e.g., pos.underlyingAmount,
    totalLend, debt shares), a discrepancy emerges. The user retains phantom
    collateral or the protocol's debt tracking becomes incorrect. This also applies
    to deposit fees that aren't reflected in share calculations.
  como_funciona: |
    1. User deposits X assets, vault records pos.underlyingAmount = X
    2. User withdraws, vault calls innerVault.withdraw(shareAmount)
    3. Inner vault applies withdrawal fee: returns X - fee
    4. But pos.underlyingAmount is only decremented by (X - fee), the actual return amount
    5. Remaining phantom amount (fee) is still tracked as user's collateral
    6. User can borrow against phantom collateral or the accounting becomes permanently broken
  invariante: |
    // After withdrawal, tracked amount must equal actual received amount
    uint256 actualReceived = asset.balanceOf(user) - balanceBefore;
    assert(pos.underlyingAmountReduction == sharesBurned_value_before_fee);
    // OR: assert(pos.underlyingAmount == 0) when all shares are withdrawn
  que_mirar:
    - "withdrawalPenalty, withdrawFee, or fee deduction in withdraw/redeem path"
    - "wAmount = vault.withdraw() where return value has fee already deducted"
    - "pos.underlyingAmount -= wAmount where wAmount is post-fee"
    - "bank.totalLend -= wAmount with post-fee amount"
    - "depositFee used where withdrawFee should be (or vice versa)"
  como_se_arregla: "Always decrement internal accounting by the pre-fee amount (the full share value), not the post-fee amount. Or track shares instead of underlying amounts. When all shares are burned, zero out the position completely."
  trampas:
    - "Vaults with 0% withdrawal fee are not affected"
    - "If the fee is taken in shares (not assets), the accounting may be correct"
  incidentes:
    - "Blueberry (Sherlock) — BlueBerryBank#withdrawLend causes phantom collateral when soft/hard vault has withdraw fee (HIGH)"
    - "Blueberry (Sherlock) — Interest component of underlying permanently locked because withdrawLend caps at initial deposit (HIGH)"
    - "Blueberry (Sherlock) — doCutRewardsFee uses depositFee instead of withdrawFee (MEDIUM)"
    - "Redacted Cartel (Code4rena) — maxWithdraw doesn't account for withdrawalPenalty, returns too-large amount (MEDIUM)"
    - "Timeless (Spearbit) — exitToVaultShares rounds down burn amount, user receives more value than burned (MEDIUM)"
    - "Burve (Sherlock) — removeValueSingle withdraws less than required from vertex vault due to unaccounted tax (HIGH)"
    - "Burve (Sherlock) — incorrect handling of ERC4626 vaults with fees, users can avoid fees (HIGH)"
    - "UsualX (Codehawks) — withdrawal fee for UsualX vault mis-calculated (HIGH)"
    - "Inconsistent withdrawal fee (Code4rena) — inconsistent withdrawal fee calculation between redeem and withdraw functions (MEDIUM)"
    - "Fee Abuse (Code4rena) — fee abuse in integrated contract actions (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, erc4626, withdrawal-fee, accounting, phantom-collateral, fee-mismatch]

- id: vault-012
  pattern: erc4626-oracle-price-manipulation
  name: "ERC4626 share price used as oracle is manipulable"
  causa_raiz: >
    When a lending protocol or other DeFi system uses an ERC4626 vault's
    convertToAssets() or previewRedeem() as a price oracle for the vault's
    LP token, the price is based on spot totalAssets/totalSupply which can
    be manipulated within a single transaction via deposits, withdrawals,
    or donations. Additionally, if vault.decimals() differs from
    asset.decimals(), the oracle calculation produces wrong results.
  como_funciona: |
    1. Protocol uses vault.previewRedeem(10**decimals) * assetPrice as LP token price
    2. Attacker deposits large amount into vault, inflating totalAssets
    3. Oracle now reports inflated price for vault LP tokens
    4. Attacker uses overvalued LP tokens as collateral to borrow
    5. Attacker withdraws from vault, restoring original price
    6. Attacker's loan is now undercollateralized, protocol has bad debt
  invariante: |
    // Oracle price must not change by more than X% within a single block (both directions)
    uint256 priceBefore = oracle.getPrice(vaultToken);
    // ... any single transaction ...
    uint256 priceAfter = oracle.getPrice(vaultToken);
    uint256 delta = priceBefore > priceAfter ? priceBefore - priceAfter : priceAfter - priceBefore;
    assert(delta <= priceBefore * 2 / 100); // max 2% change in either direction
    // NOTE: downward manipulation enables collateral devaluation + liquidation cascades
  que_mirar:
    - "ERC4626Oracle or similar using previewRedeem/convertToAssets for pricing"
    - "vault.decimals() used as asset.decimals() in oracle math"
    - "No TWAP or time-weighted averaging on vault share price"
    - "Vault LP tokens accepted as collateral in a lending protocol"
  como_se_arregla: "Use a TWAP of the vault's exchange rate instead of spot price. Use asset.decimals() independently from vault.decimals(). Add manipulation resistance checks (e.g., compare against a rolling average)."
  trampas:
    - "Vaults with virtual shares offset have high manipulation cost — may not be economically viable"
    - "If the oracle also checks the underlying asset price via Chainlink, the attack vector is limited to the share ratio"
  incidentes:
    - "Sentiment (Sherlock) — ERC4626Oracle vulnerable to price manipulation via deposit/withdraw (MEDIUM)"
    - "Sentiment (Sherlock) — ERC4626Oracle wrong when vault decimals != asset decimals (HIGH)"
    - "SecuritizeVault (Code4rena) — vault share token is in wrong decimals, oracle uses wrong precision (HIGH)"
    - "OracleVaultController (Pashov) — vault can be added after receiving deposits leading to incorrect price (HIGH)"
    - "convertToAssets (Pashov) — convertToAssets receives asset decimals instead of share decimals, miscalculation (HIGH)"
    - "Incorrect exchange rate to Balancer pools (Code4rena) — incorrect exchange rate provided to Balancer pools (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, erc4626, oracle, price-manipulation, collateral, lending, decimals]

- id: vault-013
  pattern: max-functions-non-compliant
  name: "maxDeposit/maxWithdraw return values ignore actual limits"
  causa_raiz: >
    EIP-4626 requires maxDeposit/maxMint/maxWithdraw/maxRedeem to return the
    actual maximum amount that would succeed if called. Many implementations
    return naive values (e.g., balanceOf[user] or type(uint256).max) without
    considering: (1) pause states, (2) internal caps, (3) per-user limits,
    (4) time-based restrictions, (5) available liquidity. Integrators relying
    on these functions for pre-flight checks get unexpected reverts.
  como_funciona: |
    1. Integrator calls vault.maxDeposit(user) to check how much can be deposited
    2. maxDeposit returns a large value (e.g., type(uint256).max or remaining cap)
    3. Integrator calls vault.deposit(maxDeposit_result)
    4. Deposit reverts because an internal check (tvlCap, pause, time lock) wasn't reflected in maxDeposit
    5. Integrator's transaction fails unexpectedly, potentially causing cascading failures in multi-step operations
  invariante: |
    // maxDeposit must never cause deposit to revert
    uint256 max = vault.maxDeposit(user);
    // vault.deposit(max, user) MUST NOT revert (assuming user has sufficient assets)
    // Similarly for maxMint, maxWithdraw, maxRedeem
  que_mirar:
    - "maxDeposit returns type(uint256).max or does not check deposit cap"
    - "maxWithdraw returns balanceOf[user] but withdrawal is time-locked"
    - "maxRedeem doesn't check pause state"
    - "Underlying pool/strategy has its own cap not reflected in max functions"
    - "Withdrawal restricted to certain time windows (e.g., first Tuesday of month)"
  como_se_arregla: "Override all max* functions to return 0 when the corresponding operation is disabled. Account for all internal caps, pause states, time locks, and underlying strategy limits."
  trampas:
    - "Some vaults intentionally return 0 during pause — this is CORRECT behavior"
    - "Returning a slightly lower value than the true max is acceptable (conservative)"
  incidentes:
    - "Maia DAO (Code4rena) — maxWithdraw/maxRedeem return balanceOf during time-locked period instead of 0 (MEDIUM)"
    - "GoGoPool (Code4rena) — maxWithdraw uses totalAssets() including unreleased rewards, causing underflow on beforeWithdraw (MEDIUM)"
    - "Redacted Cartel (Code4rena) — maxWithdraw doesn't account for withdrawalPenalty (MEDIUM)"
    - "Y2k Finance (Code4rena) — maxDeposit/maxMint/maxWithdraw/maxRedeem don't account for epoch locking (HIGH)"
    - "Florence Finance (Code4rena) — ERC4626 standard not followed correctly in max functions (MEDIUM)"
    - "VaultBase (Code4rena) — VaultBase is not ERC4626 compliant, max functions return wrong values (MEDIUM)"
    - "maxRedeem (Code4rena) — maxRedeem doesn't comply with ERC-4626 (MEDIUM)"
    - "maxDeposit (Code4rena) — maxDeposit doesn't comply with ERC-4626 (MEDIUM)"
    - "maxWithdraw (Code4rena) — maxWithdraw of ERC4626 vaults must not revert (MEDIUM)"
    - "Vault.maxRedeemInternal (Code4rena) — should always underestimate when user has controller enabled (MEDIUM)"
    - "Depositable/withdrawable (Code4rena) — _depositable and _withdrawable return incorrect values when paused (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, erc4626, compliance, maxDeposit, maxWithdraw, integrator, dos]

- id: vault-014
  pattern: vault-reentrancy-on-deposit-withdraw
  name: "Reentrancy during vault deposit/withdraw via callback tokens"
  causa_raiz: >
    When a vault accepts tokens with transfer callbacks (ERC777, ERC721 with
    onReceived, or native ETH with receive()), an attacker can reenter the
    vault during deposit or withdraw. If state updates happen after the
    external call (violating checks-effects-interactions), the attacker can
    manipulate share calculations, double-claim, or drain funds. This also
    applies to vault-to-strategy interactions where the strategy makes external
    calls before returning.
  como_funciona: |
    1. Attacker calls vault.deposit() with an ERC777 token or ETH
    2. During the transfer, the token/ETH triggers a callback to the attacker's contract
    3. Attacker reenters vault.withdraw() or vault.deposit() during the callback
    4. Because state (totalSupply, totalAssets, balances) hasn't been updated yet, the reentrant call uses stale values
    5. Attacker extracts more value than they deposited or gets extra shares
  invariante: |
    // Share price must not change during a single deposit or withdraw operation
    // (i.e., no reentrancy between state reads and state writes)
  que_mirar:
    - "deposit() or withdraw() without nonReentrant modifier"
    - "safeTransferFrom before _mint (ERC777 callback)"
    - "External call to strategy.deposit() before updating vault state"
    - "ETH transfers via .call{value:} before state update"
    - "Missing nonReentrant on takeOverDebt, liquidate, or other fund-moving functions"
  como_se_arregla: "Use nonReentrant modifier on all state-changing functions. Follow checks-effects-interactions: update all state before making external calls. Use pull-over-push pattern for ETH transfers."
  trampas:
    - "Standard ERC20 tokens without callbacks are NOT vulnerable"
    - "If vault uses WETH wrapper instead of raw ETH, callback risk is eliminated"
    - "Vaults that mint before transferring (not after) are also safe"
  incidentes:
    - "JPEG'd (Code4rena) — reentrancy in yVault.deposit via ERC777-like callback (HIGH)"
    - "Real Wagmi #2 (Sherlock) — reenter takeOverDebt() during liquidation swap to duplicate position (HIGH)"
    - "Hubble Exchange (Sherlock) — grief withdrawal queue via VUSD reentrancy in receive() (MEDIUM)"
    - "Sandclock (Code4rena) — deposit() open to reentrancy attacks (HIGH)"
    - "Sandclock (Code4rena) — withdrawers get more value via reentrant call (HIGH)"
    - "LP re-entrancy (Code4rena) — re-entrancy when minting LP tokens leads to stealing vault funds (HIGH)"
    - "BunniHub (Sherlock) — pools configured with malicious hook bypass reentrancy guard to drain raw balances and vault reserves (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, reentrancy, erc777, callback, deposit, withdraw, nonReentrant]

- id: vault-015
  pattern: reward-yield-distribution-desync
  name: "Reward/yield distribution not synced with share changes"
  causa_raiz: >
    When a vault distributes rewards or yield based on a per-share accumulator
    (rewardsPerShare or similar), new depositors who join after rewards accrue
    but before their claimed amount is initialized can claim rewards they didn't
    earn. Conversely, if the sync function isn't called on every deposit/withdraw,
    the distribution becomes unfair — early withdrawers or late depositors get
    disproportionate shares of rewards.
  como_funciona: |
    1. Vault accumulates rewards, sets amount_claimable_per_share = 0.1
    2. New user deposits, gets shares, but their claimed[user] is not initialized to current accumulator value
    3. User immediately calls claim() -> receives (shares * 0.1 - 0) = full reward allocation
    4. This exceeds what the vault actually holds in rewards, causing insolvency
    5. Last claimers cannot withdraw their rightful rewards
  invariante: |
    // On deposit, user's claimed amount must be initialized to prevent retroactive claiming
    assert(position.amount_claimed == shares_issued * amount_claimable_per_share);
    // Total claims must never exceed total rewards distributed
    assert(totalClaimed <= totalRewardsDistributed);
  que_mirar:
    - "amount_claimable_per_share or rewardsPerShare accumulator pattern"
    - "Missing initialization of claimed[user] on deposit/mint"
    - "syncRewards() not called in beforeDeposit/beforeWithdraw hooks"
    - "Reward calculation using current cliff/supply instead of historical values"
    - "getReward() called for ALL users when one user withdraws"
  como_se_arregla: "Initialize claimed[user] = shares * currentRewardsPerShare on every deposit. Call syncRewards before any deposit/withdraw. For cliff-based rewards (AURA/CVX), snapshot supply values at accrual time, not at claim time."
  trampas:
    - "Vaults using OpenZeppelin's RewardPerToken pattern correctly handle this"
    - "If all deposits happen before any rewards, the issue doesn't manifest"
  incidentes:
    - "Fair Funding (Sherlock) — amount_claimable_per_share not initialized on deposit, vault becomes insolvent (HIGH)"
    - "Blueberry Update #3 (Sherlock) — CVX/AURA reward calculation uses current supply across cliff boundaries (HIGH)"
    - "GoGoPool (Code4rena) — late syncRewards() causes unfair reward distribution (MEDIUM)"
    - "Stakehouse (Code4rena) — claimed[user][token] set to due instead of += due, allows double claiming (HIGH)"
    - "Vader Protocol (Code4rena) — vault rewards gamed via fake synth deposit with inflated weight (HIGH)"
    - "Illuvium Staking (Cyfrin) — notifyRewardAmount on empty vault leaves ILV stuck, rewards not distributed (LOW)"
    - "Deposits before hook (Pashov) — deposits made before hook connection not accounted for rewards (MEDIUM)"
    - "Future depositors (Code4rena) — future depositors receive portion of reward distributed before their deposit (MEDIUM)"
    - "AuraVault (Code4rena) — claim reward calculation does not deduct fees, causing DoS or extra rewards lost (HIGH)"
    - "Inconsistent Reward Allocation (Code4rena) — inconsistent reward allocation across stakers (HIGH)"
    - "BabelVault (Sherlock) — permanent loss of BabelToken if disabled emissions receiver doesn't call allocateNewEmissions (HIGH)"
    - "LoopFi (Code4rena) — users of a vault can steal other user's rewards when lastRewardTime differs between vaults (MEDIUM)"
    - "Incorrect Stake Calculations After Adding Yield (Code4rena) — incorrect stake calculations after adding yield (HIGH)"
    - "Yield tokens locked (Code4rena) — yield tokens permanently locked when all stakers withdraw during vesting window (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, rewards, yield, distribution, accumulator, insolvency, initialization]

- id: vault-016
  pattern: multi-token-vault-price-confusion
  name: "Multi-token vault treats different-priced tokens as equal"
  causa_raiz: >
    When a vault accepts multiple tokens (e.g., DAI, USDC, USDT) and calculates
    totalAssets or share price by summing raw balances (potentially normalized to
    18 decimals but NOT price-adjusted), it creates arbitrage. An attacker deposits
    the cheapest token and withdraws the most expensive one. Alternatively, mixing
    normalized (18-decimal) and raw (6-decimal) amounts in calculations causes
    massive over/under-estimation of balances.
  como_funciona: |
    1. Vault holds 1000 DAI + 1000 USDC + 1000 USDT, totalAssets = 3000 (summed without price consideration)
    2. Attacker deposits 1000 of cheapest token (e.g., slightly depegged USDT at $0.99)
    3. Vault mints shares based on totalAssets = 4000, totalSupply proportional
    4. Attacker withdraws targeting the most expensive token (e.g., DAI at $1.01)
    5. Profit = price difference * amount, repeated until vault is drained of expensive token
  invariante: |
    // Value deposited must equal value of shares received, regardless of token
    uint256 depositValue = oracle.getPrice(depositToken) * depositAmount;
    uint256 shareValue = vault.convertToAssets(sharesMinted) * averageTokenPrice;
    assert(shareValue <= depositValue);
  que_mirar:
    - "balanceOfThis() summing multiple token balances without price weighting"
    - "_normalizeDecimals used for some paths but not others"
    - "Mixing 18-decimal normalized amounts with raw 6-decimal amounts"
    - "withdraw(address _output) allowing user to choose withdrawal token"
    - "balance() adding normalized and non-normalized values"
  como_se_arregla: "Use oracle prices when converting between tokens. Never sum raw balances of different tokens. Normalize ALL balance sources consistently. Restrict withdrawal to the same token deposited, or use price-weighted accounting."
  trampas:
    - "Single-token vaults are NOT affected"
    - "If all accepted tokens are truly fungible at 1:1 (e.g., same stablecoin on different bridges), risk is lower"
  incidentes:
    - "yAxis (Code4rena) — multi-token vault treats all tokens as equal, creating arbitrage (HIGH)"
    - "yAxis (Code4rena) — balance() mixes normalized and non-normalized amounts (HIGH)"
    - "yAxis (Code4rena) — withdraw mixes normalized and standard amounts, inflated USDC withdrawal (HIGH)"
    - "yAxis (Code4rena) — withdrawals frontrun to drain specific stablecoins (MEDIUM)"
    - "Burve (Sherlock) — incorrect netting logic leads to excessive withdrawal amounts in multi-token pool (HIGH)"
    - "Stablecoin Arbitrage (Code4rena) — stablecoin arbitrage leads to VUSD becoming undercollateralized (HIGH)"
    - "Shared vault deployer config (Code4rena) — shared configuration parameters across different asset types leads to incorrect pricing (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, multi-token, decimals, normalization, arbitrage, stablecoin, price]

- id: vault-017
  pattern: vault-strategy-dos-cascade
  name: "Broken strategy/plugin cascades into vault-wide DoS"
  causa_raiz: >
    When a vault sequentially interacts with multiple strategies or underlying
    protocols during deposit/withdraw, a single failing strategy blocks the
    entire vault. Common causes: underlying protocol paused, utilization cap
    hit, external withdrawal limit exceeded, or strategy state machine stuck.
    Since deposit always goes to first strategy and withdraw iterates in order,
    there's no fallback or skip mechanism.
  como_funciona: |
    1. Vault has strategies [Aave, Compound, Yearn] for yield
    2. Aave protocol gets paused (legitimate governance action)
    3. User tries to withdraw from vault
    4. Vault tries to withdraw from Aave first -> reverts
    5. Entire vault withdraw is blocked, funds inaccessible
    6. Owner cannot remove or rebalance the strategy because that also requires withdrawing from Aave
  invariante: |
    // Vault operations must not be permanently blocked by any single strategy failure
    // maxWithdraw should return 0 if withdrawal would revert
  que_mirar:
    - "Sequential strategy iteration without try/catch or skip mechanism"
    - "No per-strategy pause functionality at vault level"
    - "removeStrategy requires withdrawing funds first"
    - "Utilization caps on underlying protocols (e.g., Aave, RageTrade senior vault)"
    - "External withdrawal limits (Lido MIN/MAX_WITHDRAWAL_AMOUNT)"
    - "State machine that can get stuck (compound_failed, deposit_failed)"
  como_se_arregla: "Implement per-strategy pause at vault level. Use try/catch for strategy interactions. Allow emergency strategy removal without withdrawal. Check underlying protocol state (paused()) before attempting operations."
  trampas:
    - "If the vault has only one strategy, the DoS is inherent to that strategy's availability"
    - "Temporary pauses (< 24h) may be acceptable risk"
  incidentes:
    - "Mycelium (Sherlock) — one broken plugin blocks entire vault deposit/withdraw (MEDIUM)"
    - "UXD Protocol (Sherlock) — RageTrade senior vault utilization cap locks deposits (HIGH)"
    - "Notional (Sherlock) — Lido min/max withdrawal limits permanently lock user funds (HIGH)"
    - "SteadeFi (Codehawks) — compound cancellation gets vault stuck at compound_failed status (MEDIUM)"
    - "Isomorph (Sherlock) — stale price or circuit breaker blocks all vault interactions including adding collateral (HIGH)"
    - "Multi strategy withdrawal DoS (Code4rena) — withdrawal of multi strategies vault DoSed while deposits unaffected (MEDIUM)"
    - "MultiStrategy removeStrategy (Code4rena) — cannot remove leverage strategies with deployed assets (MEDIUM)"
    - "Dust limit attack (Pashov) — dust limit attack on forceUpdateNodes allows DoS of rebalancing and potential vault insolvency (HIGH)"
    - "Withdraw limits (Code4rena) — withdraw limits not properly considered during balancing, leads to vault DoS (MEDIUM)"
    - "Market utilization (Code4rena) — market utilization near 100% DoS deposits as harvest tries to withdraw and reverts (MEDIUM)"
    - "Convex Arbitrum (Code4rena) — Convex cannot be configured for yield strategy vault in Arbitrum (MEDIUM)"
    - "Base pools bricked (Sherlock) — base pools can get bricked if depositors pull out (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, strategy, dos, cascade, pause, plugin, withdrawal-limit]

- id: vault-018
  pattern: vault-totalassets-desync
  name: "totalAssets desyncs from actual balance due to untracked flows"
  causa_raiz: >
    The vault's totalAssets() or internal accounting variable (yIntercept, slope,
    totalLend, idleETH, etc.) diverges from the actual token balance because
    certain fund flows are not properly tracked. This includes: partial auction
    payments not decrementing yIntercept, ETH returned to pool without updating
    idleETH, fee calculations not updating reserves, or strategy rebalancing
    not syncing balances. The desync causes incorrect share pricing.
  como_funciona: |
    1. Vault tracks totalAssets via internal variable (not balanceOf)
    2. An operation moves funds but fails to update the tracking variable
       (e.g., auction pays partial amount, yIntercept not decremented)
    3. totalAssets() now returns an inflated or deflated value
    4. Share price = totalAssets / totalSupply is wrong
    5. New depositors get too many or too few shares
    6. Existing holders can extract value on the discrepancy
  invariante: |
    // Internal tracking must stay in sync with actual balances
    assert(vault.totalAssets() == asset.balanceOf(vault) + vault.totalDeployed() - vault.pendingFees());
  que_mirar:
    - "yIntercept, slope, or similar accounting not updated in all code paths"
    - "totalLend or totalBorrow not adjusted on fee/interest operations"
    - "idleETH not updated when ETH is returned via non-standard path"
    - "setPayee() or transferLien() not updating vault's accounting parameters"
    - "bringUnusedETHBack or restoreVault not updating idle tracking"
    - "depositedBase decremented incorrectly in yield phases"
  como_se_arregla: "Audit every code path that moves tokens to/from the vault and ensure the accounting variable is updated. Use a single source of truth. Consider using balanceOf as a sanity check against internal accounting."
  trampas:
    - "Vaults using pure balanceOf for totalAssets have the opposite problem (donation vulnerability)"
    - "Small discrepancies from rounding are expected and acceptable"
  incidentes:
    - "Astaria (Spearbit) — yIntercept not updated on partial Seaport auction payment (HIGH)"
    - "Astaria (Spearbit) — WithdrawProxy.claim() updates yIntercept incorrectly (HIGH)"
    - "Astaria (Spearbit) — setPayee doesn't update yIntercept/slope, vault owner can inflate totalAssets (HIGH)"
    - "Astaria (Spearbit) — buyoutLien doesn't update new vault's slope/yIntercept (HIGH)"
    - "Stakehouse (Code4rena) — bringUnusedETHBackIntoGiantPool doesn't increment idleETH (HIGH)"
    - "Timeless (Spearbit) — xPYT auto-compound doesn't subtract pounder reward from assetBalance (HIGH)"
    - "Elytra (Pashov) — TVL double-counts assets returned from strategy; receiveFromDepositPool doesn't track assets (HIGH)"
    - "Tenbin — direct vault deposits counted as revenue leading to liquidity drain (HIGH)"
    - "Tenbin — revenue accounting ignores losses, revenue drifts on outflows (HIGH/MEDIUM)"
    - "Morpho Vaults v2 (Spearbit) — share to asset exchange rate skewed when totalSupply=0 and totalAssets!=0 (MEDIUM)"
    - "Incorrect accounting yDUSD (Code4rena) — incorrect accounting bug of yDUSD vault leads to total loss of depositors DUSD assets (HIGH)"
    - "Omo (Pashov) — funds not always in vault lead to share price calculation mess (MEDIUM)"
    - "operatorFeeAmount (Code4rena) — totalAssets calculation wrong if operatorFeeAmount>0, loss for new depositors (HIGH)"
    - "Inflated totalAssets (Code4rena) — inflated totalAssets in StrategyMainnet/StrategyArb/StrategyOp contracts (MEDIUM)"
    - "Zaros (Code4rena) — multiple instances where vault totalAssets not properly scaled to ZAROS precision (HIGH)"
    - "borrow decreases totalAssets (Pashov) — borrow should decrease totalAssets value (CRITICAL)"
    - "Inconsistent balance tracking (Pashov) — inconsistent balance tracking in vault creates DoS for asset borrowing (HIGH)"
    - "Fee-vault insolvency (Cyfrin) — fee-vault can be made insolvent in case of defaults (MEDIUM)"
    - "Risk of overreporting assets (Code4rena) — vault accounting inconsistency if harvester calls delegator functions directly (MEDIUM)"
    - "Market-vault disconnection (Sherlock) — market-vault disconnection brings permanent inconsistent state (HIGH)"
    - "vaultUtilization (Code4rena) — vaultUtilization is updated incorrectly (MEDIUM)"
    - "LendingAssetVault (Sherlock) — incorrectly updates vaultUtilization if CBR for single FraxlendPair decreases (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, totalAssets, accounting, desync, yIntercept, slope, internal-tracking]

- id: vault-019
  pattern: yield-claim-theft-via-balance-sweep
  name: "Yield/reward theft by claiming full contract balance"
  causa_raiz: >
    A vault function sends the ENTIRE token balance of the contract to the
    caller (asset.balanceOf(address(this))), rather than only the caller's
    proportional share. When combined with operations that accumulate
    unclaimed yield or rewards in the contract, a single caller can steal
    all accumulated yield belonging to other users.
  como_funciona: |
    1. Vault holds pooled yield/rewards for multiple users in its balance
    2. User calls eject(), claim(), or withdraw() which internally claims all accumulated yield
    3. Function sends asset.balanceOf(address(this)) to the caller
    4. Caller receives their share PLUS all other users' unclaimed yield
    5. Other users can no longer claim their yield
  invariante: |
    // A user's withdrawal must never exceed their proportional share
    uint256 userShare = vault.balanceOf(user) * vault.totalAssets() / vault.totalSupply();
    assert(amountSent <= userShare + DUST_TOLERANCE);
  que_mirar:
    - "asset.transfer(receiver, asset.balanceOf(address(this)))"
    - "Functions that claim yield for ALL holders but send to single caller"
    - "combine() or claimYield() called inside withdraw/redeem that aggregates"
    - "No separation between user's principal and pooled yield"
  como_se_arregla: "Never send balanceOf(this) as the withdrawal amount. Track each user's yield separately. If combining operations (redeem + claim), only send the user's proportional share of both."
  trampas:
    - "If the vault has only one user, this is not exploitable"
    - "Functions that sweep excess tokens to treasury are intentional, not a bug"
  incidentes:
    - "Sense (Sherlock) — AutoRoller#eject sends entire target balance including all users' YT yield to single caller (HIGH)"
    - "Cork Protocol (Sherlock) — users steal excess funds from vault due to redeem not decreasing raBalance and withdrawalPool (HIGH)"
    - "Cork Protocol (Sherlock) — attackers steal reserve from vault by receiving ra in FlashSwapRouter (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, yield, theft, balanceOf, sweep, claim, proportional]

- id: vault-020
  pattern: settlement-fee-double-subtraction
  name: "Settlement/management fee applied asymmetrically between global and local accounting"
  causa_raiz: >
    When a vault processes multiple users' deposits and redeems in the same
    epoch/oracle version, settlement fees or management fees are shared among
    all orders. However, the global state subtracts the fee once for deposits
    AND once for redeems (double subtraction), while the local (per-user) state
    correctly prorates the fee across all orders. This mismatch means users
    get more shares/assets locally than the vault tracks globally, leading to
    insolvency where the last user cannot redeem.
  como_funciona: |
    1. SettlementFee = $10, User1 deposits $10, User2 redeems $10 in same epoch
    2. Global: deposits converted with full fee deducted -> 0 shares; redeems also -> 0 assets
    3. Local: fee split across 2 orders -> each user pays $5 fee
    4. User1 gets 5 shares locally, User2 gets $5 locally
    5. Global says 0 shares added, 0 assets returned
    6. Local says 5 shares added, $5 returned -> accounting mismatch grows over time
    7. Eventually global underflow prevents last users from redeeming
  invariante: |
    // Sum of all local share changes must equal global share change
    assert(sumLocalSharesAdded == globalSharesAdded);
    assert(sumLocalAssetsReturned == globalAssetsReturned);
  que_mirar:
    - "_withoutSettlementFeeGlobal vs _withoutSettlementFeeLocal"
    - "Settlement fee subtracted in full for both deposit and redeem paths globally"
    - "Fee prorated by checkpoint.orders locally but not globally"
    - "Management fee calculated differently for global vs per-user state"
  como_se_arregla: "Weight the global settlement fee by the ratio of deposits vs redeems in the same epoch. Ensure global and local fee calculations are symmetric."
  trampas:
    - "If deposits and redeems never happen in the same epoch, the bug doesn't manifest"
    - "Small fee amounts may cause the discrepancy to grow slowly"
  incidentes:
    - "Perennial V2 Update #2 (Sherlock) — _withoutSettlementFeeGlobal subtracts fee twice, local only once, systematic share/asset inflation (HIGH)"
    - "Vault.settle coordinator (Code4rena) — Vault.settle(account=coordinator) will lose profitShares (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, settlement-fee, global-local, accounting-mismatch, epoch, insolvency]

- id: vault-021
  pattern: vault-access-control-missing
  name: "Critical vault functions missing access control or input validation"
  causa_raiz: >
    Vault functions that should be restricted (fee minting, strategy management,
    migration, payee changes) are either publicly callable or accept user-supplied
    addresses without validation. Common patterns: mintYieldFee() lets anyone
    specify the recipient, commitToLien() doesn't verify the vault is registered,
    withdrawFromGauge() lets anyone burn and claim deposits, or the periphery
    contract exposes unrestricted proxy-withdraw capability.
  como_funciona: |
    1. Attacker identifies a vault function without proper access control
    2. For fee theft: calls mintYieldFee(yieldAmount, attackerAddress) to mint yield shares to themselves
    3. For vault spoofing: creates fake vault, passes it to commitToLien, drains real vault
    4. For deposit theft: calls withdrawFromGauge with victim's NFT ID, receives their tokens
    5. For periphery theft: calls withdrawToken(victimAddress, ..., attackerAddress) exploiting approval
  invariante: |
    // Only authorized addresses can call privileged functions
    // Fee recipient must match the configured _yieldFeeRecipient
    // Vault addresses must be verified against registry
  que_mirar:
    - "external/public functions without onlyOwner, onlyManager, or similar modifier"
    - "mintYieldFee with user-supplied _recipient parameter"
    - "Vault address not checked against isValidVault()"
    - "withdrawFromGauge public without msg.sender == nft.owner check"
    - "Periphery withdraw/redeem where 'from' is user-supplied, not msg.sender"
  como_se_arregla: "Add access control modifiers. Use msg.sender as the source of funds (not a user-supplied 'from' parameter). Validate vault addresses against a registry. For fee functions, use the configured recipient, not a parameter."
  trampas:
    - "Some functions are intentionally permissionless (e.g., liquidation, public harvest)"
    - "Operator/approved patterns intentionally allow third-party calls"
  incidentes:
    - "PoolTogether (Code4rena) — mintYieldFee callable by anyone with arbitrary recipient (HIGH)"
    - "Astaria (Spearbit) — commitToLien doesn't check vault is registered, allows draining via fake vault (CRITICAL)"
    - "Isomorph (Sherlock) — anyone can withdraw user's Velo Deposit NFT after approval (HIGH)"
    - "Rage Trade (Sherlock) — WithdrawPeriphery lets anyone withdraw/redeem another user's approved tokens (HIGH)"
    - "Stakehouse (Code4rena) — giant pools drained via fake vault passing weak authenticity check (HIGH)"
    - "Balancer v3 (Spearbit) — lack of approval reset on buffer allows anyone to drain the vault (HIGH)"
    - "Balancer v3 (Spearbit) — vault can be drained by updating the buffer underlying token (HIGH)"
    - "VaultRouter (Code4rena) — malicious actors exploit user-approved allowances on VaultRouter to drain ERC4626 tokens (HIGH)"
    - "Malicious vault creation (Code4rena) — call to non-existent contract allows malicious vault creation (HIGH)"
    - "ArrakisMetaVault (Code4rena) — malicious executor drains vault by calling withdraw after initializePosition (HIGH)"
    - "ArrakisMetaVault (Code4rena) — executor drains 100% of vault reserves via rebalance minting cheap shares (HIGH)"
    - "Anyone can change balance (Code4rena) — anyone can change account balance to drain entire portfolio vault (HIGH)"
    - "Withdraw fee to user (Code4rena) — withdraw fee transferred to user instead of fee vault (HIGH)"
    - "Unvalidated parameters (Code4rena) — unvalidated variable parameters allow fee manipulation (HIGH)"
    - "GORPLES (Code4rena) — any account can mint infinite amount of tokens to any compatible vault (HIGH)"
    - "Security level bypass (Cyfrin) — security level constraint can be circumvented (HIGH)"
    - "Non-whitelisted shares (Code4rena) — non-whitelisted users can mint vault shares with permissioned tokens through bundler (MEDIUM)"
  severidad: critical
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, access-control, authorization, fee-theft, vault-spoofing, periphery]

- id: vault-022
  pattern: stored-total-assets-underflow-dos
  name: "storedTotalAssets underflow blocks withdrawals during reward cycle"
  causa_raiz: >
    Vaults using the xERC4626 streaming rewards pattern track storedTotalAssets
    separately from actual balance. storedTotalAssets only includes unlocked
    rewards at cycle end, but totalAssets() (used for share pricing) includes
    linearly unlocked rewards mid-cycle. When a user withdraws mid-cycle,
    beforeWithdraw decrements storedTotalAssets by the withdrawal amount,
    which may include unlocked rewards not yet in storedTotalAssets. This
    causes an underflow revert, blocking all withdrawals until the cycle ends.
  como_funciona: |
    1. Alice deposits 100 tokens. storedTotalAssets = 100
    2. Owner sends 100 reward tokens, calls syncRewards(). lastRewardAmount = 100
    3. Mid-cycle: totalAssets() = 100 + 50 (linear unlock) = 150
    4. Alice's shares worth 150 tokens (per convertToAssets)
    5. Alice redeems all shares -> beforeWithdraw(150) tries storedTotalAssets -= 150
    6. storedTotalAssets is still 100 -> underflow revert
    7. Nobody can withdraw until rewards cycle completes
  invariante: |
    // storedTotalAssets must be >= totalAssets() at all times
    // OR: beforeWithdraw must use min(amount, storedTotalAssets)
  que_mirar:
    - "storedTotalAssets -= amount in beforeWithdraw hook"
    - "totalAssets() includes linearly unlocked rewards but storedTotalAssets doesn't"
    - "syncRewards() only callable after rewardsCycleEnd"
    - "Long rewardsCycleLength (14+ days) amplifies the window"
  como_se_arregla: "Call syncRewards (without revert) before every deposit/withdraw to keep storedTotalAssets current. Or cap the decrement to min(amount, storedTotalAssets). Or use actual balance instead of storedTotalAssets for the decrement."
  trampas:
    - "If no rewards have been distributed, storedTotalAssets == totalAssets, no issue"
    - "Very short reward cycles (<1 day) minimize the exposure window"
  incidentes:
    - "Tribe (Code4rena) — xERC4626.sol storedTotalAssets underflow blocks all withdrawals during reward cycle (MEDIUM)"
    - "GoGoPool (Code4rena) — maxWithdraw/maxRedeem return values exceeding storedTotalAssets (MEDIUM)"
    - "Multipli Vault (Pashov) — underflow bug in addFundsAndFulfillRedeem prevents redemption of initial deposits (MEDIUM)"
    - "Negative credit capacity (Code4rena) — negative credit capacity handling causes complete vault lockout when underwater (MEDIUM)"
    - "CONTRACT DoS (Code4rena) — contract denial of service due to integer underflow (HIGH)"
    - "Deadlock (Code4rena) — withdrawing all liquidity before borrowing can deadlock contract (HIGH)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, xERC4626, storedTotalAssets, underflow, rewards, dos, withdrawal]

- id: vault-023
  pattern: decimal-mismatch-in-vault-operations
  name: "Decimal mismatch between vault, asset, or strategy causes inflated/deflated amounts"
  causa_raiz: >
    When vault operations pass amounts between components with different decimal
    expectations (e.g., vault uses 18 decimals, underlying USDC uses 6 decimals,
    perp protocol returns 18-decimal amounts), failing to convert between decimal
    scales causes amounts to be inflated by 10^12 or deflated by 10^12.
    This leads to vault.deposit/withdraw using massively wrong amounts.
  como_funciona: |
    1. Perp protocol returns baseAmount in 18 decimals (e.g., 1e18 = 1 token)
    2. Vault calls vault.withdraw(assetToken, baseAmount) with the raw 18-decimal value
    3. Asset token (USDC) has 6 decimals, so the vault tries to withdraw 1e18 USDC = 1 trillion USDC
    4. Transaction either reverts (if vault doesn't have that much) or massively over-withdraws
  invariante: |
    // All amounts passed to external functions must be in the target's native decimals
    // assert(amountToDeposit <= 10 ** asset.decimals() * MAX_REASONABLE_AMOUNT)
  que_mirar:
    - "vault.deposit(token, amount) where amount comes from 18-decimal source but token has 6 decimals"
    - "_normalizeDecimals applied inconsistently"
    - "Missing decimals conversion between perp protocol and vault"
    - "ERC4626 decimals() != underlying asset decimals()"
  como_se_arregla: "Always convert amounts to the target token's decimals before passing to external functions. Create explicit conversion helpers and use them consistently."
  trampas:
    - "Tokens with 18 decimals (DAI, WETH) don't trigger this bug"
    - "If all tokens in the system share the same decimals, no conversion needed"
  incidentes:
    - "UXD Protocol (Sherlock) — deposit/withdraw to vault with wrong decimals in PerpDepository (MEDIUM)"
    - "yAxis (Code4rena) — balance() mixes normalized and non-normalized amounts (HIGH)"
    - "Sentiment (Sherlock) — ERC4626Oracle wrong when vault decimals != asset decimals (HIGH)"
    - "AFI Vault (Pashov) — flawed decimal conversion logic understates share amount for non-18-decimal assets (MEDIUM)"
    - "Burve (Sherlock) — incorrect implementation of ERC4626ViewAdjustor, toNominal/toReal reversed (HIGH)"
    - "Multiple decimal conversion issues (Code4rena) — multiple issues with decimal conversions between vault and strategy (HIGH)"
    - "Incorrect decimals for vault token (Code4rena) — incorrect decimals for the vault token (MEDIUM)"
    - "LenderCommitmentGroup (Sherlock) — pools have incorrect exchange rate when fee-on-transfer tokens used due to decimal assumptions (MEDIUM)"
    - "Vault overflow (Code4rena) — Vault._calcDeposit() will overflow for low priced tokens due to decimal handling (MEDIUM)"
    - "ExternalFee (Spearbit) — ExternalFee contract treats newly deposited vault shares as yield, charges performance fee on deposit immediately due to share/asset decimal confusion (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, decimals, normalization, usdc, conversion, precision]

- id: vault-024
  pattern: async-redeem-liquidity-reservation-gap
  name: "Async redemption queue does not reserve liquidity, causing insolvency"
  causa_raiz: >
    Vaults implementing asynchronous redemption (ERC-7540 or custom queues) have
    multiple fulfillment paths: queue-based processing, manual/instant fulfillment,
    and direct requestRedeem. When some paths mark shares as claimable without
    incrementing a reservedLiquidity counter, multiple fulfillments can each pass
    the liquidity check independently. The result is sum(claimable assets) exceeds
    vault.totalAssets() - reservedLiquidity, making the vault insolvent for late
    claimers. A related variant allows inflating totalRedemption by submitting
    the same shares under different operator addresses without validation.
  como_funciona: |
    1. Vault has two fulfillment paths: queue processor (increments reservedLiquidity) and manual/instant (does not)
    2. Alice requests redeem via queue -> processed -> reservedLiquidity += aliceAssets
    3. Bob requests redeem via instant/manual path -> shares marked claimable, but reservedLiquidity NOT incremented
    4. Charlie requests via manual path -> also passes liquidity check (Bob's claim not reserved)
    5. sum(Alice + Bob + Charlie claimable) > vault.totalAssets()
    6. Last claimer's transaction reverts — funds are effectively stolen by earlier claimers
  invariante: |
    // Sum of all claimable assets must never exceed available liquidity
    assert(totalClaimableAssets <= vault.totalAssets());
    // reservedLiquidity must account for ALL fulfilled requests, regardless of path
  que_mirar:
    - "Multiple fulfillment paths: processUpTo*, fulfillRedeemRequest, instant requestRedeem"
    - "reservedLiquidity only incremented in some code paths"
    - "requestRedeem operator parameter not validated against prior requests"
    - "req.totalRedemption inflated by submitting same shares with different operators"
    - "ERC-7540 vaults with partial redemption at different share prices"
  como_se_arregla: "Increment reservedLiquidity in ALL fulfillment paths. Validate that operator+owner combination is unique per request. Check available liquidity = totalAssets - reservedLiquidity before every fulfillment."
  trampas:
    - "Vaults with only one fulfillment path (queue only) are not affected"
    - "If instant redemption is disabled, the gap does not exist"
  incidentes:
    - "Accountable (Cyfrin) — manual fulfillRedeemRequest doesn't reserve liquidity, causing over-commitment (MEDIUM)"
    - "Accountable (Cyfrin) — fulfillRedeemRequest ignores processingMode, uses currentPrice instead of request-time price (HIGH)"
    - "Astrolab (Pashov) — requestRedeem inflates totalRedemption via unvalidated operator param, DoS entire vault (CRITICAL)"
    - "Harmonixfinance (Pashov) — withdrawal mechanism fails when share price declines between initiation and execution (MEDIUM)"
    - "Harmonixfinance (Pashov) — withdrawal initiators lose value when share price increases before execution (MEDIUM)"
    - "Vaultcraft — misconfigured bounds in async vault cause underpayment during redeem fulfillment (MEDIUM)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, erc7540, async-redeem, redemption-queue, liquidity-reservation, insolvency]

- id: vault-025
  pattern: pending-withdrawal-inflates-share-price
  name: "Pending withdrawals not excluded from totalAssets inflates share price"
  causa_raiz: >
    When a vault processes redemption in two steps (request -> fulfill/claim), the
    assets earmarked for pending withdrawals remain in the vault's balance and are
    counted in totalAssets(). However, the corresponding shares are either burned
    or locked (transferred to vault). This creates a mismatch: totalAssets includes
    assets already owed to withdrawers, but totalSupply has decreased. The inflated
    share price causes new depositors to receive fewer shares, and any profit/loss
    that occurs between request and fulfillment is misattributed. When withdrawals
    are finalized, the share price corrects, harming depositors who entered during
    the inflated period.
  como_funciona: |
    1. User A requests redeem of 100 shares -> shares burned/locked, but 100 assets remain in vault
    2. totalAssets still includes the 100 assets; totalSupply decreased by 100 shares
    3. Share price = totalAssets / totalSupply is now inflated
    4. User B deposits during this period -> receives fewer shares than fair value
    5. When User A's withdrawal is finalized, share price corrects downward
    6. User B's position is now worth less than deposited
  invariante: |
    // totalAssets used for share pricing must exclude pending withdrawal amounts
    uint256 effectiveTotalAssets = vault.totalAssets() - vault.pendingWithdrawalAmount();
    uint256 pricePerShare = effectiveTotalAssets * 1e18 / vault.totalSupply();
    // pricePerShare must not change due to pending withdrawal creation
  que_mirar:
    - "totalAssets() includes balanceOf(this) without subtracting pendingWithdrawals"
    - "Shares burned on requestRedeem but assets not moved to escrow"
    - "_pendingWithdrawalAmount not subtracted in getTotalDeposited() or totalAssets()"
    - "Two-step withdrawal where assets stay in vault between request and claim"
    - "ethWithdrawn/stableWithdrawn counters not updated on withdrawal processing"
  como_se_arregla: "Subtract pending withdrawal amounts from totalAssets() when calculating share price. Move assets to a separate escrow contract on request. Track withdrawal counters and shares accurately on every withdrawal."
  trampas:
    - "Vaults with instant atomic withdrawals are not affected"
    - "If assets are moved to escrow immediately on request, the issue does not apply"
  incidentes:
    - "YuzuUSD (Pashov) — pending withdrawals in YuzuILP not considered in totalAssets (HIGH)"
    - "Nexus (Pashov) — ethWithdrawn/stableWithdrawn and shares not updated on withdrawal, share price includes withdrawn portion (CRITICAL)"
    - "Omo (Pashov) — pending withdrawal tokens in redeem() still counted in share price (HIGH)"
    - "Tagus v2 — _pendingWithdrawalAmount can be arbitrarily reset, inflating getTotalDeposited (HIGH)"
    - "Saffron Lido (Sherlock) — totalEarnings incorrect when withdrawing after ending, vault insolvent (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, pending-withdrawal, totalAssets, share-price, two-step-withdrawal, escrow]

- id: vault-026
  pattern: fee-retained-in-pool-inflates-remaining-shares
  name: "Withdrawal/redemption fees remain in pool, inflating share price for remaining holders"
  causa_raiz: >
    When a vault charges a fee on withdrawal or redemption, the fee is deducted from
    the assets returned to the user. However, the fee amount stays in the vault's
    poolSize/totalAssets without being separated into a fee reserve. Since the
    withdrawer's shares are burned but the fee's worth of assets remains, the
    effective share price increases for remaining holders. This creates a systematic
    fee avoidance vector: later redeemers benefit from accumulated fees of earlier
    redeemers, reducing their effective fee rate. The first withdrawers subsidize
    the last withdrawers. Attackers can also use this to avoid fees entirely by
    depositing right before a large redemption and withdrawing right after.
  como_funciona: |
    1. Vault has 1000 assets, 1000 shares (price = 1.0), 5% withdrawal fee
    2. User A redeems 500 shares -> receives 475 assets, 25 assets (fee) stays in vault
    3. Vault now has 525 assets, 500 shares -> price = 1.05
    4. User B redeems 500 shares -> receives 525 * 0.95 = 498.75 assets
    5. User B's effective fee was (525 - 498.75) / 525 = 5%, but they got an extra 23.75 from A's fee
    6. Attacker variant: deposit before large redemption, withdraw after to capture fee windfall
  invariante: |
    // Fee amount must be transferred to feeRecipient or separated from pool
    assert(feeReserve == cumulativeFeesCollected);
    // Remaining shares should not appreciate from fee collection
  que_mirar:
    - "Fee deducted from user but not transferred to feeRecipient in same tx"
    - "poolSize or totalAssets not decremented by fee amount on withdrawal"
    - "Fee remains in contract balance, inflating totalAssets for remaining shares"
    - "No separate feeReserve or pendingFees tracking"
    - "Performance fee calculated on totalAssets that includes uncollected withdrawal fees"
  como_se_arregla: "Transfer fees to feeRecipient immediately on withdrawal. Or track fees in a separate feeReserve that is excluded from totalAssets(). Ensure poolSize is decremented by the full pre-fee amount (not just the post-fee amount sent to user)."
  trampas:
    - "If fees are minted as shares to feeRecipient, the dilution is correct and this is not a bug"
    - "Very small fee rates (<0.1%) make the exploitation economically negligible"
  incidentes:
    - "YuzuUSD (Pashov) — fees in YuzuILP._withdraw and StakedYuzuUSD._initiateRedeem remain in poolSize, enabling fee avoidance (HIGH)"
    - "Mellow Flexible Vaults (Sherlock) — redeems through RedeemQueue avoid paying management and performance fee by burning shares before fee accrual (HIGH)"
    - "Mellow Flexible Vaults (Sherlock) — incorrect performance fee calculation uses wrong formula for price-to-share conversion (HIGH)"
    - "Terplayer (Pashov) — mint/redeem fees deducted but never transferred to treasury, protocol loses all revenue (CRITICAL)"
    - "Tokemak (Spearbit) — streaming fee calculated on totalAssets instead of profit, excessive fee share minting (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, withdrawal-fee, fee-avoidance, poolSize, totalAssets, fee-reserve, performance-fee]

- id: vault-027
  pattern: rehypothecation-dos-via-flashloan
  name: "Vault rehypothecation DoS via flashloan draining underlying"
  causa_raiz: >
    When a lending protocol's aToken (or similar receipt token) uses an ERC4626 vault
    for idle fund yield, the vault rebalances during deposit/withdraw by pulling from
    or depositing to the vault. During a flashloan, the underlying tokens are
    temporarily transferred out. If the vault's balance check happens during the
    flashloan (before repayment), the vault sees insufficient assets and the
    rebalancing reverts. An attacker can exploit this to permanently DoS all vault
    deposits and withdrawals by taking flashloans every block, or trigger a
    permanent DoS by causing the vault to enter a stuck state.
  como_funciona: |
    1. Lending pool's aToken deposits idle funds into ERC4626 vault for yield (rehypothecation)
    2. On any deposit/withdraw, aToken calls _rebalance() which may withdraw from vault
    3. Attacker takes flashloan of the underlying asset from the same pool
    4. During flashloan, aToken.transferUnderlyingTo() calls _rebalance() -> tries to withdraw from vault
    5. Vault has no assets (they're out via flashloan) -> revert
    6. All user deposits/withdrawals to the pool are blocked during the flashloan
    7. Attacker repeats every block to create persistent DoS
  invariante: |
    // Vault operations must not be blockable by flashloan-induced temporary balance changes
    // _rebalance should handle the case where vault balance is temporarily zero
  que_mirar:
    - "_rebalance() called inside transferUnderlyingTo() during flashloan path"
    - "Vault withdrawal attempted when balance is temporarily zero due to flashloan"
    - "No try/catch around vault interaction in rebalance"
    - "Flash loan and deposit/withdraw sharing same underlying pool and vault"
  como_se_arregla: "Use try/catch for vault interactions during rebalance. Skip vault withdrawal if balance is temporarily insufficient. Separate flashloan liquidity from vault-deposited liquidity."
  trampas:
    - "If the protocol does not support flashloans, this vector does not exist"
    - "If vault deposits are in a separate contract from lending pool, rebalance is isolated"
  incidentes:
    - "Astera (Spearbit) — DoSing vault rehypothecation through flashloans on AToken (HIGH)"
    - "Cod3x Lend (Spearbit) — identical AToken rehypothecation DoS via flashloan (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, rehypothecation, flashloan, dos, rebalance, atoken, lending]

- id: vault-028
  pattern: cross-vault-agent-misattribution
  name: "Shared agent/account attributes all positions to every connected vault"
  causa_raiz: >
    When multiple vaults share a common agent/account that deploys capital (e.g., a
    DeFi agent executing strategies), each vault's totalAssets() sums up ALL
    positions held by the shared agent, not just positions funded by that specific
    vault. This double/triple-counts the same capital across multiple vaults,
    inflating each vault's totalAssets and share price. Additionally, a malicious
    agent registered to a vault can deploy a reverting oracle or invalid contract,
    causing totalAssets() to revert and permanently bricking the vault.
  como_funciona: |
    1. Vault A lends 100 USDC to shared Agent, Vault B lends 200 USDC to same Agent
    2. Agent deploys all 300 USDC into a single LP position
    3. Vault A.totalAssets() iterates over Agent's positions -> sees 300 USDC LP position -> reports 300
    4. Vault B.totalAssets() also sees the same 300 USDC LP position -> reports 300
    5. Combined reported totalAssets = 600, but actual assets = 300
    6. Depositors into either vault receive shares at inflated price
    7. Variant: malicious agent registers with reverting oracle, totalAssets() reverts forever -> vault bricked
  invariante: |
    // Each vault's totalAssets must only include positions funded by that vault
    assert(vaultA.totalAssets() + vaultB.totalAssets() <= totalActualAssets + tolerance);
    // totalAssets() must not revert due to any single agent's state
  que_mirar:
    - "totalAssets() iterating over shared accounts/agents without per-vault attribution"
    - "No tracking of which vault funded which position in the shared agent"
    - "Whitelisted user can register an agent that causes totalAssets() to revert"
    - "accountList iterated in totalAssets() includes agents from multiple vaults"
  como_se_arregla: "Track per-vault funding in the agent: each position must be tagged with the source vault. Use try/catch when querying agent positions. Require vault-owner approval for agent registration."
  trampas:
    - "Single-vault agents with no shared accounts are not affected"
    - "If all agents are trusted/permissioned, the DoS variant requires admin compromise"
  incidentes:
    - "Omo (Pashov) — cross-vault misattribution in OmoAgent leads to incorrect vault valuation, all agent positions counted by every vault (HIGH)"
    - "Omo (Pashov) — malicious account with invalid oracle permanently disables vault via totalAssets revert (HIGH)"
    - "Suzaku Core — vault rewards incorrectly scaled by cross-asset-class operator totals instead of asset-class-specific shares (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, cross-vault, agent, misattribution, totalAssets, double-counting, dos]

- id: vault-029
  pattern: read-only-reentrancy-vault-state
  name: "Read-only reentrancy exposes stale vault share state to external protocols"
  causa_raiz: >
    During a vault's withdraw or deposit operation, an external call to a strategy
    or token contract occurs BEFORE internal state (totalAssets, totalSupply,
    balances) is updated. While the vault itself is protected by nonReentrant,
    external protocols that read the vault's state (share price, totalAssets,
    balanceOf) during the callback window see stale values. If those protocols
    use the stale vault state for pricing, collateral valuation, or liquidation
    decisions, they make incorrect decisions. This is a cross-protocol read-only
    reentrancy attack.
  como_funciona: |
    1. Attacker calls vault.withdraw() which triggers strategy.withdraw() external call
    2. During strategy.withdraw(), a callback or intermediate state exists
    3. Vault's nonReentrant prevents re-calling vault functions
    4. But external protocol (e.g., lending market) reads vault.convertToAssets() during callback
    5. Value is stale (pre-withdrawal), making attacker's collateral appear more valuable
    6. Attacker borrows against inflated collateral value in the lending market
    7. After vault.withdraw() completes, state updates -> collateral value drops -> bad debt
  invariante: |
    // Vault state must be consistent before any external call
    // External reads of vault state during operations must return post-operation values
  que_mirar:
    - "External call (strategy.withdraw, token.transfer) before state update in vault"
    - "nonReentrant on vault but state updates AFTER external call"
    - "Vault shares used as collateral in lending protocols"
    - "convertToAssets() or totalAssets() readable during mid-operation callback"
    - "Balancer-style read-only reentrancy pattern"
  como_se_arregla: "Update all internal state BEFORE making external calls (checks-effects-interactions). Use a reentrancy guard that also prevents view function reads during operations. Add a grace period or snapshot mechanism for external price queries."
  trampas:
    - "If no external protocol uses the vault's share price as an oracle, this has no impact"
    - "If state updates happen before the external call, no stale window exists"
    - "Vault-only nonReentrant is NOT sufficient — the vulnerability is cross-protocol"
  incidentes:
    - "Balmy (Spearbit) — potential read-only reentrancy pattern in Earn-Vault withdraw, state updated after strategy.withdraw external call (MEDIUM)"
    - "Sentiment V2 (Sherlock) — non-liquidateable positions created by exploiting rebalanceBadDebt to decrease share price, read by lending protocol (MEDIUM)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [vault, read-only-reentrancy, cross-protocol, stale-state, collateral, pricing]

- id: vault-030
  pattern: cooldown-yield-accrual-bypass
  name: "Cooldown period bypassed because yield accrues on shares during withdrawal process"
  causa_raiz: >
    Vaults with a cooldown/unstaking period record the number of shares at initiation
    time but redeem them at the current (higher) share price at execution time. The
    shares continue earning yield during the entire cooldown period, even though
    they are conceptually "in transit." This means users get yield for the cooldown
    period risk-free (they've already decided to leave). An attacker can game this
    by entering the vault, immediately initiating cooldown, waiting for cooldown to
    pass while earning yield, then unstaking at a profit. The cooldown is meant to
    prevent exactly this kind of short-term yield extraction.
  como_funciona: |
    1. Vault has cooldownDuration = 7 days, current share price = 1.0
    2. Attacker deposits large amount, receives shares
    3. Attacker immediately calls cooldownShares() -> records shares to withdraw
    4. During 7-day cooldown, yield accrues, share price increases to 1.01
    5. After cooldown, attacker calls unstake() -> shares redeemed at 1.01 price
    6. Attacker extracts 1% yield for 7 days of risk-free holding
    7. Repeat: deposit -> cooldown -> unstake cycle for continuous yield farming
  invariante: |
    // Shares in cooldown should not earn yield, OR
    // Withdrawal amount should be fixed at cooldown-initiation share price
    uint256 cooldownAssets = cooldowns[user].underlyingShares * priceAtCooldownStart;
    assert(withdrawnAssets <= cooldownAssets);
  que_mirar:
    - "cooldowns[owner].underlyingShares stores share count, redeemed at current price"
    - "No snapshot of share price at cooldown initiation"
    - "Shares continue accruing yield/interest during cooldown period"
    - "unstake() uses current convertToAssets instead of cooldown-time rate"
    - "VoteModule or staking lock that can be bypassed by timing around epoch boundaries"
  como_se_arregla: "Snapshot the share price at cooldown initiation and use that for redemption. Or convert shares to assets immediately on cooldown and hold assets (not shares) in escrow. Alternatively, exclude cooldown shares from yield distribution."
  trampas:
    - "If cooldown period is very short (<1 day), yield accrual is negligible"
    - "If share price is fixed (1:1), there is no yield to capture"
  incidentes:
    - "Level (Spearbit) — cooldown period bypassed as users gain yield during withdrawal process in StakedlvlUSD (MEDIUM)"
    - "Etherex (Spearbit) — VoteModule unlockTime can be bypassed by depositing before epoch flip and withdrawing before lock is set (LOW)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [vault, cooldown, unstaking, yield-accrual, bypass, share-price, epoch]

- id: vault-031
  pattern: vault-self-deposit-circular-inflation
  name: "Vault deposits into itself creating circular unit inflation"
  causa_raiz: >
    When a vault's provisioner or strategy mechanism allows arbitrary deposit/mint
    calls without restricting the target, the vault can be made to deposit into
    itself. This creates circular accounting: the vault mints new shares to itself
    backed by tokens it already controls, inflating totalSupply and totalAssets
    in a loop. The shares become unbacked as the vault's "assets" are just its
    own share tokens. On redemption, the circular backing unravels and the vault
    becomes insolvent.
  como_funciona: |
    1. Vault has 1000 real assets, 1000 shares
    2. Provisioner/executor calls vault.deposit(vault, 500) -> vault deposits 500 into itself
    3. Vault mints 500 new shares to itself, now holds 500 of its own shares as "assets"
    4. totalAssets appears to be 1500 (1000 real + 500 circular), totalSupply = 1500
    5. Share price appears unchanged but 500 shares are backed by vault's own shares, not real assets
    6. External user redeems -> vault tries to liquidate its own shares -> recursive unwinding
    7. Vault becomes insolvent as circular shares have no real backing
  invariante: |
    // Vault must never hold its own shares as assets
    assert(vault.balanceOf(address(vault)) == 0 || vault_shares_excluded_from_totalAssets);
    // Deposit target must not be self
  que_mirar:
    - "Provisioner or strategy allows arbitrary deposit/mint target addresses"
    - "No check preventing vault.deposit(address(vault), ...)"
    - "Vault balance includes its own share tokens in totalAssets"
    - "requestDeposit or mint callable with vault address as receiver"
  como_se_arregla: "Add explicit check: require(target != address(this)) in all deposit/mint paths. Exclude vault's own shares from totalAssets calculation. Restrict provisioner's deposit targets to a whitelist."
  trampas:
    - "If deposit target is always msg.sender or hardcoded, self-deposit is impossible"
    - "If vault shares are ERC20 and the vault never holds its own, no risk"
  incidentes:
    - "Aera v3 (Spearbit) — vault can deposit into itself via Provisioner leading to artificial unit inflation (MEDIUM)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [vault, self-deposit, circular, inflation, provisioner, totalAssets, insolvency]

- id: vault-032
  pattern: custom-totalassets-without-dependent-overrides
  name: "Custom totalAssets without overriding dependent ERC4626 functions"
  causa_raiz: >
    ERC4626 base implementations derive maxWithdraw, maxRedeem, previewWithdraw,
    previewRedeem, and convertToShares/Assets from totalAssets(). If a vault overrides
    totalAssets() with custom logic (e.g., including unrealized yield, subtracting fees,
    or using an oracle price) but does NOT override the dependent functions, those
    functions silently use the new totalAssets() in calculations that weren't designed
    for it. The accounting becomes internally inconsistent.
  como_funciona: |
    1. Vault overrides totalAssets() to return balanceOf(vault) + unclaimedYield.
    2. Base maxWithdraw(user) = convertToAssets(balanceOf(user)) uses this inflated totalAssets.
    3. User calls maxWithdraw() → gets inflated number.
    4. User calls withdraw(maxWithdrawAmount) → reverts because vault doesn't actually
       have that liquid balance (unclaimedYield hasn't been realized).
    5. Or worse: if maxWithdraw is used as slippage check → griefing.
  invariante: |
    - withdraw(maxWithdraw(user)) must not revert (INV-V4626C-005)
    - redeem(maxRedeem(user)) must not revert (INV-V4626C-006)
    - convertToAssets(totalSupply) == totalAssets (internal consistency)
  que_mirar:
    - "Does the vault override totalAssets()? If so, which dependent functions are NOT also overridden?"
    - "Can a user withdraw exactly maxWithdraw() without reverting?"
    - "Does totalAssets include illiquid or unrealized components that can't be withdrawn?"
    - "Are there fees or penalties that reduce actual withdrawable amount below preview?"
  como_se_arregla: "Either override all ERC4626 functions that derive from totalAssets, or design totalAssets to only include liquid, immediately withdrawable assets. Add invariant tests for maxWithdraw/redeem."
  trampas:
    - "If unrealized yield is small relative to liquid assets, this may never trigger in normal use — needs extreme market conditions"
    - "OpenZeppelin 5.x ERC4626 implementation requires overriding _convertToShares/_convertToAssets for custom logic — check which OZ version is used"
    - "Vaults with timelocked withdrawals legitimately violate maxWithdraw by design — confirm operational constraints"
  severidad: high
  confianza: media
  fuente: "Solodit: Plume Network (ERC4626 override inconsistency), general ERC4626 pattern"
  verificado: false
  tags: [ERC4626, totalAssets, maxWithdraw, override, composability, accounting]
  relacionado_con: [vault-003, vault-004, vault-008]

- id: vault-033
  pattern: erc4626-mint-uses-wrong-parameter
  name: "ERC4626 mint() implementation uses amount instead of shares"
  causa_raiz: >
    EIP-4626's mint(shares, receiver) should deposit exactly `shares` shares (consuming
    the necessary assets). A common copy-paste error is to use `amount` (an intermediate
    variable representing assets) instead of `shares` in the internal _mint() call, or to
    call deposit() internally with the wrong parameter. Result: user receives a different
    number of shares than specified, violating the "exact shares out" guarantee of mint().
  como_funciona: |
    1. User calls mint(100_shares, receiver).
    2. Internally: assets = previewMint(100) = 95 USDC (if exchange rate > 1).
    3. Buggy code: _mint(receiver, assets) → mints 95 shares instead of 100.
    4. User paid for 100 shares, receives 95 shares.
    5. 5 shares worth of assets are credited to the vault but no shares issued → trapped funds.
  invariante: "mint(S, receiver) must mint exactly S shares to receiver (INV-V4626-018, INV-V4626C-023)"
  que_mirar:
    - "In mint(), is the internal _mint(receiver, X) call using shares or assets as X?"
    - "Does mint() call deposit() internally? If so, does it handle the returned value as shares?"
    - "Does the function test: balanceOf(receiver) after == balanceOf(receiver) before + shares?"
    - "Are there intermediate variables named amount/assets that could be confused with shares?"
  como_se_arregla: "Ensure _mint(receiver, shares) uses the `shares` parameter directly. Never mix shares and asset amounts in the same function without explicit conversion."
  trampas:
    - "This only affects mint() not deposit() — if the vault doesn't expose mint(), not applicable"
    - "If exchange rate == 1:1, shares == assets numerically and the bug may never be noticed"
    - "Tribe Turbo H-01: the bug was in ERC4626.sol itself, not the vault — always check the base class too"
  severidad: high
  confianza: alta
  fuente: "Solodit: Tribe Turbo H-01 (ERC4626 mint uses wrong amount)"
  verificado: false
  tags: [ERC4626, mint, shares, assets, parameter-confusion, accounting]
  relacionado_con: [vault-001, vault-008]

- id: vault-034
  pattern: deposit-counted-as-protocol-revenue
  name: "User deposits incorrectly counted as protocol revenue / fee income"
  causa_raiz: >
    In vaults that track protocol fees separately from user assets, the fee accounting
    can accidentally count incoming deposits as revenue. This happens when the fee
    accumulator is updated based on the delta in contract balance rather than only on
    actual generated yield. If a deposit increases contract balance, and the fee
    accumulator grabs a percentage of that delta, users are paying fees on their own
    principal — not on yield.
  como_funciona: |
    1. Vault tracks fees: pendingFees += (currentBalance - lastBalance) * feeRate.
    2. User deposits 1000 USDC: currentBalance increases by 1000.
    3. Fee accumulator runs: pendingFees += 1000 * 0.10 = 100 USDC.
    4. Only 900 USDC is credited to user shares.
    5. User paid 10% fee on their own deposit principal — not on generated yield.
  invariante: "totalAssets increase from deposit must equal deposit amount (no fee on principal) (INV-V4626-011, INV-V4626C-013)"
  que_mirar:
    - "How is the fee accumulator updated? On deposit/withdraw, or only on yield events?"
    - "Is the fee based on balance delta or only on explicit yield/reward entries?"
    - "Does deposit() call _accrueFees() before crediting shares? What does that function see as the balance change?"
    - "Can a deposit trigger any hook or callback that incorrectly records it as yield?"
  como_se_arregla: "Separate deposit accounting from yield accounting. Update fee accumulator only on explicit yield events (harvest, reward claims), not on deposit/withdraw balance changes."
  trampas:
    - "Vaults with entry fees legitimately charge on deposit principal — verify if this is documented behavior"
    - "Performance fees only on yield are correct — the bug is specifically when the deposit itself inflates the yield measurement"
    - "If the fee rate is 0%, this is harmless — always check actual configured fee values"
  severidad: medium
  confianza: media
  fuente: "Solodit: Tenbin (deposit counted as revenue), general vault fee pattern"
  verificado: false
  tags: [ERC4626, fees, revenue, deposit, accounting, performance-fee]
  relacionado_con: [vault-002, vault-005, vault-006]

- id: vault-035
  pattern: v3-vault-rebalance-no-slippage-sandwich
  name: "Vault V3 concentrated liquidity: rebalance/addLiquidity sin proteccion de slippage vulnerable a sandwich"
  causa_raiz: >
    Los vaults que gestionan posiciones Uniswap V3 (Arrakis, RealWagmi, Maia DAO Talos, etc.)
    realizan rebalanceos periodicos: retiran liquidez de un rango, hacen swap para reequilibrar
    los tokens, y depositan en el nuevo rango. Si estas operaciones se ejecutan con
    `amountOutMin=0` o `amount0Min=0, amount1Min=0`, no hay proteccion contra sandwich attacks.
    Un MEV bot puede manipular el precio antes del swap (inflando el costo del rebalanceo)
    y arbitrar la diferencia, extrayendo valor de todos los LPs del vault. El problema es
    sistematico porque cualquier usuario del vault puede activar el rebalanceo (o llamar al
    keeper) y cualquier bloque es vulnerable.
  como_funciona: |
    1. Vault tiene posicion V3 en rango [A, B] con $1M de liquidez.
    2. Precio se mueve, keeper llama rebalanceAll() o similar.
    3. Vault llama decreaseLiquidity() para retirar toda la liquidez.
    4. Vault hace exactInputSingle/swap() en el pool con amountOutMin=0.
    5. MEV bot fronta el rebalanceo: mueve el precio en la direccion desfavorable.
    6. Vault recibe significativamente menos tokens de los que deberia.
    7. MEV bot backruns: restaura el precio y captura la diferencia.
    8. Vault deposita los tokens mal equilibrados en el nuevo rango — LP value reducido.
    9. Todos los holders del vault absorben la perdida via share price reduction.
    Variante addLiquidity: si mint() usa amounts con min=0, el ataque se aplica tambien
    al agregar liquidez (no solo al rebalancear).
  invariante: |
    // El share price del vault no debe caer significativamente durante un rebalanceo
    uint256 pricePerShareBefore = vault.totalAssets() * 1e18 / vault.totalSupply();
    // [rebalanceo ejecutado]
    uint256 pricePerShareAfter = vault.totalAssets() * 1e18 / vault.totalSupply();
    // Permitir hasta MAX_REBALANCE_SLIPPAGE (e.g. 0.5%) de perdida por fees
    assert(pricePerShareAfter >= pricePerShareBefore * (1e18 - MAX_REBALANCE_SLIPPAGE) / 1e18);
  que_mirar:
    - "¿decreaseLiquidity() usa amount0Min=0, amount1Min=0?"
    - "¿exactInputSingle() o swap() usa amountOutMin=0 o amountOutMinimum=0?"
    - "¿mint()/increaseLiquidity() usa amount0Min=0, amount1Min=0?"
    - "¿Quien puede llamar rebalanceo? ¿Solo keeper trustado o cualquier address?"
    - "¿Se calcula el slippage minimo usando TWAP o solo spot price?"
    - "rg 'amount0Min.*0\\|amount1Min.*0\\|amountOutMin.*0\\|amountOutMinimum.*0' --type sol"
    - "rg 'rebalance\\|rebalanceAll\\|_rebalance' --type sol — verificar params de slippage"
  como_se_arregla: >
    Calcular `amount0Min` y `amount1Min` usando el precio TWAP del pool (no spot) con
    tolerancia configurable (e.g. 0.5%). Para swaps: calcular `amountOutMin` como
    `amountIn * twapPrice * (1 - slippageTolerance)`. Alternativamente, usar permisos de
    keeper para que solo addresses de confianza puedan ejecutar rebalanceos, reduciendo
    la superficie de ataque MEV (aunque no elimina fronta por parte del propio keeper).
    Maia DAO Talos: la solucion fue agregar slippage params derivados de oracle en
    TalosStrategyStaked antes de que cualquier LP pueda llamar rebalanceo.
  trampas:
    - "Si solo un keeper trustado puede rebalancear y usa slippage params en offchain calldata, el riesgo se reduce pero no elimina (keeper puede ser comprometido)"
    - "El uso de TWAP para slippage introduce latencia: si el precio se mueve rapido, el TWAP puede ser obsoleto y rechazar rebalanceos legitimos"
    - "Arrakis V2 mitiga esto con un SimpleManager que valida burns/mints — verificar si el vault usa SimpleManager o un gestor custom"
    - "El porcentaje de perdida depende de la profundidad del pool y el TVL del vault — en pools profundos, el ataque es menos rentable"
    - "Vaults con fee de rebalanceo explican cierta caida de share price — distinguir fees legitimas de sandwich loss"
  incidentes:
    - "RealWagmi (Sherlock 2023) — H-2: No slippage protection when withdrawing and providing liquidity in rebalanceAll; any caller can trigger rebalance vulnerable to sandwich (HIGH, Sherlock)"
    - "Maia DAO Ecosystem / Talos (Code4rena 2023) — M-18: Lack of slippage protection in all Uniswap V3 interactions (mint, burn, swap) allows MEV extraction from LP (MEDIUM, Code4rena)"
    - "Radiant June (Pashov 2024) — M-07: Lack of slippage check in rebalance function, vulnerable to sandwich attacks (MEDIUM, Pashov)"
    - "Arrakis (Sherlock 2023) — M-2: Lack of rebalance rate limiting allows operator to drain vault via repeated rebalances (MEDIUM, Sherlock)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: RealWagmi Sherlock H-2 https://solodit.xyz/issues/h-2-no-slippage-protection-when-withdrawing-and-providing-liquidity-in-rebalanceall-sherlock-none-realwagmi-git + Maia DAO Code4rena M-18"
  tags: [vault, ERC4626, v3-position, concentrated-liquidity, rebalance, slippage, sandwich, mev, arrakis, realwagmi, maia-dao, talos, keeper]
  relacionado_con: [vault-030, vault-031, lending-043, lending-044]
```

---

## 2. Invariantes Clave

### Solvency & Accounting (CRITICAL — fund loss if broken)

| ID | Invariant | Protects Against |
|----|-----------|-----------------|
| INV-V4626-002 | totalAssets == 0 iff totalSupply == 0 | First depositor attack, accounting desync |
| INV-V4626-003 | asset.balanceOf(vault) >= vault.internalCash() | Insolvency, token extraction |
| INV-V4626-006 | totalSupply == sum(balanceOf) for all holders | Mint/burn accounting bugs |
| INV-V4626C-033 | Inflation attack victim loses < 0.1% | Share inflation attack |

### Rounding Safety (HIGH — value extraction if broken)

| ID | Invariant | Protects Against |
|----|-----------|-----------------|
| INV-V4626C-013/015/016/018 | Zero in = zero out (all conversion functions) | Free shares/assets |
| INV-V4626C-014/017/019-022 | Nonzero in = nonzero out | Free minting/withdrawal |
| INV-V4626C-035/036 | Conversion roundtrip not profitable | Arbitrage via conversion |
| INV-V4626-011 through -018 | All 8 operation roundtrips not profitable | Deposit/redeem extraction |

### Preview Bounds (HIGH — integrator loss if broken)

| ID | Invariant | Direction |
|----|-----------|-----------|
| INV-V4626C-029 / INV-V4626-023 | deposit() mints >= previewDeposit() | Preview is pessimistic floor |
| INV-V4626C-030 / INV-V4626-024 | mint() costs <= previewMint() | Preview is pessimistic ceiling |
| INV-V4626C-031 / INV-V4626-026 | redeem() returns >= previewRedeem() | Preview is pessimistic floor |
| INV-V4626C-032 / INV-V4626-025 | withdraw() burns <= previewWithdraw() | Preview is pessimistic ceiling |

### Access Control (CRITICAL — theft if broken)

| ID | Invariant | Protects Against |
|----|-----------|-----------------|
| INV-V4626C-011 | withdraw() requires sufficient share approval | Unauthorized withdrawal |
| INV-V4626C-012 | redeem() requires sufficient share approval | Unauthorized redemption |
| INV-V4626C-009/010 | Approval updates correctly after proxy operations | Allowance manipulation |

### EIP Compliance (MEDIUM — composability broken)

| ID | Invariant | Protects Against |
|----|-----------|-----------------|
| INV-V4626C-001 through -008 | View functions must not revert | Integration failures |
| INV-V4626C-023 through -028 | Preview/max functions independent of msg.sender | Caller-dependent pricing |
| INV-V4626C-034 | Vault decimals >= asset decimals | Precision loss |

### Earn/Yield Vault Specific (if applicable)

| ID | Invariant | Protects Against |
|----|-----------|-----------------|
| INV-V4626-001/010 | Share price monotonically increases (except fees) | Value extraction |
| INV-V4626-008 | totalAssets >= lastTotalAssets | Yield theft |
| INV-V4626-009 | lostAssets only increases | Loss reversal exploit |
| INV-V4626-007 | Idle funds <= maxIdleAllowed | Donation bypass of strategies |

---

## 3. Checklist Rapido

Run through this when you encounter an ERC-4626 vault. Each "NO" is a lead to investigate.

### First Depositor Protection
- [ ] Does the vault use virtual shares/assets offset (e.g., `_decimalsOffset()`)?
- [ ] OR does it burn MINIMUM_LIQUIDITY to dead address on first mint?
- [ ] OR does it enforce a minimum first deposit amount?
- [ ] If NONE of the above: **vault-001 is likely exploitable**

### Donation Resistance
- [ ] Does `totalAssets()` use internal accounting (not `balanceOf`)?
- [ ] Is there a sweep/skim function for excess donated tokens?
- [ ] Is exchange rate change limited per block?

### Rounding Direction
- [ ] Does `deposit` / `mint` round UP (against user) on assets consumed?
- [ ] Does `withdraw` / `redeem` round DOWN (against user) on assets returned?
- [ ] Is `mulDivUp` used for entry, `mulDivDown` for exit?
- [ ] Do all zero inputs return zero outputs?
- [ ] Do all nonzero inputs produce nonzero outputs?

### Roundtrip Safety
- [ ] Is `redeem(deposit(X))` <= X for any X?
- [ ] Is `deposit(redeem(S))` <= S for any S?
- [ ] Is `mint` cost >= `redeem` yield for same share amount?

### Access Control
- [ ] Does `redeem(shares, receiver, owner)` check allowance when `msg.sender != owner`?
- [ ] Does `withdraw(assets, receiver, owner)` check allowance when `msg.sender != owner`?
- [ ] Is the allowance check on SHARES (not assets)?

### Preview Consistency
- [ ] Is `previewDeposit` <= actual shares minted?
- [ ] Is `previewMint` >= actual assets consumed?
- [ ] Is `previewWithdraw` >= actual shares burned?
- [ ] Is `previewRedeem` <= actual assets returned?
- [ ] Are preview functions `view` with no side effects?

### View Function Safety
- [ ] Do `asset()`, `totalAssets()`, `convertToShares()`, `convertToAssets()` never revert?
- [ ] Do `maxDeposit()`, `maxMint()`, `maxWithdraw()`, `maxRedeem()` never revert?
- [ ] Are `max*` and `preview*` functions independent of `msg.sender`?

### Decimals
- [ ] Is vault `decimals()` >= underlying asset `decimals()`?
- [ ] Are there low-decimal tokens (USDC = 6, WBTC = 8) that amplify rounding?

### Yield Vault Extras (if applicable)
- [ ] Does share price only decrease on legitimate loss events or fee minting?
- [ ] Is cumulative loss counter monotonically increasing?
- [ ] Is idle balance within configured limits after rebalance?

---

## Solodit Verified Findings

### Maps to vault-001 (first depositor share inflation)

- **[HIGH] First depositor can break minting of shares (Solodit #1657)** -- Attacker deposits 2 wei (to survive fee deduction), then donates to _strategyController which deposits entire balance to strategy, inflating share price via an indirect donation path that bypasses vault balanceOf checks.
- **[HIGH] Share price manipulation via reward donation (Solodit #44986)** -- When nETHMinted=0, attacker triggers updateRewards after donating to strategy; getRewards() uses balanceOf, setting sharePrice to 0, causing all subsequent depositors to receive 0 shares.
- **[MEDIUM] Tranche share ratios manipulated by donating via liquidations (Solodit #31494)** -- Even with solmate's internal accounting, donation is still possible through liquidation surplus credits (realisedLiquidityOf), bypassing the donation protection that replaces balanceOf with storage tracking.
- **[MEDIUM] Inflate initial share price by front-running training block (Solodit #12253)** -- Whitelisted first-depositor protection can be front-run because setting training=true is a separate transaction from deployment; attacker deposits between deploy and training activation.
- **[MEDIUM] Interest auctions enable inflation attacks on backstop vaults (Solodit #51635 context)** -- Interest auction mechanism allows indirect token donation to newly created backstop vaults, circumventing direct-transfer protections and enabling exchange rate manipulation.

### Maps to vault-002 (donation attack / exchange rate manipulation)

- **[HIGH] Donation attack permanently fixes ratio at 1 (Solodit #51635)** -- Key insight: after a donation of >=1e18 tokens, the ratio becomes permanently stuck at 1 due to multiplyAndDivideCeil rounding, making all deposits below 1e18 return zero shares forever -- not just temporarily manipulable but a permanent vault brick.
- **[HIGH] Donation attacks on empty AAVE vaults (Solodit vault-14)** -- Attacker mints, transfers, and burns products to manipulate totalSupply to 1, then donates ATokens directly; the AToken rebasing mechanism creates a donation vector even in protocols that use internal accounting for the base asset.
- **[MEDIUM] DOS by directly transferring assets to Reaper Vault (Solodit vault-33)** -- Direct transfer causes freeFunds() underflow because tvlCap check uses balanceOf but accounting uses internal tracking; the mismatch creates a permanent denial of service rather than profit extraction.

### Maps to vault-003 (rounding direction)

- **[HIGH] Rounding issue makes it possible to steal all pool assets (Solodit vault-31)** -- withdraw() calculates required shares as 0 when it should be >= 1, AND rounds down instead of up; combined, an attacker can withdraw assets for free via repeated 0-share withdrawals, draining the entire pool.
- **[HIGH] Incorrect accounting in yDUSD vault (Solodit vault-35)** -- Vault total supply (shares) desyncs from actual deposits when protocol mints DUSD debt directly to vault; the direct minting path bypasses the deposit flow's share accounting, creating unbacked shares.
- **[HIGH] Rounding issues in wfCashERC4626 (Solodit vault-25)** -- Notional's wrapped fCash uses preview functions that round in different directions than actual operations; the fCash-to-underlying conversion has additional intermediate rounding steps that compound the error.

### Maps to vault-004 (roundtrip extraction)

- **[MEDIUM] wstUSR previewWithdraw returns 0 enabling free withdraw (Solodit #37825)** -- Wrapper vault divides by ST_USR_SHARES_OFFSET, and when inner vault's previewWithdraw returns a value smaller than the offset, the wrapper rounds to 0 shares needed; attacker withdraws assets by burning 0 shares.

### Maps to vault-007 (share price manipulation)

- **[MEDIUM] Attacker manipulates interest distribution via asset transfer and fee accrual (Solodit #41313)** -- Depositing large amount before regular user causes disproportionate interest allocation to dead-address shares (from initialization); fee share minting formula amplifies the skew because feeShares use newTotalAssets - feeAssets as denominator.
- **[MEDIUM] Strict initialSharePrice checks enable deployment DOS (Solodit #35864)** -- Constructor requires exact share price match with yield source; attacker front-runs deployment with tiny donation to shift share price by 1 wei, causing revert. New pattern: share price used as deployment precondition.

### Maps to vault-008 (preview function inconsistency)

- **[MEDIUM] UlyssesPool preview functions non-compliant with EIP-4626 (Solodit vault-36)** -- previewDeposit, previewRedeem, and previewMint do not include fees in returned values as required by the EIP; integrators using previews for slippage get wrong bounds when fees are nonzero.
- **[MEDIUM] maxDeposit non-compliant with ERC-4626 (Solodit vault-37)** -- maxDeposit returns an amount that causes deposit() to revert due to internal cap checks not reflected in the max function; integrators trusting maxDeposit get unexpected reverts.

### New patterns not in existing bugs

- **[HIGH] Malicious operator steals all deposits via numerator manipulation (Solodit vault-29)** -- Orbital vault uses numerator/denominator share system; operator can manipulate their numerator to claim disproportionate vault holdings. New pattern: custom (non-ERC20) share systems with mutable numerators.
- **[HIGH] Incorrect redemption accounting drains sUSDe balance (Solodit vault-18)** -- yUSDe vault calls pUSDeVault.redeem during yield phase, but _withdraw accounting does not properly track the sUSDe outflow, allowing attacker to drain entire sUSDe balance. New pattern: nested vault redemption accounting desync.
- **[HIGH] CVX/AURA reward distribution wrong across cliffs (Solodit vault-17)** -- _getAuraPendingReward uses current supply values instead of values at time of accrual; across cliff boundaries (where AURA emission rate changes), this over/under-counts rewards. New pattern: reward token cliff boundary miscalculation.
- **[HIGH] Funding fee rate calculated on Oracle Maker skew but applied market-wide (Solodit vault-34)** -- Attacker opens large position on Oracle Maker to generate extreme funding rate, then profits from the rate applied to all market participants. New pattern: rate scope mismatch (local calculation, global application).
- **[MEDIUM] supplyPool ignores underlying pool cap (Solodit vault-32)** -- CuratedVault deposits into underlying pools without checking the pool's own internal cap; deposit reverts or causes unintended supply queue reordering. New pattern: multi-layer cap enforcement gap.
- **[MEDIUM] 1:1 conversion rate causes last-withdrawer loss socialization (Solodit vault-28)** -- Pool uses 1:1 asset:share rate without accounting for losses from CDPVault liquidations; last withdrawer absorbs all bad debt. New pattern: fixed exchange rate pools with external loss sources.
- **[MEDIUM] Slippage controls missing on ERC4626 deposit/mint (Solodit vault-19, vault-20)** -- No slippage parameter on 4626 deposit/mint allows sandwich attacks on the exchange rate; EIP security considerations explicitly warn about this for EOA access. New pattern: missing slippage on vault entry/exit.
- **[MEDIUM] Vault can be placed back into vulnerable low supply state (Solodit vault-26)** -- After initial protection (dead shares), vault can reach low-supply state again through normal withdrawals, re-enabling inflation attack. New pattern: non-permanent first-depositor protection.
