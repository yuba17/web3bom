# ERC20 Token Vulnerabilities -- Combat Briefing

> Last updated: 2026-03-19
> Sources: crytic_properties (25 invariants), defihacklabs exploit_derived (token-related entries)

---

## 1. Bugs Conocidos

```yaml
- id: token-001
  pattern: approve-race-condition
  name: "Approval frontrunning / race condition"
  causa_raiz: "approve() overwrites existing allowance atomically. Between tx submission and confirmation, spender can front-run to use old allowance, then use new one."
  como_funciona: "1. Alice approves Bob for 100. 2. Alice sends tx to change approval to 50. 3. Bob sees pending tx, front-runs with transferFrom(100). 4. Alice's new approve(50) lands. 5. Bob calls transferFrom(50). Total: 150 instead of 50."
  invariante: "Allowance changes via approve() should not allow double-spend of old + new allowance"
  que_mirar:
    - "Does the protocol use approve() to change non-zero allowances?"
    - "Is increaseAllowance/decreaseAllowance available and used?"
    - "Does the protocol set allowance to 0 before setting new value?"
  como_se_arregla: "Use increaseAllowance/decreaseAllowance (INV-ERC20-024/025). Or approve(0) first, then approve(newAmount). OpenZeppelin safeApprove enforces this."
  trampas:
    - "This is a known ERC20 design flaw, not a protocol bug. Only report if the PROTOCOL creates a new attack path."
    - "Most judges mark this as informational unless there is a concrete protocol-specific exploit."
  solodit_ids:
    - risk-of-token-theft-due-to-race-condition-in-erc20s-approve-function-trailofbits-none-maple-labs-pdf
    - race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-golem-pdf
    - race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-dapphub-pdf
    - ptoken-double-spend-race-conditions-zokyo-none-paribus-markdown
  incidentes:
    - "Liquid Collective -- approve() front-run race condition allows token theft in SharesManager and WLSETH (Medium)"
    - "Holograph -- isOwner/onlyOwner checks bypassed in ERC721/ERC20 implementations via approval manipulation (Medium)"
  severidad: medium
  confianza: alta
  fuente: "crytic_properties (INV-ERC20-015, INV-ERC20-016, INV-ERC20-024, INV-ERC20-025)"
  verificado: true
  tags: [approval, frontrunning, race-condition, ERC20]
  relacionado_con: [token-008]

- id: token-002
  pattern: fee-on-transfer
  name: "Fee-on-transfer tokens breaking protocol accounting"
  causa_raiz: "Protocol assumes amount sent == amount received. Fee-on-transfer tokens deduct a tax, so actual received < amount parameter."
  como_funciona: "1. Protocol calls token.transferFrom(user, protocol, 100). 2. Token deducts 3% fee, protocol receives 97. 3. Protocol records deposit of 100 internally. 4. Accounting drift: protocol thinks it has 100, actually has 97. 5. Repeat N times, protocol becomes insolvent."
  invariante: "token.balanceOf(contract) >= sum(internal_accounting) at all times (INV-EXPLOIT-012)"
  que_mirar:
    - "Does the protocol measure balance before/after transfer to get actual received amount?"
    - "Or does it trust the amount parameter?"
    - "Search for: balanceOf(address(this)) before and after transfer calls"
    - "Does the protocol have a token whitelist excluding fee tokens?"
  como_se_arregla: "Measure actual received: uint256 before = token.balanceOf(address(this)); token.transferFrom(..., amount); uint256 received = token.balanceOf(address(this)) - before;"
  trampas:
    - "If protocol explicitly documents 'no fee-on-transfer tokens', this is informational."
    - "Some protocols use a whitelist -- check governance token addition flow."
  solodit_ids: []
  incidentes:
    - "Beedle -- Fee-on-transfer tokens cause insolvency in deposit/withdraw accounting (High)"
    - "Blueberry -- type(uint256).max repayment silently fails for FoT tokens, debt persists (Medium)"
    - "Numoen -- Fee-on-transfer tokens cause mint() to revert due to strict balance check (Medium)"
    - "SIZE -- Incompatibility with FoT/deflationary/rebasing tokens on both base and quote (Medium)"
    - "Gauntlet -- Fee-on-transfer blocks withdrawFromPool in AeraVaultV1 (Medium)"
    - "Harpie -- FoT tokens cause Vault insolvency, later users cannot withdraw (Medium)"
    - "Buffer Finance -- BufferBinaryPool/BufferRouter insufficient FoT token support (Medium)"
    - "Bull v Bear -- BvB Protocol does not handle FoT/deflationary tokens in matchOrder (Medium)"
    - "Debt DAO -- Variable balance ERC20 (FoT, rebasing) causes inaccurate collateral accounting (Medium)"
    - "prePO -- FoT baseToken gives recipient free collateral tokens (Medium)"
    - "Allo V2 -- Tokens that transfer less than amount break distribution (Medium)"
  severidad: high
  confianza: alta
  fuente: "defihacklabs (INV-EXPLOIT-012); crytic_properties (INV-ERC20-013 false_positive_notes)"
  verificado: true
  tags: [fee-on-transfer, accounting, balance-drift, deflationary]
  relacionado_con: [token-003, token-006]

- id: token-003
  pattern: rebasing-token
  name: "Rebasing tokens breaking balance assumptions"
  causa_raiz: "Rebasing tokens (stETH, AMPL, OHM) change balanceOf() between transactions without any transfer event. Protocols that cache balances or use internal accounting diverge from reality."
  como_funciona: "1. Protocol records user deposited 100 stETH. 2. Rebase happens, actual balance changes to 105 or 95. 3. Protocol still thinks balance is 100. 4. On withdrawal, user gets wrong amount. 5. In negative rebase: protocol owes more than it has."
  invariante: "For rebasing tokens: internal accounting must sync with actual balanceOf after each rebase event"
  que_mirar:
    - "Does the protocol cache token balances in storage?"
    - "Does it use wrapped versions (wstETH instead of stETH)?"
    - "Is there a sync() or skim() mechanism?"
    - "Are share-based accounting systems used instead of raw amounts?"
  como_se_arregla: "Use wrapped non-rebasing versions (wstETH). Or use share-based internal accounting. Or sync on every interaction."
  trampas:
    - "If protocol only supports non-rebasing tokens via whitelist, not a finding."
    - "wstETH is NOT rebasing -- only raw stETH is."
  severidad: high
  confianza: alta
  fuente: "defihacklabs (INV-EXPLOIT-012 setup_requirements)"
  verificado: true
  tags: [rebasing, balance-drift, stETH, AMPL, elastic-supply]
  relacionado_con: [token-002, token-006]

- id: token-004
  pattern: unchecked-transfer-return
  name: "Missing return value check on transfer/transferFrom"
  causa_raiz: "Some ERC20 tokens (USDT, BNB) do not return bool on transfer/transferFrom, or return false instead of reverting on failure. If return value is not checked, state advances without actual token movement."
  como_funciona: "1. Protocol calls token.transfer(recipient, amount). 2. Transfer fails but returns false (or no return value). 3. Protocol does not check return value. 4. Protocol state assumes transfer succeeded. 5. Attacker withdraws funds that were never actually deposited."
  invariante: "All ERC20 transfer/transferFrom/approve must use SafeERC20 or explicitly check return value (INV-EXPLOIT-013)"
  que_mirar:
    - "Is SafeERC20 imported and used for ALL token interactions?"
    - "Search for bare .transfer( and .transferFrom( calls without require()"
    - "Search for .approve( without SafeERC20"
    - "Check USDT compatibility (no return value)"
  como_se_arregla: "Use OpenZeppelin SafeERC20: safeTransfer, safeTransferFrom, safeApprove, forceApprove"
  trampas:
    - "If SafeERC20 is used everywhere, not a finding."
    - "Solidity interface definition may mask the issue -- check actual call site."
  solodit_ids:
    - transfertransferfrom-are-used-instead-of-their-counterparts-from-safeerc20-zokyo-none-tradable-markdown
    - m-02-erc20-return-values-not-checked-code4rena-yaxis-yaxis-contest-git
    - m-04-erc20-transfer-not-all-tokens-return-boolean-kann-none-wild-protocol-markdown
    - unhandled-return-value-of-erc20-transfer-in-transfer-and-withdraw-functions-quantstamp-fdusd-on-eth-blockchain-markdown
    - lack-of-return-value-validation-in-erc20-transfer-zokyo-none-repl-markdown
  incidentes:
    - "Amun -- ERC20 return values not checked, tokens not actually transferred but state updated (Medium)"
    - "Reality Cards -- Unchecked ERC20 transfers cause permanent fund lockup (High)"
    - "Credifi -- Unchecked ERC20 transfer in loan repayment allows phantom repayment (Medium)"
    - "Otim Smart Wallet -- USDT and non-bool-returning tokens cause transfer reverts (Medium)"
    - "Telcoin -- Unsafe ERC20 methods (no SafeERC20) across multiple contracts (Medium)"
    - "Sense -- AutoRoller does not handle ERC20 tokens with non-reverting false-return transfer (Medium)"
    - "Buffer Finance -- Limited ERC20 support due to missing SafeERC20, non-standard tokens fail (Medium)"
    - "Sense WstETHAdapter -- wrapUnderlying return value missing causes zero-amount downstream (High)"
  severidad: critical
  confianza: alta
  fuente: "defihacklabs (INV-EXPLOIT-013); real bugs: TransitSwap $21M (2022-10)"
  verificado: true
  tags: [unchecked-return, SafeERC20, USDT, silent-failure, transfer]
  relacionado_con: [token-005]

- id: token-005
  pattern: zero-address-transfer
  name: "Zero address transfer/approval"
  causa_raiz: "Transferring tokens to address(0) permanently burns them. Some tokens allow this, some revert. Protocols that do not validate recipient can accidentally destroy user funds."
  invariante: "transfer(address(0), amount) and transferFrom(sender, address(0), amount) should revert (INV-ERC20-005, INV-ERC20-006)"
  que_mirar:
    - "Does the protocol validate recipient != address(0) before transfer?"
    - "Can user-supplied addresses be address(0)?"
    - "Does approve(address(0), amount) succeed?"
  como_se_arregla: "require(recipient != address(0)); in transfer/transferFrom. Or use SafeERC20."
  trampas:
    - "Some tokens use transfer-to-zero as intentional burn mechanism."
    - "OpenZeppelin ERC20 already reverts on zero address."
  severidad: high
  confianza: alta
  fuente: "crytic_properties (INV-ERC20-005, INV-ERC20-006)"
  verificado: true
  tags: [zero-address, burn, validation, transfer]
  relacionado_con: [token-004]

- id: token-006
  pattern: decimal-mismatch
  name: "Decimal mismatch between tokens"
  causa_raiz: "Tokens have different decimals (USDC=6, WETH=18, Chainlink=8). Arithmetic combining values from different tokens without normalization causes massive over/under-valuation."
  como_funciona: "1. Protocol treats all tokens as 18 decimals. 2. User deposits 1000 USDC (1000e6). 3. Protocol values it as 1000e6 in 18-decimal math = 0.000000001 USDC worth. 4. Or inversely: 1e6 USDC treated as 1e18 = 1 trillion USDC."
  invariante: "normalizedValue == rawValue * 10**(targetDecimals - sourceDecimals) (INV-EXPLOIT-023)"
  que_mirar:
    - "Hardcoded 1e18, 1e6, 1e8 in arithmetic?"
    - "Does protocol call decimals() and normalize?"
    - "Cross-token arithmetic: price * amount with different decimal bases?"
    - "Oracle price decimals (Chainlink = 8) vs token decimals?"
  como_se_arregla: "Always normalize: amount * 10**(18 - token.decimals()). Use a scaling library. Never hardcode decimals."
  trampas:
    - "Protocol may intentionally only support 18-decimal tokens with a whitelist."
    - "Check if there is an addToken/addMarket function that validates decimals."
  solodit_ids:
    - decimal-mismatch-for-tokens-on-hyperevm-and-hypercore-cyfrin-none-button-basis-trade-markdown
    - m-07-trovemanager-does-not-work-with-non-18-decimal-tokens-pashov-audit-group-none-roots_2025-02-09-markdown
    - m-9-market-rate-never-used-due-to-decimal-discrepancy-sherlock-plaza-finance-git
    - m-02-price-will-not-always-be-18-decimals-as-expected-and-outlined-in-the-comments-code4rena-caviar-caviar-contest-git
    - the-stable-swap-pools-used-in-connext-are-incompatible-with-tokens-with-varying-decimals-spearbit-connext-pdf
  incidentes:
    - "Blueberry -- ICHI v1 (9 decimals) to v2 (18 decimals) conversion error, users get 1e9x fewer reward tokens (High)"
    - "Sense -- Untrusted decimals() return value can be mutated intra-transaction (High)"
    - "Connext -- Incorrect decimal in initializeSwap cannot be corrected, permanent calculation errors (Medium)"
    - "Notional -- Typo checks primaryDecimals instead of secondaryDecimals, >18 decimal tokens brick vault (Medium)"
    - "Sublime -- Yearn token-shares conversion uses wrong decimal base (1e18 vs actual), incorrect payouts (High)"
    - "Dexe -- TokenSaleProposal::buy assumes 18 decimals for buy token, total loss for non-18 decimal tokens (High)"
    - "Locke -- Low decimal tokens (<=4) with long stream duration cause funds locked due to precision loss (Medium)"
  severidad: critical
  confianza: alta
  fuente: "defihacklabs (INV-EXPLOIT-023); real bugs: Bedrock DeFi $1.7M (2024-09)"
  verificado: true
  tags: [decimals, scaling, precision, normalization, USDC, oracle]
  relacionado_con: [token-002, token-003]

- id: token-007
  pattern: pausable-blacklistable
  name: "Pausable/blacklistable tokens blocking protocol operations"
  causa_raiz: "Tokens like USDC and USDT have pause() and blacklist() functions. If a protocol holds these tokens and gets paused/blacklisted, all operations involving that token revert, potentially locking user funds permanently."
  como_funciona: "1. Protocol holds USDC in a pool. 2. USDC issuer blacklists the protocol contract address. 3. All USDC transfers from the contract revert. 4. User funds locked permanently. 5. Or: USDC paused globally, all protocol operations halt."
  invariante: "Protocol must have emergency withdrawal paths that do not depend on token.transfer succeeding (INV-ERC20-022, INV-ERC20-023)"
  que_mirar:
    - "Does the protocol have emergency withdrawal mechanisms?"
    - "Can users withdraw other tokens if one is frozen?"
    - "Is there a rescue/sweep function for stuck tokens?"
    - "Does the protocol interact with USDC, USDT, or other centralized tokens?"
  como_se_arregla: "Isolate token risk. Allow partial withdrawals. Emergency mode that skips frozen tokens. Track per-token rather than aggregate."
  trampas:
    - "Centralized token risk is often marked as 'known/accepted' by protocols."
    - "Only report if there is NO mitigation and concrete fund loss path."
  solodit_ids:
    - m-01-kumabondtokenapprove-should-revert-if-the-owner-of-the-tokenid-is-blacklisted-code4rena-kuma-protocol-kuma-protocol-versus-contest-git
    - reward-distribution-or-refunds-can-be-griefed-if-one-of-the-address-gets-blacklisted-zokyo-none-xyro-markdown
  incidentes:
    - "NounsDAO -- USDC-blacklisted recipient blocks cancel() for all streams (Medium)"
    - "reNFT -- Blocklisted ERC20 payment recipient causes rented NFT stuck in Safe (Medium)"
    - "reNFT -- Paused ERC721/ERC1155 causes stopRent to revert, lender issues (Medium)"
    - "Yieldfi -- Commented-out blacklist check allows restricted PerpetualBond transfers (Medium)"
  severidad: medium
  confianza: media
  fuente: "crytic_properties (INV-ERC20-022, INV-ERC20-023)"
  verificado: true
  tags: [pausable, blacklist, USDC, USDT, frozen-funds, centralization]
  relacionado_con: [token-004]

- id: token-008
  pattern: infinite-approval-danger
  name: "Infinite approval to untrusted/upgradeable contracts"
  causa_raiz: "Contracts that approve type(uint256).max to external contracts create a permanent drain vector. If the approved contract is upgradeable or has arbitrary execution capabilities, all approved tokens can be stolen."
  como_funciona: "1. Protocol approves type(uint256).max to a router/swapper. 2. Router is upgradeable or has arbitrary call capability. 3. Attacker exploits router to call transferFrom on the protocol. 4. All approved tokens drained in one tx."
  invariante: "token.allowance(contract, spender) == 0 after use, OR spender is immutable and trusted (INV-EXPLOIT-018)"
  que_mirar:
    - "Search for type(uint256).max in approve() calls"
    - "Is the approved contract upgradeable?"
    - "Does the approved contract have arbitrary call/delegatecall?"
    - "Are approvals reset to 0 after operations?"
  como_se_arregla: "Approve exact amount needed, then reset to 0. Or use forceApprove with exact amount. Only infinite-approve immutable, non-upgradeable, audited contracts."
  trampas:
    - "Infinite approval to canonical Uniswap V2/V3 Router is standard and accepted."
    - "Focus on upgradeable contracts and custom routers."
  solodit_ids: []
  incidentes:
    - "LI.FI -- Facets approve arbitrary user-supplied addresses for ERC20 tokens (Medium)"
  severidad: critical
  confianza: alta
  fuente: "defihacklabs (INV-EXPLOIT-018); real bugs: Coinbase $300K (2025-08), Bebop DEX $21K (2025-08)"
  verificado: true
  tags: [approval, infinite-allowance, upgradeable, drain, residual-approval]
  relacionado_con: [token-001]

- id: token-incident-001
  name: "Telcoin exploit"
  fecha: "2023-12"
  perdida: "$1.24M"
  causa_raiz: "Storage collision in proxy token contract"
  categoria: "Proxy storage collision"
  vector: "Proxy upgrade caused storage collision, corrupting token state and enabling unauthorized transfers"
  leccion: "Proxy storage layout MUST be verified on every upgrade. Storage collision is silent and catastrophic. Use ERC-1967 storage slots."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-004]
  tags: [proxy, storage-collision, upgrade, real-exploit]

- id: token-incident-002
  name: "DEI stablecoin exploit"
  fecha: "2023-05"
  perdida: "$5.4M USDC"
  causa_raiz: "Implementation flaw in token/stablecoin logic"
  categoria: "Implementation flaw"
  vector: "Flawed implementation in DEI stablecoin allowed attacker to extract collateral"
  leccion: "Stablecoin mint/burn/redeem paths must maintain strict collateral invariants."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-002]
  tags: [stablecoin, implementation-flaw, collateral, real-exploit]

- id: token-incident-003
  name: "Poolz exploit"
  fecha: "2023-03"
  perdida: "$390K"
  causa_raiz: "Integer overflow in token handling"
  categoria: "Integer overflow"
  vector: "Integer overflow in token amount calculations bypassed balance checks"
  leccion: "Pre-0.8.0 Solidity code or unchecked blocks are overflow-prone. See INV-ERC20-009."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-004]
  tags: [integer-overflow, arithmetic, real-exploit]

- id: token-incident-004
  name: "SSS token exploit"
  fecha: "2024-03"
  perdida: "$4.8M"
  causa_raiz: "Token balance doubles on self-transfer"
  categoria: "Self-transfer balance inflation"
  vector: "transfer(msg.sender, amount) doubled the sender's balance instead of being a no-op. Violates INV-ERC20-007."
  leccion: "CRITICAL: Self-transfer MUST preserve balance. This is INV-ERC20-007 exactly. Fuzz with from==to on every custom ERC20."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-005]
  tags: [self-transfer, balance-inflation, INV-ERC20-007, real-exploit]

- id: token-incident-005
  name: "GPU token exploit"
  fecha: "2024-05"
  perdida: "$32K"
  causa_raiz: "Self-transfer balance error"
  categoria: "Self-transfer balance inflation"
  vector: "Same class as SSS -- self-transfer did not preserve balance"
  leccion: "Pattern keeps recurring. INV-ERC20-007 is a Tier 1 invariant for custom tokens."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-incident-004]
  tags: [self-transfer, balance-inflation, real-exploit]

- id: token-incident-006
  name: "SCROLL token exploit"
  fecha: "2024-05"
  perdida: "$76 ETH"
  causa_raiz: "Integer underflow in token logic"
  categoria: "Integer underflow"
  vector: "Underflow in balance subtraction allowed minting tokens from nothing"
  leccion: "Custom transfer logic with unchecked arithmetic is a recurring pattern. INV-ERC20-009 catches this."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-004, token-incident-007]
  tags: [integer-underflow, arithmetic, real-exploit]

- id: token-incident-007
  name: "LW token exploit"
  fecha: "2024-07"
  perdida: "$7K"
  causa_raiz: "Integer underflow"
  categoria: "Integer underflow"
  vector: "Underflow in custom token transfer logic"
  leccion: "Same pattern as SCROLL. Use Solidity 0.8+ checked arithmetic or SafeMath."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-incident-006]
  tags: [integer-underflow, real-exploit]

- id: token-incident-008
  name: "Pandora token exploit"
  fecha: "2024-02"
  perdida: "$17K"
  causa_raiz: "Integer underflow"
  categoria: "Integer underflow"
  vector: "Underflow in ERC-404 hybrid token implementation"
  leccion: "ERC-404 and other hybrid token standards introduce novel attack surfaces. Test all ERC20 invariants on hybrid tokens."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-incident-006]
  tags: [integer-underflow, ERC-404, hybrid-token, real-exploit]

- id: token-incident-009
  name: "Reflection token exploits (2023 batch)"
  fecha: "2023 (multiple)"
  perdida: "Combined: BEVO $144 BNB, TINU $22 ETH, SHOCO $4 ETH, FDP $16 WBNB, Sheep $3K, OLIFE $32 WBNB, BIGFI $30K, MCC $10 ETH, HODL $2.3 ETH, BUNN $52 BNB"
  causa_raiz: "Various reflection token implementation flaws"
  categoria: "Reflection token bugs"
  vector: "Reflection tokens (auto-distributing fees to holders) have endemic bugs: incorrect fee math, balance inflation via self-transfer, rounding exploitation in reflect/unreflect conversions"
  leccion: "Reflection tokens are an ENTIRE bug class. The reflect/unreflect conversion math, excluded address handling, and fee-on-transfer interaction create dozens of attack surfaces. Apply ALL ERC20 invariants plus reflection-specific checks."
  verificado: true
  fuente: "DeFiHackLabs (github.com/SunWeb3Sec/DeFiHackLabs)"
  relacionado_con: [token-002, token-incident-004]
  tags: [reflection-token, fee-on-transfer, balance-inflation, batch-exploits, real-exploit]

- id: token-009
  pattern: erc777-reentrancy-hooks
  name: "ERC777 token hooks enable reentrancy in ERC20-assuming protocols"
  causa_raiz: "ERC777 tokens implement tokensToSend (before transfer) and tokensReceived (after transfer) hooks via ERC1820 registry. Protocols that assume ERC20 transfer is atomic and non-reentrant are vulnerable when ERC777 tokens trigger callbacks mid-transfer."
  como_funciona: |
    1. Protocol accepts arbitrary ERC20 tokens (no whitelist).
    2. Attacker registers ERC1820 tokensToSend hook for their address.
    3. Attacker calls protocol function that triggers safeTransferFrom.
    4. ERC777 tokensToSend hook fires BEFORE balances update.
    5. Attacker re-enters protocol function during hook callback.
    6. Protocol reads stale balances/state, allowing double-spend or state corruption.
    7. After reentrancy completes, original transfer finalizes.
  invariante: |
    // No state change should be possible mid-transfer
    // assert(reentrancyGuard == LOCKED) during any token transfer callback
    assert(!entered); // ReentrancyGuard must be active on all token-handling functions
  que_mirar:
    - "rg 'function\\s+\\w+' --type sol -A 5 | grep -B1 'safeTransferFrom\\|safeTransfer' | grep -v nonReentrant"
    - "rg 'balanceOf.*before.*balanceOf.*after' --type sol"
    - "Does the protocol have ReentrancyGuard on ALL functions that handle tokens?"
    - "Does the protocol explicitly block ERC777 or rely on a token whitelist?"
    - "Check if balance-before/after pattern is used (vulnerable to ERC777 tokensToSend)"
    - "NOTA: evitar 'rg safeTransfer | rg -v nonReentrant' — busca en MISMA línea, no en misma función"
  como_se_arregla: "Apply nonReentrant modifier to ALL functions that transfer tokens. Or explicitly block ERC777 tokens. Follow CEI pattern strictly -- update all state BEFORE external calls."
  trampas:
    - "If protocol has ReentrancyGuard on all entry points, not exploitable."
    - "If protocol uses a strict token whitelist excluding ERC777, not a finding."
    - "ERC777 is rare in production -- judges may downgrade if no concrete ERC777 token is in scope."
  solodit_ids: []
  incidentes:
    - "PolygonZkEVM Bridge -- ERC777 tokensToSend hook reentrancy drains bridge via duplicate deposit leaves (Critical)"
    - "Caviar -- ERC777 reentrancy in buy() allows purchasing at considerable discount (High)"
    - "Buffer Finance -- ERC777 re-enter resolveQueuedTrades to steal funds (Medium)"
    - "Buffer Finance -- ERC777 bypasses maxLiquidity check via provide() reentrancy (Medium)"
    - "SIZE -- ERC777 with tax enables auction theft via re-entrancy in createAuction (Medium)"
    - "Inverse Finance -- ERC777 reentrancy during withdraw drains all collateral (Medium)"
    - "Debt DAO -- ERC777 hook lets lender draw extra credit tokens from borrower (Medium)"
    - "Debt DAO -- ERC777 reentrancy in _close lets lender steal other lenders' funds (Medium)"
    - "RabbitHole -- ERC777/ERC1155 rewardToken reentrancy locks funds permanently (Medium)"
    - "Reserve -- ERC777 reentrancy during redeem() steals RToken holders' funds (Medium)"
    - "Sense -- Reentrancy in GClaimManager exit() via token callback (Medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc777, reentrancy, hooks, erc1820, callback, CEI]

- id: token-010
  pattern: permit-frontrun-dos
  name: "ERC-2612 permit front-running causes DoS on bundled operations"
  causa_raiz: "Permit signatures are deterministic and publicly visible in the mempool. When permit() is called as part of a multi-step function (e.g., removeLiquidityWithPermit), an attacker can extract the signature, call permit() directly to consume the nonce, and the original bundled transaction reverts because the permit has already been used."
  como_funciona: |
    1. User signs ERC-2612 permit and submits tx calling functionWithPermit(amount, deadline, v, r, s).
    2. Attacker monitors mempool, extracts permit parameters from pending tx.
    3. Attacker front-runs by calling token.permit(owner, spender, amount, deadline, v, r, s) directly.
    4. Attacker's tx succeeds, consuming the nonce.
    5. User's original tx reverts because permit() fails (nonce already used).
    6. User loses gas fees and operation is DoS'd.
  invariante: |
    // Permit calls in multi-step functions must not revert the entire operation
    // try token.permit(...) catch {} -- permit failure should be non-fatal
    assert(functionSucceeds || allowanceAlreadySufficient);
  que_mirar:
    - "rg 'permit\\(' --type sol -B 2 -A 2 — luego buscar manualmente si está dentro de try/catch"
    - "Is permit() wrapped in try/catch? Patrón correcto: try { token.permit(...) } catch { ... }"
    - "Does the function check token.allowance(owner, spender) >= amount AFTER el catch?"
    - "rg 'WithPermit|withPermit|_permit' --type sol"
    - "NOTA: 'rg permit | rg -v try|catch' NO detecta si try/catch está en líneas diferentes"
  como_se_arregla: "Wrap permit() in try/catch. If permit reverts, check if allowance is already sufficient (attacker's front-run still granted the approval). Pattern: try token.permit(...) catch {} require(token.allowance(owner, spender) >= amount)."
  trampas:
    - "This is a well-documented pattern (Trust Security Jan 2024). Judges may mark as informational if impact is just gas griefing."
    - "If the protocol already wraps permit in try/catch, not a finding."
    - "Front-running only works on chains with public mempools (not on L2s with private sequencers)."
  solodit_ids: []
  incidentes:
    - "Audit 507 (RouterV2) -- removeLiquidityWithPermit DoS via permit front-running (Medium)"
    - "EYWA (RouterV2) -- permit front-running blocks start() function (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc2612, permit, frontrunning, dos, signature, nonce]

- id: token-011
  pattern: malicious-token-injection-dos
  name: "Malicious/weird token injection bricks protocol operations"
  causa_raiz: "Protocol accepts arbitrary token deposits without validation. Attacker deposits a malicious ERC20 (reverting on transfer, zero-transfer-reverting, or ERC721 masquerading as ERC20) which poisons the token list. Subsequent operations iterate all tokens and revert on the malicious one, bricking payouts/claims for all users."
  como_funciona: |
    1. Protocol allows anyone to deposit/fund with any ERC20 token address.
    2. Attacker deposits a malicious token that: (a) reverts on transfer(), or (b) reverts on zero-amount transfer, or (c) is actually an ERC721.
    3. Malicious token gets added to protocol's internal token address list.
    4. When protocol tries to pay out / claim, it iterates ALL token addresses.
    5. Transfer of malicious token reverts, reverting the entire payout transaction.
    6. All legitimate funds become permanently locked.
  invariante: |
    // Payout must succeed for all legitimate tokens even if one token transfer fails
    // for (token in tokenList) { try token.transfer(to, amount) catch {} }
    assert(legitimateTokensCanBeWithdrawn);
  que_mirar:
    - "Can anyone add arbitrary token addresses to the protocol?"
    - "Does payout/claim iterate a token list and revert if ANY transfer fails?"
    - "rg 'tokenAddresses|depositedTokens|tokenList' --type sol"
    - "rg 'for.*token.*transfer' --type sol"
    - "Are zero-amount transfers handled (some tokens revert on transfer(0))?"
  como_se_arregla: "Validate token addresses on deposit (whitelist). Use try/catch when iterating token transfers. Skip zero-balance tokens. Separate ERC20/ERC721 handling with interface checks."
  trampas:
    - "If protocol has a token whitelist controlled by admin, not exploitable by attacker."
    - "If payouts are per-token (not iterating a list), this pattern does not apply."
  solodit_ids: []
  incidentes:
    - "OpenQ -- Malicious ERC20 with blacklist bricks bounty payouts (High)"
    - "OpenQ -- Zero-transfer-reverting token permanently breaks percentage tier bounties (High)"
    - "OpenQ -- ERC721 deposited as ERC20 bricks all bounty payouts (High)"
    - "reNFT -- Malicious ERC20 tipped via Seaport locks rental assets forever (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, malicious-token, dos, griefing, token-list, iteration, zero-transfer]

- id: token-012
  pattern: solmate-no-code-check
  name: "Solmate SafeTransferLib does not check token contract existence"
  causa_raiz: "Solmate's SafeTransferLib (unlike OpenZeppelin's SafeERC20) does not verify that the token address contains code. Calls to a non-existent contract return success (EVM behavior), so transfers to/from destroyed or not-yet-deployed token addresses silently succeed without moving any tokens."
  como_funciona: |
    1. Protocol uses Solmate's SafeTransferLib for token transfers.
    2. Token address has no deployed code (self-destructed, not yet deployed, or wrong address).
    3. safeTransfer/safeTransferFrom is called -- EVM returns success (no revert).
    4. Protocol updates internal state as if transfer succeeded.
    5. No tokens actually moved -- attacker gets credit for phantom deposit.
    6. Attacker withdraws real tokens against phantom balance.
  invariante: |
    // Token address must have code before any transfer
    assert(token.code.length > 0);
  que_mirar:
    - "rg 'SafeTransferLib|safetransfer' --type sol | rg -i 'solmate'"
    - "Does the protocol use Solmate (not OpenZeppelin) for token transfers?"
    - "Is there an explicit code.length > 0 check before transfers?"
    - "Can token addresses be set by users or only by admin?"
  como_se_arregla: "Add explicit check: require(token.code.length > 0). Or switch to OpenZeppelin SafeERC20 which includes this check. Or validate token address on registration/deposit."
  trampas:
    - "Only applies to Solmate SafeTransferLib, NOT OpenZeppelin SafeERC20."
    - "If all token addresses are admin-set and verified, impact is limited."
    - "On some chains, CREATE2 makes address predictable but deployment timing matters."
  solodit_ids: []
  incidentes:
    - "SIZE -- Solmate SafeTransferLib no code check enables honeypot attack (Medium)"
    - "Bond Protocol -- Solmate safetransfer/safetransferfrom no code size check leads to funding loss (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, solmate, code-check, phantom-transfer, SafeTransferLib]

- id: token-013
  pattern: erc721-unsafe-transfer
  name: "Using ERC721 transferFrom instead of safeTransferFrom loses NFTs"
  causa_raiz: "ERC721.transferFrom() does not check if the recipient can handle ERC721 tokens (no onERC721Received callback). If the recipient is a contract without ERC721 receiver support, the NFT is permanently locked. Similarly, _mint() without _safeMint() has the same issue."
  como_funciona: |
    1. Protocol transfers an ERC721 using transferFrom() instead of safeTransferFrom().
    2. Recipient is a smart contract (multisig, vault, another protocol).
    3. Recipient contract does not implement onERC721Received().
    4. Transfer succeeds (NFT moves) but recipient cannot interact with or retrieve the NFT.
    5. NFT is permanently frozen in the recipient contract.
  invariante: |
    // All ERC721 transfers to external addresses must use safeTransferFrom
    // All ERC721 mints must use _safeMint
    assert(recipientCanHandleERC721 || recipientIsEOA);
  que_mirar:
    - "rg 'transferFrom.*tokenId|transferFrom.*nft' --type sol | rg -v 'safeTransferFrom'"
    - "rg '_mint\\(' --type sol | rg -v '_safeMint'"
    - "Does the protocol send NFTs to user-supplied addresses?"
    - "Could the recipient be a contract (multisig, vault)?"
  como_se_arregla: "Use safeTransferFrom() for all ERC721 transfers. Use _safeMint() for all ERC721 mints. Add onERC721Received check if custom transfer logic is needed."
  trampas:
    - "safeTransferFrom introduces a callback which can be a reentrancy vector -- evaluate tradeoff."
    - "If recipient is always an EOA (user wallet), transferFrom is safe."
    - "Some protocols intentionally use transferFrom to avoid reentrancy from onERC721Received."
  solodit_ids: []
  incidentes:
    - "DODO -- transferFrom instead of safeTransferFrom for ERC721 (Medium)"
    - "FrankenDAO -- ERC721 transferFrom freezes NFT in non-receiver contract (Medium)"
    - "FrankenDAO -- _mint instead of _safeMint for ERC721 freezes token (Medium)"
    - "Golom -- transferFrom instead of safeTransferFrom for ERC721 (Medium)"
    - "PoolTogether -- transferFrom on ERC721 awards may freeze in contract winners (Medium)"
    - "Putty -- _mint instead of _safeMint for position NFTs (Medium)"
    - "Holograph -- Incorrect ERC721 safeTransferFrom parameter order (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc721, nft, safeTransferFrom, safeMint, frozen-nft]

- id: token-014
  pattern: erc20-erc721-type-confusion
  name: "ERC721/ERC1155 accepted where only ERC20 expected causes permanent lock"
  causa_raiz: "ERC721 and ERC20 share overlapping function signatures (transferFrom, balanceOf). Protocol expecting only ERC20 can accidentally accept ERC721 tokens. The ERC721 gets deposited via transferFrom(from, to, tokenId) but cannot be withdrawn via ERC20 transfer(to, amount) which does not exist on ERC721."
  como_funciona: |
    1. Protocol function accepts any token address, expects ERC20.
    2. Attacker passes an ERC721 contract address.
    3. ERC721.transferFrom(from, to, tokenId) succeeds (same signature as ERC20).
    4. ERC721.balanceOf(address) returns count of NFTs (looks like ERC20 balance).
    5. On withdrawal, protocol calls token.transfer(to, amount) -- not present on ERC721.
    6. Withdrawal reverts, funds permanently locked.
  invariante: |
    // Token type must be validated before accepting deposits
    // assert(IERC165(token).supportsInterface(type(IERC20).interfaceId))
    // or assert(!IERC165(token).supportsInterface(type(IERC721).interfaceId))
  que_mirar:
    - "Does the protocol validate token type (ERC165 supportsInterface check)?"
    - "Can users provide arbitrary token addresses to deposit functions?"
    - "rg 'transferFrom.*amount|transferFrom.*_amount' --type sol"
    - "Are there separate code paths for ERC20 vs ERC721?"
  como_se_arregla: "Add ERC165 interface check to reject ERC721/ERC1155. Or maintain a strict token whitelist. Or use separate deposit functions for different token standards."
  trampas:
    - "If protocol has an admin-curated token whitelist, not exploitable."
    - "Some tokens support both ERC721 and ERC1155 (The Sandbox) -- check for dual-standard tokens."
  solodit_ids: []
  incidentes:
    - "OpenQ -- ERC721 deposited via fundBountyToken bricks all payouts (High)"
    - "Linea TokenBridge -- ERC721 bridged one-way, permanently stuck (High)"
    - "Infinity NFT Marketplace -- Dual ERC721/ERC1155 tokens break _transferNFTs (High)"
    - "Infinity NFT Marketplace -- _transferNFTs succeeds without actually transferring if token has no ERC721/1155 support (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc721, erc20, type-confusion, interface-check, ERC165]

- id: token-015
  pattern: mutable-decimals-attack
  name: "Untrusted token decimals() can be mutated intra-transaction"
  causa_raiz: "Protocol reads token.decimals() from an untrusted external contract without caching. If the token is malicious or upgradeable, decimals() can return different values within the same transaction, causing scaling calculations to use inconsistent bases."
  como_funciona: |
    1. Protocol calls token.decimals() multiple times during a single transaction.
    2. Malicious token returns 18 on first call (during deposit valuation).
    3. Malicious token returns 6 on second call (during share calculation).
    4. Protocol calculates shares based on 6 decimals but valued deposit at 18 decimals.
    5. Attacker receives 1e12x more shares than deserved.
    6. Attacker withdraws, draining pool.
  invariante: |
    // decimals() must be cached once and reused
    uint8 cachedDecimals = token.decimals(); // cache at registration
    // All subsequent uses must reference cachedDecimals, never re-call decimals()
    assert(usedDecimals == cachedDecimals);
  que_mirar:
    - "rg 'decimals\\(\\)' --type sol -- count calls per function"
    - "Is decimals() called more than once in the same code path?"
    - "Is the decimal value cached in storage at token registration time?"
    - "Can the token address be an upgradeable proxy (decimals could change)?"
  como_se_arregla: "Cache decimals() in an immutable variable at token registration/initialization. Never call decimals() on untrusted tokens during runtime calculations."
  trampas:
    - "If protocol only supports well-known tokens (USDC, WETH), risk is low."
    - "On-chain tokens with fixed decimals (non-upgradeable) cannot mutate."
    - "Connext finding: incorrect decimals in initializeSwap cannot be corrected -- design flaw, not attack."
  solodit_ids: []
  incidentes:
    - "Sense -- Untrusted ERC-20 decimals() return values mutated intra-transaction (High)"
    - "Connext -- Incorrect decimal in initializeSwap cannot be corrected, permanently wrong calculations (Medium)"
    - "Notional -- Typo checks primaryDecimals instead of secondaryDecimals, missing validation (Medium)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [token, decimals, mutable, cache, scaling, untrusted]

- id: token-016
  pattern: blacklist-freezes-protocol
  name: "USDC/USDT blacklist on single address freezes entire protocol flow"
  causa_raiz: "Protocol has a critical code path that MUST transfer tokens to a specific address (recipient, escrow, treasury). If that address gets added to USDC/USDT blacklist, the transfer reverts and the entire protocol operation (cancel, claim, settle) is permanently blocked."
  como_funciona: |
    1. Protocol function (cancel, settle, claim) must transfer USDC to recipient address.
    2. Recipient gets added to USDC blacklist (by Circle).
    3. USDC.transfer(recipient, amount) reverts.
    4. Entire function reverts -- no fallback path.
    5. All users' funds in that flow are permanently locked.
    6. Even admin cannot rescue because the function has no skip/alternative path.
  invariante: |
    // Critical operations must not be blockable by single-address token blacklist
    // assert(canCompleteWithout(specificRecipient)) or assert(hasAlternativePath)
  que_mirar:
    - "rg 'cancel|settle|claim|close' --type sol -- do they transfer tokens?"
    - "Is there a single recipient whose blacklisting blocks everyone?"
    - "Are there try/catch or pull-over-push patterns for token distributions?"
    - "rg 'safeTransfer.*recipient|transfer.*lender|transfer.*borrower' --type sol"
  como_se_arregla: "Use pull-over-push pattern (recipients claim their own funds). Add try/catch on individual transfers. Store failed transfers in escrow mapping for later claim. Provide admin rescue function."
  trampas:
    - "This extends token-007 (pausable/blacklistable) but is about SPECIFIC address blacklisting, not global pause."
    - "Many judges accept this as a known centralization risk and mark informational."
    - "Only report if there is a concrete flow where one blacklisted address blocks OTHER users."
  solodit_ids: []
  incidentes:
    - "NounsDAO -- USDC blacklisted recipient blocks cancel() for everyone (Medium)"
    - "reNFT -- Blocklisted payment ERC20 recipient causes rented NFT to be stuck in Safe (Medium)"
    - "SIZE -- Bidders cannot withdraw unused funds if one token transfer fails (High)"
  severidad: medium
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [token, blacklist, USDC, USDT, dos, frozen-funds, pull-pattern]

- id: token-017
  pattern: deposit-same-token-double-accounting
  name: "depositToken == rewardToken or collateralToken causes double-counting"
  causa_raiz: "Protocol treats deposit token and reward/collateral token as independent, but does not handle the case where they are the same address. Functions that calculate 'excess' or 'available' balance for one role include tokens earmarked for the other role, enabling extraction of funds belonging to other users."
  como_funciona: |
    1. Protocol has depositToken and rewardToken as separate concepts.
    2. Admin or design allows same token address for both roles.
    3. recoverTokens() / sweep() calculates excess as balanceOf(this) - depositedAmount.
    4. But rewardToken balance is ALSO in balanceOf(this).
    5. Function treats reward balance as "excess deposit" (or vice versa).
    6. Attacker extracts tokens belonging to the other accounting category.
  invariante: |
    // If depositToken == rewardToken, excess calculation must account for both
    // uint256 excess = balance - depositAccounting - rewardAccounting;
    assert(recoverableAmount <= balance - totalDeposits - totalRewards);
  que_mirar:
    - "rg 'recoverToken|rescueToken|sweep|skim|excess' --type sol"
    - "Can depositToken == rewardToken? Is there a check preventing it?"
    - "rg 'balanceOf.*address.*this.*sub|balanceOf.*this.*minus' --type sol"
    - "How is 'excess' or 'recoverable' balance calculated?"
  como_se_arregla: "Either prohibit depositToken == rewardToken with require(). Or calculate excess accounting for ALL reservations: excess = balance - sum(all_reserved_amounts)."
  trampas:
    - "If protocol explicitly requires different tokens, not a finding."
    - "Admin-only token setting may reduce severity."
  solodit_ids: []
  incidentes:
    - "Streaming (C4) -- recoverTokens() double-counts when depositToken == rewardToken, draining funds (High)"
    - "Amun -- Unused ERC20 tokens not refunded; same-token overlap allows theft (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, accounting, double-counting, same-token, recover, sweep]

- id: token-018
  pattern: missing-return-value-wsteth-adapter
  name: "Missing or wrong return value in token wrapper/adapter silently zeros amount"
  causa_raiz: "Token adapter/wrapper function forgets to return the converted amount. Caller receives default value (0) and proceeds with zero-amount operations. In Solidity, a function declared as returning uint256 that does not explicitly return a value will return 0."
  como_funciona: |
    1. Token adapter wraps underlying token (e.g., stETH -> wstETH).
    2. Wrapper function performs the wrap but FORGETS to return the resulting amount.
    3. Caller receives 0 as the return value (Solidity default).
    4. Caller uses 0 as the deposit amount, minting 0 shares.
    5. User loses their wrapped tokens (sent to adapter) but receives nothing.
  invariante: |
    // Every function with a return value must explicitly return a non-zero value on success
    // assert(returnedAmount > 0) when inputAmount > 0
  que_mirar:
    - "rg 'function wrap|function unwrap|function convert' --type sol"
    - "Do wrapper functions have return statements for ALL code paths?"
    - "Are return values used by callers (not discarded)?"
    - "Compile with warnings enabled -- missing return triggers a warning"
  como_se_arregla: "Add explicit return statement. Enable compiler warnings for missing returns. Test that wrapper return values match actual token balance changes."
  trampas:
    - "Solidity 0.8+ may warn but does not error on missing return."
    - "If return value is discarded by caller, the missing return is harmless."
  solodit_ids: []
  incidentes:
    - "Sense WstETHAdapter -- wrapUnderlying() missing return value zeros out deposit (High)"
    - "BadgerDAO -- WrappedIbbtcEth stale pricePerShare used for mint/burn, wrong conversion (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, wrapper, adapter, return-value, silent-zero, wstETH]

- id: token-019
  pattern: erc1155-batch-callback-reentrancy
  name: "ERC1155 safeTransferFrom/safeBatchTransfer callbacks enable reentrancy"
  causa_raiz: "ERC1155 safeTransferFrom and safeBatchTransferFrom invoke onERC1155Received/onERC1155BatchReceived on the recipient. If the protocol transfers ERC1155 tokens before updating state, the recipient contract can re-enter during the callback, similar to ERC777 but via ERC1155 hooks."
  como_funciona: |
    1. Protocol uses ERC1155 safeTransferFrom to distribute rewards/assets.
    2. Transfer triggers onERC1155Received callback on recipient contract.
    3. Recipient re-enters the protocol during callback.
    4. Protocol state has not been updated yet (transfer happened before state update).
    5. Attacker exploits stale state to claim again or manipulate balances.
  invariante: |
    // State must be updated BEFORE ERC1155 safeTransfer calls
    // assert(stateUpdated == true) before any safeTransferFrom
  que_mirar:
    - "rg 'safeTransferFrom.*1155|safeBatchTransferFrom' --type sol"
    - "Is state updated BEFORE or AFTER the ERC1155 transfer?"
    - "Is there a nonReentrant guard on the function?"
    - "rg 'onERC1155Received|onERC1155BatchReceived' --type sol"
  como_se_arregla: "Follow CEI pattern: update all state before calling safeTransferFrom. Apply nonReentrant modifier. Consider using transfer() (without safe) if reentrancy risk outweighs receiver-check benefit."
  trampas:
    - "If nonReentrant is present on all ERC1155-interacting functions, not exploitable."
    - "Unlike ERC777, ERC1155 callbacks are expected and well-known -- judges may expect protocols to handle them."
  solodit_ids: []
  incidentes:
    - "Bridge Mutual -- ERC1155 safeTransferFrom callback reentrancy blocks all rewards (High)"
    - "Sudoswap LSSVM2 -- ERC1155 onERC1155BatchReceived reentrancy via two pairs (Medium)"
    - "ENS NameWrapper -- ERC1155 re-entrancy in _transferAndBurnFuses creates fake subdomain tokens (High)"
    - "RabbitHole -- ERC1155 rewardToken reentrancy locks contract funds (Medium)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc1155, reentrancy, callback, safeTransferFrom, CEI]

- id: token-020
  pattern: approval-shadow-storage
  name: "Custom ERC20 approval uses wrong storage mapping (shadow allowance)"
  causa_raiz: "Contract inherits OpenZeppelin ERC20 but also declares its own internal allowances mapping. approve() writes to the custom mapping while transferFrom() reads from the inherited mapping (or vice versa). Allowances are effectively split across two storage locations."
  como_funciona: |
    1. Contract inherits from OpenZeppelin ERC20 (has _allowances mapping).
    2. Developer adds a separate internal mapping(address => mapping(address => uint256)) allowances.
    3. Custom approve() writes to the developer's mapping.
    4. transferFrom() uses inherited _allowances (OpenZeppelin) which is still 0.
    5. All transferFrom calls fail -- or worse, inherited mapping has stale approvals.
    6. Users cannot transfer tokens, or old approvals persist unexpectedly.
  invariante: |
    // allowance(owner, spender) must equal the value set by the most recent approve(spender, amount)
    // assert(token.allowance(owner, spender) == lastApprovedAmount)
  que_mirar:
    - "rg 'mapping.*address.*mapping.*address.*uint.*allowance' --type sol"
    - "Does the contract declare its own allowances mapping alongside inherited ERC20?"
    - "Does approve() call super.approve() or write to a custom mapping?"
    - "Do transferFrom and approve use the SAME storage location?"
  como_se_arregla: "Remove duplicate allowances mapping. Use super._approve() for all approval logic. Or fully override both approve() and transferFrom() to use the same storage."
  trampas:
    - "This is rare but catastrophic when it occurs."
    - "Only applies to custom ERC20 implementations, not standard OpenZeppelin usage."
  solodit_ids: []
  incidentes:
    - "BadgerDAO -- approve uses internal _shares not rebalanced amount, spender spends more than intended (High)"
  severidad: high
  confianza: media
  verificado: true
  fuente: "Solodit"
  tags: [token, approval, storage, shadow, mapping, ERC20-custom]

- id: token-021
  pattern: token-transfer-to-incompatible-contract
  name: "ERC20 transferred to contract that cannot handle or return them"
  causa_raiz: "Protocol transfers ERC20 tokens to a contract address that has no mechanism to handle, forward, or return those tokens. Unlike ERC721's safeTransferFrom, ERC20 has no receiver callback, so tokens sent to incompatible contracts are silently and permanently locked."
  como_funciona: |
    1. Protocol transfers ERC20 tokens to a contract address (manager, escrow, module).
    2. Receiving contract has no function to transfer ERC20 out.
    3. Tokens arrive successfully but are permanently stuck.
    4. No recovery mechanism exists in either the sending or receiving contract.
  invariante: |
    // Every contract that receives ERC20 must have a path to transfer them out
    // assert(receivingContract.canTransferERC20Out() == true)
  que_mirar:
    - "Where do ERC20 transfers send tokens? Is the recipient a contract?"
    - "Does the receiving contract have transfer/withdraw/rescue functions for ERC20?"
    - "rg 'safeTransfer.*address.*contract|transfer.*manager|transfer.*escrow' --type sol"
  como_se_arregla: "Ensure receiving contract can handle ERC20 (has withdraw/rescue function). Or transfer to the final recipient directly. Add rescue functions to all contracts that hold tokens."
  trampas:
    - "If receiving contract is upgradeable, admin can add rescue function later -- lower severity."
    - "If amounts are small (dust), may be informational."
  solodit_ids: []
  incidentes:
    - "EYWA -- ERC20 transferred to s_emissionManager which cannot handle them (High)"
    - "Backed Protocol -- safeTransferFrom traps fees in Papr Controller with no recovery (Medium)"
    - "NounsDAO -- Extra funds sent to Payer contract cannot be withdrawn without canceling stream (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc20, stuck-funds, incompatible-receiver, rescue]

- id: token-022
  pattern: low-decimal-reward-truncation-griefing
  name: "Low-decimal reward tokens truncated to zero via frequent claim griefing"
  causa_raiz: "Reward distribution divides accrued rewards by totalStaked and elapsed time. For low-decimal tokens (USDC 6, WBTC 8), small time intervals or large totalStaked cause the per-user reward to round down to zero. An attacker can call getRewardFor(victim) repeatedly at short intervals to force zero-reward claims, resetting the victim's accrued state each time."
  como_funciona: |
    1. Protocol distributes reward tokens (USDC/WBTC) proportional to stake and elapsed time.
    2. Reward calculation: earned = rewardRate * elapsed * userStake / totalStaked.
    3. For 6-decimal USDC with high totalStaked, earned rounds to 0 for short elapsed periods.
    4. Attacker calls public getRewardFor(victim) every few seconds.
    5. Each call triggers updateReward(victim), setting victim's rewards to 0 and resetting their reward checkpoint.
    6. Victim never accumulates enough for a non-zero reward amount.
    7. Reward tokens remain in contract forever, effectively stolen from victim.
  invariante: |
    // Reward claim must not be callable by non-staker for another user, OR
    // rewards[user] must only reset when actual transfer occurs
    assert(msg.sender == account || rewardAmount > 0);
  que_mirar:
    - "rg 'getRewardFor|claimFor' --type sol -- is it publicly callable with arbitrary address?"
    - "Does updateReward reset user checkpoint even when reward == 0?"
    - "What decimal precision do reward tokens have?"
    - "rg 'rewardPerToken.*totalSupply' --type sol -- check for truncation with low decimals"
  como_se_arregla: "Restrict getRewardFor to msg.sender or approved operators. Or: only update reward checkpoint when actual non-zero transfer occurs. Use higher precision internal accounting (1e18 scaled) before converting to token decimals."
  trampas:
    - "If getRewardFor is onlyOwner or restricted, not exploitable"
    - "18-decimal reward tokens are generally safe from this truncation"
  solodit_ids: []
  incidentes:
    - "Summer.fi Governance V2 — getRewardFor callable by anyone, attacker repeatedly claims zero rewards for victim, denying USDC/WBTC accrual (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, rewards, low-decimals, truncation, griefing, precision]

- id: token-023
  pattern: erc1155-expiry-balance-desync
  name: "ERC1155 expiry tracking desynced from balance — expired tokens transferable"
  causa_raiz: "Contract maintains dual tracking: ERC1155 standard balances mapping AND a custom expiry group array. Prune function removes expired groups from custom tracking but does not call ERC1155 _burn(), leaving the standard balance unchanged. Expired tokens remain transferable via the standard ERC1155 interface."
  como_funciona: |
    1. Protocol extends ERC1155 with per-group expiration times.
    2. _pruneGroups() iterates groups, removes expired ones, emits ExpiredTokensBurned event.
    3. However, _pruneGroups() never calls _burn() on the parent ERC1155 contract.
    4. ERC1155 balanceOf(user, id) still returns the full amount including expired tokens.
    5. User calls safeTransferFrom to move expired tokens to another address.
    6. Recipient receives tokens that should have been expired/burned.
  invariante: |
    // After pruning, ERC1155 balance must equal sum of non-expired group balances
    assert(balanceOf(user, id) == sumActiveGroupBalances(user, id));
  que_mirar:
    - "rg 'pruneGroups|expire|expiration' --type sol"
    - "Does expiry logic call _burn() or just remove from custom tracking?"
    - "Are there two separate balance systems (ERC1155 + custom)?"
    - "Can expired tokens still be transferred via standard ERC1155 functions?"
  como_se_arregla: "Call _burn(account, id, expiredAmount) inside the prune function to keep ERC1155 balances in sync. Or override safeTransferFrom to prune before checking balance."
  trampas:
    - "If protocol only uses custom tracking for balanceOf (not ERC1155 standard), the desync may not matter"
    - "If tokens are non-transferable, impact is limited"
  solodit_ids: []
  incidentes:
    - "Radius Technology EVMAuth — _pruneGroups removes expired groups but ERC1155 balance unchanged, expired auth tokens transferable (High)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, erc1155, expiry, balance-desync, dual-tracking, burn]

- id: token-024
  pattern: fee-on-transfer-accounting-mismatch
  name: "Fee-on-transfer token breaks internal accounting — received < expected"
  causa_raiz: "Protocol records the transfer amount parameter as the deposited amount without checking actual balance change. Fee-on-transfer tokens (USDT, deflationary tokens) deliver less than the requested amount. Internal accounting credits more than actually received, creating a deficit exploitable by last withdrawers."
  como_funciona: |
    1. User deposits 1000 USDT (2% fee-on-transfer).
    2. Protocol records deposit = 1000 in internal accounting.
    3. Actual tokens received = 980 (20 taken as transfer fee).
    4. Protocol owes 1000 but only holds 980.
    5. First users withdraw normally. Last user finds insufficient balance.
    6. Alternatively: attacker exploits the 20-token gap to extract excess funds.
  invariante: |
    // Actual balance change must match recorded amount
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(user, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;
    assert(recordedDeposit == received);
  que_mirar:
    - "rg 'safeTransferFrom.*amount' --type sol -- does it check balance before/after?"
    - "Does protocol claim to support arbitrary ERC20s or fee-on-transfer tokens?"
    - "rg 'balanceOf.*before|balanceOf.*after' --type sol -- balance diff pattern present?"
    - "Is there a strict balance validation after transfers (revert if less received)?"
  como_se_arregla: "Use balance-before/after pattern: record actual received amount. Or explicitly block fee-on-transfer tokens. Or document that only standard ERC20s are supported."
  trampas:
    - "If protocol uses token whitelist excluding fee-on-transfer tokens, not a finding"
    - "USDT fee is currently 0% but can be activated — consider future risk"
    - "Most judges require the protocol to explicitly claim fee-on-transfer support for this to be valid"
  solodit_ids: []
  incidentes:
    - "Ammplify — RFT library strict balance check causes revert for all fee-on-transfer tokens, DoS (Medium)"
    - "Superform v2 — assumes standard ERC20, loss of funds with fee-on-transfer (Low)"
    - "NUTS Finance — mint/swap/redeem not accounting for fee-on-transfer, unpredictable behavior (Low)"
    - "Sequence Trail Contracts — raw transferFrom reverts on USDT non-standard return (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, fee-on-transfer, accounting, balance-check, USDT, deflationary]

- id: token-025
  pattern: permit-bypass-paused-token
  name: "ERC2612 permit() bypasses paused token's approve() restriction"
  causa_raiz: "Token overrides approve() with whenNotPaused modifier but inherits permit() from Solmate/OZ without overriding. While the token is paused, users cannot call approve() but CAN call permit() to set arbitrary allowances, pre-arming drains that execute instantly when unpaused."
  como_funciona: |
    1. Token pauses all transfers and approvals during an emergency.
    2. approve() correctly reverts due to whenNotPaused modifier.
    3. permit() is inherited from parent (Solmate ERC20) without override.
    4. Attacker calls permit() with pre-signed signatures while token is paused.
    5. Allowances are set despite the pause.
    6. When token unpauses, attacker immediately drains approved tokens via transferFrom.
  invariante: |
    // If approve() is paused, permit() must also be paused
    // assert(!paused || permit.reverts)
  que_mirar:
    - "Does token override approve() with whenNotPaused but NOT override permit()?"
    - "rg 'whenNotPaused.*approve|approve.*whenNotPaused' --type sol"
    - "rg 'permit' --type sol -- is permit() overridden with same pause check?"
    - "Which ERC20 base is used (Solmate, OZ)? Does it include permit?"
  como_se_arregla: "Override permit() to include the same whenNotPaused check. Or override _approve() internally to enforce pause on all allowance-setting paths."
  trampas:
    - "If token does not have pause functionality, not applicable"
    - "If permit is not supported (no ERC2612), not applicable"
  solodit_ids: []
  incidentes:
    - "ManifestFinance USHToken — approve() gated by whenNotPaused but permit() inherited from Solmate without override, allowances settable while paused (Low)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, permit, pause, bypass, allowance, ERC2612, Solmate]

- id: token-026
  pattern: blacklist-bypass-deposit-receiver-mismatch
  name: "Blacklisted user bypasses restriction by depositing to different receiver"
  causa_raiz: "Deposit/mint function checks blacklist for SOFT_RESTRICTED role but not FULL_RESTRICTED role, or only checks msg.sender but not the receiver parameter. Fully blacklisted user deposits tokens to a clean address they control, bypassing the blacklist entirely."
  como_funciona: |
    1. Admin blacklists user with FULL_RESTRICTED_STAKER_ROLE.
    2. User calls deposit(amount, cleanAddress) with a non-blacklisted receiver.
    3. _deposit() only checks SOFT_RESTRICTED_STAKER_ROLE, not FULL_RESTRICTED.
    4. Or: _deposit() checks caller but not receiver.
    5. Deposit succeeds. User retains access via the clean address.
    6. User continues earning yield/rewards through the protocol despite blacklist.
  invariante: |
    // Both caller AND receiver must pass ALL blacklist checks
    assert(!hasRole(FULL_RESTRICTED, caller) && !hasRole(FULL_RESTRICTED, receiver));
    assert(!hasRole(SOFT_RESTRICTED, caller) && !hasRole(SOFT_RESTRICTED, receiver));
  que_mirar:
    - "rg 'RESTRICTED|blacklist|blocklist' --type sol in deposit/mint functions"
    - "Does deposit check BOTH caller and receiver?"
    - "Are ALL restriction levels checked (soft AND full)?"
    - "Can a user specify a different receiver than msg.sender?"
  como_se_arregla: "Check all blacklist roles for both msg.sender and receiver in _deposit(). Add same checks to mint(), transfer(), and any function accepting a receiver parameter."
  trampas:
    - "If deposit does not accept a receiver parameter (always msg.sender), partial mitigation"
    - "If there is only one blacklist role, verify it covers all cases"
  solodit_ids: []
  incidentes:
    - "Neutrl Protocol sNUSD — _deposit() checks SOFT_RESTRICTED but not FULL_RESTRICTED, blacklisted users deposit to other addresses (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, blacklist, bypass, deposit, receiver, access-control]

- id: token-027
  pattern: rebasing-token-negative-rebase-underflow
  name: "Negative rebase causes withdrawal underflow — funds stuck"
  causa_raiz: "Vault tracks deposits at deposit-time pricing. Withdrawal converts USD value back to token units at current price. After negative rebase (price decrease), more token units are needed to represent the same USD value. Subtraction of withdrawAssetValue from assetDepositNet underflows because current-price units > deposit-price units."
  como_funciona: |
    1. User deposits 100 USDY at price $1.05 per token. Vault records assetDepositNet = 100.
    2. Negative rebase occurs: USDY price drops to $0.95.
    3. User requests withdrawal of $100 worth.
    4. At new price: withdrawAssetValue = 100 / 0.95 = 105.26 tokens.
    5. assetDepositNet -= 105.26 underflows (100 - 105.26 < 0).
    6. Transaction reverts. All withdrawals for this vault are permanently blocked.
  invariante: |
    // Withdrawal amount in token units must not exceed tracked deposit units
    // Or: use signed arithmetic / saturating subtraction
    assert(withdrawAssetValue <= VaultData.assetDepositNet || useSaturatingSub);
  que_mirar:
    - "rg 'rebasingMultiplier|rebase|rebasing' --type sol"
    - "Does vault track deposits in token units but calculate withdrawals at current price?"
    - "Can the underlying token decrease in value (negative rebase)?"
    - "Are there unchecked subtractions in withdrawal paths?"
  como_se_arregla: "Track deposits and withdrawals in USD-normalized units, not token units. Or use saturating subtraction. Or handle the negative-rebase case explicitly by capping withdrawal to available units."
  trampas:
    - "If protocol only supports non-rebasing tokens, not applicable"
    - "If underlying asset is guaranteed to only appreciate (e.g., stETH), low risk but still possible during slashing"
  solodit_ids: []
  incidentes:
    - "STBL Protocol — negative rebase on USDY/oUSG causes withdrawERC20 underflow, all withdrawals blocked (Medium)"
    - "Securitize DSToken Rebasing — token value locks restrict unlocked tokens after negative rebase (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, rebasing, negative-rebase, underflow, withdrawal, stuck-funds]

- id: token-028
  pattern: cross-chain-burn-mint-supply-inflation
  name: "Cross-chain bridge burn/mint inflates totalIssuance cap on both chains"
  causa_raiz: "Token's totalIssuance counter increments on mint but does not decrement on burn. When bridging, source chain burns tokens and destination chain mints (issues) new tokens, incrementing totalIssuance on the destination. Repeated bridging back and forth inflates totalIssuance on both chains until the cap is reached, blocking all further issuance and bridging."
  como_funciona: |
    1. Token has totalIssuance counter that only increments (tracks lifetime mints, not supply).
    2. totalIssuance is used to enforce a maximum cap.
    3. User bridges 1000 tokens from Chain A to Chain B: burn on A, issueTokens on B (+1000 to B's totalIssuance).
    4. User bridges back from B to A: burn on B, issueTokens on A (+1000 to A's totalIssuance).
    5. After N round trips, both chains have totalIssuance += N*1000.
    6. Cap is reached on one chain. All further issuances and bridges revert.
  invariante: |
    // totalIssuance must account for burns, OR
    // bridge mints must not increment totalIssuance
    assert(totalIssuance == totalMinted - totalBurned);
  que_mirar:
    - "rg 'totalIssuance|totalMinted|totalIssued' --type sol"
    - "Does totalIssuance decrement on burn?"
    - "Is totalIssuance used for cap enforcement?"
    - "Does bridge receiver call issueTokens which increments totalIssuance?"
  como_se_arregla: "Decrement totalIssuance on burn. Or use totalSupply() (which accounts for burns) for cap checks. Or create a separate bridge mint path that does not increment totalIssuance."
  trampas:
    - "If there is no issuance cap, the inflation is cosmetic only"
    - "If bridge uses lock/unlock instead of burn/mint, not affected"
  solodit_ids: []
  incidentes:
    - "Securitize Bridge CCTP — bridging DSToken back-and-forth inflates totalIssuance on both chains, cap reached, blocking issuance (Medium)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit"
  tags: [token, bridge, burn-mint, totalIssuance, cap, supply-inflation, cross-chain]

- id: token-029
  pattern: permit2-block-number-nonce-replay
  name: "Permit2 signature replayable within same block due to block.number used as nonce"
  causa_raiz: >
    Permit2 requires a nonce to prevent signature replay. If a protocol uses block.number
    as the nonce, any transaction in the SAME block can reuse the same nonce — because
    block.number does not change within a block. An attacker can observe a signed Permit2
    order in the mempool and submit a frontrunning or parallel transaction in the same block
    that replays the signature to steal the user's tokens or execute the order for their
    own benefit.
  como_funciona: |
    1. User signs Permit2 order with nonce = block.number = 12345.
    2. Protocol submits the tx. Attacker sees it in mempool.
    3. Attacker crafts a duplicate transaction with same permit2 signature, same nonce.
    4. Both transactions are in block 12345 — nonce is identical.
    5. Permit2 cannot distinguish the two: one or both succeed (depends on Permit2 nonce type).
    6. If attacker's tx is frontrun: user's allowance is consumed to fill attacker's order.
    7. Result: user's tokens transferred to attacker's chosen destination.
  invariante: |
    // Nonce must be globally unique and non-predictable
    // block.number is neither — it is shared by ALL txs in the block
    // Correct: use a monotonic counter or random nonce
    assert(nonce != block.number && nonce != block.timestamp);
  que_mirar:
    - "What value is used as the nonce when constructing a Permit2 order?"
    - "Is block.number, block.timestamp, or any other block-scoped value used as nonce?"
    - "Is the nonce checked for uniqueness across all txs in the same block?"
    - "rg 'block.number|block.timestamp' --include='*.sol' | grep -i 'nonce\\|permit\\|order'"
  como_se_arregla: "Use a user-controlled monotonic nonce counter (nonces[user]++). Or use a random uint256 (from a hash or user-provided). Never use block-scoped values (block.number, block.timestamp, block.prevrandao) as Permit2 nonces. See Permit2's SignatureTransfer: users must provide their own nonce."
  trampas:
    - "Permit2 has two nonce systems: PermitTransfer (user chooses nonce, must be unique) and PermitAllowance (monotonic counter). The attack applies to the former when protocol chooses the nonce."
    - "If the Permit2 order can only be filled once and nonce is marked used immediately, same-block replay is still possible for atomically frontrunnable orders"
    - "block.prevrandao / RANDAO on post-merge Ethereum is also predictable by validators — still not a good nonce"
  solodit_ids: []
  incidentes:
    - "Bunni (Pashov Group H-05) — BunniHook uses block.number as Permit2 nonce for Flood.bid orders, enabling same-block replay (HIGH)"
    - "Starbase (Consensys) — StarBaseDCA uses same permit2 signature for multiple claimTokens calls in same block (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Bunni Pashov Group H-05, Starbase Consensys audit"
  tags: [token, permit2, nonce, replay, block.number, same-block, signature]
  relacionado_con: [token-006, token-011]

- id: token-030
  pattern: blacklist-bypass-via-transferfrom-from-address
  name: "Blacklist enforcement missing on `from` address in transferFrom — blocked user can move funds via proxy"
  causa_raiz: >
    Blacklisted token implementations that override _transfer() or transfer() to check
    msg.sender/to but do NOT check the `from` address in transferFrom() allow a blacklisted
    user to authorize a third-party address (proxy) to call transferFrom(blacklistedUser, dest, amount).
    The blacklist check only verifies msg.sender (the proxy, not blacklisted) or the `to` address
    but misses the actual token owner (from). The blacklisted user effectively moves their
    funds through the proxy.
  como_funciona: |
    1. User is blacklisted. Their tokens should be frozen.
    2. User approves a proxy contract (or accomplice address) for their entire balance.
    3. Proxy calls transferFrom(blacklistedUser, attacker, amount).
    4. transferFrom checks: require(!blacklisted[msg.sender]) → proxy not blacklisted, passes.
    5. Tokens successfully move from blacklisted user to attacker's address.
    6. Freeze mechanism is completely bypassed.
    7. In cases like USDC/USDT: the issuer blacklists to freeze sanctioned funds. This bypass
       allows sanctioned parties to exit their position before freezing takes effect.
  invariante: |
    // ALL three addresses must pass blacklist check in transferFrom
    require(!blacklisted[msg.sender], "sender blacklisted");
    require(!blacklisted[from], "from address blacklisted");
    require(!blacklisted[to], "to address blacklisted");
  que_mirar:
    - "In _transfer() or transferFrom(), does the blacklist check cover the `from` address?"
    - "Is the override applied to _update() (OZ v5) or _beforeTokenTransfer() (OZ v4)? Both must check `from`."
    - "For tokens that override only transfer() but not transferFrom(): transferFrom still works."
    - "rg 'blacklist\\|isBlacklisted\\|_blocked\\|blocked\\[' --type sol"
  como_se_arregla: "Check all three addresses in the transfer hook: from, to, msg.sender. Use OpenZeppelin's _update() override (v5) or _beforeTokenTransfer() (v4) which intercepts both transfer() and transferFrom(). Never rely on overriding only transfer()."
  trampas:
    - "OZ v5 introduced _update() which replaces _transfer() — protocols that upgraded OZ but kept old hooks are vulnerable"
    - "If the token is non-upgradeable and the bug is post-deployment, there is no fix — this is a permanent escape hatch"
    - "The reverse: missing `to` check means blacklisted addresses can RECEIVE tokens (separate issue)"
    - "For USDC/USDT clones: the blacklist bypass must happen before the actual blacklist tx confirms — time-sensitive frontrun"
  solodit_ids: []
  incidentes:
    - "Infinigold (Sigma Prime) — transferFrom() does not check `from` blacklist status; blacklisted users can move funds via allowances (HIGH)"
    - "Anzen Finance Protocol V2 (Halborn) — USDz and sUSDz _update() override missing `from` blacklist check, blocked users can still send tokens (HIGH)"
    - "ZeroLend (Immunefi) — ZeroLendToken whitelist logic inverted, treating it as blacklist; all intended-whitelist addresses are blocked (HIGH)"
  severidad: high
  confianza: alta
  verificado: true
  fuente: "Solodit: Infinigold Sigma Prime, Anzen Finance Halborn"
  tags: [token, blacklist, transferFrom, from-address, freeze, bypass, access-control]
  relacionado_con: [token-023, token-024, token-004]

- id: token-031
  pattern: erc4626-fee-on-transfer-underlying-accounting
  name: "ERC4626 vault totalAssets/shares break when underlying token charges transfer fee"
  causa_raiz: >
    ERC4626 vaults calculate shares to mint as `shares = assets * totalSupply / totalAssets`.
    This assumes `totalAssets` accurately reflects the vault's actual holdings. When the underlying
    asset is a fee-on-transfer (FoT) token, the vault receives LESS than the deposited amount.
    totalAssets is updated based on the REQUESTED amount, not the RECEIVED amount. This creates
    a persistent accounting mismatch: totalAssets > actualBalance. Future share conversions
    are based on inflated totalAssets, meaning early redeemers get more than their fair share
    while later redeemers receive less than expected or lose funds.
  como_funciona: |
    1. Vault has totalAssets=1000, totalShares=1000 (1:1 ratio). Token has 1% transfer fee.
    2. User deposits 100 tokens. Vault calls safeTransferFrom(user, vault, 100).
    3. Token transfers 99 to vault (1 fee deducted). Vault receives 99.
    4. But vault calls: shares = 100 * 1000 / 1000 = 100. totalAssets += 100 = 1100.
    5. totalAssets=1100 but actual balance=1099. Mismatch: 1 token.
    6. Compounded over many deposits: totalAssets >> actual holdings.
    7. First withdrawers get the correct amount. Last withdrawers face a shortfall.
    8. OR: attacker repeatedly deposits/withdraws to amplify the gap and drain the vault.
  invariante: |
    // Post-deposit: totalAssets must equal actual token balance
    uint256 balanceBefore = token.balanceOf(address(this));
    token.safeTransferFrom(user, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - balanceBefore;
    // shares must be based on `received`, not `amount`
    assert(received == amount); // OR handle the difference
    assert(totalAssets() == token.balanceOf(address(this)));
  que_mirar:
    - "Does the vault use the `amount` parameter or the actual received balance to update totalAssets?"
    - "Is there a post-transfer balance check: `received = balanceAfter - balanceBefore`?"
    - "Does the protocol documentation explicitly state FoT tokens are not supported? (if not, it's a bug)"
    - "For ERC7540 (async ERC4626): is the pending deposit tracked by requested or received amount?"
    - "rg 'safeTransferFrom|totalAssets|convertToShares' --type sol"
  como_se_arregla: "Measure actual received amount using pre/post balance snapshot: `uint received = after - before`. Use `received` (not `amount`) for share minting. For ERC7540, track requests in received units. Alternatively, explicitly revert for FoT tokens in the constructor."
  trampas:
    - "If the protocol explicitly documents 'FoT tokens not supported', this becomes informational — check scope"
    - "Some tokens have optional fees (off by default, can be enabled by governance) — document the assumption"
    - "For rebasing tokens (stETH): the accounting error is the opposite — tokens increase in value, shares become undervalued over time (beneficial to holders, not an attack)"
    - "ERC4626 canonical implementation does NOT handle FoT — any fork that doesn't add balance snapshots inherits this"
  solodit_ids: []
  incidentes:
    - "PoolTogether (Code4rena M-01) — Vault._deposit() uses requested amount not received amount for FoT underlying tokens (MEDIUM)"
    - "Vaultcraft (Zokyo) — ERC7540 virtual accounting breaks with FoT tokens: withdrawal/deposit amounts diverge (MEDIUM)"
    - "Primev FastSettlementV3 (Shieldify M-01) — FoT tokens break output guarantees and internal accounting in settlement vault (MEDIUM)"
    - "Tracer (Code4rena M-03) — InsuranceFund deposit() with deflationary token creates mismatch between expected and actual deposit (MEDIUM)"
  severidad: medium
  confianza: alta
  verificado: true
  fuente: "Solodit: PoolTogether Code4rena, Vaultcraft Zokyo, multiple ERC4626 audits"
  tags: [token, ERC4626, fee-on-transfer, totalAssets, shares, accounting, vault, deflationary]
  relacionado_con: [token-015, token-016, token-008]
```

---

## 2. Invariantes Clave

Sourced from Crytic/Trail of Bits `crytic_properties` (25 invariants).

### Supply Invariants

| ID | Invariant | Severity |
|----|-----------|----------|
| INV-ERC20-001 | Total supply constant for non-mintable/non-burnable tokens | Critical |
| INV-ERC20-002 | No single balance > totalSupply | Critical |
| INV-ERC20-003 | Sum of all balances <= totalSupply | Critical |
| INV-ERC20-004 | address(0) balance == 0 | Medium |

### Transfer Invariants

| ID | Invariant | Severity |
|----|-----------|----------|
| INV-ERC20-005 | transfer to address(0) reverts | High |
| INV-ERC20-006 | transferFrom to address(0) reverts | High |
| INV-ERC20-007 | Self-transfer preserves balance | High |
| INV-ERC20-008 | Self-transferFrom preserves balance | High |
| INV-ERC20-009 | transfer > balance reverts | Critical |
| INV-ERC20-010 | transferFrom > balance reverts | Critical |
| INV-ERC20-011 | Zero-amount transfer preserves balances | Medium |
| INV-ERC20-012 | Zero-amount transferFrom preserves balances | Medium |
| INV-ERC20-013 | transfer updates sender/receiver correctly | Critical |
| INV-ERC20-014 | transferFrom updates sender/receiver correctly | Critical |

### Approval Invariants

| ID | Invariant | Severity |
|----|-----------|----------|
| INV-ERC20-015 | approve sets correct allowance | High |
| INV-ERC20-016 | Second approve overwrites first | High |
| INV-ERC20-017 | transferFrom decreases allowance (except max) | Critical |
| INV-ERC20-024 | increaseAllowance adds correctly | High |
| INV-ERC20-025 | decreaseAllowance subtracts correctly | High |

### Mint/Burn Invariants

| ID | Invariant | Severity |
|----|-----------|----------|
| INV-ERC20-018 | burn decreases balance and totalSupply | Critical |
| INV-ERC20-019 | burnFrom decreases balance and totalSupply | Critical |
| INV-ERC20-020 | burnFrom decreases allowance (except max) | High |
| INV-ERC20-021 | mint increases balance and totalSupply | Critical |

### Pausable Invariants

| ID | Invariant | Severity |
|----|-----------|----------|
| INV-ERC20-022 | transfer reverts when paused | Critical |
| INV-ERC20-023 | transferFrom reverts when paused | Critical |

---

## 3. Checklist Rapido

When auditing any contract that interacts with ERC20 tokens, check every item:

### Token Interaction Safety
- [ ] Uses SafeERC20 for ALL transfer/transferFrom/approve calls? (`token-004`)
- [ ] Measures actual received amount (balanceBefore/After) for deposits? (`token-002`)
- [ ] Validates recipient != address(0)? (`token-005`)
- [ ] Handles tokens with no return value (USDT)? (`token-004`)

### Approval Management
- [ ] No infinite approvals to upgradeable/arbitrary-call contracts? (`token-008`)
- [ ] Approvals reset to 0 after use? (`token-008`)
- [ ] Uses increaseAllowance/decreaseAllowance instead of raw approve for changing allowances? (`token-001`)

### Token Diversity
- [ ] Handles different decimals correctly? (`token-006`)
- [ ] Handles fee-on-transfer tokens or explicitly excludes them? (`token-002`)
- [ ] Handles rebasing tokens or explicitly excludes them? (`token-003`)
- [ ] Has emergency path if pausable/blacklistable tokens freeze? (`token-007`)

### Accounting Integrity
- [ ] `token.balanceOf(contract) >= sum(internal_balances)` always? (INV-EXPLOIT-012)
- [ ] Self-transfers do not break accounting? (INV-ERC20-007, INV-ERC20-008)
- [ ] Zero-amount transfers do not break accounting? (INV-ERC20-011, INV-ERC20-012)
- [ ] totalSupply consistent with sum of balances? (INV-ERC20-003)

### Grep Patterns (quick codebase scan)
```bash
# Missing SafeERC20
rg '\.transfer\(|\.transferFrom\(|\.approve\(' --type sol | rg -v 'safeTransfer|safeApprove|forceApprove'

# Infinite approvals
rg 'type\(uint256\)\.max|MAX_UINT|0xfff' --type sol | rg 'approve'

# Hardcoded decimals
rg '1e18|1e6|1e8|10\*\*18|10\*\*6' --type sol

# Balance-based accounting (donation vector)
rg 'balanceOf\(address\(this\)\)' --type sol

# Missing zero-address check
rg 'transfer\(|transferFrom\(' --type sol | rg -v 'require.*!= address\(0\)|!= address\(0\)'
```

### Decision Tree: Is This a Real Finding?

1. **Does the protocol use SafeERC20?** If yes for ALL calls, skip `token-004`.
2. **Does the protocol have a token whitelist?** If yes, check what it excludes. May invalidate `token-002`, `token-003`, `token-006`.
3. **Is the approved contract upgradeable?** If no and immutable, `token-008` is informational.
4. **Can you construct a concrete PoC?** If not, do not submit. "Might be a problem" is not a finding.

---

## Solodit Verified Findings

### Maps to token-001 (approve race condition)
- **[MEDIUM] USDT approve(non-zero) reverts** — Tether's approve() reverts if current allowance is non-zero; contracts calling approve() without first setting to 0 permanently break for USDT after first use (multiple protocols: Notional, DualityFocus, Tessera, C4/Sherlock)
- **[HIGH] Broken token approval implementation** — Contracts reimplementing ERC20 approval with separate internal `allowances` mapping shadow inherited OpenZeppelin storage; approve() writes to wrong mapping while transferFrom reads from another (BeamNetwork, OpenZeppelin)
- **[MEDIUM] Collect front-run permit** — permitCollector increments nonce on each call; attacker front-runs collectWithPermit by calling permitCollector directly, consuming the nonce and making the bundled router call revert (Napier PT, Spearbit)

### Maps to token-002 (fee-on-transfer)
- **[HIGH] ERC777 reentrancy via fee-on-transfer balance check** — Bridge uses `balanceAfter - balanceBefore` pattern for FoT support, but ERC777 `tokensToSend` hook fires before balance update; attacker re-enters bridgeAsset during hook to create duplicate deposit leaves (PolygonZkEVM Bridge, Spearbit)
- **[MEDIUM] Fee-on-transfer tokens break accounting across 15+ protocols** — Consistent pattern: protocol records `amount` parameter as deposit instead of measuring `balanceAfter - balanceBefore`; over N deposits, protocol becomes insolvent by cumulative fee gap (BufferBinary, Harpie, Numoen, BullvBear, many more)
- **[HIGH] Incorrect receipt token minting for FoT tokens** — Bridge emits BridgedDeposit event with pre-fee amount; off-chain sequencer mints xTokens on L2 based on logged amount, creating systematic over-minting relative to actual bridged value (MultipliBridger, Cantina)
- **[MEDIUM] Self-lending reverts with fee-on-transfer paired tokens** — addLiquidityV2 transfers PAIRED_LP_TOKEN into pod then uses same amount for DEX_HANDLER liquidity; FoT reduces actual balance below expected, causing revert on every leverage operation (Peapods, Sherlock)

### Maps to token-003 (rebasing token)
- **[HIGH] Aave aToken rebasing breaks share accounting** — Protocol caches `sharesReceived` (always equals deposit amount for aTokens) as static balance, but `getTokensForShares` uses rebasing `IERC20(aToken).balanceOf(this)` as denominator; share ratio drifts over time (Sublime, C4)
- **[HIGH] AaveVault TVL not updated on deposit** — Attacker deposits, gets shares based on old cached TVL, then TVL updates to include aToken rebasing interest; attacker withdraws at new higher TVL, extracting interest risk-free in single tx (Mellow, C4)
- **[MEDIUM] Axelar cross-chain balance tracking broken for rebasing tokens** — LOCK_UNLOCK token manager assumes static 1:1 between escrowed ERC20 and bank representation; positive rebase creates extractable surplus, negative rebase blocks conversions (Axelar ITS, C4)
- **[HIGH] Anyone can steal all distributed rewards via self-transfer** — Self-transfer in ERC20RebaseDistributor: cached `rebasingStateTo.nShares` still holds pre-deduction value when adding shares to `to`, allowing balance doubling that drains all unminted rebase rewards (Ethereum Credit Guild, C4)
- **[HIGH] Rebaseable tokens cause unfair vesting and claim failures** — Vesting contract calculates amountToDistribute from current balanceOf + totalClaimedAmount; positive rebase between claims gives later claimers disproportionate share, negative rebase causes reverts (CryptoLegacy, Hacken)
- **[MEDIUM] Nibiru bank coin tracking broken for rebasing tokens** — convertCoinToEvmBornERC20 assumes static 1:1 between escrowed ERC20 and bank coins; rebase changes actual escrowed amount but bank coins remain unchanged, creating extraction or loss on conversion (Nibiru EVM, C4)

### Maps to token-004 (unchecked transfer return)
- **[HIGH] Token transfer logic incorrect for non-standard tokens** — Using `require(token.transferFrom(...))` fails for USDT (no return value); combined with missing FoT handling, BaseJackpot misaccounts balances on both axes (BaseJackpot, Spearbit)

### Maps to token-005 (zero-address transfer) / self-transfer
- **[HIGH] Mint PerpetualYieldTokens for free by self-transfer** — transfer() caches balances in memory; self-transfer sets `balanceOf[sender] = 0` then overwrites with `balanceOf[to] = cached + amount`, doubling balance each call (Timeless PYT, Spearbit)
- **[HIGH] AllocationVesting infinite points via self-transfer** — transferPoints deducts from `from` in storage but adds to `to` using stale memory cache of original balance; self-transfer doubles points on every call (Bima AllocationVesting, Pashov)

### Maps to token-006 (decimal mismatch)
- **[HIGH] Protocol assumes 18 decimals collateral** — Collateral ratio, drip feed, and reward calculations all assume 18 decimals; 6-decimal tokens (USDC) produce ratios off by 1e12, and >18-decimal tokens zero out rewards entirely (Taurus, Sherlock)

### Maps to token-008 (infinite approval danger)
- **[HIGH] Non-existing revenue contract bypasses owner split** — Calling claimRevenue with unregistered address reads default ownerSplit=0, sending 100% of push-payment revenue to treasury instead of escrow; borrower can zero out all lender revenue (Debt DAO Spigot, C4)

### New patterns not in existing bugs
- **[HIGH] Tokens stolen when depositToken == rewardToken** — recoverTokens() processes same token address twice (once as deposit, once as reward), calculating excess independently; combined excess exceeds actual available balance, enabling drain (Streaming, C4)
- **[HIGH] Flashloan end result not controlled** — Flash loan transfers tokens out and back with only `safeTransfer` success check; upgradeable tokens that report success but don't update internal accounting can steal entire pool balance (Ajna, Sherlock)
- **[MEDIUM] Tokens with multiple addresses bypass collateral swap check** — Protocol checks `collateralToken != swapToken` but tokens with dual addresses (rare but real) bypass the check, allowing collateral to be swapped away (Taurus SwapHandler, Sherlock)
- **[MEDIUM] cUSDCv3 type(uint256).max transfer edge case** — Tokens where `transfer(amount == max)` only transfers user's balance can be used to set pool accounting to max with dust, permanently blocking subsequent operations (Gitcoin Allo, Sherlock)
- **[HIGH] Attacker front-runs withdrawal by depositing to block same-block withdraw** — Anyone can call deposit() with any valid dNft ID using a fake vault/token; sets `idToBlockOfLastDeposit[id] = block.number`, blocking all withdrawals for that ID in current block at zero cost (DYAD VaultManagerV2, C4)
- **[HIGH] Users front-run LST/LRT price decreases** — Instant redemption via ETH buffer allows monitoring mempool for rebase() or price drop events and front-running to redeem PT/YT tokens before value loss is reflected (Napier adapters, Sherlock)
- **[HIGH] Bids blocked by depositing non-cash asset to liquidator** — Anyone can front-run auction bids by calling WrappedERC20Asset.deposit() to send non-cash assets to bidder account, failing the _ensureBidderCashBalance check and reverting the bid (Notional, Trail of Bits)
- **[HIGH] Profit distribution susceptible to MEV sandwich** — provideLiquidityWithFlashSwapFee called with 0 tolerance and block.timestamp deadline; sandwich bots manipulate pool price before and after, extracting ~20% of LP tokens (FlashSwapRouter, Spearbit)
- **[HIGH] Owner loses NFT after unlock but before withdrawal** — unlockProtectedListing sets listing owner to zero; isListing() no longer recognizes it as protected, allowing anyone to redeem/swap/buy the NFT before rightful owner calls withdraw (Flayer, Sherlock)
