# Solodit Complete Database — Categorized Index
# Total: 21,600 findings across 12 categories
# Generated: 2026-03-19 19:55

## Summary

| Category | Findings | % of Total |
|----------|----------|------------|
| vault | 843 | 3.9% |
| lending | 915 | 4.2% |
| oracle | 581 | 2.7% |
| flash_loan | 73 | 0.3% |
| access_control | 1,517 | 7.0% |
| dex_amm | 1,083 | 5.0% |
| staking | 1,198 | 5.5% |
| token | 607 | 2.8% |
| bridge | 433 | 2.0% |
| proxy_upgrade | 199 | 0.9% |
| zk_circuits | 178 | 0.8% |
| signature_replay | 358 | 1.7% |
| uncategorized | 13,615 | 63.0% |
| **TOTAL** | **21,600** | **100%** |

## vault (843 findings)

1. **[LOW]** [L-12] Loss of backing risk when underlying ERC4626 share price decreases — _Tangent_2025-10-30_ (Pashov Audit Group) [score:10]
2. **[HIGH]** [H-05] Fee calculation mismatch in `mint`, `deposit`, `redeem` and `withdraw` — _Astrolab_ (Pashov Audit Group) [score:10]
3. **[LOW]** [L-03] lack of slippage protection for `deposit`/`mint` and `withdraw`/`redeem` — _Ebisu_ (Pashov Audit Group) [score:9]
4. **[MEDIUM]** M-5: The `SuperPool` vault is not strictly ERC4626 compliant as it should be — _Sentiment V2_ (Sherlock) [score:9]
5. **[MEDIUM]** ERC4626 Vault Share Inflation — _Treehouse_ (SigmaPrime) [score:9]
6. **[MEDIUM]** [M-12] Unclaimed rewards handling issue in `AuraVault` contract functions (`AuraVault::deposit`, `Au — _LoopFi_ (Code4rena) [score:9]
7. **[LOW]** [11] `Vault.mint` and `Vault.finishRedeem` functions do not have slippage controls — _Karak_ (Code4rena) [score:9]
8. **[MEDIUM]** [M-17] Malicious Users Can Drain The Assets Of Vault. (Due to not being ERC4626 Complaint) — _Popcorn_ (Code4rena) [score:8]
9. **[MEDIUM]** Share to asset exchange rate can be skewed when totalSupply = 0 and totalAssets != 0 — _Morpho Vaults v2_ (Spearbit) [score:8]
10. **[HIGH]** H-6: User can lose all funds when creating or increasing compounded Maker position due to share infl — _Ammplify_ (Sherlock) [score:8]
11. **[HIGH]** [H-06] Fee target mismatch in `deposit`, `mint`, `withdraw`, `redeem` and `preview***` methods — _Astrolab_ (Pashov Audit Group) [score:8]
12. **[LOW]** [L-19] `Vault.sharePrice` incorrectly assumes 18 decimals for every vault — _Hyperstable_2025-02-26_ (Pashov Audit Group) [score:8]
13. **[MEDIUM]** [M-01] Funds not always in vault lead to share price calculation mess — _Omo_2025-01-25_ (Pashov Audit Group) [score:8]
14. **[LOW]** [10] `Vault` contract's withdrawal functions can be paused while its deposit functions are unpaused — _Karak_ (Code4rena) [score:8]
15. **[HIGH]** [H-05] Inflation of ggAVAX share price by first depositor — _GoGoPool_ (Code4rena) [score:7]
16. **[HIGH]** [H-05] Underlying assets stealing in `AutoPxGmx` and `AutoPxGlp` via share price manipulation — _Redacted Cartel_ (Code4rena) [score:7]
17. **[HIGH]** [C-01] Users can duple their first deposit in the vault — _Omo_2025-01-25_ (Pashov Audit Group) [score:7]
18. **[MEDIUM]** [M-12] Perps - GTL post-only orders skew totalAssets accounting, minting excessive shares and render — _GTE_ (Code4rena) [score:7]
19. **[LOW]** share to asset ratio is 1:1 for convertToShares and convertToAssets when currentPPS == 0 but not — _Superform v2 Periphery_ (Spearbit) [score:7]
20. **[LOW]** Revert if `StakingVault::deposit, mint, redeem, withdraw` would return zero — _Syntetika_ (Cyfrin) [score:7]

... and 823 more findings

## lending (915 findings)

1. **[MEDIUM]** Missing Debt Token Supply Sync Leads to Incorrect Interest Rate Calculations — _Core Contracts_ (Codehawks) [score:13]
2. **[HIGH]** Minipools can borrow from lending pool reserves that are not borrowable — _Astera_ (Spearbit) [score:10]
3. **[HIGH]** Minipools can borrow from lending pool reserves that are not borrowable — _Cod3x lend_ (Spearbit) [score:9]
4. **[MEDIUM]** M-19: An attacker can steal the entire borrow and lending incentive of an epoch with FLASHLOAN in a  — _Debita Finance V3_ (Sherlock) [score:9]
5. **[LOW]** Clearing LTV is unsafe and poses system at risk of permanently locking in bad debt  — _Euler_ (Cantina) [score:9]
6. **[HIGH]** [H-03] When harvesting a strategy and adjusting the debt, all the leftover collateral that is not us — _BakerFi_ (Code4rena) [score:9]
7. **[MEDIUM]** Turning off an asset as collateral on Morpho-Aave still allows seizing of that collateral on Morpho  — _Morpho_ (Spearbit) [score:8]
8. **[MEDIUM]** Minipool owner can create unliquidatable loan, imposing bad debt on main lending pool — _Astera_ (Spearbit) [score:8]
9. **[HIGH]** Users can borrow more assets than they have deposited as collateral — _Core Contracts_ (Codehawks) [score:8]
10. **[MEDIUM]** Incorrect DebtToken totalSupply Scaling Breaks Interest Rate Calculations — _Core Contracts_ (Codehawks) [score:8]
11. **[MEDIUM]** Minipool owner can create unliquidatable loan, imposing bad debt on main lending pool — _Cod3x lend_ (Spearbit) [score:8]
12. **[MEDIUM]** M-33: Transaction may revert unexpectedly due to missing allowance for the lending pair asset — _Peapods_ (Sherlock) [score:8]
13. **[LOW]** updateInterestRate uses incorrect reference of borrow interest rate to calculate deposit interest ca — _Folks Finance_ (Immunefi) [score:8]
14. **[MEDIUM]** [M-02] Risk of mass liquidation after pool/asset pause and unpause, due to borrow interest compoundi — _BendDAO_ (Code4rena) [score:8]
15. **[MEDIUM]** Inconsistency In Debt Repaid And Collateral Seized — _Meso Lending_ (OtterSec) [score:8]
16. **[MEDIUM]** [M-03] Size uses wrong source to query available liquidity on Aave, resulting in borrow and lend ope — _Size_ (Code4rena) [score:8]
17. **[HIGH]** Missing Gap Between Borrow LTV and Liquidation Threshold — _Euler Vault Kit (EVK) Audit_ (OpenZeppelin) [score:8]
18. **[MEDIUM]** M-14: Liquidation does not prioritize lowest LTV tokens — _Exactly Protocol_ (Sherlock) [score:8]
19. **[HIGH]** H-2: Unassigned pool earnings can be stolen when a maturity borrow is liquidated by depositing at ma — _Exactly Protocol_ (Sherlock) [score:8]
20. **[MEDIUM]** M-4: Bad debt (shortfall) liquidation leaves liquidated user in a negative collateral balance which  — _Perennial V2_ (Sherlock) [score:7]

... and 895 more findings

## oracle (581 findings)

1. **[LOW]** [23] `PriceFeed#getSqrtPrice()` query to `latestRoundData()` is done in a wrong way since there is n — _Predy_ (Code4rena) [score:14]
2. **[MEDIUM]** PriceFeed use BTC/USD chainlink oracle to price WBTC which can be problematic if WBTC depegs  — _Bima_ (Cantina) [score:13]
3. **[MEDIUM]** Chainlink Oracle Price Feed Used Without Staleness Check — _Brt Dci Contracts_ (Halborn) [score:12]
4. **[MEDIUM]** [M-04] Inadequate checks to confirm the correct status of the sequence/`sequencerUptimeFeed` in `Pri — _Size_ (Code4rena) [score:12]
5. **[MEDIUM]** Chainlink's Oracle Might Return Stale or Incorrect Data — _Protocol V2_ (Halborn) [score:12]
6. **[MEDIUM]** [M-17] Chainlink oracle data feed is not sufficiently validated and can return stale price — _Inverse Finance_ (Code4rena) [score:11]
7. **[MEDIUM]** `ChainlinkUtil::getPrice` doesn't check for stale price — _Zaros_ (Cyfrin) [score:11]
8. **[MEDIUM]** [M-04] Chainlink's `latestRoundData` might return stale or incorrect results — _Predy_ (Code4rena) [score:11]
9. **[MEDIUM]** M-1: stETH/ETH chainlink oracle has too long of heartbeat and deviation threshold which can cause lo — _Olympus Update_ (Sherlock) [score:10]
10. **[MEDIUM]** [M-24] Chainlink price feed is not sufficiently validated and can return stale price — _Tigris Trade_ (Code4rena) [score:10]
11. **[MEDIUM]** [M-04] Lack of data validation for oracle price feed — _Dinari_2024-12-07_ (Pashov Audit Group) [score:10]
12. **[MEDIUM]** M-6: The RedstoneCoreOracle has a constant stale price threshold, this is dangerous to use with toke — _Sentiment V2_ (Sherlock) [score:10]
13. **[LOW]** Unhandled Chainlink Oracle Access Revocation Risk — _Copra_ (Zokyo) [score:10]
14. **[LOW]** [24] `PriceFeed#getSqrtPrice()` might be broken in the future due to it's integration with Pyth's `e — _Predy_ (Code4rena) [score:10]
15. **[MEDIUM]** Missing Chainlink oracle staleness check — _Licredity_ (Cyfrin) [score:9]
16. **[MEDIUM]** M-11: priceLiquidity() may not work if PriceFeed.aggregator() is updated — _Isomorph_ (Sherlock) [score:9]
17. **[MEDIUM]** M-4: No check for active Arbitrum Sequencer in WSTETH Oracle — _Sentiment Update_ (Sherlock) [score:9]
18. **[MEDIUM]** Chainlink price is used without checking validity — _Meta_ (Hans) [score:9]
19. **[MEDIUM]** M-3: _validateAndGetPrice() doesn't check If Arbitrum sequencer is down in Chainlink feeds — _Bond Protocol Update_ (Sherlock) [score:9]
20. **[MEDIUM]** M-1: Lack of price freshness check in `ChainlinkOracle.sol#getPrice()` allows a stale price to be us — _Sentiment_ (Sherlock) [score:9]

... and 561 more findings

## flash_loan (73 findings)

1. **[HIGH]** [STAKE-6] Unprotected flash loan callback can be abused to manipulate/claim other users' positions — _Stakewise_ (Hexens) [score:7]
2. **[HIGH]** H-1: Flashloan `TEL` tokens to stake and exit in the same block can fake a huge amount of stake with — _Telcoin_ (Sherlock) [score:6]
3. **[HIGH]** [H-03] Vaults with non-UST underlying asset vulnerable to flash loan attack on curve pool — _Sandclock_ (Code4rena) [score:6]
4. **[MEDIUM]** [M-08] Oracles are vulnerable to flash loan attack vectors — _StakeDAO_2025-07-21_ (Pashov Audit Group) [score:6]
5. **[LOW]** [L-11] Flash loan attack reallocates liquidity to riskier strategy vaults — _EulerEarn_2025-07-25_ (Pashov Audit Group) [score:6]
6. **[LOW]** [03] Reentrancy could occur in flash loan callback functions — _BadgerDAO_ (Code4rena) [score:6]
7. **[MEDIUM]** [M-04] Launched tokens are vulnerable to flashloan attacks forcing premature graduation, allowing re — _Virtuals Protocol_ (Code4rena) [score:5]
8. **[HIGH]** Flashloan Functionality is Blocked — _f(x) v2 Audit_ (OpenZeppelin) [score:5]
9. **[HIGH]** [H-06] Reentrancy vulnerability allows bypass of cooldown, leading to unfair reward extraction throu — _Phi_ (Code4rena) [score:5]
10. **[MEDIUM]** [M-09] SwapPool's are vulnerable to flashloan attacks — _Nabla_ (Pashov Audit Group) [score:5]
11. **[HIGH]** Reward Inflation Through a Flash Loan — _Sperax - Farms_ (Quantstamp) [score:5]
12. **[MEDIUM]** M-13: Flashloan end result isn't controlled — _Ajna_ (Sherlock) [score:4]
13. **[HIGH]** [H-05] Flash loan price manipulation in purchasePyroFlan() — _Behodler_ (Code4rena) [score:4]
14. **[HIGH]** [H-05] Synth realise is vulnerable to flash loan attacks — _Spartan Protocol_ (Code4rena) [score:4]
15. **[HIGH]** Attacker can combine flashloan with delegated voting to decide a proposal and withdraw their tokens  — _Dexe_ (Cyfrin) [score:4]
16. **[MEDIUM]** M-2: First Depositor can flash loan the protocol too artificially increase the token rewards without — _Super DCA Liquidity Network_ (Sherlock) [score:4]
17. **[MEDIUM]** Flashloan Functionality Does Not Follow ERC-3156 Standard — _f(x) v2 Audit_ (OpenZeppelin) [score:4]
18. **[HIGH]** [RUSH1-7] RushERC20 launch fee bypass due to flash loan stake — _Rush Trading_ (Hexens) [score:4]
19. **[HIGH]** [H-02] The flashloan protection for Zappers is insufficient - We can operate on Troves we don't own — _Bold Report_ (Recon Audits) [score:3]
20. **[MEDIUM]** [M-15] Pool tokens can be stolen via `PrivatePool.flashLoan` function from previous owner — _Caviar_ (Code4rena) [score:3]

... and 53 more findings

## access_control (1,517 findings)

1. **[LOW]** [L-03] Missing events for access control role changes — _Tangent_2025-12-08_ (Pashov Audit Group) [score:11]
2. **[MEDIUM]** [M-06] Centralisation risk: admin role of `TokenManagerEth` can rug pull all Eth from the bridge — _SKALE_ (Code4rena) [score:10]
3. **[MEDIUM]** Combination of Ownable and AccessControl can cause loss of admin functionality — _Button Basis Trade_ (Cyfrin) [score:10]
4. **[MEDIUM]** [M-02] Critical access control flaw: Role removal logic incorrectly grants unauthorized roles — _Audit 507_ (Code4rena) [score:10]
5. **[LOW]** Incompatibility of Admin Role Management with Multisig Wallets in SynthFactory Smart Contract — _Entangle Trillion_ (Halborn) [score:10]
6. **[LOW]** [L-05] No access control in `initializeVault()` allows unauthorized init — _Saffron_2025-07-31_ (Pashov Audit Group) [score:9]
7. **[HIGH]** ROLE-BASED ACCESS CONTROL MISSING — _MonoX_ (Halborn) [score:9]
8. **[LOW]** Use multi-sig wallet for contract admin and owner — _Avant Max_ (Cyfrin) [score:9]
9. **[MEDIUM]** Timelock Controller Retains Canceled Proposals, Enabling Unauthorized Execution and severe Governanc — _Core Contracts_ (Codehawks) [score:9]
10. **[MEDIUM]** Unauthorized role grants prevent `QuantAMMBaseAdministration` deployment — _Quantamm_ (Cyfrin) [score:9]
11. **[HIGH]** Missing Access Control in Policy termination blueprint — _HUB v1_ (Halborn) [score:9]
12. **[MEDIUM]** Owner can chain admin calls for same-block drains — _Sherpa_ (Cyfrin) [score:8]
13. **[LOW]** [L-01] Misleading `setLevel()` Governance Check with `onlyOwner` — _Terplayer Bvt Staking&Distribution_ (Shieldify) [score:8]
14. **[LOW]** Missing access control allows nonce manipulation — _Gemini Smart Wallet_ (TrailOfBits) [score:8]
15. **[MEDIUM]** Missing Access Control Allows Users to Bypass Fees — _TokenOps 3 - Airdrop_ (Quantstamp) [score:8]
16. **[HIGH]** Missing access control on critical `FeeController` setters — _Octodefi_ (Cyfrin) [score:8]
17. **[HIGH]** Lack of Access Control in BoostController::updateUserBoost Leading to Unauthorized Delegation Overwr — _Core Contracts_ (Codehawks) [score:8]
18. **[MEDIUM]** Missing Access Control on Token Release Functions — _Treasury Vesting_ (Halborn) [score:8]
19. **[MEDIUM]** Ambiguous owner terminology creates confusion in access control of SecuritizeVault — _Securitize Redeem Swap Vault Na_ (Cyfrin) [score:8]
20. **[LOW]** Timelock in ClaggMain is ineffective if owner turns malicious  — _Clave_ (Cantina) [score:8]

... and 1,497 more findings

## dex_amm (1,083 findings)

1. **[MEDIUM]** M-11: Withdrawals from IchiVaultSpell have no slippage protection so can be frontrun, stealing all u — _Blueberry_ (Sherlock) [score:9]
2. **[HIGH]** Use of spot dex price when repay portal debt leads to sandwich attacks — _Connext_ (Spearbit) [score:9]
3. **[LOW]** Curve stable swap AMM is not usable — _FIVA Yield Tokenization Protocol_ (TrailOfBits) [score:9]
4. **[HIGH]** [H-07] Missing slippage checks — _Spartan Protocol_ (Code4rena) [score:8]
5. **[LOW]** Slippage check can underflow when minReturnAmount > expectedAmountOut — _Tenbin_ (Spearbit) [score:8]
6. **[LOW]** [L-09] Using `block.timestamp` as swap deadline removes MEV protection — _WishWish_2025-11-04_ (Pashov Audit Group) [score:8]
7. **[MEDIUM]** M-11: Providing and withdrawing liquidity lacks slippage protection — _Dango DEX_ (Sherlock) [score:8]
8. **[HIGH]** [H-03] Swap Can Execute After Deadline Expires — _Gluex V2_ (Shieldify) [score:8]
9. **[LOW]** [L-02] Excessively Broad Tick Range Dilutes Liquidity on Uniswap V3 — _Daoslive_ (Shieldify) [score:8]
10. **[HIGH]** [H-05] Vulnerability in `PositionInteractionFacet` slippage control due to spot price — _Hyperhyper_2025-03-30_ (Pashov Audit Group) [score:8]
11. **[MEDIUM]** [M-01] Slippage During Transfer Fee Swap — _Berabot_ (Shieldify) [score:8]
12. **[MEDIUM]** CurveSwapper Lacks Slippage Protection on Curve Pool Interactions — _Hooks Contracts_ (Halborn) [score:8]
13. **[MEDIUM]** [LOGLAB-22] Lack of slippage protection for manual swap in SpotManager — _Basisos_ (Hexens) [score:8]
14. **[LOW]** [L-03] Missing ETH swap slippage — _BOB-September_ (Pashov Audit Group) [score:8]
15. **[MEDIUM]** [M-07] Lack of slippage check in `rebalance` Function — _Radiant June_ (Pashov Audit Group) [score:8]
16. **[MEDIUM]** [M-02] `block.timestamp` use in dex swap deadlines may cause poor trading — _Hyperhyper_2025-03-30_ (Pashov Audit Group) [score:7]
17. **[HIGH]** [H-05] Functions in the `VotiumStrategy` contract are susceptible to sandwich attacks — _Asymmetry Finance_ (Code4rena) [score:7]
18. **[HIGH]** H-1: H-01 wstETH-ETH Curve LP Token Price can be manipulated to Cause Unexpected Liquidations — _Sentiment Update #2_ (Sherlock) [score:7]
19. **[MEDIUM]** M-10: Balancer Vault Will Receive Fewer Assets As The Current Design Does Not Serve The Interest Of  — _Notional_ (Sherlock) [score:7]
20. **[HIGH]** Use of spot price in SponsorVault leads to sandwich attack. — _Connext_ (Spearbit) [score:7]

... and 1,063 more findings

## staking (1,198 findings)

1. **[MEDIUM]** Epoch mismatch in FjordPoints and FjordStaking leads to user being able to stake and unstake instant — _Fjord_ (Codehawks) [score:10]
2. **[HIGH]** H-2: `Staking.unstake()` doesn't decrease the original voting power that was used in `Staking.stake( — _FrankenDAO_ (Sherlock) [score:9]
3. **[HIGH]** RocketRewardPool - Unpredictable staking rewards as stake can be added just before claiming and rewa — _Rocketpool_ (ConsenSys) [score:9]
4. **[HIGH]** Reward Claim Post Expiry Of Locked Stake — _Adrena_ (OtterSec) [score:9]
5. **[HIGH]** `Boost.setLockStatus()` should update the caller's rewards first. — _Meta_ (Hans) [score:8]
6. **[LOW]** Short cooldown and short staking cycles increase validator churn — _Upgrade_ (TrailOfBits) [score:8]
7. **[MEDIUM]** Potential Stake Lock and Inconsistency Due to Validator State Transitions — _FCHAIN Validator and Staking Contracts Audit_ (OpenZeppelin) [score:8]
8. **[HIGH]** Signature Replay Attack Possible Between Stake, Unstake and Reward Functions Enabling Unauthorized T — _Sapien_ (Quantstamp) [score:8]
9. **[HIGH]** Gauge reward system can be gamed with repeatedly  stake/withdraw — _Core Contracts_ (Codehawks) [score:8]
10. **[MEDIUM]** Gauge reward period can be extended indefinitely — _Core Contracts_ (Codehawks) [score:8]
11. **[HIGH]** `BaseGauge` users can claim rewards without staking — _Core Contracts_ (Codehawks) [score:8]
12. **[MEDIUM]** M-7: if Slash Validator occurs, UNSTAKING_QUEUE's unstake amount will not be accurate — _Andromeda – Validator Staking ADO and Vesting ADO_ (Sherlock) [score:8]
13. **[MEDIUM]** M-5: when a validator is kicked out of the bonded validator set ,unstake funds will remain in the co — _Andromeda – Validator Staking ADO and Vesting ADO_ (Sherlock) [score:8]
14. **[HIGH]** Incorrect Stake Start Epoch Setting — _Zeta Markets Staking + Merkle_ (OtterSec) [score:8]
15. **[HIGH]** User can artificially inflate stake boosts for the next interval by repeating stake and unstake acti — _Nayms 2024 (Retainer)_ (Quantstamp) [score:8]
16. **[MEDIUM]** [M-04] Malicious validators can flood `stake/unstake` requests to DoS `confirmChange` preventing oth — _Recall_ (Code4rena) [score:7]
17. **[HIGH]** [H-02] `Staking.sol#stake()` DoS by staking 1 wei for the recipient when `warmUpPeriod > 0` — _Yieldy_ (Code4rena) [score:7]
18. **[MEDIUM]** [M-06] `ClaimFees` steals staking rewards — _Hybra Finance_ (Code4rena) [score:7]
19. **[MEDIUM]** [M-01] Protocol Can Permanently Lose Rewards During Periods When Zero Participants Are Staking — _Beraroot_ (Shieldify) [score:7]
20. **[HIGH]** Flash Loan Attack on Gauge Reward Distribution via `get_adjustment()` Manipulation — _Yield Basis_ (MixBytes) [score:7]

... and 1,178 more findings

## token (607 findings)

1. **[MEDIUM]** [M-01] Incompatibility with fee-on-transfer/inflationary/deflationary/rebasing tokens, on both base  — _SIZE_ (Code4rena) [score:8]
2. **[MEDIUM]** [M-05] When rewardToken is erc1155/erc777, an attacker can reenter and cause funds to be stuck in th — _RabbitHole_ (Code4rena) [score:7]
3. **[LOW]** Incompatibility with fee-on-transfer or rebasing tokens — _Resolv_ (MixBytes) [score:7]
4. **[LOW]** Incompatibility with fee-on-transfer or rebasing tokens — _EYWA_ (MixBytes) [score:7]
5. **[MEDIUM]** M-4: Budget allocation will break in case of a fee on transfer ERC 20 token — _Boost Account AA Wallet_ (Sherlock) [score:7]
6. **[LOW]** Fee-on-Transfer and Rebasing Tokens Not Supported for Lp Token — _Sophon Farming Program_ (Quantstamp) [score:7]
7. **[MEDIUM]** M-9: Lack of support for fee on transfer, rebasing and tokens with balance modifications outside of  — _MagicSea - the native DEX on the IotaEVM_ (Sherlock) [score:7]
8. **[HIGH]** [H-02] An attacker is able to hijack any ERC721 / ERC1155 he borrows because guard is missing valida — _reNFT_ (Code4rena) [score:6]
9. **[HIGH]** 1. ERC777 RE-ENTRANCY ATTACK — _Polygonzkevm_ (Hexens) [score:6]
10. **[HIGH]** [H-06] Some real-world NFT tokens may support both ERC721 and ERC1155 standards, which may break `In — _Infinity NFT Marketplace_ (Code4rena) [score:6]
11. **[LOW]** ERC20 Permit Functionality in sendTokensWithPermit — _Bridge Smart Contracts_ (Halborn) [score:6]
12. **[MEDIUM]** [M-12] paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lend — _reNFT_ (Code4rena) [score:6]
13. **[MEDIUM]** [M-02] The recipient receives free collateral token if an ERC20 token that deducts a fee on transfer — _prePO_ (Code4rena) [score:6]
14. **[MEDIUM]** [M-01] `isOwner` / `onlyOwner` checks can be bypassed by attacker in ERC721/ERC20 implementations — _Holograph_ (Code4rena) [score:6]
15. **[MEDIUM]** [M-09] Variable balance ERC20 support — _Debt DAO_ (Code4rena) [score:6]
16. **[LOW]** [L-03] `permit()` Can Approve a Blacklisted Spender (Missing Blacklist Check) But approve() Does Not — _Shiny_ (Shieldify) [score:6]
17. **[LOW]** Fee-on-transfer and rebasing tokens break accounting — _Wannabet_ (Cyfrin) [score:6]
18. **[LOW]** Many ERC20 tokens not supported - fee on transfer, cUSDCv3, etc... — _Superform v2 Periphery_ (Spearbit) [score:6]
19. **[LOW]** Hardcoded Decimal Conversion May Not Support All Erc-20 Tokens — _vusd-stablecoin_ (Quantstamp) [score:6]
20. **[LOW]** Incorrect handling of fee-on-transfer and rebasing tokens penalizes single beneficiary — _CryptoLegacy_ (MixBytes) [score:6]

... and 587 more findings

## bridge (433 findings)

1. **[LOW]** L1 Redeemer Rescue Inoperable for tBTC Stuck on Wormhole Bridge — _Threshold Network_ (MixBytes) [score:9]
2. **[LOW]** Missing chain ID veriﬁcation in L2 leader chain to L1 message ﬂow — _Shape Token Contract_ (TrailOfBits) [score:8]
3. **[MEDIUM]** Wormhole bridge chain IDs are different than EVM chain IDs — _LI.FI_ (Spearbit) [score:7]
4. **[HIGH]** H-3: User can evade liquidation and bridge funds by exploiting cross-chain borrow/collateral invaria — _LEND_ (Sherlock) [score:7]
5. **[HIGH]** Bridge with Axelar can be stolen with malicious external call — _LI.FI_ (Spearbit) [score:6]
6. **[MEDIUM]** [M-02] Cross-chain unstake and fast redeem operations fail due to `minAmountLD` not accounting for L — _Brix Money_ (Code4rena) [score:6]
7. **[LOW]** `USDCBridgeV2` can't bridge to non-EVM chains even though Wormhole and Circle CCTP support this — _Securitize Bridge Cctp_ (Cyfrin) [score:6]
8. **[MEDIUM]** [M-01] Bridge messages can be permanently lost — _Nucleus_2024-12-14_ (Pashov Audit Group) [score:6]
9. **[LOW]** Missing Zero Amount Check in Cross-Chain Bridge Functions — _Contracts V1_ (Halborn) [score:6]
10. **[LOW]** [L-01] Slow Bridging from L2-L1 Using `Arbitrum/Optimism` Bridge May Fail the Dispute Process in Fav — _Dinero Supereth_ (Shieldify) [score:6]
11. **[MEDIUM]** [M-12] Non-blocking LayerZero cross-chain buy operations can be blocked — _StationX_ (Pashov Audit Group) [score:6]
12. **[HIGH]** [C-01] The LayerZero implementation contract is the receiver of DAOs fees on cross-chain buy operati — _StationX_ (Pashov Audit Group) [score:6]
13. **[MEDIUM]** Temporary failed L1 to L2 token transfers might lock tokens in L1 if replayed after migrating to nat — _Wonderland_ (Cantina) [score:6]
14. **[HIGH]** Bridge Signals Can Be Forged to Drain the Protocol - Phase 3 — _Taiko Protocol Audit_ (OpenZeppelin) [score:6]
15. **[MEDIUM]** [M-11] Refunds for unconsumed gas will be lost due to incorrect refund chain ID — _Olas_ (Code4rena) [score:6]
16. **[MEDIUM]** [M-08] Not handling the failure of cross chain messaging — _Renzo_ (Code4rena) [score:6]
17. **[HIGH]** TOKENS CAN BE STUCKED IF THE SAME CHAIN-ID USED IN THE BRIDGE — _Bridge Updates_ (Halborn) [score:6]
18. **[MEDIUM]** [M-02] Executor Can Deliver Cross-Chain Messages with Unvalidated Native Value — _Onchainheroes Genesisbridge_ (Shieldify) [score:5]
19. **[LOW]** Usage of unofficial wormhole-solidity-sdk npm package poses security and maintenance risks — _Securitize Onofframp Bridge_ (Cyfrin) [score:5]
20. **[MEDIUM]** Pause modifier in bridge receiver functions causes receiver failures for in-flight messages — _Securitize Onofframp Bridge_ (Cyfrin) [score:5]

... and 413 more findings

## proxy_upgrade (199 findings)

1. **[HIGH]** [H-01] Lost roles after the proxy upgrade — _GainsNetwork-February_ (Pashov Audit Group) [score:9]
2. **[LOW]** Storage collision risk in UUPS upgradeable `StakingProxy` due to missing storage gap — _Stakedotlink Stakingproxy_ (Cyfrin) [score:7]
3. **[LOW]** The Beacon proxy pattern is better suited to upgrading multiple instances of `MembershipERC1155` — _One World Project_ (Cyfrin) [score:7]
4. **[MEDIUM]** Risk of Storage Collision in Proxy Contract — _Anvil Protocol Audit_ (OpenZeppelin) [score:7]
5. **[MEDIUM]** Selfdestruct risks in delegateCall() — _Brink_ (Spearbit) [score:6]
6. **[LOW]** [L-02] Unnecessary UUPS upgradeable logic — _Aria_2025-04-25_ (Pashov Audit Group) [score:6]
7. **[LOW]** [L-01] Some contracts not following UUPS best practices — _KittenSwap_2025-07-31_ (Pashov Audit Group) [score:6]
8. **[LOW]** Inefficient initalization in UUPS proxy — _XPress_ (MixBytes) [score:6]
9. **[LOW]** Inefficient initalization in UUPS proxy — _Hanji_ (MixBytes) [score:6]
10. **[LOW]** Inefficient initalization in UUPS proxy — _XPress Protocol_ (MixBytes) [score:6]
11. **[LOW]** Missing __gap variable in base contracts used for upgradeable derived contracts — _Berachain Pol_ (Spearbit) [score:6]
12. **[GAS]** Re-evaluate utilization of Clones minimal proxy which introduces DELEGATECALL overhead  — _Omni X_ (Cantina) [score:6]
13. **[MEDIUM]** Due to no access control on `DistributionV2::_authorizeUpgrade()` anyone can change the implementati — _MorpheusAI_ (Codehawks) [score:5]
14. **[MEDIUM]** M-1: The UUPS proxie standard is implemented incorrectly, making the protocol not upgradeable — _Cork Protocol_ (Sherlock) [score:5]
15. **[MEDIUM]** [M-08] If a MIMOProxy owner destroys their proxy, they cannot deploy another from the same address — _Mimo DeFi_ (Code4rena) [score:5]
16. **[MEDIUM]** RollupRevenueVault - Deployment and Initialization Flow ✓ Fixed — _Linea - Burn Mechanism_ (ConsenSys) [score:5]
17. **[LOW]** `GelatoVRFConsumerBase` is not upgrade-safe — _Linea Spingame_ (Cyfrin) [score:5]
18. **[MEDIUM]** AccessControlDS uses AccessControl, which has storage collision risks — _Arkis DeFi Prime Brokerage Protocol_ (TrailOfBits) [score:5]
19. **[MEDIUM]** Deployers Can Upgrade Factory Deployed Contracts — _Primex Finance_ (Quantstamp) [score:5]
20. **[LOW]** Potential Mismatch in `beacon` Contract — _Solv Protocol - SolvBTC_ (Quantstamp) [score:5]

... and 179 more findings

## zk_circuits (178 findings)

1. **[MEDIUM]** M-4: Malicious verifier will recover private witness values breaking zero-knowledge property — _Brevis Pico ZKVM_ (Sherlock) [score:13]
2. **[MEDIUM]** [M-05] SP1 host verifier rejects PLONK and Groth16 proofs with BLAKE3 hashed public values — _Succinct_ (Code4rena) [score:11]
3. **[MEDIUM]** [M-01] PLONK/Groth16 verifiers accept proofs with untrusted recursion vk root — _Succinct_ (Code4rena) [score:9]
4. **[LOW]** Missing constraint in the output of `passportVerificationSHA1` circuit — _Passport ZK Circuits Security Assessment - Freedom Tool_ (Halborn) [score:8]
5. **[MEDIUM]** [M-07] Unbounded decimal public inputs enable verifier-side DoS via oversized numeric parsing — _Succinct_ (Code4rena) [score:7]
6. **[HIGH]** H-9: Polynomial evaluations are never observed by recursive verifier — _Brevis Pico ZKVM_ (Sherlock) [score:7]
7. **[LOW]** Missing Field Order Constraint — _Light Protocol_ (OtterSec) [score:7]
8. **[MEDIUM]** No Validation of Raw Merkle Proof Length ✓ Fixed — _Linea ENS_ (ConsenSys) [score:7]
9. **[MEDIUM]** [M-04] Public verifier API panics on malformed inputs, enabling DoS — _Succinct_ (Code4rena) [score:6]
10. **[HIGH]** [H-01] Range check fails to bind limbs to value, enabling invalid witnesses — _Succinct_ (Code4rena) [score:6]
11. **[HIGH]** Missing On-Chain ZK Proof Verification — _Dipcoin Perpetual_ (Quantstamp) [score:6]
12. **[MEDIUM]** Weak Fiat-Shamir Implementation for the LogUp Phase allows crafting Backdoored Circuits  — _OpenVM_ (Cantina) [score:6]
13. **[HIGH]** Additional airs can be added to proof in recursion program  — _OpenVM_ (Cantina) [score:6]
14. **[HIGH]** Inverted Merkle Proof Veriﬁcation in claimLogic  — _DefiApp_ (Cantina) [score:6]
15. **[MEDIUM]** Merkle Proof Verification Path Inconsistency Enables Cross-Chain Message Verification Bypass — _Era_ (Codehawks) [score:6]
16. **[LOW]** Cross-function Merkle Proof Usage Vulnerability — _Liquid Staking_ (Codehawks) [score:6]
17. **[MEDIUM]** Inconsistent Plonk Implementation — _Linea Plonk Prover (Backend) and Plonk Verifier Audit_ (OpenZeppelin) [score:6]
18. **[LOW]** Missing Context Header in for merkle proof — _Elektrik_ (Zokyo) [score:6]
19. **[MEDIUM]** M-2: PerAddressTrancheVestingMerkleDistributor.claim always reverts because it checks the Merkle pro — _Tokensoft Distributor Contracts Update_ (Sherlock) [score:6]
20. **[HIGH]** Missing constraints in LOADWand STOREW  — _OpenVM_ (Cantina) [score:5]

... and 158 more findings

## signature_replay (358 findings)

1. **[MEDIUM]** Token name update breaks EIP-712 Domain Separator for permit functionality — _Securitize Global Registry_ (Cyfrin) [score:10]
2. **[HIGH]** Use EIP-712-style Signed Hashing to Prevent Cross-Chain Signature Replaying ✓ Fixed — _Aligned Layer_ (ConsenSys) [score:10]
3. **[HIGH]** Potential Signature Replay Attack in ERC1271Handler — _SSO Account OIDC Recovery Solidity Audit_ (OpenZeppelin) [score:9]
4. **[HIGH]** [H-01] Cross-chain signature replay attack due to user-supplied `domainSeparator` and missing deadli — _Next Generation_ (Code4rena) [score:9]
5. **[LOW]** [L-01] Signature malleability due to missing ECDSA checks — _GammaSwap_2024-12-30_ (Pashov Audit Group) [score:9]
6. **[MEDIUM]** Signature Replay Allows Unauthorized Use of Permits — _P2P.org_ (MixBytes) [score:9]
7. **[LOW]** Using `ecrecover` directly vulnerable to signature malleability — _Bima_ (Cyfrin) [score:9]
8. **[MEDIUM]** [M-01] Incorrect `chainId` used for permit EIP712 domain separator — _SushiSwap_ (Pashov Audit Group) [score:9]
9. **[LOW]** DIRECT USAGE OF ECRECOVER ALLOWS SIGNATURE MALLEABILITY — _Token Sale & Comptroller Updates_ (Halborn) [score:9]
10. **[LOW]** Direct usage of ecrecover allows signature malleability — _EVM Smart Contracts_ (Halborn) [score:9]
11. **[LOW]** Prefer `ECDSA::tryRecover` to using `ecrecover` directly — _Securitize Dstoken Rebasing_ (Cyfrin) [score:8]
12. **[MEDIUM]** Signature replay possible with shared signers — _Stackup Keystore_ (Spearbit) [score:8]
13. **[HIGH]** Missing nonce validation in signature verification allows transaction replay attacks — _Securitize Onofframp Bridge_ (Cyfrin) [score:8]
14. **[LOW]** Signature validation is not EIP712 compliant — _Liquorice_ (MixBytes) [score:8]
15. **[MEDIUM]** Collect front run permit  — _Napier Finance_ (Cantina) [score:8]
16. **[MEDIUM]** Minting from signature is vulnerable to replay attacks  — _Hyperware_ (Cantina) [score:8]
17. **[LOW]** Direct usage of ecrecover allows for signature malleability — _Protocol_ (Halborn) [score:8]
18. **[LOW]** Use of `ecrecover` is Susceptible to Signature Malleability — _Limit Orders_ (Halborn) [score:8]
19. **[MEDIUM]** [M-13] EIP-712 domain type hash mismatch breaks signature-based delegation — _Audit 507_ (Code4rena) [score:7]
20. **[HIGH]** [H-07] Replay attack (EIP712 signed transaction) — _Biconomy_ (Code4rena) [score:7]

... and 338 more findings

## uncategorized (13,615 findings)

These findings didn't match any category strongly enough (score < 2).
They may need new categories or refined keywords.

- **[MEDIUM]** [M-01] Unchecked `approve( )` return causes permanent fund loss in UDA.sol
- **[MEDIUM]** [M-04] Malicious user can spam orders that expire immediately or cancel them immediately to wipe out
- **[HIGH]** [H-01] Order double-linked list is broken because order.prevOrderId is not persisted
- **[MEDIUM]** [M-02] Liquidation Can Be Blocked By Pausing or Blacklisting the NFT Contract, Permanently Trapping 
- **[LOW]** Incorrect information in redeem-documentation
- **[LOW]** [L-10] `MIN_NOTIONAL_WEI` check provides no additional safety and overlaps existing limits
- **[LOW]** [L-03] Gas Griefing and DoS via Malicious Fallback in `refund()`
- **[LOW]** [L-07] Missing User Tickets Mapping Update in `JackpotBridgeManager::claimTickets` Function Causes G
- **[MEDIUM]** [M-07] Claiming rewards in `GovernanceHYBR` will always revert
- **[HIGH]** H-1: Pool managers can steal all other pools' pending deposits from `globalEscrow` via malicious `re

... and 13,605 more
