# Solodit Findings Index — Categorized from 350 audit findings
# Source: solodit.cyfrin.io via MCP extraction (2026-03-19)
# Purpose: Cross-reference with briefings, identify gaps, add new patterns

## VAULT (44 findings)

1. H-6: User can lose all funds when creating or increasing compounded Maker position due to share inflation first deposit attack in any segment of the user's range
   slug: h-6-user-can-lose-all-funds-when-creating-or-increasing-compounded-maker-position-due-to-share-inflation-first-deposit-attack-in-any-segment-of-the-users-range-sherlock-ammplify-git
2. M-13: First ERC4626 deposit can break share calculation
   slug: m-13-first-erc4626-deposit-can-break-share-calculation-sherlock-astaria-astaria-git
3. [M-02] First xERC4626 deposit exploit can break share calculation
   slug: m-02-first-xerc4626-deposit-exploit-can-break-share-calculation-code4rena-tribe-xtribe-contest-git
4. ERC4626 Vault Share Inflation
   slug: erc4626-vault-share-inflation-sigmaprime-none-treehouse-pdf
5. M-19: Attacker Can Manipulate Interest Distribution by Exploiting Asset Transfers and Fee Accrual Mechanism
   slug: m-19-attacker-can-manipulate-interest-distribution-by-exploiting-asset-transfers-and-fee-accrual-mechanism-sherlock-sentiment-v2-git
6. [C-01] First Depositor Can Inflate Share Price to Steal Funds from Subsequent Depositors
   slug: c-01-first-depositor-can-inflate-share-price-to-steal-funds-from-subsequent-depositors-shieldify-none-harmonixfinance-hyperliquid-markdown
7. M-2: AutoRoller.sol#roll can revert if lastSettle is zero because solmate ERC4626 deposit revert if previewDeposit returns 0
   slug: m-2-autorollersolroll-can-revert-if-lastsettle-is-zero-because-solmate-erc4626-deposit-revert-if-previewdeposit-returns-0-sherlock-sense-sense-git
8. M-4: AutoRoller.sol#roll can revert if lastSettle is zero because solmate ERC4626 deposit revert if previewDeposit returns 0
   slug: m-4-autorollersolroll-can-revert-if-lastsettle-is-zero-because-solmate-erc4626-deposit-revert-if-previewdeposit-returns-0-sherlock-sense-sense-git
9. M-3: FundRateArbitrage is vulnerable to inflation attacks
   slug: m-3-fundratearbitrage-is-vulnerable-to-inflation-attacks-sherlock-jojo-exchange-update-git
10. First deposit attack via share price manipulation
   slug: first-deposit-attack-via-share-price-manipulation-zokyo-none-vaultka-markdown
11. H-3: Exchange rate is calculated incorrectly when the vault is closed, potentially leading to funds being stolen
   slug: h-3-exchange-rate-is-calculated-incorrectly-when-the-vault-is-closed-potentially-leading-to-funds-being-stolen-sherlock-amphor-git
12. [M-18] Interest auctions enable inflation attacks on backstop vaults, allowing attackers to steal user deposits
   slug: m-18-interest-auctions-enable-inflation-attacks-on-backstop-vaults-allowing-attackers-to-steal-user-deposits-code4rena-blend-blend-git
13. M-6: BalancedVault.sol: Early depositor can manipulate exchange rate and steal funds
   slug: m-6-balancedvaultsol-early-depositor-can-manipulate-exchange-rate-and-steal-funds-sherlock-none-perennial-git
14. M-5: Early depositors to DnGmxSeniorVault can manipulate exchange rates to steal funds from later depositors
   slug: m-5-early-depositors-to-dngmxseniorvault-can-manipulate-exchange-rates-to-steal-funds-from-later-depositors-sherlock-rage-trade-rage-trade-git
15. H-3: Early depositors to BufferBinaryPool can manipulate exchange rates to steal funds from later depositors
   slug: h-3-early-depositors-to-bufferbinarypool-can-manipulate-exchange-rates-to-steal-funds-from-later-depositors-sherlock-buffer-finance-buffer-finance-git
16. M-3: Malicious actors can execute sandwich attacks during market addition with existing funds
   slug: m-3-malicious-actors-can-execute-sandwich-attacks-during-market-addition-with-existing-funds-sherlock-zerolend-one-git
17. [H-05] Inflation of ggAVAX share price by first depositor
   slug: h-05-inflation-of-ggavax-share-price-by-first-depositor-code4rena-gogopool-gogopool-contest-git
18. H-2: Vault is vulnerable to inflation attack which can cause complete loss of user funds
   slug: h-2-vault-is-vulnerable-to-inflation-attack-which-can-cause-complete-loss-of-user-funds-sherlock-numa-git
19. H-2: YT holder are unable to claim their interest
   slug: h-2-yt-holder-are-unable-to-claim-their-interest-sherlock-napier-git
20. [M-39] Lack of slippage check while interacting with ERC4626 Vault in `PositionAction4626` could lead to users' fund loss
   slug: m-39-lack-of-slippage-check-while-interacting-with-erc4626-vault-in-positionaction4626-could-lead-to-users-fund-loss-code4rena-loopfi-loopfi-git
21. Lack of input validations can lead to loss of $SOL
   slug: lack-of-input-validations-can-lead-to-loss-of-sol-halborn-entangle-labs-gorples-ido-core-markdown
22. M-3: Predefined amount parameter can challange allocation to Obol validators
   slug: m-3-predefined-amount-parameter-can-challange-allocation-to-obol-validators-sherlock-mellow-modular-lrts-git
23. M-13: Unintended Vault Operation Due to Product Settling and Oracle Version Skips
   slug: m-13-unintended-vault-operation-due-to-product-settling-and-oracle-version-skips-sherlock-none-perennial-git
24. Vault can be placed back into vulnerable low supply state
   slug: vault-can-be-placed-back-into-vulnerable-low-supply-state-openzeppelin-pods-finance-ethereum-volatility-vault-audit-2-markdown
25. M-4: Attacker Can Decide The Initialization Ratio Of The AMM Pair
   slug: m-4-attacker-can-decide-the-initialization-ratio-of-the-amm-pair-sherlock-cork-protocol-git
26. [M-19] Because of the asset: `Share 1:1 Conversion`, if vault incurs a loss, the last user to withdraw will take the entire loss
   slug: m-19-because-of-the-asset-share-11-conversion-if-vault-incurs-a-loss-the-last-user-to-withdraw-will-take-the-entire-loss-code4rena-loopfi-loopfi-git
27. M-5: Vault Inflation Attack
   slug: m-5-vault-inflation-attack-sherlock-flatmoney-git
28. TRST-H-2 A malicious operator can steal all user deposits
   slug: trst-h-2-a-malicious-operator-can-steal-all-user-deposits-trust-security-none-orbital-finance-markdown_
29. Inﬂation Attack On Empty Vault Can DoS The Vault
   slug: inflation-attack-on-empty-vault-can-dos-the-vault-sigmaprime-none-august-pdf
30. Inﬂation Attack On Empty Vault Can DoSThe Vault
   slug: inflation-attack-on-empty-vault-can-dosthe-vault-sigmaprime-none-august-pdf
31. [M-06] Funds locked due to missing transfer check
   slug: m-06-funds-locked-due-to-missing-transfer-check-code4rena-pooltogether-pooltogether-git
32. [M-10] New gALCX token denomination can be depressed by the first depositor
   slug: m-10-new-galcx-token-denomination-can-be-depressed-by-the-first-depositor-code4rena-alchemix-alchemix-contest-git
33. Evault.ConverToAssets() is overestimated when exchangeRate < 1 
   slug: evaultconvertoassets-is-overestimated-when-exchangerate-1-cantina-none-euler-pdf
34. [M-12] Perps - GTL post-only orders skew totalAssets accounting, minting excessive shares and rendering the GTL vault insolvent
   slug: m-12-perps-gtl-post-only-orders-skew-totalassets-accounting-minting-excessive-shares-and-rendering-the-gtl-vault-insolvent-code4rena-gte-gte-git
35. [M-01] Incorrect call argument in `THORChain_Router::_transferOutAndCallV5`, leading to grief/steal of `THORChain_Aggregator`'s funds or DoS
   slug: m-01-incorrect-call-argument-in-thorchain_router_transferoutandcallv5-leading-to-griefsteal-of-thorchain_aggregators-funds-or-dos-code4rena-thorchain-thorchain-git
36. M-13: Curated Vault allocators cannot `reallocate()` a pool to zero due to attempting to withdraw 0 tokens from the underlying pool
   slug: m-13-curated-vault-allocators-cannot-reallocate-a-pool-to-zero-due-to-attempting-to-withdraw-0-tokens-from-the-underlying-pool-sherlock-zerolend-one-git
37. Share Price Manipulation
   slug: share-price-manipulation-ottersec-none-bluefin-pdf
38. H-1: Public vault : Initial depositor can manipulate the price per share value and future depositors are forced to deposit huge value in vault.
   slug: h-1-public-vault-initial-depositor-can-manipulate-the-price-per-share-value-and-future-depositors-are-forced-to-deposit-huge-value-in-vault-sherlock-sense-sense-git
39. Vault price manipulation allows yield manager to mint tokens
   slug: vault-price-manipulation-allows-yield-manager-to-mint-tokens-spearbit-none-aragon-generic-money-pdf
40. [L-03] Morpho low-liquidity vaults at risk of price manipulation
   slug: l-03-morpho-low-liquidity-vaults-at-risk-of-price-manipulation-pashov-audit-group-none-level_2025-04-09-markdown
41. [H-06] Share price manipulation
   slug: h-06-share-price-manipulation-pashov-audit-group-none-nexus_2024-11-29-markdown
42. INITIAL vTHOR SHARE PRICE MANIPULATION EXPOSURE
   slug: initial-vthor-share-price-manipulation-exposure-halborn-thorswap-thorswap-aggregators-markdown
43. [H-05] Underlying assets stealing in `AutoPxGmx` and `AutoPxGlp` via share price manipulation
   slug: h-05-underlying-assets-stealing-in-autopxgmx-and-autopxglp-via-share-price-manipulation-code4rena-redacted-cartel-redacted-cartel-contest-git
44. M-8: Gas engineering during `adapter` execution can be used to maliciously split critical message batches
   slug: m-8-gas-engineering-during-adapter-execution-can-be-used-to-maliciously-split-critical-message-batches-sherlock-centrifuge-protocol-v3-audit-git

## LENDING (55 findings)

1. [H-05] Bad debt is never handled which places insolvency risks on BendDAO
   slug: h-05-bad-debt-is-never-handled-which-places-insolvency-risks-on-benddao-code4rena-benddao-benddao-git
2. M-9: Profitable liquidations and accumulation of bad debt due to earnings accumulator not being triggered before liquidating
   slug: m-9-profitable-liquidations-and-accumulation-of-bad-debt-due-to-earnings-accumulator-not-being-triggered-before-liquidating-sherlock-exactly-protocol-git
3. [M-17] Bad debt can be permanently blocked from being moved to backstop
   slug: m-17-bad-debt-can-be-permanently-blocked-from-being-moved-to-backstop-code4rena-blend-blend-git
4. [M-07] There is no way to liquidate a position if it breaches `maxDebtPerCollateralToken` value creating bad debt.
   slug: m-07-there-is-no-way-to-liquidate-a-position-if-it-breaches-maxdebtpercollateraltoken-value-creating-bad-debt-code4rena-ethereum-credit-guild-ethereum-credit-guild-git
5. Incorrect calculation of effective borrow value in ```getLoanLiquidity``` leads to protocol insolvency through wrong withdrawals and liquidations.
   slug: incorrect-calculation-of-effective-borrow-value-in-getloanliquidity-leads-to-protocol-insolvency-through-wrong-withdrawals-and-liquidations-immunefi-folks-finance-git
6. VaultConfig.setVaultConfig doesn’t check all critical arguments
   slug: vaultconfigsetvaultconfig-doesnt-check-all-critical-arguments-consensys-notional-finance-markdown
7. Usage of Manually Updated Prices Could Result in Protocol Insolvency in Case of Low Update Frequency and Significant Price Deviation
   slug: usage-of-manually-updated-prices-could-result-in-protocol-insolvency-in-case-of-low-update-frequency-and-significant-price-deviation-quantstamp-elara-finance-markdown
8. [H-06] The amount of `xezETH` in circulation will not represent the amount of `ezETH` tokens 1:1
   slug: h-06-the-amount-of-xezeth-in-circulation-will-not-represent-the-amount-of-ezeth-tokens-11-code4rena-renzo-renzo-git
9. [H-06] Owner of a position can prevent liquidation due to the `onERC721Received` callback
   slug: h-06-owner-of-a-position-can-prevent-liquidation-due-to-the-onerc721received-callback-code4rena-revert-lend-revert-lend-git
10. Adversaries can create a position that is nearly impossible to liquidate due to high gas consumption
   slug: adversaries-can-create-a-position-that-is-nearly-impossible-to-liquidate-due-to-high-gas-consumption-immunefi-folks-finance-git
11. [H-07] Malicious borrower cycle exploits to inflate interest rates
   slug: h-07-malicious-borrower-cycle-exploits-to-inflate-interest-rates-code4rena-loopfi-loopfi-git
12. Interest Accrual Mismatch
   slug: interest-accrual-mismatch-ottersec-none-meso-lending-pdf
13. [H-03] Malicious borrowers will never repay loans with high interest
   slug: h-03-malicious-borrowers-will-never-repay-loans-with-high-interest-code4rena-lavarage-lavarage-git
14. M-19: Attacker Can Manipulate Interest Distribution by Exploiting Asset Transfers and Fee Accrual Mechanism
   slug: m-19-attacker-can-manipulate-interest-distribution-by-exploiting-asset-transfers-and-fee-accrual-mechanism-sherlock-sentiment-v2-git
15. Interest Accrual Failure Due to Incorrect Scaling in RToken Implementation
   slug: interest-accrual-failure-due-to-incorrect-scaling-in-rtoken-implementation-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
16. `AccountableOpenTerm` loan interest cannot be repaid once principal hits zero
   slug: accountableopenterm-loan-interest-cannot-be-repaid-once-principal-hits-zero-cyfrin-none-accountable-markdown
17. `Licredity::decreaseDebtShare` bypasses interest accrual
   slug: licreditydecreasedebtshare-bypasses-interest-accrual-cyfrin-none-licredity-markdown
18. [M-04] Liquidity pool interest accrual can be manipulated
   slug: m-04-liquidity-pool-interest-accrual-can-be-manipulated-pashov-audit-group-none-sharwafinance-markdown
19. Interest accrual whilst the VaultController is paused
   slug: interest-accrual-whilst-the-vaultcontroller-is-paused-sigmaprime-none-interest-protocol-pdf
20. Borrower can reduce lender accruals
   slug: borrower-can-reduce-lender-accruals-trailofbits-atlendis-labs-loan-products-pdf
21. [M-09] User collateral NFT open auctions would be sold as min price immediately next time user health factor gets below the liquidation threshold, protocol should check health factor and set auctionValidityTime value anytime a valid action happens to user account to invalidate old open auctions
   slug: m-09-user-collateral-nft-open-auctions-would-be-sold-as-min-price-immediately-next-time-user-health-factor-gets-below-the-liquidation-threshold-protocol-should-check-health-factor-and-set-auctionvaliditytime-value-anytime-a-valid-action-happens-to-user-account-to-invalidate-old-open-auctions-code4rena-paraspace-paraspace-contest-git
22. WithdrawHandler.getWithdrawableAmount() should utilize _unsettled, which is not scaled by the collateral factor 
   slug: withdrawhandlergetwithdrawableamount-should-utilize-_unsettled-which-is-not-scaled-by-the-collateral-factor-cantina-none-desk-pdf
23. Users can become immediately liquidatable after executing an action
   slug: users-can-become-immediately-liquidatable-after-executing-an-action-trailofbits-none-aave-v4-pdf
24. Liquidation Is Prevented Due To Strict Implementation of Liqudation Bonus
   slug: liquidation-is-prevented-due-to-strict-implementation-of-liqudation-bonus-codehawks-foundry-defi-stablecoin-codehawks-audit-contest-git
25. M-14: Liquidation does not prioritize lowest LTV tokens
   slug: m-14-liquidation-does-not-prioritize-lowest-ltv-tokens-sherlock-exactly-protocol-git
26. [M-10] Liquidation should make a borrower healthier
   slug: m-10-liquidation-should-make-a-borrower-healthier-code4rena-inverse-finance-inverse-finance-contest-git
27. M-10: `TARGET_HEALTH` calculation does not consider the adjust factors of the picked seize and repay markets
   slug: m-10-target_health-calculation-does-not-consider-the-adjust-factors-of-the-picked-seize-and-repay-markets-sherlock-exactly-protocol-git
28. M-1: Attacker/partial liquidator can extend Liquidation action by resetting  $.liquidationStart[_agent] to 0.
   slug: m-1-attackerpartial-liquidator-can-extend-liquidation-action-by-resetting-liquidationstart_agent-to-0-sherlock-cap-git
29. Discrepancy between health calculation and slashable collateral computation
   slug: discrepancy-between-health-calculation-and-slashable-collateral-computation-trailofbits-none-cap-labs-covered-agent-protocol-pdf
30. M-4: Compound exchange rate can be manipulated to withdraw more underlying tokens from NotionalV3
   slug: m-4-compound-exchange-rate-can-be-manipulated-to-withdraw-more-underlying-tokens-from-notionalv3-sherlock-none-notional-v3-git
31. [M-02] Chainlink Oracles may return stale prices or may be unusable when aggregator `roundId` is less than 50
   slug: m-02-chainlink-oracles-may-return-stale-prices-or-may-be-unusable-when-aggregator-roundid-is-less-than-50-code4rena-wise-lending-wise-lending-git
32. Missing staleness checks in oracle queries
   slug: missing-staleness-checks-in-oracle-queries-halborn-swaylend-swaylend-protocol-markdown
33. Incomplete User Data State Update in initiateLiquidation Causes Inconsistent Liquidation Behavior
   slug: incomplete-user-data-state-update-in-initiateliquidation-causes-inconsistent-liquidation-behavior-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
34. [M-05] Missing oracle updates in `RewardsManager`
   slug: m-05-missing-oracle-updates-in-rewardsmanager-pashov-audit-group-none-level_2025-04-09-markdown
35. Additional Risks for Lenders Due to Lack of Checks on Oracle Output
   slug: additional-risks-for-lenders-due-to-lack-of-checks-on-oracle-output-quantstamp-altr-markdown
36. [M-02] Invalid utilization ratio check, blocking users from submitting a flash loan
   slug: m-02-invalid-utilization-ratio-check-blocking-users-from-submitting-a-flash-loan-code4rena-blend-blend-git
37. M-19: An attacker can steal the entire borrow and lending incentive of an epoch with FLASHLOAN in a single transaction
   slug: m-19-an-attacker-can-steal-the-entire-borrow-and-lending-incentive-of-an-epoch-with-flashloan-in-a-single-transaction-sherlock-debita-finance-v3-git
38. M-2: Users can borrow all loan tokens
   slug: m-2-users-can-borrow-all-loan-tokens-sherlock-none-surge-git
39. M-8: Users can borrow all loan tokens
   slug: m-8-users-can-borrow-all-loan-tokens-sherlock-surge-surge-git
40. [H-10] Flash loan protection mechanism can be bypassed via self-liquidations
   slug: h-10-flash-loan-protection-mechanism-can-be-bypassed-via-self-liquidations-code4rena-dyad-dyad-git
41. [H-02] An attacker can contribute to the ETH crowdfund using a flash loan and control the party as he likes
   slug: h-02-an-attacker-can-contribute-to-the-eth-crowdfund-using-a-flash-loan-and-control-the-party-as-he-likes-code4rena-partydao-party-protocol-versus-contest-git
42. Usage of `balanceOf(address(this))` can lead to manipulation
   slug: usage-of-balanceofaddressthis-can-lead-to-manipulation-zokyo-none-copra-markdown
43. Flash loan with 0 fees 
   slug: flash-loan-with-0-fees-cantina-none-metastreet-labs-pdf
44. Pi interest rate model is manipulatable due to current balances used
   slug: pi-interest-rate-model-is-manipulatable-due-to-current-balances-used-spearbit-none-astera-pdf
45. Pi interest rate model is manipulatable due to current balances used
   slug: pi-interest-rate-model-is-manipulatable-due-to-current-balances-used-spearbit-none-cod3x-lend-pdf
46. [H-02] Liquidation doesn't account for penalty when calculating collateral to give, allowing users to profit by borrowing and self-liquidating
   slug: h-02-liquidation-doesnt-account-for-penalty-when-calculating-collateral-to-give-allowing-users-to-profit-by-borrowing-and-self-liquidating-code4rena-loopfi-loopfi-git
47. Self liquidations are profitable under certain collateralization ratios
   slug: self-liquidations-are-profitable-under-certain-collateralization-ratios-spearbit-none-size-v1-pdf
48. [M-12] Pull Based Oracle may allow for profitable self-liquidations
   slug: m-12-pull-based-oracle-may-allow-for-profitable-self-liquidations-recon-audits-none-apollon-report-markdown
49. Self-liquidations of leveraged positions can be profitable
   slug: self-liquidations-of-leveraged-positions-can-be-profitable-spearbit-none-euler-labs-evk-pdf
50. H-1: It is possible to frontrun liquidations with self liquidation with high strain value to clear warning and keep unhealthy positions from liquidation
   slug: h-1-it-is-possible-to-frontrun-liquidations-with-self-liquidation-with-high-strain-value-to-clear-warning-and-keep-unhealthy-positions-from-liquidation-sherlock-aloe-git
51. Self liquidation with sub-accounts is allowed, which can enable "future unknown protocol attacks" 
   slug: self-liquidation-with-sub-accounts-is-allowed-which-can-enable-future-unknown-protocol-attacks-cantina-none-euler-pdf
52. Unexpected fee deduction on self-liquidations
   slug: unexpected-fee-deduction-on-self-liquidations-spearbit-none-size-v1-pdf
53. [M-10] Liquidation should make a borrower *healthier*
   slug: m-10-liquidation-should-make-a-borrower-healthier-code4rena-inverse-finance-inverse-finance-git
54. Proxy-Based self-liquidation creates bad debt for lenders
   slug: proxy-based-self-liquidation-creates-bad-debt-for-lenders-cyfrin-none-licredity-markdown
55. The stale price feed update in the _isLoanLiquidatable can cause loss of funds to the lender 
   slug: the-stale-price-feed-update-in-the-_isloanliquidatable-can-cause-loss-of-funds-to-the-lender-cantina-none-hyperlabs-inc-pdf

## ORACLE (42 findings)

1. Lack Of Chainlink's Stale Price Checks
   slug: lack-of-chainlinks-stale-price-checks-halborn-concrete-spokes-v1-markdown
2. Missing stale price validation in chainlink 's agreggator latestRoundData() call 
   slug: missing-stale-price-validation-in-chainlink-s-agreggator-latestrounddata-call-cantina-none-threshold-pdf
3. [M-24] Chainlink price feed is not sufficiently validated and can return stale price
   slug: m-24-chainlink-price-feed-is-not-sufficiently-validated-and-can-return-stale-price-code4rena-tigris-trade-tigris-trade-contest-git
4. [L-03] `AssetPriceProvider` misses stale Chainlink price check
   slug: l-03-assetpriceprovider-misses-stale-chainlink-price-check-pashov-audit-group-none-napier_2025-09-30-markdown
5. Missing Chainlink oracle staleness check
   slug: missing-chainlink-oracle-staleness-check-cyfrin-none-licredity-markdown
6. Chainlink Oracle Price Feed Used Without Staleness Check
   slug: chainlink-oracle-price-feed-used-without-staleness-check-halborn-prodigy-brt-dci-contracts-markdown
7. [M-04] Chainlink's `latestRoundData` might return stale or incorrect results
   slug: m-04-chainlinks-latestrounddata-might-return-stale-or-incorrect-results-code4rena-predy-predy-git
8. `RewardsDistributor::amountToCompound()` - L118: The `staleThreshold` variable was accidentally left at a value suitable for testing phase only, which carries a very high risk of very stale prices being used.
   slug: rewardsdistributoramounttocompound-l118-the-stalethreshold-variable-was-accidentally-left-at-a-value-suitable-for-testing-phase-only-which-carries-a-very-high-risk-of-very-stale-prices-being-used-immunefi-alchemix-git
9. M-6: Chainlink price feed is `deprecated`, not sufficiently validated and can return `stale` prices.
   slug: m-6-chainlink-price-feed-is-deprecated-not-sufficiently-validated-and-can-return-stale-prices-sherlock-none-index-git
10. M-2: Chainlink's `latestRoundData` might return stale or incorrect results
   slug: m-2-chainlinks-latestrounddata-might-return-stale-or-incorrect-results-sherlock-knox-knox-finance-git
11. TWAP oracle can be manipulated by only manipulating around the _updateGap oracle writes
   slug: twap-oracle-can-be-manipulated-by-only-manipulating-around-the-_updategap-oracle-writes-spearbit-none-hyperdrive-june-2023-pdf
12. M-1: LibUbiquityPool::mintDollar/redeemDollar reliance on outdated TWAP oracle may be inefficient for preventing depeg
   slug: m-1-libubiquitypoolmintdollarredeemdollar-reliance-on-outdated-twap-oracle-may-be-inefficient-for-preventing-depeg-sherlock-ubiquity-git
13. [M-11] An attacker can manipulate oracle easily
   slug: m-11-an-attacker-can-manipulate-oracle-easily-code4rena-panoptic-panoptic-git
14. M-4: LibTWAPOracle::update Providing large liquidity will manipulate TWAP, DOSing redeem of uADs
   slug: m-4-libtwaporacleupdate-providing-large-liquidity-will-manipulate-twap-dosing-redeem-of-uads-sherlock-ubiquity-git
15. M-3: LibUbiquityPool::mintDollar/redeemDollar reliance on arbitrarily short TWAP oracle may be inefficient for preventing depeg
   slug: m-3-libubiquitypoolmintdollarredeemdollar-reliance-on-arbitrarily-short-twap-oracle-may-be-inefficient-for-preventing-depeg-sherlock-ubiquity-git
16. [M-01] Updating oracle with post-swap `lnImpliedRate` allows TWAP manipulation
   slug: m-01-updating-oracle-with-post-swap-lnimpliedrate-allows-twap-manipulation-pashov-audit-group-none-napier_2025-09-30-markdown
17. AmAmm manager can manipulate TWAP prices without risk
   slug: amamm-manager-can-manipulate-twap-prices-without-risk-trailofbits-none-bunni-v2-pdf
18. Time Weighted Average Price oracles are susceptible to manipulation
   slug: time-weighted-average-price-oracles-are-susceptible-to-manipulation-cyfrin-none-beanstalk-wells-markdown_
19. [M-30] Chainlink price feed uses BTC, not WBTC. In case of depegging, oracles will become easier to manipulate
   slug: m-30-chainlink-price-feed-uses-btc-not-wbtc-in-case-of-depegging-oracles-will-become-easier-to-manipulate-code4rena-saltyio-saltyio-git
20. [M-01] TWAP price manipulation
   slug: m-01-twap-price-manipulation-pashov-audit-group-none-titanx-markdown
21. Pools Can Be Subject to Price Manipulation Leading to Early Liquidations or Arbitrage
   slug: pools-can-be-subject-to-price-manipulation-leading-to-early-liquidations-or-arbitrage-openzeppelin-none-fx-v2-audit-markdown
22. Use of spot price in SponsorVault leads to sandwich attack.
   slug: use-of-spot-price-in-sponsorvault-leads-to-sandwich-attack-spearbit-connext-pdf
23. Spot price manipulation can lead to unfair liquidations
   slug: spot-price-manipulation-can-lead-to-unfair-liquidations-cyfrin-none-deriverse-dex-markdown
24. deposit and withdraw functions are susceptible to sandwich attacks
   slug: deposit-and-withdraw-functions-are-susceptible-to-sandwich-attacks-spearbit-gauntlet-pdf
25. IRM synth rate always moves even when no trade is possible due to swap fees 
   slug: irm-synth-rate-always-moves-even-when-no-trade-is-possible-due-to-swap-fees-cantina-none-euler-pdf
26. calc_withdraw_one_coin is vulnerable to manipulation
   slug: calc_withdraw_one_coin-is-vulnerable-to-manipulation-trailofbits-frax-solidity-pdf
27. [H-05] Synth realise is vulnerable to flash loan attacks
   slug: h-05-synth-realise-is-vulnerable-to-flash-loan-attacks-code4rena-spartan-protocol-spartan-protocol-contest-git
28. Oracle manipulation via missing balancer vault read-only reentrancy check 
   slug: oracle-manipulation-via-missing-balancer-vault-read-only-reentrancy-check-cantina-none-opalprotocol-pdf
29. Read-only reentrancy
   slug: read-only-reentrancy-cyfrin-beanstalk-wells-markdown
30. H-13: `BalancerPairOracle` can be manipulated using read-only reentrancy
   slug: h-13-balancerpairoracle-can-be-manipulated-using-read-only-reentrancy-sherlock-none-blueberry-update-git
31. Liquidation won 't work when a nesting vault of the liability vault is used as collateral 
   slug: liquidation-won-t-work-when-a-nesting-vault-of-the-liability-vault-is-used-as-collateral-cantina-none-euler-pdf
32. H-5: Curve V2 Vaults can be drained because CurveV2CryptoEthOracle can be reentered with WETH tokens
   slug: h-5-curve-v2-vaults-can-be-drained-because-curvev2cryptoethoracle-can-be-reentered-with-weth-tokens-sherlock-tokemak-git
33. [H-04] There are multiple issues with the decimal conversions between the vault and the strategy
   slug: h-04-there-are-multiple-issues-with-the-decimal-conversions-between-the-vault-and-the-strategy-code4rena-bakerfi-bakerfi-git
34. [M-08] PriceFeed does not return to the correct price for quote pairs
   slug: m-08-pricefeed-does-not-return-to-the-correct-price-for-quote-pairs-code4rena-predy-predy-git
35. LP Oracle Should Enforce 18 Decimals Or Use Decimal Flexible Fixed Point Math
   slug: lp-oracle-should-enforce-18-decimals-or-use-decimal-flexible-spearbit-sense-pdf
36. Fee calculations break when token decimals are different from 18
   slug: fee-calculations-break-when-token-decimals-are-different-from-18-cyfrin-none-octodefi-markdown
37. Bigger Precision loss In tokenAmount To USD conversion will lead incorrect liquidation re- sult 
   slug: bigger-precision-loss-in-tokenamount-to-usd-conversion-will-lead-incorrect-liquidation-re-sult-cantina-none-hyperlabs-inc-pdf
38. M-18: TwoTokenPoolUtils's _getOraclePairPrice produces incorrect oraclePairPrice when balancerOracleWeight is set to be bigger than BALANCER_ORACLE_WEIGHT_PRECISION
   slug: m-18-twotokenpoolutilss-_getoraclepairprice-produces-incorrect-oraclepairprice-when-balanceroracleweight-is-set-to-be-bigger-than-balancer_oracle_weight_precision-sherlock-notional-notional-git
39. Decimal Adjustment Safety in DIAOracleV2Guardian
   slug: decimal-adjustment-safety-in-diaoraclev2guardian-mixbytes-none-dia-markdown
40. M-1: MetaStable2TokenAuraVault allows only up to 1bp weight for Balancer TWAP oracle
   slug: m-1-metastable2tokenauravault-allows-only-up-to-1bp-weight-for-balancer-twap-oracle-sherlock-notional-notional-git
41. Chainlink oracles could return stale price data
   slug: chainlink-oracles-could-return-stale-price-data-trailofbits-none-saltyio-pdf
42. M-13: Rely On Balancer Oracle Which Is Not Updated Frequently
   slug: m-13-rely-on-balancer-oracle-which-is-not-updated-frequently-sherlock-notional-notional-git

## FLASH LOAN (29 findings)

1. FlasherFTM - Unsolicited invocation of the callback (CREAM auth bypass)
   slug: flasherftm-unsolicited-invocation-of-the-callback-cream-auth-bypass-consensys-fuji-protocol-markdown
2. [H-06] Reentrancy vulnerability allows bypass of cooldown, leading to unfair reward extraction through flash loan
   slug: h-06-reentrancy-vulnerability-allows-bypass-of-cooldown-leading-to-unfair-reward-extraction-through-flash-loan-code4rena-phi-phi-git
3. [H-02] Stealing fund by applying reentrancy attack on `removeCollateral`, `startLiquidationAuction`, and `purchaseLiquidationAuctionNFT`
   slug: h-02-stealing-fund-by-applying-reentrancy-attack-on-removecollateral-startliquidationauction-and-purchaseliquidationauctionnft-code4rena-backed-protocol-backed-protocol-git
4. [H-02] Stealing fund by applying reentrancy attack on removeCollateral, startLiquidationAuction, and purchaseLiquidationAuctionNFT
   slug: h-02-stealing-fund-by-applying-reentrancy-attack-on-removecollateral-startliquidationauction-and-purchaseliquidationauctionnft-code4rena-backed-protocol-papr-contest-git
5. H-1: CNumaToken.leverageStrategy() can be re-entered, causing all the vault funds to be moved to a cToken, crashing NUMA price.
   slug: h-1-cnumatokenleveragestrategy-can-be-re-entered-causing-all-the-vault-funds-to-be-moved-to-a-ctoken-crashing-numa-price-sherlock-numa-git
6. H-2: Reentrancy in flashAction() allows draining liquidity pools
   slug: h-2-reentrancy-in-flashaction-allows-draining-liquidity-pools-sherlock-arcadia-git
7. Random task execution ✓ Fixed
   slug: random-task-execution-fixed-consensys-defi-saver-markdown
8. [H-03] An attacker can hijack any ERC1155 token he rents due to a design issue in reNFT via reentrancy exploitation
   slug: h-03-an-attacker-can-hijack-any-erc1155-token-he-rents-due-to-a-design-issue-in-renft-via-reentrancy-exploitation-code4rena-renft-renft-git
9. (HAL-03) Potential reentrancy
   slug: hal-03-potential-reentrancy-halborn-harvest-finance-harvest-strategy-base-markdown
10. [M-06] Risky Footguns from Bold
   slug: m-06-risky-footguns-from-bold-recon-audits-none-quill-finance-report-markdown
11. H-7: Attacker can block all votes to a specific pool by triggering an overflow error
   slug: h-7-attacker-can-block-all-votes-to-a-specific-pool-by-triggering-an-overflow-error-sherlock-magicsea-the-native-dex-on-the-iotaevm-git
12. [M-01] Low data feed frequency from Tellor makes your protocol vulnerable to flash loan attacks
   slug: m-01-low-data-feed-frequency-from-tellor-makes-your-protocol-vulnerable-to-flash-loan-attacks-code4rena-ethos-reserve-ethos-reserve-contest-git
13. Flash minting can be used to redeem ​fyDAI
   slug: flash-minting-can-be-used-to-redeem-fydai-trailofbits-yield-protocol-pdf
14. Flash Loan Attack on Gauge Reward Distribution via `get_adjustment()` Manipulation
   slug: flash-loan-attack-on-gauge-reward-distribution-via-get_adjustment-manipulation-mixbytes-none-yield-basis-markdown
15. [M-02] All yield generated in the IBT vault can be drained by performing a vault deflation attack using the flash loan functionality of the Principal Token contract
   slug: m-02-all-yield-generated-in-the-ibt-vault-can-be-drained-by-performing-a-vault-deflation-attack-using-the-flash-loan-functionality-of-the-principal-token-contract-code4rena-spectra-spectra-git
16. [H-04] TokenisableRange's incorrect accounting of non-reinvested fees in "deposit" exposes the fees to a flash-loan attack
   slug: h-04-tokenisableranges-incorrect-accounting-of-non-reinvested-fees-in-deposit-exposes-the-fees-to-a-flash-loan-attack-code4rena-good-entry-good-entry-git
17. H-4: An attacker can hijack the `CuratedVault`'s matured yield
   slug: h-4-an-attacker-can-hijack-the-curatedvaults-matured-yield-sherlock-zerolend-one-git
18. An attacker can steal the StabilityPool depositors profit
   slug: an-attacker-can-steal-the-stabilitypool-depositors-profit-mixbytes-none-prisma-finance-markdown
19. If MAX_FEE is set too high, user may be able to underﬂow deposit value to steal all funds 
   slug: if-max_fee-is-set-too-high-user-may-be-able-to-underflow-deposit-value-to-steal-all-funds-cantina-none-sablier-pdf
20. [H-10] Flash loan protection mechanism can be bypassed via self-liquidations
   slug: h-10-flash-loan-protection-mechanism-can-be-bypassed-via-self-liquidations-code4rena-dyad-dyad-git
21. [M-11] An attacker can manipulate oracle easily
   slug: m-11-an-attacker-can-manipulate-oracle-easily-code4rena-panoptic-panoptic-git
22. `UniswapV2Router::getAmountsOut()` based upon pool reserves allowing returned price to be manipulated via flash loan
   slug: uniswapv2routergetamountsout-based-upon-pool-reserves-allowing-returned-price-to-be-manipulated-via-flash-loan-cyfrin-none-cyfrin-dexe-markdown
23. [H-05] Flash loan price manipulation in purchasePyroFlan()
   slug: h-05-flash-loan-price-manipulation-in-purchasepyroflan-code4rena-behodler-behodler-contest-git
24. [M-08] Oracles are vulnerable to flash loan attack vectors
   slug: m-08-oracles-are-vulnerable-to-flash-loan-attack-vectors-pashov-audit-group-none-stakedao_2025-07-21-markdown
25. [H-04] Oracle price can be manipulated
   slug: h-04-oracle-price-can-be-manipulated-code4rena-abracadabra-money-abracadabra-money-git
26. [M-08] `reLPContract.reLP()` is susceptible to sandwich attack due to user control over `bond()`
   slug: m-08-relpcontractrelp-is-susceptible-to-sandwich-attack-due-to-user-control-over-bond-code4rena-dopex-dopex-git
27. Emission Rate can be Manipulated (Locked, Higher or Lower)
   slug: emission-rate-can-be-manipulated-locked-higher-or-lower-codehawks-regnum-aurum-acquisition-corp-core-contracts-git
28. [M-30] Chainlink price feed uses BTC, not WBTC. In case of depegging, oracles will become easier to manipulate
   slug: m-30-chainlink-price-feed-uses-btc-not-wbtc-in-case-of-depegging-oracles-will-become-easier-to-manipulate-code4rena-saltyio-saltyio-git
29. Oracle Manipulation with Flashloans Can Exploit Funds via Liquidation
   slug: oracle-manipulation-with-flashloans-can-exploit-funds-via-liquidation-quantstamp-ethereum-reserve-dollar-erd-markdown

## ACCESS CONTROL (44 findings)

1. Missing Access Control in Policy termination blueprint
   slug: missing-access-control-in-policy-termination-blueprint-halborn-concrete-hub-v1-markdown
2. Missing Access Control
   slug: missing-access-control-ottersec-none-cega-sharkfin-notes-pdf
3. [M-03] Missing access control on UTB:receiveFromBridge allows UTB swaps to be executed without spending bridge fees while bypassing fee/swap instruction signature verification
   slug: m-03-missing-access-control-on-utbreceivefrombridge-allows-utb-swaps-to-be-executed-without-spending-bridge-fees-while-bypassing-feeswap-instruction-signature-verification-code4rena-decent-decent-git
4. H-4: Missing access modifier for `RFPSimpleStrategy.setPoolActive()` may lead to multiple issues
   slug: h-4-missing-access-modifier-for-rfpsimplestrategysetpoolactive-may-lead-to-multiple-issues-sherlock-allo-v2-git
5. [H-01] Missing access control in `updateFairLaunchProperties()` function
   slug: h-01-missing-access-control-in-updatefairlaunchproperties-function-naman-none-hyacinth-markdown
6. Missing access control in burn
   slug: missing-access-control-in-burn-zokyo-none-trzn-finance-markdown
7. [H-01] All tokens can be stolen from `VirtualAccount` due to missing access modifier
   slug: h-01-all-tokens-can-be-stolen-from-virtualaccount-due-to-missing-access-modifier-code4rena-maia-dao-maia-dao-git
8. [H-18] Reentrancy attack possible on `RootBridgeAgent.retrySettlement()` with missing access control for `RootBridgeAgentFactory.createBridgeAgent()`
   slug: h-18-reentrancy-attack-possible-on-rootbridgeagentretrysettlement-with-missing-access-control-for-rootbridgeagentfactorycreatebridgeagent-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git
9. Missing access control in `SDLVesting::stakeReleasableTokens`
   slug: missing-access-control-in-sdlvestingstakereleasabletokens-cyfrin-none-stakelink-vesting-markdown
10. Missing access control in `CollateralLiquidityProvider::setExternalCollateralRedemption`
   slug: missing-access-control-in-collateralliquidityprovidersetexternalcollateralredemption-cyfrin-none-securitize-redemptions-markdown
11. [M-01] Some arbitrary proposal calls will fail because `executeProposal()` in `ProposalExecutionEngine` is not payable
   slug: m-01-some-arbitrary-proposal-calls-will-fail-because-executeproposal-in-proposalexecutionengine-is-not-payable-code4rena-party-protocol-party-protocol-git
12. Refunding ETH to the caller can be exploited using the Tractor component to call any arbitrary function on behalf of the publisher
   slug: refunding-eth-to-the-caller-can-be-exploited-using-the-tractor-component-to-call-any-arbitrary-function-on-behalf-of-the-publisher-codehawks-beanstalk-the-finale-git
13. Extra attention must be paid to future contract upgrades that utilize new or otherwise modify existing low-level calls
   slug: extra-attention-must-be-paid-to-future-contract-upgrades-that-utilize-new-or-otherwise-modify-existing-low-level-calls-cyfrin-none-cyfrin-beanstalk-markdown
14. [H-01] Unauthorized contracts can bypass precompile authorization via `delegatecall` in Kakarot zkEVM
   slug: h-01-unauthorized-contracts-can-bypass-precompile-authorization-via-delegatecall-in-kakarot-zkevm-code4rena-kakarot-kakarot-git
15. Both Transactor.CALL and Transactor.DELEGATECALL Do Not Emit Events
   slug: both-transactorcall-and-transactordelegatecall-do-not-emit-events-spearbit-optimism-drippie-pdf
16. [H-16] Attacker can block LayerZero channel due to variable gas cost of saving payload
   slug: h-16-attacker-can-block-layerzero-channel-due-to-variable-gas-cost-of-saving-payload-code4rena-tapioca-dao-tapioca-dao-git
17. Transactor.DELEGATECALL Data Overwrite and selfdestruct Risks
   slug: transactordelegatecall-data-overwrite-and-selfdestruct-risks-spearbit-optimism-drippie-pdf
18. [H-02] CM can `delegatecall` to any address and bypass all restrictions
   slug: h-02-cm-can-delegatecall-to-any-address-and-bypass-all-restrictions-code4rena-olas-olas-git
19. Missing checks cause DoS & consistent failed redemptions in IntentTokenMinting
   slug: missing-checks-cause-dos-consistent-failed-redemptions-in-intenttokenminting-halborn-dappos-intent-assets-markdown
20. Lack of contract existence check on delegatecall will result in unexpected behavior
   slug: lack-of-contract-existence-check-on-delegatecall-will-result-in-unexpected-behavior-trailofbits-frax-finance-pdf
21. [L-15] Shared privilege concerns in role-based access control cards
   slug: l-15-shared-privilege-concerns-in-role-based-access-control-cards-pashov-audit-group-none-ripit_2025-04-25-markdown
22. H-2: Missing input validation for _rewardProportion parameter allows keeper to escalate his privileges and pay back all loans
   slug: h-2-missing-input-validation-for-_rewardproportion-parameter-allows-keeper-to-escalate-his-privileges-and-pay-back-all-loans-sherlock-taurus-taurus-git
23. [M-05] Bridge watcher can forge arbitrary message and drain bridge
   slug: m-05-bridge-watcher-can-forge-arbitrary-message-and-drain-bridge-code4rena-taiko-taiko-git
24. [M-02] Critical access control flaw: Role removal logic incorrectly grants unauthorized roles
   slug: m-02-critical-access-control-flaw-role-removal-logic-incorrectly-grants-unauthorized-roles-code4rena-audit-507-audit-507-git
25. [L-01] SetRoles prevents self-assignment for `GOV_TIMELOCK` only
   slug: l-01-setroles-prevents-self-assignment-for-gov_timelock-only-pashov-audit-group-none-gainsnetwork_2025-05-26-markdown
26. M-9: is_permissioned() It doesn't make sense to have permissions by default after Blacklisted expires.
   slug: m-9-is_permissioned-it-doesnt-make-sense-to-have-permissions-by-default-after-blacklisted-expires-sherlock-andromeda-validator-staking-ado-and-vesting-ado-git
27. RollupRevenueVault - Deployment and Initialization Flow ✓ Fixed
   slug: rolluprevenuevault-deployment-and-initialization-flow-fixed-consensys-none-linea-burn-mechanism-markdown
28. A claim cannot be paid out or escalated if the protocol agent changes after the claim has been initialized
   slug: a-claim-cannot-be-paid-out-or-escalated-if-the-protocol-agent-changes-after-the-claim-has-been-initialized-trailofbits-sherlock-protocol-v2-pdf
29. [M-01] Excessive Authority Granted to Managers in the `ckr_btc.cairo` Contract Presents Significant Management Risks
   slug: m-01-excessive-authority-granted-to-managers-in-the-ckr_btccairo-contract-presents-significant-management-risks-code4rena-chakra-chakra-git
30. Initialize implementations for proxy contracts and protect initialization methods ✓ Addressed
   slug: initialize-implementations-for-proxy-contracts-and-protect-initialization-methods-addressed-consensys-thesis-tbtc-and-keep-markdown
31. Custom unprotected initializer in upgradeable token.
   slug: custom-unprotected-initializer-in-upgradeable-token-zokyo-none-taunt-token-markdown
32. Unprotected initializer.
   slug: unprotected-initializer-zokyo-none-stablr-markdown
33. Unprotected initialize function
   slug: unprotected-initialize-function-zokyo-none-sivira-markdown
34. zAuction - pot. initialization fronrunning and unnecessary init function ✓ Fixed
   slug: zauction-pot-initialization-fronrunning-and-unnecessary-init-function-fixed-consensys-zer0-zauction-markdown
35. DiamondInit can be initialized itself
   slug: diamondinit-can-be-initialized-itself-openzeppelin-zksync-layer-1-audit-markdown
36. Potentially Uninitialized Implementations
   slug: potentially-uninitialized-implementations-consensys-none-kilnfi-staking-consensys-markdown
37. Potentially Uninitialized Implementations
   slug: potentially-uninitialized-implementations-consensys-none-kilnfi-staking-markdown
38. [STAKE-6] Unprotected flash loan callback can be abused to manipulate/claim other users' positions
   slug: stake-6-unprotected-flash-loan-callback-can-be-abused-to-manipulateclaim-other-users-positions-hexens-none-stakewise-markdown
39. Withdraw Root Can Be Set Up as a Rug Pull
   slug: withdraw-root-can-be-set-up-as-a-rug-pull-openzeppelin-none-scroll-phase-1-audit-markdown
40. Usage of `tx.origin` for Access Control Is Unsafe Due to Phishing Risk
   slug: usage-of-txorigin-for-access-control-is-unsafe-due-to-phishing-risk-quantstamp-powerloom-l2-markdown
41. Usage Of Tx.Origin
   slug: usage-of-txorigin-ottersec-none-eth-sign-vesting-v2-pdf
42. Check For Admin Address
   slug: check-for-admin-address-ottersec-none-vtvl-pdf
43. Vulnerable to phishing
   slug: vulnerable-to-phishing-zokyo-none-velocore-markdown
44. Opportunities for Malicious Tokens to Poison Logs
   slug: opportunities-for-malicious-tokens-to-poison-logs-sigmaprime-none-sushi-pdf

## DEX AMM (32 findings)

1. [L-08] `x * y = k` invariant not maintained
   slug: l-08-x-y-k-invariant-not-maintained-pashov-audit-group-none-aburra-markdown
2. [H-01] Protocol allows creating broken tri-crypto CPMM pools
   slug: h-01-protocol-allows-creating-broken-tri-crypto-cpmm-pools-code4rena-mantra-mantra-git
3. Curve stable swap AMM is not usable
   slug: curve-stable-swap-amm-is-not-usable-trailofbits-none-fiva-yield-tokenization-protocol-pdf
4. Missing zero output validation in `SecuritizeAmmNavProvider` quote and buy functions
   slug: missing-zero-output-validation-in-securitizeammnavprovider-quote-and-buy-functions-cyfrin-none-securitize-public-stock-ramp-markdown
5. `removeLiquidity` logic is not correct for generalized Well functions other than ConstantProduct
   slug: removeliquidity-logic-is-not-correct-for-generalized-well-functions-other-than-constantproduct-cyfrin-beanstalk-wells-markdown_
6. Stricter State Transitions
   slug: stricter-state-transitions-ottersec-none-raydium-amm-pdf
7. SwapManager Swaps Without Slippage Protection
   slug: swapmanager-swaps-without-slippage-protection-halborn-tren-finance-hooks-contracts-markdown
8. Missing Slippage Protection in Token Swap Execution  Acknowledged
   slug: missing-slippage-protection-in-token-swap-execution-acknowledged-consensys-none-metamask-delegation-framework-april-2025-markdown
9. Missing slippage protection for rewards swap
   slug: missing-slippage-protection-for-rewards-swap-consensys-fuji-protocol-markdown
10. [M-01] `_harvest` has no slippage protection when swapping `auraBAL` for `AURA`
   slug: m-01-_harvest-has-no-slippage-protection-when-swapping-aurabal-for-aura-code4rena-badgerdao-badger-vested-aura-contest-git
11. No slippage protection for swaps
   slug: no-slippage-protection-for-swaps-halborn-altcoinist-staking-markdown
12. Slippage protection 
   slug: slippage-protection-cantina-none-sushi-pdf
13. Missing slippage protection on SyncSwap swaps 
   slug: missing-slippage-protection-on-syncswap-swaps-cantina-none-clave-pdf
14. Insuﬃcient slippage protection in redeemEarlyLv leads to MEV through ﬂash swaps 
   slug: insufficient-slippage-protection-in-redeemearlylv-leads-to-mev-through-flash-swaps-cantina-none-cork-pdf
15. [M-03] Slippage protection in `AgentTax::dcaSell` and `BondingTax::swapForAsset` is calculated at execution time, effectively retrieving the very same price that the trade will be executing at, ultimately providing no protection
   slug: m-03-slippage-protection-in-agenttaxdcasell-and-bondingtaxswapforasset-is-calculated-at-execution-time-effectively-retrieving-the-very-same-price-that-the-trade-will-be-executing-at-ultimately-providing-no-protection-code4rena-virtuals-protocol-virtuals-protocol-git
16. [C-01] Critical precision loss in slippage protection calculation
   slug: c-01-critical-precision-loss-in-slippage-protection-calculation-pashov-audit-group-none-ulti-november-markdown
17. [M-08] `reLPContract.reLP()` is susceptible to sandwich attack due to user control over `bond()`
   slug: m-08-relpcontractrelp-is-susceptible-to-sandwich-attack-due-to-user-control-over-bond-code4rena-dopex-dopex-git
18. Liquidations are vulnerable to sandwich attacks
   slug: liquidations-are-vulnerable-to-sandwich-attacks-trailofbits-increment-finance-increment-protocol-pdf
19. [M-06] add liquidity is vulnerable to sandwich attack
   slug: m-06-add-liquidity-is-vulnerable-to-sandwich-attack-code4rena-vader-protocol-vader-protocol-contest-git
20. H-3: Vault: The attacker can sandwich attack himself on swaps in open_position, close_position and reduce_position to make a bad debt
   slug: h-3-vault-the-attacker-can-sandwich-attack-himself-on-swaps-in-open_position-close_position-and-reduce_position-to-make-a-bad-debt-sherlock-none-unstoppable-git
21. Attacker can drain protocol tokens by sandwich attacking owner call to `setPositionWidth` and `unpause` to force redeployment of Beefy's liquidity into an unfavorable range
   slug: attacker-can-drain-protocol-tokens-by-sandwich-attacking-owner-call-to-setpositionwidth-and-unpause-to-force-redeployment-of-beefys-liquidity-into-an-unfavorable-range-cyfrin-none-cyfrin-beefy-finance-markdown
22. [M-11] `addLiquidity` Sandwich Attack for unbalanced token deposits
   slug: m-11-addliquidity-sandwich-attack-for-unbalanced-token-deposits-code4rena-basin-basin-git
23. Sandwich Attack Possible via JIT Attack in AntiSandwichHook
   slug: sandwich-attack-possible-via-jit-attack-in-antisandwichhook-openzeppelin-none-openzeppelin-uniswap-hooks-v110-rc-1-audit-markdown
24. M-3: Malicious actors can execute sandwich attacks during market addition with existing funds
   slug: m-3-malicious-actors-can-execute-sandwich-attacks-during-market-addition-with-existing-funds-sherlock-zerolend-one-git
25. [M-08] Sandwich attack on loan fulfillment will temporarily prevent users from accessing their borrowed funds
   slug: m-08-sandwich-attack-on-loan-fulfillment-will-temporarily-prevent-users-from-accessing-their-borrowed-funds-code4rena-size-size-git
26. Sandwich Attacks and Price Manipulation
   slug: sandwich-attacks-and-price-manipulation-quantstamp-reach-diff-1-markdown
27. [H-05] LPs of VaderPoolV2 can manipulate pool reserves to extract funds from the reserve.
   slug: h-05-lps-of-vaderpoolv2-can-manipulate-pool-reserves-to-extract-funds-from-the-reserve-code4rena-vader-protocol-vader-protocol-contest-git
28. [H-06] LPs of VaderPoolV2 can manipulate pool reserves to extract funds from the reserve.
   slug: h-06-lps-of-vaderpoolv2-can-manipulate-pool-reserves-to-extract-funds-from-the-reserve-code4rena-vader-protocol-vader-protocol-contest-git
29. M-5: Uniswap Aggregated Fees Can be Increased at Close to Zero Cost
   slug: m-5-uniswap-aggregated-fees-can-be-increased-at-close-to-zero-cost-sherlock-aloe-git
30. [M-02] `claim` function lacks slippage controls for `amount0` and `amount1` returned by `pool.burn` function call
   slug: m-02-claim-function-lacks-slippage-controls-for-amount0-and-amount1-returned-by-poolburn-function-call-code4rena-vultisig-vultisig-git
31. Missing Tick and Liquidity Checks in _decodeAndReward (currentOnly=true ) Enables Front-Running and Slippage Attacks 
   slug: missing-tick-and-liquidity-checks-in-_decodeandreward-currentonlytrue-enables-front-running-and-slippage-attacks-cantina-none-sorella-labs-pdf
32. M-4: Attackers can create positions that have no incentive to be liquidated
   slug: m-4-attackers-can-create-positions-that-have-no-incentive-to-be-liquidated-sherlock-perpetual-git

## STAKING (31 findings)

1. [H-01] Updating a pool's total points doesn't affect existing stake positions for rewards calculation
   slug: h-01-updating-a-pools-total-points-doesnt-affect-existing-stake-positions-for-rewards-calculation-code4rena-neo-tokyo-neo-tokyo-contest-git
2. M-2: Integer overflow when calculating rewards
   slug: m-2-integer-overflow-when-calculating-rewards-sherlock-gamma-locked-staking-contract-git
3. [L-06] Precision error in reward calculation may lock tokens
   slug: l-06-precision-error-in-reward-calculation-may-lock-tokens-pashov-audit-group-none-resolv_2025-04-15-markdown
4. Incorrect Reward Calculation When Reward Rate Changes
   slug: incorrect-reward-calculation-when-reward-rate-changes-mixbytes-none-dia-markdown
5. Imprecise Reward Distribution Calculation
   slug: imprecise-reward-distribution-calculation-ottersec-none-fluid-protocol-hydrogen-labs-pdf
6. SHER reward calculation uses confusing six-decimal SHER reward rate
   slug: sher-reward-calculation-uses-confusing-six-decimal-sher-reward-rate-trailofbits-sherlock-protocol-v2-pdf
7. H-6: Loss of rewards due to continuous griefing attacks on L2 environment
   slug: h-6-loss-of-rewards-due-to-continuous-griefing-attacks-on-l2-environment-sherlock-notional-leveraged-vaults-pendle-pt-and-vault-incentives-git
8. Staking limit calculation is not accurate
   slug: staking-limit-calculation-is-not-accurate-spearbit-none-kinetiq-lst-pdf
9. H-2: A voter lose bribe rewards if another voter voted before claim.
   slug: h-2-a-voter-lose-bribe-rewards-if-another-voter-voted-before-claim-sherlock-magicsea-the-native-dex-on-the-iotaevm-git
10. [H-01] Staking.earned calculates the rewards wrongly
   slug: h-01-stakingearned-calculates-the-rewards-wrongly-pashov-audit-group-none-coinflip_2025-02-05-markdown
11. Wrong reward distribution formula, YT holders can get more rewards for themselves by just collecting accrued YBT yield 
   slug: wrong-reward-distribution-formula-yt-holders-can-get-more-rewards-for-themselves-by-just-collecting-accrued-ybt-yield-cantina-none-napier-finance-pdf
12. Reward Distribution Inconsistency
   slug: reward-distribution-inconsistency-ottersec-none-aries-markets-pdf
13. Improper Reward Distribution
   slug: improper-reward-distribution-ottersec-none-goosefx-v2-pdf
14. Reward Parameter Modifications
   slug: reward-parameter-modifications-ottersec-none-hubble-farms-pdf
15. Vault rewards incorrectly scaled by cross-asset-class operator totals instead of asset class specific shares causing rewards leakage
   slug: vault-rewards-incorrectly-scaled-by-cross-asset-class-operator-totals-instead-of-asset-class-specific-shares-causing-rewards-leakage-cyfrin-none-suzaku-core-markdown
16. Operator can over allocate the same stake to unlimited nodes within one epoch causing weight inflation and reward theft
   slug: operator-can-over-allocate-the-same-stake-to-unlimited-nodes-within-one-epoch-causing-weight-inflation-and-reward-theft-cyfrin-none-suzaku-core-markdown
17. Operators can lose their reward share
   slug: operators-can-lose-their-reward-share-cyfrin-none-suzaku-core-markdown
18. [M-23] StakingRewards pools are not given their promised share of rewards due to incorrect calculation
   slug: m-23-stakingrewards-pools-are-not-given-their-promised-share-of-rewards-due-to-incorrect-calculation-code4rena-saltyio-saltyio-git
19. Inequitable reward distribution in zlrewardscontroller due to dynamic available rewards adjustment 
   slug: inequitable-reward-distribution-in-zlrewardscontroller-due-to-dynamic-available-rewards-adjustment-cantina-none-zerolend-pdf
20. Missing Timestamp Update
   slug: missing-timestamp-update-ottersec-none-aries-markets-pdf
21. Signature Replay Attack Possible Between Stake, Unstake and Reward Functions Enabling Unauthorized Token Claims
   slug: signature-replay-attack-possible-between-stake-unstake-and-reward-functions-enabling-unauthorized-token-claims-quantstamp-sapien-markdown
22. M-5: No cooldown in `recoverUnstaking()`, opens up several possible attacks by abusing this functionality.
   slug: m-5-no-cooldown-in-recoverunstaking-opens-up-several-possible-attacks-by-abusing-this-functionality-sherlock-covalent-git
23. M-11: ZivoeYDL::distributeYield yield distribution is flash-loan manipulatable
   slug: m-11-zivoeydldistributeyield-yield-distribution-is-flash-loan-manipulatable-sherlock-zivoe-git
24. User can artificially inflate stake boosts for the next interval by repeating stake and unstake actions
   slug: user-can-artificially-inflate-stake-boosts-for-the-next-interval-by-repeating-stake-and-unstake-actions-quantstamp-nayms-2024-retainer-markdown
25. [M-05] User can frontrun `completeGame` to finalize stake or unstake request
   slug: m-05-user-can-frontrun-completegame-to-finalize-stake-or-unstake-request-pashov-audit-group-none-coinflip_2025-02-19-markdown
26. M-3: New staking between reward epochs will dilute rewards for existing stakers. Anyone can then front-run `OperationalStaking.rewardValidators()` to steal rewards
   slug: m-3-new-staking-between-reward-epochs-will-dilute-rewards-for-existing-stakers-anyone-can-then-front-run-operationalstakingrewardvalidators-to-steal-rewards-sherlock-covalent-git
27. M-1: stakerTierHistory is an unbound array that can be extended such that a user's funds are permamently lost
   slug: m-1-stakertierhistory-is-an-unbound-array-that-can-be-extended-such-that-a-users-funds-are-permamently-lost-sherlock-layeredge-staking-git
28. A malicious staker can force validator withdrawals by instantly staking and unstaking
   slug: a-malicious-staker-can-force-validator-withdrawals-by-instantly-staking-and-unstaking-cyfrin-none-casimir-markdown
29. [C-04] Attacker can steal Staking reward
   slug: c-04-attacker-can-steal-staking-reward-pashov-audit-group-none-peapods_2024-11-16-markdown
30. Missing Balance Deduction in Unstaking Functions Allows Contract Drainage and Lock Period Bypass
   slug: missing-balance-deduction-in-unstaking-functions-allows-contract-drainage-and-lock-period-bypass-quantstamp-sapien-markdown
31. M-19: Attacker Can Manipulate Interest Distribution by Exploiting Asset Transfers and Fee Accrual Mechanism
   slug: m-19-attacker-can-manipulate-interest-distribution-by-exploiting-asset-transfers-and-fee-accrual-mechanism-sherlock-sentiment-v2-git

## TOKEN (39 findings)

1. [M-01] Fee-on-Transfer Tokens Break User Output Guarantees and Accounting
   slug: m-01-fee-on-transfer-tokens-break-user-output-guarantees-and-accounting-shieldify-none-primev-fastsettlementv3-markdown
2. Fee-on-transfer and rebasing tokens break accounting
   slug: fee-on-transfer-and-rebasing-tokens-break-accounting-cyfrin-none-wannabet-markdown
3. SherpaUSD does not work with fee-on-transfer tokens
   slug: sherpausd-does-not-work-with-fee-on-transfer-tokens-cyfrin-none-sherpa-markdown
4. M-10: incompatible library used for Fee on Transfer tokens
   slug: m-10-incompatible-library-used-for-fee-on-transfer-tokens-sherlock-ammplify-git
5. Fee-On-Transfer Tokens Not Supported
   slug: fee-on-transfer-tokens-not-supported-mixbytes-none-nuts-finance-markdown
6. Incorrect handling of fee-on-transfer and rebasing tokens penalizes single beneficiary
   slug: incorrect-handling-of-fee-on-transfer-and-rebasing-tokens-penalizes-single-beneficiary-mixbytes-none-cryptolegacy-markdown
7. [L-01] RFTLib incompatible with fee-on-transfer tokens
   slug: l-01-rftlib-incompatible-with-fee-on-transfer-tokens-pashov-audit-group-none-itos_2025-05-24-markdown
8. Transfers of Fee-On-Transfer Tokens Will Revert
   slug: transfers-of-fee-on-transfer-tokens-will-revert-openzeppelin-none-across-protocol-oft-integration-differential-audit-markdown
9. [L-10] Fee-on-transfer token incompatibility
   slug: l-10-fee-on-transfer-token-incompatibility-pashov-audit-group-none-kittenswap_2025-05-07-markdown_
10. [L-10] Fee-on-transfer token incompatibility
   slug: l-10-fee-on-transfer-token-incompatibility-pashov-audit-group-none-kittenswap_2025-05-07-markdown
11. [M-01]  Axelar cross chain token transfers balance tracking logic is completely broken for rebasing tokens and the transfers of these type of tokens can be exploited
   slug: m-01-axelar-cross-chain-token-transfers-balance-tracking-logic-is-completely-broken-for-rebasing-tokens-and-the-transfers-of-these-type-of-tokens-can-be-exploited-code4rena-axelar-network-axelar-network-git
12. M-9: Lack of support for fee on transfer, rebasing and tokens with balance modifications outside of transfers.
   slug: m-9-lack-of-support-for-fee-on-transfer-rebasing-and-tokens-with-balance-modifications-outside-of-transfers-sherlock-magicsea-the-native-dex-on-the-iotaevm-git
13. [H-02] Anyone can steal all distributed rewards
   slug: h-02-anyone-can-steal-all-distributed-rewards-code4rena-ethereum-credit-guild-ethereum-credit-guild-git
14. [M-03] Protocol markets are incompatible with rebasing tokens
   slug: m-03-protocol-markets-are-incompatible-with-rebasing-tokens-code4rena-wildcat-protocol-wildcat-protocol-git
15. M-5: Balances of rebasing tokens aren't properly tracked
   slug: m-5-balances-of-rebasing-tokens-arent-properly-tracked-sherlock-sentiment-sentiment-git
16. Rebaseable Tokens Cause Unfair Vesting and Claim Failures
   slug: rebaseable-tokens-cause-unfair-vesting-and-claim-failures-mixbytes-none-cryptolegacy-markdown
17. [M-08] Nibiru's bank coin to EVM balance tracking logic is completely broken for rebasing tokens and would lead to leakage/loss of funds when converting
   slug: m-08-nibirus-bank-coin-to-evm-balance-tracking-logic-is-completely-broken-for-rebasing-tokens-and-would-lead-to-leakageloss-of-funds-when-converting-code4rena-nibiru-nibiru-git
18. [M-08] StakingToken.sol doesn't properly handle FOT, rebasing tokens or those with variable which will lead to accounting issues downstream
   slug: m-08-stakingtokensol-doesnt-properly-handle-fot-rebasing-tokens-or-those-with-variable-which-will-lead-to-accounting-issues-downstream-code4rena-olas-olas-git
19. Incorrect `lastBalance` update in treasury token transfer for rebasing tokens
   slug: incorrect-lastbalance-update-in-treasury-token-transfer-for-rebasing-tokens-mixbytes-none-cryptolegacy-markdown
20. Risk of unexpected results when long-term swaps involving rebasing tokens are canceled
   slug: risk-of-unexpected-results-when-long-term-swaps-involving-rebasing-tokens-are-canceled-trailofbits-frax-finance-pdf
21. ERC20 Approve Race Condition
   slug: erc20-approve-race-condition-auditone-none-coinlend-markdown
22. ERC20 approve race condition
   slug: erc20-approve-race-condition-zokyo-none-unity-markdown
23. Risk of token theft due to race condition in ERC20’s approve function
   slug: risk-of-token-theft-due-to-race-condition-in-erc20s-approve-function-trailofbits-none-maple-labs-pdf
24. Race condition in the ERC20 “approve” function may lead to token the�t
   slug: race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-mcd-core-smart-contracts-pdf
25. Race condition in the ERC20 approve function may lead to token theft
   slug: race-condition-in-the-erc20-approve-function-may-lead-to-token-theft-trailofbits-set-protocol-pdf
26. ERC20 approve race conditions
   slug: erc20-approve-race-conditions-trailofbits-origin-protocol-pdf
27. Race condition in the ERC20 approve function may lead to token the�t
   slug: race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-golem-pdf
28. Race condition in the ERC20 approve function may lead to token the�t
   slug: race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-dapphub-pdf
29. Race condition in the ERC20 approve function may lead to token the�t
   slug: race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-sai-pdf
30. [L-11] Erc20 Race condition for allowance
   slug: l-11-erc20-race-condition-for-allowance-code4rena-wild-credit-wild-credit-contest-git
31. `AllocationVesting` contract can be exploited for infinite points via self-transfer
   slug: allocationvesting-contract-can-be-exploited-for-infinite-points-via-self-transfer-cyfrin-none-bima-markdown
32. Mint PerpetualYieldTokens for free by self-transfer
   slug: mint-perpetualyieldtokens-for-free-by-self-transfer-spearbit-timeless-pdf
33. [M-01] Inflated `GaugeV3` rewards when period is skipped
   slug: m-01-inflated-gaugev3-rewards-when-period-is-skipped-code4rena-ramses-exchange-ramses-exchange-git
34. RLQ-3 | Burn-on-Transfer Tokens
   slug: rlq-3-burn-on-transfer-tokens-guardian-audits-none-reliquary-markdown
35. [L-07] Deflationary tokens are not considered in time-locked ERC20 functions
   slug: l-07-deflationary-tokens-are-not-considered-in-time-locked-erc20-functions-code4rena-visor-visor-contest-git
36. Deflationary spl_token support
   slug: deflationary-spl_token-support-zokyo-none-escrow-markdown
37. The FXS1559 documentation is inaccurate
   slug: the-fxs1559-documentation-is-inaccurate-trailofbits-frax-solidity-pdf
38. Polkaswap blindly trusts upgradeable ERC20 proxy tokens
   slug: polkaswap-blindly-trusts-upgradeable-erc20-proxy-tokens-trailofbits-none-polkaswap-pdf
39. [M-01] Fee on transfer tokens will not behave as expected
   slug: m-01-fee-on-transfer-tokens-will-not-behave-as-expected-code4rena-numoen-numoen-contest-git

## BRIDGE (33 findings)

1. Potential Replay Attack Due to Missing Contract Address in Signed Message
   slug: potential-replay-attack-due-to-missing-contract-address-in-signed-message-quantstamp-opera-sonic-bridge-markdown
2. Risk of replay attacks across contract instances
   slug: risk-of-replay-attacks-across-contract-instances-trailofbits-none-polkaswap-pdf
3. M-6: Causing users lose fund if bridging long message from L2 to L1 due to uncontrolled out-of-gas error
   slug: m-6-causing-users-lose-fund-if-bridging-long-message-from-l2-to-l1-due-to-uncontrolled-out-of-gas-error-sherlock-none-optimism-update-git
4. Router signatures can be replayed when executing messages on the destination domain
   slug: router-signatures-can-be-replayed-when-executing-messages-on-the-destination-domain-spearbit-connext-pdf
5. [M-10] Attacker can make claimed staking incentives irredeemable on Gnosis Chain
   slug: m-10-attacker-can-make-claimed-staking-incentives-irredeemable-on-gnosis-chain-code4rena-olas-olas-git
6. Missing Validation Logic
   slug: missing-validation-logic-ottersec-none-eclipse-canonical-bridge-pdf
7. Failed messages never expire and can be replayed by anyone, potentially allowing users to be griefed
   slug: failed-messages-never-expire-and-can-be-replayed-by-anyone-potentially-allowing-users-to-be-griefed-immunefi-folks-finance-git
8. M-4: Usage of **revert** in case of low gas in `L1CrossDomainMessenger` can result in loss of fund
   slug: m-4-usage-of-revert-in-case-of-low-gas-in-l1crossdomainmessenger-can-result-in-loss-of-fund-sherlock-none-optimism-update-git
9. H-2: Malicious actor cause rebase to an old inflation multiplier
   slug: h-2-malicious-actor-cause-rebase-to-an-old-inflation-multiplier-sherlock-none-eco-protocol-git
10. Signature-related code lacks a proper speciﬁcation and documentation
   slug: signature-related-code-lacks-a-proper-specification-and-documentation-trailofbits-chainport-pdf
11. [H-01] Cross-chain signature replay attack due to user-supplied `domainSeparator` and missing deadline check
   slug: h-01-cross-chain-signature-replay-attack-due-to-user-supplied-domainseparator-and-missing-deadline-check-code4rena-next-generation-next-generation-git
12. Code Reuse May Lead to Wormhole Replay Attack Due to VAA Hash Not Being Marked as Processed
   slug: code-reuse-may-lead-to-wormhole-replay-attack-due-to-vaa-hash-not-being-marked-as-processed-quantstamp-hashflow-hashverse-markdown
13. [M-21] Deployment Nonce Does not Increment For a Reverted Child Contract
   slug: m-21-deployment-nonce-does-not-increment-for-a-reverted-child-contract-code4rena-zksync-zksync-git
14. M-1: Incorrect game type can be proven and finalized due to unsafe cast
   slug: m-1-incorrect-game-type-can-be-proven-and-finalized-due-to-unsafe-cast-sherlock-optimism-fault-proofs-git
15. [M-08] Insufficient support for tokens with different decimals on different chains lead to loss of funds on cross-chain bridging
   slug: m-08-insufficient-support-for-tokens-with-different-decimals-on-different-chains-lead-to-loss-of-funds-on-cross-chain-bridging-code4rena-axelar-network-axelar-network-git
16. M-12: Rebalancer can drain market funds via excessive bridge fees
   slug: m-12-rebalancer-can-drain-market-funds-via-excessive-bridge-fees-sherlock-malda-git
17. [L-05] Replaying the same BTC transactions on different LPs
   slug: l-05-replaying-the-same-btc-transactions-on-different-lps-pashov-audit-group-none-bob-onramp-markdown
18. No precision scaling or minimum received amount check when subtracting `relayerFeeAmount` can revert due to underflow or return less tokens to user than specified
   slug: no-precision-scaling-or-minimum-received-amount-check-when-subtracting-relayerfeeamount-can-revert-due-to-underflow-or-return-less-tokens-to-user-than-specified-cyfrin-none-cyfrin-thermae-markdown
19. Potential for Race Condition between Unlock Time and Proof Verification leading to Double Spending
   slug: potential-for-race-condition-between-unlock-time-and-proof-verification-leading-to-double-spending-auditone-none-aurorafastbridge-markdown
20. Freeze Bridge with Invalid Sender
   slug: freeze-bridge-with-invalid-sender-ottersec-none-layerzero-aptos-pdf
21. TargetAMB receipt proof may behave unexpectedly on future transaction types
   slug: targetamb-receipt-proof-may-behave-unexpectedly-on-future-transaction-types-trailofbits-none-succinct-labs-telepathy-pdf
22. Malicious tokens can be deployed at deterministic addresses on other chains to steal funds
   slug: malicious-tokens-can-be-deployed-at-deterministic-addresses-on-other-chains-to-steal-funds-spearbit-none-optimism-interop-pdf
23. Centralisation Risks
   slug: centralisation-risks-sigmaprime-none-aurora-pdf
24. UniswapV3 Oracle Vulnerability on L2 Networks Due to Sequencer Downtime
   slug: uniswapv3-oracle-vulnerability-on-l2-networks-due-to-sequencer-downtime-halborn-lucid-labs-contracts-v1-markdown
25. Access-controlled functions cannot be called when L2 sequencers are down
   slug: access-controlled-functions-cannot-be-called-when-l2-sequencers-are-down-cyfrin-none-cyfrin-wormhole-evm-ntt-v2-markdown
26. Lack of L2 Sequencer Status Monitoring in Deployment
   slug: lack-of-l2-sequencer-status-monitoring-in-deployment-halborn-apro-evm-smart-contracts-markdown
27. User might be unfairly liquidated after L2 Sequencer grace period
   slug: user-might-be-unfairly-liquidated-after-l2-sequencer-grace-period-codehawks-zaros-git
28. Missing L2 Sequencer Uptime Checks
   slug: missing-l2-sequencer-uptime-checks-openzeppelin-none-fx-v2-audit-markdown
29. M-3: L2 sequencer down will push an auction's price down, causing unfair liquidation prices, and potentially guaranteeing bad debt
   slug: m-3-l2-sequencer-down-will-push-an-auctions-price-down-causing-unfair-liquidation-prices-and-potentially-guaranteeing-bad-debt-sherlock-arcadia-git
30. Missing L2 sequencer uptime check in `OracleAdapter`
   slug: missing-l2-sequencer-uptime-check-in-oracleadapter-cyfrin-none-yieldfi-markdown
31. Redemptions are blocked when L2 sequencers are down
   slug: redemptions-are-blocked-when-l2-sequencers-are-down-cyfrin-none-cyfrin-wormhole-evm-cctp-v2-1-markdown
32. M-4: Loss of option token from Teller and reward from OTLM if L2 sequencer goes down
   slug: m-4-loss-of-option-token-from-teller-and-reward-from-otlm-if-l2-sequencer-goes-down-sherlock-none-bond-options-git
33. M-4: No check if Arbitrum L2 sequencer is down in Chainlink feeds
   slug: m-4-no-check-if-arbitrum-l2-sequencer-is-down-in-chainlink-feeds-sherlock-sentiment-sentiment-update-3-git

## ZK (1 findings)

1. [M-01] zkTrie maximum depth limit is not enforced in Scroll
   slug: m-01-zktrie-maximum-depth-limit-is-not-enforced-in-scroll-code4rena-unruggable-unruggable-git
