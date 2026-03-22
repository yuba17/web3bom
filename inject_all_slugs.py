#!/usr/bin/env python3
"""
Inject Solodit slugs into all remaining briefing files.
Replaces `solodit_ids: []` blocks for specific pattern IDs with real slug lists.
"""

import re
import os

BASE = "/home/kali/Documents/Web3/knowledge"

SLUGS = {
    # lending.md
    ("lending.md", "lending-010"): [
        "m-1-vault-inflation-attack-sherlock-smilee-finance-git",
        "first-depositor-inflation-attack-in-stakedtoken-contract-spearbit-none-infinifi-contracts-pdf",
        "first-depositor-can-break-minting-of-shares-zokyo-none-narwhal-finance-markdown",
        "first-depositor-inflation-attack-in-sheepdog-contract-cantina-none-ceazor-snack-sandwich-pdf",
        "l-18-vault-is-susceptible-to-inflation-attack-by-first-depositor-pashov-audit-group-none-hyperstable_2025-02-26-markdown",
    ],
    ("lending.md", "lending-014"): [
        "m-2-fixed-interest-rates-can-be-manipulated-by-a-whale-borrower-sherlock-exactly-protocol-git",
        "trst-h-2-pool-initialization-can-be-front-ran-to-manipulate-the-interest-rate-trust-security-none-timeswap-markdown",
        "potential-manipulation-of-stable-interest-rates-using-flash-loans-consensys-aave-protocol-v2-markdown",
        "adversaries-can-manipulate-victims-stable-rate-to-remain-excessively-high-via-flashloan-immunefi-folks-finance-git",
        "m-14-interest-rates-can-be-raised-above-the-market-as-a-griefing-disabling-the-pool-sherlock-ajna-ajna-git",
    ],
    ("lending.md", "lending-003"): [
        "users-can-become-immediately-liquidatable-after-executing-an-action-trailofbits-none-aave-v4-pdf",
        "h-04-shrines-recovery-mode-can-be-weaponized-as-leverage-to-liquidate-healthy-troves-code4rena-opus-opus-git",
        "liquidation-cannot-be-closed-even-with-healthy-position-due-to-strict-debt-check-codehawks-regnum-aurum-acquisition-corp-core-contracts-git",
        "m-1-attackerpartial-liquidator-can-extend-liquidation-action-by-resetting-liquidationstart_agent-to-0-sherlock-cap-git",
    ],
    ("lending.md", "lending-004"): [
        "m-12-some-bad-debt-will-not-be-cleared-when-it-should-which-will-cause-accrual-of-bad-debt-decreasing-the-protocols-solvency-sherlock-exactly-protocol-update-stacking-contract-git",
        "m-1-bad-debt-isnt-cleared-when-earningsaccumulator-is-lower-than-a-fixed-pool-bad-debt-sherlock-exactly-protocol-git",
        "bad-debt-accumulation-index-is-reset-on-partial-liquidation-and-is-not-reset-on-cdp-increase-allowing-for-phantom-bad-debt-creation-cantina-none-badgerdao-pdf",
        "m-5-bad-debt-is-not-accounted-for-during-partial-liquidation-of-an-insolvent-position-sherlock-lend-git",
        "protocol-lacks-bad-debt-management-mechanisms-risking-permanent-insolvency-trailofbits-none-cap-labs-covered-agent-protocol-pdf",
    ],
    ("lending.md", "lending-028"): [
        "m-11-debt-calculation-should-be-rounded-up-during-repayment-pashov-audit-group-none-sharwafinance-markdown",
        "m-05-borrowers-can-be-left-with-debt-shares-after-full-repayment-pashov-audit-group-none-sharwafinance-markdown",
        "c-03-users-can-borrow-tokens-without-generating-debt-shares-pashov-audit-group-none-sharwafinance-markdown",
        "liquidation-repaidshares-computation-rounding-issue-cantina-none-morpho-pdf",
        "m-36-sgl-and-bb-repay-do-not-round-up-both-on-allowance-spending-and-elastic-amount-sherlock-tapioca-git",
    ],
    ("lending.md", "lending-007"): [
        "h-03-critical-oracle-manipulation-risk-by-lender-code4rena-abracadabra-money-abranft-contest-git",
        "h-04-oracle-periodsize-is-very-low-allowing-the-twap-price-to-be-easily-manipulated-code4rena-canto-canto-git",
        "m-19-v3oracle-susceptible-to-price-manipulation-code4rena-revert-lend-revert-lend-git",
        "h-5-wrong-calculation-of-amount-of-ltokens-to-seize-in-liquidatecrosschain-function-sherlock-lend-git",
    ],
    ("lending.md", "lending-020"): [
        "h-03-high-erc721-utilization-rate-can-be-exploited-to-steal-funds-zachobront-none-fungify-markdown",
        "m-4-utilisation-can-be-manipulated-far-above-100-sherlock-arcadia-git",
        "utilizationrate-should-be-upper-capped-by-1e18-halborn-gloop-finance-gmi-and-lending-markdown",
        "m-6-vaultadaptermultiplier-not-initialized-can-lead-first-borrows-to-have-utilizationrate-0-sherlock-cap-git",
    ],
    ("lending.md", "lending-008"): [
        "self-liquidations-of-leveraged-positions-can-be-profitable-spearbit-none-euler-labs-evk-pdf",
        "self-liquidations-are-profitable-under-certain-collateralization-ratios-spearbit-none-size-v1-pdf",
        "h-02-liquidation-doesnt-account-for-penalty-when-calculating-collateral-to-give-allowing-users-to-profit-by-borrowing-and-self-liquidating-code4rena-loopfi-loopfi-git",
        "proxy-based-self-liquidation-creates-bad-debt-for-lenders-cyfrin-none-licredity-markdown",
    ],

    # oracle.md
    ("oracle.md", "oracle-001"): [
        "m-7-latestrounddata-has-no-check-for-round-completeness-sherlock-isomorph-isomorph-git",
        "m-05-chainlinks-latestrounddata-might-return-stale-or-incorrect-results-code4rena-mochi-mochi-contest-git",
        "missing-chainlink-oracle-staleness-check-cyfrin-none-licredity-markdown",
        "chainlink-oracle-data-may-be-stale-quantstamp-stakestone-vault-markdown",
        "should-check-return-data-from-chainlink-aggregator-severity-medium-auditone-none-coinlend-markdown",
        "m-15-lacking-validation-of-chainlink-oracle-queries-code4rena-vader-protocol-vader-protocol-contest-git",
        "m-02-chainlinks-latestrounddata-might-return-stale-or-incorrect-results-code4rena-phuture-finance-phuture-finance-contest-git",
        "l-03-chainlinkadapter-does-not-check-for-round-completeness-which-may-lead-to-stale-data-pashov-none-fyde-markdown",
    ],
    ("oracle.md", "oracle-003"): [
        "m-10-taporacle-twap-duration-for-uniswap-oracle-should-be-at-least-30-mins-pashov-none-tapiocadao-markdown",
        "m-08-twap-can-be-manipulated-pashov-audit-group-none-ulti-november-markdown",
        "h-04-use-of-only-higher-price-in-seer-makes-it-vulnerable-to-price-manipulation-pashov-none-tapiocadao-markdown",
        "m-06-uniswap-oracle-prices-can-be-manipulated-pashov-audit-group-none-ouroboros_2024-12-06-markdown",
        "uniswap-oracle-are-very-easy-to-manipulate-on-l2-cantina-none-euler-pdf",
    ],
    ("oracle.md", "oracle-002"): [
        "m-10-erc4626oracle-vulnerable-to-price-manipulation-sherlock-sentiment-sentiment-git",
        "m-04-fallback-oracle-is-using-spot-price-in-uniswap-liquidity-pool-which-is-very-vulnerable-to-flashloan-price-manipulation-code4rena-paraspace-paraspace-contest-git",
        "spot-price-manipulation-can-lead-to-unfair-liquidations-cyfrin-none-deriverse-dex-markdown",
        "pools-can-be-subject-to-price-manipulation-leading-to-early-liquidations-or-arbitrage-openzeppelin-none-fx-v2-audit-markdown",
    ],
    ("oracle.md", "oracle-013"): [
        "incorrect-prices-will-be-returned-if-the-nodetype-is-price_deviation_circuit_breaker-immunefi-folks-finance-git",
        "lastgoodprice-updates-during-divergence-spearbit-none-buck-labs-pdf",
        "mint-pricing-bypasses-oracle-validation-spearbit-none-buck-labs-pdf",
        "oracle-update-front-running-allows-extraction-of-value-from-vaults-trailofbits-none-cap-labs-covered-agent-protocol-pdf",
    ],
    ("oracle.md", "oracle-005"): [
        "missing-checks-for-sequencer-uptime-when-fetching-chainlink-prices-quantstamp-venus-multichain-support-markdown",
        "trst-m-3-no-check-for-active-arbitrum-sequencer-in-chainlink-oracle-trust-security-none-stella-markdown_",
        "unchecked-chainlink-sequencer-uptime-zokyo-none-umami-markdown",
        "missing-l2-sequencer-uptime-check-in-oracleadapter-cyfrin-none-yieldfi-markdown",
        "missing-checks-for-sequencer-uptime-when-fetching-chainlink-prices-quantstamp-open-dollar-smart-contract-audit-markdown",
    ],
    ("oracle.md", "oracle-019"): [
        "incorrect-staleness-threshold-for-chainlink-price-feeds-zokyo-none-copra-markdown",
        "m-07-oraclemodule-assumes-that-all-chainlink-feeds-have-a-heartbeat-of-24-hours-pashov-none-fyde-markdown",
        "m-1-lack-of-price-freshness-check-in-chainlinkoraclesolgetprice-allows-a-stale-price-to-be-used-sherlock-sentiment-sentiment-git",
        "m-04-omooraclegetusdvalue-price-feed-updates-may-be-incorrectly-marked-stale-pashov-audit-group-none-omo_2025-01-25-markdown",
        "oracle-freshness-threshold-can-lead-to-stale-data-being-provided-zokyo-none-paribus-markdown",
    ],

    # staking.md
    ("staking.md", "staking-001"): [
        "rounding-errors-result-in-lost-accrued-rewards-ottersec-none-mysten-labs-sui-pdf",
        "m-01-the-user-who-withdraws-liquidity-from-a-particular-pool-is-able-to-claim-more-rewards-than-they-should-by-carefully-selecting-a-decreaseshareamount-value-such-that-the-virtualrewardstoremove-is-rounded-down-to-zero-code4rena-saltyio-saltyio-git",
        "rounding-to-zero-if-duration-is-greater-than-reward-sigmaprime-none-synthetix-pdf",
        "m-2-integer-overflow-when-calculating-rewards-sherlock-gamma-locked-staking-contract-git",
        "m-16-accumulated-rewards-per-share-can-round-to-zero-code4rena-gte-gte-git",
        "lps-can-lose-fees-if-fee-growth-accumulator-overflows-their-checkpoint-spearbit-none-primitive-pdf",
        "improper-reward-distribution-ottersec-none-goosefx-v2-pdf",
    ],
    ("staking.md", "staking-002"): [
        "h-04-nftxlpstaking-is-subject-to-a-flash-loan-attack-that-can-steal-nearly-all-rewardsfees-that-have-accrued-for-a-particular-vault-code4rena-nftx-nftx-git",
        "flash-loan-attack-on-gauge-reward-distribution-via-get_adjustment-manipulation-mixbytes-none-yield-basis-markdown",
        "h-27-attacker-can-inflate-stake-rewards-as-he-wants-sherlock-elfi-git",
        "m-11-the-variable-fshareratio-is-vulnerable-to-manipulation-by-flash-minting-and-burning-code4rena-fairside-fairside-contest-git",
    ],
    ("staking.md", "staking-018"): [
        "future-epoch-cache-manipulation-via-calcandcachestakes-allows-reward-manipulation-cyfrin-none-suzaku-core-markdown",
        "incorrect-reward-epoch-start-date-calculation-fixed-consensys-forta-delegated-staking-markdown",
        "timestamp-boundary-condition-causes-reward-dilution-for-active-operators-cyfrin-none-suzaku-core-markdown",
        "h-07-inconsistent-rounding-of-lock-time-causes-voting-power-errors-pashov-audit-group-none-kittenswap_2025-05-07-markdown",
    ],
    ("staking.md", "staking-020"): [
        "manipulation-of-ve-voting-mechanism-unlimited-boost-circumvention-of-cooldown-immunefi-alchemix-git",
        "attackers-can-control-the-vote-result-and-amplify-target-gauges-share-immunefi-zerolend-git",
        "manipulation-of-governance-voting-result-by-unlimited-minting-the-flux-token-by-exploiting-the-logic-of-reset-and-merge-tokenid-immunefi-alchemix-git",
        "max-voter-weight-manipulation-ottersec-none-pyth-governance-pdf",
    ],
    ("staking.md", "staking-013"): [
        "h-02-reward-rates-can-be-reset-to-0-and-future-rewards-can-be-stolen-from-voters-pashov-audit-group-none-kittenswap_2025-07-31-markdown",
        "h-01-repeated-distributions-for-killed-gauges-can-block-valid-distributions-pashov-audit-group-none-kittenswap_2025-07-31-markdown",
        "gauge-emissions-revert-when-emissions-are-higher-than-the-leftover-buffer-instead-of-depositing-the-difference-codehawks-regnum-aurum-acquisition-corp-core-contracts-git",
        "alchemix-the-first-epochs-alcx-emissions-of-voter-contract-will-be-stuck-forever-immunefi-alchemix-git",
    ],
    ("staking.md", "staking-004"): [
        "malicious-user-can-drain-rewards-through-reentrancy-in-staking-quantstamp-zero-staking-markdown",
        "l-04-the-unstake-function-can-be-re-entered-pashov-audit-group-none-dyad-markdown",
        "missing-reentrancy-protection-in-cllockerincreaseliquidity-mixbytes-none-velodrome-markdown",
    ],
    ("staking.md", "staking-003"): [
        "h-01-stakedtoken-is-vulnerable-to-share-inflation-attack-via-donation-pashov-none-increment-markdown",
        "inflation-attack-on-zero-total-stake-ottersec-none-thala-lsd-deps-pdf",
        "backstop-deposit-inflation-ottersec-none-blend-capital-pdf",
        "vaults-are-vulnerable-to-a-donation-attack-halborn-tagus-labs-v2-markdown",
    ],

    # vault-erc4626.md
    ("vault-erc4626.md", "vault-001"): [
        "m-13-first-erc4626-deposit-can-break-share-calculation-sherlock-astaria-astaria-git",
        "m-1-vault-inflation-attack-sherlock-smilee-finance-git",
        "first-deposit-attack-via-share-price-manipulation-zokyo-none-vaultka-markdown",
        "first-depositor-inflation-attack-in-stakedtoken-contract-spearbit-none-infinifi-contracts-pdf",
        "h-02-erc4626cloned-deposit-and-mint-logic-differ-on-first-deposit-code4rena-astaria-astaria-git",
    ],
    ("vault-erc4626.md", "vault-018"): [
        "revenue-accounting-ignores-losses-spearbit-none-tenbin-pdf",
        "direct-vault-deposits-incorrectly-counted-as-revenue-leading-to-liquidity-drain-spearbit-none-tenbin-pdf",
        "h-11-pending-withdrawal-tokens-in-redeem-affect-share-price-pashov-audit-group-none-omo_2025-01-25-markdown",
        "m-12-unclaimed-rewards-handling-issue-in-auravault-contract-functions-auravaultdeposit-auravaultmint-auravaultwithdraw-and-auravaultredeem-code4rena-loopfi-loopfi-git",
    ],
    ("vault-erc4626.md", "vault-013"): [
        "m-16-maxwithdraw-and-maxredeem-doesnt-return-correct-value-which-can-make-other-contracts-fail-while-working-with-protocol-code4rena-gogopool-gogopool-git",
        "maxwithdraw-maxredeem-returns-wrong-values-for-fee-recipient-spearbit-none-euler-earn-pdf",
        "l-09-maxwithdraw-and-maxredeem-could-return-the-wrong-value-pashov-audit-group-none-ionprotocol-markdown",
        "maxredeem-and-maxwithdraw-dont-have-_cantransfer-check-cantina-none-centrifuge-pdf",
    ],
    ("vault-erc4626.md", "vault-003"): [
        "c-02-users-can-exploit-rounding-to-withdraw-excess-assets-from-the-fund-contract-shieldify-none-harmonixfinance-hyperliquid-markdown",
        "h-01-rounding-issues-in-certain-functions-code4rena-notional-notional-git",
        "connectors-special-withdraw-rounding-amount-direction-should-not-favor-user-cantina-none-balmy-pdf",
        "m-17-malicious-users-can-drain-the-assets-of-vault-due-to-not-being-erc4626-complaint-code4rena-popcorn-popcorn-contest-git",
    ],
    ("vault-erc4626.md", "vault-007"): [
        "losses-are-not-taken-into-account-in-the-strategy-mixbytes-none-yearn-finance-markdown__",
        "h-01-incorrect-user-accounting-in-withdraw-method-pashov-none-yield-ninja-markdown_",
        "forcedeallocate-allows-user-to-avoid-incurring-in-losses-and-dump-them-on-other-suppliers-spearbit-none-morpho-vaults-v2-pdf",
    ],
    ("vault-erc4626.md", "vault-017"): [
        "m-18-the-exchange-rate-change-in-the-case-of-lossy-strategy-will-cause-the-vault-to-be-under-collateralized-for-generic-erc4626-yield-vaults-code4rena-pooltogether-pooltogether-git",
        "unaccounted-external-vault-investment-losses-can-create-withdrawal-shortfalls-trailofbits-none-cap-labs-covered-agent-protocol-pdf",
        "h-04-strategy-allocation-tracking-errors-affect-tvl-calculations-pashov-audit-group-none-elytra_2025-07-10-markdown",
    ],
    ("vault-erc4626.md", "vault-008"): [
        "inconsistent-function-override-logic-ottersec-none-plume-network-pdf",
        "m-03-staking-contract-is-not-eip-4626-compliant-pashov-audit-group-none-lucidly-june-markdown",
        "m-42-ulyssespoolsol-does-not-match-eip4626-because-of-the-preview-functions-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git",
    ],

    # access-control.md
    ("access-control.md", "access-001"): [
        "h-01-missing-access-control-in-updatefairlaunchproperties-function-naman-none-hyacinth-markdown",
        "missing-access-control-in-collateralliquidityprovidersetexternalcollateralredemption-cyfrin-none-securitize-redemptions-markdown",
        "lack-of-access-control-ottersec-none-comet-pdf",
        "maximillionsetcether-callable-multiple-times-by-anyone-quantstamp-quadrata-lending-markdown",
        "l-03-cvxlockersetapprovals-can-be-called-by-anyone-code4rena-badgerdao-bvecvx-by-badgerdao-contest-git",
        "lpwrapper-s-initialize-can-be-called-by-anyone-to-set-and-fix-most-of-the-relevant-parame-ters-cantina-none-mellow-pdf",
    ],
    ("access-control.md", "access-010"): [
        "l-11-grantrole-and-revokerole-in-elyhype-lack-admin-privileges-pashov-audit-group-none-elytra_2025-07-10-markdown",
        "freezer_role-not-revoked-from-previous-vaultrouter-quantstamp-blexio-markdown",
        "renounceable-privileged-role-quantstamp-venus-multichain-support-markdown",
        "deployer-retaining-privileged-roles-is-risky-spearbit-none-infrared-contracts-pdf",
    ],
    ("access-control.md", "access-002"): [
        "missing-two-step-ownership-transfer-mixbytes-none-cryptolegacy-markdown",
        "missing-two-step-transfer-ownership-pattern-spearbit-porter-finance-pdf",
        "missing-two-step-transfer-ownership-pattern-spearbit-lifi-pdf",
        "missing-two-step-transfer-ownership-pattern-halborn-persistence-stkbnb-markdown",
        "lack-of-two-step-ownership-transfer-zokyo-none-filament-markdown",
        "lack-of-two-step-ownership-transfer-zokyo-none-tren-markdown",
        "lack-of-two-step-ownership-transfer-zokyo-none-symbiosis-markdown",
    ],
    ("access-control.md", "access-003"): [
        "l-03-front-runnable-initializers-code4rena-prepo-prepo-contest-git",
        "l-01-front-runnable-initializers-code4rena-skale-skale-contest-git",
        "l-03-front-runnable-initializers-code4rena-hubble-hubble-contest-git",
        "missing-_disableinitializers-and-possible-initialization-front-running-zokyo-none-devve-markdown",
    ],
    ("access-control.md", "access-005"): [
        "m-03-missing-eventstimelocks-for-owneradmin-only-functions-that-change-critical-parameters-code4rena-float-capital-float-capital-git",
        "missing-events-for-admin-only-functions-that-change-critical-parameters-halborn-moonwell-governance-timelock-updates-markdown",
        "n07-missing-event-and-or-timelock-for-critical-parameter-change-code4rena-ens-ens-contest-git",
    ],
    ("access-control.md", "access-006"): [
        "l-01-the-addblacklistaddress-and-addwhitelistaddress-functions-do-not-check-whether-the-user-has-opposite-role-code4rena-ethena-labs-ethena-labs-git",
        "m-6-freezing-roles-in-erc721nftproduct-and-erc1155nftproduct-is-moot-sherlock-nftport-nftport-git",
        "m-16-maltrepository_revokerole-may-not-work-correctly-code4rena-malt-protocol-malt-protocol-versus-contest-git",
        "insufficient-role-isolation-mixbytes-none-fantium-markdown",
        "m-02-minter-staker-spender-roles-can-never-be-revoked-code4rena-ai-arena-ai-arena-git",
    ],

    # signature-replay.md
    ("signature-replay.md", "sig-001"): [
        "signature-missing-nonce-expiration-deadline-codehawks-sparkn-git",
        "missing-nonce-validation-in-signature-verification-allows-transaction-replay-attacks-cyfrin-none-securitize-onofframp-bridge-markdown",
        "29-nonce-is-never-used-in-regards-to-the-weighted-signers-allowing-for-proofsignature-replay-code4rena-axelar-network-axelar-network-git",
        "m-31-missing-nonce-reset-during-tss-address-update-allowing-signature-replay-sherlock-zetachain-cross-chain-git",
        "h-05-signatures-can-be-replayed-in-withdraw-to-withdraw-more-tokens-than-the-user-originally-intended-code4rena-taiko-taiko-git",
    ],
    ("signature-replay.md", "sig-005"): [
        "the-eip-712-domain-separator-is-missing-the-version-field-spearbit-none-sphinx-pdf",
        "domainseparatorv4-not-updated-after-name-symbol-change-spearbit-connext-pdf",
        "lyswp2-5-immutable-domain_separator-becomes-invalid-after-a-hard-fork-hexens-none-train-protocol-markdown",
        "m-04-verifyingcontract-set-incorrectly-for-eip712-domain-separator-zachobront-none-hook-markdown",
        "domain_separator-in-uniswapv2erc20-will-be-invalid-after-chain-forks-cantina-none-sweep-n-flip-pdf",
    ],
    ("signature-replay.md", "sig-002"): [
        "h-01-cross-chain-replay-in-borrowasset-swaptoborrow-kann-audits-none-rwa-markdown",
        "m-01-join-signature-lacks-domain-separation-leading-to-cross-deploymentchain-replay-shieldify-none-soulsclub-revolver-markdown",
        "lack-of-chainid-validation-allows-reuse-of-signatures-across-forks-trailofbits-advanced-blockchain-pdf",
        "risk-of-reuse-of-signatures-across-forks-due-to-lack-of-chain-id-validation-trailofbits-none-maple-labs-pdf",
        "h-01-cross-chain-signature-replay-attack-due-to-user-supplied-domainseparator-and-missing-deadline-check-code4rena-next-generation-next-generation-git",
    ],
    ("signature-replay.md", "sig-007"): [
        "h-01-signature-malleability-of-evms-ecrecover-in-verify-code4rena-larvalabs-meebits-larvalabs-meebits-git",
        "direct-usage-of-ecrecover-allows-for-signature-malleability-halborn-holograph-protocol-markdown",
        "using-ecrecover-directly-vulnerable-to-signature-malleability-cyfrin-none-bima-markdown",
        "ecdsa-signature-malleability-quantstamp-mezo-portal-markdown",
        "l-03-direct-usage-of-ecrecover-allows-signature-malleability-code4rena-reality-cards-reality-cards-contest-git",
    ],
    ("signature-replay.md", "sig-003"): [
        "missing-signature-expiry-enables-perpetual-transaction-validity-codehawks-one-world-project-git",
        "l-01-missing-deadline-and-nonce-in-signature-pashov-audit-group-none-hybux_2025-11-11-markdown",
        "m-01-missing-time-limit-for-signature-kann-audits-none-rwa-markdown",
    ],
    ("signature-replay.md", "sig-006"): [
        "m-25-same-contract-multi-permits-fundamentally-cannot-be-solved-via-the-chosen-standards-code4rena-tapioca-dao-tapioca-dao-git",
        "permit-call-success-check-enables-front-running-dos-cantina-none-eco-inc-pdf",
        "m-10-erc-2612-permit-front-running-in-routerv2-enables-dos-of-liquidity-operations-code4rena-audit-507-audit-507-git",
        "permit-signatures-can-be-front-run-to-execute-a-temporary-denial-of-service-attack-trailofbits-none-balancer-v3-pdf",
        "permit-front-running-can-dos-requestmintwithpermit-spearbit-none-buck-labs-pdf",
    ],
    ("signature-replay.md", "sig-017"): [
        "typed-signatures-implement-insecure-nonstandard-encodings-trailofbits-meson-protocol-pdf",
        "hash-collisions-in-untyped-signatures-trailofbits-meson-protocol-pdf",
        "m-1-abiencodepacked-allows-hash-collision-sherlock-nftport-nftport-git",
        "non-injective-hash-encoding-in-getclaimkeyhash-trailofbits-paraspace-pdf",
        "multichaincompact-and-batchcompact-incompatible-with-erc712-due-to-incorrect-hashing-spearbit-none-uniswap-the-compact-pdf",
    ],

    # proxy-upgrade.md
    ("proxy-upgrade.md", "proxy-001"): [
        "h-06-storage-collision-between-proxy-and-implementation-lack-eip-1967-code4rena-joyn-joyn-contest-git",
        "risk-of-storage-collision-in-proxy-contract-openzeppelin-none-anvil-protocol-audit-markdown",
        "m09-contracts-storage-layout-can-be-corrupted-on-upgradeable-contracts-openzeppelin-celo-contracts-audit-markdown",
        "accesscontrolds-uses-accesscontrol-which-has-storage-collision-risks-trailofbits-none-arkis-defi-prime-brokerage-protocol-pdf",
        "standard-reentrancyguard-inheritance-risks-diamond-storage-collision-mixbytes-none-cryptolegacy-markdown",
    ],
    ("proxy-upgrade.md", "proxy-005"): [
        "risk-of-killing-upgrades-quantstamp-ssvnetwork-markdown",
        "upgradebranchsol-does-not-use-_disableinitializers-codehawks-zaros-git",
        "upgradeable-contract-initializer-not-disabled-in-constructor-allows-implementation-contract-initialization-cyfrin-none-securitize-vaultv2-rwasegwrap-markdown",
        "l-01-some-contracts-not-following-uups-best-practices-pashov-audit-group-none-kittenswap_2025-07-31-markdown",
    ],
    ("proxy-upgrade.md", "proxy-007"): [
        "custom-selectors-could-facilitate-proxy-selector-clashing-attack-openzeppelin-none-security-review-ink-cargo-contract-markdown",
        "risk-of-function-signature-clash-with-ifadmin-openzeppelin-none-ironblocks-onchain-firewall-audit-markdown",
        "possible-function-selector-clashing-openzeppelin-none-venus-protocol-diamond-comptroller-audit-markdown",
        "potential-function-clashes-openzeppelin-compound-iii-audit-markdown",
    ],
    ("proxy-upgrade.md", "proxy-004"): [
        "initializefunctions-not-protected-auditone-none-newwit-markdown",
        "implementation-contracts-can-be-initialized-cantina-none-olas-pdf",
        "trst-l-3-strategy-may-be-initialized-by-attacker-trust-security-none-ninja-yield-farming-v3-markdown_",
        "l-01-add-constructor-initializer-in-implementation-contracts-code4rena-jpyc-jpyc-contest-git",
    ],
    ("proxy-upgrade.md", "proxy-003"): [
        "anyone-is-able-to-upgrade-implementation-of-the-contract-zokyo-none-made-for-gamers-markdown",
        "m-04-pool-designed-to-be-upgradeable-but-does-not-set-owner-making-it-un-upgradeable-code4rena-blur-exchange-blur-exchange-contest-git",
        "m-15-crosscurrencyfcashvault-cannot-be-upgraded-sherlock-notional-notional-git",
    ],

    # bridge.md
    ("bridge.md", "bridge-001"): [
        "invalid-message-replay-design-ottersec-none-olympus-dao-pdf",
        "m-12-non-blocking-layerzero-cross-chain-buy-operations-can-be-blocked-pashov-audit-group-none-stationx-markdown",
        "l-06-uln302-verifiable-conflates-distinct-failure-states-with-verified-breaking-off-chain-relayer-logic-code4rena-layerzero-layerzero-git",
    ],
    ("bridge.md", "bridge-002"): [
        "m-02-executor-can-deliver-cross-chain-messages-with-unvalidated-native-value-shieldify-none-onchainheroes-genesisbridge-markdown",
        "usage-of-txorigin-ottersec-none-folks-finance-x-chain-pdf",
        "missing-source-validation-in-ccip-message-handling-cyfrin-none-yieldfi-markdown",
        "m-05-bridge-watcher-can-forge-arbitrary-message-and-drain-bridge-code4rena-taiko-taiko-git",
        "missing-verification-for-total-sum-of-user-withdrawals-openzeppelin-none-sonic-opera-native-token-bridge-audit-markdown",
    ],
    ("bridge.md", "bridge-004"): [
        "m-26-zeta-token-supply-keeps-growing-on-failed-onreceive-contract-calls-sherlock-zetachain-cross-chain-git",
        "bridging-dstoken-back-and-forth-between-chains-causes-totalissuance-cap-to-be-reached-preventing-further-issuances-and-cross-chain-transfers-cyfrin-none-securitize-bridge-cctp-markdown",
        "m-03-all-reallocate-cross-chain-token-and-rewards-will-be-lost-for-the-users-using-the-account-abstraction-wallet-code4rena-nudgexyz-nudgexyz-git",
        "h-1-pushvaultamounts-can-be-called-multiple-times-if-in-the-right-state-sherlock-derby-derby-git",
    ],
    ("bridge.md", "bridge-011"): [
        "h-31-on-ulysses-omnichain-retrievedeposit-might-never-be-able-to-trigger-the-fallback-function-code4rena-maia-dao-ecosystem-maia-dao-ecosystem-git",
        "pause-modifier-in-bridge-receiver-functions-causes-receiver-failures-for-in-flight-messages-cyfrin-none-securitize-onofframp-bridge-markdown",
        "fuel1-2-sent-funds-may-get-stuck-inside-of-the-bridge-hexens-none-fuel-markdown",
    ],

    # token-erc20.md
    ("token-erc20.md", "token-004"): [
        "transfertransferfrom-are-used-instead-of-their-counterparts-from-safeerc20-zokyo-none-tradable-markdown",
        "m-02-erc20-return-values-not-checked-code4rena-yaxis-yaxis-contest-git",
        "m-04-erc20-transfer-not-all-tokens-return-boolean-kann-none-wild-protocol-markdown",
        "unhandled-return-value-of-erc20-transfer-in-transfer-and-withdraw-functions-quantstamp-fdusd-on-eth-blockchain-markdown",
        "lack-of-return-value-validation-in-erc20-transfer-zokyo-none-repl-markdown",
    ],
    ("token-erc20.md", "token-001"): [
        "risk-of-token-theft-due-to-race-condition-in-erc20s-approve-function-trailofbits-none-maple-labs-pdf",
        "race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-golem-pdf",
        "race-condition-in-the-erc20-approve-function-may-lead-to-token-thet-trailofbits-dapphub-pdf",
        "ptoken-double-spend-race-conditions-zokyo-none-paribus-markdown",
    ],
    ("token-erc20.md", "token-006"): [
        "decimal-mismatch-for-tokens-on-hyperevm-and-hypercore-cyfrin-none-button-basis-trade-markdown",
        "m-07-trovemanager-does-not-work-with-non-18-decimal-tokens-pashov-audit-group-none-roots_2025-02-09-markdown",
        "m-9-market-rate-never-used-due-to-decimal-discrepancy-sherlock-plaza-finance-git",
        "m-02-price-will-not-always-be-18-decimals-as-expected-and-outlined-in-the-comments-code4rena-caviar-caviar-contest-git",
        "the-stable-swap-pools-used-in-connext-are-incompatible-with-tokens-with-varying-decimals-spearbit-connext-pdf",
    ],
    ("token-erc20.md", "token-007"): [
        "m-01-kumabondtokenapprove-should-revert-if-the-owner-of-the-tokenid-is-blacklisted-code4rena-kuma-protocol-kuma-protocol-versus-contest-git",
        "reward-distribution-or-refunds-can-be-griefed-if-one-of-the-address-gets-blacklisted-zokyo-none-xyro-markdown",
    ],

    # nft-erc721.md
    ("nft-erc721.md", "nft-001"): [
        "reentrancy-in-escrowmanager-mixbytes-none-eywa-markdown",
        "lack-of-reentrancy-guards-where-erc721-is-used-increases-the-risk-profile-for-reentrancy-issues-zokyo-none-isle-finance-markdown",
        "m-3-using-erc721transferfrom-instead-of-safetransferfrom-may-cause-the-nft-to-be-frozen-in-a-contract-that-does-not-support-erc721-sherlock-frankendao-git",
    ],
    ("nft-erc721.md", "nft-008"): [
        "all-nfts-can-be-stolen-by-calling-vestedzeronftsplit-immunefi-zerolend-git",
        "h-5-owner-can-hide-a-staked-nft-via-removetokenidatindex-and-inflate-shares-using-this-to-make-profit-sherlock-steth-by-easedefi-git",
        "m-03-vulnerability-in-burntomin-function-allows-double-use-of-nft-code4rena-nextgen-nextgen-git",
    ],
    ("nft-erc721.md", "nft-006"): [
        "borrowers-could-manipulate-the-floor-price-quantstamp-nemeos-markdown",
        "undocumented-danger-of-market-manipulation-on-nft-prices-quantstamp-altr-markdown",
        "price-oracle-functionality-may-not-align-with-protocols-needs-quantstamp-tribe3-markdown",
        "m-02-nft-oracle-missing-chainlink-liveness-checks-fungify-fungify-markdown",
    ],

    # governance.md
    ("governance.md", "gov-001"): [
        "h-05-flash-loans-can-affect-governance-voting-in-daosol-code4rena-vader-protocol-vader-protocol-contest-git",
        "malicious-user-could-flash-loan-the-vealcx-to-inflate-the-voting-balance-of-their-account-immunefi-alchemix-git",
        "flash-loan-attack-on-gauge-reward-distribution-via-get_adjustment-manipulation-mixbytes-none-yield-basis-markdown",
        "it-is-possible-to-carry-out-attacks-to-manipulate-pools-within-one-transaction-using-a-flash-loan-mixbytes-none-cover-protocol-markdown",
    ],
    ("governance.md", "gov-007"): [
        "timelock-controller-retains-canceled-proposals-enabling-unauthorized-execution-and-severe-governance-voting-manipulation-codehawks-regnum-aurum-acquisition-corp-core-contracts-git",
        "h02-queued-proposal-with-repeated-actions-cannot-be-executed-openzeppelin-compound-alpha-governance-system-audit-markdown",
        "quantammbaseadministrationonlyexecutor-modifier-does-not-enforce-a-time-lock-on-actions-cyfrin-none-quantamm-markdown",
    ],
    ("governance.md", "gov-006"): [
        "cordinated-group-of-attacker-can-artificially-lower-quorum-threshold-during-active-proposals-forcing-malicious-proposals-to-pass-without-true-majority-support-codehawks-regnum-aurum-acquisition-corp-core-contracts-git",
        "it-is-possible-to-lower-the-quorum-requirements-that-will-lead-to-the-past-unmet-proposals-become-executable-immunefi-alchemix-git",
        "missing-quorum-requirement-in-governance-voting-cyfrin-none-deriverse-dex-markdown",
        "m-3-post-proposal-vote-quorumthreshold-checks-use-a-stale-total-supply-value-olympus-olympus-on-chain-governance-markdown",
    ],
    ("governance.md", "gov-003"): [
        "historical-power-manipulation-in-veraactoken-codehawks-regnum-aurum-acquisition-corp-core-contracts-git",
        "voting-power-miscalculation-in-balanceofnftat-function-cantina-none-zerolend-pdf",
        "voting-checkpoints-refer-to-block-numbers-despite-unstable-block-production-frequency-openzeppelin-none-zk-token-capped-minter-and-merkle-distributor-audit-markdown",
        "h01-proposal-process-could-result-in-the-wrong-outcome-openzeppelin-notional-governance-contracts-v2-audit-markdown",
    ],

    # zk-circuits.md
    ("zk-circuits.md", "zk-001"): [
        "etrp-6-missing-constraints-on-message-padding-in-poseidon-decryption-circuit-hexens-none-avacloud-markdown",
        "missing-constraint-in-the-output-of-passportverificationsha1-circuit-halborn-rarimo-passport-zk-circuits-security-assessment-freedom-tool-markdown",
        "h-01-range-check-fails-to-bind-limbs-to-value-enabling-invalid-witnesses-code4rena-succinct-succinct-git",
        "missing-field-order-constraint-ottersec-none-light-protocol-pdf",
        "m-01-zktrie-maximum-depth-limit-is-not-enforced-in-scroll-code4rena-unruggable-unruggable-git",
    ],
    ("zk-circuits.md", "zk-009"): [
        "right-shift-overflow-panic-ottersec-none-solana-zk-token-pdf",
        "memory-access-without-explicit-bounds-checks-openzeppelin-none-zksync-protocol-precompiles-implementation-audit-markdown",
        "batchedrangeproofcontext-tryinto-assumes-all-used-commitments-are-nonzero-trailofbits-none-transfer-blockchain-pdf",
        "vecpoly1eval-can-panic-on-malformed-structs-trailofbits-none-transfer-blockchain-pdf",
    ],
    ("zk-circuits.md", "zk-008"): [
        "m-01-plonkgroth16-verifiers-accept-proofs-with-untrusted-recursion-vk-root-code4rena-succinct-succinct-git",
        "m-4-malicious-verifier-will-recover-private-witness-values-breaking-zero-knowledge-property-sherlock-brevis-pico-zkvm-git",
        "m-05-sp1-host-verifier-rejects-plonk-and-groth16-proofs-with-blake3-hashed-public-values-code4rena-succinct-succinct-git",
    ],

    # erc4337-account-abstraction.md
    ("erc4337-account-abstraction.md", "aa-006"): [
        "nativetokenlimitmodule-can-be-bypassed-quantstamp-alchemy-modular-account-v2-markdown",
        "validation-modules-validation-can-be-fully-bypassed-if-signature-validation-is-skipped-quantstamp-alchemy-modular-account-v2-markdown",
        "m-01-balance-check-during-magicspend-validation-cannot-ensure-that-magicspend-has-enough-balance-to-cover-the-requested-fund-code4rena-coinbase-coinbase-git",
        "h01-incorrect-prefund-calculation-core-openzeppelin-eip-4337-ethereum-account-abstraction-audit-markdown",
    ],
    ("erc4337-account-abstraction.md", "aa-001"): [
        "h-05-paymaster-eth-can-be-drained-with-malicious-sender-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git",
        "verifyingsigner-has-no-authority-over-paymaster-related-gas-limits-cantina-none-coinbase-pdf",
        "m-05-dos-of-user-operations-and-loss-of-user-transaction-fee-due-to-insufficient-gas-value-submission-by-malicious-bundler-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git",
    ],
    ("erc4337-account-abstraction.md", "aa-002"): [
        "h05-incorrect-gas-price-core-openzeppelin-eip-4337-ethereum-account-abstraction-audit-markdown",
        "bundler-may-drop-userops-if-the-owner-of-lightaccount-violates-erc-4337s-validation-requirements-in-isvalidsignature-quantstamp-alchemy-light-account-markdown",
        "enable-mode-can-be-frontrun-to-add-policies-for-a-different-permissionid-codehawks-biconomy-nexus-git",
    ],
    ("erc4337-account-abstraction.md", "aa-005"): [
        "h-07-replay-attack-eip712-signed-transaction-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git",
        "missing-nonce-in-_getenablemodedatahash-allows-signature-replay-codehawks-biconomy-nexus-git",
        "m-03-cross-chain-signature-replay-attack-code4rena-biconomy-biconomy-smart-contract-wallet-contest-git",
        "nonce-logic-is-skipped-for-smart-contract-wallets-spearbit-none-fastlane-atlas-pdf",
        "replay-attacks-on-co-signer-signed-invocations-sigmaprime-none-dapper-labs-pdf",
    ],
}


def build_slug_block(slugs, indent="  "):
    """Build a solodit_ids YAML block with the given slugs."""
    lines = [f"{indent}solodit_ids:"]
    for slug in slugs:
        lines.append(f"{indent}  - {slug}")
    return "\n".join(lines)


def inject_slugs_into_file(filepath, pattern_id, slugs):
    """
    Find the block for `pattern_id` in `filepath` and replace
    `solodit_ids: []` with the populated slug list.
    Returns True if injection was done, False if skipped.
    """
    with open(filepath, "r") as f:
        content = f.read()

    # Find the pattern block start (id: <pattern_id>)
    id_pattern = re.compile(
        r"(- id: " + re.escape(pattern_id) + r"\b.*?)"
        r"(\n  solodit_ids: \[\])",
        re.DOTALL
    )

    match = id_pattern.search(content)
    if not match:
        # Try alternate: solodit_ids already populated?
        if f"- id: {pattern_id}" in content:
            print(f"  SKIP {pattern_id}: solodit_ids already populated or not found as []")
        else:
            print(f"  WARN {pattern_id}: pattern not found in {os.path.basename(filepath)}")
        return False

    slug_block = build_slug_block(slugs, indent="  ")
    new_content = content[:match.start(2)] + "\n" + slug_block + content[match.end(2):]

    with open(filepath, "w") as f:
        f.write(new_content)

    print(f"  OK   {pattern_id}: injected {len(slugs)} slugs")
    return True


def main():
    injected = 0
    skipped = 0
    warned = 0

    # Group by file
    by_file = {}
    for (fname, pid), slugs in SLUGS.items():
        by_file.setdefault(fname, []).append((pid, slugs))

    for fname, patterns in sorted(by_file.items()):
        filepath = os.path.join(BASE, fname)
        if not os.path.exists(filepath):
            print(f"\nERROR: {filepath} not found")
            continue
        print(f"\n{fname} ({len(patterns)} patterns):")
        for pid, slugs in sorted(patterns):
            result = inject_slugs_into_file(filepath, pid, slugs)
            if result:
                injected += 1
            else:
                skipped += 1

    print(f"\n{'='*50}")
    print(f"Injected: {injected}  |  Skipped/Warned: {skipped}")


if __name__ == "__main__":
    main()
