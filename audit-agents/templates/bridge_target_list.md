# TOP 10 BRIDGE BOUNTIES TO TARGET NOW

Last updated: 2026-03-16

---

## Priority Ranking

### #1. LayerZero -- $15,000,000 max payout
- **Platform**: Immunefi
- **Max Payout**: $15M (Critical, V1 Group 1 chains)
- **Scope**: EndpointV2, SendULN302, ReceiveULN302, DVN, OFT, ONFT, OApp across 40+ chains (Solidity + Solana/Rust + TON + Aptos/Move)
- **Repo**: https://github.com/LayerZero-Labs
- **Why Target**: Largest bounty in Web3. Multi-language codebase (Solidity + Rust + TON). V2 is relatively new. OFT/ONFT integrations by third parties are classified as low severity but the core infrastructure is the real prize.
- **Focus Areas**: DVN configuration attacks, EndpointV2 message verification, cross-chain OFT accounting, sharedDecimals precision loss, V1->V2 migration edge cases.
- **Key Restriction**: Findings in already-audited code (LayerZero-Labs/Audits repo) are ineligible. OFT/ONFT findings capped at low severity.
- **Score**: 9.2/10 PRIORITY TARGET

### #2. Stargate -- $10,000,000 max payout
- **Platform**: Immunefi
- **Max Payout**: $10M (Critical)
- **Scope**: StargatePool (USDC, USDT, METIS, mETH, Native), FeeLibV1, StargateStaking, StargateMultiRewarder on Ethereum
- **Repo**: Via Immunefi scope page
- **Why Target**: Extremely high payout. Liquidity pool model (not lock-and-mint) introduces unique rebalancing and LP vulnerabilities. LayerZero recently acquired Stargate DAO -- integration changes may introduce bugs.
- **Focus Areas**: LP share price manipulation, cross-chain rebalancing exploits, fee library precision errors, staking/reward accounting, pool imbalance attacks.
- **Score**: 8.8/10 PRIORITY TARGET

### #3. Wormhole -- $2,000,000 max payout
- **Platform**: Immunefi
- **Max Payout**: $2M (Tier 1: full TVL extraction across all chains). Historically paid $10M for a critical bug.
- **Scope**: Guardian nodes, Ethereum, Solana, CosmWasm, Algorand, Aptos, Sui, Near, NTT (Native Token Transfers), MultiGov
- **Repo**: https://github.com/wormhole-foundation/wormhole
- **Why Target**: Massive multi-language scope (Solidity + Rust + CosmWasm + Move + PyTeal). NTT is a newer product with less scrutiny. MultiGov (cross-chain governance) is a complex attack surface. Historical $10M payout proves willingness to pay.
- **Focus Areas**: NTT accounting invariants, MultiGov cross-chain proposal manipulation, guardian VAA verification edge cases, Sui/Aptos bridge logic (less auditor coverage).
- **Key Restriction**: Governor module limits critical payouts to 10% of 24-hour extractable value.
- **Score**: 8.5/10 PRIORITY TARGET

### #4. Hyperlane -- $2,500,000 max payout
- **Platform**: Immunefi
- **Max Payout**: $2.5M (Critical, 10% of funds affected)
- **Scope**: 222 assets across 10+ chains -- mailbox proxies, hooks, ISMs (Interchain Security Modules), gas paymasters
- **Repo**: https://github.com/hyperlane-xyz
- **Why Target**: Modular ISM architecture means each deployment can have different security models. Custom ISMs by integrators are a rich attack surface. 222 in-scope assets is an enormous scope. Relatively newer protocol compared to Wormhole/LZ.
- **Focus Areas**: ISM misconfiguration (wrong security model per chain), mailbox message validation, hook injection, gas paymaster exploits, custom ISM bypasses.
- **Score**: 8.1/10 PRIORITY TARGET

### #5. Celer cBridge -- $2,000,000 max payout
- **Platform**: Immunefi
- **Max Payout**: $2M
- **Scope**: cBridge smart contracts, State Guardian Network (SGN) integration
- **Repo**: https://github.com/celer-network
- **Why Target**: Uses a PoS-based State Guardian Network (Tendermint) which is a unique architecture. Dual model: liquidity pool + lock-and-mint. SGN acts as both validator and liquidity manager.
- **Focus Areas**: SGN message validation, liquidity pool <-> lock-mint interaction, cross-model accounting inconsistency, validator set management.
- **Score**: 7.5/10 PRIORITY TARGET

### #6. Axelar Network -- $2,250,000 max payout (combined)
- **Platform**: Immunefi
- **Max Payout**: $500K per severity tier (Critical: up to $500K smart contracts, up to $500K blockchain/DLT)
- **Scope**: Gateway contracts (ETH, AVAX, BSC, FTM, Polygon, Moonbeam), Interchain Token Service, axelar-core, tofnd signer, GMP SDK
- **Repo**: https://github.com/axelarnetwork
- **Why Target**: Full-stack scope including Cosmos chain (axelar-core) and ECDSA signing code (tofnd). Interchain Token Service (ITS) is relatively new. GMP (General Message Passing) enables arbitrary cross-chain calls.
- **Focus Areas**: ITS token factory vulnerabilities, GMP arbitrary execution, Gateway validation logic, tofnd ECDSA edge cases, cross-chain governance.
- **Key Restriction**: Critical requires >= $500K loss to qualify.
- **Score**: 7.2/10 GO

### #7. Across Protocol -- $1,000,000+ max payout (estimated)
- **Platform**: Immunefi
- **Scope**: Across V3 smart contracts, UMA optimistic oracle integration
- **Repo**: https://github.com/across-protocol
- **Why Target**: Intent-based bridge model is architecturally novel (relayer advances funds, gets reimbursed after optimistic verification). UMA oracle integration adds an oracle attack surface layer.
- **Focus Areas**: Optimistic oracle manipulation, relayer front-running, intent fulfillment race conditions, deposit/relay accounting, challenge period exploits.
- **Score**: 7.0/10 GO

### #8. Circle CCTP v2 -- Variable payout
- **Platform**: Direct with Circle (not Immunefi)
- **Scope**: Cross-Chain Transfer Protocol v2, TokenMessenger, MessageTransmitter
- **Repo**: https://github.com/circlefin/evm-cctp-contracts
- **Why Target**: CCTP is the canonical way to bridge USDC. V2 is recently deployed. Native USDC burn-and-mint model. Any vulnerability affects billions in USDC liquidity.
- **Focus Areas**: MessageTransmitter attestation verification, TokenMessenger accounting, burn/mint parity, cross-chain nonce management.
- **Score**: 6.8/10 GO

### #9. deBridge -- $200,000 max payout
- **Platform**: Immunefi
- **Max Payout**: $200K (Critical, flat)
- **Scope**: deBridgeGate, SignatureVerifier, CallProxy, WethGate across 7 chains
- **Repo**: Via Immunefi scope page
- **Why Target**: Lower max payout but NO KYC required (unique among major bridge bounties). SignatureVerifier is a custom implementation (not using a standard library). CallProxy enables arbitrary cross-chain calls.
- **Focus Areas**: SignatureVerifier bypass, CallProxy arbitrary execution, deBridgeGate accounting, WethGate native ETH handling edge cases.
- **Score**: 6.2/10 GO

### #10. Chainlink CCIP -- $500,000+ max payout (estimated)
- **Platform**: Direct with Chainlink
- **Scope**: CCIP Router, OnRamp, OffRamp, CommitStore, Token Pools
- **Repo**: https://github.com/smartcontractkit/ccip
- **Why Target**: Chainlink's cross-chain protocol. Router/OnRamp/OffRamp architecture. Token Pool model for bridging. CCIP is increasingly integrated into major DeFi protocols as their bridge solution.
- **Focus Areas**: Token Pool accounting, OnRamp message construction, OffRamp execution, CommitStore merkle root management, rate limiter bypasses.
- **Score**: 6.0/10 MAYBE (limited public scope, but high impact)

---

## Summary Table

| Rank | Protocol | Max Payout | Score | Decision | Primary Focus |
|------|----------|-----------|-------|----------|---------------|
| 1 | LayerZero | $15M | 9.2 | PRIORITY | DVN, EndpointV2, OFT accounting |
| 2 | Stargate | $10M | 8.8 | PRIORITY | LP manipulation, fee precision |
| 3 | Wormhole | $2M ($10M historical) | 8.5 | PRIORITY | NTT, MultiGov, multi-chain |
| 4 | Hyperlane | $2.5M | 8.1 | PRIORITY | ISM config, mailbox, hooks |
| 5 | Celer cBridge | $2M | 7.5 | PRIORITY | SGN validation, dual model |
| 6 | Axelar | $2.25M | 7.2 | GO | ITS, GMP, ECDSA signing |
| 7 | Across | $1M+ | 7.0 | GO | Intent model, UMA oracle |
| 8 | Circle CCTP v2 | Variable | 6.8 | GO | Attestation, burn/mint |
| 9 | deBridge | $200K | 6.2 | GO | SignatureVerifier, CallProxy |
| 10 | Chainlink CCIP | $500K+ | 6.0 | MAYBE | Token Pools, CommitStore |

---

## RECOMMENDED ATTACK SEQUENCE

**Week 1-2**: LayerZero + Stargate (shared messaging layer -- findings in one may apply to both)
**Week 3-4**: Wormhole NTT + MultiGov (newer products with less auditor coverage)
**Week 5-6**: Hyperlane ISMs (modular architecture = many configuration permutations)
**Week 7-8**: Across + Celer (novel architectures -- intent-based and PoS-based)

Start each target with the Bridge Triage (scoring system), then deploy agents in order:
1. Message Verification Agent (10)
2. Accounting Invariant Agent (11)
3. Validator/Key Management Agent (12)
4. Cross-Chain State Agent (13)
5. Integration Surface Agent (14)
