"""
V2 Agent Pipeline Orchestrator
================================
Runs the 5 agents sequentially, feeding each agent's output as context
to the next. This is fundamentally different from v1 where agents ran
independently and in parallel -- the v2 pipeline builds UNDERSTANDING
before attempting to find bugs.

Pipeline:
  [Code + Docs] -> ProtocolModel -> Invariants -> Novelty -> InvariantBreaker -> Exploit
                   "What is it?"    "What must    "Where     "How to break     "Prove it
                                     be true?"    to look?"   the rules?"       works"

Usage:
    pipeline = V2Pipeline(llm_client, domain="defi-lending")
    findings = pipeline.run(contract_sources, documentation)
"""

from dataclasses import dataclass, field
from typing import Optional

from .protocol_model_agent import PROTOCOL_MODEL_PROMPT
from .invariant_agent import INVARIANT_EXTRACTION_PROMPT
from .novelty_agent import NOVELTY_IDENTIFICATION_PROMPT
from .invariant_breaker_agent import INVARIANT_BREAKER_PROMPT
from .exploit_agent import EXPLOIT_SYNTHESIS_PROMPT


# Domain-specific supplements appended to the InvariantBreaker prompt
# to encode the deep specialization that top hunters use.
DOMAIN_SUPPLEMENTS = {
    "defi-lending": """
DOMAIN FOCUS: DeFi Lending Protocol

You are a lending protocol specialist. Your top attack vectors:
1. Interest rate manipulation -- can rates be pushed to extremes?
2. Liquidation edge cases -- dust positions, self-liquidation, cascading liquidation
3. Collateral factor manipulation -- can governance change factors to create bad debt?
4. Oracle staleness creating liquidation opportunities or blocking legitimate liquidations
5. Share/asset desync in vault-based lending (ERC4626 inflation attacks)
6. Flash loan to borrow -> manipulate -> repay cycles
7. Bad debt socialization -- does it work correctly? Can one user create bad debt for all?
8. Interest accrual across multiple blocks -- is the math exact or does it drift?
9. Token-specific issues: rebasing tokens as collateral, fee-on-transfer tokens
10. Utilization rate jumps creating MEV opportunities
""",

    "defi-dex": """
DOMAIN FOCUS: DEX / AMM

You are a DEX specialist. Your top attack vectors:
1. Constant product/sum invariant violations during swaps
2. LP token minting/burning ratios during add/remove liquidity
3. Price impact calculations -- can they be manipulated?
4. Fee accumulation and distribution fairness
5. Concentrated liquidity tick boundary issues
6. Multi-hop routing creating arbitrage against the protocol itself
7. First LP deposit manipulation (inflation attack)
8. Sandwich attack amplification through pool mechanics
9. Flash swap callback abuse
10. TWAP oracle manipulation through sustained trading
""",

    "defi-staking": """
DOMAIN FOCUS: Staking / Rewards

You are a staking protocol specialist. Your top attack vectors:
1. Reward rate per share calculation -- rounding exploitation
2. Stake/unstake timing to claim unearned rewards
3. Reward token donation to inflate rewards-per-share
4. Last-second staking before reward distribution
5. Multiple stake/unstake in same block to exploit reward snapshots
6. Cooldown period bypass or manipulation
7. Reward exhaustion -- what happens when reward pool is empty?
8. Multiple reward tokens with different distribution schedules
9. Delegation/boost mechanics creating unfair advantages
10. Migration between staking versions -- can rewards be double-claimed?
""",

    "bridge": """
DOMAIN FOCUS: Cross-Chain Bridge

You are a bridge specialist. Your top attack vectors (highest payouts in history):
1. Message replay across chains or within same chain
2. Message forgery -- can you create a valid-looking message without locking tokens?
3. Validator/relayer trust assumptions -- what if M of N validators collude?
4. Race conditions between source lock and destination mint
5. Token mapping inconsistencies (different decimals, different standards)
6. Failed message handling -- are locked tokens recoverable?
7. Chain reorganization impact on finality assumptions
8. Gas limit differences between chains causing execution failures
9. Upgrade path creating temporary inconsistencies between chains
10. Nonce management -- can messages be reordered or skipped?
""",

    "zk": """
DOMAIN FOCUS: ZK Circuits

You are a ZK circuit specialist. 96% of ZK bugs are under-constrained circuits.

Your top attack vectors:
1. Under-constrained signals -- which signals can take unexpected values while still
   producing a valid proof?
2. Missing range checks -- are all field elements properly bounded?
3. Hash preimage attacks via under-constrained inputs
4. Nullifier reuse -- can the same proof be submitted twice?
5. Public input manipulation -- can the verifier be fooled about what was proven?
6. Arithmetic overflow in field operations
7. Missing completeness -- can valid transactions fail to produce a valid proof?
8. Witness generation bugs that leak private information
9. Trusted setup parameter reuse across circuits
10. Interaction between on-chain verifier and off-chain prover assumptions
""",

    "governance": """
DOMAIN FOCUS: Governance / DAO

You are a governance specialist. Your top attack vectors:
1. Flash loan governance attacks (borrow -> vote -> return)
2. Proposal execution reentrancy
3. Timelock bypass or manipulation
4. Quorum manipulation via vote delegation
5. Vote snapshot timing exploitation
6. Proposal overwrite or cancellation griefing
7. Governance parameter manipulation (change quorum to 0, change timelock to 0)
8. Treasury drain via governance proposal
9. Proxy upgrade via governance to malicious implementation
10. Cross-proposal interaction (two proposals that are safe individually but dangerous together)
""",

    "invariant-testing": """
DOMAIN FOCUS: Economic Invariant Testing (Protocol-Agnostic)

You are NOT looking for code bugs. You are testing whether the protocol's
ECONOMIC INVARIANTS hold under adversarial conditions.

Your methodology:
1. For each invariant from the InvariantAgent, construct 2-3 concrete
   transaction sequences that attempt to violate it.
2. Prioritize IMPLICIT invariants (no require/assert in code).
3. For each attack, specify exact function calls with parameters.
4. Your output must be convertible to Foundry fork tests.

Attack patterns to apply (in order of historical success):
A. Donation attack (transfer tokens directly, bypass deposit)
B. Flash loan amplification (borrow -> manipulate -> extract -> repay)
C. First/last user edge cases (1 wei deposit, empty vault, sole withdrawer)
D. Rounding exploitation (many small operations accumulating dust)
E. Reentrancy during state transition (callback mid-update)
F. Oracle manipulation (flash swap to move price)
G. Fee avoidance (zero amount, dust amount, same-block round-trip)
H. Sandwich protocol operations (front-run harvest/rebalance/liquidate)
I. Cross-function composition (function A state + function B = violation)
J. Extreme values (0, 1, type(uint256).max, address(0))

For EACH attack, trace through the actual code path. Point to the specific
line that would block the attack, or confirm it is unblocked.

Output format must include:
- Target invariant ID
- Exact transaction sequence (contract.function(args) for each step)
- Expected state before and after
- Whether the invariant is violated
- Foundry cheatcodes needed (vm.deal, vm.prank, deal(), vm.warp)
""",
}


@dataclass
class PipelineConfig:
    """Configuration for the V2 audit pipeline."""
    domain: str = "defi-lending"  # Key into DOMAIN_SUPPLEMENTS
    max_novel_functions: int = 50  # Cap on functions for deep analysis
    min_confidence: str = "MEDIUM"  # Minimum confidence to include in output
    include_false_positives: bool = False  # Include FP analysis for learning
    v1_agents_enabled: bool = True  # Also run v1 pattern agents as baseline


@dataclass
class PipelineStage:
    """Result of one pipeline stage."""
    agent_name: str
    prompt_used: str
    output: str
    tokens_used: int = 0
    duration_seconds: float = 0.0


@dataclass
class PipelineResult:
    """Complete result of the V2 pipeline."""
    stages: list[PipelineStage] = field(default_factory=list)
    validated_findings: list[dict] = field(default_factory=list)
    false_positives: list[dict] = field(default_factory=list)
    domain: str = ""

    @property
    def summary(self) -> str:
        n = len(self.validated_findings)
        fp = len(self.false_positives)
        crits = sum(1 for f in self.validated_findings if f.get("severity") == "CRITICAL")
        highs = sum(1 for f in self.validated_findings if f.get("severity") == "HIGH")
        return (
            f"V2 Pipeline complete: {n} validated findings "
            f"({crits} critical, {highs} high), {fp} false positives eliminated"
        )


def build_pipeline_prompts(
    contract_sources: dict[str, str],
    documentation: str = "",
    domain: str = "defi-lending",
) -> list[tuple[str, str]]:
    """
    Build the ordered list of (agent_name, prompt) tuples for the pipeline.

    In actual execution, each prompt is sent to the LLM with the contract
    source code AND the output of all previous stages as context.

    Args:
        contract_sources: mapping of filename -> source code
        documentation: any available protocol documentation
        domain: protocol domain for specialist knowledge

    Returns:
        List of (agent_name, full_prompt) tuples in execution order
    """
    # Build the code context that goes into every prompt
    code_block = "\n\n".join(
        f"=== {fname} ===\n{source}"
        for fname, source in contract_sources.items()
    )

    doc_block = f"\n\n=== DOCUMENTATION ===\n{documentation}" if documentation else ""

    context = f"{doc_block}\n\n=== SOURCE CODE ===\n{code_block}"

    # Get domain supplement (falls back to empty if unknown domain)
    domain_supplement = DOMAIN_SUPPLEMENTS.get(domain, "")

    # Build the pipeline
    stages = [
        (
            "ProtocolModelAgent",
            f"{PROTOCOL_MODEL_PROMPT}\n\n{context}",
        ),
        (
            "InvariantAgent",
            f"{INVARIANT_EXTRACTION_PROMPT}\n\n"
            f"[The Protocol Model from the previous agent will be inserted here]\n\n{context}",
        ),
        (
            "NoveltyAgent",
            f"{NOVELTY_IDENTIFICATION_PROMPT}\n\n"
            f"[The Protocol Model and Invariant List from previous agents will be inserted here]\n\n{context}",
        ),
        (
            "InvariantBreakerAgent",
            f"{INVARIANT_BREAKER_PROMPT}\n\n{domain_supplement}\n\n"
            f"[Protocol Model, Invariant List, and Novelty Analysis from previous agents will be inserted here]\n\n{context}",
        ),
        (
            "ExploitAgent",
            f"{EXPLOIT_SYNTHESIS_PROMPT}\n\n"
            f"[All previous agent outputs and candidate bugs will be inserted here]\n\n{context}",
        ),
    ]

    return stages
