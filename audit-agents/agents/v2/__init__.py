# V2 Agent System: LLM-native logic bug hunting
#
# Philosophy: The old agents (v1) use regex pattern matching to find known
# vulnerability signatures. This catches only previously-seen bug classes.
# The v2 agents use LLM reasoning to UNDERSTAND protocol logic, then BREAK it.
#
# Pipeline (sequential, each feeds into the next):
#   1. ProtocolModelAgent  - Reads docs + code, builds mental model of what the protocol SHOULD do
#   2. InvariantAgent      - Extracts the implicit and explicit invariants the protocol relies on
#   3. NoveltyAgent        - Identifies custom/novel mechanisms and ignores standard library code
#   4. InvariantBreakerAgent - Systematically tries to violate each invariant via the novel code
#   5. ExploitAgent        - Takes candidate violations and builds concrete attack scenarios + PoCs
#
# Key research findings baked in:
#   - 37% of DeFi payouts are accounting desync bugs
#   - 96% of ZK bugs are under-constrained circuits
#   - cmichel reads 200 LOC/hour with NO tools -- pure comprehension
#   - Best bugs are LOGIC errors in NOVEL code, not pattern matches in old code
#   - Top hunters specialize in ONE domain deeply

from .protocol_model_agent import PROTOCOL_MODEL_PROMPT
from .invariant_agent import INVARIANT_EXTRACTION_PROMPT
from .novelty_agent import NOVELTY_IDENTIFICATION_PROMPT
from .invariant_breaker_agent import INVARIANT_BREAKER_PROMPT
from .exploit_agent import EXPLOIT_SYNTHESIS_PROMPT
