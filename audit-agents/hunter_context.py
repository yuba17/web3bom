"""hunter_context.py — Hunter-level context extracted from legacy run_hunt.py.

Contains the symbols that run_benchmark.py still imports:
- HUNTER_DOMAINS: hunter name -> (domain_key, description) dict.
- load_rejection_context: reads hunt_session/feedback/rejection_rules.yaml.
- load_few_shot_examples: reads audit-agents/few_shot_examples/<cat>.yaml.

Migrated from run_hunt.py during Phase 4 of the optimization roadmap
(2026-04-18). Behaviour is identical to the legacy versions.
"""
from __future__ import annotations

import yaml

from paths import WEB3_DIR, HUNT_SESSION_DIR, AUDIT_AGENTS_DIR


HUNTER_DOMAINS = {
    "MathHunter":    ("math",    "Overflow, rounding, precision, exchange rate math, share price manipulation"),
    "AccessHunter":  ("access",  "Access control, missing modifiers, privilege escalation, role misconfig"),
    "FlowHunter":    ("flow",    "Reentrancy, CEI violations, token flow, callback abuse, fund routing"),
    "OracleHunter":  ("oracle",  "Price manipulation, TWAP staleness, spot price vs TWAP, oracle dependencies"),
    "DomainHunter":  ("domain",  "Protocol-specific invariants, cross-component interactions, economic attacks"),
    "WildcardHunter":("wildcard","Novel bugs, unconventional vectors, assumption violations, composability risks"),
    "TrustBoundaryHunter":("trust","Trust boundary analysis: token quirks (ERC777, fee-on-transfer, rebasing, pausable), external call trust (reverts, unexpected returns, delegatecall), proxy/upgrade patterns (uninitialized, storage collision), compiler/EVM assumptions, cross-contract trust assumptions"),
    "SignatureHunter":("signature","Signature replay, permit abuse, EIP-712 issues, nonce handling, ecrecover validation, approval/allowance patterns, Permit2, meta-transactions"),
    "DoSHunter":     ("dos",      "Denial of service, gas griefing, unbounded loops, blocked withdrawals, revert-based DoS, resource exhaustion, emergency function blocking"),
}


def load_rejection_context() -> str:
    """Load rejection rules as anti-patterns for hunters."""
    rules_path = HUNT_SESSION_DIR / "feedback" / "rejection_rules.yaml"
    if not rules_path.exists():
        return ""
    try:
        with open(rules_path) as f:
            rules = yaml.safe_load(f)
        if not rules:
            return ""
        lines = ["\n## Anti-Patterns (Rechazados en plataformas reales -- NO reportar estos)"]
        categories = rules.get("rejection_categories", {})
        for cat_name, cat_data in categories.items():
            if cat_name == "duplicate":
                continue
            rule_text = cat_data.get("rule", "")
            count = cat_data.get("count", 0)
            if rule_text:
                lines.append(f"- **{cat_name}** ({count}x rechazado): {rule_text}")
        for lesson in rules.get("lessons", []):
            lines.append(f"- {lesson}")
        return "\n".join(lines) if len(lines) > 1 else ""
    except Exception:
        return ""


def load_few_shot_examples(hunter_domain: str) -> str:
    """Load 2-3 relevant few-shot examples for this hunter's domain."""
    domain_categories = {
        "math": ["rounding", "accounting"], "access": ["access"],
        "flow": ["accounting", "logic"], "oracle": ["oracle"],
        "domain": ["logic", "accounting"], "dos": ["dos"],
        "logic": ["logic"], "adversarial": ["accounting", "oracle", "logic"],
        "trust": ["access", "logic"], "signature": ["access"],
        "wildcard": ["logic", "dos"],
    }
    cats = domain_categories.get(hunter_domain, ["logic"])
    examples_dir = AUDIT_AGENTS_DIR / "few_shot_examples"
    if not examples_dir.exists():
        return ""
    results = []
    for cat in cats:
        cat_file = examples_dir / f"{cat}.yaml"
        if not cat_file.exists():
            continue
        try:
            data = yaml.safe_load(cat_file.read_text())
            for ex in data.get("examples", [])[:2]:
                results.append(
                    f"### {ex.get('title', '?')} ({ex.get('source', '')})\n"
                    f"```solidity\n{ex.get('vulnerable_code', '').strip()}\n```\n"
                    f"{ex.get('explanation', '').strip()}\n"
                )
        except Exception:
            continue
    if not results:
        return ""
    return (
        "\n---\n## Ejemplos Reales de Bugs (Few-Shot — bugs confirmados en auditorías reales)\n"
        + "\n".join(results[:3])
    )
