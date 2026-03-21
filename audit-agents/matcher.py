"""
Matcher Pipeline — Multi-stage invariant matching for target protocols.

Stage 0: Compile check (does invariant compile against target interface?)
Stage 1: Pattern match (keyword/signature matching on source code)
Stage 2: Slither AST analysis (structural matching) [v1.5]
Stage 3: LLM semantic match (for novel protocols) [v2]
"""

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from registry import InvariantRegistry, Invariant, get_registry


class MatchResult:
    """Result of matching an invariant against a target."""

    def __init__(self, invariant: Invariant, confidence: float, stages_passed: list[int]):
        self.invariant = invariant
        self.confidence = confidence
        self.stages_passed = stages_passed

    def __repr__(self):
        return f"<Match {self.invariant.id} conf={self.confidence:.2f} stages={self.stages_passed}>"


class MatcherPipeline:
    """Multi-stage matcher that identifies applicable invariants for a target."""

    def __init__(self, registry: Optional[InvariantRegistry] = None):
        self.registry = registry or get_registry()

    def match(
        self,
        source_dir: str,
        focus_categories: Optional[list[str]] = None,
        max_payout: int = 100000,
        time_budget_minutes: int = 120,
        novel_protocol: bool = False,
    ) -> list[MatchResult]:
        """
        Run full matching pipeline against a target directory.

        Args:
            source_dir: Path to target protocol source code
            focus_categories: Optional list of categories to focus on
            max_payout: Max bounty payout (affects priority scoring)
            time_budget_minutes: Total time budget for fuzzing
            novel_protocol: If True, skip matching and use universal invariants

        Returns:
            List of MatchResult sorted by priority score
        """
        source_path = Path(source_dir)
        if not source_path.exists():
            raise FileNotFoundError(f"Source directory not found: {source_dir}")

        # Collect all Solidity source files
        sol_files = list(source_path.rglob("*.sol"))
        # Exclude test files, lib, node_modules
        sol_files = [
            f for f in sol_files
            if not any(
                skip in str(f).lower()
                for skip in ["test/", "tests/", "lib/", "node_modules/", "mock", "script/"]
            )
        ]

        if not sol_files:
            print(f"Warning: No Solidity files found in {source_dir}")
            return []

        # Read all source code
        combined_source = ""
        for f in sol_files:
            try:
                combined_source += f.read_text(encoding="utf-8") + "\n"
            except UnicodeDecodeError:
                continue

        print(f"Loaded {len(sol_files)} Solidity files ({len(combined_source)} chars)")

        if novel_protocol:
            return self._match_universal_only(combined_source, time_budget_minutes, max_payout)

        # Filter by focus categories if specified
        candidates = self.registry.invariants
        if focus_categories:
            candidates = []
            for cat in focus_categories:
                candidates.extend(self.registry.by_category(cat))

        # Stage 1: Pattern matching
        print("Stage 1: Pattern matching...")
        stage1_results = self._stage1_pattern_match(combined_source, candidates)
        print(f"  -> {len(stage1_results)} invariants matched")

        # Convert to MatchResults with priority scoring
        results = []
        for inv, confidence in stage1_results:
            priority = inv.priority_score(confidence, max_payout)
            results.append(MatchResult(inv, confidence, [1]))

        # Sort by priority
        results.sort(
            key=lambda r: r.invariant.priority_score(r.confidence, max_payout),
            reverse=True,
        )

        # Fit within time budget
        total_time = 0
        selected = []
        for result in results:
            if total_time + result.invariant.estimated_test_minutes <= time_budget_minutes:
                selected.append(result)
                total_time += result.invariant.estimated_test_minutes

        print(f"\nSelected {len(selected)} invariants fitting {time_budget_minutes}min budget")
        print(f"Estimated total test time: {total_time} minutes")

        return selected

    def _stage1_pattern_match(
        self, source_code: str, candidates: list[Invariant]
    ) -> list[tuple[Invariant, float]]:
        """Stage 1: Fast keyword/signature matching."""
        source_lower = source_code.lower()
        results = []

        for inv in candidates:
            patterns = inv.applicable_patterns
            if not patterns:
                continue

            score = 0.0
            checks = 0

            # Function signatures
            func_sigs = patterns.get("function_sigs", [])
            if func_sigs:
                checks += 1
                # Extract just function name for flexible matching
                for sig in func_sigs:
                    func_name = sig.split("(")[0].lower()
                    if func_name in source_lower:
                        score += 1.0 / len(func_sigs)

            # Interfaces
            interfaces = patterns.get("interfaces", [])
            if interfaces:
                checks += 1
                for iface in interfaces:
                    if iface.lower() in source_lower:
                        score += 1.0 / len(interfaces)

            # Keywords
            keywords = patterns.get("keywords_in_source", [])
            if keywords:
                checks += 1
                matched_kw = sum(1 for kw in keywords if kw.lower() in source_lower)
                if matched_kw > 0:
                    score += matched_kw / len(keywords)

            if checks > 0:
                confidence = score / checks
                if confidence >= 0.3:
                    results.append((inv, min(confidence, 1.0)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def _match_universal_only(
        self, source_code: str, time_budget: int, max_payout: int
    ) -> list[MatchResult]:
        """For novel protocols: only use universal invariants."""
        universal = self.registry.by_category("universal")
        results = []
        for inv in universal:
            results.append(MatchResult(inv, 0.5, [0]))

        results.sort(
            key=lambda r: r.invariant.priority_score(r.confidence, max_payout),
            reverse=True,
        )
        return results

    def print_report(self, results: list[MatchResult], max_payout: int = 100000):
        """Print a formatted report of matching results."""
        print("\n" + "=" * 80)
        print("INVARIANT MATCHING REPORT")
        print("=" * 80)

        if not results:
            print("\nNo matching invariants found.")
            return

        # Group by category
        by_cat: dict[str, list[MatchResult]] = {}
        for r in results:
            cat = r.invariant.category
            by_cat.setdefault(cat, []).append(r)

        for cat in sorted(by_cat.keys()):
            matches = by_cat[cat]
            print(f"\n--- {cat} ({len(matches)} invariants) ---")
            for r in matches:
                priority = r.invariant.priority_score(r.confidence, max_payout)
                print(
                    f"  [{r.invariant.severity.upper():8s}] "
                    f"{r.invariant.id:16s} "
                    f"conf={r.confidence:.2f} "
                    f"prio={priority:.1f} "
                    f"| {r.invariant.title}"
                )

        total_time = sum(r.invariant.estimated_test_minutes for r in results)
        print(f"\n{'=' * 80}")
        print(f"Total: {len(results)} invariants | Est. time: {total_time} min")
        print(
            f"Severity: "
            f"{sum(1 for r in results if r.invariant.severity == 'critical')} critical, "
            f"{sum(1 for r in results if r.invariant.severity == 'high')} high, "
            f"{sum(1 for r in results if r.invariant.severity == 'medium')} medium"
        )


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python matcher.py <source_dir> [--focus cat1,cat2] [--budget N]")
        sys.exit(1)

    source_dir = sys.argv[1]
    focus = None
    budget = 120
    max_payout = 100000

    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == "--focus" and i + 1 < len(sys.argv):
            focus = sys.argv[i + 1].split(",")
        elif arg == "--budget" and i + 1 < len(sys.argv):
            budget = int(sys.argv[i + 1])
        elif arg == "--payout" and i + 1 < len(sys.argv):
            max_payout = int(sys.argv[i + 1])

    pipeline = MatcherPipeline()
    results = pipeline.match(source_dir, focus, max_payout, budget)
    pipeline.print_report(results, max_payout)
