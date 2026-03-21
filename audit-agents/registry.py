"""
Invariant Registry — Loader, Index, and Query API

Loads all invariant JSON files from invariant-registry/,
builds an in-memory index, and provides query methods for
the matcher pipeline.
"""

import json
import os
import re
from pathlib import Path
from typing import Optional


REGISTRY_DIR = Path(__file__).parent.parent / "invariant-registry"
SEVERITY_WEIGHTS = {"critical": 10, "high": 7, "medium": 4, "low": 1}


class Invariant:
    """Single invariant entry with all metadata."""

    def __init__(self, data: dict):
        self.data = data
        self.id = data["id"]
        self.title = data["title"]
        self.category = data["category"]
        self.severity = data["severity"]
        self.tags = data.get("tags", [])
        self.applicable_patterns = data.get("applicable_patterns", {})
        self.invariant_solidity = data["invariant_solidity"]
        self.invariant_natural = data["invariant_natural"]
        self.preconditions = data.get("preconditions", "")
        self.setup_requirements = data.get("setup_requirements", [])
        self.estimated_test_minutes = data.get("estimated_test_minutes", 5)
        self.composition_with = data.get("composition_with", [])
        self.conflicts_with = data.get("conflicts_with", [])
        self.positive_reference = data.get("positive_reference", {})
        self.negative_reference = data.get("negative_reference", {})
        self.found_real_bugs = data.get("found_real_bugs", [])
        self.false_positive_notes = data.get("false_positive_notes", "")
        self.false_positive_rate = data.get("false_positive_rate", 0.0)
        self.historical_hit_rate = data.get("historical_hit_rate", 0.15)
        self.source = data.get("source", "unknown")
        self.source_type = data.get("source_type", "manual")

    def severity_weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.severity, 1)

    def priority_score(self, match_confidence: float = 1.0, max_payout: int = 100000) -> float:
        payout_factor = min(max_payout / 10000, 5.0)
        return (
            self.severity_weight()
            * match_confidence
            * self.historical_hit_rate
            * payout_factor
        ) / self.estimated_test_minutes

    def __repr__(self):
        return f"<Invariant {self.id}: {self.title}>"


class InvariantRegistry:
    """In-memory registry of all invariants with indexing and query support."""

    def __init__(self, registry_dir: Optional[Path] = None):
        self.registry_dir = registry_dir or REGISTRY_DIR
        self.invariants: list[Invariant] = []
        self._by_id: dict[str, Invariant] = {}
        self._by_category: dict[str, list[Invariant]] = {}
        self._by_tag: dict[str, list[Invariant]] = {}
        self._by_severity: dict[str, list[Invariant]] = {}
        self._load()

    def _load(self):
        """Load all JSON files from registry directory."""
        if not self.registry_dir.exists():
            print(f"Warning: Registry directory not found: {self.registry_dir}")
            return

        json_files = list(self.registry_dir.rglob("*.json"))
        # Skip schema.json and results/
        json_files = [
            f for f in json_files
            if f.name != "schema.json"
            and "results" not in f.parts
            and "compositions" not in f.parts
        ]

        for json_file in json_files:
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                if isinstance(data, list):
                    for entry in data:
                        entry = self._normalize_entry(entry)
                        self._add_invariant(entry)
                elif isinstance(data, dict) and "id" in data:
                    data = self._normalize_entry(data)
                    self._add_invariant(data)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: Failed to load {json_file}: {e}")

        print(f"Loaded {len(self.invariants)} invariants from {len(json_files)} files")

    @staticmethod
    def _normalize_entry(entry: dict) -> dict:
        """Normalize entry to handle alternative field names from different agents."""
        # Map alternative field names to canonical schema
        if "invariant_solidity" not in entry:
            if "invariant" in entry:
                entry["invariant_solidity"] = entry.pop("invariant")
            elif "code" in entry:
                entry["invariant_solidity"] = entry.pop("code")
            elif "assertion" in entry:
                entry["invariant_solidity"] = entry.pop("assertion")
            else:
                entry["invariant_solidity"] = ""

        if "invariant_natural" not in entry:
            entry["invariant_natural"] = entry.get("description", entry.get("title", ""))

        # Ensure required fields with defaults
        entry.setdefault("tags", entry.get("attack_vectors", []))
        entry.setdefault("applicable_patterns", {})
        entry.setdefault("setup_requirements", [])
        entry.setdefault("estimated_test_minutes", 5)
        entry.setdefault("composition_with", [])
        entry.setdefault("positive_reference", {})
        entry.setdefault("negative_reference", {})
        entry.setdefault("found_real_bugs", [])
        entry.setdefault("false_positive_notes", "")
        entry.setdefault("historical_hit_rate", 0.15)
        entry.setdefault("source", "unknown")
        entry.setdefault("source_type", "manual")
        entry.setdefault("auto_generated", False)
        entry.setdefault("last_updated", "2026-03-19")

        return entry

    def _add_invariant(self, data: dict):
        inv = Invariant(data)
        self.invariants.append(inv)
        self._by_id[inv.id] = inv

        # Index by category
        cat = inv.category.split("/")[0]  # top-level category
        self._by_category.setdefault(cat, []).append(inv)
        self._by_category.setdefault(inv.category, []).append(inv)

        # Index by tags
        for tag in inv.tags:
            self._by_tag.setdefault(tag, []).append(inv)

        # Index by severity
        self._by_severity.setdefault(inv.severity, []).append(inv)

    def get(self, invariant_id: str) -> Optional[Invariant]:
        return self._by_id.get(invariant_id)

    def by_category(self, category: str) -> list[Invariant]:
        return self._by_category.get(category, [])

    def by_tag(self, tag: str) -> list[Invariant]:
        return self._by_tag.get(tag, [])

    def by_severity(self, severity: str) -> list[Invariant]:
        return self._by_severity.get(severity, [])

    def search(self, query: str) -> list[Invariant]:
        """Full-text search across titles, tags, and natural language descriptions."""
        query_lower = query.lower()
        results = []
        for inv in self.invariants:
            text = f"{inv.title} {inv.invariant_natural} {' '.join(inv.tags)}".lower()
            if query_lower in text:
                results.append(inv)
        return results

    def match_source_code(self, source_code: str) -> list[tuple[Invariant, float]]:
        """
        Stage 1 matcher: pattern match invariants against target source code.
        Returns list of (invariant, confidence) sorted by confidence descending.
        """
        source_lower = source_code.lower()
        results = []

        for inv in self.invariants:
            patterns = inv.applicable_patterns
            if not patterns:
                continue

            score = 0.0
            max_possible = 0.0

            # Check function signatures
            func_sigs = patterns.get("function_sigs", [])
            if func_sigs:
                max_possible += 1.0
                matches = sum(1 for sig in func_sigs if sig.lower() in source_lower)
                if matches > 0:
                    score += min(matches / len(func_sigs), 1.0)

            # Check interfaces
            interfaces = patterns.get("interfaces", [])
            if interfaces:
                max_possible += 1.0
                matches = sum(1 for iface in interfaces if iface.lower() in source_lower)
                if matches > 0:
                    score += min(matches / len(interfaces), 1.0)

            # Check keywords
            keywords = patterns.get("keywords_in_source", [])
            if keywords:
                max_possible += 1.0
                matches = sum(1 for kw in keywords if kw.lower() in source_lower)
                if matches > 0:
                    score += min(matches / len(keywords), 1.0)

            # Check state variable patterns
            state_vars = patterns.get("state_variable_patterns", [])
            if state_vars:
                max_possible += 1.0
                matches = sum(1 for sv in state_vars if re.search(sv, source_code))
                if matches > 0:
                    score += min(matches / len(state_vars), 1.0)

            if max_possible > 0:
                confidence = score / max_possible
                if confidence >= 0.3:  # Minimum threshold
                    results.append((inv, confidence))

        results.sort(key=lambda x: x[1], reverse=True)
        return results

    def rank_for_hunting(
        self,
        matched: list[tuple["Invariant", float]],
        time_budget_minutes: int = 120,
        max_payout: int = 100000,
    ) -> list[tuple["Invariant", float, float]]:
        """
        Rank matched invariants by priority score and fit within time budget.
        Returns list of (invariant, confidence, priority_score).
        """
        ranked = []
        for inv, confidence in matched:
            priority = inv.priority_score(confidence, max_payout)
            ranked.append((inv, confidence, priority))

        ranked.sort(key=lambda x: x[2], reverse=True)

        # Fit within time budget
        total_time = 0
        selected = []
        for inv, conf, prio in ranked:
            if total_time + inv.estimated_test_minutes <= time_budget_minutes:
                selected.append((inv, conf, prio))
                total_time += inv.estimated_test_minutes

        return selected

    def stats(self) -> dict:
        """Return registry statistics."""
        return {
            "total": len(self.invariants),
            "by_severity": {s: len(invs) for s, invs in self._by_severity.items()},
            "by_category": {c: len(invs) for c, invs in self._by_category.items()},
            "with_positive_ref": sum(1 for i in self.invariants if i.positive_reference),
            "with_negative_ref": sum(1 for i in self.invariants if i.negative_reference),
            "with_real_bugs": sum(1 for i in self.invariants if i.found_real_bugs),
        }


# Convenience: module-level singleton
_registry = None


def get_registry() -> InvariantRegistry:
    global _registry
    if _registry is None:
        _registry = InvariantRegistry()
    return _registry


if __name__ == "__main__":
    reg = get_registry()
    stats = reg.stats()
    print(f"\n=== Invariant Registry Stats ===")
    print(f"Total invariants: {stats['total']}")
    print(f"\nBy severity:")
    for sev, count in sorted(stats["by_severity"].items()):
        print(f"  {sev}: {count}")
    print(f"\nBy category:")
    for cat, count in sorted(stats["by_category"].items()):
        print(f"  {cat}: {count}")
    print(f"\nWith positive reference: {stats['with_positive_ref']}")
    print(f"With negative reference: {stats['with_negative_ref']}")
    print(f"With real bug findings: {stats['with_real_bugs']}")
