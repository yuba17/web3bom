# Phase 2A — Quick Wins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate 8 low-risk context-enrichment and CLI features from legacy `run_hunt.py` into the modern flow (`run_benchmark.py` + `plan_generator.py`) without regressing the Phase 1 snapshot tests.

**Architecture:** Extract 5 legacy functions into a new `audit-agents/context_enrichment.py` module, compose them via `build_hunter_context()`, call that from `plan_generator.phase_hunter_prompt`. Add 4 new CLI flags (`--hunters`, `--domain`, `--force-regen-map`, `--force-gate`) to `run_benchmark.py`.

**Tech Stack:** Python 3.10+, pytest 9.0.2 (no plugins), subprocess for wrapping external CLIs (`symmetric_analyzer.py`, `deep_flatten.py`), PyYAML, ruamel-less yaml for tests.

---

## Pre-flight

- [ ] **Step P1: Confirm Phase 1 baseline is green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -v`
Expected: `19 passed` in ~5s. If any fails, STOP — fix before starting Phase 2A.

- [ ] **Step P2: Confirm main is in a sane state**

Run: `git status --porcelain | head -5`
Expected: some modified files (the 27 pre-existing uncommitted deltas), no merge conflicts, no unrelated staged files. If confused, ask.

---

## Task 1: Scaffold `context_enrichment.py` + tests baseline

**Files:**
- Create: `audit-agents/context_enrichment.py`
- Create: `audit-agents/tests/phase_2a/__init__.py`
- Create: `audit-agents/tests/phase_2a/conftest.py`
- Create: `audit-agents/tests/phase_2a/test_scaffold.py`

- [ ] **Step 1.1: Create empty module with module docstring and `from __future__`**

Write `audit-agents/context_enrichment.py` with:

```python
"""Context-enrichment helpers for the modern hunter pipeline.

Migrated from legacy `run_hunt.py` during Phase 2A of the optimization
roadmap. These functions enrich the hunter brief with wiki excerpts,
domain briefings, asset-flow maps, symmetry signals, and deep-flatten
traces. `build_hunter_context` composes all five into a single markdown
block appended to the brief.

Each helper degrades gracefully: on failure (missing file, subprocess
error, vault unreachable) it returns an empty string. A hunter prompt
must never fail because of a context-enrichment helper.
"""
from __future__ import annotations

from pathlib import Path

# Skip deep_flatten when the contract is small — the signal isn't worth
# the subprocess cost. Threshold chosen empirically; tune if needed.
DEEP_FLATTEN_MIN_LINES = 200
```

- [ ] **Step 1.2: Create test directory infrastructure**

Create `audit-agents/tests/phase_2a/__init__.py` as an empty file.

Create `audit-agents/tests/phase_2a/conftest.py` with:

```python
"""Shared fixtures for Phase 2A tests."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

AUDIT_AGENTS = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(AUDIT_AGENTS))

REPO_ROOT = AUDIT_AGENTS.parent


@pytest.fixture
def tmp_vault(tmp_path: Path, monkeypatch) -> Path:
    """Temporary Obsidian vault rooted at <tmp>/obsidian-vault/web3-audit/.

    Override `Path.home()` via monkeypatch so `query_wiki_context` reads
    from the tmp vault instead of the user's real home directory.
    """
    vault = tmp_path / "obsidian-vault" / "web3-audit"
    vault.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    return vault


@pytest.fixture
def tmp_solidity_contract(tmp_path: Path) -> Path:
    """A minimal Solidity contract file with a handful of asset-flow patterns."""
    contract = tmp_path / "TestVault.sol"
    contract.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n\n"
        "contract TestVault {\n"
        "    function deposit(uint256 amt) external {\n"
        "        token.transferFrom(msg.sender, address(this), amt);\n"
        "    }\n"
        "    function withdraw(uint256 amt) external {\n"
        "        token.transfer(msg.sender, amt);\n"
        "    }\n"
        "    function approveSpender(address s) external {\n"
        "        token.approve(s, type(uint256).max);\n"
        "    }\n"
        "    function balance() external view returns (uint256) {\n"
        "        return token.balanceOf(address(this));\n"
        "    }\n"
        "}\n"
    )
    return contract
```

- [ ] **Step 1.3: Write a baseline smoke test**

Create `audit-agents/tests/phase_2a/test_scaffold.py` with:

```python
"""Smoke tests confirming context_enrichment module is importable."""
from __future__ import annotations


def test_module_imports():
    import context_enrichment  # noqa: F401


def test_module_constants_present():
    import context_enrichment
    assert isinstance(context_enrichment.DEEP_FLATTEN_MIN_LINES, int)
    assert context_enrichment.DEEP_FLATTEN_MIN_LINES >= 100
```

- [ ] **Step 1.4: Run the smoke test and confirm green**

Run: `python -m pytest audit-agents/tests/phase_2a/test_scaffold.py -v`
Expected: `2 passed` in <1s.

- [ ] **Step 1.5: Confirm Phase 1 still green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`. If any regression, STOP and fix.

- [ ] **Step 1.6: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/tests/phase_2a/
git commit -m "feat: scaffold context_enrichment module + phase_2a test dir"
```

---

## Task 2: Migrate F019 `query_wiki_context`

**Files:**
- Modify: `audit-agents/context_enrichment.py`
- Modify: `audit-agents/run_hunt.py:54-92` (replace body with re-export)
- Test: `audit-agents/tests/phase_2a/test_wiki_context.py`

- [ ] **Step 2.1: Write the failing tests first (TDD)**

Create `audit-agents/tests/phase_2a/test_wiki_context.py`:

```python
"""F019 — Obsidian vault wiki-context query."""
from __future__ import annotations

from pathlib import Path

from context_enrichment import query_wiki_context


def test_returns_empty_when_vault_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    # No vault created. Expect empty string, not exception.
    assert query_wiki_context("lending", "Vault") == ""


def test_returns_empty_when_no_match(tmp_vault):
    (tmp_vault / "unrelated.md").write_text("# Nothing relevant\nBody about staking.")
    assert query_wiki_context("lending", "Vault") == ""


def test_finds_match_by_domain(tmp_vault):
    (tmp_vault / "lending-notes.md").write_text(
        "---\nsummary: Key lending patterns\n---\n# Lending\nContent."
    )
    out = query_wiki_context("lending", "Vault")
    assert "lending-notes" in out
    assert "Key lending patterns" in out
    assert out.startswith("\n---\n## Prior Knowledge (Obsidian Vault)\n")


def test_finds_match_by_component(tmp_vault):
    (tmp_vault / "vault-audit.md").write_text("# Vault audit\nVault specifics here.")
    out = query_wiki_context("staking", "Vault")
    assert "vault-audit" in out


def test_skips_internal_dirs(tmp_vault):
    (tmp_vault / "_raw").mkdir()
    (tmp_vault / "_raw" / "lending-draft.md").write_text("# Lending draft")
    (tmp_vault / ".obsidian").mkdir()
    (tmp_vault / ".obsidian" / "workspace.md").write_text("# Lending workspace")
    (tmp_vault / "projects").mkdir()
    (tmp_vault / "projects" / "lending.md").write_text("# Lending project")
    assert query_wiki_context("lending", "Vault") == ""


def test_output_capped_at_8_results(tmp_vault):
    for i in range(20):
        (tmp_vault / f"lending-{i}.md").write_text(f"# Note {i} about lending")
    out = query_wiki_context("lending", "Vault")
    # Count markdown list entries
    assert out.count("\n- **") == 8


def test_prefers_frontmatter_summary_over_body(tmp_vault):
    (tmp_vault / "hit.md").write_text(
        "---\nsummary: SHORT SUMMARY\n---\n# Lending\n" + ("LONG BODY " * 200)
    )
    out = query_wiki_context("lending", "Vault")
    assert "SHORT SUMMARY" in out
    assert "LONG BODY" not in out
```

- [ ] **Step 2.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_wiki_context.py -v`
Expected: ImportError on `from context_enrichment import query_wiki_context` (not defined yet).

- [ ] **Step 2.3: Port the implementation**

Add to `audit-agents/context_enrichment.py` (after existing code):

```python
def query_wiki_context(domain: str, component: str) -> str:
    """Query Obsidian vault for relevant prior knowledge.

    Searches recursively through the vault (skipping _raw, _archives,
    .obsidian, projects). Returns up to 8 summaries, capped implicitly
    by 8 x ~300ch = ~2400ch max. Empty string if vault missing or no
    matches.
    """
    vault_dir = Path.home() / "obsidian-vault" / "web3-audit"
    if not vault_dir.exists():
        return ""
    skip_dirs = {"_raw", "_archives", ".obsidian", "projects"}
    skip_files = {"index.md", "log.md"}
    results: list[str] = []
    domain_l, comp_l = domain.lower(), component.lower()
    for md_file in vault_dir.glob("**/*.md"):
        if md_file.name.startswith("_") or md_file.name in skip_files:
            continue
        if any(part in skip_dirs for part in md_file.relative_to(vault_dir).parts):
            continue
        try:
            content = md_file.read_text(errors="ignore")
        except Exception:
            continue
        lower = content.lower()
        if domain_l in lower or comp_l in lower:
            summary = ""
            if content.startswith("---"):
                end = content.find("---", 3)
                if end != -1:
                    for line in content[3:end].splitlines():
                        if line.strip().startswith("summary:"):
                            summary = line.split("summary:", 1)[1].strip()
                            break
            snippet = summary if summary else content[:300]
            results.append(f"- **{md_file.stem}**: {snippet}")
    if not results:
        return ""
    return "\n---\n## Prior Knowledge (Obsidian Vault)\n" + "\n".join(results[:8])
```

- [ ] **Step 2.4: Run tests to confirm pass**

Run: `python -m pytest audit-agents/tests/phase_2a/test_wiki_context.py -v`
Expected: `7 passed` in <1s.

- [ ] **Step 2.5: Re-export from `run_hunt.py` to preserve legacy callers**

Replace the body of `query_wiki_context` at `audit-agents/run_hunt.py:54-92` with a single import-and-delegate:

```python
def query_wiki_context(domain: str, component: str) -> str:
    """Thin re-export — see context_enrichment.query_wiki_context for details."""
    from context_enrichment import query_wiki_context as _impl
    return _impl(domain, component)
```

- [ ] **Step 2.6: Sanity-check — legacy still works**

Run: `python -c "from audit_agents_shim import noop" 2>/dev/null; cd audit-agents && python -c "from run_hunt import query_wiki_context; print(query_wiki_context('x', 'y'))"`
Expected: empty string printed (no vault in test env or no match), no exception.

- [ ] **Step 2.7: Confirm Phase 1 still green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 2.8: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/run_hunt.py audit-agents/tests/phase_2a/test_wiki_context.py
git commit -m "feat(F019): migrate query_wiki_context to context_enrichment"
```

---

## Task 3: Migrate F022 `load_briefings` tiered

**Files:**
- Modify: `audit-agents/context_enrichment.py`
- Modify: `audit-agents/run_hunt.py` (re-export the three functions)
- Test: `audit-agents/tests/phase_2a/test_briefings.py`

- [ ] **Step 3.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_briefings.py`:

```python
"""F022 — Domain briefings loader (tiered: primary full, secondary grep-only)."""
from __future__ import annotations

from pathlib import Path

import pytest

from context_enrichment import (
    load_briefing_single,
    load_briefings_tiered,
    load_grep_targets_only,
)


@pytest.fixture
def tmp_briefings(tmp_path, monkeypatch):
    """Install a fake WEB3_DIR with knowledge/ briefings."""
    web3 = tmp_path / "Web3"
    knowledge = web3 / "knowledge"
    knowledge.mkdir(parents=True)
    (knowledge / "lending.md").write_text(
        "# Lending\n"
        "### 1. First bug\n"
        "### 2. Second bug\n"
        "## 3. Invariant Checklist\n"
        "- must do X\n"
        "- must do Y\n"
        "## 4. Grep Targets\n"
        "- grep foo\n"
        "- grep bar\n"
        "## 2.3 Real-World Incidents\n"
        "- Protocol A 2023\n"
    )
    (knowledge / "vault-erc4626.md").write_text(
        "# Vault\n## 4. Grep Targets\n- grep vault\n- grep shares\n"
    )
    import context_enrichment
    monkeypatch.setattr(context_enrichment, "WEB3_DIR", web3)
    return web3


def test_single_returns_empty_when_domain_unknown(tmp_briefings):
    assert load_briefing_single("not-a-domain") == ""


def test_single_extracts_structured_sections(tmp_briefings):
    out = load_briefing_single("lending")
    assert "PATRONES CONOCIDOS" in out
    assert "First bug" in out
    assert "CHECKLIST DE INVARIANTES" in out
    assert "GREP TARGETS" in out
    assert "INCIDENTES REALES" in out


def test_grep_only_compact(tmp_briefings):
    out = load_grep_targets_only("vault")
    assert "grep vault" in out
    assert "grep shares" in out
    # Must NOT contain checklist markers
    assert "CHECKLIST" not in out


def test_tiered_primary_full(tmp_briefings):
    out = load_briefings_tiered(["lending"])
    assert "Briefing principal: lending" in out
    assert "CHECKLIST DE INVARIANTES" in out


def test_tiered_primary_plus_secondary_grep(tmp_briefings):
    out = load_briefings_tiered(["lending", "vault"])
    assert "Briefing principal: lending" in out
    assert "Grep targets adicionales (vault)" in out
    assert "grep vault" in out


def test_tiered_drops_tertiary(tmp_briefings):
    out = load_briefings_tiered(["lending", "vault", "staking"])
    assert "staking" not in out.lower() or "Grep targets adicionales (staking)" not in out


def test_tiered_empty_list_returns_empty(tmp_briefings):
    assert load_briefings_tiered([]) == ""
```

- [ ] **Step 3.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_briefings.py -v`
Expected: ImportError on `load_briefing_single`, `load_briefings_tiered`, `load_grep_targets_only`.

- [ ] **Step 3.3: Port constants and functions**

Add to `audit-agents/context_enrichment.py` (imports at top):

```python
import re
```

After the existing code, add:

```python
WEB3_DIR = Path(__file__).resolve().parents[1]  # /home/kali/Documents/Web3

DOMAIN_BRIEFING: dict[str, str] = {
    "staking":    "knowledge/staking.md",
    "lending":    "knowledge/lending.md",
    "vault":      "knowledge/vault-erc4626.md",
    "oracle":     "knowledge/oracle.md",
    "dex":        "knowledge/dex-amm.md",
    "flash":      "knowledge/flash-loan.md",
    "token":      "knowledge/token-erc20.md",
    "access":     "knowledge/access-control.md",
    "signature":  "knowledge/signature-replay.md",
    "proxy":      "knowledge/proxy-upgrade.md",
    "trust":      "knowledge/trust-boundaries.md",
    "bridge":     "knowledge/bridge.md",
    "opstack":    "knowledge/bridge-opstack.md",
    "erc4337":    "knowledge/erc4337-account-abstraction.md",
    "zk":         "knowledge/zk-circuits.md",
    "governance": "knowledge/governance.md",
    "nft":        "knowledge/nft-erc721.md",
    "yield":      "knowledge/yield-aggregator.md",
    "liquid":     "knowledge/liquid-staking.md",
    "perps":      "knowledge/perps-derivatives.md",
    "crosschain": "knowledge/cross-chain-intents.md",
    "vesting":    "knowledge/vesting-tokenomics.md",
    "options":    "knowledge/options-structured-products.md",
    "mev":        "knowledge/mev-sandwich.md",
    "reentrancy": "knowledge/reentrancy-patterns.md",
    "inputval":   "knowledge/input-validation.md",
}


def load_briefing_single(domain: str) -> str:
    """Extract structured sections from a domain briefing markdown file.

    Returns a compressed summary (patrones conocidos, trampas, checklist,
    grep, incidents). Empty string if the briefing does not exist.
    Falls back to the first 4000 chars if structured extraction finds
    nothing useful (<200 chars of structured output).
    """
    rel_path = DOMAIN_BRIEFING.get(domain, "")
    if not rel_path:
        return ""
    full_path = WEB3_DIR / rel_path
    if not full_path.exists():
        return ""
    try:
        text = full_path.read_text()
    except Exception:
        return ""

    lines = text.split("\n")
    sections: dict[str, list[str]] = {
        "bugs_index": [], "trampas": [], "checklist": [], "grep": [], "incidents": [],
    }
    current = None
    in_trampa_block = False

    for line in lines:
        if line.startswith("### 1.") or line.startswith("### 2."):
            sections["bugs_index"].append(line.strip())
            current = None
        elif "Invariant Checklist" in line or "## 3." in line:
            current = "checklist"
        elif "Grep Targets" in line or "## 4." in line:
            current = "grep"
        elif "Real-World Incidents" in line or "## 2.3" in line:
            current = "incidents"
        elif line.strip() == "trampas:":
            in_trampa_block = True
        elif in_trampa_block:
            if line.strip().startswith("- ") or line.strip().startswith("  - "):
                sections["trampas"].append(line.strip())
            elif line.strip() and not line.strip().startswith(" "):
                in_trampa_block = False
        elif current in sections:
            if line.strip():
                sections[current].append(line)
            if line.startswith("## ") and current != "checklist":
                current = None

    parts: list[str] = []
    if sections["bugs_index"]:
        parts.append("## PATRONES CONOCIDOS (busca primero estos)")
        parts.extend(sections["bugs_index"])
    if sections["trampas"]:
        parts.append("\n## TRAMPAS — NO pierdas tiempo en esto")
        seen: set[str] = set()
        for t in sections["trampas"]:
            clean = t.strip().lstrip("- ").strip('"')
            if clean and clean not in seen:
                seen.add(clean)
                parts.append(f"  ⚠ {clean}")
                if len(seen) >= 12:
                    break
    if sections["checklist"]:
        parts.append("\n## CHECKLIST DE INVARIANTES")
        parts.extend(sections["checklist"][:20])
    if sections["grep"]:
        parts.append("\n## GREP TARGETS")
        parts.extend(sections["grep"][:15])
    if sections["incidents"]:
        parts.append("\n## INCIDENTES REALES (protocolos afectados)")
        parts.extend(sections["incidents"][:10])

    result = "\n".join(parts)
    if len(result) < 200:
        return text[:4000]
    return result


def load_grep_targets_only(domain: str) -> str:
    """Compact secondary-domain briefing: just the Grep Targets section."""
    rel_path = DOMAIN_BRIEFING.get(domain, "")
    if not rel_path:
        return ""
    full_path = WEB3_DIR / rel_path
    if not full_path.exists():
        return ""
    try:
        text = full_path.read_text()
    except Exception:
        return ""
    lines = text.split("\n")
    in_grep = False
    grep_lines: list[str] = []
    for line in lines:
        if "Grep Targets" in line or "Quick Grep" in line or "## 4." in line:
            in_grep = True
            continue
        if in_grep:
            if line.startswith("## ") and grep_lines:
                break
            if line.strip():
                grep_lines.append(line)
            if len(grep_lines) >= 12:
                break
    return "\n".join(grep_lines)


def load_briefings_tiered(domains: list[str]) -> str:
    """Tiered briefings: primary full, secondary grep-only, tertiary dropped.

    Rationale: more than one full briefing saturates the hunter prompt with
    irrelevant patterns and lowers invariant quality. Grep-targets-only is
    the signal/noise sweet spot for secondary domains.
    """
    if not domains:
        return ""
    parts: list[str] = []
    primary = domains[0]
    primary_text = load_briefing_single(primary)
    if primary_text:
        parts.append(f"### Briefing principal: {primary}\n{primary_text}")
    if len(domains) > 1:
        secondary = domains[1]
        grep_text = load_grep_targets_only(secondary)
        if grep_text:
            parts.append(f"\n### Grep targets adicionales ({secondary})\n{grep_text}")
    return "\n\n".join(parts)
```

- [ ] **Step 3.4: Run tests to confirm pass**

Run: `python -m pytest audit-agents/tests/phase_2a/test_briefings.py -v`
Expected: `7 passed`.

- [ ] **Step 3.5: Re-export in `run_hunt.py`**

Replace the three function bodies in `audit-agents/run_hunt.py`:
- `load_briefing_single` (around line 1010)
- `load_grep_targets_only` (around line 1106)
- `load_briefings` (around line 1137)

With thin re-exports. Keep their signatures identical.

```python
def load_briefing_single(domain: str) -> str:
    from context_enrichment import load_briefing_single as _impl
    return _impl(domain)


def load_grep_targets_only(domain: str) -> str:
    from context_enrichment import load_grep_targets_only as _impl
    return _impl(domain)


def load_briefings(domains: list) -> str:
    from context_enrichment import load_briefings_tiered as _impl
    return _impl(list(domains))
```

- [ ] **Step 3.6: Confirm legacy smoke-check still works**

Run: `cd audit-agents && python -c "from run_hunt import load_briefings; print(bool(load_briefings(['lending'])))"`
Expected: `True` (briefing exists in `knowledge/lending.md`). If `False`, check the `WEB3_DIR` resolution.

- [ ] **Step 3.7: Confirm Phase 1 still green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 3.8: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/run_hunt.py audit-agents/tests/phase_2a/test_briefings.py
git commit -m "feat(F022): migrate tiered briefings to context_enrichment"
```

---

## Task 4: Migrate F024 `generate_asset_flow_map`

**Files:**
- Modify: `audit-agents/context_enrichment.py`
- Modify: `audit-agents/run_hunt.py` (re-export)
- Test: `audit-agents/tests/phase_2a/test_asset_flow.py`

- [ ] **Step 4.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_asset_flow.py`:

```python
"""F024 — Asset flow map regex scanner."""
from __future__ import annotations

from pathlib import Path

from context_enrichment import generate_asset_flow_map


def test_empty_for_missing_file(tmp_path):
    assert generate_asset_flow_map(tmp_path / "nope.sol") == ""


def test_empty_for_contract_without_asset_ops(tmp_path):
    f = tmp_path / "nothing.sol"
    f.write_text("contract X { function f() external {} }")
    assert generate_asset_flow_map(f) == ""


def test_detects_transferFrom_as_money_in(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "Money IN" in out
    assert "transferFrom" in out


def test_detects_transfer_as_money_out(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "Money OUT" in out
    assert "transfer" in out


def test_does_not_double_count_transferFrom_as_money_out(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    # money_out section should not contain transferFrom entries
    lines = out.splitlines()
    in_money_out = False
    for line in lines:
        if line.startswith("### Money OUT"):
            in_money_out = True
            continue
        if in_money_out and line.startswith("### "):
            break
        if in_money_out:
            assert "transferFrom" not in line


def test_detects_approvals_and_balance_reads(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "Approvals" in out
    assert "approve" in out
    assert "Balance Reads" in out
    assert "balanceOf" in out


def test_includes_function_context(tmp_solidity_contract):
    out = generate_asset_flow_map(tmp_solidity_contract)
    assert "deposit()" in out or "deposit" in out
```

- [ ] **Step 4.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_asset_flow.py -v`
Expected: ImportError on `generate_asset_flow_map`.

- [ ] **Step 4.3: Port the function**

Add to `audit-agents/context_enrichment.py`:

```python
def generate_asset_flow_map(contract_path: Path) -> str:
    """Regex-based asset-flow scanner for a Solidity contract.

    Detects transfers, approvals, mints/burns, and balance reads with
    line-number + function-name context. Output is a markdown section
    ready to be injected into a hunter brief.
    """
    if not contract_path or not contract_path.exists():
        return ""
    try:
        src = contract_path.read_text()
    except Exception:
        return ""

    lines = src.split("\n")
    patterns = {
        "money_in": [
            (r'\.transferFrom\(', "transferFrom"),
            (r'\.safeTransferFrom\(', "safeTransferFrom"),
            (r'msg\.value', "msg.value"),
        ],
        "money_out": [
            (r'\.transfer\(', "transfer"),
            (r'\.safeTransfer\(', "safeTransfer"),
            (r'\.call\{value:', "call{value:}"),
        ],
        "approvals": [
            (r'\.approve\(', "approve"),
            (r'\.safeApprove\(', "safeApprove"),
            (r'\.forceApprove\(', "forceApprove"),
        ],
        "balance_reads": [
            (r'balanceOf\(', "balanceOf"),
            (r'address\(this\)\.balance', "address(this).balance"),
        ],
        "mint_burn": [
            (r'\.mint\(', "mint"),
            (r'\.burn\(', "burn"),
            (r'_mint\(', "_mint"),
            (r'_burn\(', "_burn"),
        ],
    }

    current_function = "<top-level>"
    results: dict[str, list[str]] = {k: [] for k in patterns}

    for line_num, line in enumerate(lines, start=1):
        stripped = line.strip()
        fn_match = re.match(r'\s*function\s+(\w+)\s*\(', line)
        if fn_match:
            current_function = fn_match.group(1) + "()"
        if re.match(r'\s*(receive|fallback)\s*\(', line):
            current_function = stripped.split("(")[0].strip() + "()"
            if "receive" in stripped:
                results["money_in"].append(
                    f"- L{line_num} {current_function}: accepts ETH via payable receive"
                )
        for category, pattern_list in patterns.items():
            for regex, _label in pattern_list:
                if re.search(regex, line):
                    display_line = stripped
                    if len(display_line) > 120:
                        display_line = display_line[:117] + "..."
                    results[category].append(
                        f"- L{line_num} {current_function}: {display_line}"
                    )

    # Filter transferFrom out of money_out to avoid double-counting
    results["money_out"] = [
        e for e in results["money_out"]
        if "transferFrom" not in e and "safeTransferFrom" not in e
    ]

    sections: list[str] = []
    section_map = [
        ("money_in",      "Money IN (deposits/receives)"),
        ("money_out",     "Money OUT (withdrawals/sends)"),
        ("approvals",     "Approvals (attack surface)"),
        ("mint_burn",     "Minting/Burning"),
        ("balance_reads", "Balance Reads (manipulation vectors)"),
    ]
    for key, title in section_map:
        if results[key]:
            sections.append(f"### {title}\n" + "\n".join(results[key]))
    if not sections:
        return ""
    return "## Asset Flow Map\n" + "\n\n".join(sections) + "\n"
```

- [ ] **Step 4.4: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_asset_flow.py -v`
Expected: `7 passed`.

- [ ] **Step 4.5: Re-export in `run_hunt.py`**

Replace the body of `generate_asset_flow_map` (around line 833) with:

```python
def generate_asset_flow_map(contract_path: Path) -> str:
    from context_enrichment import generate_asset_flow_map as _impl
    return _impl(contract_path)
```

- [ ] **Step 4.6: Confirm Phase 1 still green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 4.7: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/run_hunt.py audit-agents/tests/phase_2a/test_asset_flow.py
git commit -m "feat(F024): migrate asset_flow_map to context_enrichment"
```

---

## Task 5: Migrate F015 `symmetric_analyzer` wrapper

**Files:**
- Modify: `audit-agents/context_enrichment.py`
- Modify: `audit-agents/run_hunt.py` (re-export `_run_symmetric_analysis`)
- Test: `audit-agents/tests/phase_2a/test_symmetric.py`

- [ ] **Step 5.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_symmetric.py`:

```python
"""F015 — symmetric_analyzer subprocess wrapper."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from context_enrichment import run_symmetric_analysis


def test_empty_for_missing_file(tmp_path):
    assert run_symmetric_analysis(tmp_path / "nope.sol") == ""


def test_empty_when_script_missing(tmp_solidity_contract, monkeypatch, tmp_path):
    import context_enrichment
    monkeypatch.setattr(context_enrichment, "AUDIT_AGENTS_DIR", tmp_path)
    assert run_symmetric_analysis(tmp_solidity_contract) == ""


def test_success_path_returns_stdout(tmp_solidity_contract):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## Symmetry Analysis\nok\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result):
        out = run_symmetric_analysis(tmp_solidity_contract)
    assert "Symmetry Analysis" in out


def test_error_returncode_returns_empty(tmp_solidity_contract):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=1, stdout="ERROR: parse failed", stderr="boom"
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result):
        assert run_symmetric_analysis(tmp_solidity_contract) == ""


def test_caching_avoids_second_subprocess(tmp_solidity_contract):
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## cache hit test\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        run_symmetric_analysis(tmp_solidity_contract, cache_dir=None)
        run_symmetric_analysis(tmp_solidity_contract, cache_dir=None)
    # Without cache_dir, caching uses module-level dict — second call hits cache
    assert m.call_count == 1


def test_filesystem_cache_roundtrip(tmp_solidity_contract, tmp_path):
    cache = tmp_path / "cache"
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## disk cache\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        out1 = run_symmetric_analysis(tmp_solidity_contract, cache_dir=cache)
    # Second call in a fresh mock should read from disk, NOT call subprocess
    with patch("context_enrichment.subprocess.run", side_effect=AssertionError("should be cached")) as m2:
        out2 = run_symmetric_analysis(tmp_solidity_contract, cache_dir=cache)
    assert out1 == out2 == "## disk cache"
```

- [ ] **Step 5.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_symmetric.py -v`
Expected: ImportError.

- [ ] **Step 5.3: Add imports + module-level cache + implementation**

At the top of `audit-agents/context_enrichment.py`, add:

```python
import hashlib
import subprocess
import sys
```

Below `DEEP_FLATTEN_MIN_LINES`, add:

```python
AUDIT_AGENTS_DIR = Path(__file__).resolve().parent  # /home/kali/Documents/Web3/audit-agents

_symmetric_mem_cache: dict[str, str] = {}
_flatten_mem_cache: dict[str, str] = {}


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def _cached_subprocess(
    key: str,
    cache_dir: Path | None,
    mem_cache: dict[str, str],
    runner,
) -> str:
    """Shared cache plumbing for symmetric + deep_flatten wrappers.

    Lookup order: in-memory dict → filesystem (if cache_dir) → runner().
    `runner` must be a zero-arg callable returning the raw string output
    (empty string on any failure is acceptable; caller still caches it).
    """
    if key in mem_cache:
        return mem_cache[key]
    if cache_dir is not None:
        cache_dir.mkdir(parents=True, exist_ok=True)
        disk = cache_dir / f"{key}.txt"
        if disk.exists():
            value = disk.read_text()
            mem_cache[key] = value
            return value
    value = runner()
    mem_cache[key] = value
    if cache_dir is not None:
        (cache_dir / f"{key}.txt").write_text(value)
    return value
```

Add the F015 wrapper:

```python
def run_symmetric_analysis(
    contract_path: Path,
    *,
    cache_dir: Path | None = None,
) -> str:
    """Wrap `symmetric_analyzer.py` CLI. Returns trimmed stdout or "".

    Caches by sha256 of file bytes. Pass `cache_dir` to persist across
    runs; otherwise caches in-process only.
    """
    if not contract_path or not contract_path.exists():
        return ""
    script = AUDIT_AGENTS_DIR / "symmetric_analyzer.py"
    if not script.exists():
        return ""
    key = f"sym-{contract_path.stem}-{_file_sha256(contract_path)}"

    def _run() -> str:
        try:
            result = subprocess.run(
                [sys.executable, str(script), str(contract_path), "--contract", contract_path.stem],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and result.stdout.strip() and "ERROR" not in result.stdout[:20]:
                return result.stdout.strip()
        except Exception:
            pass
        return ""

    return _cached_subprocess(key, cache_dir, _symmetric_mem_cache, _run)
```

- [ ] **Step 5.4: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_symmetric.py -v`
Expected: `6 passed`.

- [ ] **Step 5.5: Re-export in `run_hunt.py`**

Replace `_run_symmetric_analysis` (around line 2153):

```python
def _run_symmetric_analysis(contract_path: Path) -> str:
    from context_enrichment import run_symmetric_analysis as _impl
    return _impl(contract_path)
```

- [ ] **Step 5.6: Confirm Phase 1 still green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 5.7: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/run_hunt.py audit-agents/tests/phase_2a/test_symmetric.py
git commit -m "feat(F015): migrate symmetric_analyzer wrapper with caching"
```

---

## Task 6: Migrate F016 `deep_flatten` wrapper

**Files:**
- Modify: `audit-agents/context_enrichment.py`
- Modify: `audit-agents/run_hunt.py` (re-export `_run_deep_flatten`)
- Test: `audit-agents/tests/phase_2a/test_deep_flatten.py`

- [ ] **Step 6.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_deep_flatten.py`:

```python
"""F016 — deep_flatten subprocess wrapper with LOC threshold."""
from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from context_enrichment import DEEP_FLATTEN_MIN_LINES, run_deep_flatten


def test_empty_for_missing_file(tmp_path):
    assert run_deep_flatten(tmp_path / "nope.sol") == ""


def test_skipped_below_threshold(tmp_path):
    f = tmp_path / "small.sol"
    f.write_text("\n".join(["// line"] * 50))  # 50 lines < 200
    with patch("context_enrichment.subprocess.run") as m:
        out = run_deep_flatten(f)
    assert out == ""
    m.assert_not_called()


def _make_large_contract(path: Path, lines: int = DEEP_FLATTEN_MIN_LINES + 10) -> Path:
    path.write_text("\n".join(["// filler"] * lines))
    return path


def test_runs_above_threshold(tmp_path):
    f = _make_large_contract(tmp_path / "big.sol")
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## Deep Flatten\nok\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        out = run_deep_flatten(f)
    assert "Deep Flatten" in out
    m.assert_called_once()


def test_error_returncode_returns_empty(tmp_path):
    f = _make_large_contract(tmp_path / "big.sol")
    fake_result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="boom")
    with patch("context_enrichment.subprocess.run", return_value=fake_result):
        assert run_deep_flatten(f) == ""


def test_caches_across_calls(tmp_path):
    f = _make_large_contract(tmp_path / "big.sol")
    fake_result = subprocess.CompletedProcess(
        args=[], returncode=0, stdout="## cache test\n", stderr=""
    )
    with patch("context_enrichment.subprocess.run", return_value=fake_result) as m:
        run_deep_flatten(f)
        run_deep_flatten(f)
    assert m.call_count == 1
```

- [ ] **Step 6.2: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_deep_flatten.py -v`
Expected: ImportError.

- [ ] **Step 6.3: Add the F016 implementation**

Append to `audit-agents/context_enrichment.py`:

```python
def _count_lines(path: Path) -> int:
    try:
        return sum(1 for _ in path.open("r"))
    except Exception:
        return 0


def run_deep_flatten(
    contract_path: Path,
    *,
    cache_dir: Path | None = None,
) -> str:
    """Wrap `deep_flatten.py --critical-only`. Skips files below threshold.

    Returns trimmed stdout or "". Caches by sha256 of file bytes.
    """
    if not contract_path or not contract_path.exists():
        return ""
    if _count_lines(contract_path) < DEEP_FLATTEN_MIN_LINES:
        return ""
    script = AUDIT_AGENTS_DIR / "deep_flatten.py"
    if not script.exists():
        return ""
    key = f"flat-{contract_path.stem}-{_file_sha256(contract_path)}"

    def _run() -> str:
        try:
            result = subprocess.run(
                [
                    sys.executable, str(script), str(contract_path),
                    "--critical-only", "--contract", contract_path.stem,
                ],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except Exception:
            pass
        return ""

    return _cached_subprocess(key, cache_dir, _flatten_mem_cache, _run)
```

- [ ] **Step 6.4: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_deep_flatten.py -v`
Expected: `5 passed`.

- [ ] **Step 6.5: Re-export in `run_hunt.py`**

Replace `_run_deep_flatten` (around line 2173):

```python
def _run_deep_flatten(contract_path: Path) -> str:
    from context_enrichment import run_deep_flatten as _impl
    return _impl(contract_path)
```

- [ ] **Step 6.6: Confirm Phase 1 still green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 6.7: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/run_hunt.py audit-agents/tests/phase_2a/test_deep_flatten.py
git commit -m "feat(F016): migrate deep_flatten wrapper with LOC threshold + caching"
```

---

## Task 7: Build `build_hunter_context` + wire into `phase_hunter_prompt`

**Files:**
- Modify: `audit-agents/context_enrichment.py` (orchestrator)
- Modify: `audit-agents/plan_generator.py:893+` (call the orchestrator)
- Modify: `audit-agents/run_benchmark.py:557+` (extend `build_hunter_brief` signature)
- Test: `audit-agents/tests/phase_2a/test_build_hunter_context.py`
- Test: `audit-agents/tests/phase_2a/test_plan_context_wired.py`

- [ ] **Step 7.1: Write the orchestrator test first**

Create `audit-agents/tests/phase_2a/test_build_hunter_context.py`:

```python
"""Orchestrator: build_hunter_context composes 5 sub-functions."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from context_enrichment import build_hunter_context


def test_all_empty_returns_empty_string(tmp_path):
    # Contract doesn't exist → every sub-function returns ""
    assert build_hunter_context(tmp_path / "nope.sol", "lending", "Vault") == ""


def test_combines_sections_with_separator(tmp_solidity_contract):
    with patch("context_enrichment.query_wiki_context", return_value="W"), \
         patch("context_enrichment.load_briefings_tiered", return_value="B"), \
         patch("context_enrichment.generate_asset_flow_map", return_value="A"), \
         patch("context_enrichment.run_symmetric_analysis", return_value="S"), \
         patch("context_enrichment.run_deep_flatten", return_value="D"):
        out = build_hunter_context(tmp_solidity_contract, "lending", "Vault")
    # 5 sections joined with "\n\n---\n\n"
    assert out.count("\n\n---\n\n") == 4
    assert "W" in out and "B" in out and "A" in out and "S" in out and "D" in out


def test_skips_empty_sections(tmp_solidity_contract):
    with patch("context_enrichment.query_wiki_context", return_value=""), \
         patch("context_enrichment.load_briefings_tiered", return_value="B"), \
         patch("context_enrichment.generate_asset_flow_map", return_value=""), \
         patch("context_enrichment.run_symmetric_analysis", return_value="S"), \
         patch("context_enrichment.run_deep_flatten", return_value=""):
        out = build_hunter_context(tmp_solidity_contract, "lending", "Vault")
    # Only "B" and "S" survive — one separator
    assert out == "B\n\n---\n\nS"


def test_section_order_is_wiki_brief_flow_sym_deep(tmp_solidity_contract):
    with patch("context_enrichment.query_wiki_context", return_value="WIKI"), \
         patch("context_enrichment.load_briefings_tiered", return_value="BRIEF"), \
         patch("context_enrichment.generate_asset_flow_map", return_value="FLOW"), \
         patch("context_enrichment.run_symmetric_analysis", return_value="SYM"), \
         patch("context_enrichment.run_deep_flatten", return_value="DEEP"):
        out = build_hunter_context(tmp_solidity_contract, "lending", "Vault")
    assert out.index("WIKI") < out.index("BRIEF") < out.index("FLOW") < out.index("SYM") < out.index("DEEP")
```

- [ ] **Step 7.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_build_hunter_context.py -v`
Expected: ImportError on `build_hunter_context`.

- [ ] **Step 7.3: Add the orchestrator**

Append to `audit-agents/context_enrichment.py`:

```python
def build_hunter_context(
    contract_path: Path,
    domain: str,
    component: str,
    *,
    domains: list[str] | None = None,
    cache_dir: Path | None = None,
) -> str:
    """Compose all 5 context signals into a single markdown block.

    Returns "" if nothing produced output. Each section failure is
    silently skipped; a hunter prompt never fails on context.
    """
    sections = [
        query_wiki_context(domain, component),                          # F019
        load_briefings_tiered(domains if domains is not None else [domain]),  # F022
        generate_asset_flow_map(contract_path),                         # F024
        run_symmetric_analysis(contract_path, cache_dir=cache_dir),     # F015
        run_deep_flatten(contract_path, cache_dir=cache_dir),           # F016
    ]
    return "\n\n---\n\n".join(s for s in sections if s and s.strip())
```

- [ ] **Step 7.4: Run orchestrator tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_build_hunter_context.py -v`
Expected: `4 passed`.

- [ ] **Step 7.5: Extend `build_hunter_brief` signature**

In `audit-agents/run_benchmark.py:557-564`, add a new keyword-only parameter after `few_shot_context`:

```python
def build_hunter_brief(component: str, protocol: str, src_file, src_dir,
                       protocol_model: str, prepass_signals_text: str,
                       setup_sol_text: str, setup_var_names: str,
                       existing_tests_summary: str, knowledge_context: str,
                       interfaces_code: str, accumulated_context: str,
                       hyp_dir,
                       rejection_context: str = "",
                       few_shot_context: str = "",
                       context_enrichment_block: str = "") -> str:
```

Then inject it right after `few_shot_context` in the return string (keeping alignment). Change the return-value concatenation in `build_hunter_brief` from:

```python
        + (f"{few_shot_context}\n\n" if few_shot_context else "")
        + f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
```

to:

```python
        + (f"{few_shot_context}\n\n" if few_shot_context else "")
        + (f"{context_enrichment_block}\n\n" if context_enrichment_block else "")
        + f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
```

- [ ] **Step 7.6: Wire the orchestrator into `phase_hunter_prompt`**

In `audit-agents/plan_generator.py:906`, right after `from run_benchmark import build_hunter_brief, build_hunter_dispatch_prompt`, add:

```python
    from context_enrichment import build_hunter_context
```

Locate the `build_hunter_brief(...)` call at `plan_generator.py:947-961`. Before that call, compute the enrichment block. Use this patch — insert between `protocol_model` retrieval (around line 944) and the `build_hunter_brief` call:

```python
    # F019 + F022 + F024 + F015 + F016 — context enrichment pipeline.
    # Each sub-signal degrades to empty string on failure; the brief
    # still assembles. Domain auto-detection: cheap keyword scan on src.
    detected_domain = _detect_primary_domain(source_code) or protocol
    context_block = build_hunter_context(
        contract_path=src_file,
        domain=detected_domain,
        component=component,
        cache_dir=Path(session_dir) / "cache" / "context_enrichment",
    )
```

Then pass `context_enrichment_block=context_block` as the last kwarg to `build_hunter_brief(...)`:

```python
    brief_content = build_hunter_brief(
        # ... existing kwargs ...
        context_enrichment_block=context_block,
    )
```

- [ ] **Step 7.7: Add `_detect_primary_domain` helper in plan_generator**

Near the top-level helpers in `audit-agents/plan_generator.py` (after `_results_dir`/`_hyp_dir` area, around line 880), add:

```python
# Minimal domain detector for hunter context enrichment.
# Keeps this file self-sufficient; a richer detector lives in
# context_enrichment.DOMAIN_BRIEFING keys — we reuse that list.
def _detect_primary_domain(source_code: str) -> str:
    """Return the first DOMAIN_BRIEFING key that appears in source, or ''."""
    from context_enrichment import DOMAIN_BRIEFING
    src_lower = (source_code or "").lower()
    for domain in DOMAIN_BRIEFING.keys():
        if domain in src_lower:
            return domain
    return ""
```

- [ ] **Step 7.8: Write the end-to-end plan wiring test**

Create `audit-agents/tests/phase_2a/test_plan_context_wired.py`:

```python
"""Contract: plan_generator.phase_hunter_prompt calls build_hunter_context."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.mark.parametrize("language,benchmark", [("solidity", "yieldoor")])
def test_phase_hunter_prompt_invokes_context_builder(language, benchmark, tmp_path):
    import sys
    REPO_ROOT = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    import plan_generator

    session = tmp_path / "session"
    session.mkdir()
    (session / "context").mkdir()

    repo = REPO_ROOT / "benchmarks" / benchmark / "repo"
    if not repo.exists():
        pytest.skip(f"benchmark repo missing: {repo}")

    with patch("plan_generator.build_hunter_context", return_value="STUBBED CTX") as m:
        steps = plan_generator.phase_hunter_prompt(
            component="Vault",
            protocol=benchmark,
            repo=str(repo),
            session_dir=str(session),
            lang=language,
        )
    assert m.called, "build_hunter_context not invoked"
    brief_path = session / "hunter_brief_Vault.md"
    assert brief_path.exists()
    assert "STUBBED CTX" in brief_path.read_text()
```

Note: this test imports `plan_generator` with `build_hunter_context` already hoisted to module scope. Update the earlier Step 7.6 patch: instead of `from context_enrichment import build_hunter_context` *inside* the function, move the import to **module level** at the top of `plan_generator.py`:

```python
from context_enrichment import build_hunter_context
```

(Place it near the other top-level imports around `plan_generator.py:10-30`.)

- [ ] **Step 7.9: Run the wiring test**

Run: `python -m pytest audit-agents/tests/phase_2a/test_plan_context_wired.py -v`
Expected: `1 passed`.

- [ ] **Step 7.10: Confirm Phase 1 still green (context block must be ignore-compatible)**

Run: `python -m pytest audit-agents/tests/phase_modern/ -v`
Expected: `19 passed`. If `test_plan_full_yieldoor` or `test_plan_single_component` fails because the brief now contains new content, that is expected — the hunter **brief** (`hunter_brief_*.md`) is written next to the session, not captured in the plan JSON. If the **plan JSON** itself changed shape, regenerate goldens with:

```bash
UPDATE_SNAPSHOTS=1 python -m pytest audit-agents/tests/phase_modern/test_plan_generator_golden.py -v
```

Then `git diff` to confirm the change is only in `steps[].prompt` (which is already ignored via `PLAN_IGNORE_KEYS`). If anything else changed, investigate before committing.

- [ ] **Step 7.11: Commit**

```bash
git add audit-agents/context_enrichment.py audit-agents/plan_generator.py audit-agents/run_benchmark.py audit-agents/tests/phase_2a/test_build_hunter_context.py audit-agents/tests/phase_2a/test_plan_context_wired.py
# Also add any regenerated goldens if Step 7.10 required it
git add audit-agents/tests/phase_modern/fixtures/ 2>/dev/null || true
git commit -m "feat: wire context_enrichment into modern hunter prompt flow"
```

---

## Task 8: F002 `--hunters <subset>` CLI flag

**Files:**
- Modify: `audit-agents/run_benchmark.py` (argparse + filter)
- Test: `audit-agents/tests/phase_2a/test_hunters_subset.py`

- [ ] **Step 8.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_hunters_subset.py`:

```python
"""F002 — --hunters subset CLI flag."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def _run(*args: str):
    return subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )


def test_help_mentions_hunters_flag():
    r = _run("--help")
    assert r.returncode == 0
    assert "--hunters" in r.stdout
    assert "subset" in r.stdout.lower()


def test_invalid_subset_exits_nonzero_with_valid_list():
    r = _run(
        "--repo", "/tmp", "--components", "X", "--protocol", "y",
        "--hunters", "BogusHunter",
    )
    assert r.returncode != 0
    assert "BogusHunter" in (r.stderr + r.stdout)
    assert "MathHunter" in (r.stderr + r.stdout)  # valid list surfaced


def test_valid_subset_accepted_by_argparse(tmp_path):
    # Use --help to avoid running the whole pipeline — we only verify argparse accepts.
    # Re-parse args by invoking a dry-run path: provide --ground-truth that triggers
    # scope-detection failure early, but AFTER argparse validation.
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _validate_hunters_subset  # unit-level function
    ok = _validate_hunters_subset("MathHunter,AccessHunter")
    assert ok == {"MathHunter", "AccessHunter"}


def test_validate_rejects_unknown():
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _validate_hunters_subset
    with pytest.raises(SystemExit):
        _validate_hunters_subset("MathHunter,NotARealHunter")
```

- [ ] **Step 8.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_hunters_subset.py -v`
Expected: ImportError on `_validate_hunters_subset` + no `--hunters` in help.

- [ ] **Step 8.3: Implement `_validate_hunters_subset` + argparse flag**

At the top of `audit-agents/run_benchmark.py` (near other helpers, before `main()`):

```python
def _validate_hunters_subset(raw: str) -> set[str]:
    """Parse --hunters value. Exits with list of valid names if any unknown.

    Examples:
        "MathHunter" → {"MathHunter"}
        "Math,Access" → exits with error (use full names like "MathHunter")
    """
    from run_hunt import HUNTER_DOMAINS
    valid = set(HUNTER_DOMAINS.keys())
    raw = (raw or "").strip()
    if not raw:
        return valid
    requested = {tok.strip() for tok in raw.split(",") if tok.strip()}
    unknown = requested - valid
    if unknown:
        sys.stderr.write(
            f"--hunters: unknown hunter(s): {sorted(unknown)}\n"
            f"Valid hunters: {sorted(valid)}\n"
        )
        sys.exit(2)
    return requested
```

In `main()` (around line 3655, right after `--skip-hunters`), add:

```python
    parser.add_argument("--hunters", default="",
                        help="Comma-separated subset of hunter names to run "
                             "(e.g., 'MathHunter,AccessHunter'). Default: all. "
                             "Unknown names exit non-zero with the valid list.")
```

Then, right after `args = parser.parse_args()`, validate:

```python
    hunters_subset = _validate_hunters_subset(args.hunters)
```

Thread `hunters_subset` through wherever `HUNTER_DOMAINS` is iterated. The minimal intrusive change: where `run_benchmark.py:1710` reads `domain_key = HUNTER_DOMAINS.get(hunter_name, ...)`, wrap the loop that generates hunter prompts to skip any `hunter_name not in hunters_subset`. Find the loop (search for `for hunter_name in HUNTER_DOMAINS` or similar) and add:

```python
        if hunters_subset and hunter_name not in hunters_subset:
            continue
```

If the loop does not exist in `run_benchmark.py`, then the filter applies at the Agent dispatch site — surface `hunters_subset` via module-level state and consume it in the dispatcher. Confirm during Step 8.4 that `--hunters MathHunter` actually restricts the dispatch.

- [ ] **Step 8.4: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_hunters_subset.py -v`
Expected: `4 passed`.

- [ ] **Step 8.5: Manual smoke check**

Run: `python audit-agents/run_benchmark.py --help | grep -A1 hunters`
Expected: shows `--hunters` entry with the subset description.

- [ ] **Step 8.6: Phase 1 regression check**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 8.7: Commit**

```bash
git add audit-agents/run_benchmark.py audit-agents/tests/phase_2a/test_hunters_subset.py
git commit -m "feat(F002): add --hunters subset CLI flag with validation"
```

---

## Task 9: F003 `--domain <name>` override CLI flag

**Files:**
- Modify: `audit-agents/run_benchmark.py`
- Modify: `audit-agents/plan_generator.py` (accept + use domain override)
- Test: `audit-agents/tests/phase_2a/test_domain_override.py`

- [ ] **Step 9.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_domain_override.py`:

```python
"""F003 — --domain override CLI flag."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"


def test_help_mentions_domain_flag():
    r = subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r.returncode == 0
    assert "--domain" in r.stdout


def test_plan_generator_respects_domain_arg(tmp_path, monkeypatch):
    """If plan_generator is called with domain='lending', the brief shows the lending briefing."""
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    import plan_generator

    session = tmp_path / "session"
    session.mkdir()
    (session / "context").mkdir()
    benchmark = "yieldoor"
    repo = REPO_ROOT / "benchmarks" / benchmark / "repo"
    if not repo.exists():
        import pytest
        pytest.skip(f"benchmark repo missing: {repo}")

    # Monkey-patch _detect_primary_domain to force auto-detect to return ""
    # so that the override from the call path is exercised.
    monkeypatch.setattr(plan_generator, "_detect_primary_domain", lambda src: "")

    # With no override, domain falls back to protocol name (not a real briefing).
    plan_generator.phase_hunter_prompt(
        component="Vault", protocol=benchmark,
        repo=str(repo), session_dir=str(session),
        lang="solidity",
    )
    # With override passed via new kwarg, the briefing should appear.
    plan_generator.phase_hunter_prompt(
        component="Vault", protocol=benchmark,
        repo=str(repo), session_dir=str(session),
        lang="solidity",
        domain_override="lending",
    )
    brief = (session / "hunter_brief_Vault.md").read_text()
    assert "lending" in brief.lower()
```

- [ ] **Step 9.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_domain_override.py -v`
Expected: fail on TypeError (unexpected kwarg `domain_override`) or missing `--domain` help.

- [ ] **Step 9.3: Extend `phase_hunter_prompt` signature**

In `audit-agents/plan_generator.py:893-896`, change:

```python
def phase_hunter_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "solidity",
) -> list[dict]:
```

to:

```python
def phase_hunter_prompt(
    component: str, protocol: str, repo: str, session_dir: str,
    lang: str = "solidity",
    *,
    domain_override: str = "",
) -> list[dict]:
```

Then in the body (Step 7.6 already placed the context-block compute), change:

```python
    detected_domain = _detect_primary_domain(source_code) or protocol
```

to:

```python
    detected_domain = domain_override or _detect_primary_domain(source_code) or protocol
```

- [ ] **Step 9.4: Add `--domain` argparse flag**

In `audit-agents/run_benchmark.py:main()`, right after the `--hunters` flag added in Task 8:

```python
    parser.add_argument("--domain", default="",
                        help="Override auto-detected domain for hunter briefings. "
                             "Valid values: any key of context_enrichment.DOMAIN_BRIEFING "
                             "(e.g., lending, vault, oracle, staking). Empty = auto-detect.")
```

Thread `args.domain` through to wherever `phase_hunter_prompt` is invoked. Grep: `rg -n "phase_hunter_prompt\(" audit-agents/` — the primary call is `plan_generator.py:2993`. If `run_benchmark.py` also calls it directly (via the plan-step executor), plumb `domain_override=args.domain` through the per-step context.

- [ ] **Step 9.5: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_domain_override.py -v`
Expected: `2 passed`.

- [ ] **Step 9.6: Phase 1 regression check**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`.

- [ ] **Step 9.7: Commit**

```bash
git add audit-agents/run_benchmark.py audit-agents/plan_generator.py audit-agents/tests/phase_2a/test_domain_override.py
git commit -m "feat(F003): add --domain override for hunter briefings"
```

---

## Task 10: F009 `--force-regen-map` + `--force-gate` CLI flags

**Files:**
- Modify: `audit-agents/run_benchmark.py` (two new flags)
- Modify: `audit-agents/pipeline_gate.py` (accept `--force <gate>`)
- Test: `audit-agents/tests/phase_2a/test_force_flags.py`

- [ ] **Step 10.1: Write the failing tests first**

Create `audit-agents/tests/phase_2a/test_force_flags.py`:

```python
"""F009 — granular --force-regen-map + --force-gate flags."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
RUN_BENCHMARK = REPO_ROOT / "audit-agents" / "run_benchmark.py"
PIPELINE_GATE = REPO_ROOT / "audit-agents" / "pipeline_gate.py"


def test_help_mentions_both_flags():
    r = subprocess.run(
        [sys.executable, str(RUN_BENCHMARK), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert "--force-regen-map" in r.stdout
    assert "--force-gate" in r.stdout


def test_force_regen_map_removes_cached_map(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    cache = session / "component_map_yieldoor.json"
    cache.write_text(json.dumps({"components": ["Vault"]}))
    assert cache.exists()

    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _apply_force_regen_map
    _apply_force_regen_map(session_dir=session, protocol="yieldoor")
    assert not cache.exists(), "--force-regen-map must delete the cached map"


def test_force_regen_map_noop_when_file_missing(tmp_path):
    session = tmp_path / "session"
    session.mkdir()
    import sys as _sys
    _sys.path.insert(0, str(REPO_ROOT / "audit-agents"))
    from run_benchmark import _apply_force_regen_map
    # Must not raise even when nothing to remove
    _apply_force_regen_map(session_dir=session, protocol="yieldoor")


def test_pipeline_gate_accepts_force_flag():
    r = subprocess.run(
        [sys.executable, str(PIPELINE_GATE), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert "--force" in r.stdout


def test_pipeline_gate_force_resets_component_gate(tmp_path):
    session = tmp_path / "session"
    for sub in ("results", "hypotheses", "gate_status", "context", "logs"):
        (session / sub).mkdir(parents=True)
    # Mark a gate, then force-reset it
    r1 = subprocess.run(
        [sys.executable, str(PIPELINE_GATE),
         "-c", "Vault", "--mark", "scope", "--session-dir", str(session)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r1.returncode == 0, r1.stderr
    r2 = subprocess.run(
        [sys.executable, str(PIPELINE_GATE),
         "-c", "Vault", "--force", "scope", "--session-dir", str(session)],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    assert r2.returncode == 0, r2.stderr
```

- [ ] **Step 10.2: Run tests to confirm they fail**

Run: `python -m pytest audit-agents/tests/phase_2a/test_force_flags.py -v`
Expected: all 5 fail (no `--force-regen-map`, no `--force-gate`, no `_apply_force_regen_map`, `pipeline_gate --force` unknown).

- [ ] **Step 10.3: Implement `_apply_force_regen_map` + CLI flag in `run_benchmark.py`**

Add helper before `main()`:

```python
def _apply_force_regen_map(*, session_dir: Path, protocol: str) -> None:
    """Delete the cached component map for `protocol` under `session_dir`.

    No-op if the file does not exist. Logs at info level.
    """
    for candidate in [
        session_dir / f"component_map_{protocol}.json",
        session_dir / "context" / f"component_map_{protocol}.json",
    ]:
        if candidate.exists():
            candidate.unlink()
            print(f"[force] removed cached component map: {candidate}", file=sys.stderr)
```

In `main()`, after the `--domain` flag from Task 9:

```python
    parser.add_argument("--force-regen-map", action="store_true",
                        help="Delete cached component_map_<protocol>.json before planning. "
                             "Forces re-detection of components from the repo.")
    parser.add_argument("--force-gate", default="",
                        help="Force a specific pipeline gate to re-run (e.g., 'scope', 'prepass', "
                             "'hunters'). Bypasses the gate's cached status. See pipeline_gate.py "
                             "for valid gate names.")
```

After argparse validation, before the main flow, add:

```python
    if args.force_regen_map:
        _apply_force_regen_map(session_dir=HUNT_SESSION_DIR, protocol=args.protocol)
    if args.force_gate:
        # Invoke pipeline_gate.py with --force to reset the named gate.
        force_cmd = [
            sys.executable, str(Path(__file__).resolve().parent / "pipeline_gate.py"),
            "-c", "__all__",  # pipeline_gate will fan out per component
            "--force", args.force_gate,
            "--session-dir", str(HUNT_SESSION_DIR),
        ]
        subprocess.run(force_cmd, check=False)
```

- [ ] **Step 10.4: Implement `--force <gate>` in `pipeline_gate.py`**

Open `audit-agents/pipeline_gate.py`. Locate its argparse setup. Add:

```python
    parser.add_argument("--force", default="",
                        help="Reset the named gate's status so it re-runs. "
                             "Accepts gate names like 'scope', 'prepass', 'hunters', 'merge'. "
                             "Can be used once per invocation.")
```

After argparse validation, before any existing status-check path, add:

```python
    if args.force:
        gate = args.force
        # Reset by deleting the gate's marker file under <session>/gate_status/<protocol>.json
        status_path = Path(args.session_dir) / "gate_status" / f"{args.protocol}.json" \
            if getattr(args, "protocol", "") else None
        if status_path and status_path.exists():
            import json as _json
            data = _json.loads(status_path.read_text())
            comp_gates = data.get("component_gates", {})
            for comp in list(comp_gates.keys()):
                comp_gates[comp].pop(gate, None)
            status_path.write_text(_json.dumps(data, indent=2))
            print(f"[force] reset gate '{gate}' for all components", file=sys.stderr)
        else:
            print(f"[force] no gate_status file to reset (session fresh)", file=sys.stderr)
        # Force is idempotent — return success if we made it here.
        sys.exit(0)
```

Note: if `pipeline_gate.py` already has an entrypoint that uses `args.protocol` differently, adapt to the existing convention. Grep `rg -n "args.protocol" audit-agents/pipeline_gate.py` to find the pattern.

- [ ] **Step 10.5: Run tests**

Run: `python -m pytest audit-agents/tests/phase_2a/test_force_flags.py -v`
Expected: `5 passed`.

- [ ] **Step 10.6: Phase 1 regression check**

Run: `python -m pytest audit-agents/tests/phase_modern/ -q`
Expected: `19 passed`. Specifically, the `pipeline_gate.py` contract tests in Phase 1 (`test_gate_status_export_structure`, `test_gate_status_missing_component_no_crash`) must still pass unchanged.

- [ ] **Step 10.7: Commit**

```bash
git add audit-agents/run_benchmark.py audit-agents/pipeline_gate.py audit-agents/tests/phase_2a/test_force_flags.py
git commit -m "feat(F009): add --force-regen-map + --force-gate granular escape hatches"
```

---

## Final verification

- [ ] **Step F1: Full phase_2a suite green**

Run: `python -m pytest audit-agents/tests/phase_2a/ -v --durations=10`
Expected: ~30+ tests passing in <30s.

- [ ] **Step F2: Full phase_modern regression suite green**

Run: `python -m pytest audit-agents/tests/phase_modern/ -v`
Expected: `19 passed` in <10s.

- [ ] **Step F3: Combined suite duration sanity**

Run: `python -m pytest audit-agents/tests/phase_2a/ audit-agents/tests/phase_modern/ --tb=no -q`
Expected: ~50 tests passing in <40s total.

- [ ] **Step F4: CLI surface smoke-check**

Run: `python audit-agents/run_benchmark.py --help 2>&1 | grep -E "\-\-(hunters|domain|force-regen-map|force-gate)"`
Expected: 4 lines, one per new flag.

- [ ] **Step F5: Manual end-to-end trace of one flag**

Run:
```bash
python audit-agents/plan_generator.py --generate \
  --repo benchmarks/yieldoor/repo \
  --components Vault \
  --protocol yieldoor \
  --session-dir /tmp/phase2a-e2e \
  --ground-truth benchmarks/yieldoor/benchmark.yaml \
  --fast
grep -c "Asset Flow Map\|Prior Knowledge\|Briefing principal\|Symmetry\|Flatten" \
  /tmp/phase2a-e2e/hunter_brief_Vault.md
```
Expected: count ≥ 1 (at least one enrichment section landed in the brief).

- [ ] **Step F6: Final commit of any leftover changes**

```bash
git status --porcelain | head -20
# If anything is straggling from test runs (pytest caches, etc.), ensure nothing unintended is staged.
```

---

## Post-plan notes for Phase 2B / 2C / 2D

- `context_enrichment.py` is now the stable import boundary. When Phase 4 deletes `run_hunt.py`, only the five re-export stubs need removal — the implementations already live in `context_enrichment`.
- If Phase 2B (Solodit + feedback) wants to add its own enrichment signal, follow the same pattern: add a function + test in `phase_2a/`-style directory, append it to `build_hunter_context`'s composition list.
- `--force-gate` currently resets all components. If Phase 2C (cross-component) needs per-component gate reset, extend `pipeline_gate.py` to accept `--force <gate> --component <name>`.
- `DEEP_FLATTEN_MIN_LINES = 200` is a hardcoded constant. Phase 5/6 polish may promote it to a CLI flag once telemetry tells us whether 200 is right.
