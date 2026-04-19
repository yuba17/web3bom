# Phase 10 Implementation Plan — Deprecate hybrid_pipeline.py

**Goal**: Delete `hybrid_pipeline.py` + `run_hybrid.sh`, clean 3 docs, add parity F055, refresh audit.

**Architecture**: Hard deletion. The file has zero Python importers and a single shell caller — no shim needed.

**Tech Stack**: git rm, markdown edits, YAML edit, python3 audit re-run.

---

### Task 1: Delete hybrid_pipeline.py + run_hybrid.sh

**Files:**
- Delete: `audit-agents/hybrid_pipeline.py`
- Delete: `audit-agents/run_hybrid.sh`

- [ ] **Step 1: Verify zero live Python callers** (defensive check)

```bash
cd /home/kali/Documents/Web3
grep -rn "from hybrid_pipeline\|import hybrid_pipeline" --include="*.py" audit-agents/
```

Expected: empty output.

- [ ] **Step 2: Delete files**

```bash
rtk git rm audit-agents/hybrid_pipeline.py audit-agents/run_hybrid.sh
```

- [ ] **Step 3: Verify full test suite still passes**

```bash
python3 -m pytest audit-agents/tests/ -q
```

Expected: `227 passed`.

- [ ] **Step 4: Commit**

```bash
rtk git commit -m "refactor(phase_10): delete hybrid_pipeline.py + run_hybrid.sh

Phase 10 deprecation. Zero Python importers, single shell caller,
untouched since initial commit. Superseded by run_benchmark.py +
Agent Teams. Content recoverable via git history.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2: Clean doc references

**Files:**
- Modify: `audit-agents/FUTURE_ARCHITECTURE.md`
- Modify: `AUDIT-REPORT-CONSOLIDATED.md`
- Modify: `WIKI.md`

- [ ] **Step 1: Update FUTURE_ARCHITECTURE.md:23**

Read context around the line, then replace `- hybrid_pipeline.py (prompt-based, semi-manual)` with a note marking it as historical (removed Phase 10).

- [ ] **Step 2: Update FUTURE_ARCHITECTURE.md:444**

Replace `Replace the current prompt-template approach in hybrid_pipeline.py` with `Replace the prompt-template approach that hybrid_pipeline.py used (removed Phase 10).`.

- [ ] **Step 3: Update AUDIT-REPORT-CONSOLIDATED.md:23**

Append ` (removed Phase 10)` to the existing line.

- [ ] **Step 4: Update WIKI.md:680**

Remove the table row: `| `hybrid_pipeline.py` | Pipeline semi-manual | ⚠️ manual |`.

- [ ] **Step 5: Verify no live references remain**

```bash
grep -rn "hybrid_pipeline\|run_hybrid" audit-agents/ docs/ WIKI.md AUDIT-REPORT-CONSOLIDATED.md 2>/dev/null | grep -v "\.md:.*Phase 10\|\.md:.*removed\|docs/superpowers/specs/2026-04-19-phase-10"
```

Expected: no output (all remaining references are historical markers).

- [ ] **Step 6: Commit**

```bash
rtk git add audit-agents/FUTURE_ARCHITECTURE.md AUDIT-REPORT-CONSOLIDATED.md WIKI.md
rtk git commit -m "docs(phase_10): update references after hybrid_pipeline.py removal

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3: Add parity matrix entry F055

**Files:**
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`

- [ ] **Step 1: Append F055 after F054**

Edit the features list: after the F054 entry (gate/cli package), add:

```yaml
  - id: F055
    name: "hybrid_pipeline.py (deprecated)"
    legacy_location: "audit-agents/hybrid_pipeline.py + audit-agents/run_hybrid.sh"
    modern_location: null
    migration_decision: deprecated
    notes: "Removed Phase 10 (2026-04-19). Prompt-based experiment never integrated: 0 Python importers, only run_hybrid.sh as caller, untouched since initial commit. Superseded by run_benchmark.py + Agent Teams. Git history preserves it."
```

- [ ] **Step 2: Update summary totals**

Change `total_features: 54` → `total_features: 55`.
Change `deprecated: 14` → `deprecated: 15`.

- [ ] **Step 3: Validate YAML arithmetic**

```bash
python3 -c "
import yaml
from pathlib import Path
data = yaml.safe_load(Path('docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml').read_text())
s = data['summary']
assert sum(s['by_decision'].values()) == s['total_features'], f\"Mismatch: total={s['total_features']}, sum={sum(s['by_decision'].values())}\"
print(f\"OK: total_features={s['total_features']}, sum(by_decision)={sum(s['by_decision'].values())}\")
"
```

Expected: `OK: total_features=55, sum(by_decision)=55`.

- [ ] **Step 4: Commit**

```bash
rtk git add docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
rtk git commit -m "docs(phase_10): add parity F055 for deprecated hybrid_pipeline.py

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4: Refresh Phase 8 audit + roadmap memory

**Files:**
- Modify: `audit-agents/audit_report.json` (regenerated)
- Modify: `docs/superpowers/specs/2026-04-19-phase-8-audit-report.md` (regenerated)
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`
- Modify: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/MEMORY.md`

- [ ] **Step 1: Re-run Phase 8 audit**

```bash
python3 audit-agents/phase_8_audit.py
```

Exit code may be 0 or 1 depending on WARN state. Check the resulting
`audit_report.json`.

- [ ] **Step 2: Verify hybrid_pipeline no longer in god-files list**

```bash
python3 -c "
import json
r = json.loads(open('audit-agents/audit_report.json').read())
sizes = next(c for c in r['checks'] if c['name'] == 'check_size_inventory')
god_files = [d['description'] for d in sizes.get('debt_items', [])]
has_hybrid = any('hybrid_pipeline' in d for d in god_files)
print('hybrid_pipeline still in god-files:', has_hybrid)
assert not has_hybrid, 'hybrid_pipeline should not appear'
print('OK')
"
```

Expected: `hybrid_pipeline still in god-files: False` + `OK`.

- [ ] **Step 3: Update roadmap memory**

Add a Fase 10 section to `project_optimization_roadmap.md` documenting:
- deletion of hybrid_pipeline.py + run_hybrid.sh
- parity F055 added
- 1 god-file WARN reduced
- tests 227 still passing

Update frontmatter `description` to reflect Fase 10 completion.

- [ ] **Step 4: Update MEMORY.md index**

Update the roadmap line to reflect Fase 10.

- [ ] **Step 5: Commit audit artifacts**

```bash
rtk git add audit-agents/audit_report.json docs/superpowers/specs/2026-04-19-phase-8-audit-report.md
rtk git commit -m "chore(phase_10): refresh Phase 8 audit artifacts post-deprecation

hybrid_pipeline.py no longer listed as god-file. Tests 227 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## Self-Review

- [x] Spec covered: all 4 tasks map to spec deliverables (delete, docs, parity, audit).
- [x] No placeholders.
- [x] Types consistent: no code types.
- [x] Ordering: delete → docs → parity → audit is safe (docs can't reference deleted file until deletion happens, audit re-run after everything).
