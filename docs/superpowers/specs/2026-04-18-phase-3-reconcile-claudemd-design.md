# Phase 3 — Reconcile `CLAUDE.md` with Fase 2A-2D reality

**Roadmap**: Phase 3 of the 8-phase optimization roadmap (`docs/superpowers/specs/2026-04-17-optimization-roadmap.md`).
**Precedent**: Phases 2A (F002/F003/F009/F019/F022/F024/F015/F016), 2B (F013/F014), 2C (F007/F008/F026), 2D (F006) completed 2026-04-18. Modern pipeline (`run_benchmark.py` + Agent Teams + `component_*` modules) is now the canonical entry point.

## Goal

Align `/home/kali/Documents/Web3/CLAUDE.md` with the current code reality after Fases 2A-2D, without reorganising sections and without explicitly deprecating `run_hunt.py` (which is Phase 4's job).

Specifically, fix three classes of staleness:

1. **Internal inconsistency** — the hunter count ping-pongs between "9" and "12 + 2 = 14" across sections.
2. **Stale pipeline table** — the Scripts table still lists `run_hunt.py --component X` as the canonical per-component invocation.
3. **Undocumented new surface** — 10 CLI flags and 4 modules added by Fases 2A-2D exist in code but have zero presence in `CLAUDE.md`.

## Scope

**In scope:** edits to `/home/kali/Documents/Web3/CLAUDE.md` only. Section headings and document ordering preserved.

**Out of scope:**
- Any edits to `run_hunt.py`, `audit-agents/*`, or any non-doc file.
- Explicit deprecation markers on `run_hunt.py` references (reserved for Phase 4).
- Reorganisation of Section 3 "Modo Autónomo" or the rest of the document.
- `~/.claude/CLAUDE.md` (user-global) — we only touch the project-local file.
- Adding full CLI usage examples — keep reference-table compact.

## Execution model

**Direct edits on `main`** — precedent from Fases 2A-2D (branch strategy is `main` direct). No subagent-driven-development for this phase: the changes are mechanical doc alignment without logic, and there are no automated tests to red-green against. Verification is done via `grep` smoke checks and human diff review.

This is option (1) from the brainstorm. Options (2) subagent-driven and (3) hybrid were considered and rejected: the 2-stage review overhead does not pay for ~15 localised doc edits with no behavioural surface.

## Changes

### Group A — Fix hunter-count inconsistency (5 edits)

Every mention of "9 hunters" where the real count is "12 paralelos + 2 secuenciales" (= 14 total) must be updated. The strings live in specific lines (relative to the post-uncommitted-deltas state of the file):

| Location | Stale text | Corrected text |
|---|---|---|
| Line 80 (Scripts table) | `Agent tool (9 hunters paralelos)` | `Agent tool (12 hunters paralelos + 2 secuenciales)` |
| Line 114 (Checklist 2.4) | `secuencial tras los 9 hunters, solo si multi-chain` | `secuencial tras los 12 hunters, solo si multi-chain` |
| Line 115 (Checklist 2.5) | `secuencial tras los 9 hunters, sin límite artificial` | `secuencial tras los 12 hunters, sin límite artificial` |
| Line 144 (Gates table — `hunters`) | `9 hyp_*.yaml con campos solidity \| Después de 9 hunters` | `12 hyp_*.yaml con campos solidity \| Después de 12 hunters` |
| Line 145 (Gates table — `crosschain`) | `Después de 9 hunters (solo multi-chain)` | `Después de 12 hunters (solo multi-chain)` |

The authoritative statement in Section 5 (lines 155 / 161) already says "**12 hunters paralelos**" and "Total: **14 hunters** (12 paralelos + 2 secuenciales)" — this is the source of truth; Group A aligns the rest.

### Group B — Fix Scripts del pipeline table row (line 78)

Replace the single stale row:

```
| `run_hunt.py --component X` | Inicio de cada componente |
```

with three rows covering the modern canonical invocations:

```
| `run_benchmark.py --components X --protocol <name> --repo <path>` | Inicio de cada componente (flujo canónico) |
| `run_benchmark.py --auto-components --protocol <name> --repo <path>` | Alternativa: auto-descubrir componentes (Fase 2C) |
| `run_benchmark.py --complete <COMPONENT> [--force]` | Cierre atómico: gate+state+feedback+cross-marker (Fase 2D) |
```

The `detection_engine.py --prepass` row (line 79) and subsequent rows are preserved verbatim — they are still accurate.

### Group C — New block "Flags de `run_benchmark.py`"

Insert **after** the Scripts table (after line 86 `sync_state.py` row) and **before** the Skills heading on line 88. Exact content:

```markdown
### Flags de `run_benchmark.py` (referencia rápida)

| Flag | Qué hace | Fase |
|---|---|---|
| `--components X,Y` | Componentes explícitos (mutex con --auto-components, --complete) | 2A |
| `--auto-components` | Auto-descubre vía component_discovery.generate_component_map | 2C |
| `--complete X [--force]` | Single-shot closer (mutex con --components, --auto-components) | 2D |
| `--state-file PATH` | Override path para current_hunt.json (testing) | 2D |
| `--hunters H1,H2` | Subset de hunters a lanzar | 2A |
| `--domain DOM` | Fuerza dominio (lending/dex/staking/bridges/zk) | 2A |
| `--force-regen-map` | Regenera component_map.json | 2A |
| `--force-gate G` | Re-ejecuta un gate cached | 2A |
| `--apply-feedback` | Invoca apply_feedback.py al final | 2B |
```

### Group D — New block "Módulos del pipeline moderno"

Insert **immediately after** Group C block (before the "Skills (invocar internamente)" heading). Exact content:

```markdown
### Módulos del pipeline moderno (audit-agents/)

| Módulo | Rol |
|---|---|
| `context_enrichment.py` | Orchestrator de briefings + wiki + asset flow map + symmetric/flatten analysis (Fase 2A). |
| `component_discovery.py` | 3 helpers puros: generate_component_map, find_cross_component_pairs, detect_transitive_chains (Fase 2C). |
| `component_closer.py` | close_component: atomic gate+state+feedback+cross trigger (Fase 2D). |
| `solodit_to_wiki.py` | Converter solodit_cards → ~/obsidian-vault/web3-audit/solodit/*.md (Fase 2B). |
```

## Verification

Smoke checks via `grep`:

```bash
# 1. No stale hunter counts
rtk grep -c "9 hunters" CLAUDE.md                    # expect 0

# 2. No stale pipeline invocation in Scripts table
rtk grep "run_hunt.py --component" CLAUDE.md         # expect no matches

# 3. Modern invocations present
rtk grep -c "run_benchmark.py" CLAUDE.md             # expect >= 4

# 4. All 4 new modules mentioned
rtk grep -c "component_closer\|component_discovery\|context_enrichment\|solodit_to_wiki" CLAUDE.md   # expect 4

# 5. All 9 new flags mentioned in the flags block (--force-gate already lived in pipeline_gate.py text; the new flags block is for run_benchmark.py flags)
rtk grep -E "^\| \`--(components|auto-components|complete|state-file|hunters|domain|force-regen-map|force-gate|apply-feedback)" CLAUDE.md   # expect 9 lines
```

Human diff review via `rtk git diff CLAUDE.md` before commit.

## Commits

Single commit capturing Group A-D plus the 96 pre-existing uncommitted lines in `CLAUDE.md` (deltas from previous unrelated documentation work — Rejection Rules §15, Monitoreo de procesos, expanded cross-component checklist, etc.). Precedent established in Fase 2A: pre-existing uncommitted deltas roll into the phase commit.

Message:
```
docs(phase_3): reconcile CLAUDE.md with Fase 2A-2D reality

- Fix 9↔12 hunter count inconsistency (5 locations)
- Replace run_hunt.py --component row in Scripts table with modern run_benchmark.py invocations
- Add Flags de run_benchmark.py reference table (9 flags from Fases 2A-2D)
- Add Módulos del pipeline moderno table (context_enrichment, component_discovery, component_closer, solodit_to_wiki)
- Absorb 96 lines of pre-existing uncommitted documentation deltas (Rejection Rules §15, monitoring guidance, cross-component expansion)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
```

## Deliverables

- Modified: `/home/kali/Documents/Web3/CLAUDE.md`
- Modified: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`? **No** — Phase 3 is documentation reconciliation, not a new feature migration. Parity matrix stays untouched.
- Memory update: `/home/kali/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md` — Phase 3 → ✅ COMPLETA, Phase 4 → 🔜 NEXT, append "Fase 3 — resumen al cerrar" section.

## Risk / Effort

- **Risk: low.** Pure documentation changes, no code surface touched. Verification is grep-based. Worst case: a copy-paste error in a table cell — caught by `rtk git diff` review.
- **Effort: S.** ~15 localised edits + verification + commit + memory update. No implementation plan needed (the "plan" would be a 1:1 mapping of the spec's Changes section). For consistency with Fases 2A-2D we still invoke writing-plans, but the plan will be concise.

## Non-goals

- Deleting or renaming any `run_hunt.py` references outside the single Scripts table row (Phase 4's job).
- Adding deprecation banners to legacy references.
- Documenting the internal architecture of `component_closer.close_component` or `component_discovery.generate_component_map` beyond the one-line roles in Group D.
- Re-ordering sections or rewriting prose for tone.
- Touching `~/.claude/CLAUDE.md` (user-global instructions).
