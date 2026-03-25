# Pipeline Dashboard Integration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add scope intake automation, finding queue for variant/cross-component findings, real-time gate visualization in dashboard, and fork-mandatory PoC gate.

**Architecture:** File-based pipeline. `pipeline_gate.py` is the single entrypoint for all gate checks and queue operations. It writes `gate_status.json` as a cache that `serve.py` reads. `scope_intake.py` generates `current_hunt.json` from repo + bounty text. All state flows through `current_hunt.json`.

**Tech Stack:** Python 3.10+ (stdlib + PyYAML), Alpine.js 3 (existing), Foundry/Forge (existing)

**Spec:** `docs/superpowers/specs/2026-03-24-pipeline-dashboard-integration-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `audit-agents/pipeline_gate.py` | MODIFY | Gate export (JSON cache), finding queue CLI, fork check in PoC gate |
| `audit-agents/scope_intake.py` | CREATE | Parse bounty text + map repo → generate `current_hunt.json` + fichas |
| `audit-agents/tests/test_pipeline_gate.py` | CREATE | Tests for new gate export + queue + fork check functionality |
| `audit-agents/tests/test_scope_intake.py` | CREATE | Tests for scope text parsing + component mapping |
| `hunt-dashboard/serve.py` | MODIFY | Read `gate_status.json` + `finding_queue`, add to API |
| `hunt-dashboard/index.html` | MODIFY | Gate circles, finding pipeline panel, queue panel |
| `hunt-dashboard/test_serve.py` | MODIFY | Test new data sources in dashboard response |
| `CLAUDE.md` | MODIFY | Document scope intake, queue rules, fork PoC requirement |

---

### Task 1: Gate Status Export in `pipeline_gate.py`

**Files:**
- Modify: `audit-agents/pipeline_gate.py:533-614` (gate dispatcher + show_status)
- Create: `audit-agents/tests/test_pipeline_gate.py`

This is the foundation — everything else depends on gate_status.json existing.

- [ ] **Step 1: Write test for `export_gate_status()`**

Create `audit-agents/tests/test_pipeline_gate.py`:

```python
"""Tests for pipeline_gate.py — gate export + queue + fork check."""
import json
import sys
import os
from pathlib import Path
from unittest.mock import patch

# Add parent dir to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

GATE_STATUS_FILE = Path(__file__).resolve().parent.parent.parent / "hunt_session" / "gate_status.json"


def test_export_gate_status_creates_json():
    """export_gate_status writes gate_status.json with correct structure."""
    # Clean up
    if GATE_STATUS_FILE.exists():
        GATE_STATUS_FILE.unlink()

    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")

    assert GATE_STATUS_FILE.exists(), "gate_status.json not created"
    data = json.loads(GATE_STATUS_FILE.read_text())
    assert "component_gates" in data
    assert "PreLiquidation" in data["component_gates"]

    comp = data["component_gates"]["PreLiquidation"]
    # Must have all 10 gates
    for gate in ["scope", "hunters", "deepdive", "merge", "compile",
                 "phase1", "phase2", "phase3", "phase4", "phase5"]:
        assert gate in comp, f"Missing gate: {gate}"
        assert "state" in comp[gate], f"Gate {gate} missing 'state'"
        assert comp[gate]["state"] in ("pass", "fail", "pending", "skip"), \
            f"Gate {gate} invalid state: {comp[gate]['state']}"
        assert "detail" in comp[gate], f"Gate {gate} missing 'detail'"

    assert "progress" in comp
    assert "blocked_at" in comp
    assert "updated_at" in comp
    assert "updated_at" in data


def test_export_is_incremental():
    """Exporting a second component merges into existing file."""
    if GATE_STATUS_FILE.exists():
        GATE_STATUS_FILE.unlink()

    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")
    export_gate_status("Bundler3", "")

    data = json.loads(GATE_STATUS_FILE.read_text())
    assert "PreLiquidation" in data["component_gates"]
    assert "Bundler3" in data["component_gates"]


def test_gate_states_are_4_state():
    """Gates use pass/fail/pending/skip — not boolean ok."""
    from pipeline_gate import export_gate_status
    export_gate_status("PreLiquidation", "")
    data = json.loads(GATE_STATUS_FILE.read_text())
    comp = data["component_gates"]["PreLiquidation"]
    states_used = {comp[g]["state"] for g in comp if isinstance(comp.get(g), dict) and "state" in comp[g]}
    # At minimum should have some pass and some fail/pending
    assert len(states_used) >= 2, f"Only states found: {states_used}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/test_pipeline_gate.py -v`
Expected: FAIL — `ImportError: cannot import name 'export_gate_status'`

- [ ] **Step 3: Implement `export_gate_status()` and `_map_gate_state()`**

Add to `audit-agents/pipeline_gate.py` after the `GATE_CHECKS` dict (~line 548):

```python
GATE_STATUS_FILE = HUNT_SESSION_DIR / "gate_status.json"

DISPLAY_GATES = [g for g in GATE_ORDER if g != "complete"]
DISPLAY_FINDING_GATES = [g for g in FINDING_GATE_ORDER if g != "reportable"]


def _map_gate_state(ok: bool, detail: str) -> str:
    """Map gate result to 4-state: pass, fail, pending, skip."""
    if ok and detail.startswith("SKIP"):
        return "skip"
    if ok:
        return "pass"
    return "fail"


def _load_gate_status() -> dict:
    """Load existing gate_status.json or return empty structure."""
    if GATE_STATUS_FILE.exists():
        try:
            return json.loads(GATE_STATUS_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return {"component_gates": {}, "finding_gates": {}, "updated_at": ""}


def _save_gate_status(data: dict):
    """Write gate_status.json atomically."""
    data["updated_at"] = datetime.now().isoformat()
    GATE_STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = GATE_STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2))
    tmp.rename(GATE_STATUS_FILE)


def export_gate_status(component: str, repo: str = ""):
    """Run all gates for a component and write results to gate_status.json."""
    status = _load_gate_status()
    comp_data = {}
    first_fail = None
    passed_count = 0

    for g in DISPLAY_GATES:
        if g not in GATE_CHECKS:
            comp_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        ok, passed, failed = GATE_CHECKS[g](component, repo)
        detail = passed[0] if passed else (failed[0] if failed else "")
        state = _map_gate_state(ok, detail)
        comp_data[g] = {"state": state, "detail": detail}
        if state in ("pass", "skip"):
            passed_count += 1
        elif first_fail is None:
            first_fail = g

    comp_data["progress"] = f"{passed_count}/{len(DISPLAY_GATES)}"
    comp_data["blocked_at"] = first_fail
    comp_data["updated_at"] = datetime.now().isoformat()

    status["component_gates"][component] = comp_data

    # Also export finding_queue_summary from current_hunt.json
    state_data = load_state()
    queue = state_data.get("finding_queue", [])
    status["finding_queue_summary"] = {
        "total": len(queue),
        "pending": sum(1 for f in queue if f.get("status") == "pending_pipeline"),
        "in_pipeline": sum(1 for f in queue if f.get("status") == "in_pipeline"),
    }

    _save_gate_status(status)


def export_finding_gate_status(finding_id: str):
    """Run all finding gates and write results to gate_status.json."""
    status = _load_gate_status()
    hyp = _find_hyp_with_finding(finding_id)

    f_data = {}
    if hyp:
        f_data["title"] = str(hyp.get("title", hyp.get("description", "")))[:60]
        f_data["severity"] = hyp.get("severity", "unknown")

    first_fail = None
    passed_count = 0

    for g in DISPLAY_FINDING_GATES:
        if g not in FINDING_GATE_CHECKS:
            f_data[g] = {"state": "pending", "detail": "Not yet reached"}
            continue
        ok, passed, failed = FINDING_GATE_CHECKS[g](finding_id)
        detail = passed[0] if passed else (failed[0] if failed else "")
        state = _map_gate_state(ok, detail)
        f_data[g] = {"state": state, "detail": detail}
        if state in ("pass", "skip"):
            passed_count += 1
        elif first_fail is None:
            first_fail = g

    f_data["progress"] = f"{passed_count}/{len(DISPLAY_FINDING_GATES)}"
    f_data["blocked_at"] = first_fail

    status["finding_gates"][finding_id] = f_data
    _save_gate_status(status)
```

- [ ] **Step 4: Wire auto-export into existing gate runners**

In `run_gate()` (~line 547), add at the end before `return`:
```python
    # Auto-export to gate_status.json
    export_gate_status(component, repo)
    return all_passed
```

In `show_status()` (~line 577), add before `return`:
```python
    # Auto-export to gate_status.json
    export_gate_status(component, repo)
    return passed_count == total
```

In `run_finding_gate()` (~line 844), add before `return`:
```python
    # Auto-export to gate_status.json
    export_finding_gate_status(finding_id)
    return all_passed
```

In `show_finding_status()` (~line 871), add before `return`:
```python
    # Auto-export to gate_status.json
    export_finding_gate_status(finding_id)
    return passed_count == total
```

Add `--export-json` to argparse in `main()`:
```python
parser.add_argument("--export-json", action="store_true", help="Run all gates and export to gate_status.json")
```

And in the component pipeline section of main, before `if args.status`:
```python
    if args.export_json:
        export_gate_status(args.component, args.repo)
        print(f"✅ Exported gate status for {args.component} to {GATE_STATUS_FILE}")
        sys.exit(0)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/kali/Documents/Web3 && python3 -m pytest audit-agents/tests/test_pipeline_gate.py -v`
Expected: 3 tests PASS

- [ ] **Step 6: Verify syntax + manual test**

Run: `python3 -c "import ast; ast.parse(open('audit-agents/pipeline_gate.py').read()); print('OK')"`
Run: `python3 audit-agents/pipeline_gate.py --component PreLiquidation --status && cat hunt_session/gate_status.json | python3 -m json.tool | head -30`
Expected: gate_status.json created with 4-state structure

- [ ] **Step 7: Commit**

```bash
git add audit-agents/pipeline_gate.py audit-agents/tests/test_pipeline_gate.py
git commit -m "feat: add gate status JSON export for dashboard integration"
```

---

### Task 2: PoC Fork Gate in `pipeline_gate.py`

**Files:**
- Modify: `audit-agents/pipeline_gate.py:664-701` (check_finding_poc)
- Modify: `audit-agents/tests/test_pipeline_gate.py`

- [ ] **Step 1: Write test for fork check in PoC gate**

Add to `audit-agents/tests/test_pipeline_gate.py`:

```python
def test_poc_gate_requires_fork():
    """PoC gate must verify vm.createFork or vm.selectFork usage."""
    from pipeline_gate import _check_poc_uses_fork

    # Mock PoC with fork
    poc_with_fork = """
    function test_exploit() public {
        uint256 forkId = vm.createFork(vm.envString("BASE_RPC_URL"), 12345);
        vm.selectFork(forkId);
        // ... exploit ...
    }
    """
    assert _check_poc_uses_fork(poc_with_fork) is True

    # Mock PoC without fork
    poc_no_fork = """
    function test_exploit() public {
        token.transfer(attacker, 1000);
        assertEq(token.balanceOf(attacker), 1000);
    }
    """
    assert _check_poc_uses_fork(poc_no_fork) is False

    # Edge case: fork in comment doesn't count
    poc_comment_fork = """
    function test_exploit() public {
        // vm.createFork would be nice but we use mocks
        token.transfer(attacker, 1000);
    }
    """
    assert _check_poc_uses_fork(poc_comment_fork) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest audit-agents/tests/test_pipeline_gate.py::test_poc_gate_requires_fork -v`
Expected: FAIL — `ImportError: cannot import name '_check_poc_uses_fork'`

- [ ] **Step 3: Implement `_check_poc_uses_fork()` and update `check_finding_poc()`**

Add helper function to `pipeline_gate.py`:

```python
def _check_poc_uses_fork(solidity_text: str) -> bool:
    """Check if Solidity test code uses mainnet fork (not just mocks)."""
    import re
    # Remove single-line comments
    no_comments = re.sub(r'//.*$', '', solidity_text, flags=re.MULTILINE)
    # Remove multi-line comments
    no_comments = re.sub(r'/\*.*?\*/', '', no_comments, flags=re.DOTALL)
    # Check for fork-related calls
    fork_patterns = [
        r'vm\.createFork',
        r'vm\.selectFork',
        r'vm\.createSelectFork',
        r'vm\.activeFork',
    ]
    for pattern in fork_patterns:
        if re.search(pattern, no_comments):
            return True
    return False
```

In `check_finding_poc()`, after the existing PoC file detection logic, add:

```python
    # Check that PoC uses fork (not just mocks)
    state = load_state()
    is_pre_launch = state.get("pre_launch", False)

    if not is_pre_launch:
        fork_found = False
        for f in poc_files:
            text = f.read_text()
            if _check_poc_uses_fork(text):
                fork_found = True
                passed.append(f"OK: PoC uses mainnet fork — {f.name}")
                break
        if not fork_found and poc_files:
            failed.append(
                "NO_FORK_IN_POC: PoC exists but does not use vm.createFork/vm.selectFork\n"
                "  PoCs must run against mainnet fork, not mocks (CLAUDE.md rule)\n"
                "  Add: uint256 forkId = vm.createFork(vm.envString(\"RPC_URL\"), blockNumber);"
            )
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest audit-agents/tests/test_pipeline_gate.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add audit-agents/pipeline_gate.py audit-agents/tests/test_pipeline_gate.py
git commit -m "feat: PoC gate now requires vm.createFork — rejects mock-only PoCs"
```

---

### Task 3: Finding Queue CLI in `pipeline_gate.py`

**Files:**
- Modify: `audit-agents/pipeline_gate.py:960-1100` (main + new queue functions)
- Modify: `audit-agents/tests/test_pipeline_gate.py`

- [ ] **Step 1: Write tests for queue operations**

Add to `audit-agents/tests/test_pipeline_gate.py`:

```python
import tempfile
import shutil


def test_queue_finding_generates_id():
    """--queue-finding auto-generates variant ID from parent."""
    from pipeline_gate import generate_queue_id, load_state

    # Variant: PL-M-01 → PL-M-01-V1
    assert generate_queue_id("variant", "PL-M-01") == "PL-M-01-V1"

    # Cross-component: alphabetical order
    xc_id = generate_queue_id("cross-component", None, ["Vault", "Gauge"])
    assert xc_id == "XC-Gauge-Vault-01"

    # Spillover
    sp_id = generate_queue_id("hunter_spillover", None, component="Factory", hunter="MathHunter")
    assert sp_id == "MATH-Factory-01"


def test_queue_finding_adds_to_state(tmp_path, monkeypatch):
    """queue_finding() adds entry to current_hunt.json finding_queue."""
    import pipeline_gate
    # Use temp state file to avoid polluting real state
    fake_state = tmp_path / "current_hunt.json"
    fake_state.write_text('{"protocol":"test","findings":[]}')
    monkeypatch.setattr(pipeline_gate, "STATE_FILE", fake_state)

    entry = pipeline_gate.queue_finding(
        source="variant",
        parent_id="TEST-01",
        title="Test variant finding",
        component="TestContract",
        severity="medium",
        notes="test note"
    )
    assert entry["id"] == "TEST-01-V1"
    assert entry["status"] == "pending_pipeline"

    state = pipeline_gate.load_state()
    queue = state.get("finding_queue", [])
    match = [f for f in queue if f["id"] == "TEST-01-V1"]
    assert len(match) == 1


def test_queue_promote_moves_to_findings(tmp_path, monkeypatch):
    """queue_promote() moves item from finding_queue to findings."""
    import pipeline_gate
    fake_state = tmp_path / "current_hunt.json"
    fake_state.write_text('{"protocol":"test","findings":[]}')
    monkeypatch.setattr(pipeline_gate, "STATE_FILE", fake_state)

    pipeline_gate.queue_finding(source="variant", parent_id="PROMO-01",
                  title="Promotable", component="X", severity="high")

    # Must be "completed" before promoting
    pipeline_gate.queue_update("PROMO-01-V1", "completed")
    pipeline_gate.queue_promote("PROMO-01-V1")

    state = pipeline_gate.load_state()
    queue_ids = [f["id"] for f in state.get("finding_queue", [])]
    finding_ids = [f["id"] for f in state.get("findings", [])]
    assert "PROMO-01-V1" not in queue_ids
    assert "PROMO-01-V1" in finding_ids
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest audit-agents/tests/test_pipeline_gate.py::test_queue_finding_generates_id -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement queue functions**

Add to `pipeline_gate.py` before `main()`:

```python
def _save_state(state: dict):
    """Write current_hunt.json."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    tmp.rename(STATE_FILE)


def generate_queue_id(source: str, parent_id: str = None,
                      components: list = None, component: str = "",
                      hunter: str = "") -> str:
    """Generate auto-incremented ID for finding queue entry."""
    state = load_state()
    existing_ids = {f.get("id", "") for f in state.get("finding_queue", [])}
    existing_ids |= {f.get("id", "") for f in state.get("findings", [])}

    if source == "variant" and parent_id:
        n = 1
        while f"{parent_id}-V{n}" in existing_ids:
            n += 1
        return f"{parent_id}-V{n}"

    elif source == "cross-component" and components:
        sorted_comps = sorted(components)
        prefix = f"XC-{'-'.join(sorted_comps)}"
        n = 1
        while f"{prefix}-{n:02d}" in existing_ids:
            n += 1
        return f"{prefix}-{n:02d}"

    elif source == "hunter_spillover":
        hunter_prefix = hunter.replace("Hunter", "").upper()[:4]
        prefix = f"{hunter_prefix}-{component}"
        n = 1
        while f"{prefix}-{n:02d}" in existing_ids:
            n += 1
        return f"{prefix}-{n:02d}"

    # Fallback
    n = 1
    while f"Q-{n:03d}" in existing_ids:
        n += 1
    return f"Q-{n:03d}"


def queue_finding(source: str, parent_id: str = None, title: str = "",
                  component: str = "", severity: str = "", notes: str = "",
                  components: list = None, hunter: str = "") -> dict:
    """Add a finding to the queue in current_hunt.json. Returns the entry."""
    state = load_state()
    if "finding_queue" not in state:
        state["finding_queue"] = []

    fid = generate_queue_id(source, parent_id, components, component, hunter)

    entry = {
        "id": fid,
        "title": title,
        "source": source,
        "component": component,
        "severity_estimate": severity,
        "status": "pending_pipeline",
        "added_at": datetime.now().isoformat(),
        "notes": notes,
    }
    if parent_id:
        entry["parent_finding"] = parent_id
    if components:
        entry["components"] = sorted(components)
    if hunter:
        entry["discovered_by"] = hunter

    state["finding_queue"].append(entry)
    _save_state(state)
    print(f"✅ Queued finding {fid}: {title}")
    return entry


def list_queue():
    """Print finding queue as table."""
    state = load_state()
    queue = state.get("finding_queue", [])
    if not queue:
        print("Finding queue is empty.")
        return

    print(f"\n{'ID':<20} {'Status':<18} {'Component':<20} {'Sev':<8} {'Title'}")
    print(f"{'-'*20} {'-'*18} {'-'*20} {'-'*8} {'-'*40}")
    for f in queue:
        print(f"{f.get('id',''):<20} {f.get('status',''):<18} {f.get('component',''):<20} "
              f"{f.get('severity_estimate',''):<8} {f.get('title','')[:40]}")
    print(f"\nTotal: {len(queue)} | "
          f"Pending: {sum(1 for f in queue if f.get('status')=='pending_pipeline')} | "
          f"In pipeline: {sum(1 for f in queue if f.get('status')=='in_pipeline')}")


def queue_update(finding_id: str, new_status: str, notes: str = ""):
    """Update a queue item's status."""
    state = load_state()
    queue = state.get("finding_queue", [])
    for item in queue:
        if item.get("id") == finding_id:
            item["status"] = new_status
            if notes:
                if new_status == "dismissed":
                    item["dismissed_reason"] = notes
                else:
                    item["notes"] = notes
            _save_state(state)
            print(f"✅ Updated {finding_id} → {new_status}")
            return
    print(f"⛔ {finding_id} not found in queue")


def queue_promote(finding_id: str):
    """Move a completed queue item to the findings array."""
    state = load_state()
    queue = state.get("finding_queue", [])
    if "findings" not in state:
        state["findings"] = []

    item = None
    for i, f in enumerate(queue):
        if f.get("id") == finding_id:
            if f.get("status") != "completed":
                print(f"⛔ {finding_id} status is '{f.get('status')}' — must be 'completed' before promoting")
                return
            f["status"] = "moved_to_findings"
            item = queue.pop(i)
            break

    if not item:
        print(f"⛔ {finding_id} not found in queue")
        return

    state["findings"].append({
        "id": item["id"],
        "title": item["title"],
        "severity": item.get("severity_estimate", ""),
        "component": item.get("component", ""),
        "status": "CONFIRMED",
        "source": item.get("source", ""),
        "parent_finding": item.get("parent_finding", ""),
    })
    _save_state(state)
    print(f"✅ Promoted {finding_id} from queue to findings")
```

- [ ] **Step 4: Wire CLI args in `main()`**

Add to argparse in `main()`:

```python
    # Queue operations
    parser.add_argument("--queue-finding", action="store_true", help="Add finding to queue")
    parser.add_argument("--list-queue", action="store_true", help="List finding queue")
    parser.add_argument("--queue-update", help="Update queue item (provide finding ID)")
    parser.add_argument("--queue-promote", help="Promote queue item to findings")
    parser.add_argument("--source", help="Finding source (variant|cross-component|hunter_spillover)")
    parser.add_argument("--parent", help="Parent finding ID for variants")
    parser.add_argument("--title", help="Finding title")
    parser.add_argument("--severity", help="Severity estimate")
    parser.add_argument("--notes", help="Additional notes")
    parser.add_argument("--qstatus", help="New status for queue-update")
    parser.add_argument("--components", help="Components for cross-component (comma-separated)")
    parser.add_argument("--hunter", help="Hunter name for spillover")
```

Add handling before `# ── Finding pipeline ──`:

```python
    # ── Queue operations ──
    if args.list_queue:
        list_queue()
        sys.exit(0)

    if args.queue_finding:
        comps = args.components.split(",") if args.components else None
        queue_finding(
            source=args.source or "variant",
            parent_id=args.parent,
            title=args.title or "",
            component=args.component or "",
            severity=args.severity or "",
            notes=args.notes or "",
            components=comps,
            hunter=args.hunter or "",
        )
        sys.exit(0)

    if args.queue_update:
        queue_update(args.queue_update, args.qstatus or "in_pipeline", args.notes or "")
        sys.exit(0)

    if args.queue_promote:
        queue_promote(args.queue_promote)
        sys.exit(0)
```

- [ ] **Step 5: Run tests**

Run: `python3 -m pytest audit-agents/tests/test_pipeline_gate.py -v`
Expected: All tests PASS

- [ ] **Step 6: Manual CLI test**

```bash
python3 audit-agents/pipeline_gate.py --queue-finding --source variant --parent PL-M-01 --title "Test variant" --component PreLiquidationFactory --severity low
python3 audit-agents/pipeline_gate.py --list-queue
python3 audit-agents/pipeline_gate.py --queue-update PL-M-01-V1 --qstatus in_pipeline
python3 audit-agents/pipeline_gate.py --list-queue
```
Expected: Entry created, listed, updated correctly

- [ ] **Step 7: Commit**

```bash
git add audit-agents/pipeline_gate.py audit-agents/tests/test_pipeline_gate.py
git commit -m "feat: add finding queue CLI — queue, list, update, promote"
```

---

### Task 4: Scope Intake Script

**Files:**
- Create: `audit-agents/scope_intake.py`
- Create: `audit-agents/tests/test_scope_intake.py`

- [ ] **Step 1: Write test for bounty text parser**

Create `audit-agents/tests/test_scope_intake.py`:

```python
"""Tests for scope_intake.py — bounty text parsing."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_parse_payouts():
    """Extract payout amounts from bounty text."""
    from scope_intake import parse_bounty_text

    text = """
    Critical: $250K - $2.5M
    High: $10K - $50K
    Medium: $3K-$10K
    Low: $1K-$3K
    """
    result = parse_bounty_text(text)
    assert result["payout"] != ""
    assert "$250K" in result["payout"] or "250" in result["payout"]


def test_parse_exclusions():
    """Extract exclusion rules."""
    from scope_intake import parse_bounty_text

    text = """
    Out of Scope:
    - Issues resulting solely from deployer parameter choices
    - Design choices of the protocols
    - Known issues from previous audits
    """
    result = parse_bounty_text(text)
    assert len(result["exclusions"]) >= 2


def test_parse_commits():
    """Extract commit hashes."""
    from scope_intake import parse_bounty_text

    text = "The audit covers commit 55d2d99 on branch main. Also check 7d638ad."
    result = parse_bounty_text(text)
    assert "55d2d99" in result["commits"]


def test_parse_empty_text():
    """Empty text returns empty fields, no crash."""
    from scope_intake import parse_bounty_text

    result = parse_bounty_text("")
    assert result["payout"] == ""
    assert result["exclusions"] == []
    assert result["commits"] == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest audit-agents/tests/test_scope_intake.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scope_intake'`

- [ ] **Step 3: Implement `scope_intake.py`**

Create `audit-agents/scope_intake.py`:

```python
#!/usr/bin/env python3
"""
scope_intake.py — Generate hunt state from repo + bounty text.

Usage:
    python3 scope_intake.py --repo /path/to/repo --platform cantina --scope-text "..."
    python3 scope_intake.py --repo /path/to/repo --platform cantina --scope-file rules.txt
    python3 scope_intake.py --repo /path/to/repo --platform cantina --scope-file rules.txt --dry-run
"""
import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

import yaml

WEB3_DIR = Path(__file__).resolve().parent.parent
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
STATE_FILE = Path.home() / ".claude" / "MEMORY" / "STATE" / "current_hunt.json"

# Import component mapper from run_hunt.py
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_hunt import generate_component_map


# ─── Bounty Text Parser ───────────────────────────────────────────────────

def parse_bounty_text(text: str) -> dict:
    """Parse bounty rules text and extract structured fields."""
    result = {
        "payout": "",
        "exclusions": [],
        "commits": [],
        "contracts_mentioned": [],
        "prior_audits": "",
        "attack_surfaces": [],
        "raw_scope_text": text,
    }

    if not text.strip():
        return result

    # ── Payouts ──
    payout_lines = []
    for line in text.split("\n"):
        if re.search(r'\$\s*[\d,.]+\s*[KkMm]?', line):
            payout_lines.append(line.strip())
    if payout_lines:
        result["payout"] = " | ".join(payout_lines[:6])

    # ── Exclusions ──
    exclusion_zone = False
    for line in text.split("\n"):
        lower = line.lower().strip()
        if any(kw in lower for kw in ["out of scope", "not eligible", "exclusion",
                                       "not in scope", "will not be", "are excluded"]):
            exclusion_zone = True
            continue
        if exclusion_zone:
            stripped = line.strip().lstrip("-•*").strip()
            if stripped and len(stripped) > 10:
                result["exclusions"].append(stripped)
            if not stripped and result["exclusions"]:
                exclusion_zone = False

    # ── Commits ──
    commits = re.findall(r'\b([0-9a-f]{7,40})\b', text)
    # Filter out likely non-commit hex (too many digits, addresses)
    result["commits"] = [c for c in commits if len(c) <= 40 and not c.startswith("0x")][:10]

    # ── Contract names ──
    sol_files = re.findall(r'(\w+\.sol)\b', text)
    result["contracts_mentioned"] = list(set(sol_files))

    # ── Prior audits ──
    audit_patterns = [
        r'(?:audited|reviewed|contest|audit)\s+(?:by|from|with)\s+(\w[\w\s,]+)',
        r'(trail of bits|openzeppelin|cyfrin|spearbit|cantina|code4rena|sherlock)',
    ]
    audits = []
    for pat in audit_patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            audits.append(m.group(0).strip())
    if audits:
        result["prior_audits"] = "; ".join(set(audits))

    # ── Attack surfaces ──
    surface_keywords = ["flash loan", "oracle", "reentrancy", "cross-chain",
                        "liquidation", "migration", "permit", "multicall",
                        "delegation", "proxy", "upgrade", "bridge"]
    for kw in surface_keywords:
        if kw.lower() in text.lower():
            result["attack_surfaces"].append(kw)

    return result


# ─── State Generator ──────────────────────────────────────────────────────

def generate_hunt_state(repo_path: str, platform: str, parsed: dict) -> dict:
    """Generate current_hunt.json from parsed bounty text + repo."""
    protocol = Path(repo_path).name

    # Build minimal state for generate_component_map
    temp_state = {
        "protocol": protocol,
        "repo_path": str(Path(repo_path).resolve()),
    }
    component_map = generate_component_map(temp_state)

    # Mark mentioned contracts as direct scope
    mentioned = {c.replace(".sol", "") for c in parsed.get("contracts_mentioned", [])}
    for comp in component_map:
        if comp["name"] in mentioned or f"{comp['name']}.sol" in mentioned:
            comp["scope"] = "direct"
        elif not mentioned:
            comp["scope"] = "direct"  # If no specific contracts mentioned, all are direct
        else:
            comp["scope"] = "indirect"

    # Sort by LOC descending
    component_map.sort(key=lambda c: c.get("loc", 0), reverse=True)
    for i, comp in enumerate(component_map):
        comp["priority"] = i + 1

    all_names = [c["name"] for c in component_map]

    state = {
        "protocol": protocol,
        "repo_path": str(Path(repo_path).resolve()),
        "platform": platform,
        "payout": parsed.get("payout", ""),
        "status": "active",
        "current_component": all_names[0] if all_names else None,
        "components_done": [],
        "components_remaining": all_names,
        "component_map": component_map,
        "findings": [],
        "finding_queue": [],
        "scope_notes": {
            "prior_audits": parsed.get("prior_audits", ""),
            "exclusions": parsed.get("exclusions", []),
            "key_attack_surfaces": parsed.get("attack_surfaces", []),
            "commits": parsed.get("commits", []),
            "raw_scope_text": parsed.get("raw_scope_text", ""),
        },
        "last_session": datetime.now().isoformat(),
    }
    return state


def generate_fichas(state: dict):
    """Generate empty ficha YAMLs for each component."""
    protocol = state["protocol"]
    fichas_dir = HUNT_SESSION_DIR / "fichas" / protocol
    fichas_dir.mkdir(parents=True, exist_ok=True)

    template = {
        "protocol": protocol,
        "status": "pending",
        "hunters_completed": {
            "AccessHunter": False, "DomainHunter": False, "FlowHunter": False,
            "MathHunter": False, "OracleHunter": False, "TrustBoundaryHunter": False,
            "WildcardHunter": False, "SignatureHunter": False, "DoSHunter": False,
        },
        "checklist": {
            "full_code_read": False, "protocol_model": False,
            "ai_invariants_generated": False, "invariants_added_to_properties": False,
            "handlers_added": False, "boundary_values": False,
            "optimization_functions": False, "compile_check": False,
            "foundry_fuzz": False, "findings_logged": False,
            "tier1_separated": False, "tolerance_tuned": False,
        },
        "confirmed_findings": [],
        "dismissed_findings": [],
        "false_positives": [],
        "notes": "",
        "feedback_applied": None,
    }

    for comp in state.get("component_map", []):
        ficha_path = fichas_dir / f"{comp['name']}.yaml"
        if ficha_path.exists():
            continue
        ficha = {**template}
        ficha["component"] = comp["name"]
        ficha["file"] = comp.get("file", comp.get("files", [""])[0] if comp.get("files") else "")
        ficha["domain"] = "unknown"
        with open(ficha_path, "w") as f:
            yaml.dump(ficha, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

    print(f"  Generated {len(state.get('component_map', []))} fichas in {fichas_dir}")


# ─── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Scope intake — generate hunt state from repo + bounty text")
    parser.add_argument("--repo", "-r", required=True, help="Path to cloned repo")
    parser.add_argument("--platform", "-p", required=True, help="Bounty platform (cantina|immunefi|c4|sherlock)")
    parser.add_argument("--scope-text", "-t", help="Bounty rules as text string")
    parser.add_argument("--scope-file", "-f", help="Path to file with bounty rules")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing files")
    parser.add_argument("--force", action="store_true", help="Overwrite existing current_hunt.json")
    args = parser.parse_args()

    # Validate repo
    repo_path = Path(args.repo).resolve()
    if not repo_path.is_dir():
        print(f"⛔ Repository not found: {repo_path}")
        sys.exit(1)

    # Load scope text
    scope_text = ""
    if args.scope_text:
        scope_text = args.scope_text
    elif args.scope_file:
        scope_file = Path(args.scope_file)
        if not scope_file.exists():
            print(f"⛔ Scope file not found: {scope_file}")
            sys.exit(1)
        scope_text = scope_file.read_text()
    else:
        print("WARNING: No scope text provided. Component mapping only.")

    # Check existing state
    if STATE_FILE.exists() and not args.force and not args.dry_run:
        print(f"⛔ {STATE_FILE} already exists. Use --force to overwrite.")
        sys.exit(1)

    # Parse
    parsed = parse_bounty_text(scope_text)

    # Warnings for missing fields
    if not parsed["payout"]:
        print("WARNING: Could not extract payout amounts from scope text")
    if not parsed["exclusions"]:
        print("WARNING: Could not extract exclusion rules from scope text")

    # Generate state
    state = generate_hunt_state(str(repo_path), args.platform, parsed)

    # Summary
    n_comps = len(state["component_map"])
    first = state["current_component"] or "N/A"
    first_loc = next((c["loc"] for c in state["component_map"] if c["name"] == first), 0)
    n_excl = len(parsed["exclusions"])

    print(f"\n{'='*60}")
    print(f"  SCOPE INTAKE SUMMARY")
    print(f"{'='*60}")
    print(f"  Protocol:    {state['protocol']}")
    print(f"  Platform:    {state['platform']}")
    print(f"  Repo:        {state['repo_path']}")
    print(f"  Components:  {n_comps} mapped")
    print(f"  Starting:    {first} ({first_loc} LOC)")
    print(f"  Payouts:     {parsed['payout'] or 'NOT DETECTED'}")
    print(f"  Exclusions:  {n_excl}")
    print(f"  Commits:     {parsed['commits'] or 'none detected'}")
    if parsed["attack_surfaces"]:
        print(f"  Surfaces:    {', '.join(parsed['attack_surfaces'])}")
    print()

    # Component table
    print(f"  {'#':<4} {'Component':<30} {'LOC':<8} {'Scope'}")
    print(f"  {'-'*4} {'-'*30} {'-'*8} {'-'*10}")
    for comp in state["component_map"][:15]:
        print(f"  {comp['priority']:<4} {comp['name']:<30} {comp.get('loc',0):<8} {comp.get('scope','')}")
    if n_comps > 15:
        print(f"  ... and {n_comps - 15} more")

    if args.dry_run:
        print(f"\n  DRY RUN — no files written")
        return

    # Write state
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2))
    print(f"\n  ✅ Written: {STATE_FILE}")

    # Generate fichas
    generate_fichas(state)

    # Auto-run run_hunt.py and pipeline_gate scope check for first component
    import subprocess
    print(f"\n  Running run_hunt.py --component {first} ...")
    ret = subprocess.run(
        ["python3", str(WEB3_DIR / "audit-agents" / "run_hunt.py"), "--component", first],
        cwd=str(WEB3_DIR),
    )
    if ret.returncode != 0:
        print(f"  WARNING: run_hunt.py exited with code {ret.returncode}")

    print(f"\n  Running pipeline_gate.py --gate scope ...")
    ret2 = subprocess.run(
        ["python3", str(WEB3_DIR / "audit-agents" / "pipeline_gate.py"),
         "-c", first, "--gate", "scope"],
        cwd=str(WEB3_DIR),
    )
    if ret2.returncode != 0:
        print(f"  WARNING: scope gate failed — fix before launching hunters")

    print(f"\n  Dashboard: python3 hunt-dashboard/serve.py")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest audit-agents/tests/test_scope_intake.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Integration test with real repo**

```bash
python3 audit-agents/scope_intake.py --repo /home/kali/Documents/Web3/morpho-pre-liquidation --platform cantina --scope-text "Critical: \$250K-\$2.5M. High: \$10K-\$50K. Out of Scope: Issues resulting solely from deployer parameter choices. Design choices." --dry-run
```
Expected: Summary printed with components sorted by LOC, payouts extracted, exclusions listed

- [ ] **Step 6: Commit**

```bash
git add audit-agents/scope_intake.py audit-agents/tests/test_scope_intake.py
git commit -m "feat: add scope_intake.py — auto-generate hunt state from repo + bounty text"
```

---

### Task 5: Dashboard Backend — `serve.py` Changes

**Files:**
- Modify: `hunt-dashboard/serve.py:302-351` (build_dashboard)
- Modify: `hunt-dashboard/test_serve.py`

- [ ] **Step 1: Write test for new data in dashboard response**

Add to `hunt-dashboard/test_serve.py`:

```python
def test_dashboard_includes_gates():
    """Dashboard response should include gates from gate_status.json."""
    data = build_dashboard(str(DEFAULT_STATE), str(DEFAULT_HUNT_DIR))
    # gates key should exist (may be empty if no gate_status.json)
    assert "gates" in data


def test_dashboard_includes_finding_queue():
    """Dashboard response should include finding_queue from state."""
    data = build_dashboard(str(DEFAULT_STATE), str(DEFAULT_HUNT_DIR))
    assert "finding_queue" in data
    assert isinstance(data["finding_queue"], list)
```

- [ ] **Step 2: Implement changes in `serve.py`**

Add function to load gate status:

```python
def load_gate_status(hunt_dir: str) -> dict:
    """Load gate_status.json. Returns {} if missing."""
    p = Path(hunt_dir) / "gate_status.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except (json.JSONDecodeError, Exception):
        return {}
```

In `build_dashboard()`, add after the `activity_log` line:

```python
    gate_status = load_gate_status(hunt_dir)
    finding_queue = state.get("finding_queue", [])
```

Add to the return dict:

```python
        "gates": gate_status,
        "finding_queue": finding_queue,
```

- [ ] **Step 3: Run tests**

Run: `cd /home/kali/Documents/Web3/hunt-dashboard && python3 -m pytest test_serve.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add hunt-dashboard/serve.py hunt-dashboard/test_serve.py
git commit -m "feat: dashboard serves gate status + finding queue data"
```

---

### Task 6: Dashboard Frontend — `index.html` Changes

**Files:**
- Modify: `hunt-dashboard/index.html:393-407` (replace fuzzPhases), `index.html:477-483` (after findings), `index.html:599-608` (remove fuzzPhases function)

- [ ] **Step 1: Replace fuzzPhases template with gate circles**

Replace lines 393-407 (the fuzz-pipeline div) with:

```html
                  <!-- 4d: Pipeline Gates (replaces fuzzPhases) -->
                  <div class="section-title">Pipeline de Gates</div>
                  <div class="gate-bar" x-show="data.gates && data.gates.component_gates && data.gates.component_gates[expanded]">
                    <template x-for="gname in ['scope','hunters','deepdive','merge','compile','phase1','phase2','phase3','phase4','phase5']" :key="gname">
                      <div class="gate-circle-wrap" :title="(data.gates.component_gates[expanded][gname] || {}).detail || 'N/A'">
                        <div class="gate-circle"
                          :class="{
                            'gc-pass': (data.gates.component_gates[expanded][gname] || {}).state === 'pass',
                            'gc-skip': (data.gates.component_gates[expanded][gname] || {}).state === 'skip',
                            'gc-fail': (data.gates.component_gates[expanded][gname] || {}).state === 'fail',
                            'gc-pending': !(data.gates.component_gates[expanded][gname]) || (data.gates.component_gates[expanded][gname] || {}).state === 'pending'
                          }"></div>
                        <div class="gate-label" x-text="gname.replace('phase','P').replace('scope','S').replace('hunters','H').replace('deepdive','D').replace('merge','M').replace('compile','C')"></div>
                      </div>
                    </template>
                    <span class="gate-progress" x-text="(data.gates.component_gates[expanded] || {}).progress || ''"></span>
                    <span class="gate-blocked" x-show="(data.gates.component_gates[expanded] || {}).blocked_at" x-text="'⛔ ' + ((data.gates.component_gates[expanded] || {}).blocked_at || '')"></span>
                  </div>
                  <div x-show="!data.gates || !data.gates.component_gates || !data.gates.component_gates[expanded]" class="no-ficha">
                    Sin datos de gates. Ejecutar: pipeline_gate.py --component X --status
                  </div>
```

- [ ] **Step 2: Add Finding Pipeline panel after findings table**

After line 477 (closing `</div>` of findings-section), add:

```html
      <!-- ═══ Section 7: Finding Pipeline Gates ═══ -->
      <template x-if="data.gates && data.gates.finding_gates && Object.keys(data.gates.finding_gates).length > 0">
        <div class="findings-section" style="margin-top:16px;">
          <div class="section-title" style="font-size:1rem;">Pipeline de Findings</div>
          <template x-for="(fdata, fid) in data.gates.finding_gates" :key="fid">
            <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--border);">
              <span style="min-width:100px;font-weight:600;" x-text="fid"></span>
              <span class="sev-badge" :class="sevClass(fdata.severity)" x-text="fdata.severity" style="font-size:0.65rem;"></span>
              <template x-for="gname in ['poc','escalation','variant','redteam','verify','report','submit']" :key="gname">
                <div class="gate-circle-wrap" :title="(fdata[gname] || {}).detail || 'N/A'" style="margin:0 1px;">
                  <div class="gate-circle gate-sm"
                    :class="{
                      'gc-pass': (fdata[gname] || {}).state === 'pass',
                      'gc-skip': (fdata[gname] || {}).state === 'skip',
                      'gc-fail': (fdata[gname] || {}).state === 'fail',
                      'gc-pending': !(fdata[gname]) || (fdata[gname] || {}).state === 'pending'
                    }"></div>
                  <div class="gate-label" x-text="gname[0].toUpperCase()"></div>
                </div>
              </template>
              <span style="font-size:0.7rem;color:var(--dim);" x-text="fdata.progress"></span>
              <span style="font-size:0.7rem;" x-show="fdata.blocked_at" x-text="'⛔ ' + (fdata.blocked_at || '')"></span>
            </div>
          </template>
        </div>
      </template>

      <!-- ═══ Section 8: Finding Queue ═══ -->
      <template x-if="data.finding_queue && data.finding_queue.length > 0">
        <div class="findings-section" style="margin-top:16px;">
          <div class="section-title" style="font-size:1rem;">
            Cola de Findings
            <span class="queue-badge" x-text="data.finding_queue.filter(f => f.status !== 'dismissed' && f.status !== 'moved_to_findings').length"></span>
          </div>
          <div style="overflow-x:auto;">
            <table class="findings-table">
              <thead><tr>
                <th>ID</th><th>Titulo</th><th>Fuente</th><th>Componente</th><th>Sev</th><th>Estado</th>
              </tr></thead>
              <tbody>
                <template x-for="q in data.finding_queue" :key="q.id">
                  <tr>
                    <td x-text="q.id"></td>
                    <td x-text="(q.title || '').substring(0,50)"></td>
                    <td><span class="source-badge" x-text="q.source"></span></td>
                    <td x-text="q.component"></td>
                    <td><span class="sev-badge" :class="sevClass(q.severity_estimate)" x-text="q.severity_estimate"></span></td>
                    <td><span class="queue-status" :class="'qs-' + (q.status || '').replace('_','-')" x-text="q.status"></span></td>
                  </tr>
                </template>
              </tbody>
            </table>
          </div>
        </div>
      </template>
```

- [ ] **Step 3: Add CSS for gate circles and queue**

Add in the `<style>` section:

```css
.gate-bar { display:flex; align-items:flex-end; gap:4px; flex-wrap:wrap; margin:8px 0; }
.gate-circle-wrap { display:flex; flex-direction:column; align-items:center; }
.gate-circle { width:18px; height:18px; border-radius:50%; border:2px solid var(--border); }
.gate-sm { width:14px; height:14px; }
.gc-pass { background:var(--severity-low, #22c55e); border-color:var(--severity-low, #22c55e); }
.gc-skip { background:var(--dim, #666); border-color:var(--dim, #666); opacity:0.6; }
.gc-fail { background:var(--severity-critical, #ef4444); border-color:var(--severity-critical, #ef4444); }
.gc-pending { background:transparent; border-color:var(--dim, #666); opacity:0.4; }
.gate-label { font-size:0.55rem; color:var(--dim); margin-top:2px; }
.gate-progress { font-size:0.75rem; color:var(--text); margin-left:8px; }
.gate-blocked { font-size:0.7rem; color:var(--severity-critical); }
.queue-badge { background:var(--severity-medium,#f59e0b); color:#000; border-radius:10px; padding:1px 8px; font-size:0.7rem; margin-left:8px; }
.queue-status { font-size:0.65rem; padding:2px 6px; border-radius:4px; }
.qs-pending-pipeline { background:#f59e0b33; color:#f59e0b; }
.qs-in-pipeline { background:#3b82f633; color:#3b82f6; }
.qs-completed { background:#22c55e33; color:#22c55e; }
.qs-dismissed { background:#66666633; color:#666; }
.source-badge { font-size:0.6rem; padding:1px 4px; border-radius:3px; background:var(--border); }
```

- [ ] **Step 4: Remove old `fuzzPhases()` function**

Remove lines 599-608 (the `fuzzPhases()` method) from the Alpine component.

- [ ] **Step 5: Manual test — start dashboard and verify**

```bash
# First generate gate_status.json
python3 audit-agents/pipeline_gate.py --component PreLiquidation --status
# Start dashboard
cd hunt-dashboard && python3 serve.py --port 8080 &
# Open http://localhost:8080 — verify gate circles appear
# Kill server
kill %1
```

- [ ] **Step 6: Commit**

```bash
git add hunt-dashboard/index.html
git commit -m "feat: dashboard shows gate circles, finding pipeline, and queue panel"
```

---

### Task 7: CLAUDE.md Updates

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add scope intake section**

After the "Qué invocar internamente" list, add:

```markdown
### SCOPE INTAKE — Inicio Automático de Hunt

Al recibir un nuevo target:
1. Clonar el repo
2. Ejecutar: `python3 audit-agents/scope_intake.py --repo <path> --platform <plat> --scope-text "<reglas>"` (o `--scope-file`)
3. Verificar output: componentes mapeados, payouts extraídos, exclusiones
4. `--dry-run` para previsualizar sin escribir
5. El sistema arranca automáticamente con el componente de mayor LOC
6. Dashboard: `python3 hunt-dashboard/serve.py` para monitoreo visual
```

- [ ] **Step 2: Add finding queue rules to autonomous mode**

In the autonomous mode section (around line 85), add:

```markdown
- **Finding Queue**: Después de `/variant-hunt` o cross-component hunt, ejecutar `pipeline_gate.py --queue-finding` para cada variante/finding descubierto. Al inicio de sesión, verificar `finding_queue` en current_hunt.json — items `pending_pipeline` tienen prioridad sobre nuevos componentes (pero NO interrumpen el componente actual).
```

- [ ] **Step 3: Update PoC requirements**

Update finding pipeline step 6 to emphasize fork:
```markdown
[ ] 6.  FOUNDRY FORK + POC (Phase 3) — fork local vm.createFork(), contratos reales
        └─ PoC DEBE usar vm.createFork/vm.selectFork — mock-only PoCs son rechazados por el gate
        └─ Excepción: protocolos pre-launch donde fork es imposible (marcar pre_launch: true)
```

- [ ] **Step 4: Add dashboard and scope_intake to invoke list**

```markdown
- `scope_intake.py` → al iniciar un nuevo target
- `pipeline_gate.py --queue-finding` → después de variant-hunt o cross-component hunt
- `pipeline_gate.py --list-queue` → para ver findings pendientes
- `python3 hunt-dashboard/serve.py` → al inicio de sesión para monitoreo visual
```

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: add scope intake, finding queue rules, fork PoC requirement to CLAUDE.md"
```

---

### Task 8: Integration Test — Full Flow

**Files:** None new — uses existing scripts

- [ ] **Step 1: Test scope intake → gate export → dashboard**

```bash
# 1. Scope intake (dry run)
python3 audit-agents/scope_intake.py \
  --repo /home/kali/Documents/Web3/morpho-pre-liquidation \
  --platform cantina \
  --scope-text "Critical: \$250K-\$2.5M. High: \$10K-\$50K. Out of Scope: deployer choices. Design choices." \
  --dry-run

# 2. Gate status export
python3 audit-agents/pipeline_gate.py --component PreLiquidation --status

# 3. Verify gate_status.json
python3 -c "import json; d=json.load(open('hunt_session/gate_status.json')); print(json.dumps(d, indent=2))" | head -20

# 4. Queue a test finding
python3 audit-agents/pipeline_gate.py --queue-finding --source variant --parent PL-M-01 --title "Test variant" --component PreLiquidationFactory --severity low

# 5. List queue
python3 audit-agents/pipeline_gate.py --list-queue

# 6. Finding gate status
python3 audit-agents/pipeline_gate.py --finding PL-M-01 --status

# 7. Verify gate_status.json has finding gates
python3 -c "import json; d=json.load(open('hunt_session/gate_status.json')); print(list(d.get('finding_gates',{}).keys()))"
```

Expected: All commands succeed, gate_status.json has component + finding data, queue shows the test entry.

- [ ] **Step 2: Test dashboard renders everything**

```bash
cd /home/kali/Documents/Web3/hunt-dashboard && python3 serve.py --port 8080 &
sleep 2
curl -s http://localhost:8080/api/dashboard | python3 -c "import sys,json; d=json.load(sys.stdin); print('gates:', bool(d.get('gates'))); print('queue:', len(d.get('finding_queue',[]))); print('components:', len(d.get('component_map',[])))"
kill %1
```

Expected: `gates: True`, `queue: >= 1`, `components: >= 1`

- [ ] **Step 3: Clean up test queue entry**

```bash
python3 audit-agents/pipeline_gate.py --queue-update PL-M-01-V1 --qstatus dismissed --notes "test entry"
```

- [ ] **Step 4: Run all tests**

```bash
python3 -m pytest audit-agents/tests/test_pipeline_gate.py audit-agents/tests/test_scope_intake.py hunt-dashboard/test_serve.py -v
```
Expected: All tests PASS
