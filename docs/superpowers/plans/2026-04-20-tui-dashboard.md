# TUI Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Single-file `rich` TUI dashboard reading hunt_session JSONs + orchestrator.log to show live gates grid, findings counter, activity panel with animations.

**Architecture:** One file `audit-agents/dashboard.py` with pure data helpers (testable) + render functions (rich-dependent) + `rich.Live` main loop at 4 Hz. Tests cover data helpers only.

**Tech Stack:** Python 3, `rich` (already installed), stdlib. No new deps.

**Spec:** `docs/superpowers/specs/2026-04-20-tui-dashboard-design.md`

---

## File Structure

Files created in this plan:
- `audit-agents/dashboard.py` — entry point + all logic (~240 LOC)
- `audit-agents/tests/test_dashboard.py` — 5 pure-function tests

No existing files are modified.

---

## Task 1: Scaffold dashboard.py with CLI + empty main loop

**Files:**
- Create: `audit-agents/dashboard.py`
- Create: `audit-agents/tests/test_dashboard.py`

- [ ] **Step 1: Create scaffolding for both files**

`audit-agents/dashboard.py`:
```python
"""Real-time TUI dashboard for the audit pipeline.

Reads hunt_session JSONs + orchestrator.log and renders a live rich view.
Run: python3 audit-agents/dashboard.py [--protocol NAME]
"""
from __future__ import annotations

import argparse
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

WEB3_DIR = Path(__file__).resolve().parent.parent
HUNT_SESSION = WEB3_DIR / "hunt_session"
CURRENT_HUNT = HUNT_SESSION / "MEMORY" / "STATE" / "current_hunt.json"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="TUI dashboard for audit pipeline")
    p.add_argument("--protocol", help="Protocol name (overrides current_hunt.json)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    print(f"dashboard started (protocol={args.protocol or 'auto'})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

`audit-agents/tests/test_dashboard.py`:
```python
"""Tests for dashboard data helpers."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from dashboard import (
    load_current_hunt,
    load_gate_status,
    load_findings,
    build_snapshot,
    parse_recent_events,
    aggregate_findings_by_severity,
    HuntSnapshot,
)
```

- [ ] **Step 2: Verify imports fail as expected (TDD baseline)**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: `ImportError: cannot import name 'load_current_hunt' from 'dashboard'` — confirms TDD starting state.

- [ ] **Step 3: Commit scaffold**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py audit-agents/tests/test_dashboard.py
git commit -m "feat(dashboard): scaffold dashboard.py + empty test file"
```

---

## Task 2: load_current_hunt (2 tests)

**Files:**
- Modify: `audit-agents/dashboard.py` (add `load_current_hunt`)
- Modify: `audit-agents/tests/test_dashboard.py` (add 2 tests)

- [ ] **Step 1: Write failing tests**

Append to `audit-agents/tests/test_dashboard.py`:
```python
def test_load_current_hunt_present(tmp_path, monkeypatch):
    state_dir = tmp_path / "hunt_session" / "MEMORY" / "STATE"
    state_dir.mkdir(parents=True)
    (state_dir / "current_hunt.json").write_text(
        json.dumps({"protocol": "yieldoor-bench", "components": ["Leverager", "LendingPool"]})
    )
    import dashboard as d
    monkeypatch.setattr(d, "CURRENT_HUNT", state_dir / "current_hunt.json")
    data = d.load_current_hunt()
    assert data["protocol"] == "yieldoor-bench"
    assert data["components"] == ["Leverager", "LendingPool"]


def test_load_current_hunt_missing(tmp_path, monkeypatch):
    import dashboard as d
    monkeypatch.setattr(d, "CURRENT_HUNT", tmp_path / "does_not_exist.json")
    assert d.load_current_hunt() == {}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: FAIL — `cannot import name 'load_current_hunt'`

- [ ] **Step 3: Implement loader**

Add to `audit-agents/dashboard.py` after the constants:
```python
def load_current_hunt() -> dict[str, Any]:
    """Read current_hunt.json. Return {} if missing or malformed."""
    try:
        return json.loads(CURRENT_HUNT.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
```

- [ ] **Step 4: Run tests to confirm PASS**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py audit-agents/tests/test_dashboard.py
git commit -m "feat(dashboard): load_current_hunt with missing-file handling"
```

---

## Task 3: load_gate_status + load_findings

**Files:**
- Modify: `audit-agents/dashboard.py`

- [ ] **Step 1: Implement loaders (covered by downstream snapshot test)**

Add to `audit-agents/dashboard.py`:
```python
def load_gate_status(protocol: str) -> dict[str, Any]:
    """Read hunt_session/gate_status/<protocol>.json. Return {} if missing."""
    path = HUNT_SESSION / "gate_status" / f"{protocol}.json"
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_findings(protocol: str) -> list[dict[str, Any]]:
    """Try hunt_session/findings.json first, then benchmarks/<protocol>/bench_session/findings_all.json."""
    real = HUNT_SESSION / "findings.json"
    bench = WEB3_DIR / "benchmarks" / protocol.removesuffix("-bench") / "bench_session" / "findings_all.json"
    for path in (real, bench):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "findings" in data:
                return data["findings"]
            if isinstance(data, list):
                return data
        except (FileNotFoundError, json.JSONDecodeError):
            continue
    return []
```

- [ ] **Step 2: Verify module still imports cleanly**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -c "import dashboard; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py
git commit -m "feat(dashboard): load_gate_status + load_findings with bench fallback"
```

---

## Task 4: HuntSnapshot dataclass + build_snapshot (1 test)

**Files:**
- Modify: `audit-agents/dashboard.py`
- Modify: `audit-agents/tests/test_dashboard.py`

- [ ] **Step 1: Write failing test**

Append to `audit-agents/tests/test_dashboard.py`:
```python
def test_build_snapshot_merges_sources(tmp_path, monkeypatch):
    """Snapshot must merge current_hunt + gate_status + findings into one object."""
    state_dir = tmp_path / "hunt_session" / "MEMORY" / "STATE"
    state_dir.mkdir(parents=True)
    (state_dir / "current_hunt.json").write_text(
        json.dumps({"protocol": "testproto", "components": ["Alpha", "Beta"]})
    )
    gate_dir = tmp_path / "hunt_session" / "gate_status"
    gate_dir.mkdir(parents=True)
    (gate_dir / "testproto.json").write_text(json.dumps({
        "component_gates": {
            "Alpha": {
                "scope":   {"state": "pass", "detail": "ok"},
                "prepass": {"state": "pass", "detail": "ok"},
                "hunters": {"state": "pending", "detail": "active"},
            },
            "Beta": {
                "scope":   {"state": "pass", "detail": "ok"},
                "prepass": {"state": "pending", "detail": "active"},
            },
        }
    }))
    findings_path = tmp_path / "hunt_session" / "findings.json"
    findings_path.write_text(json.dumps({"findings": [
        {"severity": "high"},
        {"severity": "medium"},
    ]}))

    import dashboard as d
    monkeypatch.setattr(d, "CURRENT_HUNT", state_dir / "current_hunt.json")
    monkeypatch.setattr(d, "HUNT_SESSION", tmp_path / "hunt_session")

    snap = d.build_snapshot(protocol_override=None)

    assert snap.protocol == "testproto"
    assert snap.components == ["Alpha", "Beta"]
    assert snap.gates["Alpha"]["scope"] == "pass"
    assert snap.gates["Alpha"]["hunters"] == "pending"
    assert snap.findings_total == 2
    assert snap.findings_by_severity["high"] == 1
    assert snap.findings_by_severity["medium"] == 1
```

- [ ] **Step 2: Run test to confirm it fails**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py::test_build_snapshot_merges_sources -v`
Expected: FAIL (`build_snapshot` / `HuntSnapshot` not defined).

- [ ] **Step 3: Implement dataclass + builder**

Add to `audit-agents/dashboard.py`:
```python
GATE_ORDER = ("scope", "prepass", "hunters", "crosschain", "deepdive",
              "merge", "compile", "phase1", "phase2", "phase3", "verify")


@dataclass
class HuntSnapshot:
    protocol: str = ""
    components: list[str] = field(default_factory=list)
    gates: dict[str, dict[str, str]] = field(default_factory=dict)
    active_component: str | None = None
    active_gate: str | None = None
    active_step: str | None = None
    findings_total: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    recent_events: list[tuple[str, str, str]] = field(default_factory=list)


def build_snapshot(protocol_override: str | None) -> HuntSnapshot:
    hunt = load_current_hunt()
    protocol = protocol_override or hunt.get("protocol", "")
    if not protocol:
        return HuntSnapshot()

    gs = load_gate_status(protocol).get("component_gates", {})
    components = hunt.get("components") or list(gs.keys())

    gates: dict[str, dict[str, str]] = {}
    active_component = None
    active_gate = None
    for comp in components:
        comp_gates = {}
        comp_data = gs.get(comp, {})
        for gate in GATE_ORDER:
            state = comp_data.get(gate, {}).get("state", "pending")
            comp_gates[gate] = state
            if state == "pending" and active_component is None:
                # The first component with a pending gate is "active" if prior gates passed
                prior_ok = all(comp_gates[g] == "pass" for g in GATE_ORDER[:GATE_ORDER.index(gate)])
                if prior_ok:
                    active_component = comp
                    active_gate = gate
        gates[comp] = comp_gates

    findings = load_findings(protocol)
    severity_counts = aggregate_findings_by_severity(findings)

    return HuntSnapshot(
        protocol=protocol,
        components=components,
        gates=gates,
        active_component=active_component,
        active_gate=active_gate,
        active_step=None,  # populated by log parser in Task 5
        findings_total=len(findings),
        findings_by_severity=severity_counts,
        recent_events=[],
    )
```

Note: `aggregate_findings_by_severity` is defined in Task 6 — add a stub now to keep `build_snapshot` working in this task:
```python
def aggregate_findings_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts
```

- [ ] **Step 4: Run test to confirm PASS**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py audit-agents/tests/test_dashboard.py
git commit -m "feat(dashboard): HuntSnapshot + build_snapshot merges all JSON sources"
```

---

## Task 5: parse_recent_events (1 test)

**Files:**
- Modify: `audit-agents/dashboard.py`
- Modify: `audit-agents/tests/test_dashboard.py`

- [ ] **Step 1: Write failing test**

Append to `audit-agents/tests/test_dashboard.py`:
```python
def test_parse_recent_events_extracts_step_markers(tmp_path):
    log = tmp_path / "orchestrator.log"
    log.write_text(
        "2026-04-20 16:58:40 INFO | some noise line\n"
        "2026-04-20 16:58:41 INFO |   Step 4: DeepDive Hunter\n"
        "2026-04-20 16:58:42 INFO |   Running claude -p sub (3175 chars)...\n"
        "2026-04-20 16:58:43 INFO |   12 Hunters completed (5.2min)\n"
    )
    import dashboard as d
    events, new_offset = d.parse_recent_events(log, offset=0, max_events=3)
    assert new_offset == log.stat().st_size
    assert len(events) == 3
    # Events are (timestamp, component_or_blank, message) tuples
    assert any("Step 4: DeepDive Hunter" in msg for _, _, msg in events)
    assert any("12 Hunters completed" in msg for _, _, msg in events)
```

- [ ] **Step 2: Run test to confirm fail**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py::test_parse_recent_events_extracts_step_markers -v`
Expected: FAIL — `parse_recent_events` not defined.

- [ ] **Step 3: Implement parser**

Add to `audit-agents/dashboard.py`:
```python
import re

_EVENT_PATTERNS = (
    re.compile(r"Step\s+[-\d.]+:\s*.+"),
    re.compile(r"\d+\s+Hunters\s+completed.*"),
    re.compile(r"DeepDive.*"),
    re.compile(r"Gate\s+\w+:\s*(PASS|FAIL)"),
    re.compile(r"Running\s+claude\s+-p.*"),
    re.compile(r"🏁.*"),
    re.compile(r"Found\s+\d+\s+findings.*"),
    re.compile(r"Phase\s+\d+.*"),
)


def _matches_event(line: str) -> bool:
    return any(p.search(line) for p in _EVENT_PATTERNS)


def parse_recent_events(log_path: Path, offset: int, max_events: int = 3
                        ) -> tuple[list[tuple[str, str, str]], int]:
    """Read log from `offset`, return (events, new_offset).

    Each event is (timestamp_str, component, message). Component is "" if not
    inferrable. Keeps only the last `max_events` matching lines.
    """
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            new_lines = fh.readlines()
            new_offset = fh.tell()
    except FileNotFoundError:
        return [], offset

    matched: list[tuple[str, str, str]] = []
    for raw in new_lines:
        line = raw.rstrip("\n")
        if not _matches_event(line):
            continue
        # Split "YYYY-MM-DD HH:MM:SS LEVEL | message"
        parts = line.split("|", 1)
        if len(parts) == 2:
            header, msg = parts[0].strip(), parts[1].strip()
            ts = header.split()[1] if len(header.split()) >= 2 else header
        else:
            ts, msg = "", line.strip()
        matched.append((ts, "", msg))

    return matched[-max_events:], new_offset
```

- [ ] **Step 4: Run test to confirm PASS**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py audit-agents/tests/test_dashboard.py
git commit -m "feat(dashboard): incremental log parser for Step/Gate/Phase events"
```

---

## Task 6: aggregate_findings_by_severity test (already stubbed in Task 4)

**Files:**
- Modify: `audit-agents/tests/test_dashboard.py`

- [ ] **Step 1: Write dedicated test**

Append to `audit-agents/tests/test_dashboard.py`:
```python
def test_findings_severity_aggregation():
    import dashboard as d
    findings = [
        {"severity": "High"}, {"severity": "high"}, {"severity": "MEDIUM"},
        {"severity": "low"}, {"severity": "low"}, {"severity": "low"},
        {},  # no severity → "unknown"
    ]
    counts = d.aggregate_findings_by_severity(findings)
    assert counts["high"] == 2
    assert counts["medium"] == 1
    assert counts["low"] == 3
    assert counts["unknown"] == 1
```

- [ ] **Step 2: Run test**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: 5 passed (function already stubbed in Task 4 handles this).

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/tests/test_dashboard.py
git commit -m "test(dashboard): severity aggregation coverage"
```

---

## Task 7: Render header + gates grid (with spinners and pulse)

**Files:**
- Modify: `audit-agents/dashboard.py`

- [ ] **Step 1: Implement render helpers for header + gates**

Add to `audit-agents/dashboard.py`:
```python
from datetime import datetime

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from rich.style import Style

# Gate display: short column headers + emoji for state
GATE_COLS = [
    ("scope", "scope"), ("prepass", "prep"), ("hunters", "hunt"),
    ("crosschain", "xch"), ("deepdive", "dd"), ("merge", "mrg"),
    ("compile", "cmp"), ("phase1", "p1"), ("phase2", "p2"),
    ("phase3", "p3"), ("verify", "vfy"),
]

_SPINNER = Spinner("dots", style="yellow")


def _gate_cell(state: str, is_active: bool):
    if is_active:
        return _SPINNER
    if state == "pass":
        return Text("✅", style="green")
    if state == "fail":
        return Text("❌", style="red")
    return Text("⋯", style="grey50")


def render_header(snap: HuntSnapshot) -> Panel:
    now = datetime.now().strftime("%H:%M:%S")
    title = f"[bold cyan]{snap.protocol or 'no active hunt'}[/]  •  [white]{now}[/]"
    return Panel(Text.from_markup(title, justify="center"), border_style="cyan")


def render_gates(snap: HuntSnapshot) -> Table:
    tbl = Table(show_lines=False, padding=(0, 1), expand=True)
    tbl.add_column("Component", style="bold white", min_width=12)
    for _key, label in GATE_COLS:
        tbl.add_column(label, justify="center", min_width=4)

    pulse_bold = int(time.time()) % 2 == 0
    for comp in snap.components:
        gates = snap.gates.get(comp, {})
        is_active_row = (comp == snap.active_component)
        row_style = (Style(bold=True) if pulse_bold else Style(dim=True)) if is_active_row else Style()
        cells: list[Any] = [Text(comp + (" ←" if is_active_row else ""), style=row_style)]
        for key, _label in GATE_COLS:
            state = gates.get(key, "pending")
            is_active_cell = is_active_row and key == snap.active_gate
            cells.append(_gate_cell(state, is_active_cell))
        tbl.add_row(*cells)
    return tbl
```

- [ ] **Step 2: Smoke test import**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -c "import dashboard; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Run all existing tests**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/test_dashboard.py -v`
Expected: 5 passed.

- [ ] **Step 4: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py
git commit -m "feat(dashboard): render_header + render_gates with active spinner + row pulse"
```

---

## Task 8: Render findings strip (with flash) + activity panel

**Files:**
- Modify: `audit-agents/dashboard.py`

- [ ] **Step 1: Implement findings + activity renderers**

Add to `audit-agents/dashboard.py`:
```python
def render_findings(snap: HuntSnapshot, flash_until: float) -> Panel:
    sev = snap.findings_by_severity
    body = Text.from_markup(
        f"🐛  [bold]{snap.findings_total}[/] findings   "
        f"[red]H:{sev.get('high', 0)}[/]  "
        f"[yellow]M:{sev.get('medium', 0)}[/]  "
        f"[white]L:{sev.get('low', 0)}[/]"
    )
    flashing = time.time() < flash_until
    border = "green" if flashing else "grey50"
    return Panel(body, border_style=border, padding=(0, 2))


def render_activity(events: list[tuple[str, str, str]]) -> Panel:
    body = Text()
    if not events:
        body.append("  (waiting for events...)", style="dim")
    for ts, comp, msg in events[-3:]:
        body.append(f"  {ts}  ", style="cyan")
        if comp:
            body.append(f"{comp}  ", style="magenta")
        body.append(msg + "\n", style="white")
    return Panel(body, title="▸▸▸ Activity", border_style="blue", padding=(0, 1))
```

- [ ] **Step 2: Smoke import**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -c "import dashboard; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py
git commit -m "feat(dashboard): render_findings flash + render_activity scroll panel"
```

---

## Task 8.5: Phase 1 progress bar (conditional render)

**Files:**
- Modify: `audit-agents/dashboard.py`

- [ ] **Step 1: Add phase1 parser + optional progress renderer**

Add to `audit-agents/dashboard.py`:
```python
from rich.progress import Progress, BarColumn, TextColumn

_PHASE1_RUNS_RE = re.compile(r"runs:\s*(\d+)", re.IGNORECASE)
_PHASE1_TARGET = 5000


def parse_phase1_progress(log_path: Path) -> int | None:
    """Return the highest `runs: N` seen in the last 200 lines, else None."""
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 20000))
            tail = fh.read().splitlines()[-200:]
    except FileNotFoundError:
        return None
    max_runs = -1
    for line in tail:
        m = _PHASE1_RUNS_RE.search(line)
        if m:
            max_runs = max(max_runs, int(m.group(1)))
    return max_runs if max_runs >= 0 else None


def render_phase1_progress(runs: int) -> Panel:
    pct = min(100, int(100 * runs / _PHASE1_TARGET))
    bar = "█" * (pct // 4) + "░" * (25 - pct // 4)
    body = Text.from_markup(f"[cyan]Phase 1 Foundry[/]  [{bar}]  {runs}/{_PHASE1_TARGET}  ({pct}%)")
    return Panel(body, border_style="cyan", padding=(0, 1))
```

- [ ] **Step 2: Smoke import**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -c "import dashboard; print('ok')"`
Expected: `ok`.

- [ ] **Step 3: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py
git commit -m "feat(dashboard): phase1 progress parser + optional progress panel"
```

---

## Task 9: Wire main loop with rich.Live @ 4 Hz + Ctrl-C

**Files:**
- Modify: `audit-agents/dashboard.py`

- [ ] **Step 1: Implement layout builder + main loop**

Replace the existing `main()` in `audit-agents/dashboard.py` with:
```python
from collections import deque

from rich.live import Live


def _find_orchestrator_log(protocol: str) -> Path | None:
    bench_logs = WEB3_DIR / "benchmarks" / protocol.removesuffix("-bench") / "bench_session" / "logs"
    hunt_logs = HUNT_SESSION / "logs"
    candidates: list[Path] = []
    for root in (bench_logs, hunt_logs):
        if root.exists():
            for p in root.rglob("orchestrator.log"):
                candidates.append(p)
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def build_layout(snap: HuntSnapshot, flash_until: float,
                 activity: list[tuple[str, str, str]],
                 phase1_runs: int | None) -> Layout:
    layout = Layout()
    panels = [
        Layout(render_header(snap), name="header", size=3),
        Layout(render_gates(snap), name="gates"),
    ]
    if phase1_runs is not None and snap.active_gate == "phase1":
        panels.append(Layout(render_phase1_progress(phase1_runs), name="phase1", size=3))
    panels.extend([
        Layout(render_findings(snap, flash_until), name="findings", size=3),
        Layout(render_activity(activity), name="activity", size=7),
    ])
    layout.split_column(*panels)
    return layout


def main() -> int:
    args = parse_args()
    console = Console()

    # Activity buffer (scrolls naturally via deque)
    activity: deque[tuple[str, str, str]] = deque(maxlen=3)
    log_offsets: dict[str, int] = {}
    prev_total = 0
    flash_until = 0.0
    snap_cache: tuple[float, HuntSnapshot] | None = None
    SNAPSHOT_TTL = 1.0

    def _refresh_snapshot() -> HuntSnapshot:
        nonlocal snap_cache
        now = time.time()
        if snap_cache and now - snap_cache[0] < SNAPSHOT_TTL:
            return snap_cache[1]
        s = build_snapshot(args.protocol)
        snap_cache = (now, s)
        return s

    try:
        with Live(console=console, refresh_per_second=4, screen=False) as live:
            while True:
                snap = _refresh_snapshot()

                # Update log tail
                if snap.protocol:
                    log = _find_orchestrator_log(snap.protocol)
                    if log is not None:
                        key = str(log)
                        offset = log_offsets.get(key, log.stat().st_size)
                        events, new_offset = parse_recent_events(log, offset, max_events=10)
                        log_offsets[key] = new_offset
                        for ev in events:
                            activity.append(ev)

                # Flash on findings increment
                if snap.findings_total > prev_total:
                    flash_until = time.time() + 1.0
                prev_total = snap.findings_total

                # Phase 1 progress (only when phase1 gate is active)
                phase1_runs: int | None = None
                if snap.active_gate == "phase1" and snap.protocol:
                    log = _find_orchestrator_log(snap.protocol)
                    if log is not None:
                        phase1_runs = parse_phase1_progress(log)

                live.update(build_layout(snap, flash_until, list(activity), phase1_runs))
                time.sleep(0.25)
    except KeyboardInterrupt:
        console.print("\n[dim]dashboard stopped[/]")
        return 0
```

- [ ] **Step 2: Smoke test — launch, verify no crash in 2 seconds, kill**

Run: `cd /home/kali/Documents/Web3 && timeout 2 python3 audit-agents/dashboard.py || true`
Expected: exits cleanly with code 124 (timeout). No Python traceback.

- [ ] **Step 3: Run full test suite**

Run: `cd /home/kali/Documents/Web3/audit-agents && python3 -m pytest tests/ -q 2>&1 | tail -5`
Expected: `243 passed` (238 existing + 5 new).

- [ ] **Step 4: Commit**

```bash
cd /home/kali/Documents/Web3
git add audit-agents/dashboard.py
git commit -m "feat(dashboard): wire Live loop with snapshot cache + log tail + flash"
```

---

## Task 10: Manual acceptance (user-driven)

**Files:** none (manual run only)

- [ ] **Step 1: Launch against a live or paused hunt**

Run: `cd /home/kali/Documents/Web3 && python3 audit-agents/dashboard.py`

Expected visible behavior:
- Header shows `yieldoor-bench` (or whatever protocol is active) + live clock ticking
- Gates grid renders with ✅/❌/⋯ cells
- If there's an active component (one with pending gate after passing ones), its row's name shows `←` marker and alternates bold/dim each second
- Findings strip shows totals; if a new finding appears, the panel border flashes green
- Activity panel shows last events from orchestrator.log

- [ ] **Step 2: Quit with Ctrl-C**

Expected: terminal prints `dashboard stopped` and returns to prompt cleanly (no garbled output).

- [ ] **Step 3: Launch with no active hunt**

```bash
cd /tmp && python3 /home/kali/Documents/Web3/audit-agents/dashboard.py --protocol does_not_exist
```

Expected: header shows `does_not_exist`, gates grid empty, findings 0, activity shows `(waiting for events...)`. No crash.

---

## Notes

- No new dependencies. `rich` is already present (verified).
- Tests live alongside other pipeline tests in `audit-agents/tests/` and run under the same pytest command the benchmark suite uses.
- The dashboard never writes to hunt_session or any shared state — read-only by design.
- If `current_hunt.json` doesn't exist, the dashboard shows "no active hunt" header and empty grid but keeps polling.
