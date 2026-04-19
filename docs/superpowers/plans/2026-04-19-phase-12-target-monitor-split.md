# Phase 12: target_monitor.py Split — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 1,261-LOC `audit-agents/target_monitor.py` god-file with a thin CLI shim + `monitor/` package (8 submodules organized by domain).

**Architecture:** `target_monitor.py` collapses to ~6 LOC delegating to `monitor.cli:main`. Domain-organized split: config/state/notifier/github/proxy/deployment/orchestrator/cli. Zero Python importers — no public API to preserve.

**Tech Stack:** Python 3, stdlib argparse/pathlib/dataclasses, requests, python-dotenv, rich. Migration order: bottom-up (config → state → notifier → monitors → orchestrator → cli).

---

## File Structure

```
audit-agents/
├─ target_monitor.py       # Shim ~6 LOC after migration
└─ monitor/                # NEW package
   ├─ __init__.py          # Empty
   ├─ config.py            # env vars, paths, API keys, console, logger
   ├─ state.py             # Alert + State dataclasses + persistence
   ├─ notifier.py          # Notifier class (telegram/discord/console)
   ├─ github.py            # GitHubMonitor
   ├─ proxy.py             # ProxyUpgradeMonitor
   ├─ deployment.py        # DeploymentMonitor
   ├─ orchestrator.py      # score_target, run_monitors, daemon_mode
   └─ cli.py               # main() + argparse

tests/phase_12/
├─ __init__.py
└─ test_monitor_shim.py    # 3 contract tests
```

**Dependency order (bottom-up):** config → state → notifier → {github, proxy, deployment} → orchestrator → cli.

---

### Task 1: Scaffold monitor/ + config.py

**Files:**
- Create: `audit-agents/monitor/__init__.py`
- Create: `audit-agents/monitor/config.py`
- Modify: `audit-agents/target_monitor.py` (lines ~30-100 — remove config constants, add re-import)

- [ ] **Step 1: Read lines 1-110 of target_monitor.py** to capture exact config block (imports, paths, API key getters, constants like POLL_INTERVAL, console, logger).

- [ ] **Step 2: Create empty package init**

```bash
: > audit-agents/monitor/__init__.py
```

- [ ] **Step 3: Create monitor/config.py**

Contents (verbatim from legacy file, plus `load_dotenv()` at top):

```python
"""Configuration for monitor package."""
import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console

load_dotenv()

console = Console()
logger = logging.getLogger("target_monitor")

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "reports" / "target_monitor"
STATE_FILE = DATA_DIR / "state.json"
ALERTS_FILE = DATA_DIR / "alerts.json"
LOG_FILE = DATA_DIR / "monitor.log"

POLL_INTERVAL = 600  # 10 minutes for daemon mode


def _get_key(env_var: str) -> str:
    val = os.environ.get(env_var, "")
    if val in ("", "TU_KEY_AQUI", "TU_TOKEN_AQUI", "TU_CHAT_ID_AQUI"):
        return ""
    return val


GITHUB_TOKEN = _get_key("GITHUB_TOKEN")
ETHERSCAN_API_KEY = _get_key("ETHERSCAN_API_KEY")
ARBISCAN_API_KEY = _get_key("ARBISCAN_API_KEY")
BASESCAN_API_KEY = _get_key("BASESCAN_API_KEY")
# ... include all API key constants from legacy file exactly as-is
```

**Important:** `BASE_DIR = Path(__file__).resolve().parent.parent` because `config.py` lives in `audit-agents/monitor/`, not `audit-agents/` directly. The `.parent.parent` reaches the `audit-agents/` dir so `DATA_DIR = BASE_DIR / "reports" / "target_monitor"` resolves to the same location as before.

Copy ALL module-level constants (severity keywords, known deployers list, etc.) that exist in lines 50-274 of the original file — anything that isn't a function or class definition.

- [ ] **Step 4: In target_monitor.py**, replace the migrated config block with:

```python
from monitor.config import (
    console,
    logger,
    BASE_DIR,
    DATA_DIR,
    STATE_FILE,
    ALERTS_FILE,
    LOG_FILE,
    POLL_INTERVAL,
    GITHUB_TOKEN,
    ETHERSCAN_API_KEY,
    ARBISCAN_API_KEY,
    BASESCAN_API_KEY,
    # ... all other constants
    _get_key,
)
```

- [ ] **Step 5: Verify CLI still works**

Run: `cd /home/kali/Documents/Web3 && python3 audit-agents/target_monitor.py --help`
Expected: argparse help prints cleanly.

- [ ] **Step 6: Commit**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/monitor/ audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): scaffold monitor/ package with config module

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 2: Migrate state.py

**Files:**
- Create: `audit-agents/monitor/state.py`
- Modify: `audit-agents/target_monitor.py` (remove Alert + State classes)

- [ ] **Step 1: Read Alert + State classes from current target_monitor.py** (grep to find current line numbers since Task 1 shifted them)

- [ ] **Step 2: Create monitor/state.py**

```python
"""Alert + State dataclasses for monitor package."""
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from monitor.config import ALERTS_FILE, STATE_FILE, logger


# <Alert dataclass verbatim>
# <State dataclass verbatim>
```

Include any save/load/to_dict methods exactly as written.

- [ ] **Step 3: Replace in target_monitor.py with re-import:**

```python
from monitor.state import Alert, State
```

- [ ] **Step 4: Verify**

Run: `cd /home/kali/Documents/Web3 && python3 audit-agents/target_monitor.py --help`
Expected: argparse help.

Run: `cd /home/kali/Documents/Web3 && python3 -c "import sys; sys.path.insert(0, 'audit-agents'); from monitor.state import Alert, State; print('OK')"`
Expected: prints `OK`.

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/state.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): migrate Alert + State dataclasses to monitor.state

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 3: Migrate notifier.py

**Files:**
- Create: `audit-agents/monitor/notifier.py`
- Modify: `audit-agents/target_monitor.py`

- [ ] **Step 1: Find Notifier class in current target_monitor.py** (grep `^class Notifier`)

- [ ] **Step 2: Create monitor/notifier.py**

```python
"""Notifier class for monitor package."""
import requests

from monitor.config import console, logger
from monitor.state import Alert


# <Notifier class verbatim>
```

Include any env var references the class uses (telegram/discord env should resolve via `os.environ` reads inside the class or via `monitor.config`).

- [ ] **Step 3: Replace in target_monitor.py**

```python
from monitor.notifier import Notifier
```

- [ ] **Step 4: Verify**

Run: `python3 audit-agents/target_monitor.py --help` — argparse help.
Run: `python3 -c "import sys; sys.path.insert(0, 'audit-agents'); from monitor.notifier import Notifier; print('OK')"` — prints `OK`.

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/notifier.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): migrate Notifier to monitor.notifier

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 4: Migrate github.py

**Files:**
- Create: `audit-agents/monitor/github.py`
- Modify: `audit-agents/target_monitor.py`

- [ ] **Step 1: Find GitHubMonitor class** (grep `^class GitHubMonitor`)

- [ ] **Step 2: Create monitor/github.py**

```python
"""GitHubMonitor for monitor package."""
import re
import requests
from datetime import datetime, timezone, timedelta
from pathlib import Path

from monitor.config import GITHUB_TOKEN, console, logger
from monitor.state import Alert, State
from monitor.notifier import Notifier


# <GitHubMonitor class verbatim>
```

Audit imports: only include what GitHubMonitor actually references.

- [ ] **Step 3: Replace in target_monitor.py**

```python
from monitor.github import GitHubMonitor
```

- [ ] **Step 4: Verify**

`python3 audit-agents/target_monitor.py --help`
`python3 -c "import sys; sys.path.insert(0, 'audit-agents'); from monitor.github import GitHubMonitor; print('OK')"`

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/github.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): migrate GitHubMonitor to monitor.github

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 5: Migrate proxy.py

**Files:**
- Create: `audit-agents/monitor/proxy.py`
- Modify: `audit-agents/target_monitor.py`

- [ ] **Step 1: Find ProxyUpgradeMonitor class**

- [ ] **Step 2: Create monitor/proxy.py** with header:

```python
"""ProxyUpgradeMonitor for monitor package."""
import requests
from datetime import datetime, timezone

from monitor.config import ETHERSCAN_API_KEY, ARBISCAN_API_KEY, BASESCAN_API_KEY, console, logger
from monitor.state import Alert, State
from monitor.notifier import Notifier


# <ProxyUpgradeMonitor class verbatim>
```

Audit actual imports from class body.

- [ ] **Step 3: Replace in target_monitor.py**

```python
from monitor.proxy import ProxyUpgradeMonitor
```

- [ ] **Step 4: Verify**

`python3 audit-agents/target_monitor.py --help`
`python3 -c "import sys; sys.path.insert(0, 'audit-agents'); from monitor.proxy import ProxyUpgradeMonitor; print('OK')"`

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/proxy.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): migrate ProxyUpgradeMonitor to monitor.proxy

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 6: Migrate deployment.py

**Files:**
- Create: `audit-agents/monitor/deployment.py`
- Modify: `audit-agents/target_monitor.py`

- [ ] **Step 1: Find DeploymentMonitor class**

- [ ] **Step 2: Create monitor/deployment.py**

```python
"""DeploymentMonitor for monitor package."""
import requests
from datetime import datetime, timezone

from monitor.config import ETHERSCAN_API_KEY, console, logger
from monitor.state import Alert, State
from monitor.notifier import Notifier


# <DeploymentMonitor class verbatim>
```

- [ ] **Step 3: Replace in target_monitor.py**

```python
from monitor.deployment import DeploymentMonitor
```

- [ ] **Step 4: Verify**

`python3 audit-agents/target_monitor.py --help`
`python3 -c "import sys; sys.path.insert(0, 'audit-agents'); from monitor.deployment import DeploymentMonitor; print('OK')"`

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/deployment.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): migrate DeploymentMonitor to monitor.deployment

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 7: Migrate orchestrator.py

**Files:**
- Create: `audit-agents/monitor/orchestrator.py`
- Modify: `audit-agents/target_monitor.py`

- [ ] **Step 1: Find score_target, run_monitors, daemon_mode** (grep each)

- [ ] **Step 2: Create monitor/orchestrator.py**

```python
"""Orchestration for monitor package."""
import time
import logging
from datetime import datetime, timezone

from monitor.config import console, logger, LOG_FILE, POLL_INTERVAL
from monitor.state import Alert, State
from monitor.notifier import Notifier
from monitor.github import GitHubMonitor
from monitor.proxy import ProxyUpgradeMonitor
from monitor.deployment import DeploymentMonitor


# <score_target function verbatim>
# <run_monitors function verbatim>
# <daemon_mode function verbatim>
```

- [ ] **Step 3: Replace in target_monitor.py**

```python
from monitor.orchestrator import score_target, run_monitors, daemon_mode
```

- [ ] **Step 4: Verify**

`python3 audit-agents/target_monitor.py --help`
`python3 -c "import sys; sys.path.insert(0, 'audit-agents'); from monitor.orchestrator import score_target, run_monitors, daemon_mode; print('OK')"`

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/orchestrator.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): migrate orchestrators to monitor.orchestrator

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 8: Migrate cli.py + collapse shim

**Files:**
- Create: `audit-agents/monitor/cli.py`
- Rewrite entirely: `audit-agents/target_monitor.py`

- [ ] **Step 1: Read current target_monitor.py** fully — should now contain only docstring + imports + main() + `__main__` guard.

- [ ] **Step 2: Create monitor/cli.py** with main() verbatim + argparse setup:

```python
"""CLI entry point for monitor package."""
import argparse
import sys

from monitor.config import console, logger
from monitor.state import State
from monitor.notifier import Notifier
from monitor.orchestrator import run_monitors, daemon_mode


def main():
    # <main body verbatim>
```

Audit imports by reading main() body.

- [ ] **Step 3: Replace target_monitor.py contents with shim:**

```python
#!/usr/bin/env python3
"""target_monitor.py — CLI entry point. Logic in monitor/ package."""
from monitor.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Verify CLI equivalence**

Run: `python3 audit-agents/target_monitor.py --help`
Expected: identical argparse help as before.

Run: `wc -l audit-agents/target_monitor.py`
Expected: ≤ 6 lines.

- [ ] **Step 5: Commit**

```bash
rtk git add audit-agents/monitor/cli.py audit-agents/target_monitor.py
rtk git commit -m "refactor(phase_12): collapse target_monitor.py to CLI shim

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

### Task 9: Contract tests + audit + memory

**Files:**
- Create: `audit-agents/tests/phase_12/__init__.py`
- Create: `audit-agents/tests/phase_12/test_monitor_shim.py`
- Modify: `docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml`
- Modify: `audit-agents/phase_8_audit.py` (expected_count 230 → 233)
- Modify: `~/.claude/projects/-home-kali-Documents-Web3/memory/project_optimization_roadmap.md`
- Modify: `~/.claude/projects/-home-kali-Documents-Web3/memory/MEMORY.md`

- [ ] **Step 1: Create tests/phase_12/__init__.py (empty)**

- [ ] **Step 2: Create tests/phase_12/test_monitor_shim.py**

```python
"""Phase 12 contract tests: target_monitor.py shim + monitor/ package."""
import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

MONITOR_SUBMODULES = [
    "monitor",
    "monitor.config",
    "monitor.state",
    "monitor.notifier",
    "monitor.github",
    "monitor.proxy",
    "monitor.deployment",
    "monitor.orchestrator",
    "monitor.cli",
]


def test_shim_loc_budget():
    """target_monitor.py must remain a thin shim (<30 LOC)."""
    shim_path = Path(__file__).resolve().parent.parent.parent / "target_monitor.py"
    loc = sum(1 for _ in shim_path.open())
    assert loc < 30, f"Shim grew to {loc} LOC"


def test_monitor_package_modules_importable():
    """All monitor/ submodules must be importable."""
    for name in MONITOR_SUBMODULES:
        importlib.import_module(name)


def test_cli_main_callable():
    """monitor.cli.main must be callable."""
    from monitor.cli import main
    assert callable(main)
```

- [ ] **Step 3: Run tests**

```bash
cd /home/kali/Documents/Web3/audit-agents
python3 -m pytest tests/phase_12/ -v
```
Expected: 3 passed.

```bash
python3 -m pytest tests/ -q 2>&1 | tail -5
```
Expected: 233 passed.

- [ ] **Step 4: Update phase_8_audit.py**

Edit line containing `expected_count: int = 230` → `expected_count: int = 233`.

- [ ] **Step 5: Add F057 to parity matrix**

Append to `features:` list:

```yaml
- id: F057
  name: "target_monitor.py"
  legacy_location: "audit-agents/target_monitor.py (1,261 LOC)"
  modern_location: "audit-agents/monitor/ (package, 9 submodules)"
  migration_decision: migrate
  notes: "Split in Phase 12 (2026-04-19). Shim ≤6 LOC + monitor/{config,state,notifier,github,proxy,deployment,orchestrator,cli}.py. Zero Python importers — CLI-only."
```

Update `summary`:
- `total_features`: 56 → 57
- `by_decision.migrate`: +1
- `added_phase_12: 1`

Verify `sum(by_decision.values()) == 57`.

- [ ] **Step 6: Run audit**

```bash
cd /home/kali/Documents/Web3/audit-agents
python3 phase_8_audit.py
```

Expected: exit 0, `target_monitor.py` no longer in god-files list.

- [ ] **Step 7: Commit tests + parity + audit config**

```bash
cd /home/kali/Documents/Web3
rtk git add audit-agents/tests/phase_12/ audit-agents/phase_8_audit.py docs/superpowers/specs/2026-04-17-phase-0-parity-matrix.yaml
rtk git commit -m "test(phase_12): contract tests + parity F057 + test count 233

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

- [ ] **Step 8: Commit refreshed audit artifacts**

```bash
rtk git add audit-agents/audit_report.json docs/superpowers/specs/2026-04-19-phase-8-audit-report.md
rtk git commit -m "chore(phase_12): refresh Phase 8 audit artifacts post-split

target_monitor.py no longer god-file. Tests 233 passed.

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

- [ ] **Step 9: Update memory files**

(a) Append Fase 12 section to `project_optimization_roadmap.md`:

```markdown
## Fase 12 — target_monitor.py split (2026-04-19) COMPLETA

**Goal**: Reducir target_monitor.py (1,261 LOC) a shim CLI + paquete monitor/.

**Resultado**:
- Shim: ≤6 LOC (target_monitor.py)
- monitor/ package: 8 submódulos (config, state, notifier, github, proxy, deployment, orchestrator, cli)
- Tests: 233 passing (230 + 3 contract tests Phase 12)
- Audit: target_monitor.py eliminado de god-files
- Parity: F057 añadida, total 57 features
- Zero importer breakage: CLI equivalencia mantenida

**Backlog remanente para Phase 13+**:
- Split benchmark/component_pipeline/runner.py (1,608 LOC)
- Eje 3 matching consolidation
- Descomponer funciones HIGH (run_split_mode, run_component_pipeline, etc.)
- Dead-code cleanup
```

(b) Update `MEMORY.md` roadmap index line to cite Phases 9-12.

Memory files outside repo — no git commit.

---

## Success Criteria (end of Phase 12)

- `target_monitor.py` ≤ 6 LOC
- `monitor/` package: 8 submodules + `__init__.py`
- Tests: 233 passing (3 new Phase 12 contract tests)
- Audit: `target_monitor.py` no longer in god-file list
- Parity matrix: F057 added, arithmetic consistent
- CLI equivalence: `--help`, `--monitor`, `--daemon`, `--notify` behave identically
