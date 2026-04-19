"""Scope master YAML I/O and path resolution."""

import sys
from datetime import datetime
from pathlib import Path

from state_manager import load_state
from gate.constants import SCOPE_MASTER_DIR

# ─── SCOPE_MASTER Auto-Update ─────────────────────────────────────────────────

import re as _re_module


def _find_scope_master(protocol: str) -> Path | None:
    """Find SCOPE_MASTER.md for the current program.

    Searches by protocol name first, then by program name in current_hunt.json.
    Returns None if no scope master exists yet.
    """
    state = load_state()

    # Try direct protocol match
    candidate = SCOPE_MASTER_DIR / protocol / "SCOPE_MASTER.md"
    if candidate.exists():
        return candidate

    # Try program field from state
    program = state.get("program", "")
    if program:
        candidate = SCOPE_MASTER_DIR / program.lower().replace(" ", "-") / "SCOPE_MASTER.md"
        if candidate.exists():
            return candidate

    # Scan all context dirs for a SCOPE_MASTER that mentions this protocol
    if SCOPE_MASTER_DIR.exists():
        for d in SCOPE_MASTER_DIR.iterdir():
            if d.is_dir():
                sm = d / "SCOPE_MASTER.md"
                if sm.exists():
                    text = sm.read_text()
                    if protocol in text:
                        return sm

    return None


def _scope_master_update_component(protocol: str, component: str,
                                    new_state: str = None,
                                    add_review_date: str = None,
                                    add_finding: str = None):
    """Update a component's entry in SCOPE_MASTER.md.

    - new_state: set component state (DONE, IN_PROGRESS, etc.)
    - add_review_date: append a review date to the Revisiones array
    - add_finding: append finding count/ID info
    """
    sm_path = _find_scope_master(protocol)
    if not sm_path:
        return

    text = sm_path.read_text()
    lines = text.split("\n")
    modified = False

    # Find the component section (look for "#### " or "### " followed by component name)
    # Use flexible matching: component name can be a substring of the heading
    escaped = _re_module.escape(component)
    comp_pattern = _re_module.compile(
        rf'^(#{2,4})\s+.*{escaped}', _re_module.IGNORECASE
    )
    section_start = None
    section_end = None

    for i, line in enumerate(lines):
        if comp_pattern.search(line):
            section_start = i
            # Find end: next heading of same or higher level
            heading_level = len(line) - len(line.lstrip("#"))
            for j in range(i + 1, len(lines)):
                if lines[j].startswith("#") and not lines[j].startswith("#" * (heading_level + 1)):
                    section_end = j
                    break
            if section_end is None:
                section_end = len(lines)
            break

    if section_start is None:
        return  # Component not found in SCOPE_MASTER

    section = lines[section_start:section_end]

    # Update state
    if new_state:
        for k, line in enumerate(section):
            if line.strip().startswith("- **Estado**:"):
                section[k] = f"- **Estado**: `{new_state}`"
                modified = True
                break

    # Add review date
    if add_review_date:
        for k, line in enumerate(section):
            if line.strip().startswith("- **Revisiones**:"):
                # Parse existing dates
                match = _re_module.search(r'\[([^\]]*)\]', line)
                if match:
                    existing = match.group(1).strip()
                    if existing:
                        dates = [d.strip().strip("`'\"") for d in existing.split(",")]
                        if add_review_date not in dates:
                            dates.append(add_review_date)
                    else:
                        dates = [add_review_date]
                else:
                    dates = [add_review_date]
                dates_str = ", ".join(f"`{d}`" for d in dates)
                section[k] = f"- **Revisiones**: [{dates_str}]"
                modified = True
                break

    # Add finding
    if add_finding:
        for k, line in enumerate(section):
            if line.strip().startswith("- **Findings**:"):
                current = line.strip()
                if add_finding not in current:
                    # Increment count and append ID
                    count_match = _re_module.search(r'(\d+)', current)
                    old_count = int(count_match.group(1)) if count_match else 0
                    # Rebuild with new info
                    section[k] = f"- **Findings**: {old_count + 1} ({add_finding})"
                    modified = True
                break

    if modified:
        lines[section_start:section_end] = section
        sm_path.write_text("\n".join(lines))


def _scope_master_update_coverage(protocol: str):
    """Recalculate and update the COVERAGE SUMMARY table in SCOPE_MASTER.md."""
    sm_path = _find_scope_master(protocol)
    if not sm_path:
        return

    text = sm_path.read_text()

    # Count states across all component entries
    states = {"DONE": 0, "SKIP": 0, "NOT_STARTED": 0, "IN_PROGRESS": 0}
    for match in _re_module.finditer(r'\*\*Estado\*\*:\s*`(\w+)', text):
        state_val = match.group(1).upper()
        if state_val == "DONE":
            states["DONE"] += 1
        elif state_val.startswith("SKIP"):
            states["SKIP"] += 1
        elif state_val == "NOT_STARTED":
            states["NOT_STARTED"] += 1
        elif state_val == "IN_PROGRESS":
            states["IN_PROGRESS"] += 1

    total = sum(states.values())
    reviewed = states["DONE"] + states["SKIP"]

    # Update the Coverage line if it exists
    coverage_pattern = _re_module.compile(r'\*\*Coverage\*\*:.*')
    new_coverage = f"**Coverage**: {reviewed}/{total} revisados ({int(100*reviewed/total) if total else 0}%) — {states['DONE']} DONE + {states['SKIP']} SKIP"

    if coverage_pattern.search(text):
        text = coverage_pattern.sub(new_coverage, text)
        sm_path.write_text(text)


def scope_master_on_complete(protocol: str, component: str):
    """Called when a component passes the 'complete' gate.
    Updates state to DONE and adds today's date as a review."""
    today = datetime.now().strftime("%Y-%m-%d")
    _scope_master_update_component(protocol, component,
                                    new_state="DONE",
                                    add_review_date=today)
    _scope_master_update_coverage(protocol)
    print(f"  📋 SCOPE_MASTER updated: {component} → DONE (reviewed {today})")


def scope_master_on_review(protocol: str, component: str):
    """Called when a component is re-reviewed (not first time).
    Adds today's date as an additional review without changing state."""
    today = datetime.now().strftime("%Y-%m-%d")
    _scope_master_update_component(protocol, component,
                                    add_review_date=today)
    print(f"  📋 SCOPE_MASTER updated: {component} — re-review {today}")


def scope_master_on_finding(protocol: str, component: str, finding_id: str):
    """Called when a finding is registered for a component."""
    _scope_master_update_component(protocol, component,
                                    add_finding=finding_id)
    print(f"  📋 SCOPE_MASTER updated: {component} — finding {finding_id}")


def show_scope_status():
    """Show SCOPE_MASTER summary for the current program."""
    state = load_state()
    protocol = state.get("protocol", "")
    sm_path = _find_scope_master(protocol)

    if not sm_path:
        print(f"⛔ No SCOPE_MASTER.md found for protocol '{protocol}'")
        print(f"  Create one at: {SCOPE_MASTER_DIR / protocol / 'SCOPE_MASTER.md'}")
        print(f"  Template: {SCOPE_MASTER_DIR / 'SCOPE_MASTER_TEMPLATE.md'}")
        sys.exit(1)

    text = sm_path.read_text()

    # Extract components and their states
    print(f"\n{'#'*60}")
    print(f"  SCOPE MASTER: {sm_path.parent.name}")
    print(f"  File: {sm_path}")
    print(f"{'#'*60}")

    # Parse all component entries — Estado must be on the NEXT line after heading
    entries = []
    for match in _re_module.finditer(
        r'#{2,4}\s+(?:[A-Z]\d+[\-.]\s+|T0-\d+[\-.]\s+)?(.+?)\n'
        r'- \*\*Estado\*\*:\s*`([^`]+)`\n'
        r'- \*\*Revisiones\*\*:\s*\[([^\]]*)\]',
        text
    ):
        name = match.group(1).strip()
        estado = match.group(2).strip()
        revisiones = match.group(3).strip()
        # Count reviews
        rev_count = len([r for r in revisiones.split(",") if r.strip()]) if revisiones else 0
        # Last review date
        if revisiones:
            last_rev = [r.strip().strip("`'\"") for r in revisiones.split(",")][-1]
        else:
            last_rev = "never"
        entries.append((name[:35], estado, rev_count, last_rev))

    if entries:
        print(f"\n  {'Component':<37} {'Estado':<14} {'Reviews':<8} {'Last Review'}")
        print(f"  {'-'*37} {'-'*14} {'-'*8} {'-'*12}")
        for name, estado, rev_count, last_rev in entries:
            estado_display = f"{'✅' if estado == 'DONE' else '⏭️' if estado.startswith('SKIP') else '🔴' if estado == 'NOT_STARTED' else '🟡'} {estado}"
            print(f"  {name:<37} {estado_display:<14} {rev_count:<8} {last_rev}")

    # Summary
    states = {"DONE": 0, "SKIP": 0, "NOT_STARTED": 0, "IN_PROGRESS": 0}
    for _, estado, _, _ in entries:
        s = estado.upper()
        if s == "DONE":
            states["DONE"] += 1
        elif s.startswith("SKIP"):
            states["SKIP"] += 1
        elif s == "NOT_STARTED":
            states["NOT_STARTED"] += 1
        else:
            states["IN_PROGRESS"] += 1

    total = len(entries)
    reviewed = states["DONE"] + states["SKIP"]
    print(f"\n  Coverage: {reviewed}/{total} ({int(100*reviewed/total) if total else 0}%)")
    print(f"  DONE={states['DONE']} | SKIP={states['SKIP']} | IN_PROGRESS={states['IN_PROGRESS']} | NOT_STARTED={states['NOT_STARTED']}")

    # Findings count
    finding_matches = _re_module.findall(r'\|\s*\w+-\w+-\d+\s*\|', text)
    if finding_matches:
        print(f"  Findings tracked: {len(finding_matches)}")

    # Stale components (last review > 14 days ago)
    today = datetime.now()
    stale = []
    for name, estado, rev_count, last_rev in entries:
        if estado == "DONE" and last_rev != "never":
            try:
                last_date = datetime.strptime(last_rev, "%Y-%m-%d")
                days_ago = (today - last_date).days
                if days_ago > 14:
                    stale.append((name, days_ago))
            except ValueError:
                pass
    if stale:
        print(f"\n  ⚠️  STALE COMPONENTS (>14 days since review):")
        for name, days in sorted(stale, key=lambda x: -x[1]):
            print(f"    {name} — {days} days ago")
