"""Finding queue management: pending_pipeline → in_pipeline → completed → moved_to_findings."""

from datetime import datetime

from state_manager import load_state, save_state as _sm_save_state
from gate.scope_master import scope_master_on_finding


# ─── Finding Queue ───────────────────────────────────────────────────────────

def _save_state(state: dict):
    """Write current_hunt.json atomically (delegates to state_manager)."""
    _sm_save_state(state)


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

    # Auto-update SCOPE_MASTER with new finding
    protocol = state.get("protocol", "")
    if protocol and component:
        scope_master_on_finding(protocol, component, fid)

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


__all__ = [
    "_save_state",
    "generate_queue_id",
    "queue_finding",
    "list_queue",
    "queue_update",
    "queue_promote",
]
