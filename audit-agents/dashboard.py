"""Real-time TUI dashboard for the audit pipeline.

Reads hunt_session JSONs + orchestrator.log and renders a live rich view.
Run: python3 audit-agents/dashboard.py [--protocol NAME]
"""
from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

WEB3_DIR = Path(__file__).resolve().parent.parent
HUNT_SESSION = WEB3_DIR / "hunt_session"
CURRENT_HUNT = HUNT_SESSION / "MEMORY" / "STATE" / "current_hunt.json"


def load_current_hunt() -> dict[str, Any]:
    """Read current_hunt.json. Return {} if missing or malformed."""
    try:
        return json.loads(CURRENT_HUNT.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


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


def aggregate_findings_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


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
        active_step=None,
        findings_total=len(findings),
        findings_by_severity=severity_counts,
        recent_events=[],
    )


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
        parts = line.split("|", 1)
        if len(parts) == 2:
            header, msg = parts[0].strip(), parts[1].strip()
            tokens = header.split()
            ts = tokens[1] if len(tokens) >= 2 else header
        else:
            ts, msg = "", line.strip()
        matched.append((ts, "", msg))

    return matched[-max_events:], new_offset


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
