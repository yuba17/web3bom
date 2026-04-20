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
