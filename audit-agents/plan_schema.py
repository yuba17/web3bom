"""
plan_schema.py — Execution plan schema for agent mode benchmark.

Defines the data structures used when --mode agent generates a JSON execution plan
instead of running Claude API calls directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Literal, ClassVar


@dataclass
class Step:
    """A single step in the execution plan."""

    id: str
    type: Literal["agent", "bash", "gate", "python", "generate"]
    description: str
    depends_on: list[str] = field(default_factory=list)
    retry: int = 0
    timeout: int = 120
    # agent steps
    prompt: str = ""
    tools: list[str] = field(default_factory=list)
    # bash / gate / python / generate steps
    cwd: str = ""
    command: str = ""
    # grouping
    parallel_group: str = ""

    # Fields that are considered "optional" and dropped when empty
    _OPTIONAL_FIELDS: ClassVar[set[str]] = {
        "retry",
        "timeout",
        "prompt",
        "tools",
        "cwd",
        "command",
        "parallel_group",
    }

    def to_dict(self) -> dict:
        """Return dict representation, dropping empty optional fields."""
        d: dict = {}
        d["id"] = self.id
        d["type"] = self.type
        d["description"] = self.description
        d["depends_on"] = self.depends_on

        # Include retry / timeout only when non-default
        if self.retry != 0:
            d["retry"] = self.retry
        if self.timeout != 120:
            d["timeout"] = self.timeout

        if self.prompt:
            d["prompt"] = self.prompt
        if self.tools:
            d["tools"] = self.tools
        if self.cwd:
            d["cwd"] = self.cwd
        if self.command:
            d["command"] = self.command
        if self.parallel_group:
            d["parallel_group"] = self.parallel_group

        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Step":
        return cls(
            id=d["id"],
            type=d["type"],
            description=d["description"],
            depends_on=d.get("depends_on", []),
            retry=d.get("retry", 0),
            timeout=d.get("timeout", 120),
            prompt=d.get("prompt", ""),
            tools=d.get("tools", []),
            cwd=d.get("cwd", ""),
            command=d.get("command", ""),
            parallel_group=d.get("parallel_group", ""),
        )


@dataclass
class ExecutionPlan:
    """Full execution plan produced by --mode agent."""

    version: str
    protocol: str
    repo: str
    session_dir: str
    hypotheses_dir: str
    components: list[str]
    is_pre_production: bool
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    steps: list[Step] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_step(self, step: Step) -> None:
        """Append a single step to the plan."""
        self.steps.append(step)

    def add_steps(self, steps: list[Step]) -> None:
        """Append multiple steps to the plan."""
        self.steps.extend(steps)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def _to_dict(self) -> dict:
        return {
            "version": self.version,
            "protocol": self.protocol,
            "repo": self.repo,
            "session_dir": self.session_dir,
            "hypotheses_dir": self.hypotheses_dir,
            "components": self.components,
            "is_pre_production": self.is_pre_production,
            "created_at": self.created_at,
            "steps": [s.to_dict() for s in self.steps],
        }

    def to_json(self, path: str) -> None:
        """Write the plan to *path* as pretty-printed JSON."""
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._to_dict(), fh, indent=2)

    @classmethod
    def from_json(cls, path: str) -> "ExecutionPlan":
        """Load an ExecutionPlan from a JSON file."""
        with open(path, "r", encoding="utf-8") as fh:
            d = json.load(fh)
        steps = [Step.from_dict(s) for s in d.get("steps", [])]
        return cls(
            version=d["version"],
            protocol=d["protocol"],
            repo=d["repo"],
            session_dir=d["session_dir"],
            hypotheses_dir=d["hypotheses_dir"],
            components=d.get("components", []),
            is_pre_production=d.get("is_pre_production", False),
            created_at=d.get("created_at", ""),
            steps=steps,
        )


# ---------------------------------------------------------------------------
# Topological batching
# ---------------------------------------------------------------------------

def topological_batches(steps: list[Step]) -> list[list[Step]]:
    """Group steps into sequential batches that respect dependency ordering.

    Rules
    -----
    * A step cannot execute before all its ``depends_on`` items are done.
    * ``depends_on`` entries of the form ``"parallel_group:X"`` mean: wait for
      ALL steps whose ``parallel_group == "X"`` to complete.
    * Steps that share a ``parallel_group`` are placed in the *same* batch so
      they can run concurrently.
    * Raises ``ValueError`` on circular dependencies (deadlock).
    """
    # Build lookup: id -> step
    by_id: dict[str, Step] = {s.id: s for s in steps}

    # Build lookup: group name -> set of step ids
    by_group: dict[str, set[str]] = {}
    for s in steps:
        if s.parallel_group:
            by_group.setdefault(s.parallel_group, set()).add(s.id)

    # Resolve depends_on for each step into a flat set of step IDs
    def resolve_deps(step: Step) -> set[str]:
        resolved: set[str] = set()
        for dep in step.depends_on:
            if dep.startswith("parallel_group:"):
                group_name = dep[len("parallel_group:"):]
                if group_name in by_group:
                    resolved.update(by_group[group_name])
                # If the group doesn't exist yet (e.g., forward reference)
                # we leave it — validate_plan() will catch it.
            else:
                resolved.add(dep)
        # A step must not depend on itself
        resolved.discard(step.id)
        return resolved

    step_deps: dict[str, set[str]] = {s.id: resolve_deps(s) for s in steps}

    # Kahn's algorithm
    in_degree: dict[str, int] = {s.id: 0 for s in steps}
    for sid, deps in step_deps.items():
        in_degree[sid] = len(deps)

    batches: list[list[Step]] = []
    remaining: dict[str, Step] = dict(by_id)

    while remaining:
        # Collect all steps with no unresolved dependencies
        ready_ids = {sid for sid, s in remaining.items() if in_degree[sid] == 0}

        if not ready_ids:
            cycle_ids = list(remaining.keys())
            raise ValueError(
                f"Deadlock detected in execution plan — circular dependency among steps: {cycle_ids}"
            )

        # Group ready steps by parallel_group so co-grouped steps land in the
        # same batch.  Steps without a group each form their own singleton, but
        # we merge them all into one batch level anyway (order within a batch
        # is not guaranteed).
        batch_steps: list[Step] = [remaining[sid] for sid in sorted(ready_ids)]
        batches.append(batch_steps)

        # Remove this batch from remaining and update in-degrees
        for sid in ready_ids:
            del remaining[sid]
        for sid in remaining:
            in_degree[sid] = len(step_deps[sid] - (set(by_id.keys()) - set(remaining.keys())))

    return batches


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_plan(plan: ExecutionPlan) -> list[str]:
    """Return a list of error strings (empty means the plan is valid).

    Checks
    ------
    * All ``depends_on`` entries reference existing step IDs or
      ``parallel_group:X`` for a group that exists in the plan.
    * Steps of type ``"agent"`` have a non-empty ``prompt``.
    * Steps of type ``"bash"``, ``"gate"``, ``"python"``, or ``"generate"``
      have a non-empty ``command``.
    """
    errors: list[str] = []

    existing_ids: set[str] = {s.id for s in plan.steps}
    existing_groups: set[str] = {s.parallel_group for s in plan.steps if s.parallel_group}

    for step in plan.steps:
        # Validate dependencies
        for dep in step.depends_on:
            if dep.startswith("parallel_group:"):
                group_name = dep[len("parallel_group:"):]
                if group_name not in existing_groups:
                    errors.append(
                        f"Step '{step.id}': depends_on references unknown parallel_group '{group_name}'"
                    )
            else:
                if dep not in existing_ids:
                    errors.append(
                        f"Step '{step.id}': depends_on references unknown step id '{dep}'"
                    )

        # Validate required fields per type
        if step.type == "agent":
            if not step.prompt:
                errors.append(f"Step '{step.id}' (agent): 'prompt' must not be empty")
        elif step.type in ("bash", "gate", "python", "generate"):
            if not step.command:
                errors.append(
                    f"Step '{step.id}' ({step.type}): 'command' must not be empty"
                )

    return errors
