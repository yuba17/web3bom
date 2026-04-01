# Benchmark Patterns

Patterns learned from real misses in benchmark runs. Each entry is anchored in a concrete bug.

## Lifecycle
1. Miss identified in benchmark → entry added with `instances_seen: 1`
2. Same pattern appears in another benchmark → `instances_seen` incremented
3. At `instances_seen >= 3` → `promoted_to_check: true` → becomes mandatory hunter check
4. Promoted patterns are added to the relevant hunter's structured output requirements

## Schema
- `class`: Abstract bug class name (reusable across protocols)
- `instance`: Concrete bug that spawned this pattern
- `detection_method`: static | llm_structured | llm_knowledge | process
- `hunter_responsible`: Which hunter should catch this class
- `generic_pattern`: One-sentence abstract description
- `grep_hint`: How to mechanically search for instances
