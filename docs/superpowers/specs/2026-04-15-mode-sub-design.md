# `--mode sub` — Subscription-Based Agentic Benchmark Mode

## Problem

The benchmark system has three execution modes:

| Mode | Auth | Orchestrator | Enforcement | Cost |
|------|------|-------------|-------------|------|
| `--mode api` | API key ($) | Python loop | Perfect | $5-20/run |
| `--mode agent` | Subscription | Claude reads plan JSON | Weak (Claude skips steps) | $0 |

`--mode api` works well but costs money per token. `--mode agent` is free but unreliable because Claude interprets a 47-step plan and can deviate, skip steps, or hallucinate completion.

## Solution

Replace `--mode agent` with `--mode sub`: same Python orchestrator as `--mode api`, but invoking `claude -p` without `ANTHROPIC_API_KEY` so it uses the Claude Code subscription. Selective steps get tool access (`--allowedTools`) for agentic exploration.

**Validated by PoC** (this session):
- `claude -p` without API key: works, uses subscription, $0
- Sonnet + subscription + tools (Read/Write/Grep/Glob/Bash): works, 14.7s for simple, 169s for full hunter
- 12 parallel `claude -p` without API key: 12/12 OK (rate limit recovers after cooldown)
- MathHunter with tools autonomously explored hooks/, found dependencies via Grep, wrote YAML with real line numbers

## Architecture

```
run_benchmark.py main()
  |
  +-- --mode api  -> run_claude()     [existing, unchanged]
  |                  uses ANTHROPIC_API_KEY, stream-json, stall detection
  |
  +-- --mode sub  -> run_claude_sub() [NEW]
                     strips ANTHROPIC_API_KEY, uses --model sonnet,
                     text output, hard timeout only,
                     selective --allowedTools for agentic steps
```

Both modes share the same Python orchestrator loop, same gates, same scoring, same output format.

## CLI Changes

### Removed
- `--mode agent` — eliminated entirely

### New default values for `--mode sub`
- `--parallel-hunters 6` — new flag, default 6, configurable (subscription rate limits are tighter than API)
- `--model sonnet` — used for all `claude -p` calls in sub mode

### Unchanged
- `--mode api` — identical to current behavior
- All other flags (`--fast`, `--benchmark-mode`, `--parallel-components`, etc.)

## `run_claude_sub()` — New Function

```python
def run_claude_sub(prompt: str, agentic: bool = False, timeout: int = 1800,
                   log_file: Path = None, cwd: str = None,
                   model: str = "sonnet") -> tuple[int, str]:
    """Run claude -p using subscription (no API key), text output mode.

    When agentic=True, passes --allowedTools so Claude can use
    Read/Write/Grep/Glob/Bash to explore code autonomously.
    """
    env = os.environ.copy()
    env.pop("CLAUDECODE", None)
    env.pop("ANTHROPIC_API_KEY", None)

    cmd = ["claude", "-p", prompt,
           "--model", model,
           "--permission-mode", "bypassPermissions"]
    if agentic:
        cmd += ["--allowedTools", "Read,Write,Grep,Glob,Bash"]

    # Text output, hard timeout only (no stall detection needed for subscription)
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True, cwd=cwd or str(WEB3_DIR)
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return proc.returncode, stdout.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait()
        return 1, "TIMEOUT"
```

Key differences from `run_claude()`:
- Strips `ANTHROPIC_API_KEY` from env
- Uses `--model sonnet` (not whatever is default)
- Text output format (no stream-json — it stalls with Sonnet + subscription)
- No stall detection — hard timeout only
- No semaphore (concurrency controlled by `--parallel-hunters` at call site)
- `--permission-mode bypassPermissions` for tool access

## Step Classification: Agentic vs Stateless

| Step | Agentic | Tools | Timeout | Why |
|------|---------|-------|---------|-----|
| Hunters (x12) | Yes | Read,Write,Grep,Glob,Bash | 1800s | Explore code, search dependencies, find patterns |
| DeepDive | Yes | Read,Write,Grep,Glob,Bash | 1800s | Read convergences + explore cross-function state |
| PoC generation | Yes | Read,Write,Bash | 900s | Write test files + compile |
| PoC fix | Yes | Read,Write,Bash | 600s | Read errors + fix + recompile |
| Cross-component | Yes | Read,Write,Grep,Glob,Bash | 1000s | Explore interactions between contracts |
| Verification | No | none | 120s | Evaluates a defined finding — no exploration needed |
| Escalation | No | none | 180s | Evaluates severity — no exploration needed |
| RedTeam | No | none | 300s | Attacks a defined finding — no exploration needed |
| Triage | No | none | 180s | Classifies — no exploration needed |
| Scoring | No | none | 120s | Pure evaluation |

## Parallelism

### Hunter parallelism
- New flag: `--parallel-hunters N` (default 6)
- Controls how many hunter `claude -p` subprocesses run simultaneously
- Uses `ThreadPoolExecutor(max_workers=N)` at call site — no global semaphore
- Rationale: subscription rate limits are tighter than API Tier 4; 6 is conservative, user can increase

### Component parallelism
- `--parallel-components` unchanged (default 2, uses git worktrees)
- Total concurrent `claude -p` calls = parallel-components x parallel-hunters = 2 x 6 = 12 max
- Within safe range based on PoC tests (12/12 OK)

## Integration Point: Switching Between Modes

In the orchestrator functions (`phase_hunters`, `phase_deepdive`, `phase_findings`, etc.), each `run_claude()` call gets a parallel `run_claude_sub()` path:

```python
# Existing pattern:
code, output = run_claude(prompt, timeout=1800, ...)

# New pattern:
if use_sub_mode:
    code, output = run_claude_sub(prompt, agentic=True, timeout=1800, ...)
else:
    code, output = run_claude(prompt, timeout=1800, ...)
```

A module-level flag `USE_SUB_MODE` is set in `main()` based on `args.mode == "sub"`.

## v10 Injection (Both Modes)

Since we're touching the hunter prompt path, inject v10 improvements into `build_hunter_brief()` — this benefits both `--mode api` and `--mode sub`:

1. **Rejection context** — call `load_rejection_context()` from `run_hunt.py`, append to brief
2. **Few-shot examples** — call `load_few_shot_examples()` per hunter domain, append to brief
3. **CoT 5-step reasoning** — add structured reasoning instructions to brief
4. **poc_sketch requirement** — add to YAML template in brief

These functions already exist in `run_hunt.py`. Import and call them from `build_hunter_brief()` in `run_benchmark.py`.

## Files Changed

| File | Change |
|------|--------|
| `run_benchmark.py` | Add `run_claude_sub()`, add `--parallel-hunters` flag, remove `--mode agent`, add `USE_SUB_MODE` branching, v10 injection in `build_hunter_brief()` |
| `run_benchmark.py` | Remove agent mode code path in `main()` (lines 3377-3419) |

## Files NOT Changed

- `plan_generator.py` — dead code after removing `--mode agent`, leave as-is for now
- `plan_schema.py` — same
- `run-benchmark-agent/SKILL.md` — same
- `run_hunt.py` — no changes, only imports from it
- `merge_invariants.py`, `detection_engine.py` — untouched

## Success Criteria

1. `python3 run_benchmark.py --mode sub --repo X --components Y --protocol Z` runs the full pipeline using subscription
2. Hunters use Read/Grep/Glob to explore code autonomously (visible in logs)
3. Hunters write YAML with real line numbers from actual code reads
4. All gates pass identically to `--mode api`
5. No `ANTHROPIC_API_KEY` used (verify by checking subprocess env)
6. `--mode api` still works unchanged
7. `--parallel-hunters 6` throttles concurrent hunter calls

## Non-Goals

- Removing `plan_generator.py` / `plan_schema.py` / `run-benchmark-agent` — cleanup later
- Changing the prompt content for any step (except v10 injection in `build_hunter_brief()`)
- Changing output format (YAML, JSON, directory structure)
- Rate limit retry logic — if we hit limits, reduce `--parallel-hunters`
