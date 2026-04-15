#!/usr/bin/env python3
"""
run_benchmark.py — Pipeline orchestrator that enforces ALL steps for each component.

Runs the full hunt pipeline sequentially. No steps can be skipped.
Uses claude CLI (-p) for LLM analysis, subprocess for tools.

Usage:
    python3 run_benchmark.py \\
      --repo /path/to/repo \\
      --components Strategy,Leverager,Vault,LendingPool \\
      --protocol yieldoor \\
      --ground-truth benchmarks/yieldoor/benchmark.yaml

    python3 run_benchmark.py \\
      --repo /path/to/repo \\
      --components Strategy \\
      --protocol myprotocol \\
      --skip-phase3          # explicit flag required to skip fork PoC
"""

import argparse
import json
import os
import re
import select
import signal
import subprocess
import sys
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from finding_pipeline import (
    extract_fingerprint,
    dedup_findings as _dedup_findings_pure,
    collect_verify_candidates as _collect_verify_candidates_pure,
    dedup_for_poc as _dedup_for_poc_pure,
    extract_findings_from_yaml,
    extract_relevant_code as _extract_relevant_code_shared,
    build_verify_prompt as _build_verify_prompt_shared,
    build_is_same_bug_prompt as _build_is_same_bug_prompt_shared,
    format_funnel,
    POC_CONFIDENCE_THRESHOLD,
)

# ─── Global Claude concurrency limiter ───────────────────────────────────────
# Safety net against runaway concurrency bugs — NOT a rate-limit guard.
# Tier 4 API: 4K RPM / 2M input tok/min. Our peak: 2 components × 9 hunters =
# 18 calls × 8k tokens ≈ 144k tok/min = 7% of limit. API is NOT the bottleneck.
# Default 24: enough for 2×9 hunters (18) + 2×10 verification (20) fully parallel,
# while capping any accidental explosion. PoC concurrency is separately controlled
# by --parallel-poc (forge/RAM bound, not API bound).
_CLAUDE_SEMAPHORE = threading.Semaphore(
    int(os.environ.get("MAX_CLAUDE_CONCURRENT", "24"))
)

# Add audit-agents to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent))

# ─── Paths ───────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
WEB3_DIR = SCRIPT_DIR.parent
PROMPTS_DIR = SCRIPT_DIR / "prompts"
HUNT_SESSION_DIR = WEB3_DIR / "hunt_session"
# POC_CONFIDENCE_THRESHOLD imported from finding_pipeline
IS_PRE_PRODUCTION = False      # set in main() — changes PoC strategy to deploy-on-fork

# ─── Load .env if present ────────────────────────────────────────────────────
_env_file = WEB3_DIR / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            key, val = key.strip(), val.strip()
            if key and val and key not in os.environ:
                os.environ[key] = val

# ─── Logging ─────────────────────────────────────────────────────────────────

LOG_DIR = None  # set in main()
logger = logging.getLogger("orchestrator")


def setup_logging(protocol: str):
    global LOG_DIR
    timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
    # Keep logs inside the session dir so benchmark logs don't pollute WEB3_DIR/logs/
    LOG_DIR = HUNT_SESSION_DIR / "logs" / f"{protocol}_{timestamp}"
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(LOG_DIR / "orchestrator.log")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    # Flush stdout immediately so tee shows progress in real-time
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(stream_handler)
    logger.setLevel(logging.INFO)
    logger.info(f"Logging to {LOG_DIR}")
    sys.stdout.reconfigure(line_buffering=True)  # force line-buffered stdout


def component_log_dir(component: str) -> Path:
    d = LOG_DIR / component
    d.mkdir(parents=True, exist_ok=True)
    return d


def detect_pragma(repo: str) -> str:
    """Detect pragma from project source files."""
    repo_path = Path(repo)
    for d in [repo_path / "src", repo_path / "contracts", repo_path]:
        if not d.is_dir():
            continue
        for sol in sorted(d.glob("**/*.sol"))[:10]:
            try:
                for line in sol.read_text(encoding="utf-8").splitlines():
                    m = re.match(r'\s*(pragma\s+solidity\s+[^;]+;)', line)
                    if m:
                        return m.group(1)
            except Exception:
                continue
    return "pragma solidity ^0.8.0;"


# ─── Claude CLI ──────────────────────────────────────────────────────────────

def run_claude(prompt: str, allowed_tools: list = None, timeout: int = 1800,
               log_file: Path = None, cwd: str = None,
               stall_timeout: int = 600) -> tuple[int, str]:
    """Run claude CLI with stall detection via stream-json.

    Uses --output-format stream-json so Claude emits events incrementally.
    This enables two kill conditions:
    - Hard timeout: kill after `timeout` seconds no matter what
    - Stall detection: kill if no event received for `stall_timeout` seconds
      (first event gets 2x grace for startup warmup)

    If stream-json emits 0 events but the process exits cleanly, retries once
    with --output-format text as fallback.
    """
    base_cmd = ["claude", "-p", prompt]
    if allowed_tools:
        base_cmd += ["--allowedTools", ",".join(allowed_tools)]

    env = os.environ.copy()
    env.pop("CLAUDECODE", None)
    work_cwd = cwd or str(WEB3_DIR)

    logger.info(f"  Running claude -p ({len(prompt)} chars prompt)...")

    with _CLAUDE_SEMAPHORE:
        return _run_claude_inner(prompt, base_cmd, env, work_cwd, timeout, stall_timeout, log_file)


def _run_claude_inner(prompt: str, base_cmd: list, env: dict, work_cwd: str,
                      timeout: int, stall_timeout: int, log_file) -> tuple[int, str]:
    """Inner Claude execution — called while semaphore is held."""
    import json as _json

    # ── stream-json attempt ──────────────────────────────────────────
    cmd = base_cmd + ["--output-format", "stream-json", "--verbose"]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, cwd=work_cwd,
        start_new_session=True  # own process group so we can killpg() cleanly
    )

    text_result = []
    start_time = time.time()
    kill_reason = ""

    # Watchdog thread: kills the entire process group after hard timeout.
    # This is the ONLY reliable way to enforce timeouts — the main loop may
    # block on readline() or select() in edge cases.
    import threading
    _watchdog_fired = threading.Event()

    def _watchdog():
        if not _watchdog_fired.wait(timeout):
            # Timeout expired, kill process group
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    proc.kill()
                except Exception:
                    pass

    wd = threading.Thread(target=_watchdog, daemon=True)
    wd.start()

    try:
        # Read stream-json line by line (may block, but watchdog will kill if needed)
        for raw_line in proc.stdout:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                ev = _json.loads(line)
                if ev.get("type") == "assistant" and "message" in ev:
                    for blk in ev["message"].get("content", []):
                        if blk.get("type") == "text":
                            text_result.append(blk["text"])
                elif ev.get("type") == "result":
                    r = ev.get("result", "")
                    if r:
                        text_result.append(r)
            except (_json.JSONDecodeError, KeyError, TypeError):
                if line:
                    text_result.append(line)
    except Exception as e:
        kill_reason = str(e)

    # Signal watchdog to stop (process finished naturally)
    _watchdog_fired.set()

    # Check if watchdog killed the process
    elapsed = time.time() - start_time
    if elapsed >= timeout - 1:
        kill_reason = f"hard timeout ({timeout}s)"

    if kill_reason:
        # Kill entire process group (claude CLI + node + forge subprocesses)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    try:
        rem, err_bytes = proc.communicate(timeout=10)
        if rem:
            for raw in rem.decode("utf-8", errors="replace").splitlines():
                raw = raw.strip()
                if raw:
                    try:
                        ev = _json.loads(raw)
                        if ev.get("type") == "result":
                            text_result.append(ev.get("result", ""))
                    except (_json.JSONDecodeError, KeyError, TypeError):
                        text_result.append(raw)
        stderr = err_bytes.decode("utf-8", errors="replace") if err_bytes else ""
    except Exception:
        stderr = ""

    stdout_text = "\n".join(text_result)
    elapsed = time.time() - start_time

    # ── If killed → report and return ────────────────────────────────
    if kill_reason:
        logger.error(f"  Claude killed: {kill_reason} ({elapsed:.0f}s)")
        if log_file:
            log_file.write_text(
                f"=== PROMPT ===\n{prompt[:2000]}...\n\n"
                f"=== RUNTIME: {elapsed:.0f}s (KILLED: {kill_reason}) ===\n"
                f"=== STDOUT ({len(stdout_text)} chars) ===\n{stdout_text}\n\n"
                f"=== STDERR ===\n{stderr}\n", encoding="utf-8"
            )
        return 1, "TIMEOUT"

    # ── If stream-json produced 0 text → fallback to text mode ──────────
    # This handles: stream-json errors (--verbose required), empty responses, etc.
    if not stdout_text.strip():
        logger.info("  stream-json: 0 text output — retrying with text mode")
        try:
            text_cmd = base_cmd + ["--output-format", "text"]
            result = subprocess.run(
                text_cmd, capture_output=True, timeout=timeout,
                env=env, cwd=work_cwd, start_new_session=True
            )
            stdout_text = result.stdout.decode("utf-8", errors="replace")
            stderr = result.stderr.decode("utf-8", errors="replace")
            elapsed = time.time() - start_time
        except subprocess.TimeoutExpired:
            elapsed = time.time() - start_time
            logger.error(f"  Claude killed (text fallback): hard timeout ({elapsed:.0f}s)")
            if log_file:
                log_file.write_text(
                    f"=== PROMPT ===\n{prompt[:2000]}...\n\n"
                    f"=== RUNTIME: {elapsed:.0f}s (KILLED: text fallback timeout) ===\n"
                    f"=== STDOUT (0 chars) ===\n\n=== STDERR ===\n", encoding="utf-8"
                )
            return 1, "TIMEOUT"

    # ── Success ──────────────────────────────────────────────────────
    if log_file:
        log_file.write_text(
            f"=== PROMPT ===\n{prompt[:2000]}...\n\n"
            f"=== RUNTIME: {elapsed:.0f}s ===\n"
            f"=== STDOUT ({len(stdout_text)} chars) ===\n{stdout_text}\n\n"
            f"=== STDERR ===\n{stderr}\n", encoding="utf-8"
        )
    logger.info(f"  Claude finished in {elapsed:.0f}s ({len(stdout_text)} chars)")
    return proc.returncode or 0, stdout_text


# ─── Claude CLI (subscription mode) ─────────────────────────────────────────

def run_claude_sub(prompt: str, agentic: bool = False, timeout: int = 1800,
                   log_file: Path = None, cwd: str = None,
                   model: str = "sonnet") -> tuple[int, str]:
    """Run claude -p using subscription (no API key), text output mode.

    Strips ANTHROPIC_API_KEY from env to force subscription auth.
    When agentic=True, passes --allowedTools so Claude can use
    Read/Write/Grep/Glob/Bash to explore code autonomously.
    No stall detection — hard timeout only (text mode, not stream-json).
    """
    env = os.environ.copy()
    env.pop("CLAUDECODE", None)
    env.pop("ANTHROPIC_API_KEY", None)

    cmd = ["claude", "-p", prompt,
           "--model", model,
           "--permission-mode", "bypassPermissions"]
    if agentic:
        cmd += ["--allowedTools", "Read,Write,Grep,Glob,Bash"]

    work_cwd = cwd or str(WEB3_DIR)
    logger.info(f"  Running claude -p sub ({len(prompt)} chars, agentic={agentic})...")

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, start_new_session=True, cwd=work_cwd
    )

    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        text = stdout.decode("utf-8", errors="replace")
        if log_file:
            log_file.write_text(
                f"=== PROMPT ===\n{prompt[:2000]}...\n\n"
                f"=== RUNTIME: sub mode, agentic={agentic} ===\n"
                f"=== STDOUT ({len(text)} chars) ===\n{text}\n\n"
                f"=== STDERR ===\n{stderr.decode('utf-8', errors='replace')}\n",
                encoding="utf-8"
            )
        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            logger.warning(f"  claude -p sub exited {proc.returncode}: {err[:200]}")
        return proc.returncode, text
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        logger.warning(f"  claude -p sub TIMEOUT after {timeout}s")
        if log_file:
            log_file.write_text("TIMEOUT", encoding="utf-8")
        return 1, "TIMEOUT"


# ─── LLM dispatcher ─────────────────────────────────────────────────────────

USE_SUB_MODE = False  # Set in main() based on --mode sub
SUB_MODEL = "sonnet"  # Set in main()
PARALLEL_HUNTERS = 6  # Set in main() from --parallel-hunters

# Steps that get tool access in sub mode (agentic exploration).
_AGENTIC_TOOLS = {"Read", "Write", "Edit", "Grep", "Glob", "Bash", "Agent"}


def _llm(prompt: str, allowed_tools: list = None, timeout: int = 1800,
         log_file: Path = None, cwd: str = None,
         stall_timeout: int = 600) -> tuple[int, str]:
    """Dispatch to run_claude (API) or run_claude_sub (subscription)."""
    if not USE_SUB_MODE:
        return run_claude(prompt, allowed_tools=allowed_tools,
                          timeout=timeout, log_file=log_file, cwd=cwd,
                          stall_timeout=stall_timeout)

    agentic = bool(allowed_tools and set(allowed_tools) & _AGENTIC_TOOLS)
    return run_claude_sub(prompt, agentic=agentic, timeout=timeout,
                          log_file=log_file, cwd=cwd, model=SUB_MODEL)


# ─── Shell Commands ──────────────────────────────────────────────────────────

def run_cmd(cmd: list[str], timeout: int = 600, cwd: str = None,
            log_file: Path = None, env: dict = None) -> tuple[int, str, str]:
    """Run a shell command. Returns (exit_code, stdout, stderr).
    Uses process groups so timeout kills child processes too."""
    import os, signal
    logger.info(f"  Running: {' '.join(cmd[:5])}...")
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=cwd or str(WEB3_DIR), env=env,
            start_new_session=True  # creates new process group
        )
        stdout_bytes, stderr_bytes = proc.communicate(timeout=timeout)
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")

        if log_file:
            log_file.write_text(
                f"=== CMD: {' '.join(cmd)} ===\n"
                f"=== EXIT: {proc.returncode} ===\n"
                f"=== STDOUT ===\n{stdout}\n"
                f"=== STDERR ===\n{stderr}\n",
                encoding="utf-8"
            )

        return proc.returncode, stdout, stderr
    except subprocess.TimeoutExpired:
        # Kill entire process group (forge + solc children)
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, OSError):
            proc.kill()
        proc.wait(timeout=5)
        logger.error(f"  Command timed out ({timeout}s): {' '.join(cmd[:5])}")
        return 1, "", "TIMEOUT"


# ─── Fix-and-Retry ───────────────────────────────────────────────────────────

def _extract_first_errors(stderr: str, max_errors: int = 25, max_chars: int = 4000) -> str:
    """Extract first N unique errors from stderr, prioritizing root causes."""
    lines = stderr.splitlines()
    error_lines = []
    char_count = 0
    error_count = 0
    in_error = False

    for line in lines:
        is_error_start = line.strip().startswith("Error") or "error[" in line.lower() or "--> " in line
        is_context = line.strip().startswith("|") or line.strip().startswith("=")

        if is_error_start:
            in_error = True
            error_count += 1
            if error_count > max_errors:
                error_lines.append(f"\n... ({len(lines) - len(error_lines)} more lines, {error_count}+ errors total)")
                break

        if in_error and (is_error_start or is_context or line.strip() == ""):
            if char_count + len(line) > max_chars:
                error_lines.append(f"\n... (truncated at {max_chars} chars, {error_count} errors shown)")
                break
            error_lines.append(line)
            char_count += len(line)
            if line.strip() == "":
                in_error = False
        elif not in_error and is_error_start:
            in_error = True
            error_lines.append(line)
            char_count += len(line)

    return "\n".join(error_lines) if error_lines else stderr[-max_chars:]


def fix_and_retry(step_name: str, cmd: list[str], context_files: list[str],
                  max_retries: int = 5, cwd: str = None) -> bool:
    """
    Run a command. If it fails, ask Claude to fix it, then retry.
    Returns True if eventually succeeds.
    """
    log_dir = component_log_dir("_fix_retry")

    for attempt in range(max_retries):
        code, stdout, stderr = run_cmd(cmd, cwd=cwd)

        if code == 0:
            logger.info(f"  ✅ {step_name} passed (attempt {attempt + 1})")
            return True

        error_text = _extract_first_errors(stderr)
        logger.warning(f"  ❌ {step_name} failed (attempt {attempt + 1}/{max_retries})")

        if attempt < max_retries - 1:
            # Build fix prompt with escalation
            file_context = ""
            for f in context_files[:5]:  # max 5 files
                try:
                    content = Path(f).read_text(encoding="utf-8")
                    if len(content) > 10000:
                        content = content[:10000] + "\n... (truncated)"
                    file_context += f"\n\n### {f}\n```\n{content}\n```"
                except Exception:
                    pass

            escalation = ""
            if attempt >= 2:
                escalation = (
                    f"\n\nATTENTION: This is attempt {attempt + 1}/{max_retries}. "
                    f"Previous fixes did NOT resolve the issue. Read the errors more carefully. "
                    f"Common pitfalls: public struct getters return tuples (not structs), "
                    f"missing imports, interface vs concrete type mismatch."
                )

            fix_prompt = (
                f"Fix this {step_name} error. Edit the files to resolve it.\n\n"
                f"## Error (FIRST errors — these are the root causes)\n```\n{error_text}\n```\n\n"
                f"## Files\n{file_context}\n\n"
                f"Fix ONLY what's needed to resolve this error. Do not refactor.{escalation}"
            )

            _llm(
                fix_prompt,
                allowed_tools=["Read", "Edit", "Write", "Grep", "Glob"],
                timeout=120,
                log_file=log_dir / f"{step_name}_fix_{attempt}.log",
                cwd=cwd
            )

    logger.error(f"  🛑 {step_name} failed after {max_retries} attempts")
    return False


# ─── Pipeline Gate ───────────────────────────────────────────────────────────

def check_gate(component: str, gate: str, protocol: str, repo: str = "") -> bool:
    """Run pipeline_gate.py and return True if gate passes."""
    cmd = [
        sys.executable, str(SCRIPT_DIR / "pipeline_gate.py"),
        "-c", component, "--gate", gate, "--protocol", protocol,
        "--session-dir", str(HUNT_SESSION_DIR),
    ]
    if repo:
        cmd += ["--repo", repo]

    code, stdout, stderr = run_cmd(cmd)
    logger.info(f"  Gate {gate}: {'PASS' if code == 0 else 'FAIL'}")
    return code == 0


# ─── Prompt Loading ──────────────────────────────────────────────────────────

def load_prompt(template_name: str, context: dict) -> str:
    """Load and render a prompt template."""
    from prompt_renderer import render_prompt
    return render_prompt(template_name, context)


def read_source(src_path: str) -> str:
    """Read source file, truncate at 60K chars."""
    content = Path(src_path).read_text(encoding="utf-8")
    if len(content) > 60000:
        content = content[:60000] + "\n// ... truncated at 60K chars"
    return content


# ─── Prompt Builders (extracted for reuse by agent mode) ────────────────────

def build_hunter_brief(component: str, protocol: str, src_file, src_dir,
                       protocol_model: str, prepass_signals_text: str,
                       setup_sol_text: str, setup_var_names: str,
                       existing_tests_summary: str, knowledge_context: str,
                       interfaces_code: str, accumulated_context: str,
                       hyp_dir,
                       rejection_context: str = "",
                       few_shot_context: str = "") -> str:
    """Build the hunter brief content written to hunter_brief_{component}.md."""
    return (
        f"# Hunter Brief — {component} ({protocol})\n\n"
        f"## Source Files to Read\n"
        f"- Main contract: {src_file}\n"
        f"- Libraries: {src_dir / 'libraries'}/ (read ALL .sol files)\n\n"
        f"## Protocol Model\n{protocol_model[:3000] if protocol_model else 'Read the source to understand the protocol.'}\n\n"
        f"## Prepass Signals (static analysis findings)\n```yaml\n{prepass_signals_text[:4000] if prepass_signals_text else 'None'}\n```\n\n"
        f"## Chimera Setup (use these EXACT variable names in solidity_property)\n```solidity\n{setup_sol_text}\n```\n\n"
        f"## Dev Test Gaps (what the project's own tests MISSED)\n{existing_tests_summary[:2000] if existing_tests_summary else 'No analysis available.'}\n\n"
        f"## Known Vulnerability Patterns (from knowledge base)\n{knowledge_context[:2000] if knowledge_context else 'None loaded.'}\n\n"
        f"## Interfaces (function signatures the contract calls externally)\n```solidity\n{interfaces_code[:5000] if interfaces_code else 'None loaded.'}\n```\n\n"
        f"## Context from Previous Components\n{accumulated_context[:1500] if accumulated_context else 'This is the first component.'}\n\n"
        + (f"{rejection_context}\n\n" if rejection_context else "")
        + (f"{few_shot_context}\n\n" if few_shot_context else "")
        + f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
        f"Para cada hipotesis, razona estos 5 pasos ANTES de escribir el YAML:\n"
        f"1. Que HACE esta funcion? (inputs, outputs, estado modificado)\n"
        f"2. Que ASUME? (precondiciones implicitas, trust en callers)\n"
        f"3. Que pasa si la asuncion es FALSA? (estado corrupto, leak de fondos)\n"
        f"4. COMO puede un atacante forzar esa condicion? (flash loan, reentrancy, params extremos)\n"
        f"5. CUAL es el impacto concreto? (perdida en $, DoS permanente, escalacion de privilegios)\n\n"
        f"## OUTPUT RULES\n"
        f"1. Write YAML to ABSOLUTE PATH: {hyp_dir}/hyp_{component}_<YourHunterName>.yaml\n"
        f"   DO NOT use relative paths. DO NOT create hunt_session/ inside the repo.\n"
        f"2. Each hypothesis MUST have `solidity_property`: a COMPLETE Solidity function body\n"
        f"3. Use EXACT variable names from Setup.sol above: {setup_var_names}\n"
        f"4. Use Chimera assertion helpers: t(condition, \"msg\"), eq(a, b, \"msg\"), gte(a, b, \"msg\"), lte(a, b, \"msg\")\n"
        f"5. Confidence >= 60% for validated: true\n"
        f"6. Minimum 5 hypotheses, no maximum\n"
        f"7. YAML schema: id, tier, type, description, attack_scenario, solidity_property, validated, priority, confidence, vulnerable_location\n"
        f"   `vulnerable_location` is REQUIRED for every finding. Format:\n"
        f"   ```yaml\n"
        f"   vulnerable_location:\n"
        f"     contract: \"Strategy.sol\"\n"
        f"     function: \"_setSecondaryPositionsTicks\"  # the primary function where bug lives\n"
        f"     lines: [142, 143]                          # exact line numbers from the source\n"
        f"     vulnerable_code: \"tick = price() >> 1\"   # the exact wrong expression/statement\n"
        f"     fix: \"should use sqrtPriceX96 not spot price\"\n"
        f"   ```\n"
        f"   This is how manual auditors think — they know the EXACT LINE and EXACT CODE that's wrong.\n"
        f"   Do NOT write a vulnerable_location that just says 'the whole function' — be specific.\n"
        f"8. **TYPE RULE (CRITICAL)**: Setup.sol declares CONCRETE types, not interfaces.\n"
        f"   Look at Setup.sol variable declarations to know the exact type of each variable.\n"
        f"   In solidity_property, use the SAME type as declared in Setup.sol for struct access.\n"
        f"   WRONG: `IFoo.SomeStruct memory x = foo.getX()` (if Setup.sol says `Foo internal foo`)\n"
        f"   RIGHT: `Foo.SomeStruct memory x = foo.getX()` (matches the concrete type in Setup.sol)\n"
        f"   SAFEST: avoid struct type annotations — use tuple destructuring: `(uint a, uint b) = foo.getX()`\n"
        f"9. **STRUCT GETTER RULE (CRITICAL)**: Solidity auto-generates getters for public struct state variables that return TUPLES, not structs.\n"
        f"   WRONG: `contract.myStruct().field` — tuple has no named fields, this WILL NOT compile\n"
        f"   WRONG: `(a,b) = (contract.myStruct().x, contract.myStruct().y)` — same error\n"
        f"   RIGHT: `(uint a, uint b) = contract.myStruct();` — destructure the tuple\n"
        f"   RIGHT: `MyStruct memory s = contract.getMyStruct();` — if an explicit getter exists that returns the struct type\n"
        f"   Before using `.field` access, verify the contract has an explicit getter returning the struct type.\n"
        f"10. Example solidity_property:\n"
        f"   ```\n"
        f"   function property_vault_no_drain() public {{\n"
        f"       uint256 bal0 = token0.balanceOf(address(vault));\n"
        f"       t(bal0 > 0, \"Vault drained\");\n"
        f"   }}\n"
        f"   ```\n"
        f"11. Example vulnerable_location:\n"
        f"   ```yaml\n"
        f"   vulnerable_location:\n"
        f"     contract: \"Leverager.sol\"\n"
        f"     function: \"withdraw\"\n"
        f"     lines: [232]\n"
        f"     vulnerable_code: \"token1Amount = amountOut;\"  # amountOut is for token0, wrong for token1\n"
        f"     fix: \"compute token1Amount independently from token0 amountOut\"\n"
        f"   ```\n"
    )


def build_hunter_dispatch_prompt(component: str, protocol: str, src_file,
                                 src_dir, hunter_brief_path, hyp_dir) -> str:
    """Build the coordinator prompt that launches 12 hunters."""
    methodology_dir = Path(__file__).resolve().parent / "prompts" / "hunters"
    return f"""You are the Hunt Coordinator for {component} in {protocol}.

Your ONLY job: launch 12 hunter subagents in parallel using the Agent tool, then wait for all to complete.

## CRITICAL INSTRUCTION FOR EACH AGENT
Every agent prompt MUST follow this EXACT template (fill in [HunterName]):

"You are [HunterName] analyzing {component} in {protocol}.

Read these files FIRST before any analysis:
1. {hunter_brief_path} — protocol context, Setup.sol, prepass signals, output rules
2. {methodology_dir}/[HunterName].md — your hunting methodology, examples of real bugs to find, and key questions

Then read the source code: {src_file} and all .sol files in {src_dir / 'libraries'}/.

Follow your methodology file. Write YAML to {hyp_dir}/hyp_{component}_[HunterName].yaml"

Do NOT summarize or paraphrase the methodology — the agent MUST read the file itself.

## HYPOTHESIS QUALITY REQUIREMENTS
- Find ≥2 distinct bugs per public/external function analyzed, or explicitly state "no additional vulnerabilities found at confidence ≥60%".
- Do NOT include hypotheses with confidence < 55%. Quality over quantity.
- Do NOT generate low-confidence padding hypotheses.
- Each hypothesis MUST have a concrete poc_sketch with specific function calls and values.
- If a function has BOTH a prepass signal AND a hunter hypothesis → investigate deeply for HIDDEN secondary bugs in the same function.
- When 2+ hunters flag the same area (convergence), the DeepDive will investigate — but YOU should still try to find the deeper bug.

## The 12 Hunters (ALL in parallel, single message)
Launch using Agent tool with run_in_background=true for all except the last:

1. **MathHunter** — arithmetic, precision, share/exchange rate manipulation
2. **AccessHunter** — roles, modifiers, privilege escalation, initialization
3. **FlowHunter** — reentrancy, CEI, callbacks, state transitions, flash loans
4. **OracleHunter** — price feeds, TWAP manipulation, oracle staleness
5. **DomainHunter** — protocol invariants, symmetric inspection, value tracing
6. **TrustBoundaryHunter** — external call trust, weird ERC-20, proxy/upgrade
7. **WildcardHunter** — low-level EVM, composability, gas griefing
8. **SignatureHunter** — ecrecover, EIP-712, nonces, permit, replay
9. **DoSHunter** — unbounded loops, gas exhaustion, blocked withdrawals
10. **LogicHunter** — copy-paste bugs, wrong variables, sibling function diffs, symmetry
11. **AdversarialHunter** — attacker mindset, backward reasoning from value exits, assumption breaking
12. **LibraryHunter** — library function analysis: stale state, ignored returns, broken loops

Launch ALL 12 NOW in a single response."""


def build_deepdive_prompt(component: str, protocol: str, source_code: str,
                          library_code: str, setup_sol_text: str,
                          protocol_model: str, hyp_dir,
                          convergence_text: str, hunter_digest: str) -> str:
    """Build the DeepDiveHunter prompt."""
    return (
        f"You are DeepDiveHunter analyzing {component} of {protocol}.\n\n"
        f"## Source Code\n```solidity\n{source_code}\n```\n\n"
        f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
        f"## Chimera Setup (use these variable names in solidity_property)\n```solidity\n{setup_sol_text}\n```\n\n"
        f"## Protocol Model\n{protocol_model[:3000]}\n\n"
        f"## Pre-Digested Hunter Convergences\n{convergence_text or 'No convergences detected.'}\n\n"
        f"## Hunter Hypothesis Summary (tier 1-2 only)\n{hunter_digest[:8000]}\n\n"
        f"Write hypotheses to: {hyp_dir}/hyp_{component}_DeepDiveHunter.yaml\n"
        f"No artificial limit. Confidence >= 60% for validated: true.\n"
        f"Each solidity_property MUST be a complete function using variable names from Setup.sol.\n"
        f"Use Chimera helpers: t(condition, \"msg\"), eq(a, b, \"msg\"), gte(a, b, \"msg\")."
    )


build_verify_prompt = _build_verify_prompt_shared


def build_poc_prompt(finding: dict, fid: str, component: str,
                     relevant_code: str, interfaces_code: str,
                     setup_content: str, poc_path, test_name: str,
                     is_pre_production: bool) -> str:
    """Build the PoC generation prompt."""
    vuln_loc = finding.get("vulnerable_location") or {}
    vuln_loc_section = ""
    if vuln_loc:
        vuln_loc_section = (
            f"## EXACT VULNERABLE LOCATION (from hunter analysis)\n"
            f"Contract: {vuln_loc.get('contract', 'N/A')}\n"
            f"Function: `{vuln_loc.get('function', 'N/A')}`\n"
            f"Lines: {vuln_loc.get('lines', 'N/A')}\n"
            f"Vulnerable code: `{vuln_loc.get('vulnerable_code', 'N/A')}`\n"
            f"Fix: {vuln_loc.get('fix', 'N/A')}\n\n"
        )

    poc_hint_section = ""
    if finding.get("_poc_hint"):
        poc_hint_section = f"## Verification Hint (from code-read step)\n{finding['_poc_hint']}\n\n"

    return (
        f"Write a Foundry fork test that proves this vulnerability.\n\n"
        f"## Finding\n"
        f"ID: {fid}\n"
        f"Title: {finding.get('title', fid)}\n"
        f"Root Cause: {finding.get('root_cause', finding.get('description', ''))}\n"
        f"Component: {component}\n"
        f"Fuzz confirmed: {finding.get('fuzz_confirmed', False)}\n"
        f"Property that broke: {finding.get('property_name', 'N/A')}\n\n"
        f"{poc_hint_section}"
        f"## Counterexample Trace from Fuzzer\n"
        f"```\n{finding.get('counterexample_trace', 'No trace available')}\n```\n\n"
        f"{vuln_loc_section}"
        f"## Source Code (focused on vulnerable area)\n```solidity\n{relevant_code}\n```\n\n"
        f"## Interfaces (CRITICAL — use ONLY these function signatures)\n"
        f"```solidity\n{interfaces_code[:5000]}\n```\n\n"
        f"## Deployment Template (from test/chimera/Setup.sol)\n"
        f"```solidity\n{setup_content}\n```\n"
        f"COPY the deployment pattern above for your setUp(). It shows correct constructor args,\n"
        f"fork setup, and dependency initialization.\n\n"
        f"## STEP 0: Constraint Analysis (DO THIS BEFORE WRITING CODE)\n"
        f"Before writing any Solidity, read the source code and:\n"
        f"1. List EVERY require/revert/assert that could block your exploit path\n"
        f"2. For each constraint, determine the exact values that satisfy it\n"
        f"3. If a swap is needed: calculate the MAXIMUM amount that stays within protocol limits\n"
        f"4. If a call needs specific msg.sender: check if it's immutable/hardcoded (if yes, the bug may be unexploitable)\n"
        f"5. Design your PoC to satisfy ALL constraints while exploiting the bug\n\n"
        f"## Requirements\n"
        f"1. Write to: {poc_path}\n"
        f"2. Test function MUST be named `{test_name}`\n"
        f"3. Use ONLY ASCII characters in strings — NO em-dashes or curly quotes\n"
        f"4. Keep <16 local variables per function (avoid stack-too-deep)\n"
        + (
        f"5. DEPLOYMENT STRATEGY — PRE-PRODUCTION PROTOCOL (contracts NOT deployed on-chain):\n"
        f"   a) Use vm.createFork(vm.envString(\"BASE_RPC_URL\")) to get real token state (USDC, WETH, etc.)\n"
        f"   b) Deploy ALL protocol contracts yourself in setUp() using `new Contract(args)`\n"
        f"   c) Read constructor args from src/ — look for immutables and initializers\n"
        f"   d) Use vm.deal() to fund attacker with tokens, then interact with YOUR deployed contracts\n"
        f"   e) Do NOT try to call contracts at hardcoded addresses — they don't exist on-chain\n"
        if is_pre_production else
        f"5. Use vm.createFork with the deployed contract address — REAL fork state, not local deployment\n"
        ) +
        f"6. The test MUST prove CONCRETE DAMAGE — one of:\n"
        f"   a) Token balance loss: `assertGt(balanceBefore - balanceAfter, threshold)`\n"
        f"   b) State corruption: a storage value is wrong after the attack\n"
        f"   c) DoS: a critical function reverts when it shouldn't\n"
        f"   d) Privilege escalation: unauthorized caller can execute privileged action AND it persists\n"
        f"7. If the attack requires msg.sender == immutable_address, the bug is likely unexploitable — SKIP it.\n\n"
        f"## Workflow\n"
        f"1. Complete Step 0 constraint analysis (write it as a comment in the test)\n"
        f"2. Write the .sol file\n"
        f"3. Run: forge test --match-test {test_name} --match-path test/poc/{poc_path.name} -vvv --fuzz-runs 1\n"
        f"4. If it fails, read the error and fix the .sol file\n"
        f"5. Repeat until it passes or you've tried 3 times\n\n"
        f"Keep it minimal — just enough to prove the bug exists."
    )


def build_escalation_prompt(finding: dict, finding_context: str) -> str:
    """Build the EscalationHunter prompt."""
    return (
        f"You are EscalationHunter. Establish the severity CEILING for this finding.\n\n"
        f"{finding_context}\n\n"
        f"Execute ALL 5 checks in order. Even if the first is ESCALABLE, continue all 5.\n\n"
        f"### CHECK 1 — ESCAPE MECHANISMS (highest ROI)\n"
        f"Can the admin/protocol undo the damage once it occurs?\n"
        f"Look for: pause(), emergencyShutdown(), upgradeable proxies, rescue functions.\n"
        f"If NO escape mechanism AND impact is permanent → severity goes up one level.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + 2-line justification.\n\n"
        f"### CHECK 2 — SCOPE MULTIPLIER\n"
        f"Does a single attack execution affect 1 victim or N victims?\n"
        f"Does it affect all positions in a pool simultaneously? All lenders? Repeatable at ~0 marginal cost?\n"
        f"If 1 attack → N victims (all users of pool/vault) → severity goes up one level.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + victim count and why.\n\n"
        f"### CHECK 3 — PERMANENCE OF DAMAGE\n"
        f"Is damage temporary (reversible) or permanent?\n"
        f"Can a user recover funds? Can admin restore correct state? Does damage accumulate over time?\n"
        f"Permanent + no escape = +1 level. Temporary with mitigation window = no escalation.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + permanence description.\n\n"
        f"### CHECK 4 — COMBINATION WITH PRIOR FINDINGS\n"
        f"Combined with another confirmed finding in same protocol, does it produce greater impact?\n"
        f"Only escalate if combination produces qualitatively different impact (e.g., liquidation bypass + oracle manipulation = fund theft).\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] / [CONDICIONAL] + which finding and how.\n\n"
        f"### CHECK 5 — ATTACKER DIRECT (no permissions)\n"
        f"Can an unprivileged actor trigger the impact directly without admin or external event?\n"
        f"If any user can trigger with only capital → +1 level. If requires trusted role → no escalation.\n"
        f"Output: [ESCALABLE] / [NO_ESCALABLE] + who can trigger and how.\n\n"
        f"## REQUIRED OUTPUT FORMAT:\n"
        f"```\n"
        f"ESCALATION HUNTER REPORT\n"
        f"═════════════════════════\n"
        f"Finding: {finding.get('title', finding.get('id', '?'))}\n"
        f"Severidad propuesta: {finding['severity']}\n\n"
        f"CHECK 1 — Escape Mechanisms:    [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n"
        f"CHECK 2 — Scope Multiplier:     [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n"
        f"CHECK 3 — Permanencia del daño: [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n"
        f"CHECK 4 — Combinación:          [ESCALABLE/NO_ESCALABLE/CONDICIONAL]\n"
        f"  → [justification]\n"
        f"CHECK 5 — Attacker directo:     [ESCALABLE/NO_ESCALABLE]\n"
        f"  → [justification]\n\n"
        f"TECHO DE SEVERIDAD: [Critical/High/Medium]\n"
        f"ARGUMENTO PARA REDTEAM (3-5 lines): [concrete, technical, falsifiable]\n"
        f"CHECKS QUE ESCALARON: [...]\n"
        f"CHECKS QUE NO ESCALARON: [...]\n"
        f"```\n\n"
        f"Rules:\n"
        f"- Max 1 level escalation per check. Multiple checks REINFORCE the level, not raise further.\n"
        f"- If no check escalates → ceiling = original severity.\n"
        f"- The RedTeam argument MUST be falsifiable — if you can't describe how JUDGE could attack it, it's too vague.\n"
        f"- Don't access code not provided in the snippets. Mark as [CONDICIONAL: requires verifying X]."
    )


def build_redteam_prompt(finding_context: str, fid: str, finding: dict,
                         component: str) -> str:
    """Build the RedTeam prompt with 4 attackers."""
    return (
        f"You are the RedTeam moderator. Attack this finding aggressively to destroy it before reporting.\n\n"
        f"{finding_context}\n\n"
        f"## 4 ADVERSARIAL ATTACKERS\n\n"
        f"**[JUDGE]** — Platform judge (Sherlock/C4/Cantina/Immunefi)\n"
        f"Seeks formal rejection: out of scope, known issue, requires admin, by design.\n"
        f"In Ronda 0: would a platform judge assign this severity? Too high (inflated) or too low?\n\n"
        f"**[DEVIL]** — Technical devil's advocate\n"
        f"Attacks exploit logic: PoC doesn't prove real loss, oracle can't be manipulated this way, slippage protection blocks it.\n"
        f"In Ronda 0: technically verify the 5 severity checks. Can severity go UP or DOWN?\n\n"
        f"**[GUARD]** — Protocol defender\n"
        f"Finds existing mitigations: checks in callers, governance limits, rate limits, circuit breakers.\n"
        f"In Ronda 0: is there a rescue mechanism (multisig, timelock, proxy upgrade) that reduces permanent impact?\n\n"
        f"**[ECONOMIST]** — Economic analyst\n"
        f"Calculates attack profitability: gas, capital needed, MEV competition, timing windows.\n"
        f"In Ronda 0: how much real money at risk? $1K or $1M? Magnitude matters.\n\n"
        f"## SEVERITY CALIBRATION TABLE\n"
        f"| Scope (% affected ops) | Permanence | Path type | Severity |\n"
        f"|---|---|---|---|\n"
        f"| 100% (all users) | permanent (no admin fix) | normal operation | Critical or High |\n"
        f"| 100% | temporal (admin can fix) | normal operation | High |\n"
        f"| 50% (one token/path) | permanent | normal operation | High |\n"
        f"| 50% | temporal | requires specific config | Medium |\n"
        f"| 10% (edge case) | permanent | requires attack | Medium |\n"
        f"| 10% | temporal | requires attack | Low |\n\n"
        f"PRIOR CALIBRATION ERRORS:\n"
        f"- Fee loss in ALL liquidations → we said Medium, GT said High. Rule: 100% scope + permanent + normal path = High minimum.\n"
        f"- DoS only in denomination==token1 path → we said High, GT said Medium. Rule: 50% scope + permanent + normal = Medium/High boundary → Medium.\n\n"
        f"## PROTOCOL: RONDA 0 + 3 ROUNDS\n\n"
        f"### RONDA 0: Severity Calibration\n"
        f"All 4 attackers answer these 5 questions BRIEFLY. Severity can go UP or DOWN:\n"
        f"1. Escape mechanisms: can admin/protocol undo damage? No rescue + permanent → consider raising.\n"
        f"2. Scope: 1 victim or all pool/vault users? Systemic → raise. Single user → lower.\n"
        f"3. Permanence: reversible or permanent? Permanent → raise. Temporal with reaction window → lower.\n"
        f"4. Trigger: unprivileged attacker can execute directly? Yes → raise. Requires trusted role → lower.\n"
        f"5. Combination: adds to another confirmed finding for qualitatively greater impact?\n"
        f"Each attacker gives severity verdict in ONE line at end of Ronda 0.\n"
        f"If consensus that proposed severity is wrong → ADJUST BEFORE rounds 1-3.\n\n"
        f"### ROUND 1: First Attack (each attacker, max 150 words)\n"
        f"Each attacker identifies the STRONGEST argument against the finding. Only the best argument.\n\n"
        f"### ROUND 2: Cross-response\n"
        f"Are the other attackers correct? Or wrong? Can ally with or contradict each other.\n"
        f"If two attackers contradict → ambiguity signal, must resolve.\n\n"
        f"### ROUND 3: Individual Verdict (1 paragraph each)\n"
        f"Each attacker: KILL (finding doesn't survive) / WEAKEN (valid but lower severity) / SURVIVE (solid)\n\n"
        f"## REQUIRED FINAL OUTPUT:\n"
        f"```\n"
        f"VEREDITO REDTEAM\n"
        f"════════════════\n"
        f"Finding: {finding.get('title', finding.get('id', '?'))}\n"
        f"Componente: {component}\n\n"
        f"RESULTADO: [REPORT / REPORT_DOWNGRADED / DO_NOT_REPORT]\n\n"
        f"Argumentos que sobrevivieron:\n  [list]\n"
        f"Argumentos que lo debilitan:\n  [list]\n"
        f"Argumentos que fallaron (attackers equivocados):\n  [list]\n\n"
        f"Severidad propuesta:   {finding['severity']}\n"
        f"Severidad final:       [Critical/High/Medium/Low]\n"
        f"Razón del cambio:      [why up/down/same]\n"
        f"Confianza: [0-100%]\n\n"
        f"Qué añadir al reporte para sobrevivir review:\n  [specific points]\n"
        f"Qué NO incluir (weakens argument):\n  [list]\n"
        f"```\n\n"
        f"Rules:\n"
        f"- Attackers do NOT help the hunter — they try to KILL the finding.\n"
        f"- Specific arguments ONLY — 'could be by design' without citing code is INVALID.\n"
        f"- No authority arguments — 'OpenZeppelin audited this' is invalid unless you cite what they found.\n"
        f"- Hunter CANNOT respond during rounds.\n"
        f"- If all 4 say KILL → DO_NOT_REPORT, no exceptions.\n"
        f"- If 3 SURVIVE + 1 KILL → investigate the KILL argument deeply before reporting.\n\n"
        f"## REPORT vs REPORT_DOWNGRADED — use these exact criteria:\n"
        f"REPORT: the finding is valid at the proposed severity. Attackers found no fatal flaw and no severe overestimate.\n"
        f"REPORT_DOWNGRADED: the finding is valid but the severity is WRONG (too high) AND you can state the correct severity.\n"
        f"  → Only use DOWNGRADED if the severity deserves 1+ levels down (e.g., proposed High → correct Medium).\n"
        f"  → Do NOT use DOWNGRADED just because the finding is 'borderline' or 'context-dependent'.\n"
        f"  → If attackers couldn't kill it AND severity seems right → REPORT, not DOWNGRADED.\n"
        f"DO_NOT_REPORT: at least one attacker found a FATAL flaw (out of scope, requires trusted role, mitigated, impossible to trigger)."
    )


def build_variant_prompt(fid: str, finding_context: str, repo: str) -> str:
    """Build the VariantHunter prompt."""
    return (
        f"You are VariantHunter. A confirmed bug rarely appears only once. Search for variants systematically.\n\n"
        f"{finding_context}\n\n"
        f"## STEP 1: ROOT CAUSE STATEMENT\n"
        f"Write the root cause in this EXACT format:\n"
        f'> "This vulnerability exists because **[UNTRUSTED DATA]** reaches **[DANGEROUS OPERATION]** without **[REQUIRED PROTECTION]**."\n\n'
        f"Examples:\n"
        f'- "...because **slot0.sqrtPriceX96** reaches **amountOut calculation** without **using TWAP instead of spot price**"\n'
        f'- "...because **balanceOf(address(this))** reaches **share calculation** without **pre-operation snapshot**"\n\n'
        f"If you can't write it in this format, you don't understand the bug well enough.\n\n"
        f"## STEP 2: EXACT MATCH (Level 0)\n"
        f"Use Grep to search the EXACT code pattern of the bug.\n"
        f"MUST match ONLY the known instance (1 result). If 0: pattern is wrong. If >1: already have variant candidates.\n"
        f"Document: Level 0: <pattern>, Matches: N, Locations: [list]\n\n"
        f"## STEP 3: PROGRESSIVE ABSTRACTION (Levels 1-3)\n"
        f"Abstract ONE element at a time. After each, search and document.\n\n"
        f"**Level 1** — Variable names → wildcards:\n"
        f"Replace specific names with generic patterns.\n\n"
        f"**Level 2** — Function names → family:\n"
        f"Replace specific function with the family (e.g., withdraw → any function that sends tokens).\n\n"
        f"**Level 3** — Full structural pattern:\n"
        f"Combine multiple grep searches to find the structural pattern.\n\n"
        f"For EACH level document: Level N: <pattern>, Matches: N, New locations: [list]\n\n"
        f"## STEP 4: TRIAGE\n"
        f"For EACH location found in Levels 1-3 that is NOT the original:\n"
        f"- **TRUE VARIANT**: same root cause, same impact, different fix → NEW FINDING\n"
        f"- **SIMILAR PATTERN**: same structure but different context → INVESTIGATE\n"
        f"- **FALSE POSITIVE**: pattern matches but protection/context prevents it → DISCARD\n\n"
        f"## REQUIRED OUTPUT FORMAT:\n"
        f"```\n"
        f"# Variant Hunt — {fid}\n\n"
        f"## Root Cause Statement\n"
        f'"This vulnerability exists because..."\n\n'
        f"## Search Results\n"
        f"### Level 0 (exact match)\n"
        f"### Level 1 (variable abstraction)\n"
        f"### Level 2 (function family)\n"
        f"### Level 3 (structural)\n\n"
        f"## Triage\n"
        f"| Location | Level | Classification | Notes |\n\n"
        f"## Variants Found: X\n"
        f"```\n\n"
        f"Search ALL .sol files in {repo}/src/. Max 15 minutes."
    )


def build_report_prompt(finding_context: str, report_path) -> str:
    """Build the ReportWriter prompt."""
    return (
        f"You are ReportWriter. Convert a RedTeam-validated finding into a platform-ready report.\n\n"
        f"{finding_context}\n\n"
        f"## STEP 1 — PLATFORM: SHERLOCK\n"
        f"This is a Sherlock contest benchmark. Use the Sherlock template.\n\n"
        f"## STEP 2 — REDTEAM MAPPING\n"
        f"Extract from the finding context:\n"
        f"- Severidad final → Severity field\n"
        f"- Surviving arguments → Impact section (strongest ones)\n"
        f"- Weakening arguments → mention + counter in Impact\n"
        f"- What NOT to include → exclusion list (don't put in report)\n"
        f"- What to ADD → reinforce in Description or Impact\n"
        f"Only arguments that survived RedTeam go in the report.\n\n"
        f"## STEP 3 — ANTI-AI WRITING RULES (CRITICAL)\n"
        f"DO NOT use:\n"
        f"- Filler phrases: 'It is important to note', 'This could potentially lead to', 'It is worth mentioning'\n"
        f"- Hedging: 'may', 'could', 'might', 'potentially', 'in some cases' — the PoC proved it, no 'might'\n"
        f"- Passive voice: write 'the function lacks', 'an attacker calls', not 'it was found that'\n"
        f"- Symmetric structure: not all sections same length, not all paragraphs with 3 sentences\n"
        f"- Explaining the obvious: don't explain what liquidation is, what a gauge is — the judge knows\n"
        f"- Generic openings: start with the punch, not context\n\n"
        f"DO write like a senior auditor:\n"
        f"- First sentence already says what's broken and what happens\n"
        f"- Active voice, specific: 'withdraw() at line 224 has no try/catch'\n"
        f"- Asymmetric: section lengths follow complexity, not aesthetics\n"
        f"- Confident: no hedging, the PoC demonstrated it\n"
        f"- Technically specific: cite contract, line, exact variable\n\n"
        f"## SHERLOCK TEMPLATE:\n"
        f"```markdown\n"
        f"## Summary\n"
        f"[One sentence: who can do what, with what result]\n\n"
        f"## Vulnerability Detail\n"
        f"[Deep technical explanation. Sherlock values depth.\n"
        f"Include code with comments. Cite Sherlock severity criteria.]\n\n"
        f"## Impact\n"
        f"[Cite which Sherlock severity rule applies:\n"
        f"- High: direct loss without time limit or user interaction\n"
        f"- Medium: with specific conditions / temporary DoS]\n\n"
        f"## Code Snippet\n"
        f"```solidity\n"
        f"// [file]:[line]\n"
        f"[vulnerable snippet]\n"
        f"```\n\n"
        f"## Tool used\n"
        f"Manual Review\n\n"
        f"## Recommendation\n"
        f"[Fix with code]\n"
        f"```\n\n"
        f"## AFTER WRITING — MANDATORY REVIEW PASS:\n"
        f"Re-read line by line and eliminate:\n"
        f"- Any sentence starting with 'It is', 'This could', 'It is worth', 'As a result'\n"
        f"- Any 'may', 'could', 'might', 'potentially', 'in some cases'\n"
        f"- Any section where all sentences are approximately equal length\n"
        f"- Any paragraph with 3 bullets when one sentence would suffice\n"
        f"- Any sentence explaining something the judge already knows\n"
        f"- Any passive voice usable as active\n"
        f"If a section sounds like corporate documentation → rewrite it.\n\n"
        f"Write the report to: {report_path}\n"
        f"Use English for all content (Sherlock platform). Be specific with line numbers."
    )


def build_cross_pair_prompt(comp_a: str, comp_b: str, iface_a: str,
                            iface_b: str, cross_calls: str, src_dir,
                            pair_file) -> str:
    """Build the cross-component pair analysis prompt."""
    return (
        f"You are CrossComponentHunter. Analyze the interaction between {comp_a} and {comp_b}.\n\n"
        f"## {comp_a} Interface\n```solidity\n{iface_a}\n```\n\n"
        f"## {comp_b} Interface\n```solidity\n{iface_b}\n```\n\n"
        f"## Known cross-component call sites\n{cross_calls}\n\n"
        f"## Your task\n"
        f"For the {comp_a} × {comp_b} interaction surface:\n"
        f"1. What breaks if {comp_b} behaves unexpectedly at each call site in {comp_a}?\n"
        f"2. What breaks if {comp_a} behaves unexpectedly at each call site in {comp_b}?\n"
        f"3. Custody invariants: assets in {comp_a} XOR {comp_b} — can both hold the same asset?\n"
        f"4. Accounting desync: does {comp_a} track a value that {comp_b} can change without notifying {comp_a}?\n"
        f"5. Sequence-dependent state: does calling {comp_a} then {comp_b} differ from {comp_b} then {comp_a}?\n"
        f"6. If you need to read full source, use the Read tool on the .sol files in {src_dir}/\n\n"
        f"Write findings (YAML list) to: {pair_file}\n\n"
        f"YAML format — top-level key must be 'findings', each entry:\n"
        f"  - id: CROSS-{comp_a[:3].upper()}-{comp_b[:3].upper()}-001\n"
        f"    title: <one line>\n"
        f"    severity: High/Medium/Low\n"
        f"    confidence: 70\n"
        f"    description: <root cause>\n"
        f"    attack_scenario: <step by step>\n"
        f"    components: [{comp_a}, {comp_b}]\n"
    )


build_is_same_bug_prompt = _build_is_same_bug_prompt_shared


# ─── FoundryTester Wrapper Generator ────────────────────────────────────────

def _generate_foundry_tester_wrappers(chimera_dir: Path):
    """Scan PropertiesX.sol files for property_* functions and generate
    invariant_* wrappers in FoundryTester.sol so Foundry actually executes them."""

    foundry_tester = chimera_dir / "FoundryTester.sol"
    if not foundry_tester.exists():
        logger.warning("  FoundryTester.sol not found — cannot generate wrappers")
        return

    # Collect all property_* and check_* function names from Properties files
    prop_fns: list[str] = []
    for sol_file in sorted(chimera_dir.glob("Properties*.sol")):
        if sol_file.name in ("Properties.sol", "PropertiesAll.sol"):
            continue
        content = sol_file.read_text(encoding="utf-8")
        for m in re.finditer(r'function\s+(property_\w+|check_\w+)\s*\(', content):
            fn_name = m.group(1)
            if fn_name not in prop_fns:
                prop_fns.append(fn_name)

    if not prop_fns:
        logger.info("  No property_* functions found — keeping placeholder")
        return

    # Generate wrapper functions
    wrappers = []
    for fn in prop_fns:
        # Convert property_math_lev_01 → invariant_math_lev_01
        inv_name = fn.replace("property_", "invariant_").replace("check_", "invariant_")
        wrappers.append(
            f"    function {inv_name}() public {{\n"
            f"        {fn}();\n"
            f"    }}"
        )

    # Detect pragma from project
    pragma = detect_pragma(str(chimera_dir.parent.parent))

    # Rewrite FoundryTester.sol
    new_content = (
        "// SPDX-License-Identifier: UNLICENSED\n"
        f"{pragma}\n"
        "\n"
        'import {TargetFunctions} from "./TargetFunctions.sol";\n'
        "\n"
        "/// @notice Foundry invariant test entry point.\n"
        "/// @dev Auto-generated by run_benchmark.py — invariant_ wrappers call property_ functions.\n"
        "contract FoundryTester is TargetFunctions {\n"
        "\n"
        "    function setUp() public {\n"
        "        setup();\n"
        "        targetContract(address(this));\n"
        "    }\n"
        "\n"
        f"    // ─── {len(wrappers)} invariant wrappers (auto-generated) ────────────\n"
        "\n"
        + "\n\n".join(wrappers) + "\n"
        "}\n"
    )

    foundry_tester.write_text(new_content, encoding="utf-8")
    logger.info(f"  FoundryTester.sol: generated {len(wrappers)} invariant_ wrappers from {len(prop_fns)} property_ functions")


# ─── Pipeline Funnel Dashboard ──────────────────────────────────────────────

def _log_funnel(component: str,
                all_findings: list,
                verified: list,
                poc_candidates: list,
                poc_confirmed: list,
                redteam_report: list):
    """Log the pipeline funnel — hypothesis → verification → PoC → RedTeam."""
    text = format_funnel(component, len(all_findings), len(verified),
                         len(poc_candidates), len(poc_confirmed), len(redteam_report))
    for line in text.splitlines():
        logger.info(f"  {line}")


# ─── PoC Helpers (top-level so cross-component can reuse them) ───────────────

def _sanitize_sol_unicode(path: Path):
    """Replace Unicode chars that break solc (em-dash, curly quotes, etc.)."""
    if not path.exists():
        return
    txt = path.read_text(encoding="utf-8")
    replacements = {
        "\u2014": "--",   # em-dash
        "\u2013": "-",    # en-dash
        "\u2018": "'",    # left single curly
        "\u2019": "'",    # right single curly
        "\u201c": '"',    # left double curly
        "\u201d": '"',    # right double curly
        "\u2026": "...",  # ellipsis
    }
    changed = False
    for uchar, repl in replacements.items():
        if uchar in txt:
            txt = txt.replace(uchar, repl)
            changed = True
    if changed:
        path.write_text(txt, encoding="utf-8")
        logger.info(f"    Sanitized Unicode chars in {path.name}")


def _filter_errors_for_file(stderr: str, filename: str) -> str:
    """Extract only compile errors related to a specific file."""
    lines = stderr.splitlines()
    relevant = []
    capture = False
    for line in lines:
        if filename in line:
            capture = True
            relevant.append(line)
        elif capture and (line.startswith("  ") or line.startswith("    |")):
            relevant.append(line)
        else:
            capture = False
    return "\n".join(relevant) if relevant else stderr[-2000:]


def generate_and_test_poc(finding: dict, source_code: str, interfaces_code: str,
                          component: str, protocol: str, repo: str,
                          clog: Path, forge_env: dict,
                          poc_confidence_threshold: int = 65):
    """Generate and test a fork PoC for a single finding.
    Top-level so both run_component_pipeline and run_cross_component can call it."""
    fid = finding.get("id") or finding.get("title", "UNKNOWN")[:20].replace(" ", "-")

    if not finding.get("fuzz_confirmed") and not finding.get("has_poc") and finding.get("confidence", 0) < poc_confidence_threshold:
        logger.info(f"    {fid}: skipping PoC (not confirmed, confidence < {poc_confidence_threshold})")
        finding["has_poc"] = False
        return

    logger.info(f"    {fid}: Generating Fork PoC")
    poc_dir = Path(repo) / "test" / "poc"
    poc_dir.mkdir(parents=True, exist_ok=True)
    poc_path = poc_dir / f"PoC_{fid.replace('-', '_')}.t.sol"
    test_name = f"test_poc_{fid.replace('-', '_').lower()}"

    setup_content = ""
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    if setup_path.exists():
        setup_content = setup_path.read_text(encoding="utf-8")[:4000]

    relevant_code = _extract_relevant_code(source_code, "", finding)
    poc_prompt = build_poc_prompt(
        finding=finding, fid=fid, component=component,
        relevant_code=relevant_code, interfaces_code=interfaces_code,
        setup_content=setup_content, poc_path=poc_path, test_name=test_name,
        is_pre_production=IS_PRE_PRODUCTION
    )

    _llm(poc_prompt, allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
               timeout=900, log_file=clog / f"{fid}_poc_gen.log", cwd=repo)

    if not poc_path.exists():
        finding["has_poc"] = False
        return

    _sanitize_sol_unicode(poc_path)

    poc_rel = str(poc_path.relative_to(Path(repo)))
    poc_rc, _, poc_stderr = run_cmd(
        ["forge", "test", "--match-test", test_name, "--match-path", poc_rel,
         "-vvv", "--fuzz-runs", "1"],
        timeout=300, cwd=repo, log_file=clog / f"{fid}_poc_run.log", env=forge_env
    )
    if poc_rc == 0:
        logger.info(f"    {fid}: PoC PASSED — vulnerability confirmed!")
        finding["has_poc"] = True
        finding["poc_path"] = str(poc_path)
        return

    # One fix attempt
    logger.info(f"    {fid}: PoC failed, attempting fix...")
    file_errors = _filter_errors_for_file(poc_stderr, poc_path.name)
    poc_content = poc_path.read_text(encoding="utf-8")[:8000] if poc_path.exists() else ""
    _llm(
        f"Fix this Foundry PoC. Only fix compile/runtime errors, keep the attack logic.\n\n"
        f"## Error\n```\n{file_errors}\n```\n\n"
        f"## Current Code\n```solidity\n{poc_content}\n```\n\n"
        f"## Interfaces\n```solidity\n{interfaces_code[:5000]}\n```\n\n"
        f"File: {poc_path}\n"
        f"Fix it, then run: forge test --match-test {test_name} --match-path {poc_rel} -vvv --fuzz-runs 1\n"
        f"Use ONLY ASCII in strings.",
        allowed_tools=["Read", "Edit", "Bash"],
        timeout=600, log_file=clog / f"{fid}_poc_fix.log", cwd=repo
    )
    _sanitize_sol_unicode(poc_path)

    poc_rc2, _, _ = run_cmd(
        ["forge", "test", "--match-test", test_name, "--match-path", poc_rel,
         "-vvv", "--fuzz-runs", "1"],
        timeout=300, cwd=repo, env=forge_env
    )
    if poc_rc2 == 0:
        logger.info(f"    {fid}: PoC PASSED after fix!")
        finding["has_poc"] = True
        finding["poc_path"] = str(poc_path)
    else:
        logger.warning(f"    {fid}: PoC FAILED — finding unverified")
        finding["has_poc"] = False


# ─── Component Pipeline ─────────────────────────────────────────────────────

def run_component_pipeline(component: str, repo: str, protocol: str,
                           args: argparse.Namespace,
                           accumulated_context: str = "") -> dict:
    """Run the full pipeline for one component. Returns summary dict."""
    comp_start = time.time()
    logger.info(f"\n{'='*60}")
    logger.info(f"  🔍 COMPONENT: {component}")
    logger.info(f"{'='*60}")

    clog = component_log_dir(component)
    src_dir = Path(repo) / "src"
    chimera_dir = Path(repo) / "test" / "chimera"

    # Find source file
    src_files = list(src_dir.glob(f"{component}.sol"))
    if not src_files:
        src_files = list(src_dir.glob(f"**/{component}.sol"))
    if not src_files:
        logger.error(f"  Source file not found for {component}")
        return {"component": component, "status": "ERROR", "reason": "source not found"}

    src_file = src_files[0]
    source_code = read_source(str(src_file))

    # Also read library files in src/libraries/
    lib_dir = src_dir / "libraries"
    library_code = ""
    if lib_dir.exists():
        for lib_file in sorted(lib_dir.glob("*.sol")):
            lib_content = lib_file.read_text(encoding="utf-8")
            library_code += f"\n// === {lib_file.name} ===\n{lib_content}"

    summary = {"component": component, "gates": {}, "findings": [], "status": "OK"}

    # ─── Step -1: Clean slate ─────────────────────────────────────────────
    logger.info("  Step -1: Clean slate (reset chimera to git state)")

    # Save current chimera state for cross-component later
    import shutil
    comp_chimera_backup = clog / "chimera_backup"
    if chimera_dir.exists():
        # Backup compiled invariants from previous component (for cross-component)
        prev_props = list(chimera_dir.glob("Properties*.sol"))
        if prev_props and comp_chimera_backup.parent.exists():
            comp_chimera_backup.mkdir(exist_ok=True)
            for f in prev_props:
                shutil.copy2(f, comp_chimera_backup / f.name)

    # Reset chimera dir to git state — removes changes from previous components
    if chimera_dir.exists():
        code_git, tracked, _ = run_cmd(
            ["git", "ls-files", str(chimera_dir.relative_to(Path(repo)))],
            cwd=repo
        )
        if code_git == 0 and tracked.strip():
            run_cmd(["git", "checkout", "--", str(chimera_dir.relative_to(Path(repo)))], cwd=repo)
            logger.info("    Chimera dir reset to git state")

        # Remove generated Properties files from previous merge (untracked)
        for gen_file in chimera_dir.glob("Properties*.sol"):
            if gen_file.name != "Properties.sol":
                code_check, _, _ = run_cmd(
                    ["git", "ls-files", "--error-unmatch", str(gen_file.relative_to(Path(repo)))],
                    cwd=repo
                )
                if code_check != 0:  # untracked = generated
                    gen_file.unlink()
                    logger.info(f"    Removed generated {gen_file.name}")

    # Clean forge cache
    out_dir = Path(repo) / "out"
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
        logger.info("    Cleaned forge out/ cache")

    # Clean PoC directory from previous runs
    poc_clean_dir = Path(repo) / "test" / "poc"
    if poc_clean_dir.exists():
        for old_poc in poc_clean_dir.glob("PoC_*.t.sol"):
            old_poc.unlink()
        logger.info("    Cleaned test/poc/ from previous runs")

    # Step 0: Scope (init ficha) — skipped in benchmark mode.
    # run_hunt.py --init-ficha uses run_hunt.HUNT_SESSION_DIR (hardcoded to real hunt_session)
    # and cannot easily accept --session-dir without a larger refactor.
    # Benchmark pipelines never read the ficha back (scope gate is not checked here),
    # so skipping init-ficha is safe and avoids contaminating the real hunt_session/fichas/.
    logger.info("  Step 0: Ficha init skipped (benchmark mode — not needed)")

    # ─── Step 1: Prepass ─────────────────────────────────────────────────
    logger.info("  Step 1: Prepass (Slither + Aderyn + patterns)")
    code, _, _ = run_cmd([
        sys.executable, str(SCRIPT_DIR / "detection_engine.py"),
        "--prepass", "--source", str(src_dir), "--name", component,
        "--output", str(HUNT_SESSION_DIR / "results")
    ], log_file=clog / "prepass.log", cwd=repo)
    summary["gates"]["prepass"] = code == 0

    # protocol_model — not generated by Claude anymore (was Step 1.5, cut for speed)
    # Hunters read the code directly, which is what I did manually
    protocol_model = ""

    # ─── Step 1.6: Read project's existing tests (inline, no Claude call) ──
    # Include raw test content in hunter brief — hunters interpret it themselves
    existing_tests_summary = ""
    test_dir = Path(repo) / "test"
    if test_dir.exists():
        test_files = [f for f in test_dir.glob("*.sol") if "chimera" not in str(f)]
        for tf in sorted(test_files)[:3]:  # max 3 test files, raw content
            content = tf.read_text(encoding="utf-8")
            existing_tests_summary += f"\n// === {tf.name} ===\n{content[:3000]}\n"
        if existing_tests_summary:
            logger.info(f"  Loaded {len(test_files)} existing test files (raw, {len(existing_tests_summary)} chars)")

    # ─── Step 1.7: Load relevant knowledge base briefings ────────────────
    # Gap C: inject domain expertise from our 64 briefings
    knowledge_context = ""
    knowledge_dir = WEB3_DIR / "knowledge"
    if knowledge_dir.exists():
        # Auto-detect relevant briefings based on source code keywords
        code_lower = source_code.lower()
        relevant_briefings = []
        briefing_map = {
            "concentrated-liquidity.md": ["uniswapv3", "tickmath", "sqrtprice", "liquidity", "tick"],
            "yield-aggregator.md": ["vault", "strategy", "yield", "harvest", "compound"],
            "dex-amm.md": ["swap", "pool", "amm", "router", "slippage"],
            "lending-market-forks.md": ["lendingpool", "borrow", "collateral", "liquidat", "interest"],
            "liquidation-mechanics.md": ["liquidat", "health", "collateral", "undercollateral"],
            "flash-loan.md": ["flashloan", "flash", "callback"],
            "oracle.md": ["oracle", "pricefeed", "chainlink", "twap", "latestround"],
            "erc4626.md": ["erc4626", "shares", "converttoassets", "converttoshares"],
            "fee-distribution.md": ["fee", "collect", "distribute", "reward"],
        }
        for briefing_file, keywords in briefing_map.items():
            if any(kw in code_lower for kw in keywords):
                bp = knowledge_dir / briefing_file
                if bp.exists():
                    relevant_briefings.append(bp)

        for bp in relevant_briefings[:3]:  # max 3 briefings
            content = bp.read_text(encoding="utf-8")
            # Extract just the bug patterns (YAML sections with known vulns)
            knowledge_context += f"\n## Known bugs from {bp.name}:\n{content[:3000]}\n"
        if relevant_briefings:
            logger.info(f"  Loaded {len(relevant_briefings)} knowledge briefings: {[b.name for b in relevant_briefings[:3]]}")

    # ─── Step 1.8: Read interfaces ───────────────────────────────────────
    # Gap D: interfaces show what the contract expects from external deps
    interfaces_code = ""
    iface_dir = src_dir / "interfaces"
    if iface_dir.exists():
        for iface_file in sorted(iface_dir.glob("*.sol")):
            content = iface_file.read_text(encoding="utf-8")
            interfaces_code += f"\n// === {iface_file.name} ===\n{content}\n"
        if interfaces_code:
            logger.info(f"  Loaded {len(list(iface_dir.glob('*.sol')))} interface files")

    # ─── Step 1.9: Ensure Chimera Setup exists BEFORE hunters ──────────
    # Hunters need Setup.sol to know which variables exist (strategy, vault, etc.)
    # Without it, they write invariants that reference non-existent variables
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    if not setup_path.exists():
        logger.info("  Step 1.9: Generate Chimera Setup (needed for hunter context)")
        chimera_dir_early = Path(repo) / "test" / "chimera"
        chimera_dir_early.mkdir(parents=True, exist_ok=True)

        # Read project's own tests to understand deployment pattern
        existing_test_code = ""
        test_dir = Path(repo) / "test"
        if test_dir.exists():
            for tf in sorted(test_dir.glob("*.sol"))[:3]:
                content = tf.read_text(encoding="utf-8")
                existing_test_code += f"\n// === {tf.name} ===\n{content[:5000]}\n"

        # Read foundry.toml for remappings and compiler settings
        foundry_toml = ""
        foundry_path = Path(repo) / "foundry.toml"
        if foundry_path.exists():
            foundry_toml = foundry_path.read_text(encoding="utf-8")[:3000]

        setup_prompt = (
            f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
            f"## Source Code\n```solidity\n{source_code}\n```\n\n"
            f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
            f"## Interfaces\n```solidity\n{interfaces_code[:10000]}\n```\n\n"
            f"## Project's Own Tests (CRITICAL — shows how THEY deploy the contracts)\n"
            f"```solidity\n{existing_test_code[:8000]}\n```\n\n"
            f"## foundry.toml (remappings, compiler version)\n```toml\n{foundry_toml}\n```\n\n"
            f"Create these files in {chimera_dir_early}/:\n"
            f"- Setup.sol: abstract contract that deploys {component} with ALL its dependencies.\n"
            f"  COPY the deployment pattern from the project's own tests above — they know their constructor args.\n"
            f"  NEVER use vm.createSelectFork or fork in Phase 1 Setup.sol — Phase 1 uses MOCKS for fast feedback (0 RPC calls).\n"
            f"  For external contracts (Uniswap pools, oracles, tokens): deploy mock contracts that simulate their interface.\n"
            f"  Use forge's `deal()` for token balances. Use MockERC20 or `deal(address(token), user, amount)` for tokens.\n"
            f"  For Uniswap V3: create a minimal MockUniswapV3Pool that returns controlled slot0/observe/mint/burn values.\n"
            f"  Fork testing is ONLY for Phase 3 PoCs (individual tests, not invariant fuzzing).\n"
            f"  MUST define internal variables accessible by Properties: the main contract + tokens + actors.\n"
            f"  Example: `Strategy internal strategy; Vault internal vault; IERC20 internal token0;`\n"
            f"  Define actors: owner, user, depositor, attacker with distinct addresses.\n"
            f"  Do an initial deposit + rebalance so the system is in a realistic state.\n"
            f"  HELPER FUNCTIONS (CRITICAL): Add internal helper functions that wrap complex calls.\n"
            f"  For EVERY public/external function that returns a struct, create a getter helper.\n"
            f"  For EVERY function that requires setup (prank, approve, deal), create an action helper.\n"
            f"  Examples:\n"
            f"    `function _getTotalAssets() internal view returns (uint256) {{ return vault.totalAssets(); }}`\n"
            f"    `function _depositAs(address who, uint256 amt0, uint256 amt1) internal {{ vm.prank(who); vault.deposit(amt0, amt1, 0, 0); }}`\n"
            f"    `function _dealAndDeposit(address who, uint256 amt) internal {{ deal(address(token0), who, amt); vm.prank(who); vault.deposit(amt, 0, 0, 0); }}`\n"
            f"  This lets hunters write simple invariants without worrying about types or setup boilerplate.\n"
            f"  IMPORTS (CRITICAL): Import ALL contracts, interfaces, and libraries the component uses.\n"
            f"  Properties*.sol inherits from Setup, so everything you import here is available to hunters.\n"
            f"  If the component uses Strategy.sol + IStrategy.sol + TickMath.sol, import ALL of them.\n"
            f"  CONSTANTS: Define constants hunters will need:\n"
            f"    `uint256 internal constant DECIMALS0 = 8;  // WBTC`\n"
            f"    `uint256 internal constant DECIMALS1 = 6;  // USDC`\n"
            f"    `uint256 internal constant ONE_TOKEN0 = 10 ** DECIMALS0;`\n"
            f"    `uint256 internal constant ONE_TOKEN1 = 10 ** DECIMALS1;`\n"
            f"  If the protocol defines precision constants (WAD, RAY, PRECISION, BPS), re-expose them.\n"
            f"  ENUMS/STRUCTS: If the component uses enums or structs, add a comment listing them with their values:\n"
            f"    `// Status enum: 0=Inactive, 1=Active, 2=Paused`\n"
            f"    `// VestingPosition struct: (uint256 amount, uint256 start, uint256 end)`\n"
            f"  INTERNAL STATE GETTERS: If the component has internal state that's only accessible via public getters\n"
            f"  that return structs, create simple getters that return individual fields:\n"
            f"    `function _getPositionAmount(uint256 id) internal view returns (uint256) {{ return strategy.positions(id).amount; }}`\n"
            f"- BeforeAfter.sol: ghost variables for state tracking (inherits Setup)\n"
            f"- Properties.sol: empty base (inherits BeforeAfter) — hunters will fill this later\n"
            f"- TargetFunctions.sol: handlers for EACH public/external function with clamped inputs.\n"
            f"  Use `_clampBetween(amount, 1, type(uint128).max)` for amounts.\n"
            f"  Use `vm.prank(actor)` before external calls. Use `_pickActor(seed)` for random actor.\n"
            f"- FoundryTester.sol: inherits Properties, placeholder for invariant_* wrappers\n"
            f"- CryticTester.sol: inherits TargetFunctions + Properties for Medusa/Echidna\n\n"
            f"AFTER creating all files, run `forge build` to verify compilation.\n"
            f"If it fails, fix the errors and re-run until it compiles.\n"
            f"Use the EXACT same import paths and remappings from foundry.toml."
        )
        _llm(
            setup_prompt,
            allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
            timeout=1200,  # Increased: complex components (Leverager, LendingPool) need >600s
            log_file=clog / "chimera_setup_early.log",
            cwd=repo
        )
        if setup_path.exists():
            logger.info(f"  Setup.sol generated ({setup_path.stat().st_size} bytes)")
        else:
            logger.warning("  Setup.sol generation failed — hunters will work without it")

    # ─── Step 2: 9 Hunters (coordinator + context file on disk) ─────────
    logger.info("  Step 2: 12 Hunters (coordinator dispatches, shared context on disk)")

    hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)

    # Load prepass signals
    import yaml as _yaml
    prepass_signals_text = ""
    prepass_path = HUNT_SESSION_DIR / "results" / f"{component}_prepass.yaml"
    if prepass_path.exists():
        try:
            prepass_data = _yaml.safe_load(prepass_path.read_text())
            signals = prepass_data.get("prepass_signals", [])
            top_signals = [s for s in signals if s.get("severity") in ("high", "medium", "critical")][:30]
            if top_signals:
                prepass_signals_text = _yaml.dump(top_signals, default_flow_style=False)
                logger.info(f"  Loaded {len(top_signals)} prepass signals for hunters")
        except Exception as e:
            logger.warning(f"  Failed to load prepass signals: {e}")

    # Load Setup.sol for hunter context (helps write compilable invariants)
    setup_sol_text = ""
    setup_var_names = ""
    setup_path = Path(repo) / "test" / "chimera" / "Setup.sol"
    if setup_path.exists():
        setup_sol_text = setup_path.read_text()
        logger.info(f"  Loaded Setup.sol ({len(setup_sol_text.splitlines())} lines) for hunter context")
        # Extract variable names dynamically so hunters use the REAL names
        import re as _re
        # Match: Type internal varName  or  Type public varName
        var_matches = _re.findall(
            r'(?:internal|public)\s+(?:constant\s+)?(\w+)\s*[=;]',
            setup_sol_text
        )
        # Also match: address internal varName
        addr_matches = _re.findall(
            r'address\s+(?:internal|public)\s+(?:constant\s+)?(\w+)\s*[=;]',
            setup_sol_text
        )
        all_vars = list(dict.fromkeys(var_matches + addr_matches))  # dedupe, preserve order
        setup_var_names = ", ".join(all_vars) if all_vars else "strategy, vault, token0, token1, pool"
        logger.info(f"  Setup.sol variables: {setup_var_names}")

    # Write shared context to a file on disk — each hunter agent reads it
    # This guarantees every hunter gets full context regardless of coordinator behavior
    context_dir = HUNT_SESSION_DIR / "context" / f"{protocol}-bench"
    context_dir.mkdir(parents=True, exist_ok=True)
    hunter_brief_path = context_dir / f"{component}_hunter_brief.md"
    # Load v10 context for hunter brief (benefits both api and sub modes)
    try:
        from run_hunt import load_rejection_context as _load_rej
        _rejection_ctx = _load_rej()
    except Exception:
        _rejection_ctx = ""

    hunter_brief_content = build_hunter_brief(
        component=component, protocol=protocol, src_file=src_file,
        src_dir=src_dir, protocol_model=protocol_model,
        prepass_signals_text=prepass_signals_text,
        setup_sol_text=setup_sol_text, setup_var_names=setup_var_names,
        existing_tests_summary=existing_tests_summary,
        knowledge_context=knowledge_context, interfaces_code=interfaces_code,
        accumulated_context=accumulated_context, hyp_dir=hyp_dir,
        rejection_context=_rejection_ctx,
    )
    hunter_brief_path.write_text(hunter_brief_content, encoding="utf-8")
    logger.info(f"  Wrote hunter brief ({len(hunter_brief_content)} chars) to {hunter_brief_path}")

    # Coordinator prompt — lightweight, tells agents to read brief + methodology from disk
    hunter_dispatch_prompt = build_hunter_dispatch_prompt(
        component=component, protocol=protocol, src_file=src_file,
        src_dir=src_dir, hunter_brief_path=hunter_brief_path, hyp_dir=hyp_dir
    )

    t0 = time.time()

    if USE_SUB_MODE:
        # Sub mode: dispatch individual hunters in parallel from Python
        # Each hunter gets agentic tools to explore code autonomously
        from run_hunt import HUNTER_DOMAINS, load_rejection_context, load_few_shot_examples
        methodology_dir = SCRIPT_DIR / "prompts" / "hunters"

        def _run_single_hunter(hunter_name: str) -> str:
            domain_key = HUNTER_DOMAINS.get(hunter_name, ("general", ""))[0]
            rejection_ctx = load_rejection_context()
            few_shot_ctx = load_few_shot_examples(domain_key)

            prompt = (
                f"You are {hunter_name} analyzing {component} in {protocol}.\n\n"
                f"Read these files FIRST before any analysis:\n"
                f"1. {hunter_brief_path} -- protocol context, Setup.sol, prepass signals, output rules\n"
                f"2. {methodology_dir}/{hunter_name}.md -- your hunting methodology\n\n"
                f"Then read the source code: {src_file} and all .sol files in {src_dir / 'libraries'}/.\n\n"
                f"Follow your methodology file. Write YAML to {hyp_dir}/hyp_{component}_{hunter_name}.yaml\n\n"
                f"## Chain-of-Thought (OBLIGATORIO antes de cada hipotesis)\n"
                f"1. Que HACE esta funcion? (inputs, outputs, estado)\n"
                f"2. Que ASUME? (precondiciones implicitas)\n"
                f"3. Que pasa si la asuncion es FALSA?\n"
                f"4. COMO puede un atacante forzar esa condicion?\n"
                f"5. CUAL es el impacto concreto en fondos/acceso?\n\n"
                f"{rejection_ctx}\n{few_shot_ctx}"
            )
            _llm(prompt, allowed_tools=["Read", "Write", "Grep", "Glob", "Bash"],
                 timeout=1800,
                 log_file=clog / f"hunter_{hunter_name}.log",
                 cwd=repo)
            return hunter_name

        hunters = ["MathHunter", "AccessHunter", "FlowHunter", "OracleHunter",
                    "DomainHunter", "TrustBoundaryHunter", "WildcardHunter",
                    "SignatureHunter", "DoSHunter", "LogicHunter",
                    "AdversarialHunter", "LibraryHunter"]
        logger.info(f"  Sub mode: {len(hunters)} hunters, {PARALLEL_HUNTERS} parallel")
        failed_hunters = []
        with ThreadPoolExecutor(max_workers=PARALLEL_HUNTERS) as executor:
            future_to_hunter = {
                executor.submit(_run_single_hunter, h): h for h in hunters
            }
            for future in as_completed(future_to_hunter):
                hunter_name = future_to_hunter[future]
                try:
                    future.result()
                except Exception as e:
                    failed_hunters.append(hunter_name)
                    logger.warning(f"  Hunter {hunter_name} FAILED: {e} — continuing with remaining hunters")
        if failed_hunters:
            logger.warning(f"  {len(failed_hunters)} hunters failed: {failed_hunters}")
    else:
        # API mode: single coordinator dispatches 12 agents
        rc, out = _llm(
            hunter_dispatch_prompt,
            allowed_tools=["Agent", "Read", "Write", "Edit", "Grep", "Glob"],
            timeout=1800,
            log_file=clog / "hunters_dispatch.log",
            cwd=repo
        )

    elapsed = time.time() - t0
    logger.info(f"  12 Hunters completed ({elapsed/60:.1f}min)")

    # Create crosschain skip file
    skip_file = hyp_dir / f"hyp_{component}_CrossChainHunter.skip"
    if not skip_file.exists():
        skip_file.write_text("single-chain protocol")

    # Check hunters gate — in benchmark mode, verify YAML count directly
    # (pipeline_gate.py checks for solidity_property fields which benchmark hunters don't require)
    REQUIRED_HUNTERS = ["AccessHunter", "DomainHunter", "FlowHunter", "MathHunter",
                        "OracleHunter", "TrustBoundaryHunter", "WildcardHunter",
                        "SignatureHunter", "DoSHunter"]
    hyp_count = len(list(hyp_dir.glob(f"hyp_{component}_*.yaml")))
    MIN_REQUIRED_HUNTERS = 7  # allow up to 2 failures
    missing_hunters = [h for h in REQUIRED_HUNTERS
                       if not (hyp_dir / f"hyp_{component}_{h}.yaml").exists()]
    present_count = len(REQUIRED_HUNTERS) - len(missing_hunters)
    if present_count < MIN_REQUIRED_HUNTERS:
        logger.error(f"  BLOCKED: Only {present_count}/{len(REQUIRED_HUNTERS)} required hunters present "
                     f"(minimum {MIN_REQUIRED_HUNTERS}). Missing: {missing_hunters}")
        summary["status"] = "BLOCKED_HUNTERS"
        summary["gates"]["hunters"] = False
        return summary
    else:
        hunters_ok = True
        summary["gates"]["hunters"] = True
        if missing_hunters:
            logger.warning(f"  Gate hunters: PASS with degradation — {present_count}/{len(REQUIRED_HUNTERS)} "
                          f"required hunters present ({hyp_count} total YAML files). "
                          f"Missing: {missing_hunters}")
        else:
            logger.info(f"  Gate hunters: PASS ({hyp_count} YAML files, all {len(REQUIRED_HUNTERS)} required hunters present)")

    # Mandatory team output verification
    verify_result = subprocess.run([
        "python3", str(SCRIPT_DIR / "verify_team_outputs.py"),
        "--session-dir", str(Path(hyp_dir).parent.parent),
        "--protocol", protocol,
        "--groups", json.dumps([{"group_id": 0, "components": [component]}])
    ], capture_output=True, text=True)
    if verify_result.returncode != 0:
        logger.warning(f"  Team verification warnings:\n{verify_result.stdout[:500]}")

    # Step 3 (Library Analyzer) — now runs as LibraryHunter (#11) in parallel with other hunters above

    # ─── Step 4: DeepDive Hunter ────────────────────────────────────────
    logger.info("  Step 4: DeepDive Hunter")

    # Pre-digest hunter hypotheses: summarize convergences for DeepDive (Gap #5)
    import yaml as _yaml_dd
    hunter_digest = ""
    convergence_map = {}  # track which areas multiple hunters flagged
    for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml")):
        if "DeepDive" in hyp_file.name or "CrossChain" in hyp_file.name:
            continue
        try:
            data = _yaml_dd.safe_load(hyp_file.read_text())
            if not data:
                continue
            hunter_name = hyp_file.stem.replace(f"hyp_{component}_", "")
            hyps = data.get("hypotheses", data.get("invariants", []))
            for h in hyps:
                if h.get("confidence", 0) >= 50 and h.get("tier", 3) <= 2:
                    desc = h.get("description", h.get("title", ""))
                    area = h.get("type", "unknown")
                    hunter_digest += f"- [{hunter_name}] (tier={h.get('tier')}, conf={h.get('confidence')}%) {desc}\n"
                    convergence_map.setdefault(area, []).append(hunter_name)
        except Exception:
            pass

    convergence_text = ""
    for area, hunters in convergence_map.items():
        if len(hunters) >= 2:
            convergence_text += f"- **{area}**: flagged by {', '.join(set(hunters))} — INVESTIGATE DEEPER\n"

    # Build deepdive prompt directly from bench_session hyp_dir.
    # Do NOT import generate_deepdive_prompt from run_hunt — that function uses
    # run_hunt.HUNT_SESSION_DIR (real hunt_session, not bench_session) to read
    # hypotheses, which is wrong in benchmark mode and would be a thread-safety
    # issue in parallel component execution (two threads patching the same module global).
    deepdive_prompt = build_deepdive_prompt(
        component=component, protocol=protocol, source_code=source_code,
        library_code=library_code, setup_sol_text=setup_sol_text,
        protocol_model=protocol_model, hyp_dir=hyp_dir,
        convergence_text=convergence_text, hunter_digest=hunter_digest
    )

    _llm(
        deepdive_prompt,
        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
        timeout=1800,
        log_file=clog / "deepdive.log",
        cwd=repo
    )

    # Rescue DeepDive YAML: Claude may write to cwd (worktree root) instead of hyp_dir.
    # Use find to locate the file wherever it landed in the worktree, then copy to hyp_dir.
    dd_yaml_target = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
    if not dd_yaml_target.exists():
        import shutil as _shutil_dd
        import subprocess as _sp_dd
        _find = _sp_dd.run(
            ["find", str(repo), "-name", f"hyp_{component}_DeepDiveHunter.yaml", "-type", "f"],
            capture_output=True, text=True
        )
        for _found in _find.stdout.strip().splitlines():
            if _found and Path(_found) != dd_yaml_target:
                _shutil_dd.copy2(_found, dd_yaml_target)
                logger.info(f"  Rescued DeepDive YAML from worktree: {Path(_found).name} → {hyp_dir.name}/")
                break

    deepdive_ok = check_gate(component, "deepdive", protocol, repo)
    summary["gates"]["deepdive"] = deepdive_ok
    if not deepdive_ok:
        dd_file = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
        if not dd_file.exists():
            logger.warning("  DeepDive gate failed and no YAML — continuing without DeepDive")
        # Not blocking — DeepDive is additive, hunters provide the base

    # ─── Forge env (shared by fuzz + PoC steps) ─────────────────────────
    forge_env = os.environ.copy()
    forge_env["FOUNDRY_PROFILE"] = "chimera"
    for _rpc_var in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
        _rpc_val = os.environ.get(_rpc_var, "")
        if _rpc_val:
            forge_env[_rpc_var] = _rpc_val

    # ─── Steps 5-9: Compile + Fuzz ──────────────────────────────────────
    # Fast mode: runs Steps 5-8 (setup+merge+compile+Phase1 5K) but skips 9-9.5 (Medusa+tuning)
    # Full mode: runs everything
    all_fuzz_failures = {}
    phase1_fuzz_failures = {}
    phase2_log = clog / "phase2_medusa.log"  # may not exist in fast mode
    _SKIP_HEAVY_FUZZ = args.fast  # skip Medusa + tolerance tuning
    if args.fast:
        logger.info("  ⚡ FAST MODE: Steps 5-8 (compile+Phase1 5K), skip 9-9.5 (Medusa+tuning)")
        summary["gates"]["phase2"] = True  # skip Medusa gate

    if True:  # Steps 5-8 always run; Steps 9-9.5 gated by _SKIP_HEAVY_FUZZ
        # ─── Step 5: Ensure Chimera Setup exists & compiles BEFORE merge ────
        setup_sol = chimera_dir / "Setup.sol"
        if not chimera_dir.exists() or not setup_sol.exists():
            logger.info("  Step 5a: Generate Chimera Setup (no existing setup found)")
            chimera_prompt = (
                f"Generate a complete Chimera fuzzing setup for {component} in {protocol}.\n\n"
                f"## Source Code\n```solidity\n{source_code}\n```\n\n"
                f"## Libraries\n```solidity\n{library_code[:20000]}\n```\n\n"
                f"Create these files in {chimera_dir}/:\n"
                f"- Setup.sol: deploy {component} with ALL its dependencies. Use MOCKS for external contracts (no fork, no RPC).\n"
                f"  NEVER use vm.createSelectFork — Phase 1 is mock-only for fast feedback.\n"
                f"  For Uniswap V3: create MockUniswapV3Pool. For oracles: MockOracle. For tokens: deal().\n"
                f"  MUST define: contract instance variables accessible by Properties (e.g., `Strategy internal strategy;`)\n"
                f"- BeforeAfter.sol: ghost variables and state snapshots\n"
                f"- Properties.sol: base with ghost vars, inherits BeforeAfter\n"
                f"- TargetFunctions.sol: handlers for each public function with clamped inputs\n"
                f"- FoundryTester.sol: inherits Properties, has invariant_* wrapper functions\n"
                f"- CryticTester.sol: inherits TargetFunctions + Properties for Medusa\n\n"
                f"The setup MUST compile with `forge build`. Test it after creating."
            )
            _llm(
                chimera_prompt,
                allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
                timeout=1200,  # Increased: complex components need >600s for full setup
                log_file=clog / "chimera_builder.log",
                cwd=repo
            )

        # Verify base chimera compiles before merge
        logger.info("  Step 5b: Verify base chimera compiles")
        base_compile_ok = fix_and_retry(
            "base_compile",
            ["forge", "build"],
            [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else [],
            max_retries=5,
            cwd=repo
        )
        if not base_compile_ok:
            logger.error("  Base chimera doesn't compile — skipping merge+fuzz")
            summary["status"] = "BLOCKED_CHIMERA"
            summary["gates"]["compile"] = False
            return summary

        # ─── Step 5c: Second-chance rescue of DeepDive YAML before merge ──────
        # (Primary rescue is right after run_claude; this catches any edge cases)
        dd_yaml_pre = hyp_dir / f"hyp_{component}_DeepDiveHunter.yaml"
        if not dd_yaml_pre.exists():
            import shutil as _shutil_pre, subprocess as _sp_pre
            _find2 = _sp_pre.run(
                ["find", str(repo), "-name", f"hyp_{component}_DeepDiveHunter.yaml", "-type", "f"],
                capture_output=True, text=True
            )
            for _f2 in _find2.stdout.strip().splitlines():
                if _f2 and Path(_f2) != dd_yaml_pre:
                    _shutil_pre.copy2(_f2, dd_yaml_pre)
                    logger.info(f"  Pre-merge rescue: {Path(_f2).name} → {hyp_dir.name}/")
                    break

        # ─── Step 6: Merge Invariants (setup-aware) ──────────────────────────
        logger.info("  Step 6: Merge Invariants")

        # Extract available variables from Setup.sol so merge knows what exists
        setup_context = ""
        if setup_sol.exists():
            setup_content = setup_sol.read_text(encoding="utf-8")
            setup_context = setup_content[:20000]  # Full Setup.sol — critical for compile fixes

        code, _, _ = run_cmd([
            sys.executable, str(SCRIPT_DIR / "merge_invariants.py"),
            "--component", component,
            "--hypotheses-dir", str(hyp_dir),
            "--session-dir", str(HUNT_SESSION_DIR),
            "--protocol", protocol,
        ], log_file=clog / "merge.log")
        merge_ok = code == 0
        summary["gates"]["merge"] = merge_ok
        if not merge_ok:
            logger.error(f"  BLOCKED: merge_invariants.py failed. Cannot compile without Properties.")
            summary["status"] = "BLOCKED_MERGE"
            return summary

        # ─── Step 6.5: Generate FoundryTester invariant_ wrappers ────────────
        logger.info("  Step 6.5: Generate FoundryTester invariant_ wrappers")
        _generate_foundry_tester_wrappers(chimera_dir)

        # ─── Step 6.7: Inject missing imports into Properties*.sol ────────────
        # merge_invariants.py generates Properties files that often lack imports
        # present in Setup.sol (e.g., IStrategy). This pre-injects them to avoid
        # burning 9 compile-fix attempts on the same import error across files.
        setup_path = chimera_dir / "Setup.sol"
        if setup_path.exists():
            setup_text = setup_path.read_text(encoding="utf-8")
            # Extract import lines from Setup.sol
            setup_imports = [line.strip() for line in setup_text.splitlines()
                           if line.strip().startswith("import ")]
            for prop_file in sorted(chimera_dir.glob("Properties*.sol")):
                if prop_file.name in ("PropertiesAll.sol",):
                    continue
                prop_text = prop_file.read_text(encoding="utf-8")
                added = []
                for imp in setup_imports:
                    # Check if the imported symbol is used but not imported
                    # Extract symbol name from: import {Foo} from "..." or import "..."
                    m_sym = re.search(r'import\s+\{([^}]+)\}', imp)
                    if m_sym:
                        symbols = [s.strip() for s in m_sym.group(1).split(",")]
                        for sym in symbols:
                            if sym in prop_text and imp not in prop_text:
                                added.append(imp)
                                break
                if added:
                    # Insert after pragma line
                    lines = prop_text.splitlines(keepends=True)
                    insert_idx = 0
                    for i, line in enumerate(lines):
                        if line.strip().startswith("pragma "):
                            insert_idx = i + 1
                            break
                    for imp_line in reversed(added):
                        lines.insert(insert_idx, imp_line + "\n")
                    prop_file.write_text("".join(lines), encoding="utf-8")
                    logger.info(f"    Injected {len(added)} imports into {prop_file.name}")

        # ─── Step 7: Compile merged invariants (setup-aware fix) ─────────────
        logger.info("  Step 7: Compile (setup-aware fix-and-retry)")

        # Custom fix prompt that understands chimera architecture
        compile_files = [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else []

        for attempt in range(9):
            code, stdout, stderr = run_cmd(["forge", "build"], cwd=repo)
            if code == 0:
                logger.info(f"  ✅ Compile passed (attempt {attempt + 1})")
                break

            error_text = _extract_first_errors(stderr, max_errors=25, max_chars=5000)
            logger.warning(f"  ❌ Compile failed (attempt {attempt + 1}/9)")

            if attempt < 8:
                # All attempts try to FIX first. Only last resort (attempt 8) deletes.
                # Each level adds more context to help the fixer understand the error.
                if attempt <= 2:
                    strategy_hint = (
                        f"## STRATEGY: Fix errors (attempt {attempt + 1}/9)\n"
                        f"1. Read Setup.sol FIRST to understand what contracts/variables are deployed and their EXACT types\n"
                        f"2. Properties*.sol can ONLY reference variables defined in Setup.sol\n"
                        f"3. If an import is missing, add it. If a type is wrong, fix the type\n"
                        f"4. **TYPE MISMATCH FIX**: If error is about IFoo.Struct vs Foo.Struct (interface vs concrete):\n"
                        f"   - Check Setup.sol — if it declares `Foo internal foo` (concrete), use `Foo.StructName` not `IFoo.StructName`\n"
                        f"   - Or remove the type annotation entirely: `(uint a, uint b) = foo.getX()` instead of `IFoo.X memory x = foo.getX()`\n"
                        f"5. **STRUCT GETTER FIX** (MOST COMMON ERROR): Solidity public struct state variables return TUPLES from auto-generated getters.\n"
                        f"   - WRONG: `strategy.mainPosition().tickLower` — `.tickLower` fails on a tuple\n"
                        f"   - RIGHT: `(int24 tickLower, int24 tickUpper, uint128 liquidity) = strategy.mainPosition();`\n"
                        f"   - OR: if the contract has explicit `getMainPosition()` returning a struct, use that instead\n"
                        f"   - Check the source contract for explicit getter functions that return structs by memory\n"
                        f"6. If an invariant references a contract/function not in Setup.sol, check if Setup.sol has a helper for it\n"
                        f"7. Do NOT delete functions — FIX them. Every invariant matters.\n"
                        f"8. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                    )
                elif attempt <= 5:
                    strategy_hint = (
                        f"## STRATEGY: Fix with more context (attempt {attempt + 1}/9)\n"
                        f"Previous attempts didn't resolve all errors. Read MORE carefully:\n"
                        f"1. Read Setup.sol line by line — list EVERY variable, its type, and what helpers exist\n"
                        f"2. Read the ACTUAL source contract to verify function signatures, return types, and struct definitions\n"
                        f"3. For each error: read the exact line, understand WHY it fails, fix the ROOT CAUSE\n"
                        f"4. Common fixes:\n"
                        f"   - Wrong type: `IFoo.X` → `Foo.X` (match Setup.sol concrete type)\n"
                        f"   - Missing function: check if Setup.sol has a `_helper()` that wraps it\n"
                        f"   - Wrong args: read the actual function signature in the source contract\n"
                        f"   - Missing import: add the import from Setup.sol's import list\n"
                        f"   - Struct field access: use a getter helper or destructure the return value\n"
                        f"5. Do NOT delete functions — FIX them. Every invariant matters.\n"
                        f"6. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                    )
                elif attempt <= 7:
                    strategy_hint = (
                        f"## STRATEGY: Simplify broken functions (attempt {attempt + 1}/9)\n"
                        f"Multiple fix attempts failed. For functions that STILL don't compile:\n"
                        f"1. Read the error and the function. Understand the INTENT of the invariant.\n"
                        f"2. REWRITE the function body to test the SAME property but with simpler code:\n"
                        f"   - Replace struct access with direct getter calls\n"
                        f"   - Replace complex expressions with multiple simple lines\n"
                        f"   - Use only variables and types from Setup.sol\n"
                        f"3. If a function calls something that doesn't exist, replace with the closest equivalent\n"
                        f"4. PRESERVE the function — rewrite it simpler, do NOT delete it\n"
                        f"5. Do NOT delete Setup.sol, BeforeAfter.sol, or TargetFunctions.sol\n"
                    )
                else:
                    strategy_hint = (
                        f"## STRATEGY: Last resort — delete ONLY what cannot be fixed (attempt {attempt + 1}/9)\n"
                        f"This is the final attempt. For each remaining error:\n"
                        f"1. Try one more time to fix or simplify the function\n"
                        f"2. ONLY if it's truly unfixable (references something that doesn't exist at all), delete JUST that one function\n"
                        f"3. Keep as many invariants as possible — each one is valuable\n"
                        f"4. Do NOT delete Setup.sol, BeforeAfter.sol, TargetFunctions.sol, FoundryTester.sol, CryticTester.sol\n"
                    )

                fix_prompt = (
                    f"Fix compile errors in the Chimera fuzzing setup for {component}.\n\n"
                    f"## Error\n```\n{error_text}\n```\n\n"
                    f"{strategy_hint}\n"
                    f"## Available Setup Context\n```solidity\n{setup_context}\n```\n\n"
                    f"Read ALL .sol files in {chimera_dir}/ to understand the full picture before making fixes.\n"
                    f"After fixing, run `forge build` to verify ALL errors are resolved — fix any new ones too."
                )
                # Shorter timeout for simple fixes, longer for later attempts
                fix_timeout = 300 if attempt <= 2 else 360 if attempt <= 5 else 480
                tier = "fix" if attempt <= 2 else "context" if attempt <= 5 else "simplify" if attempt <= 7 else "delete"
                _llm(
                    fix_prompt,
                    allowed_tools=["Read", "Edit", "Write", "Grep", "Glob", "Bash"],
                    timeout=fix_timeout,
                    log_file=clog / f"compile_fix_{attempt:02d}_{tier}.log",
                    cwd=repo
                )

        compile_ok = code == 0
        summary["gates"]["compile"] = compile_ok

        _skip_to_extract = False
        if not compile_ok:
            if _SKIP_HEAVY_FUZZ:
                logger.warning(f"  Compile failed — fast mode skips to findings extraction")
                summary["gates"]["compile"] = False
                summary["gates"]["phase1"] = False
                _skip_to_extract = True
            else:
                logger.error(f"  Component {component} BLOCKED at compile")
                summary["status"] = "BLOCKED_COMPILE"
                return summary

        # ─── Step 7.5: Enhance TargetFunctions with attack sequences ────────
        if _skip_to_extract:
            logger.info("  Skipping Step 7.5 (compile failed, fast mode)")
        else:
            logger.info("  Step 7.5: Enhance TargetFunctions with attack sequences")
            target_funcs_path = chimera_dir / "TargetFunctions.sol"
            if target_funcs_path.exists():
                top_hyps = ""
                for hyp_file in sorted(hyp_dir.glob(f"hyp_{component}_*.yaml"))[:5]:
                    try:
                        import yaml as _y
                        data = _y.safe_load(hyp_file.read_text())
                        if data:
                            hyps = data.get("hypotheses", data.get("invariants", []))
                            for h in hyps[:3]:
                                if h.get("tier", 3) <= 2 and h.get("confidence", 0) >= 60:
                                    top_hyps += f"\n- {h.get('id','?')}: {h.get('description','')}\n  Attack: {h.get('attack_scenario','')}\n"
                    except Exception:
                        pass

                if top_hyps:
                    target_funcs_code = target_funcs_path.read_text(encoding="utf-8")
                    enhance_prompt = (
                        f"Enhance the TargetFunctions.sol for {component} with multi-step attack sequences.\n\n"
                        f"## Current TargetFunctions\n```solidity\n{target_funcs_code[:15000]}\n```\n\n"
                        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
                        f"## High-Priority Attack Scenarios from Hunters\n{top_hyps}\n\n"
                        f"## Task\n"
                        f"Add 3-5 NEW handler functions that encode MULTI-STEP attack sequences:\n"
                        f"1. Flash loan → deposit → manipulate → withdraw sequences\n"
                        f"2. Sandwich patterns: frontrun → victim action → backrun\n"
                        f"3. State manipulation: set up bad state → trigger vulnerable path\n"
                        f"4. Cross-function: call A to set state, call B to exploit it\n\n"
                        f"Each handler should:\n"
                        f"- Use clamped inputs (bound by `_clampBetween`)\n"
                        f"- Prank as attacker where needed\n"
                        f"- Be a realistic attack, not random calls\n\n"
                        f"ONLY ADD new functions. Do NOT modify or remove existing handlers.\n"
                        f"Write changes to: {target_funcs_path}"
                    )
                    _llm(
                        enhance_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / "target_functions_enhance.log",
                        cwd=repo
                    )
                    # Quick recompile to make sure enhancement didn't break anything
                    recomp_ok = fix_and_retry(
                        "targetfunc_compile", ["forge", "build"],
                        [str(target_funcs_path)], max_retries=2, cwd=repo
                    )
                    if recomp_ok:
                        logger.info("  TargetFunctions enhanced and compiles")
                    else:
                        logger.warning("  TargetFunctions enhancement broke compile — reverting")
                        run_cmd(["git", "checkout", "--", str(target_funcs_path.relative_to(Path(repo)))], cwd=repo)
                        run_cmd(["forge", "build"], cwd=repo)  # restore working state
                else:
                    logger.info("  No high-priority hypotheses — skipping TargetFunctions enhancement")

        # forge_env already defined above (shared by fuzz + PoC steps)

        # ─── Step 8: Phase 1 — Foundry fuzz runs (parallel batches) ────────
        if _skip_to_extract:
            logger.info("  Skipping Steps 8-9.5 (compile failed, fast mode)")
        if not _skip_to_extract:
            FUZZ_RUNS = 3000 if args.fast else 5000
            FUZZ_PARALLEL = args.parallel_fuzz
            FUZZ_BATCH_TIMEOUT = 1800  # per batch

            # Discover all invariant_ functions from FoundryTester
            foundry_tester = chimera_dir / "FoundryTester.sol"
            inv_fns = []
            if foundry_tester.exists():
                for line in foundry_tester.read_text(encoding="utf-8").splitlines():
                    m = re.match(r'\s*function\s+(invariant_\w+)', line)
                    if m:
                        inv_fns.append(m.group(1))

            if not inv_fns:
                # Fallback: single run with all invariants
                inv_fns = ["invariant_"]  # match all

            logger.info(f"  Step 8: Phase 1 — {len(inv_fns)} invariants × {FUZZ_RUNS} runs "
                        f"({FUZZ_PARALLEL} parallel batches)")

            # Split invariants into batches for parallel execution
            batch_size = max(1, len(inv_fns) // FUZZ_PARALLEL + (1 if len(inv_fns) % FUZZ_PARALLEL else 0))
            batches = [inv_fns[i:i + batch_size] for i in range(0, len(inv_fns), batch_size)]

            all_stdout = []
            all_stderr = []
            any_infra_fail = False
            any_invariant_fail = False

            def _run_fuzz_batch(batch_idx_and_fns):
                batch_idx, fns = batch_idx_and_fns
                # Build regex pattern to match multiple invariant functions
                pattern = "|".join(fns) if len(fns) > 1 else fns[0]
                batch_log = clog / f"phase1_batch{batch_idx}.log"
                logger.info(f"    Batch {batch_idx}: {len(fns)} invariants ({fns[0]}...)")
                code, stdout, stderr = run_cmd(
                    ["forge", "test", "--match-contract", "FoundryTester",
                     "--match-test", pattern, "--fuzz-runs", str(FUZZ_RUNS), "-vv"],
                    timeout=FUZZ_BATCH_TIMEOUT, cwd=repo,
                    log_file=batch_log, env=forge_env
                )
                return batch_idx, code, stdout, stderr

            with ThreadPoolExecutor(max_workers=FUZZ_PARALLEL) as executor:
                futures = {
                    executor.submit(_run_fuzz_batch, (i, batch)): i
                    for i, batch in enumerate(batches)
                }
                for future in as_completed(futures):
                    batch_idx = futures[future]
                    try:
                        _, code, stdout, stderr = future.result()
                        all_stdout.append(stdout)
                        all_stderr.append(stderr)
                        if code != 0:
                            combined = stdout + stderr
                            if "FAIL" in stdout and ("invariant" in stdout.lower() or "assertion" in stdout.lower()):
                                any_invariant_fail = True
                            elif "createFork" in combined or "Connection refused" in combined:
                                any_infra_fail = True
                            elif "setUp()" in stdout and "FAIL" in stdout:
                                any_infra_fail = True
                            else:
                                any_invariant_fail = True  # assume real failure
                    except Exception as e:
                        logger.error(f"    Batch {batch_idx}: error: {e}")

            # Merge batch outputs into single log for downstream parsing
            merged_stdout = "\n".join(all_stdout)
            merged_stderr = "\n".join(all_stderr)
            (clog / "phase1_foundry.log").write_text(
                f"=== CMD: forge test (merged {len(batches)} batches × {FUZZ_RUNS} runs) ===\n"
                f"=== STDOUT ===\n{merged_stdout}\n=== STDERR ===\n{merged_stderr}\n",
                encoding="utf-8"
            )

            if any_infra_fail and not any_invariant_fail:
                logger.error(f"  Phase 1: Infrastructure failure — check RPC/setUp")
                summary["gates"]["phase1"] = False
            elif any_invariant_fail:
                logger.warning(f"  Phase 1: INVARIANT FAILURES detected — potential bugs!")
            else:
                logger.info("  Phase 1: ALL PASS")

            if "phase1" not in summary["gates"]:
                summary["gates"]["phase1"] = True

            if not summary["gates"].get("phase1", False):
                logger.error("  BLOCKED: Phase 1 infra failure — no fuzz data. Cannot extract findings.")
                summary["status"] = "BLOCKED_PHASE1_INFRA"
                return summary

            # ─── ITERATIVE FUZZ-REFINE LOOP (max 3 rounds) ─────────────────────
            # This replicates what I did manually: fuzz → analyze → refine → re-fuzz
            # Round 0 = Phase 1 already ran above
            # Round 1+ = targeted refinement based on what we learned
            all_fuzz_failures = {}  # accumulate across rounds

            for fuzz_round in range(2):  # max 2 rounds: initial + 1 refinement
                round_label = f"Round {fuzz_round}"

                # ─── Analyze current fuzz results ─────────────────────────────
                if fuzz_round == 0:
                    current_log = clog / "phase1_foundry.log"
                else:
                    current_log = clog / f"phase1_round{fuzz_round}.log"

                round_failures = parse_fuzz_failures(current_log)
                all_fuzz_failures.update(round_failures)

                # ─── Deep trace analysis for failures (-vvvv) ─────────────────
                # Skip in fast mode: normal -vv already has call sequences for PoC gen.
                # Deep trace adds opcodes/SLOAD/SSTORE detail but costs 10-15 min with
                # frequent timeouts, and content gets truncated before use anyway.
                if round_failures and not _SKIP_HEAVY_FUZZ:
                    logger.info(f"  {round_label}: Deep trace analysis for {len(round_failures)} failures")
                    for fail_name in list(round_failures.keys())[:5]:
                        logger.info(f"    Re-running {fail_name} with -vvvv...")
                        _, deep_stdout, _ = run_cmd(
                            ["forge", "test", "--match-test", fail_name, "--fuzz-runs", "100", "-vvvv"],
                            timeout=300, cwd=repo,
                            log_file=clog / f"deep_trace_{fail_name}.log",
                            env=forge_env
                        )
                        if deep_stdout and "FAIL" in deep_stdout:
                            all_fuzz_failures[fail_name] = deep_stdout[-5000:]
                            logger.info(f"    {fail_name}: deep trace captured")
                elif round_failures and _SKIP_HEAVY_FUZZ:
                    logger.info(f"  {round_label}: Skipping deep trace in fast mode ({len(round_failures)} failures — using -vv traces)")

                # ─── Decide: refine or stop? ──────────────────────────────────
                if fuzz_round >= 1:
                    logger.info(f"  {round_label}: Max refinement reached — proceeding to Medusa")
                    break

                if round_failures and fuzz_round < 1:
                    # FOUND BUGS → write MORE invariants targeting the SAME area
                    logger.info(f"  {round_label}: {len(round_failures)} failures → writing targeted invariants for same area")
                    failure_traces = "\n".join(
                        f"### {name}\n```\n{trace[:1500]}\n```"
                        for name, trace in list(round_failures.items())[:3]
                    )
                    existing_props = ""
                    for pf in chimera_dir.glob("Properties*.sol"):
                        existing_props += f"\n// {pf.name}\n{pf.read_text(encoding='utf-8')[:5000]}\n"

                    deepen_prompt = (
                        f"The fuzzer BROKE these invariants in {component}:\n\n"
                        f"{failure_traces}\n\n"
                        f"This means there's a real vulnerability in this area. Now DEEPEN the analysis:\n"
                        f"1. Read the counterexample traces above — understand the EXACT attack path\n"
                        f"2. Write 3-5 NEW invariants that probe DEEPER into the same area:\n"
                        f"   - Tighter bounds on the same values\n"
                        f"   - Related state variables that might also be affected\n"
                        f"   - What else can an attacker exploit AFTER this initial break?\n"
                        f"   - Can the attacker chain this with another function for bigger impact?\n"
                        f"3. Also write 2-3 invariants for ADJACENT areas that might have the same root cause\n\n"
                        f"## Current Properties\n```solidity\n{existing_props[:10000]}\n```\n\n"
                        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
                        f"## Source Code (first 15K — full source at {src_file})\n```solidity\n{source_code[:15000]}\n```\n\n"
                        f"APPEND new functions to existing Properties files. Use Setup.sol variables.\n"
                        f"Use Chimera helpers: t(), eq(), gte(), lte()."
                    )
                    _llm(
                        deepen_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / f"deepen_round{fuzz_round + 1}.log",
                        cwd=repo
                    )

                elif not round_failures:
                    # ALL PASS → invariants too weak, write more aggressive ones
                    logger.info(f"  {round_label}: All invariants held — writing more aggressive properties")
                    existing_props = ""
                    for pf in chimera_dir.glob("Properties*.sol"):
                        existing_props += f"\n// {pf.name}\n{pf.read_text(encoding='utf-8')[:5000]}\n"

                    refocus_prompt = (
                        f"ALL {component} invariants passed 5000 Foundry fuzz runs without breaking.\n\n"
                        f"This means either: (a) the code is safe, or (b) our invariants are too weak.\n\n"
                        f"## Current Properties (all passing)\n```solidity\n{existing_props[:15000]}\n```\n\n"
                        f"## Source Code (first 20K — full source at {src_file})\n```solidity\n{source_code[:20000]}\n```\n\n"
                        f"## Setup\n```solidity\n{setup_sol_text}\n```\n\n"
                        f"## Task: Write MORE AGGRESSIVE invariants\n"
                        f"Add 5-10 new property functions to the existing Properties files. Focus on:\n"
                        f"1. **Exact equalities** (not just >= or <=) — tighter bounds catch more bugs\n"
                        f"2. **Cross-function state**: after deposit+withdraw, state should be EXACTLY original\n"
                        f"3. **Economic invariants**: no profit from round-trip, no value creation from thin air\n"
                        f"4. **Edge cases**: what happens with amount=0, amount=1, amount=type(uint256).max\n"
                        f"5. **Ordering**: does calling A→B give different result than B→A?\n\n"
                        f"Use variable names from Setup.sol. Use Chimera helpers: t(), eq(), gte(), lte().\n"
                        f"APPEND to existing Properties files — do NOT overwrite them."
                    )
                    _llm(
                        refocus_prompt,
                        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
                        timeout=600,
                        log_file=clog / f"refocus_round{fuzz_round + 1}.log",
                        cwd=repo
                    )

                # ─── Re-compile and re-fuzz ───────────────────────────────────
                recompile_ok = fix_and_retry(
                    f"round{fuzz_round + 1}_compile", ["forge", "build"],
                    [str(f) for f in chimera_dir.glob("*.sol")],
                    max_retries=3, cwd=repo
                )
                if not recompile_ok:
                    logger.warning(f"  {round_label}: New invariants don't compile — stopping refinement loop")
                    break

                # Re-fuzz with new invariants
                logger.info(f"  Round {fuzz_round + 1}: Re-fuzzing with refined invariants (3K runs)")
                run_cmd(
                    ["forge", "test", "--match-contract", "FoundryTester", "--fuzz-runs", "3000", "-vv"],
                    timeout=600, cwd=repo,
                    log_file=clog / f"phase1_round{fuzz_round + 1}.log",
                    env=forge_env
                )

            # Update fuzz_failures for downstream use (includes all rounds)
            phase1_fuzz_failures = all_fuzz_failures
            if phase1_fuzz_failures:
                logger.info(f"  Total fuzz failures across all rounds: {list(phase1_fuzz_failures.keys())}")
            else:
                logger.info(f"  No fuzz failures after {fuzz_round + 1} rounds of refinement")

            # ─── Step 9: Phase 2 — Medusa 15 min (skipped in fast mode) ─────────
            if not _SKIP_HEAVY_FUZZ:
                # ─── Step 9: Phase 2 — Medusa 15 min ─────────────────────────────
                logger.info("  Step 9: Phase 2 — Medusa 15 min")
                medusa_config = chimera_dir / f"medusa-{protocol}.json"
                if not medusa_config.exists():
                    base_name = protocol.split("-")[0] if "-" in protocol else protocol
                    medusa_config = chimera_dir / f"medusa-{base_name}.json"
                if not medusa_config.exists():
                    medusa_config = chimera_dir / "medusa.json"
                if not medusa_config.exists():
                    medusa_candidates = list(chimera_dir.glob("medusa*.json"))
                    if medusa_candidates:
                        medusa_config = medusa_candidates[0]

                if medusa_config.exists():
                    code, stdout, stderr = run_cmd(
                        ["medusa", "fuzz", "--config", str(medusa_config), "--timeout", "900"],
                        timeout=1000,
                        cwd=repo,
                        log_file=clog / "phase2_medusa.log"
                    )
                    summary["gates"]["phase2"] = True
                else:
                    logger.warning("  Medusa config not found — skipping Phase 2")
                    summary["gates"]["phase2"] = False

                # ─── Step 9.5: Tolerance Tuning ───────────────────────────────────
                logger.info("  Step 9.5: Tolerance Tuning (Claude analyzes fuzz output)")
                phase1_log = clog / "phase1_foundry.log"
                phase2_log_path = clog / "phase2_medusa.log"
                fuzz_output = ""
                for log_path in [phase1_log, phase2_log_path]:
                    if log_path.exists():
                        content = log_path.read_text(encoding="utf-8", errors="replace")
                        if "=== STDOUT ===" in content:
                            fuzz_output += content.split("=== STDOUT ===")[1].split("=== STDERR ===")[0][:8000]

                triage_results = ""
                if fuzz_output.strip() and "FAIL" in fuzz_output:
                    triage_prompt = (
                        f"You are analyzing Foundry/Medusa fuzzing results for {component} in {protocol}.\n\n"
                        f"## Fuzz Output\n```\n{fuzz_output}\n```\n\n"
                        f"## Task\n"
                        f"For EACH failing test/invariant:\n"
                        f"1. Function name that failed\n"
                        f"2. Classify: REAL_BUG / ROUNDING_DUST / MOCK_ARTIFACT / INFRA_ERROR / TEST_ARTIFACT\n"
                        f"3. Reasoning (1 sentence)\n"
                        f"4. If REAL_BUG: what's the attack? If ROUNDING_DUST: what tolerance would fix it?\n\n"
                        f"Output as structured text, one finding per block.\n"
                        f"REAL_BUG = actual exploitable vulnerability\n"
                        f"ROUNDING_DUST = off by 1-2 wei, no economic impact\n"
                        f"MOCK_ARTIFACT = failure caused by mock not matching real behavior\n"
                        f"INFRA_ERROR = fork/RPC/compilation issue, not a bug\n"
                        f"TEST_ARTIFACT = test setup issue, not a protocol bug"
                    )
                    rc, triage_results = _llm(
                        triage_prompt, timeout=180,
                        log_file=clog / "tolerance_tuning.log", cwd=repo
                    )
                    logger.info(f"  Tolerance tuning complete")
                elif fuzz_output.strip():
                    logger.info("  No fuzz failures — all invariants held")
                else:
                    logger.info("  No fuzz output to analyze (infra issue?)")
            else:
                logger.info("  ⚡ Skipping Steps 9-9.5 (Medusa + tolerance tuning)")

    # ─── Step 10: Extract Findings ──────────────────────────────────────
    logger.info("  Step 10: Extract findings from hypotheses + fuzz results")

    # Rescue misplaced YAML files — hunters may write inside repo instead of global dir
    import shutil as _shutil
    for rescue_dir in [
        Path(repo) / "hunt_session" / "hypotheses",
        Path(repo) / "hunt_session" / "hypotheses" / protocol,
        Path(repo) / "results",
    ]:
        if rescue_dir.exists():
            for misplaced in rescue_dir.glob(f"hyp_{component}_*.yaml"):
                target = hyp_dir / misplaced.name
                if not target.exists():
                    _shutil.copy2(misplaced, target)
                    logger.info(f"    Rescued {misplaced.name} → {hyp_dir.name}/")

    # Parse fuzz results — combine iterative loop results + Medusa
    # phase1_fuzz_failures already accumulated from all fuzz rounds above
    fuzz_failures = dict(phase1_fuzz_failures)  # copy accumulated Phase 1 results
    medusa_failures = parse_fuzz_failures(phase2_log) if phase2_log.exists() else {}
    fuzz_failures.update(medusa_failures)
    if fuzz_failures:
        logger.info(f"  Fuzz failures detected: {list(fuzz_failures.keys())}")

    findings = extract_findings(component, protocol, fuzz_failures)
    summary["findings"] = findings
    logger.info(f"  Found {len(findings)} findings ({sum(1 for f in findings if f.get('fuzz_confirmed'))} fuzz-confirmed)")

    # ─── Early exit for hypothesis mode ──────────────────────────────────
    # In hypothesis mode, scoring happens at the main() level against the YAML files.
    # No PoC generation, no verification, no RedTeam. Fastest possible iteration.
    benchmark_mode_flag = getattr(args, "benchmark_mode", "redteam")
    if benchmark_mode_flag == "hypothesis":
        comp_elapsed = (time.time() - comp_start) / 60
        logger.info(f"  🏁 Component {component} COMPLETE (hypothesis mode) — "
                    f"{len(findings)} findings ({comp_elapsed:.1f}min)")
        return summary

    # ─── Step 10.1: Deduplicate findings by root cause ─────────────────
    finding_groups = _dedup_findings_pure(findings)
    logger.info(f"  Step 10.1: Dedup — {len(findings)} findings → {len(finding_groups)} unique groups")
    for i, g in enumerate(finding_groups):
        leader = g[0]
        logger.info(f"    Group {i}: {leader['id']} (conv={len(g)}, conf={leader.get('confidence',0)}%) "
                    f"+ {len(g)-1} dupes — {leader['title'][:60]}")
    poc_findings: list = []        # populated in Step 10.3/10.5 — initialized here for funnel
    escaped_siblings: list = []    # Capa 3: siblings that are different bugs (Step 10.6)
    fallback_findings: list = []   # Capa 2: fallbacks when group leader fails PoC (Step 10.5b)

    # ─── Step 10.2: Verification — lightweight code-read before Foundry PoC ─────
    # For every distinct (function, line) location, run a quick Claude call:
    # "Read this specific code + hypothesis — is the bug real?"
    # This replicates the manual auditor step: suspect bug → re-read focused code
    # → confirm before investing 15 min in a Foundry PoC.
    # POC_CONFIDENCE_THRESHOLD is a module-level constant (65) shared with cross-component.

    def _verify_finding(finding: dict) -> tuple[bool, str, str]:
        """Quick code-read verification: re-read the specific function and confirm
        the bug is real before investing 15 minutes in a Foundry PoC.
        Returns (is_real, reason, poc_hint)."""
        fid = finding["id"]
        relevant_code = _extract_relevant_code(source_code, library_code, finding)

        verify_prompt = build_verify_prompt(finding=finding, relevant_code=relevant_code)

        rc, output = _llm(
            verify_prompt,
            allowed_tools=[],  # pure reasoning — no tool calls, stays fast (~30-90s)
            timeout=120,
            log_file=clog / f"{fid}_verify.log",
            cwd=repo
        )

        output_lower = output.lower()
        # On timeout or empty output: conservative fallback → treat as REAL
        # (better to attempt a PoC on a false positive than to drop a real bug)
        if not output_lower.strip() or rc != 0:
            logger.info(f"    [TIMEOUT/ERROR → REAL fallback] {fid}")
            return True, "timeout — included conservatively", ""
        is_real = "verdict: real" in output_lower and "verdict: false_positive" not in output_lower

        reason, poc_hint = "", ""
        for line in output.splitlines():
            if line.upper().startswith("REASON:"):
                reason = line[7:].strip()
            elif line.upper().startswith("POC_HINT:"):
                poc_hint = line[9:].strip()

        status = "REAL ✓" if is_real else "FALSE_POSITIVE ✗"
        logger.info(f"    [{status}] {fid}: {reason[:80]}")
        return is_real, reason, poc_hint

    verify_candidates = _collect_verify_candidates_pure(finding_groups, POC_CONFIDENCE_THRESHOLD)
    logger.info(f"  Step 10.2: Verifying {len(verify_candidates)} distinct hypotheses "
                f"({min(10, len(verify_candidates))} parallel)")

    verified_findings: list[dict] = []
    if verify_candidates:
        with ThreadPoolExecutor(max_workers=min(10, len(verify_candidates))) as executor:
            futures = {executor.submit(_verify_finding, f): f for f in verify_candidates}
            for future in as_completed(futures):
                f = futures[future]
                try:
                    is_real, reason, poc_hint = future.result()
                    f["_verified"] = is_real
                    f["_verify_reason"] = reason
                    if poc_hint and poc_hint.lower() != "n/a":
                        f["_poc_hint"] = poc_hint
                    if is_real or f.get("fuzz_confirmed"):
                        verified_findings.append(f)
                except Exception as e:
                    logger.error(f"    Verification error for {f['id']}: {e}")
                    f["_verified"] = True  # conservative: include on error
                    verified_findings.append(f)
        verified_findings.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        logger.info(f"  Verification complete: {len(verified_findings)}/{len(verify_candidates)} confirmed real bugs")

    # ─── Step 10.5: Fork PoC per confirmed finding (Phase 3) ─────────
    if finding_groups:
        logger.info("  Step 10.5: Generating Fork PoCs for confirmed findings")
        poc_dir = Path(repo) / "test" / "poc"
        poc_dir.mkdir(parents=True, exist_ok=True)

        def _run_poc(finding):
            """Delegate to top-level generate_and_test_poc with component context."""
            generate_and_test_poc(
                finding, source_code, interfaces_code,
                component, protocol, repo, clog, forge_env,
                poc_confidence_threshold=POC_CONFIDENCE_THRESHOLD
            )

        # Run PoC for every verified finding (Step 10.2 output).
        # Fallback to group leaders if verification produced nothing.
        POC_PHASE_TIMEOUT = 12 * 3600 if not args.fast else 3 * 3600
        POC_PARALLEL = args.parallel_poc

        # ── Dedup verified findings before PoC phase ──────────────────────
        # Multiple hunters often find the same bug — verification confirms all of
        # them because they describe the same issue. Without dedup, we'd generate
        # N PoCs for the same bug (N = convergence count, typically 3-5×).
        # Strategy: keep only the best representative per dedup group (lowest rank
        # = highest confidence). If the leader's PoC fails, the group's fallbacks
        # are still attempted in _process_finding's retry logic.
        if verified_findings:
            pre_dedup = len(verified_findings)
            poc_findings = _dedup_for_poc_pure(verified_findings)
            post_dedup = len(poc_findings)
            if pre_dedup != post_dedup:
                logger.info(f"  Step 10.3: Dedup before PoC — {pre_dedup} verified → "
                            f"{post_dedup} unique ({pre_dedup - post_dedup} duplicates removed)")
        else:
            poc_findings = [
                g[0] for g in finding_groups
                if g and (g[0].get("fuzz_confirmed") or g[0].get("confidence", 0) >= POC_CONFIDENCE_THRESHOLD)
            ]

        logger.info(f"  Step 10.5: PoC phase — {len(poc_findings)} verified findings "
                    f"({POC_PHASE_TIMEOUT/3600:.0f}h timer, {POC_PARALLEL} parallel)")
        poc_phase_start = time.time()
        pocs_confirmed = 0

        def _process_finding(idx_and_finding):
            """Generate and test PoC for one verified finding."""
            idx, finding, total = idx_and_finding
            elapsed = time.time() - poc_phase_start
            if elapsed > POC_PHASE_TIMEOUT:
                return idx, False, None
            remaining = POC_PHASE_TIMEOUT - elapsed
            logger.info(f"    [Finding {idx+1}/{total}] {finding['id']} "
                        f"— {remaining/60:.0f}min remaining")
            _run_poc(finding)
            return idx, finding.get("has_poc", False), finding["id"]

        n_poc = len(poc_findings)
        with ThreadPoolExecutor(max_workers=POC_PARALLEL) as executor:
            futures = {
                executor.submit(_process_finding, (i, f, n_poc)): i
                for i, f in enumerate(poc_findings)
            }
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    _, confirmed, fid = future.result()
                    if confirmed:
                        pocs_confirmed += 1
                except Exception as e:
                    logger.error(f"    Finding {idx+1}: PoC error: {e}")

        logger.info(f"  PoC phase complete: {pocs_confirmed}/{len(poc_findings)} findings confirmed")

        # ── Step 10.5b: Capa 2 — Fallback PoC for groups with failed leaders ─
        # When a group leader fails PoC, its siblings were never tried.
        # Promote the best verified sibling (rank 1) to a fallback PoC attempt.
        # Without this, real bugs hidden behind a poorly-described leader are silently lost.
        fallback_findings: list[dict] = []
        for g in finding_groups:
            if len(g) > 1 and not g[0].get("has_poc"):
                # Leader failed — look for best verified sibling
                for sib in g[1:]:
                    if sib.get("_verified") or sib.get("fuzz_confirmed"):
                        sib["_capa2_fallback"] = True
                        fallback_findings.append(sib)
                        break  # only the best sibling per group

        if fallback_findings:
            logger.info(f"  Step 10.5b: Capa 2 fallback — {len(fallback_findings)} groups "
                        f"whose leader failed PoC; trying best sibling for each")
            n_fb = len(fallback_findings)
            with ThreadPoolExecutor(max_workers=POC_PARALLEL) as executor:
                futures_fb = {
                    executor.submit(_process_finding, (i, f, n_fb)): i
                    for i, f in enumerate(fallback_findings)
                }
                for future in as_completed(futures_fb):
                    try:
                        _, confirmed, fid = future.result()
                        if confirmed:
                            pocs_confirmed += 1
                            logger.info(f"    Capa 2 fallback {fid}: PoC PASSED — real bug found!")
                    except Exception as e:
                        logger.error(f"    Capa 2 fallback PoC error: {e}")
            capa2_confirmed = sum(1 for f in fallback_findings if f.get("has_poc"))
            logger.info(f"  Capa 2 fallback complete: {capa2_confirmed}/{len(fallback_findings)} confirmed")

        # ── Step 10.6: is_same_bug safety check (Capa 3) ─────────────────
        # For every group whose leader passed PoC, check each sibling:
        # "Is B really the same bug as A, or a different vulnerability?"
        # If DIFFERENT → the sibling escaped dedup by mistake and needs its own PoC.
        # This prevents silent loss of real bugs due to over-aggressive deduplication.
        def _check_is_same_bug(leader: dict, sibling: dict) -> bool:
            """60s Claude call: does sibling describe the same bug as leader?
            Conservative: returns False (DIFFERENT) on timeout/error — never silently drops."""
            prompt = build_is_same_bug_prompt(leader=leader, sibling=sibling)
            fid_s = sibling["id"]
            _, out = _llm(
                prompt, allowed_tools=[], timeout=60, stall_timeout=45,
                log_file=clog / f"{fid_s}_same_bug_check.log", cwd=repo
            )
            # Conservative fallback: empty/timeout → treat as DIFFERENT (never drop)
            result = (out or "").strip().upper()
            is_same = result.startswith("SAME") and not result.startswith("DIFFERENT")
            verdict = "SAME" if is_same else "DIFFERENT"
            logger.info(f"    is_same_bug({leader['id']}, {fid_s}): {verdict}")
            return is_same

        groups_with_passed_leader = [
            g for g in finding_groups
            if len(g) > 1 and g[0].get("has_poc")
        ]
        if groups_with_passed_leader:
            # Collect all verified siblings for parallel checking
            sibling_checks = [
                (g[0], sib)
                for g in groups_with_passed_leader
                for sib in g[1:]
                if sib.get("_verified") or sib.get("fuzz_confirmed")
            ]
            if sibling_checks:
                logger.info(f"  Step 10.6: is_same_bug check — {len(sibling_checks)} siblings "
                            f"across {len(groups_with_passed_leader)} confirmed groups")
                with ThreadPoolExecutor(max_workers=min(8, len(sibling_checks))) as ex:
                    future_map = {
                        ex.submit(_check_is_same_bug, leader, sib): (leader, sib)
                        for leader, sib in sibling_checks
                    }
                    for fut in as_completed(future_map):
                        leader, sib = future_map[fut]
                        try:
                            same = fut.result()
                        except Exception:
                            same = False  # conservative: unknown → treat as different
                        if not same:
                            sib["_escaped_dedup"] = True
                            escaped_siblings.append(sib)

        if escaped_siblings:
            logger.info(f"  Step 10.7: PoC for {len(escaped_siblings)} escaped siblings "
                        f"(different bugs grouped by mistake)")
            poc_phase_start_esc = time.time()
            n_esc = len(escaped_siblings)
            with ThreadPoolExecutor(max_workers=POC_PARALLEL) as executor:
                futures = {
                    executor.submit(_process_finding, (i, f, n_esc)): i
                    for i, f in enumerate(escaped_siblings)
                }
                for future in as_completed(futures):
                    try:
                        _, confirmed, fid = future.result()
                        if confirmed:
                            pocs_confirmed += 1
                            logger.info(f"    Escaped sibling {fid}: PoC PASSED — real distinct bug!")
                    except Exception as e:
                        logger.error(f"    Escaped sibling PoC error: {e}")
            logger.info(f"  Escaped siblings PoC complete: "
                        f"{sum(1 for f in escaped_siblings if f.get('has_poc'))}/{len(escaped_siblings)} confirmed")

        # Mark all findings without PoC (default)
        for group in finding_groups:
            for f in group:
                f.setdefault("has_poc", False)
        for f in escaped_siblings:
            f.setdefault("has_poc", False)

    # Flatten groups back to findings list for downstream
    findings = [f for group in finding_groups for f in group]
    summary["findings"] = findings

    # ─── Step 11: Finding Pipeline (parallel — 4 findings at a time) ────
    # Only findings with PoC OR fuzz-confirmed go through the full pipeline
    pipeline_findings = [f for f in findings if f.get("has_poc") or f.get("fuzz_confirmed")]
    skipped = len(findings) - len(pipeline_findings)
    if skipped:
        logger.info(f"  Skipping {skipped} unverified findings (no PoC, no fuzz confirmation)")

    # In 'poc' mode: stop here — we have PoC-confirmed findings but don't need RedTeam.
    # In 'redteam' mode (default): run the full finding pipeline.
    if benchmark_mode_flag == "poc":
        _log_funnel(component, findings, verified_findings,
                    poc_findings + escaped_siblings + fallback_findings,
                    pipeline_findings, [])
        comp_elapsed = (time.time() - comp_start) / 60
        logger.info(f"  🏁 Component {component} COMPLETE (poc mode) — "
                    f"{len(pipeline_findings)} PoC-confirmed ({comp_elapsed:.1f}min)")
        return summary

    report_findings = []
    if pipeline_findings:
        logger.info(f"  Processing {len(pipeline_findings)} verified findings (3 parallel)")
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(
                    run_finding_pipeline, f, component, protocol, source_code, repo, clog,
                    benchmark_mode=True  # always True in benchmark: skip Variant+Report, stop at RedTeam
                ): f["id"]
                for f in pipeline_findings
            }
            for future in as_completed(futures):
                fid = futures[future]
                try:
                    future.result()
                    logger.info(f"    {fid}: pipeline complete")
                except Exception as e:
                    logger.error(f"    {fid}: pipeline error: {e}")

        report_findings = [f for f in pipeline_findings
                           if f.get("redteam_verdict") in ("REPORT", "REPORT_DOWNGRADED")]

    # ─── Funnel Dashboard ────────────────────────────────────────────────
    # Total PoC attempts = initial dedup batch + escaped siblings (Capa 3) + fallback (Capa 2)
    _log_funnel(component, findings, verified_findings,
                poc_findings + escaped_siblings + fallback_findings,
                pipeline_findings, report_findings)

    # ─── Done ────────────────────────────────────────────────────────────
    comp_elapsed = (time.time() - comp_start) / 60
    logger.info(f"  🏁 Component {component} COMPLETE — {len(findings)} findings ({comp_elapsed:.1f}min)")
    return summary


# ─── Finding Extraction ──────────────────────────────────────────────────────

def parse_fuzz_failures(phase1_log: Path, phase2_log: Path = None) -> dict[str, str]:
    """Parse Foundry/Medusa output to find which invariant functions failed.

    Returns dict mapping failed function names to their counterexample traces.
    e.g. {'invariant_xxx': 'Call sequence: sender=0xBEEF, vault.deposit(1000)...'}
    """
    failed = {}
    import re

    for log_path in [phase1_log, phase2_log]:
        if not log_path or not log_path.exists():
            continue
        content = log_path.read_text(encoding="utf-8", errors="replace")

        # Only parse the STDOUT section — avoid matching text from the prompt
        if "=== STDOUT ===" in content:
            content = content.split("=== STDOUT ===")[1]
            if "=== STDERR ===" in content:
                content = content.split("=== STDERR ===")[0]

        # Foundry format: [FAIL. Reason: ...] invariant_xxx() or property_xxx() (runs: ...)
        for m in re.finditer(r'\[FAIL[^\]]*\]\s+(invariant_\w+|check_\w+|property_\w+)\(\)', content):
            name = m.group(1)
            # Extract counterexample trace — everything from this FAIL line to next test or end
            fail_pos = m.start()
            # Look for the trace section after this failure
            trace_end = content.find("[PASS]", fail_pos + 1)
            trace_end2 = content.find("[FAIL", fail_pos + 1)
            if trace_end == -1:
                trace_end = len(content)
            if trace_end2 != -1 and trace_end2 < trace_end:
                trace_end = trace_end2
            trace = content[fail_pos:trace_end].strip()[:3000]
            failed[name] = trace

        # Medusa format: "assertion failed" or "property violated" with function name
        for m in re.finditer(r'(?:assertion failed|property violated).*?(invariant_\w+|check_\w+|property_\w+)', content):
            name = m.group(1)
            fail_pos = m.start()
            # Capture surrounding context as trace
            trace_start = max(0, fail_pos - 500)
            trace_end = min(len(content), fail_pos + 2000)
            trace = content[trace_start:trace_end].strip()[:3000]
            if name not in failed:
                failed[name] = trace

        # Also catch: "Failing tests:" section
        for m in re.finditer(r'FAIL.*?\]\s+(\w+)\(\)', content):
            name = m.group(1)
            if name.startswith(("invariant_", "check_", "echidna_", "property_")) and name not in failed:
                fail_pos = m.start()
                trace_end = content.find("\n\n", fail_pos + 1)
                if trace_end == -1:
                    trace_end = min(len(content), fail_pos + 2000)
                failed[name] = content[fail_pos:trace_end].strip()[:3000]

    return failed


_extract_relevant_code = _extract_relevant_code_shared


def extract_findings(component: str, protocol: str,
                     fuzz_failures: dict[str, str] = None) -> list[dict]:
    """Extract findings from hypothesis files, prioritizing fuzz-confirmed ones.

    Thin wrapper around finding_pipeline.extract_findings_from_yaml that adds
    logging and constructs hyp_dir from HUNT_SESSION_DIR.
    """
    hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
    findings = extract_findings_from_yaml(hyp_dir, component, fuzz_failures)

    # Log fuzz-confirmed findings
    confirmed = [f for f in findings if f.get("fuzz_confirmed")]
    unconfirmed = [f for f in findings if not f.get("fuzz_confirmed")]
    for f in confirmed:
        logger.info(f"    CONFIRMED by fuzzer: {f['id']} ({f.get('property_name', '')})")
    if confirmed:
        logger.info(f"  {len(confirmed)} fuzz-confirmed findings, {len(unconfirmed)} unconfirmed")
    else:
        logger.info(f"  0 fuzz-confirmed — {len(unconfirmed)} unconfirmed findings sorted by confidence")
    return findings


# ─── Finding Pipeline ────────────────────────────────────────────────────────

def run_finding_pipeline(finding: dict, component: str, protocol: str,
                         source_code: str, repo: str, clog: Path,
                         benchmark_mode: bool = False):
    """Run escalation → redteam → variant → report for a single finding.

    Each stage mirrors the full skill implementation from ~/.claude/skills/.
    If benchmark_mode=True, stops after RedTeam (skips Variant + Report).
    """
    fid = finding.get("id", finding.get("title", "UNKNOWN")[:20])
    logger.info(f"    Finding {fid}: {finding.get('title','?')} ({finding.get('severity','?')})")

    # Load PoC code if it exists
    poc_code = ""
    poc_path = finding.get("poc_path", "")
    if poc_path and Path(poc_path).exists():
        poc_code = Path(poc_path).read_text(encoding="utf-8")[:10000]

    # Use focused code extraction for the finding — keeps prompts under 12k chars
    # instead of sending full 30k contract for every escalation/redteam call.
    focused_code = _extract_relevant_code(source_code, "", finding)

    # For cross-component findings: source_code = combined_source (all contracts).
    # Injecting source_code[:12000] would show the WRONG contracts (sorted-first small ones)
    # instead of the contracts where the bug actually lives. Since RedTeam/EscalationHunter
    # have unrestricted file access, show the repo path and let them read what they need.
    if component == "CrossComponent":
        _src_hint = (
            f"## Source Files (use Read tool to access)\n"
            f"Repo: {repo}\n"
            f"Protocol contracts: {repo}/src/\n"
            f"(focused extract above already targets the vulnerable area)"
        )
    else:
        _src_hint = f"## Full Source (for context)\n```solidity\n{source_code[:12000]}\n```"

    finding_context = (
        f"Finding ID: {fid}\n"
        f"Title: {finding.get('title', finding.get('id', '?'))}\n"
        f"Severity: {finding.get('severity', 'Medium')}\n"
        f"Confidence: {finding.get('confidence', 70)}%\n"
        f"Root Cause: {finding.get('root_cause', finding.get('description', ''))}\n"
        f"Component: {component}\n"
        f"Protocol: {protocol}\n"
        f"Fuzz Confirmed: {finding.get('fuzz_confirmed', False)}\n"
        f"Has PoC: {finding.get('has_poc', False)}\n\n"
        f"## Source Code (focused on vulnerable area)\n```solidity\n{focused_code}\n```\n\n"
        f"{_src_hint}"
    )
    if poc_code:
        finding_context += f"\n\n## Proof of Concept\n```solidity\n{poc_code}\n```"

    # ── F1: Escalation Hunter (Medium+ only) — skip in benchmark mode ────
    # EscalationHunter only adjusts severity ceiling, doesn't affect REPORT/NO verdict.
    # Skip in benchmark mode to save ~150s per finding.
    if not benchmark_mode and finding.get("severity", "Low").capitalize() in ("High", "Medium", "Critical"):
        logger.info(f"    {fid}: EscalationHunter (5 checks)")
        esc_prompt = build_escalation_prompt(finding=finding, finding_context=finding_context)
        _llm(esc_prompt, timeout=180, stall_timeout=120,
                   log_file=clog / f"{fid}_escalation.log", cwd=repo)

    # ── F2: RedTeam (4 attackers, Ronda 0 + 3 rounds) ────────────────────
    # Full skill: severity calibration table, 4 adversarial roles, structured verdict
    logger.info(f"    {fid}: RedTeam (Ronda 0 + 3 rounds)")
    redteam_prompt = build_redteam_prompt(
        finding_context=finding_context, fid=fid, finding=finding,
        component=component
    )
    _, redteam_output = _llm(redteam_prompt, timeout=300, stall_timeout=180,
                                   log_file=clog / f"{fid}_redteam.log", cwd=repo)

    # Parse RedTeam verdict and store on finding for scoring
    def _parse_redteam_verdict(text: str) -> str:
        """Try strict then lenient parse of RESULTADO line."""
        m = re.search(r'RESULTADO:\s*(REPORT_DOWNGRADED|DO_NOT_REPORT|REPORT)', text or "")
        if m:
            return m.group(1)
        # Lenient: case-insensitive, allow surrounding text
        m2 = re.search(r'(?:resultado|verdict)[:\s]+(REPORT_DOWNGRADED|DO_NOT_REPORT|REPORT)',
                       text or "", re.IGNORECASE)
        if m2:
            return m2.group(1).upper()
        return "UNKNOWN"

    verdict = _parse_redteam_verdict(redteam_output)

    # If still UNKNOWN, retry once — output may have cut off or missed the RESULTADO line
    if verdict == "UNKNOWN":
        logger.warning(f"    {fid}: RedTeam returned UNKNOWN — retrying (1/1)")
        _, redteam_output2 = _llm(redteam_prompt, timeout=300, stall_timeout=180,
                                        log_file=clog / f"{fid}_redteam_retry.log", cwd=repo)
        verdict = _parse_redteam_verdict(redteam_output2)
        if verdict != "UNKNOWN":
            logger.info(f"    {fid}: RedTeam retry → {verdict}")
        else:
            logger.warning(f"    {fid}: RedTeam still UNKNOWN after retry — keeping UNKNOWN")

    finding["redteam_verdict"] = verdict
    # Save raw output for post-hoc analysis (capped at 2K chars)
    finding["_redteam_output"] = (redteam_output or "")[:2000]

    # Categorize kill reason using R1-R5 rejection rules (for analytics)
    if verdict == "DO_NOT_REPORT":
        _rt = (redteam_output or "").lower()
        if any(w in _rt for w in ["trusted role", "admin", "owner", "manager", "privileged", "only owner", "onlyowner"]):
            finding["redteam_kill_reason"] = "R1_TRUSTED_ROLE"
        elif any(w in _rt for w in ["view only", "no-op", "read-only", "read only", "pure function"]):
            finding["redteam_kill_reason"] = "R2_VIEW_ONLY"
        elif any(w in _rt for w in ["by design", "intended behavior", "disabled by design", "works as intended"]):
            finding["redteam_kill_reason"] = "R3_BY_DESIGN"
        elif any(w in _rt for w in ["out of scope", "not in scope", "not in the scope", "oos", "outside scope"]):
            finding["redteam_kill_reason"] = "R4_OUT_OF_SCOPE"
        elif any(w in _rt for w in ["no funds", "cosmetic", "no security impact", "ux issue", "no impact"]):
            finding["redteam_kill_reason"] = "R5_NO_IMPACT"
        else:
            finding["redteam_kill_reason"] = "R0_OTHER"
    else:
        finding["redteam_kill_reason"] = ""

    logger.info(f"    {fid}: RedTeam verdict → {verdict}"
                + (f" [{finding['redteam_kill_reason']}]" if finding.get("redteam_kill_reason") else ""))

    if benchmark_mode:
        logger.info(f"    {fid}: benchmark mode — stopping after RedTeam")
        return

    # ── F3: Variant Hunt (4-step: root cause → L0-L3 → triage) ───────────
    # Full skill: root cause statement template, 4 search levels, triage classification
    logger.info(f"    {fid}: VariantHunt (L0-L3)")
    variant_prompt = build_variant_prompt(fid=fid, finding_context=finding_context, repo=repo)
    _llm(
        variant_prompt,
        allowed_tools=["Read", "Grep", "Glob"],
        timeout=240, stall_timeout=120,
        log_file=clog / f"{fid}_variant.log",
        cwd=repo
    )

    # ── F4: Report Writer (platform-aware, anti-AI writing) ───────────────
    # Full skill: platform detection, RedTeam mapping, anti-AI pass, Sherlock template
    logger.info(f"    {fid}: ReportWriter (Sherlock template)")
    # Keep benchmark reports isolated — never write to WEB3_DIR/reports/
    reports_dir = HUNT_SESSION_DIR / "reports"
    reports_dir.mkdir(exist_ok=True)

    slug = finding.get("title", fid)[:40].lower().replace(" ", "-").replace("/", "-")
    slug = re.sub(r'[^a-z0-9-]', '', slug)
    report_path = reports_dir / f"DRAFT-{fid}-{slug}.md"
    report_prompt = build_report_prompt(finding_context=finding_context, report_path=report_path)
    _llm(
        report_prompt,
        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob"],
        timeout=240, stall_timeout=120,
        log_file=clog / f"{fid}_report.log",
        cwd=repo
    )


# ─── Cross-Component Hunt ────────────────────────────────────────────────────

def run_cross_component(components_done: list[str], protocol: str, repo: str,
                        parallel_poc: int = 2) -> list[dict]:
    """Run cross-component analysis + multi-contract fuzzing after 2+ components.
    Returns list of cross-component findings that passed PoC + RedTeam."""
    if len(components_done) < 2:
        return []
    poc_candidates: list[dict] = []  # populated in Phase A.5; returned at end

    logger.info(f"\n{'='*60}")
    logger.info(f"  CROSS-COMPONENT HUNT: {', '.join(components_done)}")
    logger.info(f"{'='*60}")

    import shutil
    import itertools
    clog = component_log_dir("cross_component")
    src_dir = Path(repo) / "src"
    chimera_dir = Path(repo) / "test" / "chimera"

    # ─── Phase A: Per-pair hypothesis generation (parallel) ───────────
    # Old approach: dump all N contracts at once → 70k+ chars → Claude times out.
    # New approach: one focused call per pair, using interfaces (not full source).
    logger.info("  Cross-A: Generating interaction hypotheses (per pair)")

    def _read_interface(comp: str) -> str:
        """Read the interface file for a component, fallback to extracting
        function signatures from source if no interface file exists."""
        # Try interface file first (I<Comp>.sol or <Comp>.sol under interfaces/)
        iface_dir = src_dir / "interfaces"
        for name in (f"I{comp}.sol", f"{comp}.sol"):
            p = iface_dir / name
            if p.exists():
                return p.read_text(encoding="utf-8")[:6000]
        # Fallback: extract function signatures from source via regex
        src_files = list(src_dir.glob(f"**/{comp}.sol"))
        if not src_files:
            return ""
        import re as _re
        text = src_files[0].read_text(encoding="utf-8")
        # Extract: state variables (public), function signatures, events, errors
        lines = text.splitlines()
        sigs = []
        in_func = False
        brace_depth = 0
        for line in lines:
            stripped = line.strip()
            # State vars and events/errors — always include
            if _re.match(r'(address|uint|int|bool|bytes|mapping|struct|enum|event|error|I\w+)\s', stripped):
                sigs.append(line)
            # Function signature lines
            elif stripped.startswith("function "):
                sigs.append(line)
                if "{" in line:
                    in_func = True
                    brace_depth = line.count("{") - line.count("}")
            elif in_func:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    in_func = False
        return "\n".join(sigs[:200])  # cap at 200 lines

    def _find_cross_calls(comp_a: str, comp_b: str) -> str:
        """Grep for places where comp_a calls comp_b and vice versa."""
        results = []
        for caller, callee in ((comp_a, comp_b), (comp_b, comp_a)):
            src_files = list(src_dir.glob(f"**/{caller}.sol"))
            if not src_files:
                continue
            text = src_files[0].read_text(encoding="utf-8")
            lines = text.splitlines()
            hits = []
            for i, line in enumerate(lines):
                if callee.lower() in line.lower() or f"I{callee}" in line:
                    ctx_start = max(0, i - 1)
                    ctx_end = min(len(lines), i + 3)
                    hits.append(f"  L{i+1}: " + " | ".join(lines[ctx_start:ctx_end]))
            if hits:
                results.append(f"{caller} → {callee} ({len(hits)} call sites):\n" + "\n".join(hits[:10]))
        return "\n\n".join(results) if results else "No direct cross-calls detected."

    # Each pair writes to its own temp file; at the end we merge into the
    # canonical hyp_CrossComponent_DeepDiveHunter.yaml so extract_findings() finds it.
    hyp_dir = HUNT_SESSION_DIR / "hypotheses" / protocol
    hyp_dir.mkdir(parents=True, exist_ok=True)
    canonical_file = hyp_dir / "hyp_CrossComponent_DeepDiveHunter.yaml"

    # Clean up pair files from any previous run to avoid stale data contaminating the merge
    for stale in hyp_dir.glob("hyp_Cross_*.yaml"):
        stale.unlink()
    if canonical_file.exists():
        canonical_file.unlink()

    def _run_pair_hunt(pair: tuple) -> None:
        comp_a, comp_b = pair
        iface_a = _read_interface(comp_a)
        iface_b = _read_interface(comp_b)
        cross_calls = _find_cross_calls(comp_a, comp_b)
        # Temp file per pair — merged into canonical after all pairs complete
        pair_file = hyp_dir / f"hyp_Cross_{comp_a}_{comp_b}.yaml"
        pair_prompt = build_cross_pair_prompt(
            comp_a=comp_a, comp_b=comp_b, iface_a=iface_a, iface_b=iface_b,
            cross_calls=cross_calls, src_dir=src_dir, pair_file=pair_file
        )
        _llm(
            pair_prompt,
            allowed_tools=["Read", "Write", "Grep", "Glob"],
            timeout=900,
            stall_timeout=600,
            log_file=clog / f"cross_{comp_a}_{comp_b}.log",
            cwd=repo
        )
        logger.info(f"    Cross pair {comp_a}×{comp_b}: done")

    pairs = list(itertools.combinations(components_done, 2))
    logger.info(f"  Cross-A: {len(pairs)} pairs — {', '.join(f'{a}×{b}' for a,b in pairs)}")
    with ThreadPoolExecutor(max_workers=min(3, len(pairs))) as executor:
        list(executor.map(_run_pair_hunt, pairs))

    # Merge all per-pair YAML files into the canonical file that extract_findings() expects.
    # Also builds the combined source needed for the PoC phase below.
    import yaml as _yaml
    merged_findings = []
    for pair_file in sorted(hyp_dir.glob("hyp_Cross_*.yaml")):
        try:
            data = _yaml.safe_load(pair_file.read_text())
            if not data:
                continue
            # Collect from all possible keys — a YAML may have findings + hypotheses
            for key in ("findings", "hypotheses", "invariants"):
                for entry in (data.get(key) or []):
                    if isinstance(entry, dict):
                        merged_findings.append(entry)
        except Exception:
            pass
    if merged_findings:
        canonical_file.write_text(
            _yaml.dump({"hunter": "CrossComponentHunter",
                        "component": "CrossComponent",
                        "findings": merged_findings},
                       allow_unicode=True, sort_keys=False)
        )
        logger.info(f"  Cross-A merged: {len(merged_findings)} findings → {canonical_file.name}")

    # ─── Phase A.5: PoC + RedTeam for cross-component findings ────────
    # Cross-component findings are never PoC'd in the component pipelines.
    # We: (1) generate+test PoC, (2) only send PoC-confirmed to RedTeam.
    if merged_findings:
        # Build combined source from all component .sol files.
        # IMPORTANT: combined_source is NOT injected wholesale into any prompt.
        # It only feeds _extract_relevant_code(), which always outputs max 8K focused.
        # RedTeam/Escalation use focused_code (8K) + file access tools, never raw combined.
        # The cap exists only to bound memory and _extract_relevant_code search time.
        # Strategy: sort ascending by file size — small contracts always included fully;
        # only the largest get truncated if combined total exceeds the cap (rare).
        _CROSS_COMBINED_CAP = 100_000
        _comp_files = []
        for comp in components_done:
            src_files = list(src_dir.glob(f"**/{comp}.sol"))
            if src_files:
                size = src_files[0].stat().st_size
                _comp_files.append((size, comp, src_files[0]))
        _comp_files.sort()  # ascending by size — small contracts enter first, always complete

        combined_source = ""
        for size, comp, src_path in _comp_files:
            budget_left = _CROSS_COMBINED_CAP - len(combined_source)
            if budget_left <= 0:
                logger.warning(f"  Cross: combined_source hit {_CROSS_COMBINED_CAP//1000}K cap — "
                               f"skipping {comp} ({size//1000}K)")
                break
            raw = src_path.read_text(encoding="utf-8", errors="replace")
            if len(raw) > budget_left:
                raw = raw[:budget_left] + f"\n// ... {comp}.sol truncated (budget exhausted)\n"
                logger.info(f"  Cross: {comp}.sol truncated to {budget_left//1000}K "
                            f"(full size {size//1000}K)")
            combined_source += f"\n// === {comp}.sol ===\n{raw}\n"
        logger.info(f"  Cross: combined_source = {len(combined_source)//1000}K chars "
                    f"({len(_comp_files)} contracts)")

        # Build interfaces code (all interface files)
        cross_interfaces = ""
        iface_dir = src_dir / "interfaces"
        if iface_dir.exists():
            for ifile in sorted(iface_dir.glob("*.sol")):
                cross_interfaces += f"\n// === {ifile.name} ===\n{ifile.read_text()[:3000]}\n"

        # forge env for PoC runs
        cross_poc_env = os.environ.copy()
        cross_poc_env["FOUNDRY_PROFILE"] = "chimera"
        for _v in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
            _val = os.environ.get(_v, "")
            if _val:
                cross_poc_env[_v] = _val

        # Filter to high-confidence findings worth PoC'ing
        poc_candidates = [
            f for f in merged_findings
            if isinstance(f, dict)
            and f.get("confidence", 0) >= 65
            and f.get("severity", "Low").capitalize() in ("High", "Medium", "Critical")
        ]
        if poc_candidates:
            logger.info(f"  Cross-A.5: PoC → RedTeam on {len(poc_candidates)} cross-component findings")

            def _run_cross_finding(finding: dict) -> None:
                fid = finding.get("id", "?")
                # Step 1: generate and test PoC
                generate_and_test_poc(
                    finding, combined_source, cross_interfaces,
                    "CrossComponent", protocol, repo, clog, cross_poc_env,
                    poc_confidence_threshold=POC_CONFIDENCE_THRESHOLD
                )
                # Step 2: RedTeam only if PoC passed (or always — RedTeam will judge)
                run_finding_pipeline(
                    finding, "CrossComponent", protocol, combined_source, repo, clog,
                    benchmark_mode=True
                )
                logger.info(f"    Cross {fid}: PoC={'✓' if finding.get('has_poc') else '✗'} "
                            f"RedTeam={finding.get('redteam_verdict', '?')}")

            with ThreadPoolExecutor(max_workers=parallel_poc) as executor:
                futures = {executor.submit(_run_cross_finding, f): f for f in poc_candidates}
                for future in as_completed(futures):
                    finding = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"    Cross {finding.get('id','?')}: error: {e}")

            confirmed = [f for f in poc_candidates if f.get("has_poc")]
            reportable = [f for f in poc_candidates
                          if f.get("redteam_verdict") in ("REPORT", "REPORT_DOWNGRADED")]
            logger.info(f"  Cross-A.5 complete: {len(confirmed)} PoC confirmed, "
                        f"{len(reportable)} reportable")
        else:
            logger.info("  Cross-A.5: No high-confidence cross-component findings to PoC")

    # ─── Phase B: Multi-Contract Chimera Setup ───────────────────────
    logger.info("  Cross-B: Building multi-contract chimera setup")

    # Collect chimera backups from each component's log dir
    all_properties = {}
    for comp in components_done:
        backup_dir = LOG_DIR / comp / "chimera_backup"
        if backup_dir.exists():
            for f in backup_dir.glob("Properties*.sol"):
                # Namespace to avoid collisions: Properties_Strategy.sol etc
                target_name = f"Properties_{comp}.sol"
                all_properties[target_name] = f.read_text(encoding="utf-8")
                logger.info(f"    Restored {f.name} as {target_name} from {comp} backup")

    if not all_properties:
        logger.warning("  No chimera backups found — skipping cross-component fuzzing")
        return poc_candidates

    # Reset chimera to git state first
    if chimera_dir.exists():
        code_git, tracked, _ = run_cmd(
            ["git", "ls-files", str(chimera_dir.relative_to(Path(repo)))],
            cwd=repo
        )
        if code_git == 0 and tracked.strip():
            run_cmd(["git", "checkout", "--", str(chimera_dir.relative_to(Path(repo)))], cwd=repo)

    # Ask Claude to build multi-contract Setup.sol that deploys ALL components
    component_list = ", ".join(components_done)
    properties_summary = "\n".join(
        f"- {name}: {len(content.splitlines())} lines, "
        f"{content.count('function ')}) properties"
        for name, content in all_properties.items()
    )

    setup_prompt = (
        f"Build a CROSS-COMPONENT Chimera fuzzing setup for {protocol}.\n\n"
        f"## Components to deploy together: {component_list}\n\n"
        f"## Available per-component Properties (from individual hunts):\n{properties_summary}\n\n"
        f"## Task\n"
        f"1. Read the existing Setup.sol in {chimera_dir}/ to understand the current single-component setup\n"
        f"2. Read ALL source contracts: {', '.join(f'{c}.sol' for c in components_done)} in {src_dir}/\n"
        f"3. Create a NEW Setup.sol that deploys ALL {len(components_done)} components with their real interactions\n"
        f"   - Use the REAL contracts (not mocks) for cross-component calls\n"
        f"   - Wire dependencies correctly (e.g., Vault→Strategy, LendingPool→Vault)\n"
        f"   - Expose all contract instances as internal variables\n"
        f"4. Create Properties_CrossComponent.sol with interaction invariants:\n"
        f"   - Total value conservation across components\n"
        f"   - Custody: assets in component A XOR component B\n"
        f"   - Debt consistency: borrow in LP matches strategy accounting\n"
        f"   - Sequence invariants: A→B vs B→A should not diverge\n"
        f"5. Create TargetFunctions.sol with cross-component sequences as handlers\n"
        f"6. Update FoundryTester.sol and CryticTester.sol to inherit all Properties\n"
        f"7. Run `forge build` to verify it compiles\n\n"
        f"CRITICAL: the setup must deploy the REAL contracts interacting with each other, "
        f"not isolated instances. That's the whole point of cross-component testing."
    )
    _llm(
        setup_prompt,
        allowed_tools=["Read", "Write", "Edit", "Grep", "Glob", "Bash"],
        timeout=1800,
        log_file=clog / "cross_chimera_setup.log",
        cwd=repo
    )

    # ─── Phase C: Compile cross-component setup ──────────────────────
    logger.info("  Cross-C: Compile cross-component setup")
    compile_ok = fix_and_retry(
        "cross_compile",
        ["forge", "build"],
        [str(f) for f in chimera_dir.glob("*.sol")] if chimera_dir.exists() else [],
        max_retries=5,
        cwd=repo
    )

    if not compile_ok:
        logger.error("  Cross-component chimera failed to compile — skipping fuzzing")
        return poc_candidates

    # ─── Phase D: Fuzz cross-component ───────────────────────────────
    logger.info("  Cross-D: Phase 1 — Foundry 5K runs (cross-component)")
    # Build forge env with RPC vars
    cross_forge_env = os.environ.copy()
    cross_forge_env["FOUNDRY_PROFILE"] = "chimera"
    for var in ("ETH_RPC_URL", "FORK_URL", "BASE_RPC_URL"):
        val = os.environ.get(var, "")
        if val:
            cross_forge_env[var] = val

    code, stdout, stderr = run_cmd(
        ["forge", "test", "--match-contract", "FoundryTester", "--fuzz-runs", "5000", "-vv"],
        timeout=600,
        cwd=repo,
        log_file=clog / "cross_phase1.log",
        env=cross_forge_env
    )
    if code != 0:
        logger.info("  Cross-component Phase 1: Failures detected — potential cross-component bugs!")

    logger.info("  Cross-D: Phase 2 — Medusa 15 min (cross-component)")
    medusa_config = chimera_dir / f"medusa-{protocol}.json"
    if not medusa_config.exists():
        medusa_config = chimera_dir / "medusa.json"
    if medusa_config.exists():
        run_cmd(
            ["medusa", "fuzz", "--config", str(medusa_config), "--timeout", "900"],
            timeout=1000,
            cwd=repo,
            log_file=clog / "cross_phase2.log"
        )

    # ─── Phase E: Extract cross-component findings ───────────────────
    logger.info("  Cross-E: Extracting cross-component findings")
    cross_fuzz_failures = parse_fuzz_failures(
        clog / "cross_phase1.log",
        clog / "cross_phase2.log"
    )
    if cross_fuzz_failures:
        logger.info(f"  Cross-component fuzz failures: {cross_fuzz_failures}")
    findings = extract_findings("CrossComponent", protocol, cross_fuzz_failures)
    logger.info(f"  Cross-component hunt complete: {len(findings)} findings")
    return poc_candidates


# ─── Main ────────────────────────────────────────────────────────────────────

def _create_worktree(repo: str, component: str, protocol: str, run_id: str = "") -> str:
    """Create a git worktree for a component. Returns the effective repo path inside worktree.

    If --repo points to a subdirectory of the git root (e.g., .../repo/yieldoor),
    we create the worktree from the git root and return worktree_path + subdirectory offset.

    run_id: unique suffix per benchmark run (timestamp) to avoid collisions between concurrent runs.
    """
    import tempfile, shutil

    repo_path = Path(repo).resolve()

    # Find the actual git root
    code, git_root, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=str(repo_path))
    if code != 0:
        logger.error(f"  {repo} is not inside a git repo")
        return ""
    git_root = Path(git_root.strip()).resolve()

    # Prune any stale worktree registrations (missing dirs still registered in git)
    run_cmd(["git", "worktree", "prune"], cwd=str(git_root))

    # Compute subdirectory offset (e.g., "yieldoor" if repo=.../repo/yieldoor and git root=.../repo)
    try:
        subdir = repo_path.relative_to(git_root)
    except ValueError:
        subdir = Path(".")

    # Include run_id in name to avoid collisions between concurrent benchmark runs
    suffix = f"-{run_id}" if run_id else ""
    wt_path = str(Path(tempfile.gettempdir()) / f"bench-{protocol}-{component}{suffix}")

    # Clean up stale worktree if the directory still exists
    if Path(wt_path).exists():
        run_cmd(["git", "worktree", "remove", "--force", wt_path], cwd=str(git_root))
        if Path(wt_path).exists():
            shutil.rmtree(wt_path, ignore_errors=True)

    # Use -f (force) to override any stale git registration that survived prune
    code, _, stderr = run_cmd(
        ["git", "worktree", "add", "-f", "--detach", wt_path, "HEAD"], cwd=str(git_root)
    )
    if code != 0:
        logger.error(f"  Failed to create worktree for {component}: {stderr}")
        return ""

    effective_path = str(Path(wt_path) / subdir) if str(subdir) != "." else wt_path

    # Copy .env to worktree root so forge/foundry can read env vars (especially in agent mode
    # where subprocesses don't inherit shell exports)
    for _env_search in [repo_path, repo_path.parent, repo_path.parent.parent, git_root, git_root.parent]:
        _env_candidate = _env_search / ".env"
        if _env_candidate.exists():
            shutil.copy2(str(_env_candidate), str(Path(wt_path) / ".env"))
            logger.info(f"  Copied .env to worktree: {_env_candidate} → {wt_path}/.env")
            break

    # Patch foundry.toml to add [rpc_endpoints] if missing — prevents vm.createSelectFork("mainnet") failures
    ft = Path(effective_path) / "foundry.toml"
    if ft.exists():
        ft_text = ft.read_text(encoding="utf-8")
        if "[rpc_endpoints]" not in ft_text:
            ft.write_text(
                ft_text.rstrip() + "\n\n[rpc_endpoints]\n"
                'mainnet = "${ETH_RPC_URL}"\n'
                'base = "${BASE_RPC_URL}"\n'
                'arbitrum = "${ARB_RPC_URL}"\n',
                encoding="utf-8"
            )
            logger.info(f"  Patched foundry.toml: added [rpc_endpoints] in {effective_path}")

    logger.info(f"  Worktree created: {wt_path} (effective repo: {effective_path})")
    return effective_path


def _remove_worktree(repo: str, wt_path: str):
    """Remove a git worktree. Finds the actual worktree root (may differ from wt_path if subdir offset)."""
    if not wt_path or not Path(wt_path).exists():
        return
    # Find git root of the worktree to get the actual worktree path
    code, wt_root, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=wt_path)
    if code == 0:
        wt_root = wt_root.strip()
    else:
        wt_root = wt_path
    # Find git root of the main repo for the worktree remove command
    code, git_root, _ = run_cmd(["git", "rev-parse", "--show-toplevel"], cwd=repo)
    git_root = git_root.strip() if code == 0 else repo
    run_cmd(["git", "worktree", "remove", "--force", wt_root], cwd=git_root)
    logger.info(f"  Worktree removed: {wt_root}")


def main():
    parser = argparse.ArgumentParser(description="Pipeline orchestrator for hunt benchmarks")
    parser.add_argument("--repo", required=True, help="Path to the repo root")
    parser.add_argument("--components", required=True, help="Comma-separated component names")
    parser.add_argument("--protocol", required=True, help="Protocol name for namespacing")
    parser.add_argument("--ground-truth", help="Path to benchmark YAML (for scoring at end)")
    parser.add_argument("--max-retries", type=int, default=5, help="Max fix-and-retry attempts")
    parser.add_argument("--skip-phase3", action="store_true", help="Skip fork PoC (explicit)")
    parser.add_argument("--fast", action="store_true",
                        help="Fast mode: reduced fuzz runs (3K vs 5K), skip Medusa, compile retry=1. "
                             "Does NOT skip finding pipeline (verify/PoC/RedTeam) — that's controlled by --benchmark-mode.")
    parser.add_argument("--benchmark-mode",
                        choices=["hypothesis", "poc", "redteam"],
                        default="redteam",
                        help=(
                            "Benchmark depth. "
                            "'hypothesis': hunters+deepdive+scoring only (~45min/component). "
                            "'poc': +verification+PoC phase (~3h/component). "
                            "'redteam': +EscalationHunter+RedTeam (default, full pipeline)."
                        ))
    parser.add_argument("--workers", type=int, default=9, help="Max parallel hunters (default 9 = all hunters truly parallel, pure API calls)")
    parser.add_argument("--parallel-components", type=int, default=2,
                        help="Number of components to run in parallel (requires git worktrees, default 2 proven stable on 16GB)")
    parser.add_argument("--parallel-fuzz", type=int, default=3,
                        help="Number of parallel fuzz batches per component (forge-bound, default 3 for 16GB RAM)")
    parser.add_argument("--parallel-poc", type=int, default=3,
                        help="Number of parallel PoC generators per component (forge-bound, default 3 for 16GB RAM)")
    parser.add_argument("--pre-production", action="store_true",
                        help=(
                            "Protocol is pre-production (not deployed on-chain). "
                            "PoC generation deploys contracts in setUp() instead of using fork state. "
                            "Auto-detected if ground-truth YAML has no on-chain addresses."
                        ))
    parser.add_argument("--session-dir", help=(
        "Override hunt_session output directory. "
        "Default in benchmark mode: benchmarks/<protocol>/bench_session/ "
        "(isolated from the real hunt_session to avoid contamination)."
    ))
    parser.add_argument("--mode", choices=["api", "sub"], default="api",
                        help="Execution mode: 'api' (API key, stream-json, stall detection) or 'sub' (subscription, agentic tools, sonnet)")
    parser.add_argument("--parallel-hunters", type=int, default=6,
                        help="Max parallel hunter calls in sub mode (default 6, subscription rate limits)")
    parser.add_argument("--lang", default="",
                        help="Contract language: solidity, rust (auto-detected from repo if empty)")
    parser.add_argument("--chain", default="mainnet",
                        help="Target chain for fork PoCs (mainnet, base, optimism, arbitrum, polygon)")
    parser.add_argument("--fork-block", type=int, default=0,
                        help="Fork block for PoCs. 0 = latest (portable), N = pinned (deterministic)")

    args = parser.parse_args()

    # ── Isolate benchmark outputs ──────────────────────────────────────────
    # When running a benchmark, NEVER write to the real hunt_session/.
    # Auto-derive an isolated session dir alongside the ground-truth YAML,
    # or use the explicit --session-dir override.
    global HUNT_SESSION_DIR, IS_PRE_PRODUCTION
    if args.session_dir:
        HUNT_SESSION_DIR = Path(args.session_dir).resolve()
    elif args.ground_truth:
        HUNT_SESSION_DIR = Path(args.ground_truth).resolve().parent / "bench_session"
    # else: keep default WEB3_DIR / "hunt_session" (non-benchmark invocation)
    HUNT_SESSION_DIR.mkdir(parents=True, exist_ok=True)

    # Auto-detect pre-production: flag set OR ground-truth has no on-chain addresses
    IS_PRE_PRODUCTION = getattr(args, "pre_production", False)
    if not IS_PRE_PRODUCTION and args.ground_truth:
        try:
            import yaml as _yaml
            gt = _yaml.safe_load(Path(args.ground_truth).read_text())
            scope = gt.get("scope", [])
            # Pre-production if scope has only .sol paths (no 0x addresses)
            has_address = any(
                str(s).strip().startswith("0x") or str(s).strip().startswith("0X")
                for s in scope if isinstance(s, str)
            )
            if not has_address:
                IS_PRE_PRODUCTION = True
        except Exception:
            pass
    if IS_PRE_PRODUCTION:
        logger.info("  ⚠️  PRE-PRODUCTION mode: PoC will deploy contracts, not use fork state")

    setup_logging(args.protocol)

    # ── Sub mode globals ──────────────────────────────────────────────────
    global USE_SUB_MODE, SUB_MODEL, PARALLEL_HUNTERS
    if args.mode == "sub":
        USE_SUB_MODE = True
        SUB_MODEL = "sonnet"
        PARALLEL_HUNTERS = args.parallel_hunters
        logger.info(f"  SUB MODE: subscription, model={SUB_MODEL}, "
                    f"parallel-hunters={PARALLEL_HUNTERS}")

    components = [c.strip() for c in args.components.split(",")]
    repo = str(Path(args.repo).resolve())

    logger.info(f"Pipeline Orchestrator starting")
    logger.info(f"  Protocol: {args.protocol}")
    logger.info(f"  Components: {components}")
    logger.info(f"  Repo: {repo}")
    logger.info(f"  Session dir: {HUNT_SESSION_DIR}")
    logger.info(f"  Ground truth: {args.ground_truth or 'none'}")
    logger.info(f"  Parallel components: {args.parallel_components}")

    start_time = time.time()
    # Unique run ID (short timestamp) so concurrent benchmark runs never share worktree names
    run_id = datetime.now().strftime("%H%M%S")
    results = []
    components_done = []
    accumulated_context = ""

    def _write_incremental_findings(extra_findings: list = None) -> None:
        """Write findings_all.json checkpoint after each component completes (P0.3)."""
        flat = []
        for r in results:
            for f in r.get("findings", []):
                flat.append({
                    "component": r["component"],
                    "id": f.get("id", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "confidence": f.get("confidence", 0),
                    "fuzz_confirmed": f.get("fuzz_confirmed", False),
                    "poc_passed": f.get("has_poc", False),
                    "poc_path": f.get("poc_path", ""),
                    "hunter": f.get("hunter", ""),
                    "redteam_verdict": f.get("redteam_verdict", ""),
                    "redteam_kill_reason": f.get("redteam_kill_reason", ""),
                })
        for f in (extra_findings or []):
            flat.append({
                "component": "CrossComponent",
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", 0),
                "fuzz_confirmed": f.get("fuzz_confirmed", False),
                "poc_passed": f.get("has_poc", False),
                "poc_path": f.get("poc_path", ""),
                "hunter": "CrossComponentHunter",
                "redteam_verdict": f.get("redteam_verdict", ""),
                "redteam_kill_reason": f.get("redteam_kill_reason", ""),
            })
        findings_json = HUNT_SESSION_DIR / "findings_all.json"
        findings_json.write_text(json.dumps({
            "protocol": args.protocol,
            "components_done": components_done[:],
            "total_findings": len(flat),
            "generated_at": datetime.now().isoformat(),
            "complete": False,
            "findings": flat,
        }, indent=2, ensure_ascii=False))
        logger.info(f"  [checkpoint] findings_all.json updated: {len(flat)} findings")

    if args.parallel_components > 1:
        # ─── Parallel mode: worktrees ────────────────────────────────────
        logger.info(f"  🔀 PARALLEL MODE: {args.parallel_components} components at a time via worktrees")
        logger.info(f"  Run ID: {run_id} (worktree suffix to avoid cross-run conflicts)")

        # Process in batches of parallel_components
        for batch_start in range(0, len(components), args.parallel_components):
            batch = components[batch_start:batch_start + args.parallel_components]
            logger.info(f"\n  ── Batch {batch_start // args.parallel_components + 1}: "
                        f"{', '.join(batch)} ──")

            # Create worktrees
            worktrees = {}
            for comp in batch:
                wt = _create_worktree(repo, comp, args.protocol, run_id=run_id)
                if wt:
                    worktrees[comp] = wt
                else:
                    logger.error(f"  Skipping {comp} — worktree creation failed")

            # Run components in parallel
            batch_results = {}
            with ThreadPoolExecutor(max_workers=args.parallel_components) as executor:
                futures = {
                    executor.submit(
                        run_component_pipeline, comp, worktrees[comp],
                        args.protocol, args, accumulated_context=accumulated_context
                    ): comp
                    for comp in worktrees
                }
                for future in as_completed(futures):
                    comp = futures[future]
                    try:
                        result = future.result()
                        batch_results[comp] = result
                        results.append(result)
                    except Exception as e:
                        logger.error(f"  {comp}: pipeline error: {e}")
                        results.append({"component": comp, "status": "ERROR",
                                       "gates": {}, "findings": []})

            # Cleanup worktrees
            for comp, wt in worktrees.items():
                _remove_worktree(repo, wt)

            # Build accumulated context from this batch (for next batch)
            for comp in batch:
                result = batch_results.get(comp)
                if result and result.get("status") == "OK":
                    components_done.append(comp)
                    n_findings = len(result.get("findings", []))
                    confirmed = sum(1 for f in result.get("findings", [])
                                   if f.get("fuzz_confirmed"))
                    finding_summary = ""
                    for f in result.get("findings", [])[:10]:
                        finding_summary += (
                            f"\n  - {f.get('id','?')}: {f.get('title','')}"
                            f" (conf={f.get('confidence',0)}%,"
                            f" fuzz={f.get('fuzz_confirmed',False)})"
                        )
                    accumulated_context += (
                        f"\n## {comp} (completed)\n"
                        f"- {n_findings} findings ({confirmed} fuzz-confirmed)\n"
                        f"- Key findings:{finding_summary}\n"
                        f"- Key patterns found: check trust boundaries with this component\n"
                    )

            # Write incremental checkpoint after each batch
            _write_incremental_findings()

            # Cross-component runs once after ALL batches — see below

    else:
        # ─── Sequential mode (original) ─────────────────────────────────
        for i, component in enumerate(components):
            result = run_component_pipeline(component, repo, args.protocol, args,
                                            accumulated_context=accumulated_context)
            results.append(result)
            if result.get("status") == "OK":
                components_done.append(component)
                n_findings = len(result.get("findings", []))
                confirmed = sum(1 for f in result.get("findings", []) if f.get("fuzz_confirmed"))
                finding_summary = ""
                for f in result.get("findings", [])[:10]:
                    finding_summary += f"\n  - {f.get('id','?')}: {f.get('title','')} (conf={f.get('confidence',0)}%, fuzz={f.get('fuzz_confirmed',False)})"
                accumulated_context += (
                    f"\n## {component} (completed)\n"
                    f"- {n_findings} findings ({confirmed} fuzz-confirmed)\n"
                    f"- Key findings:{finding_summary}\n"
                    f"- Key patterns found: check trust boundaries with this component\n"
                )
            else:
                logger.warning(f"  {component} not added to cross-component (status: {result.get('status')})")
            # Write checkpoint after every component regardless of status
            # (so findings from a failed component are not lost if run is interrupted)
            _write_incremental_findings()

    # ─── Cross-component: single run after ALL components complete ────────
    # Runs once with the full components_done list to avoid redundant pair analysis.
    cross_findings: list[dict] = []
    if len(components_done) >= 2:
        cross_findings = run_cross_component(components_done, args.protocol, repo,
                                             parallel_poc=args.parallel_poc) or []

    # ─── Scoring ─────────────────────────────────────────────────────────
    if args.ground_truth:
        logger.info(f"\n{'='*60}")
        logger.info(f"  FINAL SCORING")
        logger.info(f"{'='*60}")

        # Filter scoring to only the components we actually ran
        score_cmd = [
            sys.executable, str(SCRIPT_DIR / "benchmark_score.py"),
            "--ground-truth", args.ground_truth,
            "--hypotheses-dir", str(HUNT_SESSION_DIR / "hypotheses" / args.protocol)
        ]
        if components:
            score_cmd += ["--components", ",".join(components)]
        code, stdout, _ = run_cmd(score_cmd, log_file=LOG_DIR / "scoring.log")

        logger.info(stdout)

    # ─── Summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    total_findings = sum(len(r.get("findings", [])) for r in results)

    logger.info(f"\n{'═'*60}")
    logger.info(f"  BENCHMARK COMPLETE: {args.protocol}")
    logger.info(f"{'═'*60}")
    logger.info(f"  Duration:       {elapsed/60:.1f} min")
    logger.info(f"  Components:     {len(components_done)}/{len(components)}")
    logger.info(f"  Total findings: {total_findings}")
    for r in results:
        gates_ok = sum(1 for v in r.get("gates", {}).values() if v)
        gates_total = len(r.get("gates", {}))
        n_findings = len(r.get("findings", []))
        status = r.get("status", "?")
        logger.info(f"    {r['component']:15s}  {gates_ok}/{gates_total} gates  {n_findings} findings  [{status}]")
    logger.info(f"{'═'*60}")
    logger.info(f"  Logs: {LOG_DIR}")

    # ─── Persist consolidated findings to JSON ────────────────────────────
    # Allows querying all findings from all components after the run completes.
    findings_json = HUNT_SESSION_DIR / "findings_all.json"
    all_findings_flat = []
    for r in results:
        for f in r.get("findings", []):
            all_findings_flat.append({
                "component": r["component"],
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "confidence": f.get("confidence", 0),
                "fuzz_confirmed": f.get("fuzz_confirmed", False),
                "poc_passed": f.get("has_poc", False),
                "poc_path": f.get("poc_path", ""),
                "hunter": f.get("hunter", ""),
                "redteam_verdict": f.get("redteam_verdict", ""),
                "redteam_kill_reason": f.get("redteam_kill_reason", ""),
            })
    # Include cross-component findings that were PoC'd and RedTeam'd
    for f in cross_findings:
        all_findings_flat.append({
            "component": "CrossComponent",
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "confidence": f.get("confidence", 0),
            "fuzz_confirmed": f.get("fuzz_confirmed", False),
            "poc_passed": f.get("has_poc", False),
            "poc_path": f.get("poc_path", ""),
            "hunter": "CrossComponentHunter",
            "redteam_verdict": f.get("redteam_verdict", ""),
            "redteam_kill_reason": f.get("redteam_kill_reason", ""),
        })
    findings_json_data = {
        "protocol": args.protocol,
        "components": components_done,
        "total_findings": len(all_findings_flat),
        "generated_at": datetime.now().isoformat(),
        "complete": True,
        "findings": all_findings_flat,
    }
    findings_json.write_text(json.dumps(findings_json_data, indent=2, ensure_ascii=False))
    logger.info(f"  Findings JSON: {findings_json}")

    # ─── P1.3: Hunter performance tracking ───────────────────────────────
    # Scan all hyp_*.yaml files and compute per-hunter stats:
    # total hypotheses, validated count, avg confidence, finding conversion rate
    import yaml as _perf_yaml  # ensure yaml is available in main() scope
    hunter_stats: dict = {}
    hyp_dir_final = HUNT_SESSION_DIR / "hypotheses" / args.protocol
    if hyp_dir_final.exists():
        for hyp_file in sorted(hyp_dir_final.glob("hyp_*.yaml")):
            # Extract hunter name from filename: hyp_<Component>_<HunterName>.yaml
            parts = hyp_file.stem.split("_", 2)  # ['hyp', 'Component', 'HunterName']
            hunter_name = parts[2] if len(parts) >= 3 else hyp_file.stem
            try:
                data = _perf_yaml.safe_load(hyp_file.read_text())
                if not data:
                    continue
                hyps = []
                for key in ("hypotheses", "findings", "invariants"):
                    hyps.extend(h for h in (data.get(key) or []) if isinstance(h, dict))
                if not hyps:
                    continue
                confidences = [h.get("confidence", 0) for h in hyps]
                validated = sum(1 for h in hyps if h.get("validated"))
                hs = hunter_stats.setdefault(hunter_name, {
                    "total_hypotheses": 0, "validated": 0, "confidence_sum": 0,
                    "files": 0, "high_confidence": 0,
                })
                hs["total_hypotheses"] += len(hyps)
                hs["validated"] += validated
                hs["confidence_sum"] += sum(confidences)
                hs["files"] += 1
                hs["high_confidence"] += sum(1 for c in confidences if c >= 70)
            except Exception:
                pass

    # Compute derived metrics and write JSON
    hunter_perf = []
    for hunter_name, hs in sorted(hunter_stats.items()):
        total = hs["total_hypotheses"]
        # Count how many findings in all_findings_flat came from this hunter
        # Exact match: "MathHunter" == f["hunter"] — avoid substring false positives
        # e.g. "Hunter" substring would match every hunter name
        findings_generated = sum(
            1 for f in all_findings_flat if f.get("hunter", "") == hunter_name
        )
        hunter_perf.append({
            "hunter": hunter_name,
            "total_hypotheses": total,
            "validated_hypotheses": hs["validated"],
            "high_confidence_hypotheses": hs["high_confidence"],
            "avg_confidence": round(hs["confidence_sum"] / total, 1) if total else 0,
            "findings_generated": findings_generated,
            "components_covered": hs["files"],
        })
    # Sort by findings_generated desc, then avg_confidence desc
    hunter_perf.sort(key=lambda x: (-x["findings_generated"], -x["avg_confidence"]))

    perf_json = HUNT_SESSION_DIR / "hunter_performance.json"
    perf_json.write_text(json.dumps({
        "protocol": args.protocol,
        "generated_at": datetime.now().isoformat(),
        "hunters": hunter_perf,
    }, indent=2, ensure_ascii=False))
    logger.info(f"  Hunter perf:   {perf_json}")
    if hunter_perf:
        logger.info(f"  Top hunters by findings:")
        for hp in hunter_perf[:5]:
            logger.info(f"    {hp['hunter']:25s} {hp['findings_generated']} findings, "
                        f"{hp['total_hypotheses']} hyps, avg_conf={hp['avg_confidence']}")

    logger.info(f"  Reports:       {HUNT_SESSION_DIR / 'reports'}/")
    logger.info(f"  Hypotheses:    {HUNT_SESSION_DIR / 'hypotheses' / args.protocol}/")
    logger.info(f"")
    logger.info(f"  To re-score hypotheses vs ground truth:")
    if args.ground_truth:
        logger.info(f"    python3 audit-agents/benchmark_score.py \\")
        logger.info(f"      --ground-truth {args.ground_truth} \\")
        logger.info(f"      --hypotheses-dir {HUNT_SESSION_DIR / 'hypotheses' / args.protocol}")


if __name__ == "__main__":
    main()
