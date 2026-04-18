"""LLM/subprocess runners — extracted from run_benchmark.py in Phase 6.

Provides:
    - run_claude (async Claude Code invocation via CLI)
    - _run_claude_inner (internal helper)
    - run_claude_sub (subscription mode variant)
    - _llm (dispatch wrapper selecting mode)
    - run_cmd (generic subprocess wrapper with timeout + capture)
    - _extract_first_errors (stderr truncation utility)

Zero internal dependencies — consumers: benchmark.poc_pipeline,
benchmark.component_pipeline, benchmark.finding_pipeline,
benchmark.cross_component, benchmark.cli.
"""
from __future__ import annotations

import json as _json_mod
import logging
import os
import signal
import subprocess
import threading
import time
from pathlib import Path

from paths import WEB3_DIR

# ─── Logger (shared with orchestrator via Python logging singleton) ──────────
logger = logging.getLogger("orchestrator")

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

# ─── LLM dispatcher globals (mutated by run_benchmark.main()) ────────────────
USE_SUB_MODE = False  # Set in main() based on --mode sub
SUB_MODEL = "sonnet"  # Set in main()

# Steps that get tool access in sub mode (agentic exploration).
_AGENTIC_TOOLS = {"Read", "Write", "Edit", "Grep", "Glob", "Bash", "Agent"}


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
