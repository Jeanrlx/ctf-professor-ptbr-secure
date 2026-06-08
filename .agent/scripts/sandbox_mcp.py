"""
Sandbox MCP Server — CTF Professor
=====================================
Exposes the Docker CTF sandbox to Claude Code via the Model Context Protocol.

Security controls layered here (in addition to sandbox_manager.py):
  - Rate limiting: 20 calls / 60 s (token-bucket, per-caller)
  - Output already capped inside SandboxManager; reported here too
  - Errors returned as opaque messages (no stack traces to the LLM)
  - Tool docstrings intentionally describe what is SAFE to call so the
    LLM agent doesn't accidentally invoke privileged operations.
"""

import logging
import os
import sys
import time
from collections import defaultdict

from mcp.server.fastmcp import FastMCP  # type: ignore

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sandbox_manager import SandboxManager  # type: ignore

# Silence sandbox_manager's INFO stream; WARN/ERROR still surface
logging.getLogger("sandbox_manager").setLevel(logging.WARNING)

mcp = FastMCP("CTF Sandbox")
manager = SandboxManager()

# ── Rate limiter ─────────────────────────────────────────────────────────────
# Token-bucket: max 20 calls per 60-second sliding window, per caller ID.
_rate_windows: dict[str, list[float]] = defaultdict(list)
_RATE_MAX = 20
_RATE_WINDOW = 60  # seconds


def _check_rate_limit(caller_id: str = "default") -> bool:
    now = time.monotonic()
    cutoff = now - _RATE_WINDOW
    calls = [t for t in _rate_windows[caller_id] if t > cutoff]
    _rate_windows[caller_id] = calls
    if len(calls) >= _RATE_MAX:
        return False
    _rate_windows[caller_id].append(now)
    return True


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
def execute_in_sandbox(command: str) -> str:
    """
    Execute a shell command inside the isolated Kali Linux CTF sandbox.

    The sandbox runs as a non-root user with a read-only filesystem,
    custom seccomp profile, and minimal Linux capabilities.
    Commands that attempt container escapes, disk writes, or privilege
    escalation are blocked before reaching Docker.

    Output is capped at 50 KB per call. Rate limited to 20 calls/min.

    Args:
        command: A shell command appropriate for CTF analysis (file, strings,
                 nmap, gdb, python3, radare2, etc.)

    Returns:
        String containing exit code, stdout, and stderr from the command.
    """
    if not _check_rate_limit():
        return "[SECURITY] Rate limit exceeded — max 20 commands per 60 seconds."

    if not command or not command.strip():
        return "[ERROR] Empty command."

    try:
        manager.start()
        code, out, err = manager.execute_command(command)
        parts = [f"Exit code: {code}"]
        if out:
            parts.append(f"STDOUT:\n{out}")
        if err:
            parts.append(f"STDERR:\n{err}")
        return "\n".join(parts)
    except Exception:
        # Return an opaque error — never expose stack traces to the LLM
        return "[ERROR] Sandbox execution failed. Check that Docker is running."


@mcp.tool()
def start_sandbox() -> str:
    """
    Start the CTF sandbox container.

    Safe to call multiple times — returns immediately if already running.
    """
    try:
        if manager.start():
            return "Sandbox started successfully."
        return "Failed to start sandbox. Ensure Docker is running and 'cyber-ctf-kali' image exists."
    except Exception:
        return "[ERROR] Could not start sandbox."


@mcp.tool()
def stop_sandbox() -> str:
    """Stop the CTF sandbox container and free its resources."""
    try:
        if manager.stop():
            return "Sandbox stopped."
        return "Could not stop sandbox."
    except Exception:
        return "[ERROR] Could not stop sandbox."


@mcp.tool()
def sandbox_status() -> str:
    """Return whether the CTF sandbox is currently running."""
    try:
        running = manager.is_running()
        return "Sandbox is RUNNING." if running else "Sandbox is STOPPED."
    except Exception:
        return "[ERROR] Could not query sandbox status."


if __name__ == "__main__":
    mcp.run()
