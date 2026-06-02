import os
import sys
import time
import logging
from collections import defaultdict
from mcp.server.fastmcp import FastMCP  # type: ignore

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from sandbox_manager import SandboxManager  # type: ignore

logging.getLogger("sandbox_manager").setLevel(logging.CRITICAL)

mcp = FastMCP("CTF Sandbox")
manager = SandboxManager()

# Simple token-bucket rate limiter: max 20 calls per 60-second window per caller.
_rate_limit: dict = defaultdict(list)
_RATE_LIMIT_MAX = 20
_RATE_LIMIT_WINDOW = 60  # seconds


def _check_rate_limit(caller_id: str = "default") -> bool:
    now = time.monotonic()
    window_start = now - _RATE_LIMIT_WINDOW
    calls = [t for t in _rate_limit[caller_id] if t > window_start]
    _rate_limit[caller_id] = calls
    if len(calls) >= _RATE_LIMIT_MAX:
        return False
    _rate_limit[caller_id].append(now)
    return True


@mcp.tool()
def execute_in_sandbox(command: str) -> str:
    """
    Execute a command inside the isolated CTF Kali Linux Docker Sandbox.
    Dangerous patterns (container escapes, disk overwrites, privilege escalation)
    are blocked before execution. Rate limited to 20 calls/minute.
    Returns stdout, stderr, and exit code.
    """
    if not _check_rate_limit():
        return "[SECURITY] Rate limit exceeded. Max 20 commands per 60 seconds."

    if not command or len(command.strip()) == 0:
        return "[ERROR] Empty command."

    try:
        manager.start()
        code, out, err = manager.execute_command(command)
        result = f"Exit code: {code}\n"
        if out:
            result += f"STDOUT:\n{out}\n"
        if err:
            result += f"STDERR:\n{err}\n"
        return result
    except Exception as e:
        return f"[ERROR] Sandbox execution failed: {e}"


@mcp.tool()
def start_sandbox() -> str:
    """Start the sandbox container manually."""
    if manager.start():
        return "Sandbox started successfully."
    return "Failed to start sandbox. Check Docker is running and the image exists."


@mcp.tool()
def stop_sandbox() -> str:
    """Stop the sandbox container."""
    if manager.stop():
        return "Sandbox stopped successfully."
    return "Failed to stop sandbox."


@mcp.tool()
def sandbox_status() -> str:
    """Check if the sandbox container is currently running."""
    if manager.is_running():
        return "Sandbox is currently RUNNING."
    return "Sandbox is currently STOPPED."


if __name__ == "__main__":
    mcp.run()
