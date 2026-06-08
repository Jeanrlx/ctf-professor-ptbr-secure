"""
SandboxManager — CTF Professor
================================
Manages an ephemeral Docker Kali Linux container for CTF command execution.

Security model
--------------
- Non-root user 'ctfuser' inside the container.
- Custom seccomp profile; seccomp=unconfined is NEVER used.
- Capabilities explicitly dropped (--cap-drop=ALL), then re-added minimally.
- Commands validated against a blocklist AFTER normalisation (base64/hex decode)
  to defeat encoding-based bypasses.
- Output is capped at MAX_OUTPUT_BYTES to prevent terminal flooding.
- Per-execution timeout (default 60 s) enforced via subprocess.
- Container healthcheck polled before first exec to avoid race conditions.
- Every executed command is written to a structured JSONL audit log.
"""

import base64
import binascii
import datetime
import json
import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("sandbox_manager")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_COMMAND_LEN = 4096
_MAX_OUTPUT_BYTES = 51_200          # 50 KB per execution — prevents terminal flood
_DEFAULT_EXEC_TIMEOUT = 60          # seconds
_CONTAINER_READY_TIMEOUT = 30       # seconds to wait for healthcheck
_AUDIT_LOG_PATH = Path(".agent/logs/audit.jsonl")

# Patterns checked on the RAW command AND on normalised (decoded) variants.
# They match container-escape, destructive, or privilege-escalation primitives.
_BLOCKED_PATTERNS: list[tuple[str, str]] = [
    (r"nsenter",                   "namespace escape"),
    (r"--privileged",              "privilege escalation flag"),
    (r"/proc/sysrq",               "kernel panic trigger"),
    (r"mkfs\.",                    "filesystem destruction"),
    (r"\bdd\b.*of=/dev/",          "raw disk overwrite"),
    (r">\s*/dev/sd[a-z]",          "disk overwrite via redirect"),
    (r"docker\s+(run|exec)\s",     "docker-in-docker"),
    (r"unshare\s+--mount",         "mount namespace escape"),
    (r"mount\s+-t\s+(proc|sys)",   "host procfs/sysfs mount"),
    (r"curl\s+.*\|\s*(bash|sh)",   "remote shell pipe (curl)"),
    (r"wget\s+.*\|\s*(bash|sh)",   "remote shell pipe (wget)"),
    (r"chmod\s+[0-9]*s",           "setuid bit (symbolic)"),
    (r"chmod\s+[4-7][0-7]{3}",        "setuid/sticky bit (octal)"),
    (r"chown\s+root",              "chown to root"),
    # Additional patterns not present in original
    (r"python[23]?\s+-c.*os\.system", "inline os.system via python"),
    (r"\$\(.*\)",                  "command substitution (review)"),
    (r"`[^`]+`",                   "backtick command substitution"),
    (r"eval\s+",                   "eval execution"),
    (r"exec\s+\d*<>",              "file descriptor redirect exec"),
    (r"/proc/self/mem",            "process memory write via /proc"),
    (r"LD_PRELOAD",                "LD_PRELOAD injection"),
    (r"LD_LIBRARY_PATH.*\.\./",    "library path traversal"),
]

# ANSI escape sequence stripper — prevents terminal control attacks in output
_ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _decode_base64_segments(text: str) -> str:
    """Replace any base64-looking segments with their decoded form."""
    # Match tokens that look like base64 (length ≥8, only b64 chars, '=' padding)
    b64_re = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")

    def try_decode(m: re.Match) -> str:
        token = m.group(0)
        try:
            decoded = base64.b64decode(token + "==").decode("utf-8", errors="replace")
            # Only substitute if the decoded string is printable ASCII
            if decoded.isprintable():
                return decoded
        except (binascii.Error, ValueError):
            pass
        return token

    return b64_re.sub(try_decode, text)


def _decode_hex_escapes(text: str) -> str:
    """Expand \\xNN hex escapes in a string."""
    def try_hex(m: re.Match) -> str:
        try:
            return bytes.fromhex(m.group(1)).decode("utf-8", errors="replace")
        except ValueError:
            return m.group(0)

    return re.sub(r"\\x([0-9a-fA-F]{2})", try_hex, text)


def _normalise(command: str) -> str:
    """
    Return all decoded variants of *command* as a single concatenated string.

    By checking one long string we avoid choosing the "wrong" candidate —
    the blocklist regex just needs to match ANY decoded form.
    """
    hex_decoded  = _decode_hex_escapes(command)
    b64_decoded  = _decode_base64_segments(command)
    both_decoded = _decode_base64_segments(hex_decoded)
    # Join all variants; patterns will match whichever form contains the threat
    combined = " ".join({command, hex_decoded, b64_decoded, both_decoded})
    return re.sub(r"\s+", " ", combined)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_command(command: str) -> Tuple[bool, str]:
    """
    Validate *command* against the blocklist.

    Checks are applied to both the raw string and a normalised (decoded)
    variant to defeat encoding-based bypasses.

    Returns:
        (True, "OK")  — safe to execute
        (False, reason) — must abort
    """
    if not command or not command.strip():
        return False, "Empty command rejected."

    if len(command) > _MAX_COMMAND_LEN:
        return False, f"Command exceeds {_MAX_COMMAND_LEN} chars."

    candidates = [command, _normalise(command)]

    for candidate in candidates:
        for pattern, label in _BLOCKED_PATTERNS:
            if re.search(pattern, candidate, re.IGNORECASE):
                return False, f"Blocked: {label} (pattern: {pattern!r})"

    return True, "OK"


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def _audit(event: str, **kwargs) -> None:
    """Append a structured JSONL entry to the audit log."""
    _AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.datetime.utcnow().isoformat() + "Z",
        "event": event,
        **kwargs,
    }
    try:
        with _AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as exc:
        logger.warning("Audit log write failed: %s", exc)


# ---------------------------------------------------------------------------
# SandboxManager
# ---------------------------------------------------------------------------

class SandboxManager:
    """Manages an ephemeral Docker container for safe CTF command execution."""

    def __init__(
        self,
        image_name: str = "cyber-ctf-kali",
        container_name: str = "ctf_sandbox",
    ) -> None:
        self.image_name = image_name
        self.container_name = container_name
        self._seccomp_path = (
            Path(__file__).resolve().parent / ".." / "sandbox" / "seccomp-ctf.json"
        ).resolve()

    # ── Container lifecycle ──────────────────────────────────────────────────

    def is_running(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
                capture_output=True, text=True, check=False,
            )
            return result.stdout.strip() == "true"
        except Exception:
            return False

    def _wait_healthy(self, timeout: int = _CONTAINER_READY_TIMEOUT) -> bool:
        """
        Poll the container's healthcheck until it reports 'healthy' or times out.
        This prevents execute_command from racing against a not-yet-ready container.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                result = subprocess.run(
                    ["docker", "inspect", "-f", "{{.State.Health.Status}}", self.container_name],
                    capture_output=True, text=True, check=False,
                )
                status = result.stdout.strip()
                if status == "healthy":
                    return True
                # Container has no healthcheck configured — treat as ready
                if status in ("", "none"):
                    return True
            except Exception:
                pass
            time.sleep(1)
        logger.warning("Container did not become healthy within %d s.", timeout)
        return False

    def start(self, workdir: str | None = None) -> bool:
        if self.is_running():
            logger.info("Sandbox '%s' is already running.", self.container_name)
            return True

        workdir = os.path.realpath(workdir or os.getcwd())

        if self._seccomp_path.exists():
            seccomp_opt = f"seccomp={self._seccomp_path}"
        else:
            logger.warning("Custom seccomp profile not found — using Docker default.")
            seccomp_opt = "no-new-privileges"

        cmd = [
            "docker", "run", "-d", "--rm",
            "--name", self.container_name,
            "--network=bridge",
            # Drop ALL capabilities; re-add only what CTF tools strictly need
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",    # nmap raw-socket / ICMP
            "--cap-add=NET_ADMIN",  # openvpn tun interface
            "--cap-add=SYS_PTRACE", # gdb / strace
            "--security-opt", seccomp_opt,
            "--security-opt", "no-new-privileges",
            # Read-only root FS; /tmp writable but non-executable
            "--read-only",
            "--tmpfs", "/tmp:size=256m,noexec,nosuid",
            # Mount workspace read-write so challenge files are accessible
            "-v", f"{workdir}:/workspace",
            "-w", "/workspace",
            "--user", "ctfuser",
            # Resource limits to prevent runaway processes
            "--memory=1g",
            "--memory-swap=1g",     # disables swap (swap = memory limit)
            "--cpus=1.5",
            "--pids-limit=256",
            self.image_name,
            "sleep", "infinity",
        ]

        logger.info("Starting sandbox '%s'…", self.container_name)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info("Sandbox started: %s", result.stdout.strip()[:12])
            _audit("sandbox_start", container=self.container_name, workdir=workdir)
            self._wait_healthy()
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to start sandbox: %s", exc.stderr)
            _audit("sandbox_start_failed", error=exc.stderr)
            return False

    def stop(self) -> bool:
        if not self.is_running():
            logger.info("Sandbox is not running.")
            return True

        logger.info("Stopping sandbox '%s'…", self.container_name)
        try:
            subprocess.run(
                ["docker", "kill", self.container_name],
                capture_output=True, text=True, check=True,
            )
            logger.info("Sandbox stopped.")
            _audit("sandbox_stop", container=self.container_name)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Failed to stop sandbox: %s", exc.stderr)
            return False

    # ── Command execution ────────────────────────────────────────────────────

    def execute_command(
        self,
        command: str,
        timeout: int = _DEFAULT_EXEC_TIMEOUT,
    ) -> Tuple[int, str, str]:
        """
        Validate and execute *command* inside the running sandbox.

        Output is capped at MAX_OUTPUT_BYTES and stripped of ANSI sequences
        to prevent terminal control attacks from reaching the host.

        Returns:
            (exit_code, stdout, stderr)
        """
        is_safe, reason = _validate_command(command)
        if not is_safe:
            logger.warning("[BLOCKED] %s | cmd=%r", reason, command)
            _audit("command_blocked", reason=reason, command=command)
            return 1, "", f"[SECURITY] Command blocked: {reason}"

        if not self.is_running():
            logger.warning("Sandbox not running — attempting start.")
            if not self.start():
                return 1, "", "Failed to start sandbox."

        logger.info("[AUDIT] exec: %r", command)
        _audit("command_exec", command=command)

        docker_cmd = ["docker", "exec", self.container_name, "bash", "-c", command]

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("Command timed out after %d s.", timeout)
            _audit("command_timeout", command=command, timeout=timeout)
            # Kill the lingering process inside the container
            subprocess.run(
                ["docker", "exec", self.container_name, "bash", "-c",
                 "kill -9 $(jobs -p) 2>/dev/null; true"],
                capture_output=True, timeout=5,
            )
            return 124, "", f"[TIMEOUT] Command exceeded {timeout} s."
        except Exception as exc:
            logger.error("Execution error: %s", exc)
            return 1, "", str(exc)

        stdout = _truncate_output(result.stdout)
        stderr = _truncate_output(result.stderr)
        _audit(
            "command_result",
            command=command,
            exit_code=result.returncode,
            stdout_bytes=len(result.stdout),
            stderr_bytes=len(result.stderr),
            truncated=len(result.stdout) > _MAX_OUTPUT_BYTES or len(result.stderr) > _MAX_OUTPUT_BYTES,
        )
        return result.returncode, stdout, stderr


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _truncate_output(text: str) -> str:
    """Strip ANSI escapes and cap output at MAX_OUTPUT_BYTES."""
    clean = _ANSI_ESCAPE.sub("", text)
    encoded = clean.encode("utf-8", errors="replace")
    if len(encoded) > _MAX_OUTPUT_BYTES:
        truncated = encoded[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")
        return truncated + f"\n[... output truncated at {_MAX_OUTPUT_BYTES} bytes ...]"
    return clean


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="CTF Sandbox Manager")
    parser.add_argument("action", choices=["start", "stop", "exec", "status"])
    parser.add_argument("--cmd", help="Command to execute (exec action)")
    parser.add_argument("--workdir", help="Directory to mount (start action)")
    parser.add_argument("--timeout", type=int, default=_DEFAULT_EXEC_TIMEOUT,
                        help="Execution timeout in seconds")
    args = parser.parse_args()

    mgr = SandboxManager()

    if args.action == "status":
        print(f"Sandbox running: {mgr.is_running()}")
    elif args.action == "start":
        mgr.start(args.workdir)
    elif args.action == "stop":
        mgr.stop()
    elif args.action == "exec":
        if not args.cmd:
            parser.error("--cmd is required for 'exec'")
        code, out, err = mgr.execute_command(args.cmd, timeout=args.timeout)
        print(f"Exit code: {code}")
        if out:
            print(f"Stdout:\n{out}")
        if err:
            print(f"Stderr:\n{err}")


if __name__ == "__main__":
    main()
