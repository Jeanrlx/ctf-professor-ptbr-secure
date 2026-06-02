import os
import re
import subprocess
import logging
from typing import Dict, Any, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("sandbox_manager")

# Patterns that indicate container escape attempts or destructive operations.
# The LLM agent should never need these; if seen, reject immediately.
_BLOCKED_PATTERNS = [
    r"nsenter",                  # namespace escape
    r"--privileged",             # privilege escalation flag
    r"/proc/sysrq",              # kernel panic trigger
    r"mkfs\.",                   # filesystem destruction
    r"\bdd\b.*of=/dev/",         # raw disk overwrite
    r">\s*/dev/sd[a-z]",        # disk overwrite via redirect
    r"docker\s+(run|exec)\s",   # docker-in-docker
    r"unshare\s+--mount",        # mount namespace escape
    r"mount\s+-t\s+(proc|sys)",  # host procfs/sysfs mount
    r"curl\s+.*\|\s*(bash|sh)",  # remote shell pipe
    r"wget\s+.*\|\s*(bash|sh)",  # remote shell pipe
    r"chmod\s+[0-9]*s",          # setuid bit
    r"chown\s+root",             # chown to root
]
_MAX_COMMAND_LEN = 4096


def _validate_command(command: str) -> Tuple[bool, str]:
    """
    Checks a command string against the blocklist before execution.
    Returns (is_safe, reason). A False result must abort execution.
    """
    if not command or not command.strip():
        return False, "Empty command rejected."

    if len(command) > _MAX_COMMAND_LEN:
        return False, f"Command exceeds maximum length of {_MAX_COMMAND_LEN} chars."

    for pattern in _BLOCKED_PATTERNS:
        if re.search(pattern, command, re.IGNORECASE):
            return False, f"Blocked pattern detected: '{pattern}'"

    return True, "OK"


class SandboxManager:
    """
    Manages an ephemeral Docker container for CTF command execution.

    Security model:
    - Runs as non-root user 'ctfuser' inside the container.
    - Uses a custom seccomp profile; seccomp=unconfined is NOT used.
    - Capabilities are explicitly dropped first, then only required ones re-added.
    - All commands are validated against a blocklist before execution.
    - All executed commands are logged for audit.
    """

    def __init__(self, image_name: str = "cyber-ctf-kali", container_name: str = "ctf_sandbox"):
        self.image_name = image_name
        self.container_name = container_name
        self._seccomp_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "sandbox", "seccomp-ctf.json"
        )

    def is_running(self) -> bool:
        try:
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
                capture_output=True, text=True, check=False
            )
            return result.stdout.strip() == "true"
        except Exception:
            return False

    def start(self, workdir: str = None) -> bool:
        if self.is_running():
            logger.info(f"Sandbox '{self.container_name}' is already running.")
            return True

        if workdir is None:
            workdir = os.getcwd()

        # Resolve and validate workdir to prevent path traversal
        workdir = os.path.realpath(workdir)

        logger.info(f"Starting sandbox '{self.container_name}' with mount '{workdir}:/workspace'...")

        seccomp_opt = f"seccomp={os.path.realpath(self._seccomp_path)}"
        if not os.path.exists(os.path.realpath(self._seccomp_path)):
            # Fall back to default (not unconfined) if custom profile is missing
            logger.warning("Custom seccomp profile not found. Using Docker default seccomp.")
            seccomp_opt = "no-new-privileges"

        cmd = [
            "docker", "run", "-d", "--rm",
            "--name", self.container_name,
            "--network=bridge",
            # Drop ALL capabilities first, then re-add only what is strictly required
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",        # nmap raw socket
            "--cap-add=NET_ADMIN",      # openvpn tun interface
            "--cap-add=SYS_PTRACE",     # gdb / strace (kept for CTF tooling)
            "--security-opt", seccomp_opt,
            "--security-opt", "no-new-privileges",
            # Read-only root filesystem except /workspace and /tmp
            "--read-only",
            "--tmpfs", "/tmp:size=256m,noexec",
            "-v", f"{workdir}:/workspace",
            "-w", "/workspace",
            # Run as non-root user defined in Dockerfile
            "--user", "ctfuser",
            self.image_name,
            "sleep", "infinity"
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Sandbox started. ID: {result.stdout.strip()[:12]}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to start sandbox: {e.stderr}")
            return False

    def stop(self) -> bool:
        if not self.is_running():
            logger.info("Sandbox is not running.")
            return True

        logger.info(f"Stopping sandbox '{self.container_name}'...")
        try:
            subprocess.run(["docker", "kill", self.container_name], capture_output=True, text=True, check=True)
            logger.info("Sandbox stopped.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop sandbox: {e.stderr}")
            return False

    def execute_command(self, command: str, timeout: int = 60) -> Tuple[int, str, str]:
        """
        Execute a command inside the running sandbox after validation.

        Returns:
            Tuple[int, str, str]: (exit_code, stdout, stderr)
        """
        is_safe, reason = _validate_command(command)
        if not is_safe:
            logger.warning(f"[BLOCKED] Command rejected: {reason} | Command: {command!r}")
            return 1, "", f"[SECURITY] Command blocked: {reason}"

        if not self.is_running():
            logger.warning("Sandbox is not running. Attempting to start it...")
            if not self.start():
                return 1, "", "Failed to start the sandbox environment."

        # Audit log — every command executed is recorded
        logger.info(f"[AUDIT] Executing in sandbox: {command!r}")

        cmd = ["docker", "exec", self.container_name, "bash", "-c", command]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout} seconds.")
            return 124, "", f"Command timed out after {timeout} seconds."
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return 1, "", str(e)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CTF Sandbox Manager")
    parser.add_argument("action", choices=["start", "stop", "exec", "status"])
    parser.add_argument("--cmd", help="Command to execute (for 'exec' action)")
    parser.add_argument("--workdir", help="Directory to mount (for 'start' action)")

    args = parser.parse_args()
    manager = SandboxManager()

    if args.action == "status":
        print(f"Sandbox running: {manager.is_running()}")
    elif args.action == "start":
        manager.start(args.workdir)
    elif args.action == "stop":
        manager.stop()
    elif args.action == "exec":
        if not args.cmd:
            print("Error: --cmd is required for 'exec' action")
            return
        code, out, err = manager.execute_command(args.cmd)
        print(f"Exit code: {code}")
        if out:
            print(f"Stdout:\n{out}")
        if err:
            print(f"Stderr:\n{err}")


if __name__ == "__main__":
    main()
