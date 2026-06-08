#!/usr/bin/env python3
"""
CTF Platform Client — CTF Professor
=====================================
Unified API client for CTFd, HackTheBox, and TryHackMe.
Handles metadata fetching, file downloads, and flag submission.

Security hardening applied:
  - URL validation (scheme + allowlist) before every request
  - Download size capped at MAX_DOWNLOAD_BYTES
  - Credentials loaded from .env with strict parsing (no shell expansion)
  - Requests always set explicit timeouts
  - No sensitive values logged or surfaced in error messages
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("platform_bridge")

# ── Constants ─────────────────────────────────────────────────────────────────
_CONNECT_TIMEOUT = 10    # seconds for connection establishment
_READ_TIMEOUT    = 30    # seconds for response body read
_MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024  # 50 MB cap on downloaded challenge files

# Only these URL schemes are permitted for outbound requests
_ALLOWED_SCHEMES = {"https"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_url(url: str) -> bool:
    """Return True only for https:// URLs with a non-empty hostname."""
    try:
        parsed = urlparse(url)
        return (
            parsed.scheme in _ALLOWED_SCHEMES
            and bool(parsed.netloc)
            and ".." not in parsed.path   # no path traversal
        )
    except Exception:
        return False


def _make_session() -> requests.Session:
    """Build a requests.Session with retry logic and strict TLS verification."""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    return session


# ── PlatformClient ────────────────────────────────────────────────────────────

class PlatformClient:
    """Interact with CTFd, HackTheBox, and TryHackMe via their APIs."""

    def __init__(self) -> None:
        self.workspace = Path(".agent/sandbox/workspace")
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.config: Dict[str, str] = {}
        self._load_env()
        self._session = _make_session()

    def _load_env(self) -> None:
        """
        Load credentials from .env with strict line-by-line parsing.
        Shell expansion and multi-line values are rejected.
        """
        env_path = Path(".env")
        if not env_path.exists():
            return

        with env_path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.rstrip("\n\r")
                # Skip blanks and comments
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    logger.debug(".env line %d has no '=' — skipped", lineno)
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                # Reject keys with spaces or shell-special chars
                if not key.isidentifier():
                    logger.warning(".env line %d: invalid key %r — skipped", lineno, key)
                    continue
                # Strip optional surrounding quotes from value
                value = value.strip().strip('"').strip("'")
                self.config[key] = value

    def identify_platform(self, url: str) -> Optional[str]:
        """Identify the CTF platform from the challenge URL."""
        if not _validate_url(url):
            logger.warning("Invalid or unsafe URL: %r", url)
            return None
        netloc = urlparse(url).netloc.lower()
        if "hackthebox.com" in netloc:
            return "htb"
        if "tryhackme.com" in netloc:
            return "thm"
        ctfd_url = self.config.get("CTFD_URL", "")
        if ctfd_url and urlparse(ctfd_url).netloc.lower() in netloc:
            return "ctfd"
        return "ctfd"  # default fallback for self-hosted CTFd

    # ── CTFd ─────────────────────────────────────────────────────────────────

    def fetch_ctfd_challenge(self, challenge_id: str) -> Optional[Dict[str, Any]]:
        """Fetch challenge metadata (and attached file list) from CTFd API."""
        base = self.config.get("CTFD_URL", "").rstrip("/")
        if not base or not _validate_url(base):
            logger.error("CTFD_URL is not configured or is invalid.")
            return None

        token = self.config.get("CTFD_TOKEN", "")
        if not token:
            logger.error("CTFD_TOKEN is not configured.")
            return None

        headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        }
        challenge_url = f"{base}/api/v1/challenges/{challenge_id}"
        if not _validate_url(challenge_url):
            logger.error("Constructed challenge URL is invalid: %r", challenge_url)
            return None

        try:
            resp = self._session.get(
                challenge_url, headers=headers,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                verify=True,
            )
            resp.raise_for_status()
            data: Dict[str, Any] = resp.json().get("data", {})
        except requests.RequestException as exc:
            logger.error("Failed to fetch CTFd challenge: %s", exc)
            return None

        # Fetch attached files
        files_url = f"{base}/api/v1/challenges/{challenge_id}/files"
        try:
            rf = self._session.get(
                files_url, headers=headers,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                verify=True,
            )
            if rf.status_code == 200:
                data["files"] = rf.json().get("data", [])
        except requests.RequestException as exc:
            logger.warning("Could not fetch challenge files: %s", exc)

        return data

    def download_file(self, url: str, filename: str) -> Optional[Path]:
        """
        Download a challenge file to the sandbox workspace.

        Download is capped at MAX_DOWNLOAD_BYTES to prevent storage exhaustion.
        Only https:// URLs are accepted.
        """
        if not _validate_url(url):
            logger.error("Refusing to download from invalid URL: %r", url)
            return None

        # Sanitise filename — strip path components
        safe_name = Path(filename).name
        if not safe_name or safe_name in (".", ".."):
            logger.error("Invalid filename: %r", filename)
            return None

        dest = self.workspace / safe_name
        # Prevent path traversal outside workspace
        try:
            dest.resolve().relative_to(self.workspace.resolve())
        except ValueError:
            logger.error("Path traversal detected for filename %r.", filename)
            return None

        headers: Dict[str, str] = {}
        ctfd_base = self.config.get("CTFD_URL", "")
        if ctfd_base and url.startswith(ctfd_base):
            token = self.config.get("CTFD_TOKEN", "")
            if token:
                headers["Authorization"] = f"Token {token}"

        try:
            with self._session.get(
                url, headers=headers, stream=True,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                verify=True,
            ) as resp:
                resp.raise_for_status()
                total = 0
                with dest.open("wb") as fh:
                    for chunk in resp.iter_content(chunk_size=65_536):
                        total += len(chunk)
                        if total > _MAX_DOWNLOAD_BYTES:
                            fh.close()
                            dest.unlink(missing_ok=True)
                            logger.error(
                                "Download aborted: file exceeds %d MB limit.",
                                _MAX_DOWNLOAD_BYTES // (1024 * 1024),
                            )
                            return None
                        fh.write(chunk)
            logger.info("Downloaded: %s (%d bytes)", safe_name, total)
            return dest
        except requests.RequestException as exc:
            logger.error("Download failed for %r: %s", url, exc)
            return None

    def submit_flag_ctfd(self, challenge_id: str, flag: str) -> bool:
        """Submit a flag to CTFd and return True if accepted."""
        base = self.config.get("CTFD_URL", "").rstrip("/")
        token = self.config.get("CTFD_TOKEN", "")
        if not base or not token or not _validate_url(base):
            logger.error("CTFd not configured — cannot submit flag.")
            return False

        submit_url = f"{base}/api/v1/challenges/attempt"
        headers = {
            "Authorization": f"Token {token}",
            "Content-Type": "application/json",
        }
        payload = {"challenge_id": challenge_id, "submission": flag}
        try:
            resp = self._session.post(
                submit_url, headers=headers, json=payload,
                timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT),
                verify=True,
            )
            status = resp.json().get("data", {}).get("status")
            return status == "correct"
        except requests.RequestException as exc:
            logger.error("Flag submission failed: %s", exc)
            return False


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    client = PlatformClient()
    if len(sys.argv) < 2:
        print("Usage: platform_client.py <fetch|submit> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "fetch" and len(sys.argv) > 2:
        data = client.fetch_ctfd_challenge(sys.argv[2])
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif cmd == "submit" and len(sys.argv) > 3:
        success = client.submit_flag_ctfd(sys.argv[2], sys.argv[3])
        print("Correct:", success)
    else:
        print("Unknown command.")
        sys.exit(1)
