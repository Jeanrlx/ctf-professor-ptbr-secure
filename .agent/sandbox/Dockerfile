# Pin a specific Kali rolling tag so builds are reproducible and won't silently
# break when upstream updates tools or base packages.
FROM kalilinux/kali-rolling:2024.4

# ── System packages ──────────────────────────────────────────────────────────
# pwntools is installed here (inside the container), NOT on the host.
# This ensures all exploit-capable code stays inside the sandbox boundary.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        nmap \
        radare2 \
        python3 \
        python3-pip \
        python3-venv \
        python3-pwntools \
        python3-requests \
        gdb \
        curl \
        checksec \
        file \
        binutils \
        strace \
        ltrace \
        iproute2 \
        openvpn \
        sudo \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ─────────────────────────────────────────────────────────────
# ctfuser has a proper home directory so tools like gdb/.pwndbg won't fail
# trying to write config files to a non-existent home.
# sudo access is restricted to the four tools that genuinely need root:
#   - nmap        (raw socket / OS detection)
#   - openvpn     (tun interface creation)
#   - gdb         (ptrace on foreign processes)
#   - strace      (ptrace on foreign processes)
RUN useradd -m -d /home/ctfuser -s /bin/bash ctfuser && \
    echo "ctfuser ALL=(root) NOPASSWD: /usr/bin/nmap, /usr/sbin/openvpn, /usr/bin/gdb, /usr/bin/strace" \
        > /etc/sudoers.d/ctfuser && \
    chmod 0440 /etc/sudoers.d/ctfuser && \
    # Validate sudoers syntax so a malformed entry won't lock out sudo entirely
    visudo -c -f /etc/sudoers.d/ctfuser

# ── Workspace ─────────────────────────────────────────────────────────────────
# Pre-create with correct ownership so volume mounts work without a root step.
RUN mkdir -p /workspace && chown ctfuser:ctfuser /workspace

# ── Healthcheck ───────────────────────────────────────────────────────────────
# Docker can report the container as healthy only after the shell is ready.
# This prevents execute_command from racing against a not-yet-ready container.
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=3 \
    CMD [ "bash", "-c", "echo ok" ]

WORKDIR /workspace
USER ctfuser

CMD ["sleep", "infinity"]
