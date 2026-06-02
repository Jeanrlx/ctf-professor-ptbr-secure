FROM kalilinux/kali-rolling

# Install tools required for CTF challenge solving
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

# Create a non-root user for command execution.
# Tools that genuinely need root (nmap OS detection, openvpn) are granted via
# a narrow sudoers entry rather than running everything as root.
RUN useradd -m -s /bin/bash ctfuser && \
    echo "ctfuser ALL=(root) NOPASSWD: /usr/bin/nmap, /usr/sbin/openvpn, /usr/bin/gdb, /usr/bin/strace" \
    >> /etc/sudoers.d/ctfuser && \
    chmod 0440 /etc/sudoers.d/ctfuser

# Pre-create workspace with correct ownership so volume mounts work without root
RUN mkdir -p /workspace && chown ctfuser:ctfuser /workspace

WORKDIR /workspace

USER ctfuser

CMD ["sleep", "infinity"]
