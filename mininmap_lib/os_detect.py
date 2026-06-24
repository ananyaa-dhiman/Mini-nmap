"""
os_detect.py
------------
Lightweight OS fingerprinting.

True raw-socket OS fingerprinting (like nmap -O, which analyzes TCP
window size, options ordering, ISN behaviour, etc.) needs raw sockets
and root/admin privileges. To keep this tool runnable without root,
we use two practical, well-documented heuristics instead:

  1. TTL (Time To Live) analysis from a ping/ICMP probe (or a TCP
     handshake) - different OS families ship with different default
     starting TTLs:
         Linux/Unix     -> 64
         Windows        -> 128
         Cisco/Network  -> 255
     (the TTL we observe = default_ttl - hops, so we bucket it)

  2. Banner-based hints - many service banners (SSH, HTTP Server
     header, SMB) directly leak the OS, e.g. "OpenSSH ... Ubuntu",
     "Microsoft-IIS", "Win32".

This is the same fallback approach real lightweight scanners use when
they don't have raw socket access.
"""

import platform
import re
import socket
import subprocess
from dataclasses import dataclass


@dataclass
class OSGuess:
    os_family: str
    confidence: str
    ttl_observed: int = None
    reason: str = ""


TTL_BUCKETS = [
    (60, 64, "Linux / Unix / macOS"),
    (120, 128, "Windows"),
    (250, 255, "Network device (router/switch - Cisco-like) or Solaris"),
]


def _bucket_ttl(ttl: int) -> str:
    for low, high, name in TTL_BUCKETS:
        if low <= ttl <= high:
            return name
    if ttl is not None and ttl > 64:
        return "Windows (possibly, TTL decremented by hops)"
    return "Unknown"


def get_ttl_via_ping(target_ip: str, timeout_s: int = 2) -> int:
    """
    Cross-platform ping that extracts the TTL value from the reply.
    Uses the system `ping` command (1 packet) - no root required.
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), target_ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), target_ip]

        output = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s + 2
        ).stdout

        match = re.search(r"ttl[=\s](\d+)", output, re.IGNORECASE)
        if match:
            return int(match.group(1))
    except Exception:
        pass
    return None


def get_ttl_via_tcp(ip: str, port: int = 80, timeout: float = 1.5) -> int:
    """
    Fallback TTL retrieval using a raw TCP connection's socket option.
    On Linux this reads IP_TTL from an established connection, which
    works without root (unlike full raw-socket sniffing).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            ttl = s.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
            return ttl
    except Exception:
        return None


def guess_os_from_banners(banners: list) -> str:
    """Look through collected service banners for direct OS hints."""
    joined = " ".join(b for b in banners if b).lower()

    if "ubuntu" in joined:
        return "Linux (Ubuntu)"
    if "debian" in joined:
        return "Linux (Debian)"
    if "centos" in joined or "red hat" in joined or "rhel" in joined:
        return "Linux (RHEL/CentOS)"
    if "win32" in joined or "windows" in joined or "microsoft-iis" in joined:
        return "Windows"
    if "freebsd" in joined:
        return "FreeBSD"
    if "darwin" in joined or "mac os" in joined:
        return "macOS"
    if "openssh" in joined:
        return "Linux/Unix (OpenSSH present)"
    return ""


def detect_os(ip: str, open_ports: list, banners: list) -> OSGuess:
    """
    Combine TTL analysis + banner inspection into a single OS guess.
    `open_ports` is a list of ints, `banners` a list of banner strings
    collected during the version scan.
    """
    ttl = get_ttl_via_ping(ip)
    if ttl is None and open_ports:
        ttl = get_ttl_via_tcp(ip, port=open_ports[0])

    banner_guess = guess_os_from_banners(banners)

    if banner_guess:
        confidence = "High (banner match)"
        reason = "Matched OS keywords inside a service banner"
        return OSGuess(os_family=banner_guess, confidence=confidence,
                        ttl_observed=ttl, reason=reason)

    if ttl is not None:
        family = _bucket_ttl(ttl)
        confidence = "Medium (TTL heuristic)" if family != "Unknown" else "Low"
        reason = f"Observed TTL={ttl}, matched against common default-TTL ranges"
        return OSGuess(os_family=family, confidence=confidence,
                        ttl_observed=ttl, reason=reason)

    return OSGuess(os_family="Unknown", confidence="Low",
                    ttl_observed=None, reason="No ICMP/TCP TTL available and no banner hints")
