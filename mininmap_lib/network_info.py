"""
network_info.py
----------------
Discovers information about the network the scanning machine is
currently connected to: local IP, subnet/CIDR, default gateway, and
generates the live host list to scan for a "scan my whole network"
style run (similar to `nmap -sn 192.168.1.0/24`).
"""

import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class LocalNetworkInfo:
    local_ip: str
    hostname: str
    subnet_cidr: str
    gateway: Optional[str]
    interface_guess: Optional[str] = None


def get_local_ip() -> str:
    """
    Find this machine's primary local IP by opening a dummy UDP socket
    to a public address (no packets are actually sent for UDP connect).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def guess_subnet_cidr(local_ip: str, prefix: int = 24) -> str:
    """
    Assume a /24 (the overwhelmingly common case for home & small
    office LANs) unless told otherwise. Returns e.g. '192.168.1.0/24'.
    """
    network = ipaddress.ip_network(f"{local_ip}/{prefix}", strict=False)
    return str(network)


def get_default_gateway() -> Optional[str]:
    """Cross-platform default gateway lookup using system commands."""
    system = platform.system().lower()
    try:
        if system == "windows":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5).stdout
            match = re.search(r"Default Gateway[ .]*: ([\d.]+)", out)
            if match:
                return match.group(1)
        elif system == "darwin":
            out = subprocess.run(["route", "-n", "get", "default"],
                                  capture_output=True, text=True, timeout=5).stdout
            match = re.search(r"gateway:\s*([\d.]+)", out)
            if match:
                return match.group(1)
        else:  # Linux
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=5).stdout
            match = re.search(r"default via ([\d.]+)", out)
            if match:
                return match.group(1)
            # fallback to /proc/net/route parsing or `route` command
            out2 = subprocess.run(["route", "-n"], capture_output=True, text=True, timeout=5).stdout
            for line in out2.splitlines():
                if line.startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) > 1:
                        return parts[1]
    except Exception:
        pass
    return None


def get_network_info(prefix: int = 24) -> LocalNetworkInfo:
    local_ip = get_local_ip()
    hostname = socket.gethostname()
    subnet = guess_subnet_cidr(local_ip, prefix=prefix)
    gateway = get_default_gateway()
    return LocalNetworkInfo(
        local_ip=local_ip,
        hostname=hostname,
        subnet_cidr=subnet,
        gateway=gateway,
    )


def host_list_from_cidr(cidr: str) -> List[str]:
    """Expand a CIDR block into a list of usable host IP strings."""
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in network.hosts()]


def is_host_alive(ip: str, timeout: float = 1.0) -> bool:
    """
    Quick liveness check used during host discovery sweeps.
    Tries a fast TCP connect to a couple of very common ports first
    (much faster than waiting on ICMP across a whole /24), then
    falls back to a system ping.
    """
    common_check_ports = [80, 443, 22, 445, 3389]
    for port in common_check_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout / len(common_check_ports))
                if s.connect_ex((ip, port)) == 0:
                    return True
        except OSError:
            continue

    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        return result.returncode == 0
    except Exception:
        return False
