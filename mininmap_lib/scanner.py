"""
scanner.py
----------
Core scanning engine.

Implements:
    - TCP Connect Scan (the classic "full connect" scan technique,
      same idea as `nmap -sT`)
    - Multithreaded scanning across a port range / target list using
      a ThreadPoolExecutor + a thread-safe queue-like pattern
    - Banner grabbing for service/version detection
"""

import socket
import ssl
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional

from .ports_db import COMMON_PORTS


@dataclass
class PortResult:
    port: int
    state: str                     # "open", "closed", "filtered"
    service: str = "unknown"
    banner: str = ""
    version: str = ""
    response_time_ms: float = 0.0


@dataclass
class HostResult:
    target: str
    ip: str
    is_up: bool = True
    ports: List[PortResult] = field(default_factory=list)
    os_guess: str = "Unknown"
    os_confidence: str = ""
    ttl: Optional[int] = None
    hostname: Optional[str] = None
    scan_duration: float = 0.0


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address. Raises socket.gaierror if it fails."""
    return socket.gethostbyname(target)


def tcp_connect_scan(ip: str, port: int, timeout: float = 1.0) -> PortResult:
    """
    Classic TCP Connect Scan.

    Attempts a full TCP three-way handshake via socket.connect().
    - connect() succeeds            -> port is OPEN
    - connection refused (RST)      -> port is CLOSED
    - timeout / no response         -> port is FILTERED (likely firewalled)
    """
    start = time.time()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((ip, port))
        elapsed = (time.time() - start) * 1000

        if result == 0:
            service = COMMON_PORTS.get(port, "unknown")
            pr = PortResult(port=port, state="open", service=service,
                             response_time_ms=round(elapsed, 2))
            return pr
        else:
            # ECONNREFUSED (111 on Linux, 10061 on Windows) => closed
            if result in (111, 10061):
                return PortResult(port=port, state="closed",
                                   response_time_ms=round(elapsed, 2))
            return PortResult(port=port, state="filtered",
                               response_time_ms=round(elapsed, 2))
    except socket.timeout:
        return PortResult(port=port, state="filtered",
                           response_time_ms=round((time.time() - start) * 1000, 2))
    except OSError:
        return PortResult(port=port, state="filtered",
                           response_time_ms=round((time.time() - start) * 1000, 2))
    finally:
        sock.close()


def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    """
    Try to read a banner directly from the service (many services like
    FTP, SSH, SMTP announce themselves immediately on connect).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                data = s.recv(1024)
                if data:
                    return data.decode(errors="ignore").strip()
            except socket.timeout:
                pass
    except OSError:
        pass
    return ""


def probe_http(ip: str, port: int, use_tls: bool = False, timeout: float = 2.0) -> str:
    """Send a minimal HTTP HEAD request and return the Server header line + status line."""
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.connect((ip, port))

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock)
        else:
            sock = raw_sock

        req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        resp = sock.recv(4096).decode(errors="ignore")
        sock.close()

        lines = resp.split("\r\n")
        status_line = lines[0] if lines else ""
        server_line = next((l for l in lines if l.lower().startswith("server:")), "")
        combo = " | ".join(x for x in [status_line, server_line] if x)
        return combo
    except Exception:
        return ""


def probe_ssl_cert(ip: str, port: int, timeout: float = 2.0) -> str:
    """Grab basic info from a TLS certificate (useful for https/other TLS services)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock) as ssock:
                cert_bin = ssock.getpeercert(binary_form=False)
                cipher = ssock.cipher()
                version = ssock.version()
                info = f"TLS:{version}"
                if cipher:
                    info += f" Cipher:{cipher[0]}"
                return info
    except Exception:
        return ""


def detect_service_version(ip: str, port: int, service_guess: str) -> tuple:
    """
    Active service/version detection ("version scanning"), inspired by
    nmap's -sV. Uses protocol-appropriate probes rather than one
    generic probe for every port.

    Returns (banner, version_string)
    """
    banner = ""
    version = ""

    http_ports = {80, 8080, 8000, 8008, 8888, 9000, 9090, 3000, 5000}
    https_ports = {443, 8443}

    if port in https_ports:
        banner = probe_http(ip, port, use_tls=True)
        tls_info = probe_ssl_cert(ip, port)
        version = f"{banner} [{tls_info}]" if tls_info else banner
    elif port in http_ports:
        banner = probe_http(ip, port, use_tls=False)
        version = banner
    else:
        # generic banner grab works well for ftp, ssh, smtp, pop3, imap, etc.
        # (services that speak first as soon as a connection opens)
        banner = grab_banner(ip, port)
        version = banner

        # Fallback: many "unknown" ports are actually plain HTTP services
        # (dev servers, admin panels, etc.) that stay silent until spoken
        # to. If the passive grab got nothing, try an active HTTP probe
        # before giving up.
        if not banner:
            http_probe = probe_http(ip, port, use_tls=False)
            if http_probe:
                banner = http_probe
                version = http_probe

    if not banner and not version:
        version = service_guess

    return banner, version


def scan_port_full(ip: str, port: int, timeout: float, do_version_scan: bool) -> PortResult:
    """Connect-scan a single port, then optionally grab service/version info if open."""
    result = tcp_connect_scan(ip, port, timeout=timeout)
    if result.state == "open" and do_version_scan:
        banner, version = detect_service_version(ip, port, result.service)
        result.banner = banner
        result.version = version
        if result.service == "unknown" and banner.upper().startswith("HTTP/"):
            result.service = "http"
    return result


def scan_host(
    target: str,
    ports: List[int],
    threads: int = 100,
    timeout: float = 1.0,
    do_version_scan: bool = True,
) -> HostResult:
    """
    Scan a single host across a list of ports using a thread pool.
    This is the multithreading layer that gives the speed-up over a
    naive sequential scan (this is the part of the project that maps
    to your "multithreading for scan speed/efficiency" bullet point).
    """
    start_time = time.time()

    try:
        ip = resolve_target(target)
    except socket.gaierror:
        return HostResult(target=target, ip="unresolvable", is_up=False)

    host_result = HostResult(target=target, ip=ip)

    try:
        host_result.hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        host_result.hostname = None

    open_results: List[PortResult] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(scan_port_full, ip, port, timeout, do_version_scan): port
            for port in ports
        }
        for future in as_completed(future_map):
            res = future.result()
            if res.state == "open":
                open_results.append(res)

    open_results.sort(key=lambda r: r.port)
    host_result.ports = open_results
    host_result.scan_duration = round(time.time() - start_time, 2)
    return host_result
