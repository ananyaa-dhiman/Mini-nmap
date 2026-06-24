"""
report.py
---------
Formats scan results for console display and for export to a file
(JSON or plain text), so scan results can be attached to the
internship report/documentation.
"""

import json
from datetime import datetime

from .scanner import HostResult

BANNER = r"""
 _____ ____  _   _ ____    ___ ____ ____   ____   ____    _    _____   _
|  ___/ ___|| | | / ___|  |_ _/ ___| ___| |  _ \ / ___|  / \  |_ _\ \ / /
| |_ |\___ \| | | \___ \   | | |  _\___ \  | | | | |    / _ \  | | \ V /
|  _|  ___) | |_| |___) |  | | |_| |___) | | |_| | |___/ ___ \ | |  | |
|_|   |____/ \___/|____/  |___\____|____/  |____/ \____/_/   \_\___| |_|

                 MINI NMAP -- Python Network Scanner
"""

STATE_COLORS = {
    "open": "\033[92m",      # green
    "closed": "\033[91m",    # red
    "filtered": "\033[93m",  # yellow
}
RESET = "\033[0m"


def print_banner():
    print(BANNER)


def print_network_info(net_info):
    print("=" * 65)
    print(" LOCAL NETWORK INFORMATION")
    print("=" * 65)
    print(f"  Hostname        : {net_info.hostname}")
    print(f"  Local IP        : {net_info.local_ip}")
    print(f"  Subnet (guessed): {net_info.subnet_cidr}")
    print(f"  Default Gateway : {net_info.gateway or 'Not found'}")
    print("=" * 65 + "\n")


def print_host_discovery(live_hosts, cidr, elapsed):
    print(f"Host discovery on {cidr} complete in {elapsed:.2f}s")
    print(f"{len(live_hosts)} live host(s) found:\n")
    for ip in live_hosts:
        print(f"  [+] {ip}")
    print()


def print_host_result(result: HostResult, use_color: bool = True):
    print("=" * 65)
    header = f" SCAN REPORT FOR {result.target}"
    if result.hostname and result.hostname != result.target:
        header += f" ({result.hostname})"
    print(header)
    print("=" * 65)
    print(f"  IP Address     : {result.ip}")
    print(f"  Status         : {'UP' if result.is_up else 'DOWN'}")

    if not result.is_up:
        print("  Could not resolve/reach host.\n")
        return

    print(f"  Scan duration  : {result.scan_duration}s")
    print(f"  OS Guess       : {result.os_guess}  ({result.os_confidence})")
    print("-" * 65)

    if not result.ports:
        print("  No open ports found in the scanned range.")
    else:
        print(f"  {'PORT':<10}{'STATE':<10}{'SERVICE':<16}{'VERSION/BANNER'}")
        print(f"  {'-'*8:<10}{'-'*7:<10}{'-'*14:<16}{'-'*20}")
        for p in result.ports:
            color = STATE_COLORS.get(p.state, "") if use_color else ""
            reset = RESET if use_color else ""
            version_display = (p.version or "")[:45]
            print(f"  {p.port:<10}{color}{p.state:<10}{reset}{p.service:<16}{version_display}")

    print(f"\n  {len(result.ports)} open port(s) reported.")
    print("=" * 65 + "\n")


def export_json(results, filepath):
    """Export all scan results to a JSON file."""
    data = {
        "scan_time": datetime.now().isoformat(),
        "hosts": [],
    }
    for r in results:
        data["hosts"].append({
            "target": r.target,
            "ip": r.ip,
            "is_up": r.is_up,
            "hostname": r.hostname,
            "os_guess": r.os_guess,
            "os_confidence": r.os_confidence,
            "scan_duration": r.scan_duration,
            "open_ports": [
                {
                    "port": p.port,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "banner": p.banner,
                    "response_time_ms": p.response_time_ms,
                }
                for p in r.ports
            ],
        })
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Results exported to {filepath}")


def export_text(results, filepath):
    """Export all scan results to a plain text report file."""
    with open(filepath, "w") as f:
        f.write(f"Mini Nmap Scan Report - {datetime.now().isoformat()}\n")
        f.write("=" * 65 + "\n\n")
        for r in results:
            f.write(f"Target: {r.target}\n")
            f.write(f"IP: {r.ip}\n")
            f.write(f"Status: {'UP' if r.is_up else 'DOWN'}\n")
            if r.is_up:
                f.write(f"Hostname: {r.hostname}\n")
                f.write(f"OS Guess: {r.os_guess} ({r.os_confidence})\n")
                f.write(f"Scan duration: {r.scan_duration}s\n")
                f.write(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<16}{'VERSION/BANNER'}\n")
                for p in r.ports:
                    f.write(f"{p.port:<10}{p.state:<10}{p.service:<16}{p.version}\n")
            f.write("-" * 65 + "\n\n")
    print(f"[+] Results exported to {filepath}")
