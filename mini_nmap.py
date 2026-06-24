#!/usr/bin/env python3
"""
mini_nmap.py
============
Mini Network Scanner -- a lightweight Nmap-inspired tool built with
Python sockets and multithreading.

Features:
    [x] TCP connect scanning
    [x] Service detection on common ports
    [x] Multithreading for scan speed across ports/hosts
    [x] Service version scanning (banner grabbing + protocol probes)
    [x] OS detection (TTL analysis + banner heuristics)
    [x] Local network discovery (what network am I on / live hosts)

USAGE EXAMPLES
--------------
  # Show info about the network this machine is connected to
  python3 mini_nmap.py --net-info

  # Discover live hosts on your local subnet automatically
  python3 mini_nmap.py --discover

  # Scan a single target's top 100 ports, with version + OS detection
  python3 mini_nmap.py -t 192.168.1.10

  # Scan specific ports
  python3 mini_nmap.py -t scanme.nmap.org -p 22,80,443

  # Scan a port range
  python3 mini_nmap.py -t 192.168.1.10 -p 1-1000

  # Scan multiple targets
  python3 mini_nmap.py -t 192.168.1.10,192.168.1.11,192.168.1.12

  # Scan the whole discovered subnet
  python3 mini_nmap.py --scan-network

  # Skip version/OS detection for a faster raw port scan
  python3 mini_nmap.py -t 192.168.1.10 --no-version --no-os

  # Export results
  python3 mini_nmap.py -t 192.168.1.10 -o report.json
  python3 mini_nmap.py -t 192.168.1.10 -o report.txt
"""

import argparse
import sys
import time

from mininmap_lib.network_info import get_network_info, host_list_from_cidr
from mininmap_lib.discovery import discover_live_hosts
from mininmap_lib.scanner import scan_host
from mininmap_lib.os_detect import detect_os
from mininmap_lib.ports_db import TOP_100_PORTS
from mininmap_lib.report import (
    print_banner, print_network_info, print_host_discovery,
    print_host_result, export_json, export_text,
)


def parse_ports(port_str: str):
    """Parse '22,80,443' or '1-1000' or a mix '22,80,1000-2000' into a list of ints."""
    ports = set()
    for chunk in port_str.split(","):
        chunk = chunk.strip()
        if "-" in chunk:
            start, end = chunk.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif chunk:
            ports.add(int(chunk))
    return sorted(ports)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Mini Nmap -- lightweight Python network scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--target", help="Target host(s): IP, hostname, or comma-separated list")
    parser.add_argument("-p", "--ports", default=None,
                         help="Ports to scan, e.g. '22,80,443' or '1-1000'. Default: top 100 common ports")
    parser.add_argument("--threads", type=int, default=150, help="Number of worker threads (default: 150)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Per-port socket timeout in seconds (default: 1.0)")
    parser.add_argument("--no-version", action="store_true", help="Disable service/version detection")
    parser.add_argument("--no-os", action="store_true", help="Disable OS detection")
    parser.add_argument("--net-info", action="store_true", help="Show local network info and exit")
    parser.add_argument("--discover", action="store_true", help="Discover live hosts on the local subnet and exit")
    parser.add_argument("--scan-network", action="store_true",
                         help="Discover live hosts on local subnet, then full-scan each one")
    parser.add_argument("--subnet", default=None, help="Override subnet CIDR, e.g. 192.168.1.0/24")
    parser.add_argument("-o", "--output", default=None, help="Export results to file (.json or .txt)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    return parser


def run_single_host_scan(target, ports, threads, timeout, do_version, do_os, use_color):
    print(f"[*] Scanning {target} ({len(ports)} ports) with {threads} threads...\n")
    result = scan_host(target, ports, threads=threads, timeout=timeout, do_version_scan=do_version)

    if result.is_up and do_os:
        banners = [p.banner for p in result.ports if p.banner]
        open_port_nums = [p.port for p in result.ports]
        os_guess = detect_os(result.ip, open_port_nums, banners)
        result.os_guess = os_guess.os_family
        result.os_confidence = os_guess.confidence
    elif result.is_up:
        result.os_guess = "Skipped"
        result.os_confidence = "--no-os used"

    print_host_result(result, use_color=use_color)
    return result


def main():
    parser = build_arg_parser()
    args = parser.parse_args()
    use_color = not args.no_color

    print_banner()

    # ---- Mode: network info only ----
    if args.net_info:
        net_info = get_network_info()
        print_network_info(net_info)
        return

    # ---- Mode: host discovery only ----
    if args.discover:
        net_info = get_network_info()
        print_network_info(net_info)
        cidr = args.subnet or net_info.subnet_cidr
        host_list = host_list_from_cidr(cidr)
        print(f"[*] Sweeping {len(host_list)} addresses on {cidr} ...\n")
        start = time.time()
        live_hosts = discover_live_hosts(host_list, threads=args.threads, timeout=args.timeout)
        elapsed = time.time() - start
        print_host_discovery(live_hosts, cidr, elapsed)
        return

    # ---- Mode: full subnet scan ----
    if args.scan_network:
        net_info = get_network_info()
        print_network_info(net_info)
        cidr = args.subnet or net_info.subnet_cidr
        host_list = host_list_from_cidr(cidr)
        print(f"[*] Sweeping {len(host_list)} addresses on {cidr} to find live hosts...\n")
        start = time.time()
        live_hosts = discover_live_hosts(host_list, threads=args.threads, timeout=args.timeout)
        elapsed = time.time() - start
        print_host_discovery(live_hosts, cidr, elapsed)

        if not live_hosts:
            print("[!] No live hosts found, nothing to scan.")
            return

        ports = parse_ports(args.ports) if args.ports else TOP_100_PORTS
        results = []
        for host in live_hosts:
            result = run_single_host_scan(
                host, ports, args.threads, args.timeout,
                not args.no_version, not args.no_os, use_color,
            )
            results.append(result)

        if args.output:
            if args.output.endswith(".json"):
                export_json(results, args.output)
            else:
                export_text(results, args.output)
        return

    # ---- Mode: explicit target scan ----
    if not args.target:
        parser.print_help()
        print("\n[!] Error: you must provide -t/--target, or use --net-info / --discover / --scan-network")
        sys.exit(1)

    targets = [t.strip() for t in args.target.split(",") if t.strip()]
    ports = parse_ports(args.ports) if args.ports else TOP_100_PORTS

    results = []
    for target in targets:
        result = run_single_host_scan(
            target, ports, args.threads, args.timeout,
            not args.no_version, not args.no_os, use_color,
        )
        results.append(result)

    if args.output:
        if args.output.endswith(".json"):
            export_json(results, args.output)
        else:
            export_text(results, args.output)


if __name__ == "__main__":
    main()
