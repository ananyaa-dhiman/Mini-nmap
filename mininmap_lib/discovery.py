"""
discovery.py
------------
Multithreaded host discovery ("is this host alive?") across an entire
subnet - the equivalent of `nmap -sn 192.168.1.0/24`.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from .network_info import is_host_alive


def discover_live_hosts(host_list: List[str], threads: int = 100, timeout: float = 1.0) -> List[str]:
    """
    Sweep a list of IPs in parallel and return only the ones that
    respond (TCP connect to common ports, or ICMP ping fallback).
    """
    live_hosts = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_map = {
            executor.submit(is_host_alive, ip, timeout): ip
            for ip in host_list
        }
        for future in as_completed(future_map):
            ip = future_map[future]
            try:
                if future.result():
                    live_hosts.append(ip)
            except Exception:
                continue

    # sort by last octet for a clean, readable report
    def sort_key(ip):
        try:
            return tuple(int(part) for part in ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)

    return sorted(live_hosts, key=sort_key)
