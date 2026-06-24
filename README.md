# Mini Nmap — Mini Network Scanner
A lightweight, Nmap-inspired network scanning tool built in Python using **sockets** and **multithreading**. Built as a cybersecurity internship project.

## Features

| Feature | How it's implemented |
|---|---|
| **TCP Connect Scan** | Full three-way handshake via `socket.connect_ex()` — the same fundamental technique as `nmap -sT` |
| **Service Detection** | 80+ common ports mapped to service names (HTTP, SSH, FTP, MySQL, RDP, etc.) |
| **Multithreading** | `concurrent.futures.ThreadPoolExecutor` scans hundreds of ports/hosts in parallel instead of one at a time |
| **Version Scanning** | Protocol-aware active probes (HTTP HEAD requests, TLS handshake + cert info, raw banner grabbing) — inspired by `nmap -sV` |
| **OS Detection** | TTL analysis (Linux≈64, Windows≈128, network gear≈255) combined with banner keyword matching — a practical fallback since true raw-socket fingerprinting (`nmap -O`) requires root privileges |
| **Network Discovery** | Detects local IP/subnet/gateway, then sweeps the whole `/24` in parallel to find live hosts — like `nmap -sn` |

## Project Structure

```
mini_nmap/
├── mini_nmap.py              # CLI entry point (argparse + orchestration)
└── mininmap_lib/
    ├── ports_db.py            # Port -> service name database
    ├── scanner.py             # TCP connect scan + version/banner detection + threading
    ├── os_detect.py           # TTL-based + banner-based OS fingerprinting
    ├── network_info.py        # Local IP / subnet / gateway discovery
    ├── discovery.py           # Multithreaded subnet host sweep
    └── report.py              # Console output + JSON/text export
```

## Requirements

- Python 3.8+
- No external dependencies (standard library only: `socket`, `ssl`, `concurrent.futures`, `subprocess`, `ipaddress`)
- No root/admin privileges required (this is a deliberate design choice — see "OS Detection" note below)

## Usage

```bash
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

# Scan multiple targets at once
python3 mini_nmap.py -t 192.168.1.10,192.168.1.11,192.168.1.12

# Discover live hosts on the LAN, then fully scan every one of them
python3 mini_nmap.py --scan-network

# Faster raw port scan, skip version/OS detection
python3 mini_nmap.py -t 192.168.1.10 --no-version --no-os

# Export results
python3 mini_nmap.py -t 192.168.1.10 -o report.json
python3 mini_nmap.py -t 192.168.1.10 -o report.txt

# Tune performance
python3 mini_nmap.py -t 192.168.1.10 --threads 300 --timeout 0.5
```

## Sample Output

```
=================================================================
 SCAN REPORT FOR 192.168.1.10
=================================================================
  IP Address     : 192.168.1.10
  Status         : UP
  Scan duration  : 2.31s
  OS Guess       : Linux (Ubuntu)  (High (banner match))
-----------------------------------------------------------------
  PORT      STATE     SERVICE         VERSION/BANNER
  --------  -------   --------------  --------------------
  22        open      ssh             SSH-2.0-OpenSSH_8.9p1 Ubuntu
  80        open      http            HTTP/1.1 200 OK | Server: nginx/1.24.0
  443       open      https           HTTP/1.1 200 OK [TLS:TLSv1.3 Cipher:TLS_AES_256...]

  3 open port(s) reported.
=================================================================
```

## Design Notes for the Report

### Why TCP Connect scan instead of SYN scan?
A SYN scan (`nmap -sS`) needs raw sockets, which requires root/admin privileges and OS-level packet crafting. A **TCP connect scan** uses the OS's normal `connect()` syscall, so it works cross-platform with zero privileges — the trade-off is it's slightly noisier (it completes the full handshake, so it shows up in target logs) and a touch slower per-port. This is the same trade-off documented in nmap's own manual.

### Why TTL-based OS detection instead of raw-socket fingerprinting?
Real `nmap -O` sends several crafted TCP/ICMP probes and analyzes window size, options ordering, and ISN generation — but that needs raw sockets (root/admin). Since this tool is meant to run anywhere without elevated privileges, it uses two non-invasive signals instead:
1. **TTL bucketing** from a normal ping or the `IP_TTL` socket option (Linux≈64, Windows≈128, network hardware≈255)
2. **Banner keyword matching** (e.g., an SSH banner that says "Ubuntu", or an HTTP `Server:` header that says "Microsoft-IIS")

This is lower-confidence than raw fingerprinting but is explainable, accurate enough for a LAN environment, and a good way to demonstrate you understand *why* the real technique needs privileges and what the practical alternative looks like.

### Multithreading performance
Sequential scanning of N ports takes roughly `N × timeout` in the worst case (e.g., scanning firewalled/filtered ports that don't respond until the timeout fires). With a thread pool, all N ports are attempted concurrently, so total time approaches a single `timeout` regardless of N. In testing, scanning 50 filtered ports went from ~25 seconds (1 thread) to ~0.5 seconds (50 threads) — **about a 49x speedup**, which is the core efficiency gain this project demonstrates.

## Legal / Ethical Note
Only scan systems you own or have explicit written permission to test. Unauthorized scanning of networks you don't control may violate computer misuse laws (e.g., the Computer Fraud and Abuse Act in the US, or equivalent laws elsewhere). This tool is for educational use and authorized security assessments only.

## Installation on Linux
-git clone https://github.com/ananyaa-dhiman/Mini-nmap.git
-ls
-cd Mini-nmap
-ls
-python3 mini_nmap.py -h



