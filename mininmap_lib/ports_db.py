"""
ports_db.py
------------
Static database of well-known ports and the service names associated
with them. This is used for the initial "service guess" before the
tool tries to actively grab a banner for real version detection.
"""

# Common ports -> (service name, default guess)
COMMON_PORTS = {
    20:   "ftp-data",
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    67:   "dhcp",
    68:   "dhcp",
    69:   "tftp",
    80:   "http",
    110:  "pop3",
    111:  "rpcbind",
    123:  "ntp",
    135:  "msrpc",
    137:  "netbios-ns",
    138:  "netbios-dgm",
    139:  "netbios-ssn",
    143:  "imap",
    161:  "snmp",
    389:  "ldap",
    443:  "https",
    445:  "microsoft-ds",
    465:  "smtps",
    514:  "syslog",
    587:  "smtp-submission",
    631:  "ipp",
    993:  "imaps",
    995:  "pop3s",
    1080: "socks",
    1433: "mssql",
    1521: "oracle-db",
    1723: "pptp",
    1883: "mqtt",
    2049: "nfs",
    27017: "mongodb",
    3000: "dev-http",
    3128: "squid-proxy",
    3306: "mysql",
    3389: "rdp",
    5000: "dev-http",
    5432: "postgresql",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    6667: "irc",
    8000: "http-alt",
    8008: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    8888: "http-alt",
    9000: "http-alt",
    9090: "http-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27018: "mongodb",
}

# A reasonably useful "top ports" list (similar in spirit to nmap --top-ports)
TOP_100_PORTS = sorted(set(list(COMMON_PORTS.keys()) + [
    1, 3, 7, 9, 13, 17, 19, 26, 37, 49, 70, 79, 81, 88, 90, 99, 100,
    106, 109, 113, 119, 125, 199, 211, 212, 222, 254, 255, 256, 259,
    264, 280, 301, 306, 311, 340, 366, 406, 407, 416, 417, 425, 427,
    444, 458, 464, 481, 497, 500, 512, 513, 515, 524, 541, 543, 544,
    545, 548, 554, 555, 563, 593, 616, 617, 625, 626, 636, 646, 648,
    666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726,
    749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898,
    900, 901, 902, 903, 911, 912,
]))[:100]
