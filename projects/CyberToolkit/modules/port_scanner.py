"""
Standalone TCP connect-scan port scanner.

No dependency on Flask, HTML, or any web framework — this module can be
imported and used from a CLI script, a test suite, or a web app alike.
Import scan_range() and call it; everything else is an implementation detail.
"""

import ipaddress
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_PORT = 1
MAX_PORT = 65535
MAX_THREADS = 500  # hard ceiling, regardless of what the caller requests

# The most useful, commonly-seen ports — each with a short human-readable
# name and description. Used to enrich results whether the port turns out
# open or closed. Not exhaustive on purpose: only the ports someone
# scanning a host actually cares to recognize at a glance.
COMMON_PORTS = {
    20:   {"name": "FTP-DATA", "description": "File Transfer Protocol — data channel"},
    21:   {"name": "FTP",      "description": "File Transfer Protocol — command channel"},
    22:   {"name": "SSH",      "description": "Secure Shell — encrypted remote login"},
    23:   {"name": "Telnet",   "description": "Unencrypted remote login (legacy, avoid)"},
    25:   {"name": "SMTP",     "description": "Simple Mail Transfer Protocol — sending email"},
    53:   {"name": "DNS",      "description": "Domain Name System — hostname resolution"},
    67:   {"name": "DHCP",     "description": "Dynamic Host Configuration Protocol (server)"},
    68:   {"name": "DHCP",     "description": "Dynamic Host Configuration Protocol (client)"},
    80:   {"name": "HTTP",     "description": "Unencrypted web traffic"},
    110:  {"name": "POP3",     "description": "Post Office Protocol — retrieving email"},
    111:  {"name": "RPCbind",  "description": "Remote Procedure Call port mapper"},
    123:  {"name": "NTP",      "description": "Network Time Protocol — clock sync"},
    135:  {"name": "MSRPC",    "description": "Microsoft RPC endpoint mapper"},
    139:  {"name": "NetBIOS",  "description": "Windows file/printer sharing (legacy)"},
    143:  {"name": "IMAP",     "description": "Internet Message Access Protocol — email"},
    161:  {"name": "SNMP",     "description": "Simple Network Management Protocol"},
    389:  {"name": "LDAP",     "description": "Lightweight Directory Access Protocol"},
    443:  {"name": "HTTPS",    "description": "Encrypted web traffic (TLS/SSL)"},
    445:  {"name": "SMB",      "description": "Windows file sharing"},
    465:  {"name": "SMTPS",    "description": "SMTP over TLS/SSL"},
    587:  {"name": "SMTP",     "description": "Mail submission (with authentication)"},
    993:  {"name": "IMAPS",    "description": "IMAP over TLS/SSL"},
    995:  {"name": "POP3S",    "description": "POP3 over TLS/SSL"},
    1433: {"name": "MSSQL",    "description": "Microsoft SQL Server"},
    1521: {"name": "Oracle",   "description": "Oracle database listener"},
    3306: {"name": "MySQL",    "description": "MySQL / MariaDB database"},
    3389: {"name": "RDP",      "description": "Remote Desktop Protocol (Windows)"},
    5432: {"name": "PostgreSQL", "description": "PostgreSQL database"},
    5900: {"name": "VNC",      "description": "Virtual Network Computing — remote desktop"},
    6379: {"name": "Redis",    "description": "Redis in-memory database"},
    8080: {"name": "HTTP-alt", "description": "Common alternate web server port"},
    8443: {"name": "HTTPS-alt", "description": "Common alternate encrypted web port"},
    27017: {"name": "MongoDB", "description": "MongoDB database"},
}


# ---------------------------------------------------------------------------
# Custom exceptions — lets any caller (Flask, CLI, tests...) catch precisely
# what went wrong instead of parsing an error string.
# ---------------------------------------------------------------------------

class PortScannerError(Exception):
    """Base class for all validation errors raised by this module."""


class InvalidTargetError(PortScannerError):
    pass


class InvalidPortRangeError(PortScannerError):
    pass


class InvalidTimeoutError(PortScannerError):
    pass


class InvalidThreadCountError(PortScannerError):
    pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_target(target: str) -> str:
    """
    Validate a target and return its resolved IPv4 address as a string.

    Accepts:
      - a literal IPv4 address ("192.168.1.1")
      - a hostname that resolves to an IPv4 address ("example.com")

    Raises InvalidTargetError if neither works.
    """
    target = (target or "").strip()
    if not target:
        raise InvalidTargetError("Target is required.")

    try:
        ipaddress.IPv4Address(target)
        return target
    except ipaddress.AddressValueError:
        pass

    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise InvalidTargetError(f"Could not resolve host: {target}")


def validate_port_range(start_port: int, end_port: int) -> None:
    if not (MIN_PORT <= start_port <= MAX_PORT):
        raise InvalidPortRangeError(f"start_port must be between {MIN_PORT} and {MAX_PORT}.")
    if not (MIN_PORT <= end_port <= MAX_PORT):
        raise InvalidPortRangeError(f"end_port must be between {MIN_PORT} and {MAX_PORT}.")
    if start_port > end_port:
        raise InvalidPortRangeError("start_port must be less than or equal to end_port.")


def validate_timeout(timeout: float) -> None:
    if timeout <= 0:
        raise InvalidTimeoutError("timeout must be greater than 0.")


def validate_threads(threads: int) -> None:
    if not (1 <= threads <= MAX_THREADS):
        raise InvalidThreadCountError(f"threads must be between 1 and {MAX_THREADS}.")


# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------

def scan_port(ip: str, port: int, timeout: float) -> dict:
    """
    Test a single TCP port. Always returns a dict — never None — so the
    caller can see OPEN, CLOSED, and TIMEOUT results, not just successes.
    Looks up the port in COMMON_PORTS regardless of its status, so a
    well-known port shows its name/description whether it's open or closed.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    known = COMMON_PORTS.get(port)
    name = known["name"] if known else None
    description = known["description"] if known else None

    try:
        result = sock.connect_ex((ip, port))
    except socket.timeout:
        status = "timeout"
    except OSError:
        status = "error"
    else:
        status = "open" if result == 0 else "closed"
    finally:
        sock.close()  # explicit close, on every exit path

    return {
        "port": port,
        "status": status,
        "name": name,
        "description": description,
    }


def scan_range(target: str, start_port: int, end_port: int,
                timeout: float = 0.5, threads: int = 100) -> dict:
    """
    Validate inputs, scan a port range concurrently, and return a single
    structured result — everything the caller needs, nothing it has to
    recompute (duration, counts, etc.).
    """
    ip = validate_target(target)
    validate_port_range(start_port, end_port)
    validate_timeout(timeout)
    validate_threads(threads)

    ports_tested = end_port - start_port + 1
    all_results = []

    start_time = time.perf_counter()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            all_results.append(future.result())

    duration = round(time.perf_counter() - start_time, 3)

    # Every open port — recognized or not — the security-relevant list.
    open_ports = sorted(
        (r for r in all_results if r["status"] == "open"),
        key=lambda r: r["port"],
    )

    # Well-known ports tested in this range, open OR closed, so the user
    # can see "SSH: closed" as useful info without scrolling 1024 rows.
    known_ports = sorted(
        (r for r in all_results if r["name"] is not None),
        key=lambda r: r["port"],
    )

    return {
        "target": target,
        "resolved_ip": ip,
        "start_port": start_port,
        "end_port": end_port,
        "timeout": timeout,
        "threads": threads,
        "ports_tested": ports_tested,
        "open_count": len(open_ports),
        "closed_count": sum(1 for r in all_results if r["status"] == "closed"),
        "timeout_count": sum(1 for r in all_results if r["status"] == "timeout"),
        "open_ports": open_ports,
        "known_ports": known_ports,
        "duration": duration,
    }


# ---------------------------------------------------------------------------
# Standalone usage — proves this module needs nothing but the stdlib.
# Run: python port_scanner.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    report = scan_range("127.0.0.1", 1, 1024, timeout=0.3, threads=100)
    print(f"Scanned {report['ports_tested']} ports on {report['resolved_ip']} "
          f"in {report['duration']}s — {report['open_count']} open")
    for p in report["open_ports"]:
        label = f" ({p['name']})" if p["name"] else ""
        print(f"  {p['port']:<6} open{label}")