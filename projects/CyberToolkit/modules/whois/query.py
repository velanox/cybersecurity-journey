"""
WHOIS network engine — raw socket queries on port 43 (the WHOIS protocol
is plain text over TCP, no HTTP involved), with timeout handling and
referral following.

No parsing here — that's parser.py's job. This module's only concern is
"send a query, get text back, or fail cleanly."
"""

import socket

from .validators import validate_domain, WhoisError
from .servers import get_whois_server, IANA_WHOIS_SERVER

DEFAULT_TIMEOUT = 10.0
WHOIS_PORT = 43
MAX_RESPONSE_BYTES = 200_000  # sanity cap against a misbehaving/malicious server


class WhoisNetworkError(WhoisError):
    """Raised on any network-level failure: DNS, connection, or protocol issues."""


class WhoisTimeoutError(WhoisNetworkError):
    """Raised specifically when the server didn't respond within the timeout."""


def query_whois_server(server: str, query: str, timeout: float = DEFAULT_TIMEOUT,
                        port: int = WHOIS_PORT) -> str:
    """
    Send a single raw WHOIS query to `server` and return the decoded text
    response. `port` is parameterized (rather than hardcoded) so tests can
    point this at a local fake server without touching the real protocol
    port.
    """
    try:
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))

            chunks = []
            total = 0
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
                if total > MAX_RESPONSE_BYTES:
                    break

            return b"".join(chunks).decode("utf-8", errors="ignore")

    except socket.timeout:
        raise WhoisTimeoutError(f"Timed out waiting for a response from {server}.")
    except socket.gaierror:
        raise WhoisNetworkError(f"Could not resolve WHOIS server: {server}")
    except ConnectionRefusedError:
        raise WhoisNetworkError(f"Connection refused by {server}.")
    except OSError as e:
        raise WhoisNetworkError(f"Could not connect to {server}: {e}")


def extract_referral(response: str) -> str:
    """
    Look for a "refer:" or "whois:" line in a WHOIS response (the
    convention IANA and some thin registries use to point to the
    authoritative server for more detail). Returns the server name, or
    None if no referral line is present.
    """
    for line in response.splitlines():
        line = line.strip()
        lower = line.lower()
        if lower.startswith("refer:") or lower.startswith("whois:"):
            value = line.split(":", 1)[1].strip()
            if value:
                return value
    return None


def lookup_domain_raw(domain: str, timeout: float = DEFAULT_TIMEOUT,
                       _query_fn=query_whois_server) -> dict:
    """
    Validate the domain, resolve its WHOIS server, query it, and follow
    a single referral hop if the response points elsewhere (this covers
    both "IANA telling us the real registry" and "a thin registry telling
    us the registrar's own WHOIS server has more detail").

    `_query_fn` is an injection point for tests — production code never
    needs to pass it, it defaults to the real network function.

    Returns a dict: {"domain", "server", "raw", "error"}. On success,
    `error` is None and `raw` holds the final response text. On failure,
    `raw` is None (or the partial response we did get, if a referral
    follow-up failed) and `error` holds a human-readable message.
    """
    domain = validate_domain(domain)  # raises WhoisValidationError on bad input
    server = get_whois_server(domain)

    try:
        response = _query_fn(server, domain, timeout)
    except WhoisNetworkError as e:
        return {"domain": domain, "server": server, "raw": None, "error": str(e)}

    referral = extract_referral(response)
    if referral and referral.lower() != server.lower():
        try:
            response2 = _query_fn(referral, domain, timeout)
            return {"domain": domain, "server": referral, "raw": response2, "error": None}
        except WhoisNetworkError as e:
            # Referral failed — fall back to what we already have rather
            # than losing the first server's response entirely.
            return {"domain": domain, "server": server, "raw": response, "error": str(e)}

    return {"domain": domain, "server": server, "raw": response, "error": None}