"""
Standalone DNS lookup engine, built on dnspython.

No dependency on Flask, HTML, or JavaScript — this module can be imported
and used from a CLI script, a test suite, or a web app alike. Import
lookup_domain() and call it; everything else is an implementation detail.
"""

import re
import time

import dns.resolver
import dns.exception

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"]

DEFAULT_TIMEOUT = 5.0  # seconds, per DNS query

# A conservative domain-name pattern: labels of letters/digits/hyphens,
# separated by dots, no leading/trailing hyphen per label, valid TLD length.
_DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


# ---------------------------------------------------------------------------
# Custom exceptions — lets any caller (Flask, CLI, tests...) catch precisely
# what went wrong instead of parsing an error string.
# ---------------------------------------------------------------------------

class DnsLookupError(Exception):
    """Base class for all errors raised by this module."""


class InvalidDomainError(DnsLookupError):
    pass


class InvalidRecordTypeError(DnsLookupError):
    pass


class InvalidTimeoutError(DnsLookupError):
    pass


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_domain(domain: str) -> str:
    """
    Validate a domain name's format and return it, lowercased and stripped.
    Does NOT check whether the domain actually exists — that happens at
    query time (a well-formed domain can still be NXDOMAIN).
    """
    domain = (domain or "").strip().lower()
    domain = domain.rstrip(".")  # trailing dot is valid DNS syntax, normalize it away

    if not domain:
        raise InvalidDomainError("Domain is required.")

    if not _DOMAIN_PATTERN.match(domain):
        raise InvalidDomainError(f"'{domain}' is not a valid domain name.")

    return domain


def validate_record_types(record_types: list[str]) -> list[str]:
    if not record_types:
        raise InvalidRecordTypeError("At least one record type is required.")

    normalized = [rt.strip().upper() for rt in record_types]
    unknown = [rt for rt in normalized if rt not in SUPPORTED_RECORD_TYPES]

    if unknown:
        raise InvalidRecordTypeError(
            f"Unsupported record type(s): {', '.join(unknown)}. "
            f"Supported: {', '.join(SUPPORTED_RECORD_TYPES)}."
        )

    return normalized


def validate_timeout(timeout: float) -> None:
    if timeout <= 0:
        raise InvalidTimeoutError("timeout must be greater than 0.")


# ---------------------------------------------------------------------------
# Core lookup
# ---------------------------------------------------------------------------

def _format_record(record_type: str, rdata) -> str:
    """Turn a dnspython rdata object into a plain, readable string."""
    if record_type == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if record_type == "TXT":
        return " ".join(part.decode("utf-8", errors="replace") for part in rdata.strings)
    return rdata.to_text().rstrip(".")


def query_record(domain: str, record_type: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Query a single DNS record type for a domain. Always returns a dict —
    never raises for "no record" or "timeout" — so the caller can
    distinguish FOUND / NOT_FOUND / TIMEOUT / ERROR per record type.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answer = resolver.resolve(domain, record_type)
        records = [_format_record(record_type, rdata) for rdata in answer]
        return {"type": record_type, "status": "found", "records": records, "error": None}

    except dns.resolver.NXDOMAIN:
        return {"type": record_type, "status": "nxdomain", "records": [],
                "error": f"Domain '{domain}' does not exist."}

    except dns.resolver.NoAnswer:
        return {"type": record_type, "status": "not_found", "records": [], "error": None}

    except dns.exception.Timeout:
        return {"type": record_type, "status": "timeout", "records": [],
                "error": f"DNS query timed out after {timeout}s."}

    except dns.exception.DNSException as e:
        return {"type": record_type, "status": "error", "records": [], "error": str(e)}


def lookup_domain(domain: str, record_types: list[str] | None = None,
                   timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Validate inputs, query each requested record type, and return a single
    structured report — everything the caller needs, nothing it has to
    recompute (duration, per-type status, etc.).
    """
    domain = validate_domain(domain)
    record_types = validate_record_types(record_types or SUPPORTED_RECORD_TYPES)
    validate_timeout(timeout)

    start_time = time.perf_counter()

    results = {rt: query_record(domain, rt, timeout) for rt in record_types}

    duration = round(time.perf_counter() - start_time, 3)

    found_count = sum(1 for r in results.values() if r["status"] == "found")

    return {
        "domain": domain,
        "record_types": record_types,
        "timeout": timeout,
        "results": results,
        "found_count": found_count,
        "duration": duration,
    }


# ---------------------------------------------------------------------------
# Standalone usage — proves this module needs nothing but the stdlib + dnspython.
# Run: python modules/dns_lookup.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    report = lookup_domain("example.com")
    print(f"DNS lookup for {report['domain']} — {report['found_count']} record type(s) found "
          f"in {report['duration']}s\n")

    for record_type, result in report["results"].items():
        if result["status"] == "found":
            print(f"{record_type}:")
            for rec in result["records"]:
                print(f"  {rec}")
        else:
            print(f"{record_type}: {result['status']}")