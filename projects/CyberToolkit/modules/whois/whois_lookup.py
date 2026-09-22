"""
Top-level WHOIS lookup — combines query.py (network) and parser.py (text)
into a single function returning one fully-structured result.

This is the main entry point the rest of the app (Flask, CLI, tests)
should import: `from modules.whois.whois_lookup import lookup_domain`.
"""

from .query import lookup_domain_raw, DEFAULT_TIMEOUT
from .parser import parse_whois
from .validators import WhoisValidationError, WhoisError  # re-exported for convenience

__all__ = ["lookup_domain", "WhoisValidationError", "WhoisError", "DEFAULT_TIMEOUT"]


def _empty_fields():
    return {
        "registrar": None, "created": None, "updated": None, "expires": None,
        "status": [], "nameservers": [],
    }


def lookup_domain(domain: str, timeout: float = DEFAULT_TIMEOUT, _lookup_fn=lookup_domain_raw) -> dict:
    """
    Perform a full WHOIS lookup: validate, query the right server (following
    a referral if needed), and parse the response into structured fields.

    Raises WhoisValidationError if `domain` isn't a plausible domain name —
    that's a caller/input problem, distinct from a lookup outcome, so it's
    raised rather than folded into the result (mirrors how the Port Scanner
    and Hash Cracker modules handle input validation elsewhere in this app).

    Never raises for network failures or "domain not found" — those are
    legitimate lookup outcomes, reported through the returned dict's
    `error` and `not_found` fields respectively. Always returns the same
    shape:

        {
          "domain": str, "registrar": str|None, "created": str|None,
          "updated": str|None, "expires": str|None, "status": list[str],
          "nameservers": list[str], "raw": str|None, "error": str|None,
          "not_found": bool,
        }

    `_lookup_fn` is a test injection point (defaults to the real network
    function) — production code never needs to pass it.
    """
    raw_result = _lookup_fn(domain, timeout)  # may raise WhoisValidationError

    if raw_result["error"]:
        return {
            "domain": raw_result["domain"],
            **_empty_fields(),
            "raw": raw_result["raw"],
            "error": raw_result["error"],
            "not_found": False,
        }

    parsed = parse_whois(raw_result["raw"])

    return {
        "domain": raw_result["domain"],
        "registrar": parsed["registrar"],
        "created": parsed["created"],
        "updated": parsed["updated"],
        "expires": parsed["expires"],
        "status": parsed["status"],
        "nameservers": parsed["nameservers"],
        "raw": raw_result["raw"],
        "error": None,
        "not_found": parsed["not_found"],
    }
