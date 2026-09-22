"""
Input validation for the WHOIS module.
Pure functions, no network, no Flask — cleans and validates a domain
string, raising WhoisValidationError on anything that isn't a plausible
domain name.
"""

import re

# One DNS label: starts/ends with alphanumeric, hyphens allowed in the
# middle, 1-63 chars (per RFC 1035/1123).
_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"

# A domain: one or more "label." groups, then a final label (the TLD) of
# at least 2 alphabetic characters (also accepts punycode TLDs like xn--p1ai).
_DOMAIN_RE = re.compile(rf"^({_LABEL}\.)+(xn--[a-zA-Z0-9]+|[a-zA-Z]{{2,63}})$")

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

MAX_DOMAIN_LENGTH = 253  # RFC 1035 full-name limit


class WhoisError(Exception):
    """Base class for all errors raised by this module."""


class WhoisValidationError(WhoisError):
    """Raised when the input isn't a plausible domain name."""


def validate_domain(raw_domain: str) -> str:
    """
    Clean and validate a domain string. Returns the cleaned domain
    (lowercase, no scheme/path/port) on success.

    Deliberately does NOT try to guess a fix for malformed input beyond
    stripping an obvious scheme/path/port a user might paste — anything
    still ambiguous (an email address, a bare IP, garbage) is rejected
    with a specific message rather than silently reinterpreted.
    """
    if raw_domain is None:
        raise WhoisValidationError("Domain is required.")

    domain = raw_domain.strip()
    if not domain:
        raise WhoisValidationError("Domain is required.")

    if "@" in domain:
        raise WhoisValidationError("That looks like an email address, not a domain.")

    # Strip a scheme if pasted (http://, https://, ftp://, etc.)
    if "://" in domain:
        domain = domain.split("://", 1)[1]

    # Strip a path/query if pasted (example.com/page -> example.com)
    for sep in ("/", "?", "#"):
        if sep in domain:
            domain = domain.split(sep, 1)[0]

    # Strip a port if present (example.com:8080 -> example.com)
    if domain.count(":") == 1:
        domain = domain.split(":", 1)[0]

    domain = domain.lower().strip()

    # Strip one trailing dot (a fully-qualified "example.com." is valid DNS)
    if domain.endswith(".") and domain.count(".") > 1:
        domain = domain[:-1]

    if not domain:
        raise WhoisValidationError("Domain is required.")

    if len(domain) > MAX_DOMAIN_LENGTH:
        raise WhoisValidationError(f"Domain is too long (max {MAX_DOMAIN_LENGTH} characters).")

    if _IPV4_RE.match(domain) or ":" in domain:
        raise WhoisValidationError("IP address WHOIS lookups aren't supported — enter a domain name.")

    if "." not in domain:
        raise WhoisValidationError("Domain must include a TLD (e.g. 'example.com', not just 'example').")

    if not _DOMAIN_RE.match(domain):
        raise WhoisValidationError(f"'{raw_domain}' doesn't look like a valid domain name.")

    return domain