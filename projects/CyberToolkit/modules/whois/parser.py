"""
WHOIS response parser.

Different registries format their WHOIS output differently — there is no
single universal standard. This parser handles that by trying several
known label variants per field (case-insensitive, line-prefix matching)
rather than assuming one fixed format.

Pure text processing, no network, no Flask.
"""

# Each field: a list of line-prefix labels (lowercase) that different
# registries use for it. Order doesn't matter — every line is checked
# against every label, first match per field wins for single-value fields.
_SINGLE_VALUE_LABELS = {
    "registrar": [
        "registrar:", "sponsoring registrar:", "registrar organization:",
    ],
    "created": [
        "creation date:", "created on:", "created:", "registered on:",
        "domain registration date:", "registration time:",
        "[created on]",  # JPRS-style (.jp): bracketed, no colon
    ],
    "updated": [
        "updated date:", "last updated on:", "last modified:", "changed:",
        "modified:", "domain last updated date:",
        "[last updated]",  # JPRS-style
    ],
    "expires": [
        "registry expiry date:", "expiration date:", "expiry date:",
        "paid-till:", "registrar registration expiration date:",
        "expiration time:",
    ],
}

# Fields that can legitimately appear multiple times (a domain has several
# nameservers, several status codes).
_MULTI_VALUE_LABELS = {
    "status": ["domain status:", "status:", "[status]"],
    "nameservers": ["name server:", "nserver:", "nameserver:", "nameservers:", "[name server]"],
}

# Substrings (checked against the whole response, lowercase) that indicate
# the domain isn't registered — this varies a lot by registry, so the list
# is intentionally broad.
_NOT_FOUND_MARKERS = [
    "no match for",
    "not found",
    "no entries found",
    "no data found",
    "domain not found",
    "no matching record",
    "object does not exist",
    "status: available",
    "is available for registration",
    "no object found",
]


def is_not_found(raw: str) -> bool:
    """Heuristic: does this raw response indicate the domain isn't registered?"""
    if not raw or not raw.strip():
        return True
    lower = raw.lower()
    return any(marker in lower for marker in _NOT_FOUND_MARKERS)


def _matching_label(line_lower: str, labels: list) -> str:
    """Return the label that `line_lower` starts with, or None."""
    for label in labels:
        if line_lower.startswith(label):
            return label
    return None


def _extract_single(lines: list, labels: list) -> str:
    """First non-empty value found for any of `labels`, across all lines."""
    for line in lines:
        label = _matching_label(line.lower(), labels)
        if label:
            value = line[len(label):].strip()
            if value:
                return value
    return None


def _extract_multi(lines: list, labels: list, first_token_only: bool = False) -> list:
    """
    Every non-empty value found for any of `labels`, in order, deduplicated.
    `first_token_only` keeps just the first whitespace-separated token —
    useful for nameserver lines that sometimes trail an IP address, or
    status lines that trail an ICANN reference URL.
    """
    results = []
    for line in lines:
        label = _matching_label(line.lower(), labels)
        if not label:
            continue
        value = line[len(label):].strip()
        if not value:
            continue
        if first_token_only:
            value = value.split()[0]
        value = value.rstrip(".")
        if value and value not in results:
            results.append(value)
    return results


def parse_whois(raw: str) -> dict:
    """
    Parse a raw WHOIS response into a structured dict:
      {registrar, created, updated, expires, status, nameservers, not_found}

    Every field defaults to None/[] rather than being absent, so callers
    never have to check for missing keys. `not_found=True` means the
    domain appears unregistered — every other field will be empty in
    that case, which is the correct, non-error outcome for that query.
    """
    if is_not_found(raw):
        return {
            "registrar": None, "created": None, "updated": None, "expires": None,
            "status": [], "nameservers": [], "not_found": True,
        }

    lines = [line.strip() for line in raw.splitlines() if line.strip()]

    registrar = _extract_single(lines, _SINGLE_VALUE_LABELS["registrar"])
    created = _extract_single(lines, _SINGLE_VALUE_LABELS["created"])
    updated = _extract_single(lines, _SINGLE_VALUE_LABELS["updated"])
    expires = _extract_single(lines, _SINGLE_VALUE_LABELS["expires"])
    status = _extract_multi(lines, _MULTI_VALUE_LABELS["status"], first_token_only=True)
    nameservers = _extract_multi(lines, _MULTI_VALUE_LABELS["nameservers"], first_token_only=True)
    nameservers = [ns.lower() for ns in nameservers]

    return {
        "registrar": registrar,
        "created": created,
        "updated": updated,
        "expires": expires,
        "status": status,
        "nameservers": nameservers,
        "not_found": False,
    }
