"""
Data structures for the WHOIS module.
No Flask, no I/O — just a typed reference for what lookup_domain() returns.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class WhoisResult:
    """
    Shape of lookup_domain()'s return value (as a dict in practice — this
    class documents the exact fields callers can rely on).

    `error` is None on success. On failure, every other field stays at its
    default (domain is still filled in, since we know what was asked for)
    so the frontend never has to special-case a "shape-less" error object.
    """
    domain: str
    registrar: Optional[str] = None
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    status: List[str] = field(default_factory=list)
    nameservers: List[str] = field(default_factory=list)
    raw: Optional[str] = None
    error: Optional[str] = None