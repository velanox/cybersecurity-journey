"""
TLD -> WHOIS server resolution.

No network calls here — just static knowledge (a table of common TLDs)
plus the constant needed for the fallback path. For a TLD not in the
table, the caller (whois_lookup.py) queries IANA_WHOIS_SERVER first,
which replies with a "refer: whois.xxxx" line pointing to the real
authoritative server — this is the standard technique real WHOIS clients
use, and it covers virtually any TLD (including new gTLDs) without this
module needing to maintain an exhaustive list.
"""

# The IANA root WHOIS server — the fallback starting point for any TLD
# not explicitly listed below. Almost every WHOIS client bootstraps from
# here for TLDs it doesn't already know.
IANA_WHOIS_SERVER = "whois.iana.org"

# Common TLDs with a well-known, stable WHOIS server. Not exhaustive by
# design — this exists purely as a shortcut to skip the extra IANA
# round-trip for the TLDs looked up most often.
COMMON_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "tv": "whois.nic.tv",
    "cc": "ccwhois.verisign-grs.com",
    "xyz": "whois.nic.xyz",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "ai": "whois.nic.ai",
    "us": "whois.nic.us",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "nl": "whois.domain-registry.nl",
    "ca": "whois.cira.ca",
    "eu": "whois.eu",
    "ru": "whois.tcinet.ru",
    "cn": "whois.cnnic.cn",
    "jp": "whois.jprs.jp",
    "au": "whois.auda.org.au",
    "ch": "whois.nic.ch",
    "se": "whois.iis.se",
    "no": "whois.norid.no",
    "es": "whois.nic.es",
    "it": "whois.nic.it",
    "pl": "whois.dns.pl",
    "br": "whois.registro.br",
    "in": "whois.registry.in",
}

# Two-label ccTLD suffixes (e.g. "example.co.uk" — the effective TLD is
# "co.uk", not just "uk"). Checked before falling back to the last label.
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "co.jp", "or.jp", "ne.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "com.br", "net.br", "org.br",
    "co.za", "org.za", "net.za",
    "com.cn", "net.cn", "org.cn",
}


def get_tld(domain: str) -> str:
    """
    Return the effective TLD of a (already-validated) domain: the last
    two labels if they form a known multi-part ccTLD (e.g. "co.uk"),
    otherwise just the last label.
    """
    labels = domain.split(".")
    if len(labels) >= 2:
        last_two = ".".join(labels[-2:])
        if last_two in MULTI_PART_TLDS:
            return last_two
    return labels[-1]


def get_whois_server(domain: str) -> str:
    """
    Return the known WHOIS server for this domain's TLD, or the IANA
    root server as a starting point if the TLD isn't in our static table
    (the caller is expected to follow IANA's "refer:" line from there).

    Checks the full effective TLD first (e.g. "co.uk"), then falls back
    to just the last label (e.g. "uk") — many ccTLD registries (like
    Nominet for .uk) handle all their second-level variants through the
    same WHOIS server, so there's no need to bounce through IANA for
    "co.uk" if "uk" is already a known entry.
    """
    tld = get_tld(domain)
    if tld in COMMON_WHOIS_SERVERS:
        return COMMON_WHOIS_SERVERS[tld]

    last_label = domain.rsplit(".", 1)[-1]
    if last_label in COMMON_WHOIS_SERVERS:
        return COMMON_WHOIS_SERVERS[last_label]

    return IANA_WHOIS_SERVER