"""
Hash analysis — figures out what a hash *might* be before any cracking
attempt starts: length, character set used, structured format detection
(bcrypt, crypt-style prefixes), salt convention, and which raw algorithms
match by output length.

No Flask, no I/O — pure string analysis.
"""

# Output length (hex chars) -> possible raw algorithms.
# Some lengths are ambiguous on purpose (MD5 and NTLM are both 32 hex
# chars) — that ambiguity is real and should be shown to the user, not
# hidden behind a guess.
LENGTH_MAP = {
    32:  ["MD5", "NTLM"],
    40:  ["SHA1"],
    56:  ["SHA224"],
    64:  ["SHA256"],
    96:  ["SHA384"],
    128: ["SHA512"],
}

# Recognizable prefixes for structured/salted formats this tool can
# *identify* but does not attempt to crack directly (bcrypt embeds its
# own salt and cost factor; crypt-style formats need their own parser).
STRUCTURED_PREFIXES = {
    "$1$":  "MD5-crypt",
    "$2a$": "bcrypt",
    "$2b$": "bcrypt",
    "$2y$": "bcrypt",
    "$5$":  "SHA256-crypt",
    "$6$":  "SHA512-crypt",
}


def analyze(hash_value: str) -> dict:
    """
    Inspect a hash string and return a structured description of it.
    Does not validate emptiness/length limits — that's validators.py's job,
    called before this by whoever owns the request (engine or Flask layer).
    """
    value = hash_value.strip()
    length = len(value)
    charset_used = sorted(set(value))
    is_hex = length > 0 and all(c in "0123456789abcdefABCDEF" for c in value)

    # 1) Check structured/salted-by-design formats first (bcrypt, crypt...)
    prefix = None
    fmt = "raw"
    structured = False
    for p, name in STRUCTURED_PREFIXES.items():
        if value.startswith(p):
            prefix = p
            fmt = name
            structured = True
            break

    # 2) If not structured, try to match a raw hex digest to known algorithms
    possible_algorithms = []
    if not structured and is_hex:
        possible_algorithms = LENGTH_MAP.get(length, [])
        fmt = "hex" if possible_algorithms else "unknown"
    elif not structured and not is_hex:
        fmt = "unknown"

    # 3) Detect the common "hash:salt" lab convention (colon-separated)
    salt_format = None
    if not structured and ":" in value:
        parts = value.split(":")
        if len(parts) == 2 and all(parts):
            salt_format = "hash:salt"

    return {
        "input": hash_value,
        "length": length,
        "charset_used": charset_used,
        "is_hex": is_hex,
        "format": fmt,
        "prefix": prefix,
        "structured": structured,
        "salt_format": salt_format,
        "possible_algorithms": possible_algorithms,
        # "crackable_locally" = this tool can attempt dictionary/brute-force
        # against it. Structured formats (bcrypt...) are identified but not
        # crackable through the raw-hash path this module implements.
        "crackable_locally": bool(possible_algorithms) and not structured,
    }