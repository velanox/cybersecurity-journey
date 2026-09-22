"""
Hash computation — the only file in this module that touches hashlib.
No Flask, no validation logic — just "given bytes, give me a digest".
"""

import hashlib

SUPPORTED = {
    "MD5": hashlib.md5,
    "SHA1": hashlib.sha1,
    "SHA224": hashlib.sha224,
    "SHA256": hashlib.sha256,
    "SHA384": hashlib.sha384,
    "SHA512": hashlib.sha512,
}


def compute(algorithm: str, data: bytes) -> str:
    """Hash raw bytes with the given algorithm and return the hex digest."""
    fn = SUPPORTED.get(algorithm)
    if not fn:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    return fn(data).hexdigest()


def compute_salted(algorithm: str, candidate: str, salt: str, order: str = "suffix") -> str:
    """
    Hash a candidate combined with a salt, in the given order:
      - "suffix": candidate + salt
      - "prefix": salt + candidate
    """
    combined = (candidate + salt) if order == "suffix" else (salt + candidate)
    return compute(algorithm, combined.encode("utf-8", errors="ignore"))