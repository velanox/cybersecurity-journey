"""
Brute-force strategy — generates every possible string over a character
set, within a length range. Thin wrapper around candidates.py.
"""

from ..candidates import iter_bruteforce, estimate_total_bruteforce

NAME = "brute_force"


def build_candidates(charset: str, min_len: int, max_len: int):
    return iter_bruteforce(charset, min_len, max_len)


def estimate_total(charset_size: int, min_len: int, max_len: int) -> int:
    return estimate_total_bruteforce(charset_size, min_len, max_len)
