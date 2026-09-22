"""
Input validation for the hash cracker module.
Pure functions, no Flask — raises ValidationError on bad input, returns
cleaned values on success.
"""

import os

# Hard technical ceiling on a single length value, independent of the
# spread rule below. This exists only to keep numbers (candidate counts,
# generator internals) from becoming pathological — NOT to second-guess
# the user's knowledge of the target. 24 chars over any charset is already
# far beyond anything feasible locally; the feasibility check (engine.py)
# is what actually stops unreasonable requests, with a clear reason why.
ABSOLUTE_MAX_LENGTH = 24

# The real constraint requested: the *range* the user searches (max - min)
# must stay small, not the absolute length. Someone who knows the password
# is "10 or 11 characters" pays for 2 lengths, not for scanning 1..11.
MAX_LENGTH_SPREAD = 8


class ValidationError(Exception):
    pass


def validate_hash_input(value):
    value = (value or "").strip()
    if not value:
        raise ValidationError("Hash value is required.")
    if len(value) > 512:
        raise ValidationError("Hash value is too long.")
    return value


def validate_algorithm(algorithm, supported):
    algorithm = (algorithm or "").strip().upper()
    if algorithm not in supported:
        raise ValidationError(f"Unsupported algorithm: {algorithm}")
    return algorithm


def validate_charset(lowercase, uppercase, numbers, symbols):
    if not any([lowercase, uppercase, numbers, symbols]):
        raise ValidationError("Select at least one character set.")
    charset = ""
    if lowercase:
        charset += "abcdefghijklmnopqrstuvwxyz"
    if uppercase:
        charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if numbers:
        charset += "0123456789"
    if symbols:
        charset += "!@#$%^&*()-_=+"
    return charset


def validate_length_range(min_len, max_len, max_spread=MAX_LENGTH_SPREAD,
                           absolute_max=ABSOLUTE_MAX_LENGTH):
    """
    Validates a [min_len, max_len] search range.

    Two independent rules:
      1) spread = max_len - min_len must stay <= max_spread (default 8).
         This is about the SIZE OF THE SEARCH, not how long the password
         actually is — searching lengths 10..11 (spread=1) is cheap even
         though 10 and 11 are both above the old flat cap of 8.
      2) max_len itself can't exceed absolute_max (24) — a hard technical
         ceiling so the numbers involved stay sane, independent of spread.
         In practice the feasibility check (engine.estimate) will reject
         far smaller ranges long before this ceiling matters.
    """
    if min_len < 1:
        raise ValidationError("Minimum length must be at least 1.")
    if max_len < min_len:
        raise ValidationError("Maximum length must be greater than or equal to minimum length.")
    if max_len > absolute_max:
        raise ValidationError(f"Maximum length cannot exceed {absolute_max} (hard technical ceiling).")
    spread = max_len - min_len
    if spread > max_spread:
        raise ValidationError(
            f"The range between minimum and maximum length is too wide "
            f"({spread} — max allowed is {max_spread}). Narrow the range if you "
            f"have any idea of the actual length."
        )
    return min_len, max_len


def validate_single_length(length, absolute_max=ABSOLUTE_MAX_LENGTH):
    """
    Rainbow tables target a FIXED length (reduction functions produce a
    string of exactly that length) — unlike brute force, there's no
    min/max range here, just one validated length.
    """
    if length < 1:
        raise ValidationError("Length must be at least 1.")
    if length > absolute_max:
        raise ValidationError(f"Length cannot exceed {absolute_max} (hard technical ceiling).")
    return length


def validate_wordlist_name(name, wordlist_dir):
    """
    Only accepts a bare filename that already exists inside wordlist_dir.
    Rejects anything containing a path separator, so a caller can never
    point this at an arbitrary file on disk.
    """
    if not name:
        raise ValidationError("No wordlist selected.")
    if os.path.basename(name) != name:
        raise ValidationError("Invalid wordlist name.")
    full_path = os.path.join(wordlist_dir, name)
    if not os.path.isfile(full_path):
        raise ValidationError(f"Wordlist not found: {name}")
    return full_path


def validate_salt_order(order):
    order = (order or "suffix").strip().lower()
    if order not in ("prefix", "suffix"):
        raise ValidationError("salt_order must be 'prefix' or 'suffix'.")
    return order