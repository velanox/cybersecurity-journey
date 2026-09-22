"""
Rainbow table compatibility check.

The actual table generation/search algorithm lives in rainbow_table.py —
this file only answers "can a rainbow table even work against this hash?",
which is the one piece of strategy-selection logic callers need before
offering the option at all.
"""

NAME = "rainbow"


def is_compatible(analysis: dict) -> bool:
    """
    Rainbow tables can't target salted or structured (bcrypt/crypt) hashes:
    a table built for one salt is useless against another, and structured
    formats need their own parser, not a raw-hash comparison.
    """
    return not analysis.get("salt_format") and not analysis.get("structured")
