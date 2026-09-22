"""
Strategy registry — maps a strategy name to its module, so callers can
look one up by string ("dictionary", "brute_force", "rainbow") instead of
importing each one by name everywhere.
"""

from . import dictionary, brute_force, rainbow

STRATEGIES = {
    "dictionary": dictionary,
    "brute_force": brute_force,
    "rainbow": rainbow,
}