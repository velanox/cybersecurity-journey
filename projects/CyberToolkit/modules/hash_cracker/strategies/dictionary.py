"""
Dictionary strategy — reads candidates from a wordlist file, optionally
applying simple transformations to each word before testing it.
"""

from ..candidates import iter_dictionary

NAME = "dictionary"

TRANSFORMATIONS = {
    "capitalize": lambda w: w.capitalize(),
    "upper": lambda w: w.upper(),
    "append_1": lambda w: w + "1",
    "append_123": lambda w: w + "123",
    "leet": lambda w: w.replace("a", "4").replace("e", "3").replace("o", "0").replace("i", "1"),
}


def build_candidates(wordlist_path: str, transformations: list = None):
    """
    Yield every word from the wordlist, and — if requested — its
    transformed variants right after it.
    """
    transformations = transformations or []
    transform_fns = [TRANSFORMATIONS[t] for t in transformations if t in TRANSFORMATIONS]

    for word in iter_dictionary(wordlist_path):
        yield word
        for fn in transform_fns:
            variant = fn(word)
            if variant != word:
                yield variant