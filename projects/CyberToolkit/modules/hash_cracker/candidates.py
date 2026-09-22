
import itertools
import os


def iter_dictionary(path: str):
    """
    Yield candidate words from a wordlist file, one line at a time.
    Never loads the whole file into memory — a 4GB wordlist costs the same
    RAM as a 4KB one here.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.rstrip("\r\n")
                if word:
                    yield word
    except OSError as e:
        raise OSError(f"Could not read wordlist '{path}': {e}")


def iter_bruteforce(charset: str, min_len: int, max_len: int):
    """
    Yield every possible string over `charset`, for each length from
    min_len to max_len inclusive. Shortest candidates first.
    """
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def estimate_total_bruteforce(charset_size: int, min_len: int, max_len: int) -> int:
    """Total candidate count for a brute-force run, without generating any of them."""
    return sum(charset_size ** length for length in range(min_len, max_len + 1))


def count_dictionary(path: str) -> int:
    """
    Count the lines in a wordlist without loading it into memory (streams
    through it once). Costs a full read pass — used only if a caller
    explicitly wants a total (e.g. for a progress percentage), not called
    by default.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Wordlist not found: {path}")

    count = 0
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.strip():
                count += 1
    return count