"""
Real rainbow table: precomputed hash chains built from reduction functions,
used to recover a plaintext from its hash without hashing every candidate
one by one.

How it actually works (this is the real algorithm, not brute force in
disguise):

  A "chain" starts from a random plaintext p0. We alternate hashing and
  reducing: h0 = H(p0), p1 = R0(h0), h1 = H(p1), p2 = R1(h1), ... for
  `chain_length` steps. We only ever STORE the start (p0) and the final
  endpoint (p_k) — everything in between is thrown away and recomputed
  on demand. A table of `table_size` chains covers up to
  table_size * chain_length plaintexts while only storing table_size pairs.

  R_i (the reduction function) maps a hash back to a same-length candidate
  string, and is different for every position `i` in the chain — this is
  the actual "rainbow" part: using a different reduction per column means
  two chains that collide at one position usually diverge afterwards,
  instead of merging into the same (wasted) chain forever.

  To look up a target hash: for each possible position j in the chain
  (working from the end backward), assume the target hash occurred at
  that position, finish the chain from there, and check if the resulting
  endpoint is in the table. If it is, regenerate that whole chain from its
  known start and check each intermediate hash for an exact match.

Limitations, stated plainly:
  - Coverage is probabilistic, not exhaustive. A table of a given size
    covers a fraction of the total space; a legitimate "not found" is
    expected outside that coverage, same as a real rainbow table.
  - Table sizes here are demo-scale (thousands of chains), meant to
    illustrate the technique on a local machine — not a production
    rockyou-scale precomputed table.
  - Chain merges (two different chains reaching the same endpoint) lose a
    little coverage silently, exactly as they do in a real implementation.
"""

from .algorithms import compute


def index_to_candidate(index: int, charset: str, length: int) -> str:
    """Convert an integer index into a fixed-length string over charset (base conversion)."""
    base = len(charset)
    chars = []
    for _ in range(length):
        index, rem = divmod(index, base)
        chars.append(charset[rem])
    return "".join(reversed(chars))


def _hash_to_index(hash_hex: str, position: int, space_size: int) -> int:
    """Map a hash + chain position to an index in [0, space_size), varying by position."""
    n = int(hash_hex[:16], 16)  # first 64 bits of the hash is plenty of entropy for this space
    return (n + position) % space_size


def reduce_hash(hash_hex: str, position: int, charset: str, length: int) -> str:
    """The reduction function R_position: hash -> candidate string."""
    space_size = len(charset) ** length
    index = _hash_to_index(hash_hex, position, space_size)
    return index_to_candidate(index, charset, length)


def generate_chain(start_candidate: str, algorithm: str, charset: str, length: int,
                    chain_length: int) -> str:
    """Run one full chain from a starting plaintext, return only the endpoint."""
    candidate = start_candidate
    for position in range(chain_length):
        digest = compute(algorithm, candidate.encode("utf-8", errors="ignore"))
        candidate = reduce_hash(digest, position, charset, length)
    return candidate


def build_table(algorithm: str, charset: str, length: int, table_size: int, chain_length: int,
                 rng, stop_event=None, pause_event=None, on_progress=None) -> dict:
    """
    Build a rainbow table: `table_size` chains of `chain_length` reduction
    steps each. Returns {endpoint: start}. Cooperative pause/stop: checked
    once per chain.
    """
    space_size = len(charset) ** length
    table = {}

    for i in range(table_size):
        if pause_event is not None:
            pause_event.wait()
        if stop_event is not None and stop_event.is_set():
            break

        start = index_to_candidate(rng.randrange(space_size), charset, length)
        end = generate_chain(start, algorithm, charset, length, chain_length)
        table[end] = start  # last write wins on collision — small, accepted coverage loss

        if on_progress:
            on_progress(i + 1, table_size)

    return table


def search(target_hash: str, algorithm: str, charset: str, length: int, table: dict,
           chain_length: int, stop_event=None, pause_event=None, on_progress=None) -> dict:
    """
    Look up target_hash against a prebuilt table. Returns:
      {"found": True, "candidate": "...", "hash_ops": N}
    or:
      {"found": False, "candidate": None, "hash_ops": N}

    hash_ops counts every H() call made (during both the backward search
    and the forward chain regeneration on a table hit) — reported as
    "candidates_tested" to the frontend, a unit of work comparable across
    strategies.
    """
    hash_ops = 0

    for j in range(chain_length):
        if pause_event is not None:
            pause_event.wait()
        if stop_event is not None and stop_event.is_set():
            return {"found": False, "candidate": None, "hash_ops": hash_ops, "stopped": True}

        start_position = chain_length - 1 - j

        # Assume target_hash occurred at `start_position`; finish the chain from there.
        candidate = reduce_hash(target_hash, start_position, charset, length)
        for position in range(start_position + 1, chain_length):
            digest = compute(algorithm, candidate.encode("utf-8", errors="ignore"))
            hash_ops += 1
            candidate = reduce_hash(digest, position, charset, length)

        if candidate in table:
            # Potential hit — regenerate the real chain from its known start
            # and check every intermediate hash for an exact match.
            replay = table[candidate]
            for position in range(chain_length):
                digest = compute(algorithm, replay.encode("utf-8", errors="ignore"))
                hash_ops += 1
                if digest == target_hash:
                    return {"found": True, "candidate": replay, "hash_ops": hash_ops}
                replay = reduce_hash(digest, position, charset, length)
            # False alarm (a merge collision) — keep searching other positions.

        if on_progress:
            on_progress(j + 1, chain_length, hash_ops)

    return {"found": False, "candidate": None, "hash_ops": hash_ops}


def recommended_params(space_size: int) -> dict:
    """
    Pick demo-scale table parameters based on the size of the search space,
    aiming for noticeable (not exhaustive) coverage on a local machine.
    Caller can override these.
    """
    chain_length = 200
    target_coverage = min(space_size, 2_000_000)
    table_size = max(100, min(20000, target_coverage // chain_length or 100))
    return {"table_size": table_size, "chain_length": chain_length}