#!/usr/bin/env python3
"""
Hash Cracker CLI
================

Educational CLI for hashing and cracking passwords: dictionary, rule-based,
mask, brute-force and rainbow-table attacks, with adaptive benchmarking.

Usage:
    python3 hash_cracker.py
    Then type /help.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import secrets
import shlex
import string
import time
from typing import Callable, Iterator, Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALGORITHM_MENU: list[str] = [
    "md5", "sha1", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s",
]

MODE_MENU: list[tuple[str, str]] = [
    ("standard", "Standard hash (no salt, single round)"),
    ("salted", "Salted hash (random salt, single round)"),
    ("salted_stretched", "Salted + stretched hash (random salt, many rounds)"),
]

DEFAULT_STRETCH_ITERATIONS = 200_000
CALIBRATION_TARGET_SECONDS = 0.5
CALIBRATION_WARMUP_ROUNDS = 20

CHARSETS: dict[str, str] = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "symbols": string.punctuation,
}

MASK_TOKENS: dict[str, str] = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": string.punctuation,
}

# Rule-based attack: (label, transform). Applied to every wordlist entry.
RULES: list[tuple[str, Callable[[str], str]]] = [
    ("as-is", lambda w: w),
    ("lowercase", str.lower),
    ("uppercase", str.upper),
    ("capitalize", str.capitalize),
    ("reversed", lambda w: w[::-1]),
    ("leetspeak", lambda w: w.translate(str.maketrans("aeios", "43105"))),
    ("append_123", lambda w: w + "123"),
    ("append_!", lambda w: w + "!"),
    ("append_1", lambda w: w + "1"),
]


# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

class Session:
    """State that persists across commands during a single run."""

    def __init__(self) -> None:
        self.algorithm: str = "sha256"
        self.hash_mode: str = "standard"
        self.salt: Optional[str] = None
        self.iterations: int = 1
        self.target_hash: Optional[str] = None
        self.rainbow_table: Optional[dict[str, str]] = None
        self.rainbow_meta: Optional[dict] = None


# ---------------------------------------------------------------------------
# Core hashing
# ---------------------------------------------------------------------------

def compute_hash(plaintext: str, algorithm: str, salt: Optional[str] = None, iterations: int = 1) -> str:
    """Hash plaintext, optionally salted and stretched over multiple rounds."""
    algorithm = algorithm.lower()
    if algorithm not in hashlib.algorithms_guaranteed:
        raise ValueError(f"Unsupported algorithm: '{algorithm}'")

    digest = (salt or "") + plaintext
    for _ in range(max(1, iterations)):
        digest = hashlib.new(algorithm, digest.encode("utf-8")).hexdigest()
    return digest


def format_duration(seconds: float) -> str:
    """Convert seconds into the most readable unit (s/min/h/days/weeks/years)."""
    if seconds == float("inf"):
        return "∞"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.2f} min"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.2f} h"
    days = hours / 24
    if days < 7:
        return f"{days:.2f} days"
    weeks = days / 7
    if weeks < 52:
        return f"{weeks:.2f} weeks"
    return f"{days / 365.25:.2f} years"


def calibrate_hash_rate(algorithm: str, salt: Optional[str], iterations: int) -> float:
    """Estimate hashes/s for this machine, adapting sample size to hashing cost."""
    warmup_start = time.perf_counter()
    for i in range(CALIBRATION_WARMUP_ROUNDS):
        compute_hash(f"warmup{i}", algorithm, salt, iterations)
    per_hash_time = (time.perf_counter() - warmup_start) / CALIBRATION_WARMUP_ROUNDS or 1e-9

    sample_size = max(10, min(20_000, int(CALIBRATION_TARGET_SECONDS / per_hash_time)))

    start = time.perf_counter()
    for i in range(sample_size):
        compute_hash(f"calib{i}", algorithm, salt, iterations)
    elapsed = time.perf_counter() - start

    return sample_size / elapsed if elapsed > 0 else float("inf")


# ---------------------------------------------------------------------------
# Generic attack engine (shared by dictionary / rule / mask / brute force)
# ---------------------------------------------------------------------------

def _confirm_run(session: Session, total_operations: int, prompt: str = "Launch the attack now?") -> bool:
    """Show a calibrated time estimate and ask for confirmation before running."""
    print("[i] Calibrating hash rate for this machine...")
    rate = calibrate_hash_rate(session.algorithm, session.salt, session.iterations)
    estimated_seconds = total_operations / rate if rate > 0 else float("inf")

    print(f"[i] Estimated speed : ~{rate:,.0f} hashes/s")
    print(f"[i] Estimated time  : {format_duration(estimated_seconds)}")

    try:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return False
    return answer in ("y", "yes")


def print_benchmark_block(
    attack_name: str, total: int, attempts: int, elapsed: float,
    total_label: str = "Keyspace", unit: str = "candidates",
) -> None:
    """Print the standardized benchmark summary block shared by all attacks."""
    rate = attempts / elapsed if elapsed > 0 else float("inf")
    print(f"""
{attack_name}
{total_label}:
{total:,} {unit}
Attempts:
{attempts:,}
Time:
{format_duration(elapsed)}
↓
{rate:,.0f} hashes/s
""")


def _execute_attack(
    session: Session, target_hash: str, candidates: Callable[[], Iterator[str]],
) -> tuple[int, float, Optional[str]]:
    """Run the actual hashing loop. Returns (attempts, elapsed_seconds, found_candidate)."""
    start = time.perf_counter()
    attempts = 0
    found: Optional[str] = None
    for candidate in candidates():
        attempts += 1
        if compute_hash(candidate, session.algorithm, session.salt, session.iterations) == target_hash:
            found = candidate
            break
    return attempts, time.perf_counter() - start, found


def run_attack(
    session: Session,
    target_hash: str,
    attack_name: str,
    total_candidates: int,
    candidates: Callable[[], Iterator[str]],
    total_label: str = "Keyspace",
    unit: str = "candidates",
) -> None:
    """Run any keyspace-based attack: estimate, confirm, execute, report."""
    target_hash = target_hash.lower()
    if total_candidates <= 0:
        print("[Error] Empty keyspace.")
        return

    print(f"[i] {total_label}: {total_candidates:,} {unit}")
    if session.hash_mode != "standard":
        print(f"[i] Hash mode: {session.hash_mode} (salt={session.salt}, iterations={session.iterations})")

    if not _confirm_run(session, total_candidates):
        print("[i] Attack cancelled.")
        return

    attempts, elapsed, found = _execute_attack(session, target_hash, candidates)

    print_benchmark_block(attack_name, total_candidates, attempts, elapsed, total_label, unit)
    print(f"[+] Password found: {found}" if found else "[-] Password not found.")


def _count_wordlist_entries(wordlist_path: str) -> Optional[int]:
    """Count non-empty lines in a wordlist file. None if the file doesn't exist."""
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except FileNotFoundError:
        return None


def _build_charset(charset_keys: str) -> str:
    """Combine comma-separated charset keys (lower,upper,digits,symbols) into one string."""
    chars = []
    for key in charset_keys.split(","):
        key = key.strip().lower()
        if key not in CHARSETS:
            raise KeyError(f"Unknown charset '{key}' (available: {', '.join(CHARSETS)})")
        chars.append(CHARSETS[key])
    return "".join(dict.fromkeys("".join(chars)))  # dedupe, preserve order


def _parse_mask(mask: str) -> list[str]:
    """Parse a mask like '?l?l?l?d?d' into a list of charsets/literals per position."""
    groups: list[str] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i + 1]
            if token not in MASK_TOKENS:
                raise KeyError(f"Unknown mask token '?{token}' (available: ?l ?u ?d ?s)")
            groups.append(MASK_TOKENS[token])
            i += 2
        else:
            groups.append(mask[i])
            i += 1
    return groups


# ---------------------------------------------------------------------------
# CLI commands - configuration
# ---------------------------------------------------------------------------

def cmd_help(session: Session, args: list[str]) -> None:
    print(f"""
================================================================================
 HASH CRACKER CLI - HELP
================================================================================

CONFIGURATION
  /algo [name|number]
      Select the active hash algorithm. Shows an interactive menu if no
      argument is given.
      Available : md5, sha1, sha256, sha384, sha512, sha3_256, sha3_512,
                  blake2b, blake2s

  /mode [name|number] [iterations]
      Select the hashing mode applied on top of the algorithm.
        1. standard          no salt, 1 round               (fast)
        2. salted            random salt, 1 round            (defeats precomputed tables)
        3. salted_stretched  random salt, N rounds            (slow, simulates PBKDF2/bcrypt)
      [iterations] only applies to salted_stretched (default: {DEFAULT_STRETCH_ITERATIONS:,}).

  /hash <text>
      Hash <text> with the active algorithm/mode and store the result as the
      current target hash (reusable directly in the attack commands).

--------------------------------------------------------------------------------
ATTACKS
  All attack commands show an estimated speed and duration (calibrated live on
  this machine) and ask for confirmation BEFORE actually running.

  /dict <hash> <wordlist>
      Try every line of <wordlist> as-is against <hash>.

  /rule <hash> <wordlist>
      Like /dict, but each word is also tried through {len(RULES)} transformation
      rules (lowercase, uppercase, capitalize, reversed, leetspeak, and common
      numeric/symbol suffixes).

  /mask <hash> <mask>
      Try every combination matching a mask pattern.
      Tokens : ?l lowercase   ?u uppercase   ?d digits   ?s symbols
      Any other character in the mask is treated as a fixed literal.
      Example : ?u?l?l?l?d?d?d  ->  1 uppercase + 3 lowercase + 3 digits

  /brute <hash> <charsets> <max_length>
      Try every combination of the given charset(s), for every length from
      1 to <max_length>.
      Charset keys (comma-separated) : lower, upper, digits, symbols
      Example : lower,digits 4  ->  all lowercase+digit strings, length 1-4

  /rainbow build <charsets> <max_length>
      Precompute a hash -> plaintext table for the given keyspace. Expensive
      once, then every lookup against it is instant (O(1)).
  /rainbow crack <hash>
      Look up <hash> in the currently built/loaded table.
  /rainbow save <file>  |  /rainbow load <file>
      Persist a table to disk (JSON) or reload one, so it can be reused
      across sessions without rebuilding it.

  /benchmark <hash> <wordlist> <mask> <charsets> <max_length>
      Run dictionary, rule, mask and brute-force attacks on the SAME hash
      back-to-back, then print a side-by-side comparison table
      (attempts, time, hashes/s) so you can see how each method scales.

--------------------------------------------------------------------------------
EXAMPLES
  /algo sha256
  /mode salted_stretched 200000
  /hash password123
  /dict {{hash}} rockyou.txt
  /rule {{hash}} rockyou.txt
  /mask {{hash}} ?u?l?l?l?d?d?d
  /brute {{hash}} lower,digits 5
  /rainbow build lower,digits 4
  /rainbow crack {{hash}}
  /benchmark {{hash}} rockyou.txt ?l?l?l?d?d lower,digits 4

--------------------------------------------------------------------------------
  /quit                                Exit the program

Active algorithm : {session.algorithm}
Active mode      : {session.hash_mode}
================================================================================
""")


def cmd_algo(session: Session, args: list[str]) -> None:
    if args:
        _set_algorithm(session, args[0])
        return

    print("\nSelect a hash algorithm:")
    for index, name in enumerate(ALGORITHM_MENU, start=1):
        marker = "  <- current" if name == session.algorithm else ""
        print(f"  {index}. {name}{marker}")

    try:
        choice = input("Number or name: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    _set_algorithm(session, choice)


def _set_algorithm(session: Session, choice: str) -> None:
    choice = choice.lower()
    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(ALGORITHM_MENU):
            choice = ALGORITHM_MENU[index]
        else:
            print(f"[Error] Invalid option (expected 1-{len(ALGORITHM_MENU)})")
            return

    if choice not in hashlib.algorithms_guaranteed:
        print(f"[Error] Unsupported algorithm: '{choice}'")
        return

    session.algorithm = choice
    print(f"[+] Active algorithm set to: {choice}")


def cmd_mode(session: Session, args: list[str]) -> None:
    if args:
        _apply_mode(session, args[0], args[1] if len(args) > 1 else None)
        return

    print("\nSelect a hashing mode:")
    for index, (key, label) in enumerate(MODE_MENU, start=1):
        marker = "  <- current" if key == session.hash_mode else ""
        print(f"  {index}. {label}{marker}")

    try:
        choice = input("Number or name: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return

    iterations_arg = None
    if _resolve_mode_key(choice) == "salted_stretched":
        try:
            raw = input(f"Number of iterations [default {DEFAULT_STRETCH_ITERATIONS}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            return
        iterations_arg = raw or None

    _apply_mode(session, choice, iterations_arg)


def _resolve_mode_key(choice: str) -> Optional[str]:
    choice = choice.lower()
    if choice.isdigit():
        index = int(choice) - 1
        return MODE_MENU[index][0] if 0 <= index < len(MODE_MENU) else None
    valid_keys = {key for key, _ in MODE_MENU}
    return choice if choice in valid_keys else None


def _apply_mode(session: Session, choice: str, iterations_arg: Optional[str]) -> None:
    key = _resolve_mode_key(choice)
    if key is None:
        print(f"[Error] Invalid mode: '{choice}'")
        return

    session.hash_mode = key

    if key == "standard":
        session.salt = None
        session.iterations = 1
        print("[+] Mode set to: standard (no salt, 1 round)")
        return

    session.salt = secrets.token_hex(8)

    if key == "salted":
        session.iterations = 1
        print(f"[+] Mode set to: salted (salt={session.salt}, 1 round)")
    else:
        iterations = DEFAULT_STRETCH_ITERATIONS
        if iterations_arg:
            try:
                iterations = int(iterations_arg)
                if iterations < 1:
                    raise ValueError
            except ValueError:
                print(f"[Error] Invalid iteration count. Using default ({DEFAULT_STRETCH_ITERATIONS}).")
                iterations = DEFAULT_STRETCH_ITERATIONS
        session.iterations = iterations
        print(f"[+] Mode set to: salted_stretched (salt={session.salt}, iterations={iterations})")


def cmd_hash(session: Session, args: list[str]) -> None:
    if not args:
        print("Usage: /hash <text>")
        return

    plaintext = args[0]
    try:
        result = compute_hash(plaintext, session.algorithm, session.salt, session.iterations)
        session.target_hash = result
        print(f"[{session.algorithm} | {session.hash_mode}] {plaintext} -> {result}")
        if session.salt:
            print(f"[i] Salt: {session.salt}  |  Iterations: {session.iterations}")
        print("[i] Hash stored as current target (reusable in attack commands)")
    except ValueError as error:
        print(f"[Error] {error}")


# ---------------------------------------------------------------------------
# CLI commands - attacks
# ---------------------------------------------------------------------------

def cmd_dict(session: Session, args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: /dict <hash> <wordlist>")
        return
    target_hash, wordlist_path = args[0], args[1]

    total_words = _count_wordlist_entries(wordlist_path)
    if total_words is None:
        print(f"[Error] Wordlist file not found: {wordlist_path}")
        return
    if total_words == 0:
        print("[Error] Wordlist is empty.")
        return

    def candidates() -> Iterator[str]:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word:
                    yield word

    run_attack(session, target_hash, "Dictionary Attack", total_words, candidates, "Wordlist", "words")


def cmd_rule(session: Session, args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: /rule <hash> <wordlist>")
        return
    target_hash, wordlist_path = args[0], args[1]

    total_words = _count_wordlist_entries(wordlist_path)
    if total_words is None:
        print(f"[Error] Wordlist file not found: {wordlist_path}")
        return
    if total_words == 0:
        print("[Error] Wordlist is empty.")
        return

    total_candidates = total_words * len(RULES)

    def candidates() -> Iterator[str]:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                for _, rule in RULES:
                    yield rule(word)

    run_attack(session, target_hash, "Rule-Based Attack", total_candidates, candidates, "Wordlist x Rules", "candidates")


def cmd_mask(session: Session, args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: /mask <hash> <mask>  (e.g. /mask <hash> ?l?l?l?d?d)")
        return
    target_hash, mask = args[0], args[1]

    try:
        groups = _parse_mask(mask)
    except KeyError as error:
        print(f"[Error] {error}")
        return

    total_candidates = 1
    for group in groups:
        total_candidates *= len(group)

    def candidates() -> Iterator[str]:
        for combo in itertools.product(*groups):
            yield "".join(combo)

    run_attack(session, target_hash, "Mask Attack", total_candidates, candidates, "Keyspace", "combinations")


def cmd_brute(session: Session, args: list[str]) -> None:
    if len(args) < 3:
        print("Usage: /brute <hash> <charsets> <max_length>  (e.g. /brute <hash> lower,digits 4)")
        return
    target_hash, charset_keys, max_length_arg = args[0], args[1], args[2]

    try:
        charset = _build_charset(charset_keys)
        max_length = int(max_length_arg)
    except (KeyError, ValueError) as error:
        print(f"[Error] {error}")
        return

    total_candidates = sum(len(charset) ** length for length in range(1, max_length + 1))

    def candidates() -> Iterator[str]:
        for length in range(1, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    run_attack(session, target_hash, "Brute Force Attack", total_candidates, candidates, "Keyspace", "combinations")


# ---------------------------------------------------------------------------
# CLI commands - benchmark
# ---------------------------------------------------------------------------

def cmd_benchmark(session: Session, args: list[str]) -> None:
    """Run dictionary, rule, mask and brute force attacks on the same hash and compare."""
    if len(args) < 5:
        print("Usage: /benchmark <hash> <wordlist> <mask> <charsets> <max_length>")
        return
    target_hash, wordlist_path, mask, charset_keys, max_length_arg = args[0].lower(), args[1], args[2], args[3], args[4]

    # Validate and prepare every attack spec before running anything.
    total_words = _count_wordlist_entries(wordlist_path)
    if total_words is None:
        print(f"[Error] Wordlist file not found: {wordlist_path}")
        return
    if total_words == 0:
        print("[Error] Wordlist is empty.")
        return

    try:
        mask_groups = _parse_mask(mask)
        charset = _build_charset(charset_keys)
        max_length = int(max_length_arg)
    except (KeyError, ValueError) as error:
        print(f"[Error] {error}")
        return

    mask_total = 1
    for group in mask_groups:
        mask_total *= len(group)
    brute_total = sum(len(charset) ** length for length in range(1, max_length + 1))

    def dict_candidates() -> Iterator[str]:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if word:
                    yield word

    def rule_candidates() -> Iterator[str]:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if not word:
                    continue
                for _, rule in RULES:
                    yield rule(word)

    def mask_candidates() -> Iterator[str]:
        for combo in itertools.product(*mask_groups):
            yield "".join(combo)

    def brute_candidates() -> Iterator[str]:
        for length in range(1, max_length + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    # (name, total, candidates_factory, total_label, unit)
    specs: list[tuple[str, int, Callable[[], Iterator[str]], str, str]] = [
        ("Dictionary Attack", total_words, dict_candidates, "Wordlist", "words"),
        ("Rule-Based Attack", total_words * len(RULES), rule_candidates, "Wordlist x Rules", "candidates"),
        ("Mask Attack", mask_total, mask_candidates, "Keyspace", "combinations"),
        ("Brute Force Attack", brute_total, brute_candidates, "Keyspace", "combinations"),
    ]

    print("[i] Calibrating hash rate for this machine...")
    rate = calibrate_hash_rate(session.algorithm, session.salt, session.iterations)
    print(f"[i] Estimated speed: ~{rate:,.0f} hashes/s\n")

    print("Planned attacks:")
    for name, total, _, _, unit in specs:
        estimated = total / rate if rate > 0 else float("inf")
        print(f"  - {name:<20} {total:>12,} {unit:<12} ~{format_duration(estimated)}")

    overall_estimate = sum(total for _, total, _, _, _ in specs) / rate if rate > 0 else float("inf")
    print(f"\n[i] Combined estimated time: {format_duration(overall_estimate)}")

    try:
        answer = input("Run full benchmark now? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return
    if answer not in ("y", "yes"):
        print("[i] Benchmark cancelled.")
        return

    results: list[tuple[str, Optional[str], int, float]] = []
    for name, total, candidates_factory, total_label, unit in specs:
        attempts, elapsed, found = _execute_attack(session, target_hash, candidates_factory)
        print_benchmark_block(name, total, attempts, elapsed, total_label, unit)
        print(f"[+] Password found: {found}" if found else "[-] Password not found.")
        results.append((name, found, attempts, elapsed))

    _print_comparison_table(results)


def _print_comparison_table(results: list[tuple[str, Optional[str], int, float]]) -> None:
    """Print a side-by-side comparison of all attacks run during a benchmark."""
    header = f"{'Attack':<20}{'Found':<8}{'Attempts':>12}{'Time':>14}{'Rate (h/s)':>16}"
    print("=== Benchmark Comparison ===")
    print(header)
    print("-" * len(header))
    for name, found, attempts, elapsed in results:
        rate = attempts / elapsed if elapsed > 0 else float("inf")
        print(f"{name:<20}{'yes' if found else 'no':<8}{attempts:>12,}{format_duration(elapsed):>14}{rate:>16,.0f}")
    print()


# ---------------------------------------------------------------------------
# CLI commands - rainbow table
# ---------------------------------------------------------------------------

def cmd_rainbow(session: Session, args: list[str]) -> None:
    if not args:
        print("Usage: /rainbow build|crack|save|load ...  (see /help)")
        return

    subcommand, rest = args[0], args[1:]
    handlers = {
        "build": _rainbow_build,
        "crack": _rainbow_crack,
        "save": _rainbow_save,
        "load": _rainbow_load,
    }
    handler = handlers.get(subcommand)
    if handler is None:
        print(f"[Error] Unknown /rainbow subcommand: '{subcommand}'")
        return
    handler(session, rest)


def _rainbow_build(session: Session, args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: /rainbow build <charsets> <max_length>")
        return

    try:
        charset = _build_charset(args[0])
        max_length = int(args[1])
    except (KeyError, ValueError) as error:
        print(f"[Error] {error}")
        return

    total_candidates = sum(len(charset) ** length for length in range(1, max_length + 1))
    print(f"[i] Keyspace to precompute: {total_candidates:,} candidates")
    if session.hash_mode != "standard":
        print(f"[i] Hash mode: {session.hash_mode} (salt={session.salt}, iterations={session.iterations})")

    if not _confirm_run(session, total_candidates, prompt="Build the table now?"):
        print("[i] Build cancelled.")
        return

    start = time.perf_counter()
    table: dict[str, str] = {}
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            candidate = "".join(combo)
            table[compute_hash(candidate, session.algorithm, session.salt, session.iterations)] = candidate
    elapsed = time.perf_counter() - start

    session.rainbow_table = table
    session.rainbow_meta = {
        "algorithm": session.algorithm,
        "hash_mode": session.hash_mode,
        "salt": session.salt,
        "iterations": session.iterations,
    }
    print(f"[+] Table built: {len(table):,} unique hashes in {format_duration(elapsed)}")
    print("[i] Future /rainbow crack lookups against this table are instant (O(1)).")


def _rainbow_crack(session: Session, args: list[str]) -> None:
    if not args:
        print("Usage: /rainbow crack <hash>")
        return
    if session.rainbow_table is None:
        print("[Error] No rainbow table loaded. Use /rainbow build or /rainbow load first.")
        return

    target_hash = args[0].lower()
    start = time.perf_counter()
    candidate = session.rainbow_table.get(target_hash)
    elapsed = time.perf_counter() - start

    print_benchmark_block("Rainbow Table Lookup", len(session.rainbow_table), 1, elapsed, "Table size", "entries")
    print(f"[+] Password found: {candidate}" if candidate else "[-] Hash not present in table.")


def _rainbow_save(session: Session, args: list[str]) -> None:
    if not args:
        print("Usage: /rainbow save <file>")
        return
    if session.rainbow_table is None:
        print("[Error] No rainbow table to save.")
        return

    with open(args[0], "w", encoding="utf-8") as f:
        json.dump({"meta": session.rainbow_meta, "table": session.rainbow_table}, f)
    print(f"[+] Table saved to {args[0]} ({len(session.rainbow_table):,} entries)")


def _rainbow_load(session: Session, args: list[str]) -> None:
    if not args:
        print("Usage: /rainbow load <file>")
        return
    try:
        with open(args[0], "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[Error] File not found: {args[0]}")
        return

    session.rainbow_table = data["table"]
    session.rainbow_meta = data["meta"]
    print(f"[+] Table loaded: {len(session.rainbow_table):,} entries "
          f"(algorithm={session.rainbow_meta.get('algorithm')}, mode={session.rainbow_meta.get('hash_mode')})")


COMMANDS: dict[str, Callable[[Session, list[str]], None]] = {
    "/help": cmd_help,
    "/algo": cmd_algo,
    "/mode": cmd_mode,
    "/hash": cmd_hash,
    "/dict": cmd_dict,
    "/rule": cmd_rule,
    "/mask": cmd_mask,
    "/brute": cmd_brute,
    "/rainbow": cmd_rainbow,
    "/benchmark": cmd_benchmark,
}


# ---------------------------------------------------------------------------
# Main REPL loop
# ---------------------------------------------------------------------------

def main() -> None:
    session = Session()
    print("=== Hash Cracker CLI - type /help to get started ===")

    while True:
        try:
            raw_input_line = input(f"[{session.algorithm}|{session.hash_mode}] >> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not raw_input_line:
            continue

        tokens = shlex.split(raw_input_line)
        command, args = tokens[0], tokens[1:]

        if command == "/quit":
            print("Goodbye!")
            break
        elif command in COMMANDS:
            COMMANDS[command](session, args)
        else:
            print(f"Unknown command: {command} (type /help)")


if __name__ == "__main__":
    main()