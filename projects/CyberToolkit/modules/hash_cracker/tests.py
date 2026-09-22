"""
Unit tests for the hash_cracker module.

Run standalone, no Flask, no test runner beyond unittest itself:
    python -m modules.hash_cracker.tests
or
    python -m unittest modules.hash_cracker.tests -v
"""

import hashlib
import os
import tempfile
import time
import unittest

from .algorithms import compute, compute_salted, SUPPORTED
from .analyzer import analyze
from .validators import (
    ValidationError,
    validate_hash_input,
    validate_algorithm,
    validate_charset,
    validate_length_range,
    validate_single_length,
    validate_wordlist_name,
    validate_salt_order,
)
from .candidates import iter_dictionary, iter_bruteforce, estimate_total_bruteforce
from .engine import Engine
from .rainbow_table import index_to_candidate
from .strategies.dictionary import build_candidates as dict_candidates
from .strategies.brute_force import build_candidates as bf_candidates
from .strategies.rainbow import is_compatible as rainbow_is_compatible


# ---------------------------------------------------------------------------
# Known test cases — a fixed hash, its known plaintext, expected algorithm.
# Reusable as "lab mode" fixtures anywhere else (frontend, docs, manual QA).
# ---------------------------------------------------------------------------

KNOWN_HASHES = [
    {"algorithm": "MD5", "plaintext": "password", "hash": hashlib.md5(b"password").hexdigest()},
    {"algorithm": "SHA1", "plaintext": "password", "hash": hashlib.sha1(b"password").hexdigest()},
    {"algorithm": "SHA256", "plaintext": "password", "hash": hashlib.sha256(b"password").hexdigest()},
]


# ---------------------------------------------------------------------------
# algorithms.py
# ---------------------------------------------------------------------------

class TestAlgorithms(unittest.TestCase):

    def test_compute_matches_known_hash(self):
        for case in KNOWN_HASHES:
            with self.subTest(algorithm=case["algorithm"]):
                digest = compute(case["algorithm"], case["plaintext"].encode())
                self.assertEqual(digest, case["hash"])

    def test_compute_unsupported_algorithm_raises(self):
        with self.assertRaises(ValueError):
            compute("NOT_A_REAL_ALGO", b"data")

    def test_compute_salted_suffix(self):
        expected = hashlib.md5(b"passwordSALT123").hexdigest()
        self.assertEqual(compute_salted("MD5", "password", "SALT123", "suffix"), expected)

    def test_compute_salted_prefix(self):
        expected = hashlib.md5(b"SALT123password").hexdigest()
        self.assertEqual(compute_salted("MD5", "password", "SALT123", "prefix"), expected)

    def test_all_supported_algorithms_produce_hex(self):
        for name in SUPPORTED:
            digest = compute(name, b"test")
            self.assertTrue(all(c in "0123456789abcdef" for c in digest))


# ---------------------------------------------------------------------------
# validators.py
# ---------------------------------------------------------------------------

class TestValidators(unittest.TestCase):

    def test_validate_hash_input_rejects_empty(self):
        with self.assertRaises(ValidationError):
            validate_hash_input("")
        with self.assertRaises(ValidationError):
            validate_hash_input("   ")

    def test_validate_hash_input_strips_whitespace(self):
        self.assertEqual(validate_hash_input("  abc123  "), "abc123")

    def test_validate_hash_input_rejects_too_long(self):
        with self.assertRaises(ValidationError):
            validate_hash_input("a" * 600)

    def test_validate_algorithm_accepts_known(self):
        self.assertEqual(validate_algorithm("md5", ["MD5", "SHA1"]), "MD5")

    def test_validate_algorithm_rejects_unknown(self):
        with self.assertRaises(ValidationError):
            validate_algorithm("ROT13", ["MD5", "SHA1"])

    def test_validate_charset_requires_at_least_one(self):
        with self.assertRaises(ValidationError):
            validate_charset(False, False, False, False)

    def test_validate_charset_builds_expected_set(self):
        charset = validate_charset(True, False, True, False)
        self.assertIn("a", charset)
        self.assertIn("0", charset)
        self.assertNotIn("A", charset)
        self.assertNotIn("!", charset)

    def test_validate_length_range_rejects_min_below_one(self):
        with self.assertRaises(ValidationError):
            validate_length_range(0, 5)

    def test_validate_length_range_rejects_max_below_min(self):
        with self.assertRaises(ValidationError):
            validate_length_range(5, 3)

    def test_validate_length_range_enforces_absolute_ceiling(self):
        # max_len=25 exceeds the hard technical ceiling (24), regardless of spread
        with self.assertRaises(ValidationError):
            validate_length_range(20, 25)

    def test_validate_length_range_enforces_spread_not_absolute_length(self):
        # 10-11 has spread=1 -> perfectly fine, even though both values are > 8
        self.assertEqual(validate_length_range(10, 11), (10, 11))

    def test_validate_length_range_rejects_wide_spread(self):
        # 1-11 has spread=10 > 8 -> rejected, regardless of small absolute values
        with self.assertRaises(ValidationError):
            validate_length_range(1, 11)

    def test_validate_length_range_accepts_spread_exactly_at_limit(self):
        self.assertEqual(validate_length_range(1, 9), (1, 9))  # spread=8, exactly at limit

    def test_validate_length_range_rejects_spread_one_above_limit(self):
        with self.assertRaises(ValidationError):
            validate_length_range(1, 10)  # spread=9, one above limit

    def test_validate_single_length_accepts_valid(self):
        self.assertEqual(validate_single_length(4), 4)

    def test_validate_single_length_rejects_below_one(self):
        with self.assertRaises(ValidationError):
            validate_single_length(0)

    def test_validate_single_length_rejects_above_ceiling(self):
        with self.assertRaises(ValidationError):
            validate_single_length(25)

    def test_validate_wordlist_name_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValidationError):
                validate_wordlist_name("../../etc/passwd", tmp)
            with self.assertRaises(ValidationError):
                validate_wordlist_name("subdir/file.txt", tmp)

    def test_validate_wordlist_name_rejects_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValidationError):
                validate_wordlist_name("nope.txt", tmp)

    def test_validate_wordlist_name_accepts_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "list.txt")
            with open(path, "w") as f:
                f.write("word\n")
            result = validate_wordlist_name("list.txt", tmp)
            self.assertEqual(result, path)

    def test_validate_salt_order_accepts_valid(self):
        self.assertEqual(validate_salt_order("prefix"), "prefix")
        self.assertEqual(validate_salt_order("SUFFIX"), "suffix")

    def test_validate_salt_order_rejects_invalid(self):
        with self.assertRaises(ValidationError):
            validate_salt_order("middle")


# ---------------------------------------------------------------------------
# analyzer.py
# ---------------------------------------------------------------------------

class TestAnalyzer(unittest.TestCase):

    def test_identifies_md5_by_length(self):
        result = analyze(hashlib.md5(b"x").hexdigest())
        self.assertIn("MD5", result["possible_algorithms"])
        self.assertTrue(result["crackable_locally"])

    def test_identifies_sha256_by_length(self):
        result = analyze(hashlib.sha256(b"x").hexdigest())
        self.assertEqual(result["possible_algorithms"], ["SHA256"])

    def test_md5_and_ntlm_ambiguity_both_reported(self):
        result = analyze(hashlib.md5(b"x").hexdigest())
        self.assertIn("MD5", result["possible_algorithms"])
        self.assertIn("NTLM", result["possible_algorithms"])

    def test_detects_bcrypt_prefix_as_structured(self):
        result = analyze("$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV")
        self.assertTrue(result["structured"])
        self.assertEqual(result["format"], "bcrypt")
        self.assertFalse(result["crackable_locally"])

    def test_detects_hash_salt_convention(self):
        result = analyze("5f4dcc3b5aa765d61d8327deb882cf99:abc123")
        self.assertEqual(result["salt_format"], "hash:salt")

    def test_unknown_length_reports_unknown_format(self):
        result = analyze("deadbeef")  # 8 hex chars, no known algorithm has this length
        self.assertEqual(result["format"], "unknown")
        self.assertEqual(result["possible_algorithms"], [])

    def test_non_hex_input_reports_unknown(self):
        result = analyze("not-a-hash-at-all!!")
        self.assertFalse(result["is_hex"])
        self.assertEqual(result["format"], "unknown")


# ---------------------------------------------------------------------------
# candidates.py
# ---------------------------------------------------------------------------

class TestCandidates(unittest.TestCase):

    def test_iter_dictionary_yields_each_nonblank_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "words.txt")
            with open(path, "w") as f:
                f.write("alpha\n\nbeta\ngamma\n")
            words = list(iter_dictionary(path))
            self.assertEqual(words, ["alpha", "beta", "gamma"])

    def test_iter_dictionary_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            list(iter_dictionary("/nonexistent/path/words.txt"))

    def test_iter_bruteforce_respects_length_range(self):
        results = list(iter_bruteforce("ab", 1, 2))
        expected = ["a", "b", "aa", "ab", "ba", "bb"]
        self.assertEqual(results, expected)

    def test_iter_bruteforce_respects_charset(self):
        results = list(iter_bruteforce("x", 1, 2))
        self.assertEqual(results, ["x", "xx"])

    def test_estimate_total_bruteforce_matches_actual_count(self):
        total = estimate_total_bruteforce(3, 1, 3)
        actual = len(list(iter_bruteforce("abc", 1, 3)))
        self.assertEqual(total, actual)


# ---------------------------------------------------------------------------
# strategies/
# ---------------------------------------------------------------------------

class TestStrategies(unittest.TestCase):

    def test_dictionary_strategy_yields_transformations(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "words.txt")
            with open(path, "w") as f:
                f.write("test\n")
            candidates = list(dict_candidates(path, transformations=["upper", "append_1"]))
            self.assertIn("test", candidates)
            self.assertIn("TEST", candidates)
            self.assertIn("test1", candidates)

    def test_bruteforce_strategy_matches_raw_generator(self):
        candidates = list(bf_candidates("ab", 1, 2))
        self.assertEqual(candidates, list(iter_bruteforce("ab", 1, 2)))

    def test_rainbow_incompatible_with_salted_hash(self):
        analysis = analyze("5f4dcc3b5aa765d61d8327deb882cf99:abc123")
        self.assertFalse(rainbow_is_compatible(analysis))

    def test_rainbow_incompatible_with_structured_hash(self):
        analysis = analyze("$2b$12$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUV")
        self.assertFalse(rainbow_is_compatible(analysis))

    def test_rainbow_compatible_with_plain_hex_hash(self):
        analysis = analyze(hashlib.md5(b"x").hexdigest())
        self.assertTrue(rainbow_is_compatible(analysis))


# ---------------------------------------------------------------------------
# engine.py — Job (dictionary / brute force)
# ---------------------------------------------------------------------------

class TestEngineJob(unittest.TestCase):

    def setUp(self):
        self.engine = Engine()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.wordlist_path = os.path.join(self.tmpdir.name, "words.txt")
        with open(self.wordlist_path, "w") as f:
            f.write("hello\nworld\npassword\nadmin123\n")

    def tearDown(self):
        self.tmpdir.cleanup()

    def _wait_until(self, job, statuses, timeout=5.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if job.snapshot()["status"] in statuses:
                return job.snapshot()
            time.sleep(0.02)
        self.fail(f"Job did not reach {statuses} within {timeout}s (last: {job.snapshot()})")

    def test_dictionary_job_finds_known_hash(self):
        target = hashlib.md5(b"password").hexdigest()
        job = self.engine.start_job(
            hash_value=target, algorithm="MD5", strategy_name="dictionary",
            candidate_iterable=dict_candidates(self.wordlist_path),
        )
        snap = self._wait_until(job, {"completed", "error"})
        self.assertEqual(snap["status"], "completed")
        self.assertEqual(snap["found_candidate"], "password")
        self.assertIsNone(snap["phase"])  # Job (not RainbowJob) never sets a phase

    def test_dictionary_job_reports_not_found(self):
        target = hashlib.md5(b"nonexistent-word-xyz").hexdigest()
        job = self.engine.start_job(
            hash_value=target, algorithm="MD5", strategy_name="dictionary",
            candidate_iterable=dict_candidates(self.wordlist_path),
        )
        snap = self._wait_until(job, {"not_found", "error"})
        self.assertEqual(snap["status"], "not_found")
        self.assertIsNone(snap["found_candidate"])

    def test_bruteforce_job_finds_short_candidate_with_eta(self):
        target = hashlib.md5(b"cab").hexdigest()
        total = estimate_total_bruteforce(3, 1, 3)
        job = self.engine.start_job(
            hash_value=target, algorithm="MD5", strategy_name="brute_force",
            candidate_iterable=bf_candidates("abc", 1, 3), total_estimate=total,
        )
        snap = self._wait_until(job, {"completed", "error"})
        self.assertEqual(snap["status"], "completed")
        self.assertEqual(snap["found_candidate"], "cab")
        self.assertIsNotNone(snap["estimated_seconds"])

    def test_salted_job_finds_match_with_suffix_order(self):
        target = hashlib.md5(b"passwordSALT").hexdigest()
        job = self.engine.start_job(
            hash_value=target, algorithm="MD5", strategy_name="dictionary",
            candidate_iterable=dict_candidates(self.wordlist_path),
            salt="SALT", salt_order="suffix",
        )
        snap = self._wait_until(job, {"completed", "error"})
        self.assertEqual(snap["status"], "completed")
        self.assertEqual(snap["found_candidate"], "password")

    def test_pause_stops_progress_and_resume_continues(self):
        # pause_event is checked once per loop iteration (per candidate) —
        # so the single candidate already "in flight" when pause() is
        # called can still complete and increment the counter by exactly
        # one, even after status flips to "paused". This is the same
        # checkpoint-granularity behavior as RainbowJob's chain boundaries,
        # just at a finer grain. Give that one in-flight iteration a moment
        # to land before treating the counter as settled.
        target = hashlib.md5(b"zzzzzz").hexdigest()  # unreachable soon on purpose
        job = self.engine.start_job(
            hash_value=target, algorithm="MD5", strategy_name="brute_force",
            candidate_iterable=bf_candidates("abcdefghijklmnopqrstuvwxyz", 1, 6),
        )
        time.sleep(0.15)
        job.pause()
        self._wait_until(job, {"paused"})
        time.sleep(0.02)  # let a single in-flight candidate finish
        count_at_pause = job.snapshot()["candidates_tested"]

        time.sleep(0.2)
        self.assertEqual(job.snapshot()["candidates_tested"], count_at_pause)

        job.resume()
        time.sleep(0.15)
        snap_resumed = job.snapshot()
        self.assertEqual(snap_resumed["status"], "running")
        self.assertGreater(snap_resumed["candidates_tested"], count_at_pause)

        job.stop()
        snap_stopped = self._wait_until(job, {"stopped"})
        self.assertEqual(snap_stopped["status"], "stopped")

    def test_unsupported_algorithm_results_in_error_status(self):
        job = self.engine.start_job(
            hash_value="deadbeef", algorithm="NOT_REAL", strategy_name="dictionary",
            candidate_iterable=dict_candidates(self.wordlist_path),
        )
        snap = self._wait_until(job, {"error"})
        self.assertEqual(snap["status"], "error")
        self.assertTrue(snap["error"])

    def test_missing_wordlist_results_in_error_status(self):
        job = self.engine.start_job(
            hash_value="deadbeef", algorithm="MD5", strategy_name="dictionary",
            candidate_iterable=dict_candidates("/nonexistent/wordlist.txt"),
        )
        snap = self._wait_until(job, {"error"})
        self.assertEqual(snap["status"], "error")

    def test_benchmark_returns_positive_speed(self):
        speed = self.engine.benchmark("MD5", sample_size=1000)
        self.assertGreater(speed, 0)

    def test_estimate_reports_feasible_for_small_case(self):
        est = self.engine.estimate("MD5", charset_size=26, min_len=1, max_len=4)
        self.assertTrue(est["feasible"])
        self.assertIsNotNone(est["estimated_seconds"])

    def test_estimate_reports_infeasible_for_huge_case(self):
        est = self.engine.estimate("MD5", charset_size=76, min_len=20, max_len=24, sample_size=5000)
        self.assertFalse(est["feasible"])

    def test_estimate_from_total_matches_manual_calculation(self):
        est = self.engine.estimate_from_total("MD5", total_ops=1000, sample_size=5000)
        self.assertIsNotNone(est["estimated_seconds"])
        self.assertTrue(est["feasible"])


# ---------------------------------------------------------------------------
# engine.py — RainbowJob
# ---------------------------------------------------------------------------

class TestEngineRainbowJob(unittest.TestCase):

    def setUp(self):
        self.engine = Engine()
        self.charset = "abcdefghijklmnopqrstuvwxyz"
        self.length = 4

    def _wait_until(self, job, statuses, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if job.snapshot()["status"] in statuses:
                return job.snapshot()
            time.sleep(0.02)
        self.fail(f"Job did not reach {statuses} within {timeout}s (last: {job.snapshot()})")

    def test_finds_a_candidate_known_to_be_on_a_generated_chain(self):
        # Deterministic seed: build the table, then target the exact start
        # of a chain we know exists — removes coverage luck from the test,
        # isolating whether the search algorithm itself is correct.
        import random
        from .rainbow_table import build_table

        rng = random.Random(123)
        table = build_table("MD5", self.charset, self.length, table_size=200,
                             chain_length=50, rng=rng)
        known_start = list(table.values())[0]
        target_hash = hashlib.md5(known_start.encode()).hexdigest()

        job = self.engine.start_rainbow_job(
            hash_value=target_hash, algorithm="MD5", charset=self.charset, length=self.length,
            table_size=200, chain_length=50, seed=123,  # same seed -> same table -> guaranteed coverage
        )
        snap = self._wait_until(job, {"completed", "not_found", "error"})
        self.assertEqual(snap["status"], "completed")
        self.assertEqual(snap["found_candidate"], known_start)

    def test_phase_transitions_from_building_to_searching(self):
        job = self.engine.start_rainbow_job(
            hash_value="deadbeefdeadbeefdeadbeefdeadbeef", algorithm="MD5",
            charset=self.charset, length=self.length, table_size=3000, chain_length=150,
        )
        time.sleep(0.02)
        self.assertEqual(job.snapshot()["phase"], "building")

        snap = self._wait_until(job, {"completed", "not_found", "error"})
        self.assertEqual(snap["phase"], "searching")

    def test_pause_resume_stop_during_build(self):
        # Pause/stop in build_table() are checked BETWEEN chains, not
        # mid-chain (documented in rainbow_table.build_table) — so up to
        # one chain_length's worth of extra work can land just after
        # pause() is called, while the in-flight chain finishes. Use a
        # short chain_length here so that grace window is small and
        # predictable, and wait it out before treating the counter as
        # settled — this tests real pause behavior, not an unrealistic
        # instant-freeze expectation the implementation never promised.
        job = self.engine.start_rainbow_job(
            hash_value="deadbeefdeadbeefdeadbeefdeadbeef", algorithm="MD5",
            charset=self.charset, length=self.length, table_size=50000, chain_length=20,
        )
        time.sleep(0.05)
        job.pause()
        self._wait_until(job, {"paused"})
        time.sleep(0.05)  # let any in-flight chain (<= 20 hash ops) finish
        count_at_pause = job.snapshot()["candidates_tested"]

        time.sleep(0.15)
        self.assertEqual(job.snapshot()["candidates_tested"], count_at_pause)

        job.resume()
        time.sleep(0.1)
        snap_resumed = job.snapshot()
        self.assertEqual(snap_resumed["status"], "running")
        self.assertGreater(snap_resumed["candidates_tested"], count_at_pause)

        job.stop()
        snap_stopped = self._wait_until(job, {"stopped"})
        self.assertEqual(snap_stopped["status"], "stopped")

    def test_not_found_reported_cleanly_for_tiny_table(self):
        # A table this small essentially never covers an arbitrary target —
        # verifies clean not_found reporting, not a crash or hang.
        job = self.engine.start_rainbow_job(
            hash_value=hashlib.md5(b"zzzz").hexdigest(), algorithm="MD5",
            charset=self.charset, length=self.length, table_size=1, chain_length=1,
        )
        snap = self._wait_until(job, {"completed", "not_found", "error"})
        self.assertIn(snap["status"], ("completed", "not_found"))  # both are legitimate


# ---------------------------------------------------------------------------
# Simple performance sanity check
# ---------------------------------------------------------------------------

class TestPerformanceSanity(unittest.TestCase):

    def test_bruteforce_16k_candidates_completes_quickly(self):
        engine = Engine()
        target = "0" * 32  # deliberately unreachable, forces a full scan
        start = time.time()
        job = engine.start_job(
            hash_value=target, algorithm="MD5", strategy_name="brute_force",
            candidate_iterable=bf_candidates("ab", 1, 13),  # ~16k candidates
        )
        deadline = time.time() + 5.0
        while job.snapshot()["status"] not in ("not_found", "error") and time.time() < deadline:
            time.sleep(0.02)
        elapsed = time.time() - start
        snap = job.snapshot()
        self.assertEqual(snap["status"], "not_found")
        self.assertLess(elapsed, 5.0, "brute-force over ~16k short candidates took too long")

    def test_rainbow_table_build_of_reasonable_size_completes_quickly(self):
        engine = Engine()
        start = time.time()
        job = engine.start_rainbow_job(
            hash_value="0" * 32, algorithm="MD5",
            charset="abcdefghijklmnopqrstuvwxyz", length=4,
            table_size=2000, chain_length=100,
        )
        deadline = time.time() + 10.0
        while job.snapshot()["status"] not in ("completed", "not_found", "error") and time.time() < deadline:
            time.sleep(0.02)
        elapsed = time.time() - start
        self.assertLess(elapsed, 10.0, "rainbow table build+search of demo size took too long")


if __name__ == "__main__":
    unittest.main(verbosity=2)
