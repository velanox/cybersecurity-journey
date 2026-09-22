"""
Execution engine — runs a strategy in a background thread, tracks progress,
and can be paused/resumed/stopped mid-run.

Two job types share the same control interface (pause/resume/stop/snapshot)
but run very differently internally:
  - Job: dictionary/brute-force — iterate candidates, hash, compare.
  - RainbowJob: build a rainbow table, then search it — a fundamentally
    different algorithm (works backward from the target hash), so it does
    not fit the "iterate and compare" loop Job uses.

No Flask — the Flask layer only ever talks to an Engine instance and gets
back plain dicts.
"""

import random
import threading
import time

from .algorithms import compute, compute_salted
from .candidates import estimate_total_bruteforce
from .models import JobStatus
from .rainbow_table import build_table, search as rainbow_search

# Hard cap: an estimate above this is reported as NOT feasible locally.
# Not an arbitrary length limit — this is measured on the actual machine
# via the benchmark, so it adapts: a fast server and a slow laptop get
# different verdicts for the same charset/length request.
DEFAULT_HARD_CAP_SECONDS = 24 * 3600  # 1 day


class _ControllableJob:
    """Shared pause/resume/stop plumbing for both job types."""

    def __init__(self, job_id):
        self.job_id = job_id
        self._lock = threading.Lock()
        self._pause_event = threading.Event()
        self._pause_event.set()  # set = NOT paused
        self._stop_event = threading.Event()

        self.status = JobStatus.IDLE
        self.error = None
        self.start_time = None
        self.end_time = None

    def pause(self):
        self._pause_event.clear()
        with self._lock:
            if self.status == JobStatus.RUNNING:
                self.status = JobStatus.PAUSED

    def resume(self):
        self._pause_event.set()
        with self._lock:
            if self.status == JobStatus.PAUSED:
                self.status = JobStatus.RUNNING

    def stop(self):
        self._stop_event.set()
        self._pause_event.set()  # unblock a paused thread so it can exit

    def _elapsed(self):
        now = self.end_time or time.perf_counter()
        return now - (self.start_time or now)


class Job(_ControllableJob):
    """One dictionary/brute-force cracking attempt."""

    def __init__(self, job_id, hash_value, algorithm, strategy, candidate_iterable,
                 total_estimate=None, salt=None, salt_order="suffix", estimated_seconds=None):
        super().__init__(job_id)
        self.hash_value = hash_value
        self.algorithm = algorithm
        self.strategy = strategy
        self.candidate_iterable = candidate_iterable
        self.total_estimate = total_estimate
        self.salt = salt
        self.salt_order = salt_order
        self.estimated_seconds = estimated_seconds
        self.candidates_tested = 0
        self.found_candidate = None

    def _digest(self, candidate: str) -> str:
        if self.salt:
            return compute_salted(self.algorithm, candidate, self.salt, self.salt_order)
        return compute(self.algorithm, candidate.encode("utf-8", errors="ignore"))

    def run(self):
        """Runs in a background thread. Never raises out of this method."""
        self.start_time = time.perf_counter()
        with self._lock:
            self.status = JobStatus.RUNNING

        try:
            for candidate in self.candidate_iterable:
                self._pause_event.wait()  # blocks here while paused

                if self._stop_event.is_set():
                    with self._lock:
                        self.status = JobStatus.STOPPED
                    return

                self.candidates_tested += 1

                if self._digest(candidate) == self.hash_value:
                    self.found_candidate = candidate
                    with self._lock:
                        self.status = JobStatus.COMPLETED
                    return

            with self._lock:
                self.status = JobStatus.NOT_FOUND

        except Exception as e:
            self.error = str(e)
            with self._lock:
                self.status = JobStatus.ERROR
        finally:
            self.end_time = time.perf_counter()

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = self._elapsed()
            speed = self.candidates_tested / elapsed if elapsed > 0 else 0.0
            progress = None
            if self.total_estimate:
                progress = min(100.0, round(self.candidates_tested / self.total_estimate * 100, 2))

            return {
                "job_id": self.job_id,
                "status": self.status.value,
                "algorithm": self.algorithm,
                "strategy": self.strategy,
                "phase": None,
                "candidates_tested": self.candidates_tested,
                "speed": round(speed, 1),
                "elapsed": round(elapsed, 3),
                "progress": progress,
                "estimated_seconds": self.estimated_seconds,
                "found_candidate": self.found_candidate,
                "error": self.error,
            }


class RainbowJob(_ControllableJob):
    """
    Builds a rainbow table, then searches it for the target hash.
    Two phases, reported via `phase`: "building" then "searching".
    `candidates_tested` here means total hash operations performed —
    the same unit of "work" as Job, so the two are comparable.
    """

    def __init__(self, job_id, hash_value, algorithm, charset, length,
                 table_size, chain_length, estimated_seconds=None, seed=None):
        super().__init__(job_id)
        self.hash_value = hash_value
        self.algorithm = algorithm
        self.strategy = "rainbow"
        self.charset = charset
        self.length = length
        self.table_size = table_size
        self.chain_length = chain_length
        self.estimated_seconds = estimated_seconds
        self.seed = seed

        self.phase = "building"
        self.candidates_tested = 0
        self.found_candidate = None
        # upper-bound total, used only for a progress percentage
        self._total_estimate = table_size * chain_length + chain_length * chain_length

    def run(self):
        self.start_time = time.perf_counter()
        with self._lock:
            self.status = JobStatus.RUNNING

        try:
            rng = random.Random(self.seed) if self.seed is not None else random.Random()

            def on_build_progress(done, total):
                with self._lock:
                    self.candidates_tested = done * self.chain_length

            table = build_table(
                self.algorithm, self.charset, self.length, self.table_size, self.chain_length,
                rng, stop_event=self._stop_event, pause_event=self._pause_event,
                on_progress=on_build_progress,
            )

            if self._stop_event.is_set():
                with self._lock:
                    self.status = JobStatus.STOPPED
                return

            with self._lock:
                self.phase = "searching"

            def on_search_progress(done, total, hash_ops):
                with self._lock:
                    self.candidates_tested = self.table_size * self.chain_length + hash_ops

            result = rainbow_search(
                self.hash_value, self.algorithm, self.charset, self.length, table, self.chain_length,
                stop_event=self._stop_event, pause_event=self._pause_event,
                on_progress=on_search_progress,
            )

            if result.get("stopped"):
                with self._lock:
                    self.status = JobStatus.STOPPED
                return

            with self._lock:
                if result["found"]:
                    self.found_candidate = result["candidate"]
                    self.status = JobStatus.COMPLETED
                else:
                    self.status = JobStatus.NOT_FOUND

        except Exception as e:
            self.error = str(e)
            with self._lock:
                self.status = JobStatus.ERROR
        finally:
            self.end_time = time.perf_counter()

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = self._elapsed()
            speed = self.candidates_tested / elapsed if elapsed > 0 else 0.0
            progress = min(100.0, round(self.candidates_tested / self._total_estimate * 100, 2)) \
                if self._total_estimate else None

            return {
                "job_id": self.job_id,
                "status": self.status.value,
                "algorithm": self.algorithm,
                "strategy": self.strategy,
                "phase": self.phase,
                "candidates_tested": self.candidates_tested,
                "speed": round(speed, 1),
                "elapsed": round(elapsed, 3),
                "progress": progress,
                "estimated_seconds": self.estimated_seconds,
                "found_candidate": self.found_candidate,
                "error": self.error,
            }


class Engine:
    """In-memory registry of jobs — fine for a local single-user tool."""

    def __init__(self):
        self._jobs = {}
        self._counter = 0
        self._lock = threading.Lock()

    def _new_job_id(self) -> str:
        with self._lock:
            self._counter += 1
            return f"job-{self._counter}"

    def benchmark(self, algorithm: str, sample_size: int = 20000) -> float:
        """
        Invisible mini speed-test: hashes `sample_size` throwaway values
        with this algorithm on THIS machine, returns candidates/sec.
        """
        start = time.perf_counter()
        for i in range(sample_size):
            compute(algorithm, str(i).encode())
        elapsed = time.perf_counter() - start
        return sample_size / elapsed if elapsed > 0 else 0.0

    def estimate(self, algorithm: str, charset_size: int, min_len: int, max_len: int,
                 sample_size: int = 20000, hard_cap_seconds: float = DEFAULT_HARD_CAP_SECONDS) -> dict:
        """
        Compute a feasibility estimate WITHOUT starting a job. Meant to be
        called before showing a "Start" button, so the user sees a real
        number (and a real yes/no on feasibility) rather than guessing.
        """
        total = estimate_total_bruteforce(charset_size, min_len, max_len)
        speed = self.benchmark(algorithm, sample_size)
        estimated_seconds = (total / speed) if speed > 0 else None
        feasible = estimated_seconds is not None and estimated_seconds <= hard_cap_seconds

        return {
            "total_candidates": total,
            "speed": round(speed, 1),
            "estimated_seconds": round(estimated_seconds, 2) if estimated_seconds is not None else None,
            "feasible": feasible,
            "hard_cap_seconds": hard_cap_seconds,
        }

    def estimate_from_total(self, algorithm: str, total_ops: int, sample_size: int = 20000,
                             hard_cap_seconds: float = DEFAULT_HARD_CAP_SECONDS) -> dict:
        """
        Same feasibility check as estimate(), but for callers (rainbow)
        that already know their total operation count instead of deriving
        it from a charset/length range.
        """
        speed = self.benchmark(algorithm, sample_size)
        estimated_seconds = (total_ops / speed) if speed > 0 else None
        feasible = estimated_seconds is not None and estimated_seconds <= hard_cap_seconds

        return {
            "total_candidates": total_ops,
            "speed": round(speed, 1),
            "estimated_seconds": round(estimated_seconds, 2) if estimated_seconds is not None else None,
            "feasible": feasible,
            "hard_cap_seconds": hard_cap_seconds,
        }

    def start_job(self, hash_value, algorithm, strategy_name, candidate_iterable,
                  total_estimate=None, salt=None, salt_order="suffix", estimated_seconds=None):
        if total_estimate and estimated_seconds is None:
            speed = self.benchmark(algorithm)
            if speed > 0:
                estimated_seconds = round(total_estimate / speed, 2)

        job_id = self._new_job_id()
        job = Job(job_id, hash_value, algorithm, strategy_name, candidate_iterable,
                  total_estimate=total_estimate, salt=salt, salt_order=salt_order,
                  estimated_seconds=estimated_seconds)
        self._jobs[job_id] = job
        threading.Thread(target=job.run, daemon=True).start()
        return job

    def start_rainbow_job(self, hash_value, algorithm, charset, length,
                           table_size, chain_length, estimated_seconds=None, seed=None):
        job_id = self._new_job_id()
        job = RainbowJob(job_id, hash_value, algorithm, charset, length, table_size, chain_length,
                          estimated_seconds=estimated_seconds, seed=seed)
        self._jobs[job_id] = job
        threading.Thread(target=job.run, daemon=True).start()
        return job

    def get(self, job_id):
        return self._jobs.get(job_id)


engine = Engine()