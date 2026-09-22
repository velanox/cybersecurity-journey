"""
Data structures shared across the hash cracker module.
No Flask, no I/O — just typed containers/reference shapes for what
analyzer.analyze() and Job.snapshot() return as plain dicts. Keeping this
as a typed reference (rather than instantiating these classes at runtime)
keeps the hot paths (engine.py) free of dataclass overhead while still
documenting the exact shape callers can rely on.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, List


class JobStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    NOT_FOUND = "not_found"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class AnalysisResult:
    """Shape of analyzer.analyze()'s return value."""
    input: str
    length: int
    charset_used: List[str]
    is_hex: bool
    format: str
    prefix: Optional[str]
    structured: bool
    salt_format: Optional[str]
    possible_algorithms: List[str]
    crackable_locally: bool


@dataclass
class JobSnapshot:
    """Shape of Job.snapshot() / RainbowJob.snapshot()'s return value."""
    job_id: str
    status: str
    algorithm: str
    strategy: str
    phase: Optional[str] = None
    candidates_tested: int = 0
    speed: float = 0.0
    elapsed: float = 0.0
    progress: Optional[float] = None
    estimated_seconds: Optional[float] = None
    found_candidate: Optional[str] = None
    error: Optional[str] = None
