"""hashcracker -- an educational MD5/SHA-1/SHA-256 hash cracker.

Public surface is intentionally small; the CLI in :mod:`hashcracker.cli` is the
main entry point, but the pieces are importable for experimentation and tests.
"""

from .engine import crack
from .hashing import (
    SUPPORTED,
    HashCrackerError,
    detect_algorithm,
    hash_string,
    resolve_algorithm,
    validate_target,
)

__version__ = "1.0.0"

__all__ = [
    "crack",
    "SUPPORTED",
    "HashCrackerError",
    "detect_algorithm",
    "hash_string",
    "resolve_algorithm",
    "validate_target",
    "__version__",
]
