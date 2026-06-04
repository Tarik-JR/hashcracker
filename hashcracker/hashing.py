"""Hash algorithm support: construction, auto-detection, and validation.

This module is the single source of truth for "which algorithms do we
support and how do we recognise them". Keeping it separate from the CLI and
the cracking engine means the rest of the code never has to hard-code an
algorithm name or a digest length.

Design decisions
----------------
* We drive everything through ``hashlib.new(name)`` rather than calling
  ``hashlib.md5()`` / ``hashlib.sha1()`` directly. ``hashlib.new`` takes the
  algorithm *name as a string*, which is exactly what the user gives us on the
  command line. That turns "support a new algorithm" into "add a string to a
  dict" instead of writing a new branch.
* Auto-detection is based purely on the *hex length* of the digest. This is a
  useful heuristic but it is genuinely ambiguous (see ``detect_algorithm``),
  so the user can always override it with ``--algo``.
"""

from __future__ import annotations

import hashlib
import string


class HashCrackerError(Exception):
    """Base class for every user-facing error in this project.

    The CLI catches this one type and turns it into a clean message + a
    non-zero exit code, instead of dumping a traceback at the user.
    """


# --- The algorithms we support -------------------------------------------------
#
# Maps our public name -> the number of hexadecimal characters a digest has.
# A digest of N bits prints as N/4 hex characters:
#     MD5    = 128 bits -> 32 hex chars
#     SHA-1  = 160 bits -> 40 hex chars
#     SHA-256= 256 bits -> 64 hex chars
#
# The names are exactly what ``hashlib.new`` expects, so we can pass them
# straight through without translation.
DIGEST_HEX_LEN: dict[str, int] = {
    "md5": 32,
    "sha1": 40,
    "sha256": 64,
}

SUPPORTED = tuple(DIGEST_HEX_LEN)  # ("md5", "sha1", "sha256")

# Reverse lookup for auto-detection: hex length -> algorithm name.
_LEN_TO_ALGO: dict[int, str] = {length: name for name, length in DIGEST_HEX_LEN.items()}

_HEX_DIGITS = set(string.hexdigits)  # "0123456789abcdefABCDEF"


def normalise_hash(target: str) -> str:
    """Strip surrounding whitespace and lower-case a hex digest.

    Hashes are case-insensitive hex, so we canonicalise to lower-case once,
    up front, and never worry about case again.
    """
    return target.strip().lower()


def is_hex(target: str) -> bool:
    """Return True if every character is a hexadecimal digit (and non-empty)."""
    return bool(target) and all(c in _HEX_DIGITS for c in target)


def detect_algorithm(target: str) -> str:
    """Guess the algorithm from the digest's hex length.

    Returns one of ``SUPPORTED``. Raises :class:`HashCrackerError` if the
    length doesn't match anything we know.

    IMPORTANT (and a good thing to understand): length-based detection is a
    *heuristic*, not proof. Many algorithms share a digest size -- e.g. a
    64-char hex string could be SHA-256, SHA3-256, BLAKE2s, RIPEMD-256, and
    more. Within the three algorithms this tool supports the mapping is
    unambiguous, but in the real world you often need the *context* of where a
    hash came from. That's exactly why ``--algo`` exists as an override.
    """
    target = normalise_hash(target)
    if not is_hex(target):
        raise HashCrackerError(
            f"target hash contains non-hex characters: {target!r}"
        )
    try:
        return _LEN_TO_ALGO[len(target)]
    except KeyError:
        raise HashCrackerError(
            f"cannot auto-detect algorithm from a {len(target)}-character hash; "
            f"expected one of {sorted(_LEN_TO_ALGO)} hex chars. "
            f"Specify the algorithm explicitly with --algo."
        ) from None


def resolve_algorithm(target: str, algo: str | None) -> str:
    """Return the algorithm to use, given the user's ``--algo`` choice.

    ``algo`` is either an explicit name, or ``None`` / ``"auto"`` meaning
    "figure it out from the hash length".
    """
    if algo in (None, "auto"):
        return detect_algorithm(target)
    algo = algo.lower()
    if algo not in DIGEST_HEX_LEN:
        raise HashCrackerError(
            f"unsupported algorithm {algo!r}; choose from {list(SUPPORTED)}"
        )
    return algo


def validate_target(target: str, algo: str) -> str:
    """Check that ``target`` is a well-formed digest for ``algo``.

    Returns the normalised (stripped, lower-cased) hash so the caller can use
    the cleaned-up value. Raises :class:`HashCrackerError` on any mismatch --
    catching a typo here saves the user from a run that could never match.
    """
    target = normalise_hash(target)
    if not is_hex(target):
        raise HashCrackerError(f"target hash is not valid hex: {target!r}")
    expected = DIGEST_HEX_LEN[algo]
    if len(target) != expected:
        raise HashCrackerError(
            f"{algo} digests are {expected} hex chars, but this hash is "
            f"{len(target)}. Wrong --algo, or a malformed hash?"
        )
    return target


def hash_string(text: str, algo: str) -> str:
    """Hash ``text`` with ``algo`` and return the hex digest.

    Kept simple and readable for tests and the single-process path. The hot
    parallel path in :mod:`hashcracker.engine` compares raw digest *bytes*
    instead (skipping hex encoding per candidate), but the logic is identical.

    We encode with ``surrogateescape`` so that odd bytes coming from a wordlist
    (which may not be valid UTF-8) round-trip losslessly back to their original
    bytes instead of crashing. See :mod:`hashcracker.candidates`.
    """
    h = hashlib.new(algo)
    h.update(text.encode("utf-8", "surrogateescape"))
    return h.hexdigest()
