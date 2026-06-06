"""Candidate generators -- the *source* of guesses for an attack.

The key abstraction of this whole project lives here: both attack modes are
just **iterators of candidate strings**. The cracking engine doesn't care
whether a candidate came from a file or from a combinatorial generator; it
just hashes each one and compares. That symmetry is what keeps the engine
tiny and lets both modes share progress reporting, batching, and
parallelism for free.

Two things to notice:

* We yield candidates **lazily** (generators, not lists). A brute-force space
  of, say, ``95 ** 8`` strings is far too large to hold in memory -- but it's
  fine to stream one batch at a time. The same laziness lets us start cracking
  a huge wordlist immediately instead of reading it all first.

* Wordlists are opened with ``errors="surrogateescape"``. Real-world wordlists
  (rockyou.txt and friends) contain bytes that aren't valid UTF-8. Rather than
  crash or silently drop those lines, ``surrogateescape`` smuggles the raw
  bytes into the string so that ``.encode("utf-8", "surrogateescape")`` in the
  hashing step reproduces the *exact original bytes*. That correctness matters:
  the password we're looking for might be one of those lines.
"""

from __future__ import annotations

import itertools
import os
import string
from collections.abc import Iterator

from .hashing import HashCrackerError

# Named character sets so the user can type ``--charset digits`` instead of
# spelling out every character. ``printable`` deliberately omits whitespace,
# which is rarely part of a brute-forced password and only inflates the space.
CHARSET_PRESETS: dict[str, str] = {
    "digits": string.digits,                              # 0-9
    "lower": string.ascii_lowercase,                      # a-z
    "upper": string.ascii_uppercase,                      # A-Z
    "alpha": string.ascii_letters,                        # a-zA-Z
    "alnum": string.ascii_letters + string.digits,        # a-zA-Z0-9
    "printable": string.ascii_letters + string.digits + string.punctuation,
}


# --- Dictionary mode -----------------------------------------------------------

def dictionary_candidates(path: str) -> Iterator[str]:
    """Yield one candidate per line of the wordlist at ``path``.

    Blank lines are skipped. Only the trailing newline is stripped -- we keep
    any other whitespace, because a password legitimately could contain it.
    """
    if not os.path.isfile(path):
        raise HashCrackerError(f"wordlist not found: {path}")
    try:
        # Stream line by line; never load the whole file into memory.
        with open(path, "r", encoding="utf-8", errors="surrogateescape") as fh:
            for line in fh:
                word = line.rstrip("\r\n")
                if word:
                    yield word
    except OSError as exc:  # permission denied, is-a-directory, etc.
        raise HashCrackerError(f"could not read wordlist {path!r}: {exc}") from exc


def count_lines(path: str) -> int | None:
    """Best-effort count of non-empty lines, used to show a % / ETA.

    We read the file in binary chunks (fast) and count newlines. If anything
    goes wrong we return ``None`` and the progress display simply omits the
    percentage rather than failing the run. For an enormous wordlist you might
    skip this pre-pass entirely (``--no-count``) to start cracking instantly.
    """
    try:
        total = 0
        with open(path, "rb") as fh:
            while chunk := fh.read(1024 * 1024):
                total += chunk.count(b"\n")
        return total
    except OSError:
        return None


# --- Brute-force mode ----------------------------------------------------------

def resolve_charset(spec: str) -> str:
    """Turn a ``--charset`` value into an actual character set.

    If ``spec`` names a preset (e.g. ``"alnum"``) we expand it; otherwise we
    treat it as a literal set of characters (e.g. ``"abc123"``). Duplicate
    characters are removed while preserving order, because a repeated character
    would make ``itertools.product`` emit the same candidate twice.
    """
    chars = CHARSET_PRESETS.get(spec, spec)
    # dict.fromkeys de-duplicates while keeping first-seen order.
    deduped = "".join(dict.fromkeys(chars))
    if not deduped:
        raise HashCrackerError("charset is empty")
    return deduped


def bruteforce_candidates(charset: str, min_len: int, max_len: int) -> Iterator[str]:
    """Yield every string over ``charset`` from ``min_len`` to ``max_len`` chars.

    ``itertools.product(charset, repeat=length)`` is the workhorse: it produces
    the Cartesian product of the charset with itself ``length`` times -- i.e.
    every possible string of exactly that length -- as tuples of characters,
    which we join back into strings. We loop lengths shortest-first so that
    likely-shorter passwords are tried before longer ones.

    Because ``product`` is itself a lazy generator, this streams: at no point do
    we materialise the (possibly astronomical) full list.
    """
    if min_len < 1:
        raise HashCrackerError("min length must be >= 1")
    if max_len < min_len:
        raise HashCrackerError("max length must be >= min length")
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield "".join(combo)


def bruteforce_total(charset: str, min_len: int, max_len: int) -> int:
    """Exact size of the brute-force space, for the progress bar's %/ETA.

    Unlike a wordlist, the brute-force space size is a closed-form sum:
    ``sum(len(charset) ** L for L in [min_len .. max_len])``. Knowing it up
    front lets us show a real percentage and ETA (and warn when a run is
    hopelessly large).
    """
    n = len(charset)
    return sum(n ** length for length in range(min_len, max_len + 1))
