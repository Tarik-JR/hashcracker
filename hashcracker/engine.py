"""The cracking engine: hash candidates in parallel and stop on the first match.

This module is deliberately ignorant of *where* candidates come from -- it just
consumes an iterator of strings (see :mod:`hashcracker.candidates`). That single
abstraction is what lets dictionary and brute-force modes share all of this
code.

The three ideas that make it fast and correct
----------------------------------------------

1. **Processes, not threads.** Hashing is CPU-bound Python work, and CPython's
   Global Interpreter Lock (GIL) prevents threads from executing Python
   bytecode on more than one core at a time. ``multiprocessing`` sidesteps the
   GIL by running a separate interpreter per core.

2. **Batching beats the IPC tax.** Every task handed to a worker must be
   pickled and pushed through a pipe. If we sent one candidate at a time, that
   overhead would dwarf the cost of a single hash. So we group candidates into
   batches (default 10,000) and send one batch per message. Each worker hashes
   the whole batch locally and returns a tiny summary.

3. **Prompt, correct shutdown.** We use ``imap_unordered`` so results stream
   back as soon as any worker finishes a batch, and we break on the first hit.
   A shared ``Event`` lets the finding worker signal its siblings to stop
   immediately, and the ``Pool`` context manager terminates the rest.

A note on ``spawn`` vs ``fork``
-------------------------------
On macOS (and Windows) the default start method is **spawn**: each worker is a
brand-new Python process that *re-imports* this module rather than inheriting
the parent's memory. Two consequences:

* Worker functions must be importable top-level functions (they are).
* A plain ``multiprocessing.Event`` can't be pickled across the spawn boundary,
  so we create the event from a ``Manager`` instead -- a ``Manager`` event is a
  picklable proxy that works under both start methods. We only touch it once
  per batch, so the small proxy overhead is irrelevant.
"""

from __future__ import annotations

import hashlib
import itertools
import multiprocessing as mp
import os
import time
from collections.abc import Iterable, Iterator

# ---------------------------------------------------------------------------
# Worker-side state.
#
# Under spawn, each worker process runs ``_init_worker`` once (via the Pool's
# ``initializer``) and stashes the target + algorithm in module-level globals.
# That way we don't re-send the target with every batch; it's set up once per
# worker and read for free thereafter.
# ---------------------------------------------------------------------------
_TARGET_BYTES: bytes = b""      # the digest we're hunting, as raw bytes
_ALGO: str = ""                 # e.g. "sha256"
_FOUND = None                   # a shared Event: set once any worker matches


def _init_worker(target_hex: str, algo: str, found_event) -> None:
    """Pool initializer: runs once in every worker process."""
    global _TARGET_BYTES, _ALGO, _FOUND
    # Compare raw digest bytes rather than hex strings: it skips a hex-encode
    # per candidate in the hot loop. Convert the target to bytes just once here.
    _TARGET_BYTES = bytes.fromhex(target_hex)
    _ALGO = algo
    _FOUND = found_event


def _check_batch(batch: list[str]) -> tuple[str | None, int]:
    """Hash every candidate in ``batch``; return (match_or_None, num_tried).

    Runs inside a worker process. Returning just the match and a count keeps the
    message sent back to the parent tiny, regardless of batch size.
    """
    # If another worker already won, bail out cheaply. We check once per batch
    # (not per candidate) to keep the inner loop tight; a batch is milliseconds
    # of work, so the worst-case wasted effort after a match is negligible.
    if _FOUND is not None and _FOUND.is_set():
        return None, 0

    tried = 0
    for candidate in batch:
        tried += 1
        h = hashlib.new(_ALGO)
        h.update(candidate.encode("utf-8", "surrogateescape"))
        if h.digest() == _TARGET_BYTES:
            if _FOUND is not None:
                _FOUND.set()  # tell the other workers to stop
            return candidate, tried
    return None, tried


def _batched(iterable: Iterable[str], size: int) -> Iterator[list[str]]:
    """Yield successive lists of up to ``size`` items from ``iterable``.

    (Python 3.12+ ships ``itertools.batched``, but we spell it out so the
    behaviour is obvious and the tool runs on older versions too.)
    """
    iterator = iter(iterable)
    while batch := list(itertools.islice(iterator, size)):
        yield batch


def crack(
    candidates: Iterable[str],
    target_hex: str,
    algo: str,
    *,
    workers: int | None = None,
    batch_size: int = 10_000,
    reporter=None,
) -> str | None:
    """Search ``candidates`` for one whose ``algo`` digest equals ``target_hex``.

    Returns the matching candidate string, or ``None`` if the stream is
    exhausted without a match. ``reporter``, if given, is called with
    ``(tried, elapsed)`` as progress is made and ``finish(...)`` at the end.
    """
    if workers is None:
        workers = os.cpu_count() or 1
    target_hex = target_hex.lower()
    start = time.perf_counter()
    tried = 0

    # --- Single-process path -------------------------------------------------
    # For workers <= 1 we skip multiprocessing entirely. It's simpler, easier to
    # debug, has no start-up cost, and is what the tests use for determinism.
    if workers <= 1:
        target_bytes = bytes.fromhex(target_hex)
        for batch in _batched(candidates, batch_size):
            for candidate in batch:
                tried += 1
                h = hashlib.new(algo)
                h.update(candidate.encode("utf-8", "surrogateescape"))
                if h.digest() == target_bytes:
                    if reporter:
                        reporter.finish(candidate, tried, time.perf_counter() - start)
                    return candidate
            if reporter:
                reporter.update(tried, time.perf_counter() - start)
        if reporter:
            reporter.finish(None, tried, time.perf_counter() - start)
        return None

    # --- Parallel path -------------------------------------------------------
    # ``Manager().Event()`` gives us a shared, picklable stop-flag that works
    # under the spawn start method used on macOS/Windows (see module docstring).
    with mp.Manager() as manager:
        found_event = manager.Event()
        pool = mp.Pool(
            processes=workers,
            initializer=_init_worker,
            initargs=(target_hex, algo, found_event),
        )
        result: str | None = None
        try:
            batches = _batched(candidates, batch_size)
            # imap_unordered streams results back as batches complete, in
            # whatever order they finish -- ideal for "stop as soon as anyone
            # finds it". The pool pulls batches from our lazy generator on
            # demand, so memory stays bounded to a few in-flight batches.
            for match, count in pool.imap_unordered(_check_batch, batches):
                tried += count
                if reporter:
                    reporter.update(tried, time.perf_counter() - start)
                if match is not None:
                    result = match
                    break
        finally:
            # terminate() stops workers immediately (we already have our answer
            # or the user hit Ctrl-C); join() reaps them cleanly.
            pool.terminate()
            pool.join()

        if reporter:
            reporter.finish(result, tried, time.perf_counter() - start)
        return result
