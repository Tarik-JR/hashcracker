"""Command-line front-end: parse arguments, validate, dispatch, report.

This is the only module that talks to the user, so it owns all of the
"be friendly about mistakes" behaviour:

* Every expected failure (missing file, bad algorithm, malformed hash, empty
  charset, ...) is raised as :class:`HashCrackerError` deep in the code and
  caught *here*, turned into a one-line ``error: ...`` message and a non-zero
  exit code. The user never sees a raw traceback for an ordinary mistake.
* Exit codes follow convention so the tool scripts nicely:
    0  -> password found
    1  -> exhausted the search space, no match
    2  -> usage / input error (bad file, bad algo, ...)
    130-> interrupted with Ctrl-C
"""

from __future__ import annotations

import argparse
import sys

from . import candidates as cand
from .engine import crack
from .hashing import (
    SUPPORTED,
    HashCrackerError,
    resolve_algorithm,
    validate_target,
)
from .reporter import Reporter

# Above this many brute-force candidates we print a friendly "this is huge"
# warning. 1e10 hashes is minutes-to-hours even when parallelised.
_HUGE_SPACE = 10_000_000_000


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser (kept separate so tests can reuse it)."""
    parser = argparse.ArgumentParser(
        prog="hashcracker",
        description=(
            "Educational hash cracker for MD5 / SHA-1 / SHA-256. "
            "Use ONLY on hashes you generated yourself or that come from "
            "CTF challenges / systems you are authorised to test."
        ),
        epilog=(
            "examples:\n"
            "  # dictionary attack, algorithm auto-detected from length\n"
            "  hashcracker 5f4dcc3b5aa765d61d8327deb882cf99 -w examples/wordlist.txt\n\n"
            "  # brute-force all 1-4 char lowercase strings, force SHA-256\n"
            "  hashcracker <hash> -m brute --charset lower --max-length 4 -a sha256\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("hash", help="the target hash (hex digest) to crack")
    parser.add_argument(
        "-m", "--mode",
        choices=("dictionary", "brute"),
        default="dictionary",
        help="attack mode (default: dictionary)",
    )
    parser.add_argument(
        "-a", "--algo",
        choices=("auto", *SUPPORTED),
        default="auto",
        help="hash algorithm; 'auto' detects it from the hash length "
             "(default: auto)",
    )

    # Dictionary-mode options.
    dict_group = parser.add_argument_group("dictionary mode")
    dict_group.add_argument(
        "-w", "--wordlist",
        help="path to a newline-separated wordlist file",
    )
    dict_group.add_argument(
        "--no-count",
        action="store_true",
        help="skip the line-counting pre-pass (start faster, no %% / ETA)",
    )

    # Brute-force-mode options.
    bf_group = parser.add_argument_group("brute-force mode")
    bf_group.add_argument(
        "--charset",
        default="alnum",
        help="characters to combine: a preset name "
             f"({', '.join(cand.CHARSET_PRESETS)}) or a literal string like "
             "'abc123' (default: alnum)",
    )
    bf_group.add_argument(
        "--min-length", type=int, default=1,
        help="minimum candidate length (default: 1)",
    )
    bf_group.add_argument(
        "--max-length", type=int, default=4,
        help="maximum candidate length (default: 4)",
    )

    # Execution / output options.
    exec_group = parser.add_argument_group("execution")
    exec_group.add_argument(
        "-j", "--workers", type=int, default=None,
        help="number of worker processes (default: all CPU cores; 1 disables "
             "multiprocessing)",
    )
    exec_group.add_argument(
        "--batch-size", type=int, default=10_000,
        help="candidates hashed per task sent to a worker (default: 10000)",
    )
    exec_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="suppress the live progress line",
    )
    return parser


def _build_attack(args) -> tuple:
    """Return ``(candidate_iterator, total_or_None)`` for the chosen mode.

    Centralising this keeps :func:`run` readable and means each mode's
    validation lives right next to the generator it configures.
    """
    if args.mode == "dictionary":
        if not args.wordlist:
            raise HashCrackerError(
                "dictionary mode needs a wordlist: pass -w/--wordlist PATH"
            )
        total = None if args.no_count else cand.count_lines(args.wordlist)
        return cand.dictionary_candidates(args.wordlist), total

    # brute-force
    charset = cand.resolve_charset(args.charset)
    total = cand.bruteforce_total(charset, args.min_length, args.max_length)
    if total > _HUGE_SPACE:
        # Not fatal -- the user may well mean it -- but they should know.
        print(
            f"warning: brute-force space is {total:,} candidates; "
            f"this could take a very long time. Consider a smaller charset "
            f"or --max-length.",
            file=sys.stderr,
        )
    generator = cand.bruteforce_candidates(charset, args.min_length, args.max_length)
    return generator, total


def run(argv=None) -> int:
    """Parse ``argv``, run the attack, and return a process exit code."""
    args = build_parser().parse_args(argv)

    # Resolve + validate the algorithm and hash *before* doing any work, so a
    # typo fails instantly instead of after a pointless run.
    algo = resolve_algorithm(args.hash, args.algo)
    target = validate_target(args.hash, algo)

    generator, total = _build_attack(args)
    reporter = Reporter(total=total, enabled=not args.quiet)

    if not args.quiet:
        print(f"[*] target : {target}", file=sys.stderr)
        print(f"[*] algo   : {algo} (auto-detected)"
              if args.algo == "auto" else f"[*] algo   : {algo}", file=sys.stderr)
        print(f"[*] mode   : {args.mode}", file=sys.stderr)

    result = crack(
        generator, target, algo,
        workers=args.workers,
        batch_size=args.batch_size,
        reporter=reporter,
    )

    if result is not None:
        # Human-readable summary on stderr; the bare password on stdout so it
        # can be captured cleanly in a pipeline.
        print(f"[+] password found: {result!r}", file=sys.stderr)
        print(result)
        return 0

    print("[-] not found (search space exhausted)", file=sys.stderr)
    return 1


def main(argv=None) -> int:
    """Entry point used by the console script and ``python -m hashcracker``.

    Wraps :func:`run` with the top-level error handling so that ordinary
    mistakes and Ctrl-C produce clean messages, not tracebacks.
    """
    try:
        return run(argv)
    except HashCrackerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
