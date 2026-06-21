#!/usr/bin/env python3
"""Generate test hashes so you have something safe to crack.

This is the companion to the cracker: give it a known plaintext and it prints
the digest, which you can then feed back into ``hashcracker``. Because *you*
chose the plaintext, you always know the right answer -- perfect for learning
and for checking the tool actually works.

Examples
--------
    # single value, default MD5
    python scripts/make_hashes.py "password"

    # pick the algorithm
    python scripts/make_hashes.py "letmein" --algo sha256

    # hash several values at once, showing the plaintext next to each digest
    python scripts/make_hashes.py hunter2 dragon 123456 --algo sha1 --show

    # hash every line of a file (e.g. to build a batch of CTF-style targets)
    python scripts/make_hashes.py --from-file examples/wordlist.txt -a sha256
"""

from __future__ import annotations

import argparse
import hashlib
import sys


def digest(text: str, algo: str) -> str:
    """Return the hex digest of ``text`` under ``algo`` (mirrors the cracker)."""
    h = hashlib.new(algo)
    h.update(text.encode("utf-8", "surrogateescape"))
    return h.hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate MD5/SHA-1/SHA-256 hashes for test plaintexts.",
    )
    parser.add_argument("text", nargs="*", help="plaintext value(s) to hash")
    parser.add_argument(
        "-a", "--algo",
        choices=("md5", "sha1", "sha256"),
        default="md5",
        help="hash algorithm (default: md5)",
    )
    parser.add_argument(
        "--from-file",
        help="read plaintexts from this file, one per line",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="print 'plaintext -> hash' instead of just the hash",
    )
    args = parser.parse_args(argv)

    values = list(args.text)
    if args.from_file:
        try:
            with open(args.from_file, "r", encoding="utf-8",
                      errors="surrogateescape") as fh:
                values.extend(line.rstrip("\r\n") for line in fh if line.strip())
        except OSError as exc:
            print(f"error: could not read {args.from_file!r}: {exc}", file=sys.stderr)
            return 2

    if not values:
        parser.error("give at least one plaintext, or use --from-file")

    for text in values:
        h = digest(text, args.algo)
        print(f"{text} -> {h}" if args.show else h)
    return 0


if __name__ == "__main__":
    sys.exit(main())
