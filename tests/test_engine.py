"""Tests for candidate generation and the cracking engine.

Most tests pin ``workers=1`` so they run in the single-process path: fast, no
process-spawn overhead, and fully deterministic. One test exercises the real
multiprocessing path to make sure the parallel plumbing works end to end.
"""

import hashlib

from hashcracker.candidates import (
    bruteforce_candidates,
    bruteforce_total,
    dictionary_candidates,
    resolve_charset,
)
from hashcracker.engine import crack
from hashcracker.hashing import hash_string


def _md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


# --- candidate generators ------------------------------------------------------

def test_bruteforce_total_is_closed_form():
    # charset of 2, lengths 1..3 -> 2 + 4 + 8 = 14
    assert bruteforce_total("ab", 1, 3) == 14


def test_bruteforce_generates_expected_strings():
    got = list(bruteforce_candidates("ab", 1, 2))
    assert got == ["a", "b", "aa", "ab", "ba", "bb"]


def test_resolve_charset_expands_presets_and_dedupes():
    assert resolve_charset("digits") == "0123456789"
    assert resolve_charset("aabbc") == "abc"  # duplicates removed, order kept


def test_dictionary_reads_lines(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("alpha\n\nbeta\n")  # blank line should be skipped
    assert list(dictionary_candidates(str(wl))) == ["alpha", "beta"]


# --- the engine ----------------------------------------------------------------

def test_crack_dictionary_finds_word(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("foo\nbar\nletmein\nbaz\n")
    target = _md5("letmein")
    assert crack(dictionary_candidates(str(wl)), target, "md5", workers=1) == "letmein"


def test_crack_returns_none_when_absent(tmp_path):
    wl = tmp_path / "words.txt"
    wl.write_text("foo\nbar\n")
    target = _md5("not-in-list")
    assert crack(dictionary_candidates(str(wl)), target, "md5", workers=1) is None


def test_crack_bruteforce_finds_short_string():
    target = hash_string("zz", "sha256")
    result = crack(bruteforce_candidates("xyz", 1, 2), target, "sha256", workers=1)
    assert result == "zz"


def test_crack_parallel_path_finds_word():
    # Exercise the real multiprocessing pool (workers=2) on a small brute space.
    target = _md5("cab")
    result = crack(
        bruteforce_candidates("abc", 1, 3), target, "md5",
        workers=2, batch_size=4,
    )
    assert result == "cab"
