"""Tests for algorithm support, auto-detection, and validation."""

import hashlib

import pytest

from hashcracker.hashing import (
    HashCrackerError,
    detect_algorithm,
    hash_string,
    resolve_algorithm,
    validate_target,
)

# Known-answer values so the tests double as documentation.
MD5_PASSWORD = "5f4dcc3b5aa765d61d8327deb882cf99"      # md5("password")
SHA1_PASSWORD = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
SHA256_PASSWORD = (
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
)


def test_hash_string_matches_hashlib():
    for algo in ("md5", "sha1", "sha256"):
        expected = hashlib.new(algo, b"password").hexdigest()
        assert hash_string("password", algo) == expected


@pytest.mark.parametrize(
    "digest, expected",
    [
        (MD5_PASSWORD, "md5"),
        (SHA1_PASSWORD, "sha1"),
        (SHA256_PASSWORD, "sha256"),
    ],
)
def test_detect_algorithm_by_length(digest, expected):
    assert detect_algorithm(digest) == expected


def test_detect_handles_whitespace_and_case():
    assert detect_algorithm("  " + MD5_PASSWORD.upper() + "\n") == "md5"


def test_detect_rejects_unknown_length():
    with pytest.raises(HashCrackerError):
        detect_algorithm("abc123")  # 6 chars: not a digest length we know


def test_detect_rejects_non_hex():
    with pytest.raises(HashCrackerError):
        detect_algorithm("z" * 32)  # right length, but 'z' isn't hex


def test_resolve_prefers_explicit_algo():
    assert resolve_algorithm(SHA256_PASSWORD, "sha256") == "sha256"


def test_resolve_auto_falls_back_to_detection():
    assert resolve_algorithm(MD5_PASSWORD, "auto") == "md5"


def test_validate_rejects_length_mismatch():
    # A 32-char MD5 digest validated as sha256 should be rejected.
    with pytest.raises(HashCrackerError):
        validate_target(MD5_PASSWORD, "sha256")


def test_validate_returns_normalised_hash():
    assert validate_target("  " + MD5_PASSWORD.upper(), "md5") == MD5_PASSWORD
