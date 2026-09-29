"""Tests for the separate educational hashing demo (synthetic password only)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demos"))

import hashing_demo  # noqa: E402


def test_hash_is_salted_and_one_way():
    first = hashing_demo.hash_password(hashing_demo.DEMO_PASSWORD)
    second = hashing_demo.hash_password(hashing_demo.DEMO_PASSWORD)
    assert first != second                       # random salt
    assert hashing_demo.DEMO_PASSWORD not in first
    assert first.startswith("$argon2id$")


def test_verify_password():
    stored = hashing_demo.hash_password(hashing_demo.DEMO_PASSWORD)
    assert hashing_demo.verify_password(stored, hashing_demo.DEMO_PASSWORD)
    assert not hashing_demo.verify_password(stored, "demo-only-wrong-guess")
