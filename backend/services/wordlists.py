"""
Loading of local word lists and text normalization helpers.

All lists are read from local files in data/ - nothing is downloaded and no
password is ever sent anywhere.
"""

import re
import unicodedata
from functools import lru_cache
from pathlib import Path

from backend.config import Config

MIN_WORD_LENGTH = 4

# One-to-one "leetspeak" substitutions. Because every mapping replaces exactly
# one character with one character, match positions stay aligned with the
# original password.
LEET_MAP = str.maketrans({
    "@": "a", "4": "a",
    "3": "e",
    "1": "i", "!": "i",
    "0": "o",
    "$": "s", "5": "s",
    "7": "t", "+": "t",
    "8": "b",
})
# Alternative reading of "1" as "l" (e.g. "he11o").
LEET_MAP_L = str.maketrans({"1": "l", "|": "l"})


def normalize(text: str) -> str:
    """Unicode-normalize (NFKC) and lowercase text for comparisons."""
    return unicodedata.normalize("NFKC", text).lower()


_TRAILING_DIGITS_SYMBOLS = re.compile(r"[\d\W_]*$")


def leet_variants(text: str) -> list[str]:
    """
    Return the lowercase text plus its de-leeted variants (all the same length).

    The last variant de-leets everything except a trailing run of digits and
    symbols, so "p@ssw0rd1" becomes "password1" rather than "passwordi".
    """
    lowered = text.lower()
    tail = _TRAILING_DIGITS_SYMBOLS.search(lowered)
    head_end = tail.start() if tail and tail.start() > 0 else len(lowered)
    variants = [
        lowered,
        lowered.translate(LEET_MAP),
        lowered.translate(LEET_MAP_L).translate(LEET_MAP),
        lowered[:head_end].translate(LEET_MAP) + lowered[head_end:],
    ]
    # Preserve order, remove duplicates.
    return list(dict.fromkeys(variants))


@lru_cache(maxsize=None)
def load_list(path: str) -> frozenset:
    """Read a word list file: one entry per line, '#' comments ignored."""
    entries = set()
    file_path = Path(path)
    if not file_path.exists():
        return frozenset()
    with file_path.open(encoding="utf-8") as handle:
        for line in handle:
            entry = line.strip().lower()
            if entry and not entry.startswith("#"):
                entries.add(entry)
    return frozenset(entries)


def common_passwords() -> frozenset:
    return load_list(str(Config.COMMON_PASSWORDS_FILE))


@lru_cache(maxsize=None)
def dictionary_words() -> frozenset:
    """
    Words used for dictionary detection: the common-word list, the alphabetic
    common passwords, and the passphrase word list (so generated passphrases
    are honestly recognised as combinations of dictionary words).
    """
    words = set(load_list(str(Config.COMMON_WORDS_FILE)))
    words |= {w for w in common_passwords() if w.isalpha()}
    words |= load_list(str(Config.PASSPHRASE_WORDLIST))
    return frozenset(w for w in words if len(w) >= MIN_WORD_LENGTH and w.isalpha())


def passphrase_wordlist() -> list[str]:
    """Sorted list of passphrase generator words (sorted for determinism)."""
    return sorted(w for w in load_list(str(Config.PASSPHRASE_WORDLIST)) if w.isalpha())
