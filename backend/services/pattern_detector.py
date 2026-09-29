"""
Pattern detection.

Humans rarely choose characters at random. They type sequences (1234, abcd),
walk across the keyboard (qwerty, asdf), repeat things (aaaa, abcabc), append
years (2026) and build "Word + number + symbol" layouts to satisfy composition
rules. Guessing tools try exactly these patterns first, so each one found
reduces the *effective* strength of a password.

Every detector returns a list of match dicts with positions/lengths only.
The matched characters are never included, so results can be shown safely.
"""

import re

from backend.services.wordlists import dictionary_words, common_passwords, leet_variants

# --------------------------------------------------------------------------
# Sequences: 1234, 9876, abcd, dcba
# --------------------------------------------------------------------------

def _sequence_class(char: str) -> str | None:
    if "0" <= char <= "9":
        return "numeric"
    if "a" <= char <= "z":
        return "alphabetic"
    return None


def detect_sequences(password: str, min_length: int = 3) -> list[dict]:
    """
    Detect ascending or descending runs of consecutive digits or letters.

    Examples: "1234" (ascending numeric), "9876" (descending numeric),
    "abcd" (ascending alphabetic), "dcba" (descending alphabetic).
    """
    s = password.lower()
    matches = []
    n = len(s)
    i = 0
    while i < n - 1:
        kind = _sequence_class(s[i])
        delta = ord(s[i + 1]) - ord(s[i])
        if kind and _sequence_class(s[i + 1]) == kind and delta in (1, -1):
            j = i + 1
            while (j + 1 < n and _sequence_class(s[j + 1]) == kind
                   and ord(s[j + 1]) - ord(s[j]) == delta):
                j += 1
            length = j - i + 1
            if length >= min_length:
                matches.append({
                    "type": "sequence",
                    "start": i,
                    "end": j + 1,
                    "length": length,
                    "kind": kind,
                    "direction": "ascending" if delta == 1 else "descending",
                })
            i = j  # the last char may start a run in the other direction
        else:
            i += 1
    return matches


# --------------------------------------------------------------------------
# Keyboard walks: qwerty, asdf, zxcv, 1qaz ...
# --------------------------------------------------------------------------

KEYBOARD_SEQUENCES = (
    # US QWERTY rows
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
    # Shifted number row
    "~!@#$%^&*()_+",
    # Common column / diagonal walks
    "1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",
    "qazwsxedcrfvtgbyhnujmikolp",
    "zaq1xsw2cde3vfr4bgt5",
    "qweasdzxc",
    # Other common layouts
    "qwertzuiop",
    "yxcvbnm",
    "azertyuiop",
    "wxcvbn",
    # Numeric keypad walks
    "789456123",
    "147258369",
)
KEYBOARD_MIN_LENGTH = 4


def _build_keyboard_fragments(min_length: int) -> frozenset:
    fragments = set()
    for seq in KEYBOARD_SEQUENCES:
        for text in (seq, seq[::-1]):
            for i in range(len(text)):
                for j in range(i + min_length, len(text) + 1):
                    fragments.add(text[i:j])
    return frozenset(fragments)


_KEYBOARD_FRAGMENTS = _build_keyboard_fragments(KEYBOARD_MIN_LENGTH)
_MAX_KEYBOARD_FRAGMENT = max(len(s) for s in KEYBOARD_SEQUENCES)


def _is_numeric_run(fragment: str) -> bool:
    """True for digit runs like '1234' / '4321' (already reported as sequences)."""
    if not fragment.isdigit():
        return False
    steps = {ord(b) - ord(a) for a, b in zip(fragment, fragment[1:])}
    return steps in ({1}, {-1})


def detect_keyboard_patterns(password: str, min_length: int = KEYBOARD_MIN_LENGTH) -> list[dict]:
    """
    Detect keyboard walks such as "qwerty", "asdf", "zxcv", "1qaz" or keypad
    walks such as "7894".

    Straight digit runs (e.g. "1234") are left to detect_sequences() so the
    same weakness is not reported twice.
    """
    s = password.lower()
    matches = []
    n = len(s)
    i = 0
    while i < n:
        found = None
        for j in range(min(n, i + _MAX_KEYBOARD_FRAGMENT), i + min_length - 1, -1):
            fragment = s[i:j]
            if fragment in _KEYBOARD_FRAGMENTS and not _is_numeric_run(fragment):
                found = j
                break
        if found:
            matches.append({"type": "keyboard_pattern", "start": i, "end": found,
                            "length": found - i})
            i = found
        else:
            i += 1
    return matches


# --------------------------------------------------------------------------
# Repetition: aaaa, 1111, ababab, abcabcabc
# --------------------------------------------------------------------------

_REPEAT_RE = re.compile(r"(.+?)\1+", re.DOTALL)


def detect_repetition(password: str) -> list[dict]:
    """
    Detect repeated characters ("aaaa", "1111") and repeated substrings
    ("ababab", "abcabcabc"). Case-insensitive.

    - A single character must repeat at least 3 times in a row.
    - A multi-character unit must appear at least twice in a row and cover
      at least 4 characters.
    """
    s = password.lower()
    matches = []
    for m in _REPEAT_RE.finditer(s):
        unit_length = len(m.group(1))
        total = m.end() - m.start()
        repeat_count = total // unit_length
        if unit_length == 1 and repeat_count >= 3:
            kind = "repeated_characters"
        elif unit_length > 1 and total >= 4:
            kind = "repeated_substring"
        else:
            continue
        matches.append({
            "type": "repetition",
            "kind": kind,
            "start": m.start(),
            "end": m.end(),
            "length": total,
            "unit_length": unit_length,
            "repeat_count": repeat_count,
        })
    return matches


def repetition_coverage(password: str, matches: list[dict]) -> float:
    """Fraction of the password covered by repeated segments (0.0 - 1.0)."""
    if not password:
        return 0.0
    covered = set()
    for m in matches:
        covered.update(range(m["start"], m["end"]))
    return len(covered) / len(password)


# --------------------------------------------------------------------------
# Years and dates: 1998, 2026, 12/05/2001, 20010512
# --------------------------------------------------------------------------

_YEAR_RE = re.compile(r"(?<!\d)(19\d{2}|20\d{2})(?!\d)")
_SEPARATED_DATE_RE = re.compile(r"(?<!\d)\d{1,2}[-/.]\d{1,2}[-/.](?:\d{4}|\d{2})(?!\d)")
_DIGIT_RUN_RE = re.compile(r"\d{6,8}")


def _valid_day_month(day: int, month: int) -> bool:
    return 1 <= day <= 31 and 1 <= month <= 12


def _looks_like_compact_date(digits: str) -> bool:
    if len(digits) == 8:
        y1, m1, d1 = int(digits[:4]), int(digits[4:6]), int(digits[6:])
        if 1900 <= y1 <= 2099 and _valid_day_month(d1, m1):
            return True  # yyyymmdd
        a, b, y2 = int(digits[:2]), int(digits[2:4]), int(digits[4:])
        return 1900 <= y2 <= 2099 and (_valid_day_month(a, b) or _valid_day_month(b, a))
    if len(digits) == 6:
        a, b = int(digits[:2]), int(digits[2:4])
        return _valid_day_month(a, b) or _valid_day_month(b, a)  # ddmmyy / mmddyy
    return False


def detect_dates(password: str) -> list[dict]:
    """Detect year-like numbers (1900-2099) and date-like digit groups."""
    matches = []
    covered = set()
    for m in _SEPARATED_DATE_RE.finditer(password):
        matches.append({"type": "date", "kind": "date", "start": m.start(), "end": m.end(),
                        "length": m.end() - m.start()})
        covered.update(range(m.start(), m.end()))
    for m in _DIGIT_RUN_RE.finditer(password):
        if m.end() - m.start() in (6, 8) and _looks_like_compact_date(m.group()):
            if not covered.intersection(range(m.start(), m.end())):
                matches.append({"type": "date", "kind": "date", "start": m.start(),
                                "end": m.end(), "length": m.end() - m.start()})
                covered.update(range(m.start(), m.end()))
    for m in _YEAR_RE.finditer(password):
        if not covered.intersection(range(m.start(), m.end())):
            matches.append({"type": "date", "kind": "year", "start": m.start(), "end": m.end(),
                            "length": 4})
    return sorted(matches, key=lambda item: item["start"])


# --------------------------------------------------------------------------
# Predictable structure: welcome123, admin2026, Password123!, Summer2024!
# --------------------------------------------------------------------------

# letters, then digits and/or symbols (in either order) at the end
_WORD_SUFFIX_RE = re.compile(r"^([^\W\d_]+)([\d\W_]+)$")
# Capitalized word + digits + optional symbols: the classic "policy-compliant" layout
_POLICY_LAYOUT_RE = re.compile(r"^[A-Z][a-z]+[\W_]?\d{1,4}[\W_]{0,2}$")


def detect_predictable_structure(password: str) -> list[dict]:
    """
    Detect "common word + predictable suffix" structures.

    Adding a number or symbol to a common word (welcome123, admin2026,
    hello1234) does not create a strong password: guessing tools apply these
    exact "mangling rules" to every word in their dictionaries.
    """
    matches = []
    m = _WORD_SUFFIX_RE.match(password)
    if m:
        word = m.group(1)
        suffix = m.group(2)
        known = dictionary_words() | common_passwords()
        if any(variant in known for variant in leet_variants(word)):
            suffix_digits = re.sub(r"\D", "", suffix)
            if _YEAR_RE.search(suffix_digits or ""):
                suffix_kind = "year"
            elif suffix_digits:
                suffix_kind = "digits"
            else:
                suffix_kind = "symbols"
            matches.append({
                "type": "predictable_structure",
                "kind": "common_word_with_suffix",
                "start": 0,
                "end": len(password),
                "length": len(password),
                "word_length": len(word),
                "suffix_kind": suffix_kind,
                "capitalized_first": word[:1].isupper(),
            })
            return matches

    if _POLICY_LAYOUT_RE.match(password):
        matches.append({
            "type": "predictable_structure",
            "kind": "capitalized_word_digits_symbol",
            "start": 0,
            "end": len(password),
            "length": len(password),
        })
    return matches
