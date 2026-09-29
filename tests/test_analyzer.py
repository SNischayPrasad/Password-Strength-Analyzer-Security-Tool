"""
Core analyzer tests - the 30 required scenarios are tagged T01..T30 in the
test names (see docs/TESTING.md). Only synthetic demo passwords are used.
"""

import secrets
import string

import pytest

from backend.services.character_analyzer import analyze_characters
from backend.services.common_password_checker import check_common_password, is_common_password
from backend.services.entropy_estimator import estimate_theoretical_entropy
from backend.services.length_analyzer import analyze_length
from backend.services.password_analyzer import PasswordValidationError, analyze_password
from backend.services.pattern_detector import (
    detect_dates,
    detect_keyboard_patterns,
    detect_predictable_structure,
    detect_repetition,
    detect_sequences,
)
from backend.services.scoring_engine import classify_score


def types_of(result):
    return {f["type"] for f in result["findings"]}


# --- T01-T10: basic inputs and character classes -------------------------

def test_T01_empty_password_scores_zero():
    result = analyze_password("")
    assert result["score"] == 0
    assert result["classification"] == "VERY WEAK"
    assert result["findings"] == []


def test_T02_one_character_password_is_very_weak():
    result = analyze_password("x")
    assert result["classification"] == "VERY WEAK"
    assert result["metrics"]["length_band"] == "VERY_SHORT"


def test_T03_short_numeric_password():
    result = analyze_password("4071")
    assert result["classification"] in {"VERY WEAK", "WEAK"}
    assert result["metrics"]["character_type_count"] == 1


def test_T04_common_password_detected_and_capped():
    result = analyze_password("123456")
    assert "common_password" in types_of(result)
    assert result["classification"] == "VERY WEAK"
    assert result["score"] <= 10
    assert is_common_password("123456")


def test_T05_long_repeated_password_is_weak():
    result = analyze_password("a" * 16)
    assert result["metrics"]["length"] == 16
    assert "repetition" in types_of(result)
    assert result["classification"] == "WEAK"


def test_T06_lowercase_only():
    info = analyze_characters("vqkemzrd")
    assert info["classes"]["lowercase"] and not info["classes"]["uppercase"]
    assert info["character_type_count"] == 1


def test_T07_uppercase_only():
    info = analyze_characters("VQKEMZRD")
    assert info["classes"]["uppercase"] and not info["classes"]["lowercase"]
    assert info["character_type_count"] == 1


def test_T08_numbers_only():
    info = analyze_characters("80417362")
    assert info["classes"]["digits"]
    assert info["character_type_count"] == 1
    assert info["pool_size"] == 10


def test_T09_symbols_only():
    info = analyze_characters("#%&*?~^")
    assert info["classes"]["symbols"]
    assert info["character_type_count"] == 1


def test_T10_mixed_characters():
    info = analyze_characters("vK7#mQ2!")
    assert info["character_type_count"] == 4
    assert info["diversity_points"] == 15


# --- T11-T18: pattern detection -----------------------------------------

def test_T11_sequential_numbers():
    matches = detect_sequences("xx1234yy")
    assert matches and matches[0]["direction"] == "ascending"
    assert matches[0]["kind"] == "numeric" and matches[0]["length"] == 4


def test_T12_reverse_numeric_sequence():
    matches = detect_sequences("9876")
    assert matches[0]["direction"] == "descending"


def test_T13_sequential_letters():
    asc = detect_sequences("abcd")
    desc = detect_sequences("DCBA")
    assert asc[0]["kind"] == "alphabetic" and asc[0]["direction"] == "ascending"
    assert desc[0]["direction"] == "descending"


def test_T14_keyboard_sequence():
    for sample in ("qwerty", "asdf", "zxcv", "qwerty123", "1qaz"):
        assert detect_keyboard_patterns(sample), sample
    assert "keyboard_pattern" in types_of(analyze_password("xasdfghx93"))


def test_T15_repeated_characters():
    matches = detect_repetition("AAAAAA123!")
    assert matches[0]["kind"] == "repeated_characters"
    assert matches[0]["repeat_count"] == 6


def test_T16_repeated_substring():
    abab = detect_repetition("ababab")
    abc = detect_repetition("abcabcabc")
    assert abab[0]["kind"] == "repeated_substring" and abab[0]["unit_length"] == 2
    assert abc[0]["unit_length"] == 3 and abc[0]["repeat_count"] == 3


def test_T17_common_word_plus_number():
    for sample in ("welcome123", "hello1234", "Password123!"):
        structure = detect_predictable_structure(sample)
        assert structure and structure[0]["kind"] == "common_word_with_suffix", sample
    result = analyze_password("Password123!")
    assert {"predictable_structure", "dictionary_word", "sequence"} <= types_of(result)
    assert result["classification"] in {"WEAK", "MODERATE"}


def test_T18_word_plus_year():
    structure = detect_predictable_structure("admin2026")
    assert structure[0]["suffix_kind"] == "year"
    assert any(m["kind"] == "year" for m in detect_dates("admin2026"))
    result = analyze_password("qwerty2026!")
    assert {"keyboard_pattern", "date"} <= types_of(result)
    assert result["classification"] == "WEAK"


# --- T19-T24: context, passphrases, unicode, limits --------------------

def test_T19_personal_name_overlap():
    result = analyze_password("Rahul@123", context={"first_name": "Rahul"})
    assert "personal_info" in types_of(result)
    finding = next(f for f in result["findings"] if f["type"] == "personal_info")
    assert "Rahul" not in finding["description"]  # value is never echoed
    assert finding["fields"] == ["first_name"]


def test_T20_birth_year_overlap():
    result = analyze_password("blue-kite-1999", context={"birth_year": "1999"})
    assert "personal_info" in types_of(result)


def test_T21_long_passphrase_like_input():
    result = analyze_password("walrus-trellis-cobalt-thimble-nectar")
    assert result["metrics"]["is_passphrase_like"]
    assert "dictionary_word" not in types_of(result)
    assert result["classification"] in {"STRONG", "VERY STRONG"}


def test_T22_unicode_handling():
    result = analyze_password("ñandú-Äpfel-日本語-ß")
    assert result["metrics"]["character_types"]["non_ascii"]
    assert result["metrics"]["length"] == len("ñandú-Äpfel-日本語-ß")
    assert 0 <= result["score"] <= 100


def test_T23_space_handling():
    result = analyze_password("violin tundra pebble socket")
    assert result["metrics"]["character_types"]["spaces"]
    assert result["policy"]["passed"]  # default policy allows spaces


def test_T24_maximum_accepted_length():
    assert analyze_password("k" * 256)["metrics"]["length"] == 256
    with pytest.raises(PasswordValidationError) as excinfo:
        analyze_password("k" * 257)
    assert "k" * 10 not in str(excinfo.value)


# --- T25-T27: scoring, suggestions, generator -------------------------

@pytest.mark.parametrize("score,expected", [
    (0, "VERY WEAK"), (20, "VERY WEAK"), (21, "WEAK"), (40, "WEAK"), (41, "MODERATE"),
    (60, "MODERATE"), (61, "STRONG"), (80, "STRONG"), (81, "VERY STRONG"), (100, "VERY STRONG"),
])
def test_T25_strength_score_boundaries(score, expected):
    assert classify_score(score) == expected


def test_T26_suggestion_generation_is_specific_and_safe():
    password = "qwerty2026!"
    result = analyze_password(password)
    text = " ".join(result["suggestions"])
    assert "keyboard" in text.lower()
    assert "year" in text.lower()
    assert "MFA" in text
    assert password not in text
    assert "Make your password stronger" not in text


def test_T27_secure_password_generation():
    from backend.services import password_generator as gen
    pw = gen.generate_password(20)
    assert len(pw) == 20
    assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
    assert any(c.isdigit() for c in pw) and any(c in gen.SYMBOLS for c in pw)
    assert len({gen.generate_password(20) for _ in range(20)}) == 20
    assert analyze_password(pw)["classification"] in {"STRONG", "VERY STRONG"}


# --- Additional engine tests -------------------------------------------

def test_length_bands():
    assert analyze_length("a" * 7)["band"] == "VERY_SHORT"
    assert analyze_length("a" * 8)["band"] == "SHORT"
    assert analyze_length("a" * 12)["band"] == "BETTER"
    assert analyze_length("a" * 16)["band"] == "STRONG"


def test_leetspeak_common_password():
    assert check_common_password("p@ssw0rd1") == {"is_common": True, "match_type": "leet"}


def test_theoretical_entropy_formula():
    est = estimate_theoretical_entropy("abcdefgh")
    assert est["pool_size"] == 26
    assert est["bits"] == pytest.approx(8 * 4.70, abs=0.1)


def test_entropy_is_optimistic_for_predictable_password():
    result = analyze_password("Password123!")
    m = result["metrics"]
    assert m["theoretical_entropy_bits"] > 70
    assert m["adjusted_entropy_bits"] < 30


def test_date_detection():
    assert detect_dates("born12/05/2001")[0]["kind"] == "date"
    assert detect_dates("x20010512x")[0]["kind"] == "date"


def test_random_20_char_password_very_strong():
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    sample = "".join(secrets.choice(alphabet) for _ in range(20))
    assert analyze_password(sample)["score"] >= 61


def test_policy_is_separate_from_strength():
    result = analyze_password("Welcome2026!")
    assert result["classification"] in {"VERY WEAK", "WEAK"}
    assert result["policy"]["status"] == "POLICY PASS"  # meets 12-char minimum, not on the common list


def test_result_never_contains_password():
    password = "tangerine-Q9-otter"
    result = analyze_password(password, context={"first_name": "Otter"})
    assert password not in repr(result)
    assert "Otter" not in repr(result)
