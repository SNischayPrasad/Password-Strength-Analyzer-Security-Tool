"""
Common-password and dictionary-word detection.

Attackers do not guess randomly - they start with lists of the most common
passwords and dictionary words, including simple "leetspeak" variants such as
p@ssw0rd. This module checks the password against small, local, educational
lists (data/common_passwords.txt and data/common_words.txt).
"""

from backend.services.wordlists import (
    MIN_WORD_LENGTH,
    common_passwords,
    dictionary_words,
    leet_variants,
    normalize,
)

COMMON_PASSWORD_MESSAGE = (
    "Your password matches a commonly used password pattern and should not be used."
)


def check_common_password(password: str) -> dict:
    """
    Check the whole password against the common-password list.

    Returns {"is_common": bool, "match_type": "exact" | "leet" | None}.
    "leet" means it only matched after undoing substitutions like @->a, 0->o.
    """
    if not password:
        return {"is_common": False, "match_type": None}
    lowered = normalize(password)
    common = common_passwords()
    if lowered in common:
        return {"is_common": True, "match_type": "exact"}
    for variant in leet_variants(lowered)[1:]:
        if variant in common:
            return {"is_common": True, "match_type": "leet"}
    return {"is_common": False, "match_type": None}


def is_common_password(password: str) -> bool:
    """Convenience wrapper: True when the password is on the common list."""
    return check_common_password(password)["is_common"]


def find_dictionary_words(password: str, max_word_length: int = 20) -> list[dict]:
    """
    Find dictionary words hidden inside the password.

    Scans left-to-right and keeps the longest word starting at each position,
    then skips past it. Leetspeak variants are checked too. The returned
    matches contain positions and lengths only - never the matched text.
    """
    words = dictionary_words()
    normalized = normalize(password)
    matches: list[dict] = []
    if len(normalized) != len(password):
        # NFKC can change length for exotic characters; fall back to lowercase.
        normalized = password.lower()

    variants = leet_variants(normalized)
    n = len(normalized)
    i = 0
    while i < n:
        best = None
        for variant_index, variant in enumerate(variants):
            upper = min(n, i + max_word_length)
            for j in range(upper, i + MIN_WORD_LENGTH - 1, -1):
                if variant[i:j] in words:
                    if best is None or (j - i) > best["length"]:
                        best = {
                            "type": "dictionary_word",
                            "start": i,
                            "end": j,
                            "length": j - i,
                            "leet": variant_index > 0 and variant[i:j] != normalized[i:j],
                            "capitalized": password[i:i + 1].isupper(),
                        }
                    break
        if best:
            matches.append(best)
            i = best["end"]
        else:
            i += 1
    return matches
