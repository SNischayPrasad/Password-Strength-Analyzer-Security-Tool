"""
Entropy-style estimation.

1) Theoretical entropy

       Entropy (bits) ~= L x log2(N)

   L = password length, N = size of the character pool it appears to use.
   This is exact ONLY if every character was picked uniformly at random.
   Humans do not pick randomly, so "Password123!" gets an optimistic
   ~79 bits here even though it would be among an attacker's first guesses.

2) Pattern-adjusted entropy (this project's educational estimate)

   Each detected pattern is re-priced at roughly what it costs an attacker
   who knows about that pattern. For example, a dictionary word costs about
   log2(dictionary size) bits instead of length x log2(N). Characters not
   covered by any pattern keep log2(N) bits each. This is a simplified
   version of the idea behind tools like zxcvbn - it is NOT a precise
   measurement, and the result is always labelled as an estimate.

Nothing here tries passwords against anything. It is arithmetic only.
"""

import math

from backend.services.character_analyzer import estimate_pool_size
from backend.services.wordlists import common_passwords, dictionary_words
from backend.services.pattern_detector import KEYBOARD_SEQUENCES


def estimate_theoretical_entropy(password: str) -> dict:
    """Return the classic L x log2(N) estimate (assumes random selection)."""
    length = len(password)
    pool = estimate_pool_size(password)
    bits = length * math.log2(pool) if length and pool else 0.0
    return {"bits": round(bits, 1), "length": length, "pool_size": pool}


def _pattern_bits(match: dict, bits_per_char: float) -> float:
    """Approximate attacker cost (in bits) of one detected pattern."""
    kind = match["type"]
    length = match["length"]
    if kind == "common_password":
        return math.log2(max(len(common_passwords()), 2))
    if kind == "dictionary_word":
        bits = math.log2(max(len(dictionary_words()), 2))
        bits += 1 if match.get("capitalized") else 0
        bits += 1 if match.get("leet") else 0
        return bits
    if kind == "sequence":
        start_choices = 10 if match.get("kind") == "numeric" else 26
        return math.log2(start_choices) + 1 + math.log2(length)
    if kind == "keyboard_pattern":
        return math.log2(len(KEYBOARD_SEQUENCES) * 2) + math.log2(12) + math.log2(length)
    if kind == "repetition":
        unit = match.get("unit_length", 1)
        return unit * bits_per_char + math.log2(max(match.get("repeat_count", 2), 2))
    if kind == "date":
        return math.log2(200) if match.get("kind") == "year" else math.log2(365 * 100)
    if kind == "personal_info":
        return 3.0  # an attacker who knows you guesses this almost immediately
    return length * bits_per_char


def estimate_pattern_adjusted_entropy(password: str, matches: list[dict]) -> dict:
    """
    Combine theoretical entropy with the detected patterns.

    Greedy approach: patterns that "save" the attacker the most bits are
    applied first; overlapping patterns are skipped. The result can only be
    lower than or equal to the theoretical estimate.
    """
    theoretical = estimate_theoretical_entropy(password)
    length = len(password)
    if length == 0:
        return {"bits": 0.0, "theoretical_bits": 0.0, "patterns_applied": 0}

    bits_per_char = math.log2(theoretical["pool_size"])

    def savings(match: dict) -> float:
        return match["length"] * bits_per_char - _pattern_bits(match, bits_per_char)

    covered: set[int] = set()
    total = 0.0
    applied = 0
    for match in sorted(matches, key=savings, reverse=True):
        span = set(range(match["start"], match["end"]))
        if not span or span & covered or savings(match) <= 0:
            continue
        covered |= span
        total += _pattern_bits(match, bits_per_char)
        applied += 1

    total += (length - len(covered)) * bits_per_char
    total = min(total, theoretical["bits"])
    return {
        "bits": round(total, 1),
        "theoretical_bits": theoretical["bits"],
        "patterns_applied": applied,
    }


# --------------------------------------------------------------------------
# Educational guess-resistance illustration
# --------------------------------------------------------------------------

# Illustrative attacker models. Real-world rates vary enormously with hardware,
# hashing algorithm, work factor and defences - these exist only to show how
# the SAME password fares very differently in different scenarios.
ATTACK_SCENARIOS = (
    {"key": "online_throttled", "label": "Online, rate-limited login",
     "guesses_per_second": 100 / 3600},
    {"key": "online_unthrottled", "label": "Online, no rate limiting",
     "guesses_per_second": 10},
    {"key": "offline_slow_hash", "label": "Offline, slow hash (e.g. Argon2id/bcrypt)",
     "guesses_per_second": 1e4},
    {"key": "offline_fast_hash", "label": "Offline, fast unsalted hash (bad practice)",
     "guesses_per_second": 1e10},
)


def humanize_seconds(seconds: float) -> str:
    """Turn a number of seconds into a coarse, human-readable range."""
    if seconds < 1:
        return "less than a second"
    units = (
        ("second", 60), ("minute", 60), ("hour", 24), ("day", 365), ("year", 100),
    )
    value = seconds
    for name, size in units:
        if value < size:
            value = int(value)
            return f"{value} {name}{'s' if value != 1 else ''}"
        value /= size
    return "centuries or more"


def estimate_guess_resistance(adjusted_bits: float) -> dict:
    """
    Educational estimate only.

    Average guesses ~= 2^(bits - 1). Returned durations are order-of-magnitude
    illustrations, not guarantees.
    """
    guesses = 2 ** max(adjusted_bits - 1, 0)
    return {
        "disclaimer": "Educational estimate only. Real guessing resistance depends on the "
                      "attacker model, password predictability, hashing algorithm, work "
                      "factor, rate limiting and online vs offline conditions.",
        "estimated_guesses_log10": round(math.log10(guesses), 1) if guesses >= 1 else 0.0,
        "scenarios": [
            {
                "key": s["key"],
                "label": s["label"],
                "time": humanize_seconds(guesses / s["guesses_per_second"]),
            }
            for s in ATTACK_SCENARIOS
        ],
    }
