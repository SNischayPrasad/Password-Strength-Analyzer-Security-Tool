"""
Character analysis.

Measures which character classes are present and how varied the characters are.
Diversity *can* help because it enlarges the pool an attacker must consider,
but it must never be the only metric: "Password123!" contains all four classes
and is still one of the first things an attacker tries.
"""

import math

# Approximate pool sizes used by the theoretical entropy estimate.
POOL_SIZES = {
    "lowercase": 26,
    "uppercase": 26,
    "digits": 10,
    "symbols": 33,    # printable ASCII punctuation
    "spaces": 1,
    "non_ascii": 100,  # rough allowance for accented letters, emoji, other scripts
}

MAX_DIVERSITY_POINTS = 15
MAX_UNIQUE_POINTS = 10
DIVERSITY_POINTS_BY_TYPE_COUNT = {0: 0, 1: 3, 2: 7, 3: 11, 4: 15}


def character_classes(password: str) -> dict:
    """Return which character classes appear in the password."""
    return {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digits": any(c.isdigit() for c in password),
        "symbols": any(not c.isalnum() and not c.isspace() for c in password),
        "spaces": any(c.isspace() for c in password),
        "non_ascii": any(not c.isascii() for c in password),
    }


def estimate_pool_size(password: str) -> int:
    """Estimate the size of the character set the password appears to draw from."""
    classes = character_classes(password)
    return sum(POOL_SIZES[name] for name, present in classes.items() if present)


def analyze_characters(password: str) -> dict:
    """
    Analyze character diversity.

    character_type_count counts the four classic classes (lowercase, uppercase,
    digits, symbols); spaces count toward the symbol class.
    """
    classes = character_classes(password)
    type_count = sum([
        classes["lowercase"],
        classes["uppercase"],
        classes["digits"],
        classes["symbols"] or classes["spaces"],
    ])
    length = len(password)
    unique_count = len(set(password))
    unique_ratio = (unique_count / length) if length else 0.0

    return {
        "classes": classes,
        "character_type_count": type_count,
        "unique_character_count": unique_count,
        "unique_character_ratio": round(unique_ratio, 3),
        "pool_size": estimate_pool_size(password),
        "diversity_points": DIVERSITY_POINTS_BY_TYPE_COUNT[type_count],
        "unique_points": round(MAX_UNIQUE_POINTS * unique_ratio),
        "bits_per_character": round(math.log2(estimate_pool_size(password)), 2)
        if length else 0.0,
    }
