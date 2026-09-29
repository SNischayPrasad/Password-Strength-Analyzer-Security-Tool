"""
Strength scoring engine (0-100).

IMPORTANT: these weights and bands are PROJECT-DEFINED for education. They are
not a universal security standard. No single formula can perfectly measure
password strength - the goal is a transparent, explainable assessment that
rewards LENGTH + UNPREDICTABILITY + PATTERN RESISTANCE and punishes the
predictable choices attackers try first.

Score = contributions - penalties, then caps, then clamp to 0..100.

Contributions (max 100):
    Length ...................... up to 35
    Character diversity ......... up to 15
    Unique-character ratio ...... up to 10
    Pattern resistance .......... up to 20
    Not a common password ....... up to 10
    Additional unpredictability . up to 10   (from pattern-adjusted entropy)

Penalties: one per weakness type. Overlapping findings often describe the same
weakness (e.g. "qwerty" is both a keyboard walk and a common base word), so
penalties are combined with diminishing weights (1, 1/2, 1/4, ...) to avoid
double-counting.

Caps (upper limits):
    * common password ........... max 10
    * length < 6 -> max 20, < 8 -> max 30, < 10 -> max 55, < 12 -> max 75
    * entropy ceiling ........... max 15 + pattern-adjusted bits
"""

CLASSIFICATION_BANDS = (
    (20, "VERY WEAK"),
    (40, "WEAK"),
    (60, "MODERATE"),
    (80, "STRONG"),
    (100, "VERY STRONG"),
)

MAX_PATTERN_RESISTANCE = 20
PATTERN_RESISTANCE_STEP = 5
MAX_NON_COMMON_POINTS = 10
MAX_UNPREDICTABILITY_POINTS = 10

# Base penalty per weakness type.
PENALTIES = {
    "common_password": 40,
    "personal_info": 20,
    "keyboard_pattern": 12,
    "predictable_structure": 10,
    "repetition": 8,
    "sequence": 8,
    "dictionary_word": 6,
    "date": 6,
}
HIGH_REPETITION_PENALTY = 25   # when repeats dominate the password
LONG_SEQUENCE_BONUS_PENALTY = 2  # extra for sequences of 5+

COMMON_PASSWORD_CAP = 10
LENGTH_CAPS = ((6, 20), (8, 30), (10, 55), (12, 75))   # (length below, max score)
ENTROPY_CEILING_OFFSET = 15

# Adjusted-entropy thresholds for the "additional unpredictability" points.
UNPREDICTABILITY_THRESHOLDS = ((75, 10), (60, 8), (45, 6), (35, 4), (28, 2))

# Finding types that count against "pattern resistance".
PATTERN_TYPES = ("sequence", "keyboard_pattern", "repetition", "date",
                 "predictable_structure", "dictionary_word", "personal_info")


def classify_score(score: int) -> str:
    """Map a 0-100 score to a classification band."""
    for upper, label in CLASSIFICATION_BANDS:
        if score <= upper:
            return label
    return CLASSIFICATION_BANDS[-1][1]


def unpredictability_points(adjusted_bits: float) -> int:
    for threshold, points in UNPREDICTABILITY_THRESHOLDS:
        if adjusted_bits >= threshold:
            return points
    return 0


def _penalty_for(finding: dict) -> int:
    ftype = finding["type"]
    if ftype == "repetition" and finding.get("high_repetition"):
        return HIGH_REPETITION_PENALTY
    penalty = PENALTIES.get(ftype, 0)
    if ftype == "sequence" and finding.get("max_length", 0) >= 5:
        penalty += LONG_SEQUENCE_BONUS_PENALTY
    return penalty


def combine_penalties(findings: list[dict]) -> tuple[float, list[dict]]:
    """Largest penalty per type, combined with weights 1, 1/2, 1/4 ..."""
    per_type: dict[str, int] = {}
    for finding in findings:
        value = _penalty_for(finding)
        if value:
            per_type[finding["type"]] = max(per_type.get(finding["type"], 0), value)

    ordered = sorted(per_type.items(), key=lambda item: item[1], reverse=True)
    total = 0.0
    applied = []
    for index, (ftype, value) in enumerate(ordered):
        weighted = value / (2 ** index)
        total += weighted
        applied.append({"type": ftype, "base": value, "applied": round(weighted, 1)})
    return total, applied


def calculate_score(*, length_info: dict, char_info: dict, is_common: bool,
                    findings: list[dict], adjusted_bits: float) -> dict:
    """
    Compute the final score with a full, explainable breakdown.

    `findings` are the weakness findings produced by the analyzer.
    """
    length = length_info["length"]
    if length == 0:
        return {"score": 0, "classification": classify_score(0),
                "breakdown": {"contributions": {}, "penalties": [], "caps": ["empty password"],
                              "raw_score": 0}}

    finding_types = {f["type"] for f in findings}
    pattern_hits = len(finding_types.intersection(PATTERN_TYPES))

    if is_common:
        non_common = 0
    elif finding_types & {"dictionary_word", "predictable_structure"}:
        non_common = MAX_NON_COMMON_POINTS // 2
    else:
        non_common = MAX_NON_COMMON_POINTS

    contributions = {
        "length": length_info["points"],
        "character_diversity": char_info["diversity_points"],
        "unique_character_ratio": char_info["unique_points"],
        "pattern_resistance": max(0, MAX_PATTERN_RESISTANCE - PATTERN_RESISTANCE_STEP * pattern_hits),
        "not_common_password": non_common,
        "additional_unpredictability": unpredictability_points(adjusted_bits),
    }
    penalty_total, penalties = combine_penalties(findings)
    raw = sum(contributions.values()) - penalty_total

    caps = []
    score = raw
    if is_common and score > COMMON_PASSWORD_CAP:
        score = COMMON_PASSWORD_CAP
        caps.append(f"common password: capped at {COMMON_PASSWORD_CAP}")
    for below, cap in LENGTH_CAPS:
        if length < below:
            if score > cap:
                score = cap
                caps.append(f"length under {below}: capped at {cap}")
            break
    ceiling = ENTROPY_CEILING_OFFSET + adjusted_bits
    if score > ceiling:
        score = ceiling
        caps.append(f"entropy ceiling: capped at {round(ceiling)} "
                    f"({ENTROPY_CEILING_OFFSET} + pattern-adjusted bits)")

    final = int(round(max(0, min(100, score))))
    return {
        "score": final,
        "classification": classify_score(final),
        "breakdown": {
            "contributions": contributions,
            "penalties": penalties,
            "penalty_total": round(penalty_total, 1),
            "raw_score": round(raw, 1),
            "caps": caps,
        },
    }
