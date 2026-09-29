"""
Length analysis.

Length is the single biggest contributor to guessing resistance for a
*randomly chosen* password: every extra character multiplies the number of
possibilities. But length alone does not make a password secure -
"aaaaaaaaaaaaaaaaaaaa" is 20 characters long and still trivially predictable.
That is why the length score is combined with pattern analysis elsewhere.
"""

# Educational length bands (project-defined, configurable).
# Each entry: (max_length_inclusive, band_key, label, message)
LENGTH_BANDS = (
    (7, "VERY_SHORT", "Very short",
     "Fewer than 8 characters can be exhausted quickly, even when characters are random."),
    (11, "SHORT", "Short",
     "8-11 characters meets old minimums but leaves little margin if any part is predictable."),
    (15, "BETTER", "Better length",
     "12-15 characters is a solid baseline when the content is also unpredictable."),
    (None, "STRONG", "Strong length contribution",
     "16+ characters gives a strong length contribution - as long as it is not built from a pattern."),
)

MAX_LENGTH_POINTS = 35          # scoring weight for length
FULL_POINTS_LENGTH = 20         # length at which the full length points are reached


def length_points(length: int) -> int:
    """Linear length contribution: 0 points for empty, 35 points at 20+ characters."""
    if length <= 0:
        return 0
    return min(MAX_LENGTH_POINTS, round(length * MAX_LENGTH_POINTS / FULL_POINTS_LENGTH))


def analyze_length(password: str) -> dict:
    """
    Describe the password length.

    Returns a dict with the length, its educational band and the score
    contribution. The password itself is never included in the result.
    """
    length = len(password)
    for max_len, key, label, message in LENGTH_BANDS:
        if max_len is None or length <= max_len:
            return {
                "length": length,
                "band": key,
                "label": label,
                "message": message,
                "points": length_points(length),
                "max_points": MAX_LENGTH_POINTS,
            }
    raise AssertionError("unreachable: last band has no upper bound")
