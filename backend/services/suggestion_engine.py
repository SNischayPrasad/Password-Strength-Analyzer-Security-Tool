"""
Security suggestion engine.

Suggestions must be SPECIFIC to what was found ("Your password contains a
predictable numeric sequence") rather than vague ("make it stronger").
They never quote or display the password itself.
"""

# Specific advice for each weakness type (first entry = headline suggestion).
FINDING_SUGGESTIONS = {
    "common_password": [
        "This password appears on common-password lists and should not be used anywhere.",
        "Replace it with a generated password or a long passphrase of randomly chosen words.",
    ],
    "sequence": [
        "Your password contains a predictable sequence (like 1234 or abcd) - remove it.",
    ],
    "keyboard_pattern": [
        "Avoid keyboard walks such as qwerty, asdf or 1qaz - they are among the first guesses tried.",
    ],
    "repetition": [
        "Your password repeats characters or chunks - repeated parts add length without adding unpredictability.",
    ],
    "dictionary_word": [
        "Your password is built around a common dictionary word - on its own, a single word is guessed quickly.",
    ],
    "predictable_structure": [
        "Adding numbers or a symbol to the end of a word is a predictable pattern that guessing tools try automatically.",
    ],
    "date": [
        "Avoid years and dates (birth years, the current year, anniversaries) - they are easy to guess.",
    ],
    "personal_info": [
        "Avoid including your name, birth year or organization - attackers try personal details first.",
    ],
}

GENERAL_HYGIENE = [
    "Use a unique password for every account - never reuse passwords across sites.",
    "Use a password manager to generate and store unique passwords.",
    "Enable multi-factor authentication (MFA) wherever it is available.",
]

MAX_SPECIFIC_SUGGESTIONS = 6  # hygiene tips are always appended after these


def generate_suggestions(findings: list[dict], metrics: dict) -> list[str]:
    """
    Build an ordered, de-duplicated list of suggestions.

    Order: weakness-specific advice (most severe first), then length and
    variety guidance, then general hygiene advice.
    """
    suggestions: list[str] = []

    def add(text: str) -> None:
        if text not in suggestions:
            suggestions.append(text)

    length = metrics.get("length", 0)
    if length == 0:
        return ["Enter a password to receive an analysis."]

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for finding in sorted(findings, key=lambda f: severity_rank.get(f.get("severity"), 5)):
        for text in FINDING_SUGGESTIONS.get(finding["type"], []):
            add(text)

    if length < 12:
        add("Use at least 12 characters - 16 or more is better. A passphrase of 4-6 random words "
            "is a practical way to get there.")
    elif length < 16:
        add("Consider a longer password or passphrase (16+ characters) for extra margin.")

    if metrics.get("character_type_count", 0) <= 1 and length < 20:
        add("Only one type of character is used. Adding length is usually the most effective fix; "
            "mixing in other character types also helps.")

    if metrics.get("is_passphrase_like"):
        add("Passphrases are strongest when the words are chosen randomly (for example by a "
            "generator), not taken from a quote, song or common phrase.")

    if findings and not any(f["type"] == "common_password" for f in findings):
        add("Consider a generated password or a long random passphrase to increase unpredictability.")

    suggestions = suggestions[:MAX_SPECIFIC_SUGGESTIONS]
    for tip in GENERAL_HYGIENE:
        add(tip)
    return suggestions
