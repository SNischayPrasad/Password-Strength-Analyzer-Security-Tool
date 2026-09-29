"""
Optional personal-information check.

Targeted attackers (and "password spraying" tools) try names, birth years,
companies, colleges, pets and similar details first, because people often
build passwords from them. If the user *voluntarily* provides demo context,
we compare it with the password locally, in memory.

Privacy rules:
  * The context is never stored, logged or returned.
  * Findings mention only WHICH field overlapped (e.g. "first_name"),
    never the value.
  * Use demo values for demonstrations - never real personal data.
"""

import re

from backend.services.wordlists import leet_variants, normalize

SUPPORTED_FIELDS = ("first_name", "birth_year", "organization")
FIELD_LABELS = {
    "first_name": "first name",
    "birth_year": "birth year",
    "organization": "company/college name",
}
MIN_TOKEN_LENGTH = 3


def _tokens(value: str) -> list[str]:
    """Split a context value into comparable tokens (plus the joined form)."""
    cleaned = normalize(value)
    parts = [p for p in re.split(r"[^\w]+", cleaned) if len(p) >= MIN_TOKEN_LENGTH]
    joined = "".join(parts)
    if len(parts) > 1 and len(joined) >= MIN_TOKEN_LENGTH:
        parts.append(joined)
    return sorted(set(parts), key=len, reverse=True)


def check_personal_context(password: str, context: dict | None) -> list[dict]:
    """
    Return matches where the password contains any provided context value.

    Supported context keys: first_name, birth_year, organization.
    Also detects the reversed form (e.g. a name written backwards).
    """
    if not password or not context:
        return []

    password_variants = leet_variants(normalize(password))
    matches = []

    for field in SUPPORTED_FIELDS:
        raw = context.get(field)
        if not raw or not isinstance(raw, str):
            continue
        raw = raw.strip()
        if field == "birth_year":
            tokens = [raw] if re.fullmatch(r"(19|20)\d{2}", raw) else []
        else:
            tokens = _tokens(raw)

        for token in tokens:
            hit = None
            for variant in password_variants:
                for candidate, reversed_ in ((token, False), (token[::-1], True)):
                    index = variant.find(candidate)
                    if index != -1:
                        hit = {"index": index, "reversed": reversed_}
                        break
                if hit:
                    break
            if hit:
                matches.append({
                    "type": "personal_info",
                    "field": field,
                    "field_label": FIELD_LABELS[field],
                    "start": hit["index"],
                    "end": hit["index"] + len(token),
                    "length": len(token),
                    "reversed": hit["reversed"],
                })
                break  # one finding per field is enough
    return matches
