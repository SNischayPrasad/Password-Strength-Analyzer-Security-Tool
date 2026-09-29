"""
Password analysis engine - the orchestrator.

    analyze_password(password, context=None, policy=None) -> dict

Pipeline:
    input validation
      -> length analysis
      -> character analysis
      -> common-password check
      -> pattern detection (sequences, keyboard, repetition, dates,
                            dictionary words, predictable structure)
      -> optional personal-context check
      -> entropy-style estimation (theoretical + pattern-adjusted)
      -> scoring + classification
      -> suggestions
      -> policy evaluation (reported separately from strength)

PRIVACY: the password lives only in memory for the duration of this call.
It is never logged, stored, or included in the returned result. Findings
describe positions, lengths and types - never the characters themselves.
"""

import unicodedata

from backend.config import Config
from backend.services.character_analyzer import analyze_characters
from backend.services.common_password_checker import (
    COMMON_PASSWORD_MESSAGE,
    check_common_password,
    find_dictionary_words,
)
from backend.services.context_checker import check_personal_context
from backend.services.entropy_estimator import (
    estimate_guess_resistance,
    estimate_pattern_adjusted_entropy,
)
from backend.services.length_analyzer import analyze_length
from backend.services.pattern_detector import (
    detect_dates,
    detect_keyboard_patterns,
    detect_predictable_structure,
    detect_repetition,
    detect_sequences,
    repetition_coverage,
)
from backend.services.policy_checker import PasswordPolicy, evaluate_policy
from backend.services.scoring_engine import calculate_score
from backend.services.suggestion_engine import generate_suggestions

SEVERITY = {
    "common_password": "critical",
    "personal_info": "high",
    "keyboard_pattern": "high",
    "predictable_structure": "high",
    "repetition": "medium",
    "sequence": "medium",
    "dictionary_word": "medium",
    "date": "medium",
    "passphrase_like": "info",
}

HIGH_REPETITION_COVERAGE = 0.5
PASSPHRASE_MIN_WORDS = 3
PASSPHRASE_MIN_LENGTH = 16


class PasswordValidationError(ValueError):
    """Invalid input. Messages never contain the password."""


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _build_findings(matches_by_type: dict, *, common: dict, high_repetition: bool,
                    coverage: float, passphrase_like: bool) -> list[dict]:
    """Aggregate raw matches into one human-readable finding per weakness type."""
    findings = []

    def add(ftype: str, title: str, description: str, matches: list[dict], **extra):
        findings.append({
            "type": ftype,
            "severity": extra.pop("severity", SEVERITY[ftype]),
            "title": title,
            "description": description,
            "count": len(matches),
            "max_length": max((m["length"] for m in matches), default=0),
            **extra,
        })

    if common["is_common"]:
        detail = COMMON_PASSWORD_MESSAGE
        if common["match_type"] == "leet":
            detail += " It only differs by simple character substitutions (such as @ for a)."
        add("common_password", "Common password", detail, [])

    if matches := matches_by_type.get("sequence"):
        longest = max(m["length"] for m in matches)
        add("sequence", "Predictable sequence",
            f"Found {_plural(len(matches), 'sequential run')} of characters "
            f"(longest: {longest} characters), like 1234 or dcba.", matches)

    if matches := matches_by_type.get("keyboard_pattern"):
        longest = max(m["length"] for m in matches)
        add("keyboard_pattern", "Keyboard pattern",
            f"Found {_plural(len(matches), 'keyboard walk')} (longest: {longest} characters), "
            "like qwerty or asdf.", matches)

    if matches := matches_by_type.get("repetition"):
        add("repetition", "Repeated pattern",
            f"Repeated characters or chunks cover about {round(coverage * 100)}% "
            "of the password.", matches,
            severity="high" if high_repetition else "medium",
            high_repetition=high_repetition)

    if (matches := matches_by_type.get("dictionary_word")) and not passphrase_like:
        leet = any(m.get("leet") for m in matches)
        add("dictionary_word", "Dictionary word",
            f"Contains {_plural(len(matches), 'common word')}"
            + (" disguised with character substitutions (such as 0 for o)." if leet else "."),
            matches)

    if matches := matches_by_type.get("predictable_structure"):
        m = matches[0]
        if m["kind"] == "common_word_with_suffix":
            suffix = {"year": "a year", "digits": "digits", "symbols": "symbols"}[m["suffix_kind"]]
            text = f"A common word followed by {suffix} - a pattern guessing tools apply to every word."
        else:
            text = ("Follows the 'Capitalized word + digits + symbol' layout that old "
                    "composition rules encourage.")
        add("predictable_structure", "Predictable structure", text, matches)

    if matches := matches_by_type.get("date"):
        add("date", "Year or date",
            f"Contains {_plural(len(matches), 'year- or date-like value')}.", matches)

    if matches := matches_by_type.get("personal_info"):
        fields = ", ".join(sorted({m["field_label"] for m in matches}))
        add("personal_info", "Personal information",
            f"Password appears to contain personal information (your {fields}).", matches,
            fields=sorted({m["field"] for m in matches}))

    if passphrase_like:
        add("passphrase_like", "Passphrase detected",
            "Looks like a multi-word passphrase. This is strong when the words are chosen "
            "randomly - not from a quote, lyric or common phrase.",
            matches_by_type.get("dictionary_word", []))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: order[f["severity"]])


def _build_checks(findings_types: set, metrics: dict, context_used: bool) -> list[dict]:
    """Simple ✓ / ⚠ checklist for the real-time meter (label reflects the outcome)."""
    checks = [
        ("Good length (12+ characters)", "Shorter than 12 characters", metrics["length"] >= 12),
        ("Character variety (3+ types)", "Fewer than 3 character types",
         metrics["character_type_count"] >= 3),
        ("Not a common password", "Common password", "common_password" not in findings_types),
        ("No predictable sequences", "Predictable sequence", "sequence" not in findings_types),
        ("No keyboard patterns", "Keyboard pattern", "keyboard_pattern" not in findings_types),
        ("No repeated patterns", "Repeated pattern", "repetition" not in findings_types),
        ("No word + number structure", "Word + number structure",
         "predictable_structure" not in findings_types),
        ("No years or dates", "Year or date", "date" not in findings_types),
    ]
    if context_used:
        checks.append(("No personal information", "Personal information",
                       "personal_info" not in findings_types))
    return [{"label": ok if passed else bad, "passed": passed} for ok, bad, passed in checks]


def validate_password_input(password, max_length: int | None = None) -> str:
    """Validate type and length. Error messages never echo the input."""
    max_length = max_length or Config.MAX_PASSWORD_LENGTH
    if not isinstance(password, str):
        raise PasswordValidationError("Password must be a string.")
    if len(password) > max_length:
        raise PasswordValidationError(
            f"Password exceeds the maximum supported length of {max_length} characters."
        )
    if any(unicodedata.category(c) == "Cc" and c not in "\t" for c in password):
        raise PasswordValidationError("Password contains unsupported control characters.")
    return password


def analyze_password(password: str, context: dict | None = None,
                     policy: PasswordPolicy | None = None,
                     max_length: int | None = None) -> dict:
    """
    Analyze a password locally and return a structured, password-free result:

        {"score", "classification", "findings", "suggestions",
         "metrics", "checks", "policy"}
    """
    password = validate_password_input(password, max_length)
    policy = policy or PasswordPolicy()
    # Normalize compatibility characters (e.g. full-width letters) so they
    # are compared the same way an attacker's tools would see them.
    normalized = unicodedata.normalize("NFKC", password)
    if len(normalized) != len(password):
        normalized = password  # keep positions aligned for exotic input

    length_info = analyze_length(normalized)
    char_info = analyze_characters(normalized)
    common = check_common_password(normalized)

    raw_matches: list[dict] = []
    raw_matches += detect_sequences(normalized)
    raw_matches += detect_keyboard_patterns(normalized)
    repetition_matches = detect_repetition(normalized)
    raw_matches += repetition_matches
    raw_matches += detect_dates(normalized)
    dictionary_matches = find_dictionary_words(normalized)
    raw_matches += dictionary_matches
    raw_matches += detect_predictable_structure(normalized)
    raw_matches += check_personal_context(normalized, context)

    coverage = repetition_coverage(normalized, repetition_matches)
    high_repetition = coverage >= HIGH_REPETITION_COVERAGE and len(normalized) >= 6
    distinct_words = len(dictionary_matches)
    passphrase_like = (distinct_words >= PASSPHRASE_MIN_WORDS
                       and len(normalized) >= PASSPHRASE_MIN_LENGTH and not common["is_common"])

    matches_by_type: dict[str, list[dict]] = {}
    for match in raw_matches:
        matches_by_type.setdefault(match["type"], []).append(match)

    findings = _build_findings(matches_by_type, common=common, high_repetition=high_repetition,
                               coverage=coverage, passphrase_like=passphrase_like)
    weakness_findings = [f for f in findings if f["severity"] != "info"]
    finding_types = {f["type"] for f in weakness_findings}

    entropy_matches = list(raw_matches)
    if common["is_common"]:
        entropy_matches.append({"type": "common_password", "start": 0,
                                "end": len(normalized), "length": len(normalized)})
    adjusted = estimate_pattern_adjusted_entropy(normalized, entropy_matches)

    scoring = calculate_score(length_info=length_info, char_info=char_info,
                              is_common=common["is_common"], findings=weakness_findings,
                              adjusted_bits=adjusted["bits"])

    metrics = {
        "length": length_info["length"],
        "length_band": length_info["band"],
        "length_label": length_info["label"],
        "length_message": length_info["message"],
        "character_types": char_info["classes"],
        "character_type_count": char_info["character_type_count"],
        "unique_character_count": char_info["unique_character_count"],
        "unique_character_ratio": char_info["unique_character_ratio"],
        "pool_size": char_info["pool_size"],
        "theoretical_entropy_bits": adjusted["theoretical_bits"],
        "adjusted_entropy_bits": adjusted["bits"],
        "guess_resistance": estimate_guess_resistance(adjusted["bits"]),
        "pattern_count": len(weakness_findings),
        "is_passphrase_like": passphrase_like,
        "score_breakdown": scoring["breakdown"],
        # Positions/types only - lets the UI draw a "pattern map" without
        # ever sending characters back.
        "pattern_map": sorted(
            ({"type": m["type"], "start": m["start"], "end": m["end"]}
             for m in raw_matches if m["type"] != "predictable_structure"),
            key=lambda seg: (seg["start"], seg["end"]),
        ),
    }

    return {
        "score": scoring["score"],
        "classification": scoring["classification"],
        "findings": findings,
        "suggestions": generate_suggestions(weakness_findings, metrics),
        "metrics": metrics,
        "checks": _build_checks(finding_types, metrics, context_used=bool(context and any(
            isinstance(v, str) and v.strip() for v in context.values()))),
        "policy": evaluate_policy(normalized, finding_types, policy),
    }
