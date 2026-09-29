"""
Password policy checker.

POLICY COMPLIANCE and STRENGTH are different questions:
  * Policy: "Does this password satisfy the organization's minimum rules?"
    (pass/fail, set by an administrator)
  * Strength: "How hard is this password likely to be to guess?" (0-100 score)

A password can pass a policy and still be weak (e.g. an old-style policy that
accepts "Password123!"), or be strong while failing a policy (e.g. a strong
passphrase on a site that forbids spaces).

The defaults follow modern guidance (e.g. NIST SP 800-63B): favour a
reasonable minimum length, allow long passwords and spaces, block known
common passwords, and do NOT force arbitrary composition rules or periodic
password changes - change passwords when compromise is suspected/confirmed.
"""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class PasswordPolicy:
    minimum_length: int = 12
    maximum_length: int = 128
    common_password_check: bool = True
    personal_info_check: bool = True
    allow_spaces: bool = True

    def to_dict(self) -> dict:
        return asdict(self)


def policy_from_config(config) -> PasswordPolicy:
    """Build the administrator-configured policy from Flask/Config settings."""
    get = config.get if hasattr(config, "get") else lambda k, d=None: getattr(config, k, d)
    return PasswordPolicy(
        minimum_length=int(get("POLICY_MIN_LENGTH", 12)),
        maximum_length=int(get("POLICY_MAX_LENGTH", 128)),
        common_password_check=bool(get("POLICY_COMMON_PASSWORD_CHECK", True)),
        personal_info_check=bool(get("POLICY_PERSONAL_INFO_CHECK", True)),
        allow_spaces=bool(get("POLICY_ALLOW_SPACES", True)),
    )


def evaluate_policy(password: str, finding_types: set[str], policy: PasswordPolicy) -> dict:
    """Return POLICY PASS / POLICY FAIL with the result of each rule."""
    length = len(password)
    rules = [
        {
            "rule": "minimum_length",
            "passed": length >= policy.minimum_length,
            "message": f"At least {policy.minimum_length} characters",
        },
        {
            "rule": "maximum_length",
            "passed": length <= policy.maximum_length,
            "message": f"No more than {policy.maximum_length} characters",
        },
    ]
    if not policy.allow_spaces:
        rules.append({
            "rule": "no_spaces",
            "passed": not any(c.isspace() for c in password),
            "message": "Spaces are not allowed by this policy",
        })
    if policy.common_password_check:
        rules.append({
            "rule": "not_common_password",
            "passed": "common_password" not in finding_types,
            "message": "Must not be a commonly used password",
        })
    if policy.personal_info_check:
        rules.append({
            "rule": "no_personal_info",
            "passed": "personal_info" not in finding_types,
            "message": "Must not contain the provided personal information",
        })

    passed = all(rule["passed"] for rule in rules)
    return {
        "status": "POLICY PASS" if passed else "POLICY FAIL",
        "passed": passed,
        "rules": rules,
        "policy": policy.to_dict(),
    }
