"""
Central configuration.

All settings come from environment variables (optionally loaded from a `.env`
file) with safe defaults, so the project runs out-of-the-box on a laptop.
Nothing in this file ever holds a real password.
"""

import os
from pathlib import Path

try:  # python-dotenv is optional; the app still runs without it.
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

# Project root = the folder that contains backend/, frontend/, data/ ...
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
DATA_DIR = PROJECT_ROOT / "data"

if load_dotenv is not None:
    load_dotenv(PROJECT_ROOT / ".env")


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


class Config:
    """Default configuration used by create_app()."""

    # --- Server -----------------------------------------------------------
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = _env_int("PORT", 5000)
    # Debug mode is OFF by default: the Werkzeug debugger shows local
    # variables in tracebacks, which could expose a submitted password.
    DEBUG = _env_bool("FLASK_DEBUG", False)

    # Reject oversized request bodies early (16 KB is plenty for a password).
    MAX_CONTENT_LENGTH = 16 * 1024

    # --- Password input limits -------------------------------------------
    # Longest password the analyzer accepts. Long passphrases must be allowed,
    # but an upper bound protects the server from very large inputs.
    MAX_PASSWORD_LENGTH = _env_int("MAX_PASSWORD_LENGTH", 256)
    MAX_CONTEXT_FIELD_LENGTH = 100

    # --- Data files -------------------------------------------------------
    COMMON_PASSWORDS_FILE = Path(
        os.environ.get("COMMON_PASSWORDS_FILE", DATA_DIR / "common_passwords.txt")
    )
    COMMON_WORDS_FILE = Path(os.environ.get("COMMON_WORDS_FILE", DATA_DIR / "common_words.txt"))
    PASSPHRASE_WORDLIST = Path(
        os.environ.get("PASSPHRASE_WORDLIST", DATA_DIR / "passphrase_words.txt")
    )

    # --- Optional analytics (metadata only, never passwords) --------------
    ANALYTICS_ENABLED = _env_bool("ANALYTICS_ENABLED", True)
    ANALYTICS_DB_PATH = Path(
        os.environ.get("ANALYTICS_DB_PATH", PROJECT_ROOT / "instance" / "analytics.db")
    )

    # --- Rate limiting (simple in-memory, per client IP) -------------------
    RATE_LIMIT_ENABLED = _env_bool("RATE_LIMIT_ENABLED", True)
    ANALYZE_RATE_LIMIT_PER_MINUTE = _env_int("ANALYZE_RATE_LIMIT_PER_MINUTE", 240)
    GENERATE_RATE_LIMIT_PER_MINUTE = _env_int("GENERATE_RATE_LIMIT_PER_MINUTE", 60)

    # --- Administrator-configurable password policy ------------------------
    POLICY_MIN_LENGTH = _env_int("POLICY_MIN_LENGTH", 12)
    POLICY_MAX_LENGTH = _env_int("POLICY_MAX_LENGTH", 128)
    POLICY_COMMON_PASSWORD_CHECK = _env_bool("POLICY_COMMON_PASSWORD_CHECK", True)
    POLICY_PERSONAL_INFO_CHECK = _env_bool("POLICY_PERSONAL_INFO_CHECK", True)
    POLICY_ALLOW_SPACES = _env_bool("POLICY_ALLOW_SPACES", True)
