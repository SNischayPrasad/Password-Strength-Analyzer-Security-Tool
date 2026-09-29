"""
Seed the analytics dashboard with SYNTHETIC demo data.

Builds throw-away demo passwords in memory (random ones from the secure
generator, plus deliberately weak ones assembled from the local word lists),
analyzes them, and stores ONLY the safe metadata. The synthetic passwords
themselves are never printed or written anywhere.

Usage (from the project root):
    python scripts/seed_demo_data.py            # add 120 synthetic analyses
    python scripts/seed_demo_data.py --reset    # clear analytics first
    python scripts/seed_demo_data.py --count 300
"""

import argparse
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.config import Config  # noqa: E402
from backend.models.database import AnalyticsRepository  # noqa: E402
from backend.services.password_analyzer import analyze_password  # noqa: E402
from backend.services.password_generator import generate_passphrase, generate_password  # noqa: E402
from backend.services.wordlists import common_passwords, dictionary_words  # noqa: E402

KEYBOARD = ["qwerty", "asdf", "zxcv", "1qaz", "qazwsx"]


def synthetic_password() -> str:
    """Return one synthetic demo password drawn from a mix of weak and strong styles."""
    words = sorted(dictionary_words())
    common = sorted(common_passwords())
    style = secrets.randbelow(10)
    if style == 0:
        return secrets.choice(common)
    if style == 1:
        return secrets.choice(words).capitalize() + str(1990 + secrets.randbelow(37)) + "!"
    if style == 2:
        return secrets.choice(words) + "123"
    if style == 3:
        return secrets.choice(KEYBOARD) + str(secrets.randbelow(10000))
    if style == 4:
        return secrets.choice(string.ascii_lowercase) * (6 + secrets.randbelow(10))
    if style == 5:
        return "".join(secrets.choice(string.ascii_lowercase) for _ in range(8 + secrets.randbelow(6)))
    if style == 6:
        return generate_passphrase(4 + secrets.randbelow(3))
    return generate_password(secrets.choice([12, 16, 20, 24]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--count", type=int, default=120)
    parser.add_argument("--reset", action="store_true", help="delete existing analytics first")
    args = parser.parse_args()

    repo = AnalyticsRepository(Config.ANALYTICS_DB_PATH)
    if args.reset:
        repo.reset()
    for _ in range(args.count):
        repo.record_analysis(analyze_password(synthetic_password()))
    stats = repo.get_dashboard_stats()
    print(f"Seeded {args.count} synthetic analyses (metadata only) into {Config.ANALYTICS_DB_PATH}")
    print(f"Total analyses: {stats['total_analyses']}, average score: {stats['average_score']}")


if __name__ == "__main__":
    main()
