"""
Command-line analyzer.

Prompts with getpass (input is not echoed to the terminal, and nothing is
added to shell history), prints the analysis, and never prints the password.

Usage (from the project root):
    python scripts/analyze_cli.py
    python scripts/analyze_cli.py --json
"""

import argparse
import getpass
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.services.password_analyzer import PasswordValidationError, analyze_password  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze a password locally.")
    parser.add_argument("--json", action="store_true", help="print the full JSON result")
    args = parser.parse_args()

    password = getpass.getpass("Password to analyze (input hidden, use a demo password): ")
    try:
        result = analyze_password(password)
    except PasswordValidationError as exc:
        print(f"Error: {exc}")
        sys.exit(1)
    finally:
        password = None  # drop our reference as soon as possible

    if args.json:
        print(json.dumps(result, indent=2))
        return

    m = result["metrics"]
    print(f"\nScore: {result['score']}/100  ->  {result['classification']}")
    print(f"Length: {m['length']} ({m['length_label']}), character types: {m['character_type_count']}/4")
    print(f"Theoretical entropy: {m['theoretical_entropy_bits']} bits, "
          f"pattern-adjusted estimate: {m['adjusted_entropy_bits']} bits")
    print(f"Policy: {result['policy']['status']}")
    print("\nFindings:")
    for finding in result["findings"] or [{"severity": "-", "title": "None", "description": "No known weak patterns."}]:
        print(f"  [{finding['severity']}] {finding['title']}: {finding['description']}")
    print("\nSuggestions:")
    for suggestion in result["suggestions"]:
        print(f"  - {suggestion}")


if __name__ == "__main__":
    main()
