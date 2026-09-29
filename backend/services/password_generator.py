"""
Secure password and passphrase generator.

Uses Python's `secrets` module, which draws from the operating system's
cryptographically secure random source (CSPRNG).

Why not `random`? The `random` module uses the Mersenne Twister, a fast
*predictable* generator designed for simulations. Its internal state can be
reconstructed from enough outputs, so it must never be used for passwords,
tokens or keys.

Generated values are returned to the caller only - never stored or logged.
"""

import math
import secrets
import string

from backend.services.wordlists import passphrase_wordlist

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/"
AMBIGUOUS = set("Il1O0o")
SUPPORTED_LENGTHS = (16, 20, 24)
MIN_GENERATED_LENGTH = 8
MAX_GENERATED_LENGTH = 128

_system_random = secrets.SystemRandom()


class GeneratorError(ValueError):
    """Raised for invalid generator options (safe to show to the user)."""


def generate_password(length: int = 20, *, use_uppercase: bool = True,
                      use_lowercase: bool = True, use_digits: bool = True,
                      use_symbols: bool = True, exclude_ambiguous: bool = False) -> str:
    """
    Generate a random password with a CSPRNG.

    Guarantees at least one character from every selected class, then
    shuffles the result with a CSPRNG-backed shuffle.
    """
    if not isinstance(length, int) or not MIN_GENERATED_LENGTH <= length <= MAX_GENERATED_LENGTH:
        raise GeneratorError(
            f"Length must be between {MIN_GENERATED_LENGTH} and {MAX_GENERATED_LENGTH}."
        )

    pools = []
    if use_lowercase:
        pools.append(string.ascii_lowercase)
    if use_uppercase:
        pools.append(string.ascii_uppercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append(SYMBOLS)
    if exclude_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS) for pool in pools]
    if not pools:
        raise GeneratorError("Select at least one character type.")

    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]  # one from each class
    chars += [secrets.choice(alphabet) for _ in range(length - len(chars))]
    _system_random.shuffle(chars)
    return "".join(chars)


def generate_passphrase(word_count: int = 6, separator: str = "-",
                        capitalize: bool = False) -> str:
    """Generate a passphrase of randomly selected words (for education/demo)."""
    if not isinstance(word_count, int) or not 4 <= word_count <= 10:
        raise GeneratorError("Word count must be between 4 and 10.")
    if separator not in {"-", " ", ".", "_", ""}:
        raise GeneratorError("Separator must be one of: '-', ' ', '.', '_' or none.")
    words = passphrase_wordlist()
    if len(words) < 100:
        raise GeneratorError("Passphrase word list is missing or too small.")
    chosen = [secrets.choice(words) for _ in range(word_count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    return separator.join(chosen)


def generated_password_entropy(length: int, alphabet_size: int) -> float:
    """Entropy of a truly random password: length x log2(alphabet size)."""
    return round(length * math.log2(alphabet_size), 1) if alphabet_size > 1 else 0.0


def passphrase_entropy(word_count: int) -> float:
    """Entropy of a random passphrase: words x log2(word list size)."""
    size = len(passphrase_wordlist())
    return round(word_count * math.log2(size), 1) if size > 1 else 0.0
